import hashlib
import json
import secrets
import uuid
from datetime import timedelta
from pathlib import Path

from django.conf import settings
from django.contrib.auth import login as django_login
from django.contrib.auth.password_validation import validate_password
from django.core.cache import cache
from django.core.exceptions import ValidationError as DjangoValidationError
from django.db import IntegrityError, transaction
from django.db.models import Q
from django.http import HttpResponse
from django.utils import timezone
from rest_framework import serializers
from rest_framework.decorators import action
from rest_framework.exceptions import AuthenticationFailed, PermissionDenied, Throttled, ValidationError
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.throttling import SimpleRateThrottle
from rest_framework.viewsets import GenericViewSet

from gt.permissions import Hccaptcha
from gt.parsers import AUTH_PARSERS
from gt_admin.audit import record
from gt_coin.models import Coin, CoinRecordType
from gt_coin import amount as coin_amount
from .education import normalize_education_email, send_email_code, consume_email_code, bind_verified_email, education_identity, education_student_id, digest
from .models import (User, Role, Quota, Permission, Privacy, AuthSession, SecurityChallenge,
                     WebAuthnCredential, ConsoleTicket, SiteSecuritySetting, ImpersonationTicket,
                     ClientCertificateIdentity, Notification, NotificationType, active_user_q)
from .roles import ROLE_LABELS, PRIVILEGED_ROLES, visible_badges, assigned_roles
from .security_policy import (enrollment_complete, key_authenticated, require_key_session,
                              allows_single_factor, high_assurance, admin_access_allowed,
                              admin_keys_satisfied, can_sign_issuance_requests,
                              security_summary, suspended, valid_session)
from .sessions import create_session
from .views import make_user_response
from . import webauthn, totp


class SecurityRateThrottle(SimpleRateThrottle):
    scope = "security"

    def get_rate(self):
        return settings.SECURITY_AUTH_RATE_LIMIT

    def get_cache_key(self, request, view):
        # Forwarding headers are caller input. Ingress must normalize REMOTE_ADDR.
        return self.cache_format % {"scope": self.scope, "ident": request.META.get("REMOTE_ADDR", "unknown")}


def require_account_factor(request, *, password=None):
    user, session = request.user, request.security_session
    if session.scope == "impersonation":
        raise PermissionDenied("代登录会话不能修改账号安全信息")
    if session.scope not in {"full", "enrollment"}:
        raise PermissionDenied("当前会话范围不允许修改账号安全信息")
    recent = session.verified_at > timezone.now() - timedelta(minutes=5)
    if user.is_management and user.security_keys.filter(is_security_key=True, backup_eligible=False, revoked_at__isnull=True).exists():
        if session.scope == "enrollment" and (user.admin_onboarding_required or not admin_keys_satisfied(user)) and recent and {"password", "email"} <= set(session.methods):
            return
        require_key_session(user, session, fresh=True)
        return
    fido_active = bool(session.credential and not session.credential.revoked_at and "fido2" in session.methods)
    if recent and (fido_active or
                   (session.scope == "enrollment" and {"password", "email"} <= set(session.methods))):
        return
    password = request.data.get("password") if password is None else password
    if isinstance(password, str) and len(password) <= 1024 and user.check_password(password):
        return
    raise PermissionDenied("请重新验证密钥，或输入当前密码")


def factor_ticket(user, *, key=None, kind="key", remember=False):
    row = webauthn.issue_challenge("login_factor", {
        "kind": kind, "key_id": key.pk if key else None,
        "remember": remember, "version": user.version,
    }, user)
    methods = []
    if kind == "enrollment" or user.email_verified_at:
        methods.append("email")
    if kind == "key":
        methods.insert(0, "password")
    if kind != "enrollment" and hasattr(user, "totp_device") and user.totp_device.confirmed_at:
        methods.insert(0, "totp")
    if key and any(webauthn.external_security_key(other) for other in
                   user.security_keys.filter(revoked_at__isnull=True).exclude(pk=key.pk)):
        methods.append("security_key")
    return Response({"factor_required": True, "ticket": str(row.pk), "methods": methods,
                     "enrollment": kind == "enrollment", "needs_email": kind == "enrollment" and not bool(user.email_verified_at)})


def password_login(request, *, throttle_checked=False):
    if not throttle_checked:
        throttle = SecurityRateThrottle()
        if not throttle.allow_request(request, None):
            raise Throttled(wait=throttle.wait())
    username, password = request.data.get("username", ""), request.data.get("password", "")
    if not isinstance(username, str) or not isinstance(password, str) or len(password) > 1024:
        raise AuthenticationFailed("账号或密码错误")
    user = User.objects.select_related("permission").filter(username=username.strip()).first()
    if user is None:
        User().set_password(password)
        raise AuthenticationFailed("账号或密码错误")
    if not user.check_password(password):
        raise AuthenticationFailed("账号或密码错误")
    if not user.is_currently_active:
        if user.active_banned_until:
            raise AuthenticationFailed(f"账号已被临时封禁至 {timezone.localtime(user.active_banned_until).strftime('%Y-%m-%d %H:%M')}")
        raise AuthenticationFailed("账号或密码错误")
    remember = request.data.get("remember_me") is True
    if user.is_management:
        exempt = not user.is_privileged and user.security_key_exempt_until and user.security_key_exempt_until > timezone.now()
        if not exempt:
            if user.security_keys.filter(is_security_key=True, backup_eligible=False, revoked_at__isnull=True).exists():
                return Response({"msg": "管理员必须使用安全密钥登录", "security_key_required": True}, status=403)
            return factor_ticket(user, kind="enrollment", remember=remember)
    if hasattr(user, "totp_device") and user.totp_device.confirmed_at:
        return factor_ticket(user, kind="password", remember=remember)
    create_session(user, ["password"], remember=remember,
                   scope="enrollment" if user.is_management and (user.admin_onboarding_required or not enrollment_complete(user)) else "full")
    record(user, "password_login", session=user._security_session)
    return make_user_response(user, True)


class RegisterSerializer(serializers.Serializer):
    username = serializers.CharField(max_length=150)
    password = serializers.CharField(max_length=1024, trim_whitespace=False, write_only=True)
    email = serializers.CharField(max_length=254)
    challenge_id = serializers.UUIDField()
    code = serializers.RegexField(r"^[0-9]{6}$")

    def validate_username(self, value):
        for validator in User._meta.get_field("username").validators:
            validator(value)
        if User.objects.filter(username=value).exists():
            raise ValidationError("该用户名已存在")
        return value

    def validate_email(self, value):
        return normalize_education_email(value)

    def validate(self, data):
        validate_password(data["password"], User(username=data["username"], email=data["email"]))
        return data


def pending_ticket(value):
    try:
        row = SecurityChallenge.objects.select_related("user__permission").filter(pk=value, purpose="login_factor").first()
    except (ValueError, DjangoValidationError):
        row = None
    if (not row or row.consumed_at or row.expires_at <= timezone.now() or row.attempts >= 5 or
        not row.user.is_currently_active or row.state["version"] != row.user.version):
        raise AuthenticationFailed("登录验证已过期，请重新登录")
    return row


def _notify_system(user, payload):
    if not getattr(user, "primary_role_id", None):
        return False
    Notification.objects.create(
        role_id=user.primary_role_id,
        type=NotificationType.SYSTEM,
        content=payload,
    )
    return True


def _eligible_async_signers(exclude_user_id):
    candidates = (
        User.objects.select_related("permission", "primary_role")
        .filter(
            Q(permission__super_admin=True) | Q(permission__superadmin_admin=True),
            is_active=True,
        )
        .exclude(pk=exclude_user_id)
    )
    eligible = []
    for item in candidates:
        if can_sign_issuance_requests(item):
            eligible.append(item)
    return eligible


def _validate_async_target_user(job):
    target = User.objects.select_related("permission", "primary_role").filter(pk=job.get("user_id")).first()
    if not target or not target.is_currently_active or suspended(target) or not enrollment_complete(target):
        return None
    if (target.version != job.get("user_version") or
            target.real_name != job.get("real_name") or
            sorted(assigned_roles(target.permission)) != job.get("roles")):
        return None
    return target


class SecurityViewset(GenericViewSet):
    permission_classes = [IsAuthenticated]
    throttle_classes = [SecurityRateThrottle]
    parser_classes = AUTH_PARSERS

    @action(detail=False, methods=["get"], url_path="watermark", throttle_classes=[])
    def watermark(self, request):
        if (not request.user.is_management or
                not admin_access_allowed(request.user, request.security_session)):
            raise PermissionDenied("仅允许当前管理会话获取自己的水印")
        from gt_admin.watermark_frames import issue
        response = Response(issue(request.user, request.security_session))
        response["Cache-Control"] = "no-store, private"
        return response

    @action(detail=False, methods=["get"], permission_classes=[AllowAny])
    def config(self, request):
        contact = SiteSecuritySetting.objects.filter(pk="material_review_contact").first()
        return Response({"education_suffixes": settings.EDUCATION_EMAIL_SUFFIXES,
                         "advanced_email": settings.ADVANCED_VERIFICATION_EMAIL,
                         "material_review_contact": contact.value if contact else settings.MATERIAL_REVIEW_CONTACT,
                         "captcha_required": settings.HCCAPTCHA_REQUIRED, "console_url": settings.CONSOLE_URL})

    @action(detail=False, methods=["post"], url_path="register-code", permission_classes=[AllowAny])
    def register_code(self, request):
        return Response(send_email_code(request.data.get("email"), "register", request))

    @action(detail=False, methods=["post"], permission_classes=[AllowAny])
    def register(self, request):
        serializer = RegisterSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data
        email = consume_email_code(data["challenge_id"], data["code"], "register", email=data["email"])
        try:
            with transaction.atomic():
                identity, school = education_identity(email)
                user = User.objects.create_user(
                    username=data["username"], password=data["password"], email=email,
                    email_verified_at=timezone.now(), real_name="", student_id=education_student_id(email), identity=identity, school=school,
                    quota=Quota.objects.create(), permission=Permission.objects.create(),
                    privacy=Privacy.objects.create(), coin=Coin.objects.create(),
                )
                Role.generate_default_role(user)
                user.coin.add_record(coin_amount.REGISTER, CoinRecordType.REGISTER, detail="注册奖励")
                create_session(user, ["password", "email"])
        except IntegrityError as exc:
            raise ValidationError("用户名或邮箱已被使用") from exc
        return make_user_response(user, True)

    @action(detail=False, methods=["post"], url_path="password-login", permission_classes=[Hccaptcha])
    def password(self, request):
        return password_login(request, throttle_checked=True)

    @action(detail=False, methods=["post"], url_path="key-login-begin", permission_classes=[AllowAny])
    def key_login_begin(self, request):
        raw_username = request.data.get("username", "")
        if raw_username is None:
            raw_username = ""
        if not isinstance(raw_username, str) or len(raw_username) > 150:
            raise ValidationError("账号格式错误")
        username = raw_username.strip()
        user = User.objects.filter(active_user_q(), username=username).first() if username else None
        keys = user.security_keys.filter(revoked_at__isnull=True) if user else ([] if username else None)
        if user and user.is_management:
            keys = keys.filter(is_security_key=True, backup_eligible=False)
        return Response(webauthn.begin_assertion("login", user=user, keys=keys,
                        state={"remember": request.data.get("remember_me") is True}))

    @action(detail=False, methods=["post"], url_path="key-login-finish", permission_classes=[AllowAny])
    def key_login_finish(self, request):
        key, row = webauthn.finish_assertion(request.data.get("challenge_id"), "login", request.data.get("credential"))
        user = key.user
        if user.is_management and not webauthn.external_security_key(key):
            raise PermissionDenied("管理员必须使用不可备份的外置安全密钥")
        if user.is_management and not allows_single_factor(key, privileged=user.is_privileged):
            return factor_ticket(user, key=key, remember=row.state["remember"])
        create_session(user, ["fido2"], credential=key, remember=row.state["remember"],
                       scope="enrollment" if user.is_management and (user.admin_onboarding_required or not enrollment_complete(user)) else "full")
        record(user, "key_login", session=user._security_session)
        return make_user_response(user, True)

    @action(detail=False, methods=["post"], url_path="factor-email", permission_classes=[AllowAny])
    def factor_email(self, request):
        row = pending_ticket(request.data.get("ticket"))
        user = row.user
        if not user.email_verified_at and row.state["kind"] != "enrollment":
            raise PermissionDenied("该账号尚未绑定已验证的教育邮箱，不能使用邮箱验证码")
        email = normalize_education_email(user.email) if user.email_verified_at else request.data.get("email")
        return Response(send_email_code(email, "login_factor", request, user=user, binding=row.pk))

    @action(detail=False, methods=["post"], url_path="factor-finish", permission_classes=[AllowAny])
    def factor_finish(self, request):
        row = pending_ticket(request.data.get("ticket"))
        with transaction.atomic():
            locked = SecurityChallenge.objects.select_for_update().get(pk=row.pk)
            if locked.consumed_at or locked.attempts >= 5:
                raise AuthenticationFailed("验证请求已失效")
            locked.attempts += 1
            locked.save(update_fields=["attempts"])
        user, method = row.user, request.data.get("method")
        verified, email, second_key = False, None, None
        if row.state["kind"] == "enrollment" and method != "email":
            raise PermissionDenied("管理员首次配置需要教育邮箱验证码")
        if row.state["kind"] == "password" and method not in {"totp", "email"}:
            raise PermissionDenied("密码登录需要验证码作为第二因素")
        if method == "password":
            password = request.data.get("password")
            verified = isinstance(password, str) and len(password) <= 1024 and user.check_password(password)
        elif method == "totp":
            verified = totp.verify(user, request.data.get("code"))
        elif method == "email":
            if not user.email_verified_at and row.state["kind"] != "enrollment":
                raise PermissionDenied("该账号尚未绑定已验证的教育邮箱，不能使用邮箱验证码")
            email = consume_email_code(request.data.get("email_challenge_id"), request.data.get("code"),
                                       "login_factor", user=user, binding=row.pk,
                                       email=normalize_education_email(user.email) if user.email_verified_at else None)
            verified = True
        elif method == "security_key" and row.state["kind"] == "key":
            second_key, proof = webauthn.finish_assertion(
                request.data.get("challenge_id"), "login_second_key", request.data.get("credential"), user=user)
            verified = (proof.state.get("factor_ticket") == str(row.pk) and
                        second_key.pk != row.state["key_id"] and webauthn.external_security_key(second_key))
            first_key = user.security_keys.filter(pk=row.state["key_id"], revoked_at__isnull=True).first()
            if first_key and webauthn.credential_data(first_key).public_key == webauthn.credential_data(second_key).public_key:
                verified = False
        if not verified:
            raise AuthenticationFailed("二次验证失败")
        with transaction.atomic():
            user = User.objects.select_for_update().select_related("permission").get(pk=user.pk)
            if not user.is_currently_active or user.version != row.state["version"]:
                raise AuthenticationFailed("账号授权已变更，请重新登录")
            if not SecurityChallenge.objects.filter(pk=row.pk, consumed_at__isnull=True, expires_at__gt=timezone.now()).update(consumed_at=timezone.now()):
                raise AuthenticationFailed("验证请求已使用")
            if email and not user.email_verified_at:
                try:
                    bind_verified_email(user, email)
                except IntegrityError as exc:
                    raise ValidationError("该邮箱已被绑定") from exc
            key = WebAuthnCredential.objects.select_for_update().filter(pk=row.state["key_id"], user=user, revoked_at__isnull=True).first()
            if row.state["kind"] == "key" and key is None:
                raise AuthenticationFailed("密钥已撤销")
            if user.is_management and key and not webauthn.external_security_key(key):
                raise AuthenticationFailed("密钥不再满足外置硬件要求")
            if second_key:
                second_key = WebAuthnCredential.objects.select_for_update().get(pk=second_key.pk)
                if not webauthn.external_security_key(second_key) or second_key.user_id != user.pk:
                    raise AuthenticationFailed("第二把密钥已失效")
            methods = ["fido2", "fido2_second" if second_key else method] if key else ["password", method]
            scope = ("enrollment" if user.is_management and (
                row.state["kind"] == "enrollment" or user.admin_onboarding_required or not enrollment_complete(user)
            ) else "full")
            create_session(user, methods, credential=key, second_credential=second_key, remember=row.state["remember"], scope=scope)
            record(user, "multifactor_login", session=user._security_session)
        return make_user_response(user, True)

    @action(detail=False, methods=["post"], url_path="factor-key-begin", permission_classes=[AllowAny])
    def factor_key_begin(self, request):
        row = pending_ticket(request.data.get("ticket"))
        if row.state["kind"] != "key":
            raise PermissionDenied("请先验证第一把安全密钥")
        first = row.user.security_keys.filter(pk=row.state["key_id"], revoked_at__isnull=True).first()
        if not webauthn.external_security_key(first):
            raise PermissionDenied("第一把安全密钥已失效")
        keys = [key for key in row.user.security_keys.filter(revoked_at__isnull=True).exclude(pk=first.pk)
                if webauthn.external_security_key(key)]
        if not keys:
            raise PermissionDenied("请先绑定另一把外置安全密钥")
        return Response(webauthn.begin_assertion("login_second_key", user=row.user, keys=keys,
                        state={"factor_ticket": str(row.pk)}))

    @action(detail=False, methods=["get"])
    def status(self, request):
        from .local_preview_keys import allowed_local_key
        data = security_summary(request.user, request.security_session)
        data["keys"] = [{"id": key.pk, "name": key.name, "is_security_key": key.is_security_key,
                         "trusted_hardware": webauthn.trusted_hardware(key), "local_preview_trusted": allowed_local_key(key),
                         "backup_eligible": key.backup_eligible,
                         "assurance_level": assurance["level"], "assurance": assurance,
                         "created_at": key.created_at, "last_used_at": key.last_used_at}
                        for key in request.user.security_keys.filter(revoked_at__isnull=True)
                        for assurance in [webauthn.credential_assurance(key)]]
        data["badges"] = visible_badges(request.user.permission)
        return Response(data)

    @action(detail=False, methods=["post"], url_path="admin-setup-begin")
    def admin_setup_begin(self, request):
        user, session = request.user, request.security_session
        if not user.is_management or session.scope not in {"full", "enrollment"}:
            raise PermissionDenied("当前会话不能配置管理员身份")
        if suspended(user):
            raise PermissionDenied("管理权限已临时冻结")
        keys = webauthn.bound_external_keys(user)
        if not keys:
            raise PermissionDenied("请先绑定外置 FIDO2 安全密钥")
        return Response(webauthn.begin_assertion("admin_setup", user=user, keys=keys,
                        state={"session_id": str(session.pk), "version": user.version}))

    @action(detail=False, methods=["post"], url_path="admin-setup-finish")
    def admin_setup_finish(self, request):
        session = request.security_session
        if not request.user.is_management or session.scope not in {"full", "enrollment"}:
            raise PermissionDenied("当前会话不能配置管理员身份")
        key, proof = webauthn.finish_assertion(request.data.get("challenge_id"), "admin_setup",
                                             request.data.get("credential"), user=request.user)
        with transaction.atomic():
            user = User.objects.select_for_update().select_related("permission").get(pk=request.user.pk)
            session = AuthSession.objects.select_for_update().select_related("second_credential").get(pk=session.pk)
            from .security_policy import valid_session, suspended, privileged_factors_satisfied
            if (proof.state.get("session_id") != str(session.pk) or proof.state.get("version") != user.version or
                    not valid_session(user, session) or not user.is_currently_active or suspended(user) or not user.is_management or
                    not enrollment_complete(user)):
                raise PermissionDenied("身份或会话状态已变化，请完成认证并重新登录")
            key = WebAuthnCredential.objects.select_for_update().get(pk=key.pk)
            if not webauthn.external_security_key(key) or key.user_id != user.pk:
                raise PermissionDenied("安全密钥已失效")
            update_fields = ["credential", "methods", "scope", "verified_at"]
            if session.second_credential_id == key.pk and session.credential_id and session.credential_id != key.pk:
                session.credential, session.second_credential = key, session.credential
                update_fields.append("second_credential")
            else:
                session.credential = key
            session.methods = list(set(session.methods) | {"fido2"})
            if not privileged_factors_satisfied(session, privileged=user.is_privileged):
                raise PermissionDenied("请先完成另一项独立登录验证")
            user.admin_onboarding_required = False
            user.save(update_fields=["admin_onboarding_required"])
            session.scope = "full"
            session.verified_at = timezone.now()
            session.save(update_fields=update_fields)
            user._security_session = session
            record(user, "admin_onboarding_completed", session=session)
        return make_user_response(user, True)

    @action(detail=False, methods=["post"], url_path="key-register-begin")
    def key_register_begin(self, request):
        require_account_factor(request)
        if not request.user.email_verified_at:
            raise PermissionDenied("请先验证教育邮箱")
        if request.user.security_keys.filter(revoked_at__isnull=True).count() >= 20:
            raise ValidationError("最多绑定 20 个凭据")
        if request.data.get("kind", "security_key") == "security_key" and request.user.security_keys.filter(is_security_key=True, revoked_at__isnull=True).count() >= 3:
            raise ValidationError("每个账号最多绑定 3 把安全密钥")
        raw_name = request.data.get("name")
        name = raw_name.strip()[:80] if isinstance(raw_name, str) and raw_name.strip() else "安全密钥"
        return Response(webauthn.begin_registration(
            request.user,
            kind=request.data.get("kind", "security_key"),
            name=name,
            resident_key=request.data.get("resident_key", "preferred"),
        ))

    @action(detail=False, methods=["post"], url_path="key-register-finish")
    def key_register_finish(self, request):
        require_account_factor(request)
        if not request.user.email_verified_at:
            raise PermissionDenied("请先验证教育邮箱")
        key = webauthn.finish_registration(request.user, request.data.get("challenge_id"), request.data.get("credential"))
        record(request.user, "key_registered", object_type="credential", object_id=key.pk, session=request.security_session)
        return Response({
            "msg": "密钥已绑定",
            "id": key.pk,
            "is_security_key": key.is_security_key,
            "high_assurance": high_assurance(key),
            "admin_keys_satisfied": admin_keys_satisfied(request.user) if request.user.is_management else True,
            "external_key_count": webauthn.distinct_external_key_count(
                request.user.security_keys.filter(is_security_key=True, backup_eligible=False, revoked_at__isnull=True)
            ),
        })

    @action(detail=False, methods=["post"], url_path="key-remove")
    def key_remove(self, request):
        require_account_factor(request)
        user = request.user
        key_id = request.data.get("key_id")
        if type(key_id) is not int or key_id <= 0:
            raise ValidationError("密钥不存在")
        with transaction.atomic():
            User.objects.select_for_update().get(pk=user.pk)
            keys = user.security_keys.select_for_update().filter(revoked_at__isnull=True)
            key = keys.filter(pk=key_id).first()
            if not key:
                raise ValidationError("密钥不存在")
            if user.is_management and key.is_security_key:
                remaining = list(keys.exclude(pk=key.pk).filter(is_security_key=True, backup_eligible=False))
                if not remaining:
                    raise PermissionDenied("管理员必须保留至少一把安全密钥")
                if (not user.admin_onboarding_required and
                        not (any(high_assurance(item) for item in remaining) or webauthn.distinct_external_key_count(remaining) >= 2)):
                    raise PermissionDenied("管理员需至少保留两把不同的普通安全密钥，或一把 FIPS 140-2 L2 / CC EAL4+ 以上高认证安全密钥")
            key.revoked_at = timezone.now()
            key.save(update_fields=["revoked_at"])
            AuthSession.objects.filter(Q(credential=key) | Q(second_credential=key)).update(revoked_at=timezone.now())
            if user.is_management and not admin_keys_satisfied(user):
                AuthSession.objects.filter(user=user, revoked_at__isnull=True).exclude(scope="enrollment").update(revoked_at=timezone.now())
            record(user, "key_revoked", object_type="credential", object_id=key.pk, session=request.security_session)
        return Response({"msg": "凭据已撤销"})

    @action(detail=False, methods=["post"], url_path="reauth-begin")
    def reauth_begin(self, request):
        session = request.security_session
        if session.scope == "impersonation":
            raise PermissionDenied("代登录不能进行安全授权")
        if session.scope not in {"full", "enrollment"}:
            raise PermissionDenied("当前会话范围不允许重新验证")
        if request.user.is_management:
            keys = webauthn.bound_external_keys(request.user)
            if not keys:
                raise PermissionDenied("请先绑定外置 FIDO2 安全密钥")
        else:
            keys = list(request.user.security_keys.filter(revoked_at__isnull=True))
        return Response(webauthn.begin_assertion("reauth", user=request.user, keys=keys, state={"session_id": str(session.pk)}))

    @action(detail=False, methods=["post"], url_path="reauth-finish")
    def reauth_finish(self, request):
        session = request.security_session
        if session.scope == "impersonation":
            raise PermissionDenied("代登录不能进行安全授权")
        if session.scope not in {"full", "enrollment"}:
            raise PermissionDenied("当前会话范围不允许重新验证")
        key, row = webauthn.finish_assertion(request.data.get("challenge_id"), "reauth", request.data.get("credential"), user=request.user)
        with transaction.atomic():
            user = User.objects.select_for_update().select_related("permission").get(pk=request.user.pk)
            session = AuthSession.objects.select_for_update().get(pk=session.pk)
            if row.state["session_id"] != str(session.pk) or not user.is_currently_active or not valid_session(user, session):
                raise PermissionDenied("登录会话不匹配或已失效")
            if user.is_management and not webauthn.external_security_key(key):
                raise PermissionDenied("管理员请使用已绑定的外置安全密钥")
            update_fields = ["credential", "methods", "verified_at"]
            if session.second_credential_id == key.pk and session.credential_id and session.credential_id != key.pk:
                session.credential, session.second_credential = key, session.credential
                update_fields.append("second_credential")
            else:
                session.credential = key
            session.methods = list(set(session.methods) | {"fido2"})
            session.verified_at = timezone.now()
            session.save(update_fields=update_fields)
        return Response({"msg": "验证成功", "fido_fresh_seconds": 300})

    @action(detail=False, methods=["post"], url_path="totp-begin")
    def totp_begin(self, request):
        require_account_factor(request)
        return Response(totp.prepare(request.user))

    @action(detail=False, methods=["post"], url_path="totp-confirm")
    def totp_confirm(self, request):
        require_account_factor(request)
        if hasattr(request.user, "totp_device") and request.user.totp_device.confirmed_at:
            raise ValidationError("已绑定二次验证器")
        if not totp.verify(request.user, request.data.get("code"), confirm=True):
            raise ValidationError("动态验证码错误或已使用")
        record(request.user, "totp_enabled", session=request.security_session)
        return Response({"msg": "二次验证器已启用"})

    @action(detail=False, methods=["post"], url_path="totp-remove")
    def totp_remove(self, request):
        require_account_factor(request)
        if not totp.verify(request.user, request.data.get("code")):
            raise ValidationError("动态验证码错误")
        request.user.totp_device.delete()
        record(request.user, "totp_disabled", session=request.security_session)
        return Response({"msg": "二次验证器已移除"})

    @action(detail=False, methods=["post"])
    def privacy(self, request):
        if request.security_session.scope == "impersonation":
            raise PermissionDenied("代登录会话不能修改账号安全信息")
        value = request.data.get("show_real_name")
        if type(value) is not bool:
            raise ValidationError("参数格式错误")
        role = request.user.primary_role
        if role is None:
            raise ValidationError("账号尚未关联注册主角色")
        role.show_user_info = value
        role.save(update_fields=["show_user_info"])
        return Response({"msg": "实名展示设置已保存", "show_real_name": value})

    @action(detail=False, methods=["post"])
    def logout(self, request):
        request.security_session.revoked_at = timezone.now()
        request.security_session.save(update_fields=["revoked_at"])
        if request._request.session.get("shou_security_session") == str(request.security_session.pk):
            request._request.session.pop("shou_security_session", None)
        return Response({"msg": "已退出"})

    @action(detail=False, methods=["post"], url_path="django-admin")
    def django_admin(self, request):
        require_key_session(request.user, request.security_session, fresh=True, privileged=True)
        if not ({"super_admin", "global_reader"} & assigned_roles(request.user.permission)):
            raise PermissionDenied("仅超级管理员与全局读者可进入 Django 管理")
        django_login(request._request, request.user, backend="django.contrib.auth.backends.ModelBackend")
        request._request.session["shou_security_session"] = str(request.security_session.pk)
        record(request.user, "django_admin_login", session=request.security_session)
        return Response({"url": "/api/django-admin/"})

    @action(detail=False, methods=["post"], url_path="console-begin")
    def console_begin(self, request):
        require_key_session(request.user, request.security_session, privileged=True)
        keys = webauthn.bound_external_keys(request.user)
        if not keys:
            raise PermissionDenied("请先绑定外置 FIDO2 安全密钥")
        return Response(webauthn.begin_assertion("console_login", user=request.user,
                        keys=keys, state={"session_id": str(request.security_session.pk)}))

    @action(detail=False, methods=["post"], url_path="console-finish")
    def console_finish(self, request):
        require_key_session(request.user, request.security_session, privileged=True)
        key, row = webauthn.finish_assertion(request.data.get("challenge_id"), "console_login", request.data.get("credential"), user=request.user)
        if (row.state["session_id"] != str(request.security_session.pk) or
                key.user_id != request.user.pk or not webauthn.external_security_key(key)):
            raise PermissionDenied("登录会话或外置安全密钥无效")
        token = secrets.token_urlsafe(48)
        ConsoleTicket.objects.create(token_hash=hashlib.sha256(token.encode()).hexdigest(), session=request.security_session,
                                     expires_at=timezone.now() + timedelta(minutes=2))
        record(request.user, "console_ticket_issued", session=request.security_session)
        return Response({"url": settings.CONSOLE_URL + "/#ticket=" + token})

    @action(detail=False, methods=["post"], url_path="impersonation-exchange")
    def impersonation_exchange(self, request):
        require_key_session(request.user, request.security_session, privileged=True)
        if "super_admin" not in assigned_roles(request.user.permission):
            raise PermissionDenied("只有超级管理员可代登录")
        token = str(request.data.get("ticket", ""))
        with transaction.atomic():
            ticket = ImpersonationTicket.objects.select_for_update().select_related(
                "session__user__permission", "session__credential", "session__second_credential"
            ).filter(
                token_hash=hashlib.sha256(token.encode()).hexdigest(), consumed_at__isnull=True,
                expires_at__gt=timezone.now(), session__parent_session=request.security_session,
            ).first()
            if not ticket:
                raise PermissionDenied("代登录授权已失效")
            target = ticket.session.user
            if (ticket.session.scope != "impersonation" or
                    ticket.session.impersonator_id != request.user.pk or
                    target.pk == request.user.pk or
                    not target.is_currently_active or
                    not valid_session(target, ticket.session)):
                raise PermissionDenied("代登录授权已失效")
            ticket.consumed_at = timezone.now()
            ticket.save(update_fields=["consumed_at"])
            target._security_session = ticket.session
            record(request.user, "impersonation_enter", object_type="user", object_id=target.pk, session=request.security_session)
            return make_user_response(target, True)

    @action(detail=False, methods=["get"], url_path="issuance-pending")
    def issuance_pending(self, request):
        require_key_session(request.user, request.security_session)
        if request.security_session.scope != "full" or (request.user.is_management and request.user.admin_onboarding_required):
            raise PermissionDenied("请先在安全中心完成管理员认证")
        if not enrollment_complete(request.user):
            raise PermissionDenied("请先完成安全密钥与身份认证")
        from .piv_public import parse_expiry, summarize_job
        now = timezone.now()
        jobs = []
        for row in SiteSecuritySetting.objects.filter(key__startswith="piv_issuance.").order_by("-updated_at"):
            job = row.value if isinstance(row.value, dict) else None
            if not job or job.get("user_id") != request.user.pk or job.get("user_version") != request.user.version:
                continue
            if job.get("state") not in {"requested", "key_ready"}:
                continue
            try:
                if parse_expiry(job.get("expires_at")) <= now:
                    continue
            except ValueError:
                continue
            jobs.append(summarize_job(job))
        return Response({"jobs": jobs})

    @action(detail=False, methods=["post"], url_path="issuance-csr")
    def issuance_csr(self, request):
        require_key_session(request.user, request.security_session)
        if request.security_session.scope != "full" or (request.user.is_management and request.user.admin_onboarding_required):
            raise PermissionDenied("请先在安全中心完成管理员认证")
        if not enrollment_complete(request.user):
            raise PermissionDenied("请先完成安全密钥与身份认证")
        from .piv_public import parse_expiry, storage_key, summarize_job, validate_target_csr
        key = storage_key(request.data.get("issuance_id"))
        csr_pem = request.data.get("csr_pem")
        card = request.data.get("card")
        with transaction.atomic():
            row = SiteSecuritySetting.objects.select_for_update().filter(pk=key).first()
            if not row or not isinstance(row.value, dict):
                raise ValidationError("签发任务不存在")
            job = dict(row.value)
            if (job.get("user_id") != request.user.pk or job.get("user_version") != request.user.version or
                    job.get("real_name") != request.user.real_name or
                    job.get("state") != "requested" or parse_expiry(job.get("expires_at")) <= timezone.now()):
                raise ValidationError("签发任务已过期、阶段不符或账号状态已变更")
            if job.get("target_csr"):
                if job["target_csr"].get("csr_pem") == csr_pem and job["target_csr"].get("card") == card:
                    return Response({"msg": "公钥请求已提交，请等待管理员使用 CA 签发", "job": summarize_job(job)})
                raise ValidationError("此任务已提交过公钥请求")
            existing = [
                item.value for item in SiteSecuritySetting.objects.filter(key__startswith="piv_issuance.")
                if isinstance(item.value, dict)
            ]
            validate_target_csr(job, csr_pem, card, existing)
            job["target_csr"] = {
                "csr_pem": csr_pem,
                "card": card,
                "submitted_at": timezone.now().isoformat(),
            }
            row.value = job
            row.save(update_fields=["value", "updated_at"])
        record(request.user, "issuance_target_csr", object_type="issuance", object_id=job["issuance_id"],
               session=request.security_session)
        return Response({"msg": "公钥请求已提交，请等待管理员使用 CA 签发", "job": summarize_job(job)})

    @action(detail=False, methods=["post"], url_path="issuance-proof")
    def issuance_proof(self, request):
        require_key_session(request.user, request.security_session)
        if request.security_session.scope != "full" or (request.user.is_management and request.user.admin_onboarding_required):
            raise PermissionDenied("请先在安全中心完成管理员认证")
        if not enrollment_complete(request.user):
            raise PermissionDenied("请先完成安全密钥与身份认证")
        from .piv_public import parse_expiry, storage_key, summarize_job, validate_target_proof
        key = storage_key(request.data.get("issuance_id"))
        proof = request.data.get("proof")
        card_slot = request.data.get("card_slot")
        chain_slots = request.data.get("chain_slots")
        with transaction.atomic():
            row = SiteSecuritySetting.objects.select_for_update().filter(pk=key).first()
            if not row or not isinstance(row.value, dict):
                raise ValidationError("签发任务不存在")
            job = dict(row.value)
            if (job.get("user_id") != request.user.pk or job.get("user_version") != request.user.version or
                    job.get("real_name") != request.user.real_name or
                    job.get("state") != "key_ready" or parse_expiry(job.get("expires_at")) <= timezone.now()):
                raise ValidationError("签发任务已过期、阶段不符或账号状态已变更")
            if job.get("target_proof"):
                raise ValidationError("此任务已提交过持钥证明")
            chosen_slot = validate_target_proof(job, proof, card_slot=card_slot, chain_slots=chain_slots)
            target_proof = {
                "proof": proof,
                "card_slot": chosen_slot,
                "readback_verified": True,
                "onsite_confirmed": True,
                "submitted_at": timezone.now().isoformat(),
            }
            if chain_slots is not None:
                target_proof["chain_slots"] = chain_slots
            job["target_proof"] = target_proof
            row.value = job
            row.save(update_fields=["value", "updated_at"])
        record(request.user, "issuance_target_proof", object_type="issuance", object_id=job["issuance_id"],
               session=request.security_session)
        return Response({"msg": "持钥证明已提交，请等待管理员完成激活", "job": summarize_job(job)})

    @action(detail=False, methods=["get"], url_path="helper-download", permission_classes=[AllowAny])
    def helper_download(self, request):
        from .piv_public import build_helper_zip_bytes

        package_path = getattr(settings, "PIV_HELPER_PACKAGE_PATH", "")
        if package_path:
            pkg = Path(package_path)
            if pkg.is_file():
                raw = pkg.read_bytes()
                response = HttpResponse(raw, content_type="application/octet-stream")
                response["Content-Disposition"] = f'attachment; filename="{pkg.name}"'
                response["Content-Length"] = str(len(raw))
                response["Cache-Control"] = "no-store"
                return response

        configured_dir = getattr(settings, "PIV_HELPER_SOURCE_DIR", "")
        source_dir = Path(configured_dir) if configured_dir else (Path(settings.BASE_DIR).parent / "shougt-sa")
        data = build_helper_zip_bytes(source_dir)
        response = HttpResponse(data, content_type="application/zip")
        response["Content-Disposition"] = 'attachment; filename="shou-smartcard-helper-windows.zip"'
        response["Content-Length"] = str(len(data))
        response["Cache-Control"] = "no-store"
        return response

    @action(detail=False, methods=["get"], url_path="self-issuance-info")
    def self_issuance_info(self, request):
        require_key_session(request.user, request.security_session, privileged=True)
        from .piv_public import collect_self_issuance_authorities, load_piv_tls_config
        roles = sorted(assigned_roles(request.user.permission))
        tls_config = load_piv_tls_config()
        if not tls_config:
            return Response({
                "available": False,
                "roles": roles,
                "site_ca_count": 0,
                "super_admin_card_count": 0,
                "superadmin_admin_card_count": 0,
                "authorities_summary": [],
            })
        data = collect_self_issuance_authorities(request.user, tls_config, temporary=True)
        avail = data["availability"]
        return Response({
            "available": True,
            "roles": roles,
            "site_ca_count": avail["site_ca_count"],
            "super_admin_card_count": avail["super_admin_card_count"],
            "superadmin_admin_card_count": avail["superadmin_admin_card_count"],
            "authorities_summary": avail["all_descriptors"],
        })

    @action(detail=False, methods=["post"], url_path="self-issuance-begin")
    def self_issuance_begin(self, request):
        require_key_session(request.user, request.security_session, fresh=True, privileged=True)
        from .piv_public import (
            ALGORITHMS, canonical, collect_self_issuance_authorities,
            load_piv_tls_config, storage_key, summarize_job,
        )
        roles = sorted(assigned_roles(request.user.permission))
        if not (set(roles) & PRIVILEGED_ROLES):
            raise PermissionDenied("仅特权管理账号可执行现场证书签发")
        temporary = request.data.get("temporary", False)
        if type(temporary) is not bool:
            raise ValidationError("签发类型格式错误")
        async_request = request.data.get("async_request", False)
        if type(async_request) is not bool:
            raise ValidationError("申请模式格式错误")
        priv_expires_at = request.user.permission.privileged_expires_at
        if priv_expires_at is not None and not temporary:
            raise PermissionDenied("临时特权账号仅可申请短期临时证书")
        tls_config = load_piv_tls_config()
        if not tls_config:
            raise ValidationError("当前站点尚未配置现场自助签发 CA 参数")
        validity_days = None
        if temporary:
            validity_days = request.data.get("validity_days", 36)
            if type(validity_days) is not int or not 1 <= validity_days <= 36:
                raise ValidationError("临时证书有效期必须在 1 至 36 天之间（严格短于 37 天）")
        if priv_expires_at is not None:
            if priv_expires_at <= timezone.now() or timezone.now() + timedelta(days=validity_days) > priv_expires_at:
                raise ValidationError("临时证书有效期不得超过当前临时特权到期时间")
        delegated_ca = bool(not temporary and (set(roles) & {"super_admin", "superadmin_admin"}))
        data = collect_self_issuance_authorities(request.user, tls_config, temporary=temporary)
        if not data["authorities"]:
            raise ValidationError("当前没有可用的签发 CA 或其他超管/超级特权 CA 证书")
        now = timezone.now()
        issuance_id = str(uuid.uuid4())
        expiry_delta = timedelta(days=7) if async_request else timedelta(minutes=30)
        job = {
            "issuance_id": issuance_id,
            "self_service": True,
            "async_request": async_request,
            "actor_id": request.user.pk,
            "user_id": request.user.pk,
            "user_version": request.user.version,
            "requester_username": request.user.username,
            "real_name": request.user.real_name,
            "roles": roles,
            "temporary": temporary,
            "validity_days": validity_days,
            "delegated_ca": delegated_ca,
            "delegated_authorities": data["delegated_fps"],
            "authority_descriptors": data["authority_descriptors"],
            "nonce": secrets.token_urlsafe(32),
            "state": "requested",
            "created_at": now.isoformat(),
            "expires_at": (now + expiry_delta).isoformat(),
            "algorithms": list(ALGORITHMS),
            "format_version": 2,
            "authorities": data["authorities"],
            "roots": data["roots"],
        }
        SiteSecuritySetting.objects.create(key=storage_key(issuance_id), value=json.loads(canonical(job).decode("utf-8")))
        record(request.user, "self_issuance_begin", object_type="issuance", object_id=issuance_id,
               details={"temporary": temporary, "validity_days": validity_days, "async_request": async_request},
               session=request.security_session)
        return Response({"job": summarize_job(job), "availability": data["availability"]})

    @action(detail=False, methods=["post"], url_path="self-issuance-key")
    def self_issuance_key(self, request):
        require_key_session(request.user, request.security_session, fresh=True, privileged=True)
        from .piv_public import parse_expiry, storage_key, summarize_job, validate_target_csr
        key = storage_key(request.data.get("issuance_id"))
        csr_pem = request.data.get("csr_pem")
        card = request.data.get("card")
        current_roles = sorted(assigned_roles(request.user.permission))
        now = timezone.now()
        with transaction.atomic():
            row = SiteSecuritySetting.objects.select_for_update().filter(pk=key).first()
            if not row or not isinstance(row.value, dict):
                raise ValidationError("签发任务不存在")
            job = dict(row.value)
            if (not job.get("self_service") or job.get("user_id") != request.user.pk or
                    job.get("user_version") != request.user.version or
                    job.get("real_name") != request.user.real_name or
                    job.get("roles") != current_roles or
                    job.get("state") != "requested" or parse_expiry(job.get("expires_at")) <= now):
                raise ValidationError("签发任务已过期、阶段不符或账号角色已变更")
            existing = [
                item.value for item in SiteSecuritySetting.objects.filter(key__startswith="piv_issuance.")
                if isinstance(item.value, dict)
            ]
            pub_sha = validate_target_csr(job, csr_pem, card, existing)
            job.update(
                state="key_ready",
                csr_pem=csr_pem,
                card=card,
                public_key_sha256=pub_sha,
                write_nonce=secrets.token_urlsafe(32),
                csr_submitted_at=now.isoformat(),
            )
            row.value = job
            row.save(update_fields=["value", "updated_at"])
        notified_count = 0
        if job.get("async_request"):
            kind_text = f"短期临时最终证书 {job.get('validity_days')} 天" if job.get("temporary") else "长期标准证书"
            payload = {
                "kind": "piv_sign_request",
                "issuance_id": job["issuance_id"],
                "title": "待签署特权管理证书申请",
                "message": (
                    f"{request.user.real_name}（{request.user.username}）已提交硬件公钥请求"
                    f"（{kind_text}），请前往「特权管理证书签发」使用 CA 卡 / 超管卡 / 超级特权卡协助签署。"
                ),
                "requester_name": request.user.real_name,
                "requester_username": request.user.username,
                "temporary": bool(job.get("temporary")),
                "validity_days": job.get("validity_days"),
                "route": "/security/issuance",
            }
            for signer in _eligible_async_signers(request.user.pk):
                if _notify_system(signer, payload):
                    notified_count += 1
        record(request.user, "self_issuance_key", object_type="issuance", object_id=job["issuance_id"],
               details={"async_request": bool(job.get("async_request")), "notified_signers": notified_count},
               session=request.security_session)
        return Response({"job": summarize_job(job), "notified_signers": notified_count})

    @action(detail=False, methods=["post"], url_path="self-issuance-cancel")
    def self_issuance_cancel(self, request):
        require_key_session(request.user, request.security_session, privileged=True)
        from .piv_public import storage_key
        key = storage_key(request.data.get("issuance_id"))
        with transaction.atomic():
            row = SiteSecuritySetting.objects.select_for_update().filter(pk=key).first()
            if not row or not isinstance(row.value, dict):
                raise ValidationError("签发任务不存在")
            job = dict(row.value)
            if not job.get("self_service") or job.get("user_id") != request.user.pk:
                raise ValidationError("签发任务不存在或不属于当前账号")
            if job.get("state") == "complete":
                raise ValidationError("已完成的签发任务不可撤销")
            if job.get("state") == "cancelled":
                return Response({"msg": "该申请已撤销"})
            job.update(state="cancelled", cancelled_at=timezone.now().isoformat())
            row.value = job
            row.save(update_fields=["value", "updated_at"])
        record(request.user, "self_issuance_cancel", object_type="issuance", object_id=job["issuance_id"],
               session=request.security_session)
        return Response({"msg": "已撤销该离线证书申请"})

    @action(detail=False, methods=["get"], url_path="issuance-sign-queue")
    def issuance_sign_queue(self, request):
        require_key_session(request.user, request.security_session, privileged=True)
        if not can_sign_issuance_requests(request.user):
            raise PermissionDenied("仅非临时授权的超级管理员或特权超级管理员可查看待签署证书队列")
        from .piv_public import collect_self_issuance_authorities, load_piv_tls_config, parse_expiry, summarize_job
        tls_config = load_piv_tls_config()
        if not tls_config:
            return Response({"jobs": []})
        now = timezone.now()
        queue = []
        for row in SiteSecuritySetting.objects.filter(key__startswith="piv_issuance.").order_by("-updated_at"):
            job = row.value if isinstance(row.value, dict) else None
            if (not job or job.get("async_request") is not True or job.get("state") != "key_ready" or
                    job.get("signed_chain_pem") or job.get("user_id") == request.user.pk):
                continue
            try:
                if parse_expiry(job.get("expires_at")) <= now:
                    continue
            except ValueError:
                continue
            target = _validate_async_target_user(job)
            if target is None:
                continue
            refreshed = collect_self_issuance_authorities(target, tls_config, temporary=bool(job.get("temporary")))
            if not refreshed["authorities"]:
                continue
            view_job = {
                **job,
                "authorities": refreshed["authorities"],
                "authority_descriptors": refreshed["authority_descriptors"],
                "delegated_authorities": refreshed["delegated_fps"],
                "roots": refreshed["roots"],
            }
            queue.append(summarize_job(view_job))
        return Response({"jobs": queue})

    @action(detail=False, methods=["post"], url_path="issuance-sign-submit")
    def issuance_sign_submit(self, request):
        require_key_session(request.user, request.security_session, fresh=True, privileged=True)
        if not can_sign_issuance_requests(request.user):
            raise PermissionDenied("仅非临时授权的超级管理员或特权超级管理员可签署其他管理员证书")
        from .piv_public import (
            collect_self_issuance_authorities, fingerprint, load_piv_tls_config,
            parse_expiry, storage_key, summarize_job, validate_signed_chain,
        )
        tls_config = load_piv_tls_config()
        if not tls_config:
            raise ValidationError("当前站点尚未配置签发 CA 参数")
        key = storage_key(request.data.get("issuance_id"))
        raw_chain = request.data.get("chain_pem")
        issuer_slot = request.data.get("issuer_slot")
        now = timezone.now()
        with transaction.atomic():
            row = SiteSecuritySetting.objects.select_for_update().filter(pk=key).first()
            if not row or not isinstance(row.value, dict):
                raise ValidationError("签发任务不存在")
            job = dict(row.value)
            if (job.get("async_request") is not True or job.get("state") != "key_ready" or
                    parse_expiry(job.get("expires_at")) <= now):
                raise ValidationError("该离线申请已过期或状态不允许签署")
            if job.get("signed_chain_pem"):
                raise ValidationError("该申请已由其他管理员签署完成，请勿重复签署")
            if job.get("user_id") == request.user.pk:
                raise ValidationError("不能在此队列签署本人申请，请使用现场自助签发或等待其他管理员签署")
            target = _validate_async_target_user(job)
            if target is None:
                raise ValidationError("申请人账号状态、实名或角色已变更，请重新提交申请")
            refreshed = collect_self_issuance_authorities(target, tls_config, temporary=bool(job.get("temporary")))
            job.update(
                authorities=refreshed["authorities"],
                authority_descriptors=refreshed["authority_descriptors"],
                delegated_authorities=refreshed["delegated_fps"],
                roots=refreshed["roots"],
            )
            leaf, chain, issuer_kind, issuer_label = validate_signed_chain(
                job, raw_chain, tls_config, requester_user=target,
            )
            target_priv_exp = target.permission.privileged_expires_at
            if target_priv_exp is not None and (job.get("delegated_ca") or not job.get("temporary") or leaf.not_valid_after_utc > target_priv_exp):
                raise ValidationError("临时特权账号证书有效期不得超过特权到期时间")
            if issuer_kind != "ca_card":
                cert_row = ClientCertificateIdentity.objects.filter(
                    fingerprint=fingerprint(chain[0]),
                    revoked_at__isnull=True,
                ).first()
                if not cert_row or cert_row.user_id != request.user.pk:
                    raise PermissionDenied("仅允许使用本人名下的超管卡 / 超级特权卡或站点 CA 卡签署")
            signer_name = request.user.real_name or request.user.username
            job.update(
                signed_chain_pem=raw_chain,
                issuer_kind=issuer_kind,
                issuer_label=issuer_label,
                signed_by_user_id=request.user.pk,
                signed_by_name=signer_name,
                signed_at=now.isoformat(),
            )
            if isinstance(issuer_slot, str) and len(issuer_slot) <= 8:
                job["issuer_slot"] = issuer_slot
            row.value = job
            row.save(update_fields=["value", "updated_at"])
        _notify_system(target, {
            "kind": "piv_sign_completed",
            "issuance_id": job["issuance_id"],
            "title": "您的特权管理证书已签署完成",
            "message": f"{signer_name} 已使用【{issuer_label}】签署了您的硬件证书，请前往「特权管理证书签发」导入原智能卡 / TPM 并完成激活。",
            "signer_name": signer_name,
            "issuer_label": issuer_label,
            "route": "/security/issuance",
        })
        record(
            request.user, "issuance_remote_sign", object_type="issuance", object_id=job["issuance_id"],
            details={"target_user_id": target.pk, "issuer_kind": issuer_kind, "leaf_fingerprint": fingerprint(leaf)},
            session=request.security_session,
        )
        return Response({
            "msg": f"已使用【{issuer_label}】完成签署，已通知申请人导入证书链并激活",
            "job": summarize_job(job),
        })

    @action(detail=False, methods=["post"], url_path="self-issuance-finish")
    def self_issuance_finish(self, request):
        require_key_session(request.user, request.security_session, fresh=True, privileged=True)
        from .piv_public import (
            fingerprint, load_piv_tls_config, parse_expiry, storage_key,
            summarize_job, validate_signed_chain, validate_target_proof,
        )
        tls_config = load_piv_tls_config()
        if not tls_config:
            raise ValidationError("当前站点尚未配置现场自助签发 CA 参数")
        if request.data.get("readback_verified") is not True or request.data.get("onsite_confirmed") is not True:
            raise ValidationError("缺少现场写入 / 导出与持钥确认标记")
        key = storage_key(request.data.get("issuance_id"))
        raw_chain = request.data.get("chain_pem")
        proof = request.data.get("proof")
        card_slot = request.data.get("card_slot")
        chain_slots = request.data.get("chain_slots")
        current_roles = sorted(assigned_roles(request.user.permission))
        with transaction.atomic():
            row = SiteSecuritySetting.objects.select_for_update().filter(pk=key).first()
            if not row or not isinstance(row.value, dict):
                raise ValidationError("签发任务不存在")
            job = dict(row.value)
            if (not job.get("self_service") or job.get("user_id") != request.user.pk or
                    job.get("user_version") != request.user.version or
                    job.get("real_name") != request.user.real_name or
                    job.get("roles") != current_roles or
                    job.get("state") != "key_ready" or parse_expiry(job.get("expires_at")) <= timezone.now()):
                raise ValidationError("签发任务已过期、阶段不符或账号角色已变更")
            if job.get("async_request"):
                signed_chain = job.get("signed_chain_pem")
                if not isinstance(signed_chain, list) or len(signed_chain) < 2:
                    raise ValidationError("该离线申请尚未由有权限的超管或 CA 管理员签署")
                if raw_chain is None:
                    raw_chain = signed_chain
                elif raw_chain != signed_chain:
                    raise ValidationError("提交的证书链与管理员已签署的证书链不一致")
            leaf, chain, issuer_kind, issuer_label = validate_signed_chain(
                job, raw_chain, tls_config, requester_user=request.user,
            )
            priv_expires_at = request.user.permission.privileged_expires_at
            if priv_expires_at is not None and (job.get("delegated_ca") or not job.get("temporary") or leaf.not_valid_after_utc > priv_expires_at):
                raise ValidationError("临时特权账号证书有效期不得超过特权到期时间")
            validate_target_proof(
                job, proof, card_slot=card_slot, chain_slots=chain_slots, raw_chain=raw_chain,
            )
            leaf_fp = fingerprint(leaf)
            if ClientCertificateIdentity.objects.filter(fingerprint=leaf_fp).exists():
                raise ValidationError("该客户端证书已登记")
            ClientCertificateIdentity.objects.create(
                fingerprint=leaf_fp,
                user=request.user,
                real_name=request.user.real_name,
                issuer_fingerprint=fingerprint(chain[0]),
                serial_number=str(leaf.serial_number),
                expires_at=leaf.not_valid_after_utc,
                is_ca=bool(job.get("delegated_ca")),
                is_temporary=bool(job.get("temporary")),
                certificate_pem=raw_chain[0],
            )
            job.update(
                state="complete",
                certificate_fingerprint=leaf_fp,
                issuer_kind=issuer_kind,
                issuer_label=issuer_label,
                completed_at=timezone.now().isoformat(),
                chain_pem=raw_chain,
            )
            row.value = job
            row.save(update_fields=["value", "updated_at"])
        record(
            request.user, "self_issuance_finish", object_type="issuance", object_id=job["issuance_id"],
            details={"certificate": leaf_fp, "issuer_kind": issuer_kind, "temporary": bool(job.get("temporary"))},
            session=request.security_session,
        )
        return Response({
            "msg": f"已通过{issuer_label}完成现场签发并登记客户端证书",
            "job": summarize_job(job),
            "certificate": {
                "fingerprint": leaf_fp,
                "expires_at": leaf.not_valid_after_utc,
                "is_ca": bool(job.get("delegated_ca")),
                "is_temporary": bool(job.get("temporary")),
                "issuer_kind": issuer_kind,
                "issuer_label": issuer_label,
            },
        })
