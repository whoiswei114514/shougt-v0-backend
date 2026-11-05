import hashlib
import secrets
from datetime import timedelta

from django.conf import settings
from django.contrib.auth import login as django_login
from django.contrib.auth.password_validation import validate_password
from django.core.cache import cache
from django.core.exceptions import ValidationError as DjangoValidationError
from django.db import IntegrityError, transaction
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
                     WebAuthnCredential, ConsoleTicket, SiteSecuritySetting, ImpersonationTicket)
from .roles import ROLE_LABELS, visible_badges
from .security_policy import (enrollment_complete, key_authenticated, require_key_session,
                              high_assurance, admin_access_allowed, security_summary)
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
    if user.is_management and user.security_keys.filter(revoked_at__isnull=True).exists():
        require_key_session(user, session, fresh=True)
        return
    recent = session.verified_at > timezone.now() - timedelta(minutes=5)
    if recent and ("fido2" in session.methods or
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
    methods = ["email"] if kind in {"enrollment", "password"} else ["password", "email"]
    if kind != "enrollment" and hasattr(user, "totp_device") and user.totp_device.confirmed_at:
        methods.insert(0, "totp")
    return Response({"factor_required": True, "ticket": str(row.pk), "methods": methods,
                     "enrollment": kind == "enrollment", "needs_email": not bool(user.email_verified_at)})


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
    if not user.is_active or not user.check_password(password):
        raise AuthenticationFailed("账号或密码错误")
    remember = request.data.get("remember_me") is True
    if user.is_management:
        exempt = not user.is_privileged and user.security_key_exempt_until and user.security_key_exempt_until > timezone.now()
        if not exempt:
            if user.security_keys.filter(is_security_key=True, revoked_at__isnull=True).exists():
                return Response({"msg": "管理员必须使用安全密钥登录", "security_key_required": True}, status=403)
            return factor_ticket(user, kind="enrollment", remember=remember)
    if hasattr(user, "totp_device") and user.totp_device.confirmed_at:
        return factor_ticket(user, kind="password", remember=remember)
    create_session(user, ["password"], remember=remember,
                   scope="enrollment" if user.is_management and not enrollment_complete(user) else "full")
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
        not row.user.is_active or row.state["version"] != row.user.version):
        raise AuthenticationFailed("登录验证已过期，请重新登录")
    return row


class SecurityViewset(GenericViewSet):
    permission_classes = [IsAuthenticated]
    throttle_classes = [SecurityRateThrottle]
    parser_classes = AUTH_PARSERS

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
        username = str(request.data.get("username", "")).strip()
        user = User.objects.filter(username=username, is_active=True).first() if username else None
        keys = user.security_keys.filter(revoked_at__isnull=True) if user else ([] if username else None)
        if user and user.is_management:
            keys = keys.filter(is_security_key=True, backup_eligible=False)
        return Response(webauthn.begin_assertion("login", user=user, keys=keys,
                        state={"remember": request.data.get("remember_me") is True}))

    @action(detail=False, methods=["post"], url_path="key-login-finish", permission_classes=[AllowAny])
    def key_login_finish(self, request):
        key, row = webauthn.finish_assertion(request.data.get("challenge_id"), "login", request.data.get("credential"))
        user = key.user
        if user.is_management and not webauthn.trusted_hardware(key):
            raise PermissionDenied("管理员必须使用提供受信任硬件证明的外置安全密钥")
        if user.is_privileged and not high_assurance(key):
            return factor_ticket(user, key=key, remember=row.state["remember"])
        create_session(user, ["fido2"], credential=key, remember=row.state["remember"],
                       scope="enrollment" if user.is_management and not enrollment_complete(user) else "full")
        record(user, "key_login", session=user._security_session)
        return make_user_response(user, True)

    @action(detail=False, methods=["post"], url_path="factor-email", permission_classes=[AllowAny])
    def factor_email(self, request):
        row = pending_ticket(request.data.get("ticket"))
        user = row.user
        email = user.email if user.email_verified_at else request.data.get("email")
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
        verified, email = False, None
        if row.state["kind"] == "enrollment" and method != "email":
            raise PermissionDenied("管理员首次配置需要教育邮箱验证码")
        if row.state["kind"] == "password" and method not in {"totp", "email"}:
            raise PermissionDenied("密码登录需要验证码作为第二因素")
        if method == "password":
            password = request.data.get("password")
            verified = isinstance(password, str) and user.check_password(password)
        elif method == "totp":
            verified = totp.verify(user, request.data.get("code"))
        elif method == "email":
            email = consume_email_code(request.data.get("email_challenge_id"), request.data.get("code"),
                                       "login_factor", user=user, binding=row.pk,
                                       email=user.email if user.email_verified_at else None)
            verified = True
        if not verified:
            raise AuthenticationFailed("二次验证失败")
        with transaction.atomic():
            if not SecurityChallenge.objects.filter(pk=row.pk, consumed_at__isnull=True).update(consumed_at=timezone.now()):
                raise AuthenticationFailed("验证请求已使用")
            if email and not user.email_verified_at:
                try:
                    bind_verified_email(user, email)
                except IntegrityError as exc:
                    raise ValidationError("该邮箱已被绑定") from exc
            key = WebAuthnCredential.objects.filter(pk=row.state["key_id"], revoked_at__isnull=True).first()
            if row.state["kind"] == "key" and key is None:
                raise AuthenticationFailed("密钥已撤销")
            methods = ["fido2", method] if key else ["password", method]
            scope = "enrollment" if user.is_management and not enrollment_complete(user) else "full"
            create_session(user, methods, credential=key, remember=row.state["remember"], scope=scope)
            record(user, "multifactor_login", session=user._security_session)
        return make_user_response(user, True)

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

    @action(detail=False, methods=["post"], url_path="key-register-begin")
    def key_register_begin(self, request):
        require_account_factor(request)
        if not request.user.email_verified_at:
            raise PermissionDenied("请先验证教育邮箱")
        if request.user.security_keys.filter(revoked_at__isnull=True).count() >= 20:
            raise ValidationError("最多绑定 20 个凭据")
        return Response(webauthn.begin_registration(request.user, kind=request.data.get("kind", "security_key"),
                                                    name=request.data.get("name", "安全密钥")))

    @action(detail=False, methods=["post"], url_path="key-register-finish")
    def key_register_finish(self, request):
        key = webauthn.finish_registration(request.user, request.data.get("challenge_id"), request.data.get("credential"))
        record(request.user, "key_registered", object_type="credential", object_id=key.pk, session=request.security_session)
        return Response({"msg": "密钥已绑定", "id": key.pk})

    @action(detail=False, methods=["post"], url_path="key-remove")
    def key_remove(self, request):
        require_account_factor(request)
        user = request.user
        with transaction.atomic():
            keys = user.security_keys.select_for_update().filter(revoked_at__isnull=True)
            key = keys.filter(pk=request.data.get("key_id")).first()
            if not key:
                raise ValidationError("密钥不存在")
            if user.is_management and key.is_security_key and not keys.exclude(pk=key.pk).filter(is_security_key=True).exists():
                raise PermissionDenied("管理员必须保留至少一把安全密钥")
            key.revoked_at = timezone.now()
            key.save(update_fields=["revoked_at"])
            AuthSession.objects.filter(credential=key).update(revoked_at=timezone.now())
            record(user, "key_revoked", object_type="credential", object_id=key.pk, session=request.security_session)
        return Response({"msg": "凭据已撤销"})

    @action(detail=False, methods=["post"], url_path="reauth-begin")
    def reauth_begin(self, request):
        session = request.security_session
        if session.scope == "impersonation":
            raise PermissionDenied("代登录不能进行安全授权")
        keys = request.user.security_keys.filter(revoked_at__isnull=True)
        if session.credential_id:
            keys = keys.filter(pk=session.credential_id)
        if request.user.is_management:
            keys = keys.filter(is_security_key=True)
        return Response(webauthn.begin_assertion("reauth", user=request.user, keys=keys, state={"session_id": str(session.pk)}))

    @action(detail=False, methods=["post"], url_path="reauth-finish")
    def reauth_finish(self, request):
        key, row = webauthn.finish_assertion(request.data.get("challenge_id"), "reauth", request.data.get("credential"), user=request.user)
        session = request.security_session
        if row.state["session_id"] != str(session.pk):
            raise PermissionDenied("登录会话不匹配")
        session.credential = key
        session.methods = list(set(session.methods) | {"fido2"})
        session.verified_at = timezone.now()
        session.save(update_fields=["credential", "methods", "verified_at"])
        return Response({"msg": "验证成功"})

    @action(detail=False, methods=["post"], url_path="totp-begin")
    def totp_begin(self, request):
        require_account_factor(request)
        return Response(totp.prepare(request.user))

    @action(detail=False, methods=["post"], url_path="totp-confirm")
    def totp_confirm(self, request):
        require_account_factor(request)
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
        return Response({"msg": "已退出"})

    @action(detail=False, methods=["post"], url_path="django-admin")
    def django_admin(self, request):
        require_key_session(request.user, request.security_session, fresh=True, privileged=True)
        if not request.user.permission.super_admin:
            raise PermissionDenied("只有超级管理员可进入 Django 管理")
        django_login(request._request, request.user, backend="django.contrib.auth.backends.ModelBackend")
        request._request.session["shou_security_session"] = str(request.security_session.pk)
        record(request.user, "django_admin_login", session=request.security_session)
        return Response({"url": "/api/django-admin/"})

    @action(detail=False, methods=["post"], url_path="console-begin")
    def console_begin(self, request):
        require_key_session(request.user, request.security_session, privileged=True)
        return Response(webauthn.begin_assertion("console_login", user=request.user,
                        keys=[request.security_session.credential], state={"session_id": str(request.security_session.pk)}))

    @action(detail=False, methods=["post"], url_path="console-finish")
    def console_finish(self, request):
        require_key_session(request.user, request.security_session, privileged=True)
        _, row = webauthn.finish_assertion(request.data.get("challenge_id"), "console_login", request.data.get("credential"), user=request.user)
        if row.state["session_id"] != str(request.security_session.pk):
            raise PermissionDenied("登录会话不匹配")
        token = secrets.token_urlsafe(48)
        ConsoleTicket.objects.create(token_hash=hashlib.sha256(token.encode()).hexdigest(), session=request.security_session,
                                     expires_at=timezone.now() + timedelta(minutes=2))
        record(request.user, "console_ticket_issued", session=request.security_session)
        return Response({"url": settings.CONSOLE_URL + "/#ticket=" + token})

    @action(detail=False, methods=["post"], url_path="impersonation-exchange")
    def impersonation_exchange(self, request):
        require_key_session(request.user, request.security_session, privileged=True)
        if not request.user.permission.super_admin:
            raise PermissionDenied("只有超级管理员可代登录")
        token = str(request.data.get("ticket", ""))
        with transaction.atomic():
            ticket = ImpersonationTicket.objects.select_for_update().select_related("session__user").filter(
                token_hash=hashlib.sha256(token.encode()).hexdigest(), consumed_at__isnull=True,
                expires_at__gt=timezone.now(), session__parent_session=request.security_session,
            ).first()
            if not ticket:
                raise PermissionDenied("代登录授权已失效")
            ticket.consumed_at = timezone.now()
            ticket.save(update_fields=["consumed_at"])
            target = ticket.session.user
            target._security_session = ticket.session
            record(request.user, "impersonation_enter", object_type="user", object_id=target.pk, session=request.security_session)
            return make_user_response(target, True)
