import re
from django.core.exceptions import ValidationError as DjangoValidationError
from rest_framework import authentication, exceptions
from gt_auth.models import AuthSession, Role, active_role_q
from gt_auth.roles import assigned_roles
from gt_auth.security_policy import valid_session, admin_access_allowed, key_authenticated
from django.utils import timezone
from .session_tokens import GtSignature


class JWTAuthentication(authentication.BaseAuthentication):
    def authenticate(self, request):
        request.role, request.source, request.is_server = None, "web", False
        request.security_session = None
        header = request.headers.get("Authorization")
        if not header:
            return None
        try:
            prefix, token = header.split(" ")
            if prefix not in {"JWT", "Bearer"} or "|" in token:
                raise ValueError()
        except ValueError as exc:
            raise exceptions.AuthenticationFailed("认证信息格式错误") from exc
        payload = GtSignature.decode(token)
        try:
            session = AuthSession.objects.select_related(
                "user__permission",
                "credential",
                "second_credential",
                "parent_session__user__permission",
                "parent_session__credential",
                "parent_session__second_credential",
            ).get(pk=payload.get("session_id"))
        except (AuthSession.DoesNotExist, ValueError, DjangoValidationError) as exc:
            raise exceptions.AuthenticationFailed("请重新登录") from exc
        user = session.user
        if (not user.is_currently_active or type(payload.get("user_id")) is not int or
            payload.get("user_id") != user.pk or type(payload.get("user_version")) is not int or
            payload.get("user_version") != user.version or not valid_session(user, session)):
            raise exceptions.AuthenticationFailed("登录已过期或已撤销")
        if session.scope not in {"full", "enrollment", "impersonation"}:
            raise exceptions.AuthenticationFailed("登录会话范围无效，请重新登录")
        if "global_reader" in assigned_roles(user.permission) and request.method not in {"GET", "HEAD", "OPTIONS"}:
            from gt_auth.read_only import reader_protocol_allowed
            if not reader_protocol_allowed(request.path):
                raise exceptions.PermissionDenied("全局读者仅可读取数据")
        path = request.path.removeprefix("/api")
        if session.scope == "enrollment" or (user.is_management and user.admin_onboarding_required):
            if not (path.startswith("/security/") or path in {"/user/info/", "/user/email_sendcode/", "/user/email_verifycode/"}):
                raise exceptions.PermissionDenied("请先在安全中心完成管理员认证")
        if user.is_management and session.scope == "full" and not key_authenticated(session):
            if user.is_privileged or not user.security_key_exempt_until or user.security_key_exempt_until <= timezone.now():
                raise exceptions.AuthenticationFailed("请使用安全密钥重新登录；非密钥登录许可已失效")
        if session.scope == "impersonation":
            parent = session.parent_session
            if (not parent or parent.pk == session.pk or parent.user_id != session.impersonator_id or
                session.impersonator_id == user.pk or
                "super_admin" not in assigned_roles(parent.user.permission) or
                not admin_access_allowed(parent.user, parent)):
                raise exceptions.AuthenticationFailed("代登录授权已撤销")
            if (path.startswith(("/admin/", "/django-admin/", "/user/setting/", "/user/email_")) or
                (path.startswith("/security/") and path not in {"/security/config/", "/security/logout/"}) or
                (request.method not in {"GET", "HEAD", "OPTIONS"} and re.fullmatch(r"/role/(?:\d+/?)?", path))):
                raise exceptions.PermissionDenied("代登录会话仅用于站内用户操作")
        role_id = payload.get("role_id")
        if role_id is not None:
            if type(role_id) is not int:
                raise exceptions.AuthenticationFailed("角色信息格式错误")
            role = Role.objects.filter(active_role_q(), pk=role_id, deleted=False, members__user=user).first()
            if role is None:
                raise exceptions.AuthenticationFailed("当前角色不可用")
            request.role = role
        request.security_session = session
        user._security_session = session
        request._request.gt_security_session = session
        return user, session

    def authenticate_header(self, request):
        return "Bearer"
