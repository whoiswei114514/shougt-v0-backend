from django.http import HttpResponseForbidden
from .models import AuthSession
from .security_policy import admin_access_allowed, require_key_session


class SecurityAdminMiddleware:
    """Django's password login is never an alternate path around WebAuthn."""
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        path = request.path.removeprefix("/api")
        if not path.startswith("/django-admin/"):
            return self.get_response(request)
        user = request.user
        session = None
        if user.is_authenticated:
            session = AuthSession.objects.select_related("credential").filter(
                pk=request.session.get("shou_security_session"), user=user,
            ).first()
        if (not user.is_authenticated or not user.permission.super_admin or
            not admin_access_allowed(user, session)):
            return HttpResponseForbidden("请先在 shou瓜田安全中心使用安全密钥登录，再进入 Django 管理。")
        if request.method not in {"GET", "HEAD", "OPTIONS"}:
            # Security-sensitive user/grant changes live exclusively in the separate console.
            if path.startswith("/django-admin/gt_auth/") or path.startswith("/django-admin/auth/"):
                return HttpResponseForbidden("账号与权限的修改请使用特权管理页面。")
            try:
                require_key_session(user, session, fresh=True, privileged=True)
            except Exception:
                return HttpResponseForbidden("请在安全中心重新验证安全密钥后操作。")
        request.gt_security_session = session
        user._security_session = session
        return self.get_response(request)
