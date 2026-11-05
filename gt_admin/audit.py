import hashlib
import hmac
from django.conf import settings
from django.db import transaction
from gt_auth.roles import assigned_roles
from .models import AdminAuditLog


def watermark_id(session):
    if not session:
        return ""
    return hmac.new(settings.SECRET_KEY.encode(), f"watermark:{session.pk}".encode(), hashlib.sha256).hexdigest()[:24]


def watermark_context(request):
    return {"shou_admin_marker": watermark_id(getattr(request, "gt_security_session", None))}


def record(actor, action, *, object_type="", object_id="", outcome="success", details=None, session=None):
    return AdminAuditLog.objects.create(
        actor_id=actor.pk if actor else None, actor_name=actor.username if actor else "",
        roles=sorted(assigned_roles(actor.permission)) if actor else [], action=action,
        object_type=object_type, object_id=str(object_id), outcome=outcome,
        details=details or {}, session_id=str(session.pk) if session else "", watermark_id=watermark_id(session),
    )


class AdminAuditMiddleware:
    """Log management reads and writes in the same transaction as the request.

    Store field names, never passwords, password hashes, TOTP seeds, or assertion bodies.
    The separate console writes the same table through its database adapter.
    """
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        with transaction.atomic():
            response = self.get_response(request)
            user = getattr(request, "user", None)
            session = getattr(request, "gt_security_session", None)
            if user and user.is_authenticated and session and session.scope == "impersonation":
                record(session.parent_session.user, f"impersonation:{request.method} {request.path}"[:128],
                       object_type="user", object_id=user.pk, outcome="success" if response.status_code < 400 else "denied",
                       details={"status": response.status_code, "impersonated_user_id": user.pk}, session=session)
            elif user and user.is_authenticated and getattr(user, "is_management", False):
                path = request.path.removeprefix("/api")
                if path.startswith(("/admin/", "/django-admin/", "/report/", "/image/", "/video/", "/file/", "/alumni/")):
                    record(user, f"{request.method} {path}"[:128], outcome="success" if response.status_code < 400 else "denied",
                           details={"status": response.status_code}, session=getattr(request, "gt_security_session", None))
                    response["Cache-Control"] = "no-store, private"
                    response["X-Shou-Watermark"] = watermark_id(getattr(request, "gt_security_session", None))
            if response.status_code >= 500:
                transaction.set_rollback(True)
            return response
