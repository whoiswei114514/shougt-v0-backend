from datetime import timedelta
from django.utils import timezone
from django.core.cache import cache
from .models import AuthSession
from gt.jwt import GtSignature


def create_session(user, methods, *, credential=None, remember=False, scope="full"):
    now = timezone.now()
    lifetime = timedelta(days=30) if remember and not user.is_management else timedelta(hours=12)
    if scope == "enrollment":
        lifetime = timedelta(minutes=20)
    session = AuthSession.objects.create(
        user=user, credential=credential, methods=list(methods), scope=scope,
        user_version=user.version, verified_at=now, expires_at=now + lifetime,
    )
    user._security_session = session
    if "fido2" in methods or "email" in methods:
        cache.set(f"captcha_valid:{user.pk}", int(now.timestamp()) + 300, timeout=300)
    user.last_login = now
    user.save(update_fields=["last_login"])
    return session


def authorization(user, session):
    if session is None:
        return None
    payload = {
        "v": 2, "user_id": user.pk, "user_version": user.version,
        "session_id": str(session.pk), "source": "web",
        "exp": int(min(session.expires_at, timezone.now() + timedelta(minutes=15)).timestamp()),
    }
    return {"payload": payload, "signature": GtSignature.calculate_signature(payload)}
