"""Server-clock provenance snapshots; ordinary users cannot request admin metadata."""
import base64
import os
from functools import lru_cache

from django.conf import settings
from django.utils import timezone

from gt_auth.models import SiteSecuritySetting
from .audit import watermark_id
from .models import AdminAuditLog
from .watermark_codec import KEY_PREFIX, encode_frame, public_identity, signing_key


@lru_cache(maxsize=4)
def _key(secret, configured):
    seed = base64.b64decode(configured, validate=True) if configured else secret.encode()
    if configured and len(seed) != 32:
        raise ValueError("SHOUGT_WATERMARK_SIGNING_KEY must encode 32 random bytes")
    return signing_key(seed)


def issue(user, session):
    key = _key(settings.SECRET_KEY, os.environ.get("SHOUGT_WATERMARK_SIGNING_KEY", ""))
    key_id, public = public_identity(key)
    value = {"source": "main", "algorithm": "Ed25519", "public_key": public}
    registered, _ = SiteSecuritySetting.objects.get_or_create(
        pk=KEY_PREFIX + key_id, defaults={"value": value})
    if registered.value != value:
        raise ValueError("Watermark public key registration conflict")
    marker = watermark_id(session)
    operation = AdminAuditLog.objects.filter(watermark_id=marker, actor_id=user.pk).exclude(
        action__in=["password_login", "key_login", "multifactor_login", "django_admin_login",
                    "console_ticket_issued"]
    ).order_by("-id").values("id", "created_at").first()
    return encode_frame({"id": user.pk, "username": user.username, "real_name": user.real_name},
                        operation, marker, "main", key, issued_at=timezone.now())
