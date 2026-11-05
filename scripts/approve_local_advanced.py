"""Explicitly approve a signed local-preview request using user-provided test identity."""
import argparse
import hashlib
import json
import os
import sys
from pathlib import Path

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--username", required=True)
parser.add_argument("--sender-name", required=True)
args = parser.parse_args()
base = Path(__file__).resolve().parents[1]
directory = base / ".local-preview"
os.environ.update(SHOUGT_MODE="dev", SHOUGT_LOCAL_PREVIEW="1", DJANGO_SETTINGS_MODULE="gt.local_preview_settings")
sys.path.insert(0, str(base))

import django
django.setup()
from django.conf import settings
from django.db import transaction
from django.utils import timezone
from gt_admin.audit import record
from gt_auth.education import education_student_id
from gt_auth.mail_identity import normalize_name
from gt_auth.models import User, AdvancedVerification, AuthSession, ClientCertificateIdentity
from gt_auth.webauthn import trusted_hardware

if not settings.LOCAL_PREVIEW_MODE or Path(settings.DATABASES["default"]["NAME"]).resolve() != directory / "forum.sqlite3":
    raise RuntimeError("Only the explicitly enabled persistent preview database may be changed")
name = normalize_name(args.sender_name)
pin_path, console_path = directory / "piv/ca-client.json", directory / "console.json"
pin = json.loads(pin_path.read_text(encoding="utf-8"))
config = json.loads(console_path.read_text(encoding="utf-8"))
now = timezone.now()
with transaction.atomic():
    user = User.objects.select_for_update().get(username=args.username)
    if user.pk != pin["user_id"] or not user.email_verified_at:
        raise RuntimeError("The local PIV account and verified email must already be configured")
    request = user.advanced_requests.select_for_update().filter(status__in=["awaiting_email", "awaiting_review"]).order_by("-issued_at").first()
    if not request or not request.signed_at or not request.assertion or request.expires_at <= now:
        raise RuntimeError("A current request genuinely signed by the existing FIDO key is required")
    if request.email != user.email or json.loads(request.payload)["user_version"] != user.version or not trusted_hardware(request.credential):
        raise RuntimeError("The signed request no longer matches the verified account or real credential")
    student_id = education_student_id(user.email)
    before = {"real_name": user.real_name, "student_id": user.student_id, "request_status": request.status}
    credential_digest = hashlib.sha256(request.credential.credential_data.encode()).hexdigest()
    request.real_name = name
    request.student_id = student_id
    request.status, request.reviewed_at = "approved", now
    request.review_note = "用户授权通过本机进阶认证；发件人测试称呼由用户指定，保留真实 FIDO 签名，未收到或伪造认证邮件"
    # Do not invent an incoming From header, DMARC result or receipt timestamp.
    request.save(update_fields=["real_name", "student_id", "status", "reviewed_at", "review_note"])
    user.real_name, user.student_id = name, student_id
    user.real_name_verified_at = user.advanced_verified_at = now
    user.version += 1
    user.save(update_fields=["real_name", "student_id", "real_name_verified_at", "advanced_verified_at", "version"])
    AuthSession.objects.filter(user=user, revoked_at__isnull=True).update(revoked_at=now)
    if ClientCertificateIdentity.objects.filter(user=user, fingerprint=pin["sha256"], revoked_at__isnull=True).update(real_name=name) != 1:
        raise RuntimeError("The existing pinned PIV identity is missing")
    record(None, "local_advanced_verification_approved", object_type="user", object_id=user.pk, details={
        "username": user.username, "verification_id": str(request.pk), "local_preview": True,
        "before": before, "after": {"real_name": name, "student_id": student_id},
        "identity_source": "user-provided local fixture sender name", "real_mail_received": False,
        "existing_fido_signature_preserved": True, "credential_id": request.credential_id,
        "credential_public_sha256": credential_digest, "piv_certificate": pin["sha256"]})
pin["account_name"] = name
config["tls"]["local_ca_client"]["account_name"] = name
pin_path.write_text(json.dumps(pin, ensure_ascii=False, indent=2), encoding="utf-8")
console_path.write_text(json.dumps(config, ensure_ascii=False, indent=2), encoding="utf-8")
print(json.dumps({"username": user.username, "real_name": name, "student_id": student_id,
                  "status": "approved", "real_mail_received": False, "fido_signature_preserved": True,
                  "relogin_required": True}, ensure_ascii=False))
