"""User-authorized local fixture: keep the actual key; fill test identity defaults."""
import argparse
import hashlib
import json
import os
import sys
from datetime import timedelta
from pathlib import Path

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--username", required=True)
parser.add_argument("--certificate", required=True)
args = parser.parse_args()
base = Path(__file__).resolve().parents[1]
directory = base / ".local-preview"
os.environ["SHOUGT_MODE"] = "dev"
os.environ["SHOUGT_LOCAL_PREVIEW"] = "1"
os.environ["DJANGO_SETTINGS_MODULE"] = "gt.local_preview_settings"
sys.path[:0] = [str(base), str(base.parent / "shougt-sa")]

import django
django.setup()
from django.conf import settings
from django.db import transaction
from django.utils import timezone
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from backend.config import Config
from backend.certificates import CertificateVerifier
from gt_auth.models import User, AdvancedVerification, ClientCertificateIdentity, AuthSession
from gt_auth.roles import assigned_roles
from gt_admin.audit import record

if Path(settings.DATABASES["default"]["NAME"]).resolve() != directory / "forum.sqlite3":
    raise RuntimeError("Only the persistent local preview database may be changed")
config = Config.load(directory / "console.json")
certificate = x509.load_pem_x509_certificate(Path(args.certificate).read_bytes())
identity = CertificateVerifier(config.tls).verify(certificate.public_bytes(serialization.Encoding.DER))
now = timezone.now()
pin_path = directory / "fido-local-pins.json"
pins = json.loads(pin_path.read_text(encoding="utf-8")) if pin_path.exists() else []

with transaction.atomic():
    user = User.objects.select_related("permission").get(username=args.username)
    keys = list(user.security_keys.filter(is_security_key=True, backup_eligible=False, revoked_at__isnull=True))
    if not keys:
        raise RuntimeError("Bind a genuine external FIDO credential before applying local administrator defaults")
    if not user.email_verified_at:
        raise RuntimeError("Complete the local education email verification first")
    before = {"roles": sorted(assigned_roles(user.permission)),
              "real_name": user.real_name}
    user.permission.super_admin = True
    user.permission.admin_admin = False
    user.permission.superadmin_admin = False
    user.permission.save()
    user.refresh_from_db()
    # A pinned CA belongs to the named local fixture; its CN is not a person's name.
    # Personal client certificates continue to use their reviewed CN.
    if identity.get("local_preview_ca"):
        pin = config.tls["local_ca_client"]
        if pin["user_id"] != user.pk:
            raise RuntimeError("The temporary CA certificate is pinned to another account")
        user.real_name = pin["account_name"]
    else:
        user.real_name = identity["real_name"]
    user.real_name_verified_at = user.advanced_verified_at = now
    user.version += 1
    user.save(update_fields=["real_name", "real_name_verified_at", "advanced_verified_at", "version"])
    AuthSession.objects.filter(user=user, revoked_at__isnull=True).update(revoked_at=now)
    pins = [pin for pin in pins if pin.get("user_id") != user.pk]
    for key in keys:
        pins.append({"user_id": user.pk, "credential_id": key.pk,
                     "public_data_sha256": hashlib.sha256(key.credential_data.encode()).hexdigest(),
                     "expires_at": (now + timedelta(days=30)).isoformat(),
                     "source": "user-authorized-local-preview-only"})
    AdvancedVerification.objects.create(user=user, credential=keys[0], email=user.email, real_name=user.real_name,
        nonce="local-preview-fixture", issued_at=now, expires_at=now + timedelta(days=30),
        payload=json.dumps({"local_preview": True, "user_id": user.pk, "user_version": user.version}),
        status="approved", reviewed_at=now, review_note="用户要求填入本地默认认证；未进行真实材料审核或接收认证邮件")
    existing = ClientCertificateIdentity.objects.filter(fingerprint=identity["fingerprint"]).first()
    if existing and existing.user_id != user.pk:
        raise RuntimeError("The selected certificate is already assigned to another account")
    ClientCertificateIdentity.objects.update_or_create(fingerprint=identity["fingerprint"], defaults={
        "user": user, "real_name": user.real_name, "issuer_fingerprint": identity["issuer_fingerprint"],
        "serial_number": identity["serial_number"], "expires_at": identity["expires_at"], "revoked_at": None})
    record(None, "local_preview_super_admin", object_type="user", object_id=user.pk, details={
        "username": user.username, "before": before, "local_preview": True,
        "reason": "用户要求给 test 超管并填入默认实名及认证；保留已绑定的真实 FIDO2 凭据",
        "real_name_source": ("explicit local CA fixture account name" if identity.get("local_preview_ca")
                             else "selected PIV certificate CN; local fixture only"),
        "key_ids": [key.pk for key in keys], "hardware_attestation_claimed": False,
        "certificate": identity["fingerprint"]})
pin_path.write_text(json.dumps(pins, ensure_ascii=False, indent=2), encoding="utf-8")
(directory / "admin-preview.json").write_text(json.dumps({"username": user.username}), encoding="utf-8")
print(json.dumps({"username": user.username, "super_admin": True, "django_superuser": user.is_superuser,
                  "real_name": user.real_name, "real_keys_preserved": len(keys), "fixture_only": True,
                  "relogin_required": True}, ensure_ascii=False))
