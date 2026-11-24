"""Explicit local allowlist for existing genuine credentials; no attestation claims."""
import hashlib
import hmac
import json
from datetime import datetime
from pathlib import Path

from django.conf import settings
from django.utils import timezone


def allowed_local_key(key):
    if not (settings.DEBUG and getattr(settings, "LOCAL_PREVIEW_MODE", False) and
            settings.WEBAUTHN_RP_ID == "localhost" and key and key.is_security_key and
            not key.backup_eligible and not key.revoked_at):
        return False
    filename = getattr(settings, "LOCAL_PREVIEW_KEY_PINS_FILE", "")
    if not filename:
        return False
    try:
        entries = json.loads(Path(filename).read_text(encoding="utf-8"))
        if not isinstance(entries, list):
            return False
        fingerprint = hashlib.sha256(key.credential_data.encode()).hexdigest()
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            if (type(entry.get("credential_id")) is int and entry["credential_id"] == key.pk and
                    type(entry.get("user_id")) is int and entry["user_id"] == key.user_id and
                    isinstance(entry.get("public_data_sha256"), str) and
                    hmac.compare_digest(entry["public_data_sha256"], fingerprint)):
                expires = datetime.fromisoformat(str(entry["expires_at"]).replace("Z", "+00:00"))
                if expires.tzinfo and expires > timezone.now():
                    return True
    except (OSError, ValueError, KeyError, TypeError):
        pass
    return False
