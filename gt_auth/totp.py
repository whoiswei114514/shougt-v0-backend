"""RFC 6238 TOTP with encrypted storage and a monotonic replay counter."""
import base64
import hashlib
import hmac
import secrets
import struct
from datetime import datetime
from urllib.parse import quote

from cryptography.fernet import Fernet
from django.conf import settings
from django.db import transaction
from django.utils import timezone
from rest_framework.exceptions import ValidationError
from .models import TotpDevice, User


def cipher():
    key = getattr(settings, "TOTP_ENCRYPTION_KEY", "")
    if not key:
        key = base64.urlsafe_b64encode(hashlib.sha256((settings.SECRET_KEY + ":totp-v1").encode()).digest())
    return Fernet(key)


def generate_code(secret, counter):
    key = base64.b32decode(secret + "=" * (-len(secret) % 8))
    mac = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = mac[-1] & 15
    return f"{(struct.unpack('>I', mac[offset:offset + 4])[0] & 0x7fffffff) % 1000000:06d}"


@transaction.atomic
def prepare(user):
    User.objects.select_for_update().get(pk=user.pk)
    device = TotpDevice.objects.select_for_update().filter(user=user).first()
    if device and device.confirmed_at:
        raise ValidationError("已绑定二次验证器")
    secret = base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")
    TotpDevice.objects.update_or_create(user=user, defaults={
        "encrypted_secret": cipher().encrypt(secret.encode()).decode(), "last_counter": -1,
    })
    uri = f"otpauth://totp/{quote('shou瓜田:' + user.username)}?secret={secret}&issuer={quote('shou瓜田')}&algorithm=SHA1&digits=6&period=30"
    return {"secret": secret, "uri": uri}


def verify(user, code, *, confirm=False):
    if not isinstance(code, str) or len(code) != 6 or not code.isascii() or not code.isdigit():
        return False
    with transaction.atomic():
        device = TotpDevice.objects.select_for_update().filter(user=user).first()
        if not device or (not confirm and not device.confirmed_at):
            return False
        secret = cipher().decrypt(device.encrypted_secret.encode()).decode()
        counter = int(timezone.now().timestamp()) // 30
        for candidate in (counter - 1, counter, counter + 1):
            if candidate > device.last_counter and hmac.compare_digest(generate_code(secret, candidate), code):
                device.last_counter = candidate
                if confirm:
                    device.confirmed_at = timezone.now()
                device.save(update_fields=["last_counter", "confirmed_at"])
                return True
    return False
