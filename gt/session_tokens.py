"""Versioned HMAC tokens. Only the selected forum role is intentionally mutable."""
import base64
import hashlib
import hmac
import json
from datetime import datetime
from django.conf import settings
from django.utils import timezone
from rest_framework.exceptions import AuthenticationFailed


class GtSignature:
    @classmethod
    def calculate_signature(cls, payload):
        data = {key: value for key, value in payload.items() if key != "role_id"}
        if isinstance(data.get("exp"), datetime):
            data["exp"] = int(data["exp"].timestamp())
        encoded = json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
        return hmac.new(settings.SECRET_KEY.encode(), b"shou-session-v2:" + encoded, hashlib.sha256).hexdigest()

    @classmethod
    def decode(cls, token):
        try:
            if len(token) > 16384:
                raise ValueError()
            data, signature = token.split(".")
            payload = json.loads(base64.urlsafe_b64decode(data + "=" * (-len(data) % 4)))
            if (not isinstance(payload, dict) or payload.get("v") != 2 or
                not isinstance(payload.get("exp"), (int, float)) or
                payload["exp"] <= timezone.now().timestamp() or
                not hmac.compare_digest(cls.calculate_signature(payload), signature)):
                raise ValueError()
            return payload
        except (ValueError, TypeError, KeyError, UnicodeError, RecursionError) as exc:
            raise AuthenticationFailed("登录已失效，请重新登录") from exc
