"""Explicit loopback preview. Database and genuine WebAuthn registrations persist on disk."""
import json
import os
from .settings import *  # noqa: F403

if os.environ.get("SHOUGT_LOCAL_PREVIEW") != "1":
    raise RuntimeError("Set SHOUGT_LOCAL_PREVIEW=1 explicitly to use local preview settings")

DEBUG = True
LOCAL_PREVIEW_MODE = True
LOCAL_PREVIEW_EMAIL_CODE = "123456"
PREVIEW_DIR = BASE_DIR / ".local-preview"
DATABASES = {"default": {"ENGINE": "django.db.backends.sqlite3", "NAME": str(PREVIEW_DIR / "forum.sqlite3"),
                         "OPTIONS": {"timeout": 30, "transaction_mode": "IMMEDIATE"}}}
CACHES = {"default": {"BACKEND": "django.core.cache.backends.db.DatabaseCache", "LOCATION": "dev_cache"}}
EMAIL_BACKEND = "django.core.mail.backends.filebased.EmailBackend"
EMAIL_FILE_PATH = str(PREVIEW_DIR / "mail")
ALLOWED_HOSTS = ["localhost", "127.0.0.1", "[::1]"]
WEBAUTHN_RP_ID = "localhost"
WEBAUTHN_ORIGINS = ("http://localhost:15173",)
CONSOLE_URL = "https://privileged.localhost:18443"
FIDO_ATTESTATION_TRUST = json.loads((PREVIEW_DIR / "fido-trust.json").read_text(encoding="utf-8"))
LOCAL_PREVIEW_KEY_PINS_FILE = str(PREVIEW_DIR / "fido-local-pins.json")
HCCAPTCHA_REQUIRED = False
CELERY_TASK_ALWAYS_EAGER = False
CELERY_BROKER_URL = "memory://"
SESSION_COOKIE_SECURE = False
CSRF_COOKIE_SECURE = False

# The interactive preview must not invoke SMTP, AI providers or cloud storage.
import socket
_resolve = socket.getaddrinfo
_connect = socket.socket.connect
_connect_ex = socket.socket.connect_ex


def _local_address(address):
    return isinstance(address, tuple) and address[0] in {"localhost", "127.0.0.1", "::1"} and int(address[1]) >= 10000


def _preview_resolve(host, port, *args, **kwargs):
    if host not in {None, "localhost", "127.0.0.1", "::1"}:
        raise OSError("本地预览不连接外部服务")
    return _resolve(host, port, *args, **kwargs)


def _preview_connect(sock, address):
    if not _local_address(address):
        raise OSError("本地预览不连接外部服务")
    return _connect(sock, address)


def _preview_connect_ex(sock, address):
    if not _local_address(address):
        raise OSError("本地预览不连接外部服务")
    return _connect_ex(sock, address)


socket.getaddrinfo = _preview_resolve
socket.socket.connect = _preview_connect
socket.socket.connect_ex = _preview_connect_ex
