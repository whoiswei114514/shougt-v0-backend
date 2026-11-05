from .settings import *  # noqa: F403

DATABASES = {"default": {"ENGINE": "django.db.backends.sqlite3", "NAME": ":memory:"}}
CACHES = {"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}}
EMAIL_BACKEND = "django.core.mail.backends.locmem.EmailBackend"
PASSWORD_HASHERS = ["django.contrib.auth.hashers.MD5PasswordHasher"]
HCCAPTCHA_REQUIRED = False
CELERY_TASK_ALWAYS_EAGER = True
CELERY_BROKER_URL = "memory://"
WEBAUTHN_RP_ID = "localhost"
WEBAUTHN_ORIGINS = ("http://localhost:15173",)
