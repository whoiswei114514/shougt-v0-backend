import os
import sys
from pathlib import Path
import yaml

BASE_DIR = Path(__file__).resolve().parent.parent

CONFIG_FILE = BASE_DIR / "config.yaml"
CONFIG = (yaml.safe_load(CONFIG_FILE.read_text(encoding="utf-8")) or {}) if CONFIG_FILE.exists() else {}

MODE = os.environ.get("SHOUGT_MODE", CONFIG.get("mode", "dev"))

SECRET_KEY = os.environ.get("SHOUGT_SECRET_KEY", CONFIG.get("secret_key", ""))
if not SECRET_KEY:
    if not MODE.startswith("dev"):
        raise RuntimeError("Production requires SHOUGT_SECRET_KEY or config.yaml secret_key")
    SECRET_KEY = "development-only-shouguatian-change-before-deployment"

ALI_ACCESS_KEY = CONFIG.get("ali_access_key", "disabled")
ALI_ACCESS_SECRET = CONFIG.get("ali_access_secret", "disabled")
ALI_OSS_BUCKET = CONFIG.get("ali_oss_bucket", "")
ALI_OSS_REGION = CONFIG.get("ali_oss_region", "")

DOGE_ACCESS = CONFIG.get("doge_access", "")
DOGE_SECRET = CONFIG.get("doge_secret", "")
DOGE_FILE_CDNKEY = CONFIG.get("doge_file_cdnkey", "")
DOGE_FILE_BUCKET = CONFIG.get("doge_file_bucket", "shougt-file")
DOGE_VIDEO_CATEGORY_ID = CONFIG.get("doge_video_category_id", 0)

OPENAI_API_KEY = CONFIG.get("openai_api_key", "disabled")
OPENAI_BASE_URL = CONFIG.get("openai_base_url", "")

DB_SQLITE = {
    "ENGINE": "django.db.backends.sqlite3",
    "NAME": os.environ.get("SHOUGT_SQLITE_PATH", str(BASE_DIR / "db.sqlite3")),
}

DB_MYSQL = {
    "ENGINE": "django.db.backends.mysql",
    "OPTIONS": {
        "read_default_file": str(BASE_DIR / "db.cnf"),
    },
}

DB_POSTGRES = {
    "ENGINE": "django.db.backends.postgresql",
    "NAME": os.environ.get("SHOUGT_DB_NAME", "gt"),
    "USER": os.environ.get("SHOUGT_DB_USER", "srv"),
    "PASSWORD": os.environ.get("SHOUGT_DB_PASSWORD", ""),
    "HOST": os.environ.get("SHOUGT_DB_HOST", "127.0.0.1"),
    "PORT": os.environ.get("SHOUGT_DB_PORT", "15432"),
}

if MODE.startswith("dev"):
    DEBUG = True
    if MODE == "dev-mysql":
        DATABASES = {"default": DB_MYSQL}
    else:
        DATABASES = {"default": DB_SQLITE}
    CACHES = {
        "default": {
            "BACKEND": "django.core.cache.backends.db.DatabaseCache",
            "LOCATION": "dev_cache",
        }
    }
    EMAIL_BACKEND = "django.core.mail.backends.console.EmailBackend"
else:
    DEBUG = False
    DATABASES = {"default": DB_POSTGRES}
    CACHES = {
        "default": {
            "BACKEND": "django_redis.cache.RedisCache",
            "LOCATION": os.environ.get("SHOUGT_REDIS_URL", "redis://127.0.0.1:16379/4"),
            "OPTIONS": {
                "CLIENT_CLASS": "django_redis.client.DefaultClient",
            },
        }
    }
    EMAIL_BACKEND = "django.core.mail.backends.smtp.EmailBackend"
    EMAIL_HOST = CONFIG["email_host"]
    EMAIL_PORT = CONFIG["email_port"]
    EMAIL_HOST_USER = CONFIG["email_host_user"]
    EMAIL_HOST_PASSWORD = os.environ.get("SHOUGT_SMTP_PASSWORD", CONFIG.get("email_host_password", ""))
    EMAIL_USE_TLS = CONFIG["email_use_tls"]
    EMAIL_USE_SSL = CONFIG["email_use_ssl"]
    EMAIL_TIMEOUT = CONFIG["email_timeout"]
    EMAIL_SSL_KEYFILE = CONFIG["email_ssl_keyfile"]
    EMAIL_SSL_CERTFILE = CONFIG["email_ssl_certfile"]

ALLOWED_HOSTS = CONFIG.get("allowed_hosts", ["localhost", "127.0.0.1", "testserver", "shouguatian.com"])
EDUCATION_EMAIL_SUFFIXES = tuple(CONFIG.get("education_email_suffixes", ["edu.cn", "edu", "ac.uk"]))
EDUCATION_INSTITUTION_ALIASES = CONFIG.get("education_institution_aliases", {})
DEFAULT_FROM_EMAIL = CONFIG.get("default_from_email", "noreply@shouguatian.com")
ADVANCED_VERIFICATION_EMAIL = "renzheng@shouguatian.com"
MATERIAL_REVIEW_CONTACT = CONFIG.get("material_review_contact", ADVANCED_VERIFICATION_EMAIL)
WEBAUTHN_RP_ID = CONFIG.get("webauthn_rp_id", "localhost" if MODE.startswith("dev") else "shouguatian.com")
WEBAUTHN_ORIGINS = tuple(CONFIG.get("webauthn_origins", ["http://localhost:15173"] if MODE.startswith("dev") else ["https://shouguatian.com"]))
FIDO_ATTESTATION_TRUST = CONFIG.get("fido_attestation_trust", [])
FIDO_ATTESTATION_TRUST = [dict(entry, root_pem=str((BASE_DIR / entry["root_pem"]).resolve()))
                          if entry.get("root_pem") else entry for entry in FIDO_ATTESTATION_TRUST]
CONSOLE_URL = CONFIG.get("console_url", "https://privileged.localhost:18443" if MODE.startswith("dev") else "https://privileged.shouguatian.com:18443")
ADVANCED_MAIL_INGEST_SECRET = os.environ.get("SHOUGT_MAIL_INGEST_SECRET", "")
TOTP_ENCRYPTION_KEY = os.environ.get("SHOUGT_TOTP_ENCRYPTION_KEY", "")
HCCAPTCHA_REQUIRED = CONFIG.get("captcha_required", False)
HCCAPTCHA_CHECK_URL = CONFIG.get("captcha_check_url", "https://captcha.shouguatian.com/check")
NO_REVIEW_QUOTA_MULTIPLIER = 5
SECURITY_AUTH_RATE_LIMIT = "40/min"


# Application definition

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "rest_framework",
    "django_filters",
    "gt_auth",
    "gt_forum",
    "gt_file",
    "gt_admin",
    "gt_coin",
    "gt_alumni",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
    "gt_admin.audit.AdminAuditMiddleware",
    "gt_auth.django_admin.SecurityAdminMiddleware",
]

ROOT_URLCONF = "gt.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [BASE_DIR / "templates"],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
                "gt_admin.audit.watermark_context",
            ],
        },
    },
]

WSGI_APPLICATION = "gt.wsgi.application"


# Password validation
# https://docs.djangoproject.com/en/3.2/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {
        "NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.MinimumLengthValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.CommonPasswordValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.NumericPasswordValidator",
    },
]

LANGUAGE_CODE = "zh-hans"

TIME_ZONE = "Asia/Shanghai"

USE_I18N = True

USE_L10N = True

USE_TZ = True


# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/3.2/howto/static-files/

STATIC_URL = "/static/"
STATIC_ROOT = BASE_DIR / "staticfiles"

# Default primary key field type
# https://docs.djangoproject.com/en/3.2/ref/settings/#default-auto-field

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"


AUTH_USER_MODEL = "gt_auth.User"


REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": ["gt.session_authentication.JWTAuthentication"],
    "DEFAULT_PARSER_CLASSES": [
        "gt.parsers.DepthCheckedJSONParser",
        "rest_framework.parsers.FormParser",
        "rest_framework.parsers.MultiPartParser",
    ],
    "DEFAULT_FILTER_BACKENDS": [
        "django_filters.rest_framework.DjangoFilterBackend",
        "rest_framework.filters.OrderingFilter",
        "rest_framework.filters.SearchFilter",
    ],
    "DEFAULT_RENDERER_CLASSES": ["rest_framework.renderers.JSONRenderer"],
    "DEFAULT_PAGINATION_CLASS": "gt.paginations.PageNumberPagination",
    "EXCEPTION_HANDLER": "gt.middlewares.gt_exception_handler",
}

CELERY_TIMEZONE = TIME_ZONE
CELERY_ACCEPT_CONTENT = ["json"]
CELERY_TASK_SERIALIZER = "json"
CELERY_BROKER_URL = os.environ.get("SHOUGT_REDIS_URL", "redis://127.0.0.1:16379/4")
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SECURE = not DEBUG
SESSION_COOKIE_SAMESITE = "Strict"
CSRF_COOKIE_SECURE = not DEBUG
SECURE_CONTENT_TYPE_NOSNIFF = True
X_FRAME_OPTIONS = "DENY"
# CELERY_RESULT_BACKEND = "redis://127.0.0.1:6379/4"
