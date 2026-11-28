import json
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
    "OPTIONS": {"timeout": 30, "transaction_mode": "IMMEDIATE"},
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

RESEND_API_KEY = os.environ.get("SHOUGT_RESEND_API_KEY", CONFIG.get("resend_api_key", ""))
RESEND_API_URL = CONFIG.get("resend_api_url", "https://api.resend.com/emails")
EMAIL_PROVIDER = os.environ.get(
    "SHOUGT_EMAIL_PROVIDER",
    CONFIG.get("email_provider", "resend" if RESEND_API_KEY else "smtp"),
).strip().lower()
EMAIL_TIMEOUT = CONFIG.get("email_timeout", 15)

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
    if EMAIL_PROVIDER == "resend":
        EMAIL_BACKEND = "gt.mail_backends.ResendEmailBackend"
    else:
        EMAIL_BACKEND = "django.core.mail.backends.smtp.EmailBackend"
        EMAIL_HOST = CONFIG.get("email_host", "127.0.0.1")
        EMAIL_PORT = CONFIG.get("email_port", 10250)
        EMAIL_HOST_USER = CONFIG.get("email_host_user", "")
        EMAIL_HOST_PASSWORD = os.environ.get("SHOUGT_SMTP_PASSWORD", CONFIG.get("email_host_password", ""))
        EMAIL_USE_TLS = CONFIG.get("email_use_tls", True)
        EMAIL_USE_SSL = CONFIG.get("email_use_ssl", False)
        EMAIL_SSL_KEYFILE = CONFIG.get("email_ssl_keyfile")
        EMAIL_SSL_CERTFILE = CONFIG.get("email_ssl_certfile")

ALLOWED_HOSTS = CONFIG.get("allowed_hosts", ["localhost", "127.0.0.1", "testserver", "shouguatian.com"])
EDUCATION_EMAIL_SUFFIXES = tuple(CONFIG.get("education_email_suffixes", ["edu.cn", "edu", "ac.uk"]))
EDUCATION_INSTITUTION_ALIASES = CONFIG.get("education_institution_aliases", {})
DEFAULT_FROM_EMAIL = CONFIG.get("default_from_email", "noreply@shouguatian.com")
ADVANCED_VERIFICATION_EMAIL = "renzheng@shouguatian.com"
MATERIAL_REVIEW_CONTACT = CONFIG.get("material_review_contact", ADVANCED_VERIFICATION_EMAIL)
WEBAUTHN_RP_ID = CONFIG.get("webauthn_rp_id", "localhost" if MODE.startswith("dev") else "shouguatian.com")
WEBAUTHN_ORIGINS = tuple(CONFIG.get("webauthn_origins", ["http://localhost:15173"] if MODE.startswith("dev") else ["https://shouguatian.com"]))
CSRF_TRUSTED_ORIGINS = list(CONFIG.get("csrf_trusted_origins", ["http://localhost:15173"] if MODE.startswith("dev") else ["https://shouguatian.com", "https://www.shouguatian.com"]))
if not MODE.startswith("dev"):
    SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")


def _resolve_trust_path(rel_path, base_dirs):
    candidate = Path(rel_path)
    if candidate.is_absolute():
        return str(candidate)
    for base_dir in base_dirs:
        if base_dir is not None and (base_dir / candidate).exists():
            return str((base_dir / candidate).resolve())
    return str((base_dirs[-1] / candidate).resolve())


def resolve_trust_entry(entry, base_dir, extra_bases=()):
    item = dict(entry)
    bases = [b for b in extra_bases if b is not None] + [base_dir]
    if item.get("root_pem"):
        item["root_pem"] = _resolve_trust_path(item["root_pem"], bases)
    if item.get("intermediate_pem"):
        item["intermediate_pem"] = _resolve_trust_path(item["intermediate_pem"], bases)
    if item.get("intermediate_pems"):
        item["intermediate_pems"] = [_resolve_trust_path(path, bases) for path in item["intermediate_pems"]]
    return item


def default_fido_attestation_trust(base_dir):
    root_w = base_dir / "certs" / "fido" / "root_w.pem"
    intermediate = base_dir / "certs" / "fido" / "shougtfidoca.pem"
    if not (root_w.exists() and intermediate.exists()):
        return []
    return [{
        "id": "shougt-j3r180-fidoca",
        "root_pem": "certs/fido/root_w.pem",
        "intermediate_pem": "certs/fido/shougtfidoca.pem",
        "aaguids": ["4b5be07b-e6a6-4443-a190-3b201b27f1c5", "*"],
        "attachment": "cross-platform",
        "assurance": "fips140-2-level2",
        "allow_privileged_single_factor": False,
        "metadata_reference": "SHOUGTFIDOCA + w (NXP J3R180 OpenFIPS201/FIDO2Applet)",
        "certification_reference": "SHOUGTFIDOCA-J3R180-FIPS140-2-L2",
        "valid_until": "2036-11-21T08:03:58Z",
        "revoked_certificates": [],
    }]


def load_fido_attestation_trust(config, base_dir):
    base_dir = Path(base_dir)
    entries = []
    seen_ids = set()

    def _add(item, extra_bases=()):
        resolved = resolve_trust_entry(item, base_dir, extra_bases=extra_bases)
        entry_id = resolved.get("id")
        if entry_id:
            if entry_id in seen_ids:
                return
            seen_ids.add(entry_id)
        entries.append(resolved)

    base_trust = config.get("fido_attestation_trust") if "fido_attestation_trust" in config else default_fido_attestation_trust(base_dir)
    for item in base_trust or []:
        _add(item)

    raw_files = []
    cfg_files = config.get("fido_attestation_trust_files", [])
    if isinstance(cfg_files, str):
        raw_files.append(cfg_files)
    elif isinstance(cfg_files, (list, tuple)):
        raw_files.extend(cfg_files)
    env_files = os.environ.get("SHOUGT_FIDO_TRUST_FILES", "")
    if env_files:
        raw_files.extend(p for p in env_files.split(os.pathsep) if p.strip())

    for raw_path in raw_files:
        file_path = Path(str(raw_path).strip())
        if not file_path.is_absolute():
            file_path = (base_dir / file_path).resolve()
        if not file_path.is_file():
            continue
        text = file_path.read_text(encoding="utf-8")
        if file_path.suffix.lower() == ".json":
            loaded = json.loads(text)
        else:
            loaded = yaml.safe_load(text) or []
        if not isinstance(loaded, list):
            continue
        extra_bases = (file_path.parent, file_path.parent.parent)
        for item in loaded:
            if isinstance(item, dict):
                _add(item, extra_bases=extra_bases)

    return entries


FIDO_ATTESTATION_TRUST = load_fido_attestation_trust(CONFIG, BASE_DIR)
CONSOLE_URL = CONFIG.get("console_url", "https://privileged.localhost:18443" if MODE.startswith("dev") else "https://privileged.shouguatian.com:18443")
CONSOLE_CONFIG_FILE = os.environ.get("SHOUGT_CONSOLE_CONFIG", CONFIG.get("console_config_file", ""))
PIV_TLS_CONFIG = CONFIG.get("piv_tls_config")
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
