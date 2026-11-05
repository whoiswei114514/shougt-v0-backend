"""Only used by the local browser test harness; never a deployment configuration."""
import json
import os
from pathlib import Path
from .test_settings import *  # noqa: F403

if os.environ.get("SHOUGT_UI_TEST") != "1":
    raise RuntimeError("UI fixtures require the explicit SHOUGT_UI_TEST=1 test environment")
UI_WORK = Path(os.environ["SHOUGT_UI_WORK"]).resolve()
DATABASES = {"default": {"ENGINE": "django.db.backends.sqlite3", "NAME": str(UI_WORK / "ui.sqlite3")}}
EMAIL_BACKEND = "django.core.mail.backends.filebased.EmailBackend"
EMAIL_FILE_PATH = str(UI_WORK / "mail")
CONSOLE_URL = "https://privileged.localhost:18443"
WEBAUTHN_RP_ID = "localhost"
WEBAUTHN_ORIGINS = ("http://localhost:15173",)
# Sequential browser fixtures share one loopback ingress; production stays 40/min.
SECURITY_AUTH_RATE_LIMIT = "600/min"
FIDO_ATTESTATION_TRUST = json.loads((UI_WORK / "fido-trust.json").read_text(encoding="utf-8")) if (UI_WORK / "fido-trust.json").exists() else []
