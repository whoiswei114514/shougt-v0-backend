"""Explicit protocol allowlist; read-only is independent of inherited capabilities."""
import re

READ_ACTIONS = frozenset({"list_users", "user_detail", "password_hash", "list_logs",
                          "list_verifications", "get_contact", "inspect_watermark",
                          "list_certificates", "issuance_status"})


def reader_protocol_allowed(path):
    path = path.removeprefix("/api")
    # Own authentication/credential maintenance and single-use read approvals.
    allowed = {"logout", "reauth-begin", "reauth-finish", "console-begin", "console-finish",
               "django-admin", "key-register-begin", "key-register-finish", "key-remove",
               "totp-begin", "totp-confirm", "totp-remove", "issuance-csr", "issuance-proof"}
    allowed |= {"admin-setup-begin", "admin-setup-finish"}
    return (path in {f"/security/{action}/" for action in allowed} or
            bool(re.fullmatch(r"/security/operation/[0-9a-f-]+/(begin|finish)/", path)))
