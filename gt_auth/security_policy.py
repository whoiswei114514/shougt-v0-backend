from datetime import timedelta
from django.utils import timezone
from rest_framework.exceptions import PermissionDenied


def suspended(user):
    return bool(user.admin_suspended_until and user.admin_suspended_until > timezone.now())


def admin_keys_satisfied(user):
    from .webauthn import distinct_external_key_count
    keys = list(user.security_keys.filter(is_security_key=True, backup_eligible=False, revoked_at__isnull=True))
    return any(high_assurance(key) for key in keys) or distinct_external_key_count(keys) >= 2


def enrollment_complete(user):
    return bool(user.email_verified_at and user.real_name.strip() and
                user.real_name_verified_at and user.advanced_verified_at and
                admin_keys_satisfied(user))


def valid_session(user, session):
    return bool(session and session.user_id == user.pk and not session.revoked_at and
                session.expires_at > timezone.now() and session.user_version == user.version)


def allows_single_factor(credential, *, privileged=False):
    if not (credential and not credential.revoked_at and credential.is_security_key and
            not credential.backup_eligible and credential.attestation_verified):
        return False
    from .webauthn import active_attestation_trust
    trust = active_attestation_trust(credential.attestation_evidence, credential.aaguid)
    if not trust or trust.get("assurance") == "standard":
        return False
    if privileged and trust.get("allow_privileged_single_factor") is False:
        return False
    return True


def high_assurance(credential):
    return allows_single_factor(credential, privileged=False)


def key_authenticated(session):
    from .webauthn import external_security_key
    return bool(session and "fido2" in session.methods and session.credential and
                session.credential.user_id == session.user_id and
                external_security_key(session.credential))


def privileged_factors_satisfied(session, *, privileged=True):
    from .webauthn import external_security_key
    second = session.second_credential if session else None
    two_keys = bool(second and second.user_id == session.user_id and
                    second.pk != session.credential_id and "fido2_second" in session.methods and
                    external_security_key(second))
    return bool(key_authenticated(session) and
                (two_keys or allows_single_factor(session.credential, privileged=privileged) or
                 set(session.methods) & {"password", "totp", "email"}))


def admin_access_allowed(user, session):
    if not user.is_currently_active or not user.is_management or user.admin_onboarding_required or suspended(user) or not enrollment_complete(user):
        return False
    if not valid_session(user, session) or session.scope != "full":
        return False
    if user.is_privileged:
        return privileged_factors_satisfied(session, privileged=True)
    if key_authenticated(session):
        return privileged_factors_satisfied(session, privileged=False)
    return bool(user.security_key_exempt_until and user.security_key_exempt_until > timezone.now())


def require_key_session(user, session, *, fresh=False, privileged=False):
    if not valid_session(user, session) or not key_authenticated(session):
        raise PermissionDenied("请使用已绑定的外置安全密钥登录")
    if suspended(user):
        raise PermissionDenied("管理权限已临时冻结")
    if fresh and session.verified_at < timezone.now() - timedelta(minutes=5):
        raise PermissionDenied("请重新验证本次登录使用的安全密钥")
    if privileged and not (user.is_privileged and admin_access_allowed(user, session)):
        raise PermissionDenied("需要完成高级安全验证的特权管理账号")


def can_sign_issuance_requests(user):
    """Return True if user holds non-temporary super-admin signing authority."""
    from .models import ClientCertificateIdentity
    from .roles import assigned_roles

    if not user or not user.is_currently_active or suspended(user) or not enrollment_complete(user):
        return False
    if not (assigned_roles(user.permission) & {"super_admin", "superadmin_admin"}):
        return False
    if getattr(user.permission, "privileged_expires_at", None) is not None:
        return False
    now = timezone.now()
    active_certs = list(
        ClientCertificateIdentity.objects.filter(
            user=user, revoked_at__isnull=True, expires_at__gt=now
        ).values_list("is_temporary", flat=True)
    )
    if active_certs and all(is_temp for is_temp in active_certs):
        return False
    return True


def certificate_summary(user):
    from .models import ClientCertificateIdentity, SiteSecuritySetting
    from .piv_public import load_piv_tls_config, parse_expiry

    now = timezone.now()
    certs = list(ClientCertificateIdentity.objects.filter(user=user, revoked_at__isnull=True).order_by("-expires_at"))
    active = [c for c in certs if c.expires_at > now]
    signer_eligible = can_sign_issuance_requests(user)
    pending_jobs = 0
    signed_ready = 0
    pending_sign_requests = 0
    for row in SiteSecuritySetting.objects.filter(key__startswith="piv_issuance."):
        job = row.value if isinstance(row.value, dict) else None
        if not job:
            continue
        state = job.get("state")
        if state not in {"requested", "key_ready"}:
            continue
        try:
            if parse_expiry(job.get("expires_at")) <= now:
                continue
        except ValueError:
            continue
        if job.get("user_id") == user.pk and job.get("user_version") == user.version:
            pending_jobs += 1
            if state == "key_ready" and job.get("signed_chain_pem"):
                signed_ready += 1
        elif (signer_eligible and job.get("async_request") is True and state == "key_ready" and
                not job.get("signed_chain_pem")):
            pending_sign_requests += 1
    self_issuance_available = bool(user.is_privileged and load_piv_tls_config())
    if not user.is_privileged:
        return {
            "certificate_status": "not_required",
            "certificate_expires_at": active[0].expires_at if active else None,
            "certificate_required": False,
            "needs_certificate_issuance": False,
            "pending_issuance_count": pending_jobs,
            "signed_issuance_ready_count": signed_ready,
            "pending_sign_requests_count": pending_sign_requests,
            "can_sign_issuance_requests": signer_eligible,
            "certificate_is_temporary": bool(active[0].is_temporary) if active else False,
            "certificate_is_ca": bool(active[0].is_ca) if active else False,
            "self_issuance_available": False,
        }
    if active:
        status = "valid"
        expires_at = active[0].expires_at
    elif certs:
        status = "expired"
        expires_at = certs[0].expires_at
    else:
        status = "missing"
        expires_at = None
    return {
        "certificate_status": status,
        "certificate_expires_at": expires_at,
        "certificate_required": True,
        "needs_certificate_issuance": status in {"missing", "expired"},
        "pending_issuance_count": pending_jobs,
        "signed_issuance_ready_count": signed_ready,
        "pending_sign_requests_count": pending_sign_requests,
        "can_sign_issuance_requests": signer_eligible,
        "certificate_is_temporary": bool(active[0].is_temporary) if active else False,
        "certificate_is_ca": bool(active[0].is_ca) if active else False,
        "self_issuance_available": self_issuance_available,
    }


def security_summary(user, session=None):
    from .webauthn import credential_assurance, distinct_external_key_count
    from .roles import assigned_roles
    key_verified = key_authenticated(session)
    fido_active = bool(session and "fido2" in session.methods and session.credential and not session.credential.revoked_at)
    fido_fresh_seconds = max(
        0,
        int(((session.verified_at + timedelta(minutes=5)) - timezone.now()).total_seconds()),
    ) if fido_active and session.verified_at else 0
    active_external_keys = list(user.security_keys.filter(is_security_key=True, backup_eligible=False, revoked_at__isnull=True))
    has_high_assurance_key = any(high_assurance(k) for k in active_external_keys)
    keys_satisfied = admin_keys_satisfied(user)
    external_key_count = distinct_external_key_count(active_external_keys)
    return {
        "email_verified": bool(user.email_verified_at),
        "real_name_verified": bool(user.real_name_verified_at),
        "advanced_verified": bool(user.advanced_verified_at),
        "is_management": user.is_management,
        "is_privileged": user.is_privileged,
        "read_only": "global_reader" in assigned_roles(user.permission),
        "security_key_limit": 3,
        "second_key_id": session.second_credential_id if session else None,
        "is_admin_candidate": bool(user.admin_candidate_until and user.admin_candidate_until > timezone.now()),
        "admin_onboarding_required": bool(user.is_management and (user.admin_onboarding_required or (session and session.scope == "enrollment"))),
        "admin_setup_ready": bool(user.is_management and enrollment_complete(user)),
        "admin_keys_satisfied": bool(keys_satisfied),
        "has_high_assurance_key": bool(has_high_assurance_key),
        "external_key_count": external_key_count,
        "admin_access": bool(user.is_management and admin_access_allowed(user, session)),
        "key_authenticated": key_verified,
        "session_key_assurance": credential_assurance(session.credential) if key_verified else None,
        "fido_authenticated": fido_active,
        "fido_fresh_seconds": fido_fresh_seconds,
        "session_scope": session.scope if session else None,
        "totp_enabled": hasattr(user, "totp_device") and bool(user.totp_device.confirmed_at),
        "key_exempt_until": user.security_key_exempt_until,
        "admin_suspended_until": user.admin_suspended_until,
        "show_real_name": bool(user.primary_role_id and user.primary_role.show_user_info),
        "primary_role_id": user.primary_role_id,
        "impersonator_id": session.impersonator_id if session else None,
        "session_key_id": session.credential_id if session else None,
        **certificate_summary(user),
    }
