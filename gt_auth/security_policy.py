from datetime import timedelta
from django.utils import timezone
from rest_framework.exceptions import PermissionDenied


def suspended(user):
    return bool(user.admin_suspended_until and user.admin_suspended_until > timezone.now())


def enrollment_complete(user):
    from .webauthn import trusted_hardware
    return bool(user.email_verified_at and user.real_name.strip() and
                user.real_name_verified_at and user.advanced_verified_at and
                any(trusted_hardware(key) for key in user.security_keys.filter(is_security_key=True, backup_eligible=False, revoked_at__isnull=True)))


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
    from .webauthn import trusted_hardware
    return bool(session and "fido2" in session.methods and session.credential and
                session.credential.user_id == session.user_id and
                session.credential.is_security_key and not session.credential.backup_eligible and
                not session.credential.revoked_at and trusted_hardware(session.credential))


def privileged_factors_satisfied(session, *, privileged=True):
    from .webauthn import trusted_hardware
    second = session.second_credential if session else None
    two_keys = bool(second and second.user_id == session.user_id and
                    second.pk != session.credential_id and "fido2_second" in session.methods and
                    trusted_hardware(second))
    return bool(key_authenticated(session) and
                (two_keys or allows_single_factor(session.credential, privileged=privileged) or
                 set(session.methods) & {"password", "totp", "email"}))


def admin_access_allowed(user, session):
    if not user.is_currently_active or user.admin_onboarding_required or suspended(user) or not enrollment_complete(user):
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


def security_summary(user, session=None):
    from .webauthn import credential_assurance
    from .roles import assigned_roles
    key_verified = key_authenticated(session)
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
        "admin_access": bool(user.is_management and admin_access_allowed(user, session)),
        "key_authenticated": key_verified,
        "session_key_assurance": credential_assurance(session.credential) if key_verified else None,
        "fido_authenticated": bool(session and "fido2" in session.methods and session.credential and not session.credential.revoked_at),
        "session_scope": session.scope if session else None,
        "totp_enabled": hasattr(user, "totp_device") and bool(user.totp_device.confirmed_at),
        "key_exempt_until": user.security_key_exempt_until,
        "admin_suspended_until": user.admin_suspended_until,
        "show_real_name": bool(user.primary_role_id and user.primary_role.show_user_info),
        "primary_role_id": user.primary_role_id,
        "impersonator_id": session.impersonator_id if session else None,
        "session_key_id": session.credential_id if session else None,
    }
