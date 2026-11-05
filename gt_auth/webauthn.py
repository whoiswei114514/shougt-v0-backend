"""WebAuthn verification through python-fido2; no client-supplied trust decisions."""
import base64
import hashlib
import re
from datetime import datetime, timedelta, timezone as dt_timezone
from pathlib import Path

from cryptography import x509
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes
from django.conf import settings
from django.core.exceptions import ValidationError as DjangoValidationError
from django.db import transaction
from django.utils import timezone
from rest_framework.exceptions import ValidationError, PermissionDenied

from .models import SecurityChallenge, WebAuthnCredential


def b64(data):
    return base64.urlsafe_b64encode(bytes(data)).decode().rstrip("=")


def unb64(value):
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _wa():
    from fido2 import webauthn
    return webauthn


def active_attestation_trust(evidence, aaguid):
    now = timezone.now()
    levels = {"standard"} | {f"fips140-{version}-level{level}" for version in (2, 3) for level in (2, 3, 4)} | {f"equivalent-level{level}" for level in (2, 3, 4)}
    for trust in settings.FIDO_ATTESTATION_TRUST:
        if (trust.get("id") != evidence.get("trust_id") or trust.get("assurance") not in levels or
            aaguid not in trust.get("aaguids", []) or trust.get("attachment") != "cross-platform" or
            not trust.get("metadata_reference") or
            (trust.get("assurance") != "standard" and not trust.get("certification_reference"))):
            continue
        try:
            expires = datetime.fromisoformat(trust["valid_until"].replace("Z", "+00:00"))
            root = x509.load_pem_x509_certificate(Path(trust["root_pem"]).read_bytes())
            chain_expiry = datetime.fromisoformat(evidence["chain_not_after"])
            if (expires.tzinfo and expires > now and root.not_valid_after_utc > now and
                chain_expiry.tzinfo and chain_expiry > now and
                root.fingerprint(hashes.SHA256()).hex() == evidence.get("root_sha256") and
                evidence.get("leaf_sha256") not in trust.get("revoked_certificates", [])):
                return trust
        except (KeyError, ValueError, OSError):
            continue
    return None


def trusted_assurance(evidence, aaguid):
    trust = active_attestation_trust(evidence, aaguid)
    return trust["assurance"] if trust else "standard"


def trusted_hardware(key):
    from .local_preview_keys import allowed_local_key
    return bool(key and not key.revoked_at and key.is_security_key and not key.backup_eligible and
                ((key.attestation_verified and active_attestation_trust(key.attestation_evidence, key.aaguid)) or
                 allowed_local_key(key)))


def credential_assurance(key):
    """Display only certification data from current, verified attestation metadata."""
    result = {"level": "standard", "label": "标准验证", "high_assurance": False, "certifications": []}
    if not (key and not key.revoked_at and key.is_security_key and
            not key.backup_eligible and key.attestation_verified):
        return result
    trust = active_attestation_trust(key.attestation_evidence, key.aaguid)
    if not trust:
        return result

    level = trust["assurance"]
    labels = []
    fips = re.fullmatch(r"fips140-([23])-level([234])", level)
    if fips:
        labels.append(f"FIPS 140-{fips[1]} L{fips[2]}")
    for certification in trust.get("certifications", []):
        if not isinstance(certification, dict) or not certification.get("reference"):
            continue
        standard, rating = certification.get("standard"), certification.get("level")
        if not isinstance(standard, str) or not isinstance(rating, str):
            continue
        if ((standard == "CC" and re.fullmatch(r"EAL[1-7]\+?", rating)) or
                (re.fullmatch(r"FIPS 140-[23]", standard) and re.fullmatch(r"L[1-4]", rating))):
            label = f"{standard} {rating}"
            if label not in labels:
                labels.append(label)
    equivalent = re.fullmatch(r"equivalent-level([234])", level)
    label = " · ".join(labels) if labels else (f"同等级 L{equivalent[1]}" if equivalent else "标准验证")
    return {"level": level, "label": label, "high_assurance": level != "standard", "certifications": labels}


def attestation_evidence(attestation, client_hash):
    from fido2.attestation import Attestation
    if attestation.fmt == "none":
        return {}
    result = Attestation.for_type(attestation.fmt)().verify(attestation.att_stmt, attestation.auth_data, client_hash)
    chain = [x509.load_der_x509_certificate(cert) for cert in result.trust_path]
    if not chain:
        return {}
    now = timezone.now()
    if any(not cert.not_valid_before_utc <= now <= cert.not_valid_after_utc for cert in chain):
        raise ValueError("Expired attestation certificate")
    evidence = {"leaf_sha256": chain[0].fingerprint(hashes.SHA256()).hex(), "format": attestation.fmt,
                "chain_not_after": min(cert.not_valid_after_utc for cert in chain).isoformat()}
    for trust in settings.FIDO_ATTESTATION_TRUST:
        try:
            root = x509.load_pem_x509_certificate(Path(trust["root_pem"]).read_bytes())
            path = list(chain)
            if path[-1].fingerprint(hashes.SHA256()) != root.fingerprint(hashes.SHA256()):
                path.append(root)
            for child, parent in zip(path, path[1:]):
                child.verify_directly_issued_by(parent)
                if not parent.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
                    raise ValueError("Issuer is not a CA")
                if not parent.not_valid_before_utc <= now <= parent.not_valid_after_utc:
                    raise ValueError("Expired CA")
            evidence.update(trust_id=trust["id"], root_sha256=root.fingerprint(hashes.SHA256()).hex())
            if active_attestation_trust(evidence, str(attestation.auth_data.credential_data.aaguid)):
                return evidence
            evidence.pop("trust_id", None)
            evidence.pop("root_sha256", None)
        except (ValueError, KeyError, OSError, x509.ExtensionNotFound, InvalidSignature, UnsupportedAlgorithm):
            continue
    return evidence


def server(evidence=None):
    from fido2.server import Fido2Server
    wa = _wa()

    def verify(attestation, client_hash):
        result = attestation_evidence(attestation, client_hash)
        if evidence is not None:
            evidence.update(result)

    return Fido2Server(
        wa.PublicKeyCredentialRpEntity(id=settings.WEBAUTHN_RP_ID, name="shou瓜田"),
        attestation=wa.AttestationConveyancePreference.DIRECT,
        verify_origin=lambda origin: origin in settings.WEBAUTHN_ORIGINS,
        verify_attestation=verify,
    )


def credential_data(key):
    return _wa().AttestedCredentialData(unb64(key.credential_data))


def issue_challenge(purpose, state, user=None, seconds=300):
    return SecurityChallenge.objects.create(user=user, purpose=purpose, state=state,
                                             expires_at=timezone.now() + timedelta(seconds=seconds))


def claim_challenge(challenge_id, purpose, user=None):
    with transaction.atomic():
        try:
            row = SecurityChallenge.objects.select_for_update().filter(pk=challenge_id, purpose=purpose).first()
        except (ValueError, DjangoValidationError):
            row = None
        if (not row or row.consumed_at or row.expires_at <= timezone.now() or
            (user is not None and row.user_id != user.pk)):
            raise ValidationError("验证请求已失效，请重新开始")
        row.consumed_at = timezone.now()
        row.save(update_fields=["consumed_at"])
    return row


def begin_registration(user, *, kind="security_key", name="安全密钥"):
    wa = _wa()
    if kind not in {"security_key", "passkey"}:
        raise ValidationError("不支持的凭据类型")
    if user.is_management and kind != "security_key":
        raise PermissionDenied("管理员请绑定外置安全密钥")
    keys = user.security_keys.filter(revoked_at__isnull=True)
    options, state = server().register_begin(
        wa.PublicKeyCredentialUserEntity(id=str(user.pk).encode(), name=user.username, display_name=user.username),
        [credential_data(key) for key in keys],
        resident_key_requirement=wa.ResidentKeyRequirement.PREFERRED,
        user_verification=wa.UserVerificationRequirement.REQUIRED,
        authenticator_attachment=wa.AuthenticatorAttachment.CROSS_PLATFORM if kind == "security_key" else None,
    )
    row = issue_challenge("register_key", {"fido": state, "kind": kind, "name": str(name)[:80]}, user)
    return {"challenge_id": str(row.pk), **dict(options)}


def finish_registration(user, challenge_id, response):
    row = claim_challenge(challenge_id, "register_key", user)
    evidence = {}
    try:
        parsed = _wa().RegistrationResponse.from_dict(response)
        if parsed.response.client_data.cross_origin:
            raise ValueError("Cross-origin credential ceremony is not allowed")
        auth = server(evidence).register_complete(row.state["fido"], parsed)
        credential = auth.credential_data
        backup = auth.is_backup_eligible()
        is_key = row.state["kind"] == "security_key" and not backup and parsed.authenticator_attachment == "cross-platform"
        if row.state["kind"] == "security_key" and not is_key:
            raise ValueError("Expected a non-backup external authenticator")
        transports = [t for t in response.get("response", {}).get("transports", [])
                      if t in {"usb", "nfc", "ble", "internal", "hybrid", "smart-card"}]
        aaguid = str(credential.aaguid)
        if b64(parsed.raw_id) != b64(credential.credential_id):
            raise ValueError("Credential id mismatch")
    except (ValueError, TypeError, KeyError, AttributeError, InvalidSignature, UnsupportedAlgorithm) as exc:
        raise ValidationError("密钥验证失败，请使用支持 PIN 或生物识别的安全密钥") from exc
    if WebAuthnCredential.objects.filter(credential_id=b64(credential.credential_id)).exists():
        raise ValidationError("该凭据已绑定")
    if user.is_management and not active_attestation_trust(evidence, aaguid):
        raise ValidationError("此密钥未提供受信任的硬件证明，请使用已纳入站点信任清单的安全密钥")
    return WebAuthnCredential.objects.create(
        user=user, credential_id=b64(credential.credential_id), credential_data=b64(credential),
        name=row.state["name"], aaguid=aaguid, sign_count=auth.counter, transports=transports,
        is_security_key=is_key, backup_eligible=backup, attestation_evidence=evidence,
        attestation_verified=bool(evidence.get("trust_id")), assurance_level=trusted_assurance(evidence, aaguid),
    )


def begin_assertion(purpose, *, user=None, keys=None, state=None, challenge=None):
    keys = list(keys) if keys is not None else None
    options, fido_state = server().authenticate_begin(
        [credential_data(key) for key in keys] if keys is not None else None,
        user_verification=_wa().UserVerificationRequirement.REQUIRED, challenge=challenge,
    )
    data = {"fido": fido_state, "allowed_ids": [key.pk for key in keys] if keys is not None else None, **(state or {})}
    row = issue_challenge(purpose, data, user)
    return {"challenge_id": str(row.pk), **dict(options)}


def finish_assertion(challenge_id, purpose, response, *, user=None):
    row = claim_challenge(challenge_id, purpose, user)
    try:
        parsed = _wa().AuthenticationResponse.from_dict(response)
        if parsed.response.client_data.cross_origin:
            raise ValueError("Cross-origin credential ceremony is not allowed")
        with transaction.atomic():
            key = WebAuthnCredential.objects.select_for_update().select_related("user__permission").get(
                credential_id=b64(parsed.raw_id), revoked_at__isnull=True,
            )
            if not key.user.is_active or (row.user_id is not None and row.user_id != key.user_id):
                raise ValueError("Wrong account")
            allowed = row.state["allowed_ids"]
            if allowed is not None and key.pk not in allowed:
                raise ValueError("Wrong credential")
            if parsed.response.user_handle is not None and parsed.response.user_handle != str(key.user_id).encode():
                raise ValueError("Wrong user handle")
            server().authenticate_complete(row.state["fido"], [credential_data(key)], parsed)
            auth = parsed.response.authenticator_data
            if auth.is_backup_eligible() != key.backup_eligible:
                raise ValueError("Backup eligibility changed")
            if (key.sign_count or auth.counter) and auth.counter <= key.sign_count:
                raise ValueError("Authenticator counter did not increase")
            key.sign_count = auth.counter
            key.last_used_at = timezone.now()
            # Refresh the verified snapshot consumed by the independent console.
            trust = active_attestation_trust(key.attestation_evidence, key.aaguid)
            key.attestation_verified = bool(trust)
            key.assurance_level = trust["assurance"] if trust else "standard"
            key.save(update_fields=["sign_count", "last_used_at", "attestation_verified", "assurance_level"])
        return key, row
    except (WebAuthnCredential.DoesNotExist, ValueError, TypeError, KeyError, AttributeError) as exc:
        raise ValidationError("安全密钥签名无效、已撤销或不是本次要求的密钥") from exc
