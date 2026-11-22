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

from .models import SecurityChallenge, WebAuthnCredential, User


def b64(data):
    return base64.urlsafe_b64encode(bytes(data)).decode().rstrip("=")


def unb64(value):
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _wa():
    from fido2 import webauthn
    return webauthn


_UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")


def _required_intermediate_fps(trust, now):
    paths = []
    if trust.get("intermediate_pem"):
        paths.append(trust["intermediate_pem"])
    if trust.get("intermediate_pems"):
        if not isinstance(trust["intermediate_pems"], list):
            return None
        paths.extend(trust["intermediate_pems"])
    required = set()
    for path in paths:
        cert = x509.load_pem_x509_certificate(Path(path).read_bytes())
        if not cert.not_valid_before_utc <= now <= cert.not_valid_after_utc:
            return None
        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
        if not bc.ca:
            return None
        required.add(cert.fingerprint(hashes.SHA256()).hex())
    for digest in trust.get("required_intermediates_sha256", []):
        if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", digest):
            return None
        required.add(digest.lower())
    return required


def _aaguid_matches(trust, aaguid, has_pinned_intermediate):
    if not isinstance(aaguid, str):
        return False
    normalized = aaguid.strip().lower()
    allowed = [str(item).strip().lower() for item in trust.get("aaguids", [])]
    if normalized in allowed:
        return True
    if has_pinned_intermediate and ("*" in allowed or trust.get("any_aaguid") is True):
        return bool(_UUID_RE.fullmatch(normalized) and normalized != "00000000-0000-0000-0000-000000000000")
    return False


def active_attestation_trust(evidence, aaguid):
    now = timezone.now()
    levels = {"standard"} | {f"fips140-{version}-level{level}" for version in (2, 3) for level in (2, 3, 4)} | {f"equivalent-level{level}" for level in (2, 3, 4)}
    evidence = evidence or {}
    for trust in settings.FIDO_ATTESTATION_TRUST:
        if (trust.get("id") != evidence.get("trust_id") or trust.get("assurance") not in levels or
            trust.get("attachment") != "cross-platform" or
            not trust.get("metadata_reference") or
            (trust.get("assurance") != "standard" and not trust.get("certification_reference"))):
            continue
        try:
            required_intermediates = _required_intermediate_fps(trust, now)
            if required_intermediates is None:
                continue
            if not _aaguid_matches(trust, aaguid, bool(required_intermediates)):
                continue
            expires = datetime.fromisoformat(trust["valid_until"].replace("Z", "+00:00"))
            root = x509.load_pem_x509_certificate(Path(trust["root_pem"]).read_bytes())
            chain_expiry = datetime.fromisoformat(evidence["chain_not_after"])
            present_intermediates = {str(fp).lower() for fp in evidence.get("intermediate_sha256s", [])}
            revoked = {str(fp).lower() for fp in trust.get("revoked_certificates", [])}
            if (expires.tzinfo and expires > now and root.not_valid_after_utc > now and
                chain_expiry.tzinfo and chain_expiry > now and
                root.fingerprint(hashes.SHA256()).hex() == evidence.get("root_sha256") and
                required_intermediates <= present_intermediates and
                str(evidence.get("leaf_sha256", "")).lower() not in revoked and
                not (present_intermediates & revoked)):
                return trust
        except (KeyError, ValueError, TypeError, OSError, x509.ExtensionNotFound):
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
    evidence = {"leaf_sha256": chain[0].fingerprint(hashes.SHA256()).hex(), "format": attestation.fmt}
    for trust in settings.FIDO_ATTESTATION_TRUST:
        try:
            root = x509.load_pem_x509_certificate(Path(trust["root_pem"]).read_bytes())
            path = list(chain)
            if path[-1].fingerprint(hashes.SHA256()) != root.fingerprint(hashes.SHA256()):
                path.append(root)
            if len(path) < 2:
                raise ValueError("Missing CA issuer")
            for idx, (child, parent) in enumerate(zip(path, path[1:])):
                child.verify_directly_issued_by(parent)
                bc = parent.extensions.get_extension_for_class(x509.BasicConstraints).value
                if not bc.ca or (bc.path_length is not None and bc.path_length < idx):
                    raise ValueError("Issuer is not a valid CA")
                try:
                    ku = parent.extensions.get_extension_for_class(x509.KeyUsage).value
                    if not ku.key_cert_sign:
                        raise ValueError("Issuer missing keyCertSign")
                except x509.ExtensionNotFound:
                    pass
                if not parent.not_valid_before_utc <= now <= parent.not_valid_after_utc:
                    raise ValueError("Expired CA")
            evidence.update(
                trust_id=trust["id"],
                root_sha256=root.fingerprint(hashes.SHA256()).hex(),
                intermediate_sha256s=[c.fingerprint(hashes.SHA256()).hex() for c in path[1:-1]],
                chain_not_after=min(cert.not_valid_after_utc for cert in path).isoformat(),
                allow_privileged_single_factor=bool(trust.get("allow_privileged_single_factor", True)),
            )
            if active_attestation_trust(evidence, str(attestation.auth_data.credential_data.aaguid)):
                return evidence
            for transient in ("trust_id", "root_sha256", "intermediate_sha256s", "chain_not_after", "allow_privileged_single_factor"):
                evidence.pop(transient, None)
        except (ValueError, KeyError, OSError, x509.ExtensionNotFound, InvalidSignature, UnsupportedAlgorithm):
            continue
    evidence.setdefault("chain_not_after", min(cert.not_valid_after_utc for cert in chain).isoformat())
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
    with transaction.atomic():
        User.objects.select_for_update().get(pk=user.pk)
        keys = user.security_keys.filter(revoked_at__isnull=True)
        if keys.count() >= 20 or (is_key and keys.filter(is_security_key=True).count() >= 3):
            raise ValidationError("每个账号最多绑定 3 把安全密钥、20 个登录凭据")
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
            if not key.user.is_currently_active or (row.user_id is not None and row.user_id != key.user_id):
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
            refreshed = dict(key.attestation_evidence or {})
            if trust:
                refreshed["allow_privileged_single_factor"] = bool(trust.get("allow_privileged_single_factor", True))
            else:
                refreshed.pop("allow_privileged_single_factor", None)
            key.attestation_evidence = refreshed
            key.save(update_fields=["sign_count", "last_used_at", "attestation_verified", "assurance_level", "attestation_evidence"])
        return key, row
    except (WebAuthnCredential.DoesNotExist, ValueError, TypeError, KeyError, AttributeError) as exc:
        raise ValidationError("安全密钥签名无效、已撤销或不是本次要求的密钥") from exc
