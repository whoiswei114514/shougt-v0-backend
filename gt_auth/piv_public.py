"""Public ceremony verification for target-browser PIV/WebCrypto self-service."""
import base64
import hashlib
import json
import uuid
from datetime import datetime

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.x509.oid import NameOID, ObjectIdentifier
from django.utils import timezone
from rest_framework.exceptions import ValidationError

BINDING_OID = ObjectIdentifier("2.25.193227676215671796411912755825224731624")
ALGORITHMS = ("P-384", "RSA-3072", "RSA-2048")
CLIENT_SLOTS = ("9a", "9c", "9e")
CERT_SLOTS = frozenset({"9a", "9c", "9d", "9e", *(f"{s:02x}" for s in range(0x82, 0x96))})


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()


def spki(key):
    return key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


def digest_key(key):
    return hashlib.sha256(spki(key)).hexdigest()


def fingerprint(cert):
    return cert.fingerprint(hashes.SHA256()).hex()


def key_algorithm(key):
    if isinstance(key, rsa.RSAPublicKey) and key.key_size in {2048, 3072}:
        return f"RSA-{key.key_size}"
    if isinstance(key, ec.EllipticCurvePublicKey) and isinstance(key.curve, ec.SECP384R1):
        return "P-384"
    raise ValueError("必须使用 P-384、RSA-3072 或 RSA-2048 密钥")


def job_binding(job):
    data = {key: job[key] for key in ("issuance_id", "nonce", "user_id", "user_version", "real_name", "roles")}
    if job.get("temporary"):
        data["temporary"] = True
        data["validity_days"] = job["validity_days"]
        data["final_certificate"] = True
    elif set(job.get("roles", ())) & {"super_admin", "superadmin_admin"}:
        data["delegated_ca"] = True
    return data


def card_binding(job, card=None):
    slot = (card or job.get("card") or {}).get("slot", "9a")
    return {**job_binding(job), "card_slot": slot}


def storage_key(identifier):
    try:
        return "piv_issuance." + uuid.UUID(str(identifier)).hex
    except (ValueError, TypeError, AttributeError) as exc:
        raise ValidationError("签发任务编号无效") from exc


def parse_expiry(value):
    dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    if timezone.is_naive(dt):
        dt = timezone.make_aware(dt, timezone.utc)
    return dt


def summarize_job(job):
    return {
        "issuance_id": job["issuance_id"],
        "nonce": job["nonce"],
        "write_nonce": job.get("write_nonce"),
        "user_id": job["user_id"],
        "user_version": job["user_version"],
        "real_name": job["real_name"],
        "roles": job["roles"],
        "temporary": bool(job.get("temporary")),
        "validity_days": job.get("validity_days"),
        "delegated_ca": bool(job.get("delegated_ca")),
        "state": job["state"],
        "expires_at": job["expires_at"],
        "algorithms": job.get("algorithms", list(ALGORITHMS)),
        "authorities": job.get("authorities", []),
        "roots": job.get("roots", []),
        "card": job.get("card"),
        "public_key_sha256": job.get("public_key_sha256"),
        "signed_chain_pem": job.get("signed_chain_pem"),
        "has_target_csr": bool(job.get("target_csr")),
        "has_target_proof": bool(job.get("target_proof")),
    }


def validate_target_csr(job, csr_pem, card, existing_jobs):
    try:
        if not isinstance(csr_pem, str) or len(csr_pem) > 16000:
            raise ValueError("CSR 大小无效")
        if not isinstance(card, dict):
            raise ValueError("设备信息格式错误")
        if set(card) - {"reader", "atr", "transport", "protocol", "slot", "algorithm", "on_card_generation", "platform", "browser_keystore"}:
            raise ValueError("设备信息包含未允许字段")
        slot = card.get("slot")
        if slot not in CLIENT_SLOTS:
            raise ValueError("无效的目标槽位")
        csr = x509.load_pem_x509_csr(csr_pem.encode())
        if not csr.is_signature_valid:
            raise ValueError("CSR 签名无效")
        alg = key_algorithm(csr.public_key())
        if alg not in job.get("algorithms", ALGORITHMS) or card.get("algorithm") != alg:
            raise ValueError("CSR 算法与设备声明不匹配")
        if csr.subject != x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, job["real_name"])]):
            raise ValueError("CSR 实名不匹配")
        expected = canonical(card_binding(job, card))
        if csr.extensions.get_extension_for_oid(BINDING_OID).value.value != expected:
            raise ValueError("CSR 任务绑定不匹配")
        if card.get("transport") == "browser":
            if (card.get("protocol") != "WebCrypto" or card.get("platform") != "browser" or
                    card.get("on_card_generation") is not False or card.get("browser_keystore") is not True or
                    slot != "9a"):
                raise ValueError("浏览器密钥参数无效")
        elif (card.get("transport") != "usb" or card.get("protocol") != "WebUSB" or
                card.get("platform") != "browser" or card.get("on_card_generation") is not True or
                card.get("browser_keystore")):
            raise ValueError("USB 智能卡参数无效")
        pub_sha = digest_key(csr.public_key())
        ca_keys = {
            digest_key(x509.load_pem_x509_certificate(p.encode()).public_key())
            for p in job.get("authorities", []) + job.get("roots", [])
        }
        if pub_sha in ca_keys:
            raise ValueError("签发 CA 公钥不能作为客户端公钥")
        for old in existing_jobs:
            if old.get("public_key_sha256") == pub_sha:
                raise ValueError("新证书必须生成全新的密钥对")
    except (ValueError, TypeError, KeyError, AttributeError, InvalidSignature, x509.ExtensionNotFound) as exc:
        raise ValidationError(f"公钥请求验证失败：{exc}") from exc


def validate_target_proof(job, proof_b64, card_slot=None, chain_slots=None):
    try:
        raw_chain = job.get("signed_chain_pem")
        if not isinstance(raw_chain, list) or len(raw_chain) < 2:
            raise ValueError("尚无已签发的证书链")
        certs = [x509.load_pem_x509_certificate(p.encode()) for p in raw_chain]
        leaf, chain = certs[0], certs[1:]
        expected_slot = job["card"]["slot"]
        chosen_slot = card_slot or expected_slot
        if chosen_slot != expected_slot:
            raise ValueError("目标槽位不匹配")
        if chain_slots is not None:
            if (not isinstance(chain_slots, list) or len(chain_slots) != len(certs) or
                    len(set(chain_slots)) != len(chain_slots) or chain_slots[0] != expected_slot or
                    any(s not in CERT_SLOTS for s in chain_slots)):
                raise ValueError("链写入槽位格式无效")
        if not isinstance(proof_b64, str) or len(proof_b64) > 2048:
            raise ValueError("持钥签名格式错误")
        sig = base64.b64decode(proof_b64, validate=True)
        msg = canonical({
            "purpose": "shou-piv-installed-v1",
            "issuance_id": job["issuance_id"],
            "write_nonce": job["write_nonce"],
            "certificate": fingerprint(leaf),
            "chain": [fingerprint(c) for c in chain],
            "card_slot": expected_slot,
        })
        pub = leaf.public_key()
        if isinstance(pub, rsa.RSAPublicKey):
            pub.verify(sig, msg, padding.PKCS1v15(), hashes.SHA384())
        elif isinstance(pub, ec.EllipticCurvePublicKey):
            pub.verify(sig, msg, ec.ECDSA(hashes.SHA384()))
        else:
            raise ValueError("不支持的公钥类型")
        return chosen_slot
    except (ValueError, TypeError, KeyError, AttributeError, InvalidSignature) as exc:
        raise ValidationError(f"持钥证明验证失败：{exc}") from exc
