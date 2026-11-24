"""Public ceremony verification for hardware smartcard (PIV) and TPM self-service."""
import base64
import hashlib
import io
import json
import re
import uuid
import zipfile
from datetime import datetime, timedelta
from pathlib import Path

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID, ObjectIdentifier
from django.conf import settings
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


def _display_algorithm(key):
    if isinstance(key, rsa.RSAPublicKey):
        return f"RSA-{key.key_size}"
    if isinstance(key, ec.EllipticCurvePublicKey) and getattr(key.curve, "name", "") == "secp384r1":
        return "P-384"
    return type(key).__name__


def issuer_matches(leaf_key, issuer_key):
    if isinstance(leaf_key, ec.EllipticCurvePublicKey) and isinstance(leaf_key.curve, ec.SECP384R1):
        return isinstance(issuer_key, ec.EllipticCurvePublicKey) and isinstance(issuer_key.curve, ec.SECP384R1)
    if isinstance(leaf_key, rsa.RSAPublicKey) and leaf_key.key_size in {2048, 3072, 4096}:
        return isinstance(issuer_key, rsa.RSAPublicKey) and issuer_key.key_size in {2048, 3072, 4096}
    return False


def _cert_cn(cert):
    names = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    if len(names) == 1 and str(names[0].value).strip():
        return str(names[0].value).strip()
    return cert.subject.rfc4514_string()


def _binding_flags(cert):
    try:
        raw = cert.extensions.get_extension_for_oid(BINDING_OID).value.value
        data = json.loads(raw.decode("utf-8"))
        return data if isinstance(data, dict) else {}
    except (x509.ExtensionNotFound, UnicodeDecodeError, json.JSONDecodeError, ValueError):
        return {}


def load_piv_tls_config():
    cfg = getattr(settings, "PIV_TLS_CONFIG", None)
    if isinstance(cfg, dict):
        return cfg
    path_str = getattr(settings, "CONSOLE_CONFIG_FILE", "")
    if not path_str:
        return None
    path = Path(path_str)
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    tls = data.get("tls") if isinstance(data, dict) else None
    return tls if isinstance(tls, dict) else None


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
        "self_service": bool(job.get("self_service")),
        "async_request": bool(job.get("async_request")),
        "requester_username": job.get("requester_username", ""),
        "format_version": job.get("format_version", 2),
        "state": job["state"],
        "created_at": job.get("created_at"),
        "csr_submitted_at": job.get("csr_submitted_at"),
        "expires_at": job["expires_at"],
        "algorithms": job.get("algorithms", list(ALGORITHMS)),
        "authorities": job.get("authorities", []),
        "authority_descriptors": job.get("authority_descriptors", []),
        "roots": job.get("roots", []),
        "card": job.get("card"),
        "csr_pem": job.get("csr_pem") if job.get("self_service") else None,
        "public_key_sha256": job.get("public_key_sha256"),
        "signed_chain_pem": job.get("signed_chain_pem"),
        "has_target_csr": bool(job.get("target_csr")),
        "has_target_proof": bool(job.get("target_proof")),
        "issuer_kind": job.get("issuer_kind"),
        "issuer_label": job.get("issuer_label"),
        "signed_by_name": job.get("signed_by_name"),
        "signed_at": job.get("signed_at"),
    }


_HELPER_SOURCE_FILES = (
    "piv_helper.pyw",
    "backend/__init__.py",
    "backend/db.py",
    "backend/piv_bridge.py",
    "backend/piv_card.py",
    "backend/piv_cli.py",
    "backend/piv_crypto.py",
    "backend/piv_helper_gui.py",
    "backend/piv_policy.py",
    "backend/smartcards.py",
    "backend/tpm_cng.py",
)

_HELPER_REQUIREMENTS = "cryptography>=42.0.0\npyscard>=2.0.0\nfido2>=1.1.0\n"

_HELPER_INSTALL_BAT = (
    "@echo off\r\n"
    "chcp 65001 >nul\r\n"
    "cd /d \"%~dp0\"\r\n"
    "echo ======================================================\r\n"
    "echo   shou瓜田 · 本机智能卡与 Windows TPM 2.0 助手安装程序\r\n"
    "echo ======================================================\r\n"
    "where py >nul 2>nul\r\n"
    "if %errorlevel%==0 (\r\n"
    "  set \"PY_CMD=py -3\"\r\n"
    ") else (\r\n"
    "  where python >nul 2>nul\r\n"
    "  if %errorlevel%==0 (\r\n"
    "    set \"PY_CMD=python\"\r\n"
    "  ) else (\r\n"
    "    echo [错误] 未检测到 Python 3。请先安装 Python 3.10 或更高版本后再运行此脚本。\r\n"
    "    pause\r\n"
    "    exit /b 1\r\n"
    "  )\r\n"
    ")\r\n"
    "if not exist \".venv\\Scripts\\python.exe\" (\r\n"
    "  echo [1/4] 正在创建独立虚拟环境 .venv ...\r\n"
    "  %PY_CMD% -m venv .venv\r\n"
    "  if errorlevel 1 (\r\n"
    "    echo [错误] 创建虚拟环境失败。\r\n"
    "    pause\r\n"
    "    exit /b 1\r\n"
    "  )\r\n"
    ")\r\n"
    "echo [2/4] 正在安装或更新依赖 (cryptography / pyscard / fido2) ...\r\n"
    "\".venv\\Scripts\\python.exe\" -m pip install --upgrade pip >nul\r\n"
    "\".venv\\Scripts\\python.exe\" -m pip install -r requirements.txt\r\n"
    "if errorlevel 1 (\r\n"
    "  echo [错误] 依赖安装失败，请检查网络或 pip 源后重试。\r\n"
    "  pause\r\n"
    "  exit /b 1\r\n"
    ")\r\n"
    "echo [3/4] 正在注册浏览器一键唤起协议 shou-piv:// ...\r\n"
    "\".venv\\Scripts\\python.exe\" -m backend.piv_helper_gui --register-protocol\r\n"
    "if errorlevel 1 (\r\n"
    "  echo [错误] 注册协议失败。\r\n"
    "  pause\r\n"
    "  exit /b 1\r\n"
    ")\r\n"
    "echo [4/4] 安装完成！正在启动本机智能卡与 TPM 助手窗口 ...\r\n"
    "if exist \".venv\\Scripts\\pythonw.exe\" (\r\n"
    "  start \"\" \".venv\\Scripts\\pythonw.exe\" piv_helper.pyw\r\n"
    ") else (\r\n"
    "  start \"\" \".venv\\Scripts\\python.exe\" piv_helper.pyw\r\n"
    ")\r\n"
    "echo 之后也可直接在网页点击「一键唤起本机智能卡 / TPM 助手」。\r\n"
    "pause\r\n"
)

_HELPER_LAUNCH_BAT = (
    "@echo off\r\n"
    "chcp 65001 >nul\r\n"
    "cd /d \"%~dp0\"\r\n"
    "if exist \".venv\\Scripts\\pythonw.exe\" (\r\n"
    "  start \"\" \".venv\\Scripts\\pythonw.exe\" piv_helper.pyw\r\n"
    "  exit /b 0\r\n"
    ")\r\n"
    "if exist \".venv\\Scripts\\python.exe\" (\r\n"
    "  start \"\" \".venv\\Scripts\\python.exe\" piv_helper.pyw\r\n"
    "  exit /b 0\r\n"
    ")\r\n"
    "echo 未检测到 .venv 虚拟环境，请先双击运行「一键安装并注册助手.bat」。\r\n"
    "pause\r\n"
)

_HELPER_README_TXT = (
    "shou瓜田 · 本机智能卡与 Windows TPM 2.0 助手（Windows 客户端）\r\n"
    "==============================================================\r\n\r\n"
    "适用场景：\r\n"
    "• 使用 Windows 接触式 / NFC 智能卡读卡器（CCID / PC/SC）生成卡内私钥并写入证书。\r\n"
    "• 或使用本机 Windows TPM 2.0 安全芯片生成不可导出私钥并安装客户端证书。\r\n\r\n"
    "安全保证：\r\n"
    "• 私钥全程在实体智能卡或硬件 TPM 2.0 芯片内部生成与保管，绝不导出或生成 .p12。\r\n"
    "• 智能卡 PIN 与管理密钥仅在本机桌面弹窗中输入，绝不发送至网页或服务器。\r\n\r\n"
    "三步启用方法：\r\n"
    "1. 请先确认电脑已安装 Python 3.10 或更高版本。\r\n"
    "2. 将本压缩包完整解压到一个固定文件夹（例如 D:\\Tools\\shou-smartcard-helper），\r\n"
    "   双击运行「一键安装并注册助手.bat」。\r\n"
    "3. 回到网页「特权管理证书签发」页面，直接点击「一键唤起本机智能卡 / TPM 助手」，\r\n"
    "   在弹出窗口确认来源站后点击「允许连接并自动配对」即可自动识别读卡器与 TPM。\r\n"
)


def build_helper_zip_bytes(source_dir: Path) -> bytes:
    source_dir = Path(source_dir)
    if not source_dir.is_dir():
        raise ValidationError("本机助手打包目录不存在")
    buf = io.BytesIO()
    prefix = "shou-smartcard-helper"
    with zipfile.ZipFile(buf, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
        for rel in _HELPER_SOURCE_FILES:
            src = source_dir / rel
            if not src.is_file():
                raise ValidationError(f"本机助手缺少必要组件：{rel}")
            zf.writestr(f"{prefix}/{rel}", src.read_bytes())
        zf.writestr(f"{prefix}/requirements.txt", _HELPER_REQUIREMENTS.encode("utf-8"))
        zf.writestr(f"{prefix}/一键安装并注册助手.bat", _HELPER_INSTALL_BAT.encode("utf-8"))
        zf.writestr(f"{prefix}/启动智能卡助手.bat", _HELPER_LAUNCH_BAT.encode("utf-8"))
        zf.writestr(f"{prefix}/使用说明.txt", _HELPER_README_TXT.encode("utf-8"))
    return buf.getvalue()


def _load_tls_certs(tls_config):
    if not isinstance(tls_config, dict) or not tls_config.get("ca_bundle"):
        raise ValidationError("尚未配置站点根证书参数")
    ca_path = Path(tls_config["ca_bundle"])
    if not ca_path.is_file():
        raise ValidationError("站点根证书文件不存在")
    roots = x509.load_pem_x509_certificates(ca_path.read_bytes())
    subcas = []
    for path_str in tls_config.get("allowed_subcas", []):
        sub_path = Path(path_str)
        if sub_path.is_file():
            subcas.extend(x509.load_pem_x509_certificates(sub_path.read_bytes()))
    local_ca_only = tls_config.get("local_ca_only") is True
    if not subcas and not local_ca_only:
        raise ValidationError("尚未配置受信任的站点签发 CA")
    site_cas = subcas if subcas else (roots if local_ca_only else [])
    return roots, subcas, site_cas, local_ca_only


def _check_crl(cert, issuer, tls_config, now):
    crl_bundle = tls_config.get("crl_bundle")
    if not crl_bundle or not Path(crl_bundle).is_file():
        raise ValidationError("未配置撤销列表")
    raw = Path(crl_bundle).read_bytes()
    blocks = re.findall(rb"-----BEGIN X509 CRL-----.*?-----END X509 CRL-----", raw, re.S)
    candidates = []
    for block in blocks:
        crl = x509.load_pem_x509_crl(block)
        if crl.issuer != issuer.subject:
            continue
        if not crl.is_signature_valid(issuer.public_key()) or crl.last_update_utc > now:
            continue
        try:
            crl.extensions.get_extension_for_class(x509.DeltaCRLIndicator)
        except x509.ExtensionNotFound:
            candidates.append(crl)
        else:
            raise ValidationError("请配置最新的完整 CRL，而不是增量 CRL")
    if not candidates:
        raise ValidationError("未找到签名可信的撤销列表")
    latest = max(candidates, key=lambda candidate: candidate.last_update_utc)
    if not latest.next_update_utc or latest.next_update_utc <= now:
        raise ValidationError("撤销列表已过期")
    if latest.get_revoked_certificate_by_serial_number(cert.serial_number):
        raise ValidationError("签发证书或链路已被撤销")


def _local_chain_to_root(cert, pool, root_fps, now):
    def walk(child, seen, depth):
        if depth > 8:
            return False
        for issuer in pool:
            fp = fingerprint(issuer)
            if fp in seen:
                continue
            try:
                child.verify_directly_issued_by(issuer)
                bc = issuer.extensions.get_extension_for_class(x509.BasicConstraints).value
                ku = issuer.extensions.get_extension_for_class(x509.KeyUsage).value
                if not (
                    bc.ca and ku.key_cert_sign and
                    issuer.not_valid_before_utc <= now <= issuer.not_valid_after_utc and
                    (bc.path_length is None or bc.path_length >= depth)
                ):
                    continue
                if fp in root_fps or walk(issuer, seen | {fp}, depth + 1):
                    return True
            except (ValueError, TypeError, InvalidSignature, x509.ExtensionNotFound):
                continue
        return False

    return walk(cert, {fingerprint(cert)}, 0)


def _verify_delegated_ca_cert(cert, roots, subcas, local_ca_only, tls_config, now):
    fp = fingerprint(cert)
    if fp in {fingerprint(c) for c in subcas + roots}:
        return False
    if not cert.not_valid_before_utc <= now <= cert.not_valid_after_utc:
        return False
    try:
        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
        ku = cert.extensions.get_extension_for_class(x509.KeyUsage).value
        eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    except x509.ExtensionNotFound:
        return False
    if not (bc.ca and bc.path_length == 0 and ku.key_cert_sign and ku.digital_signature and ExtendedKeyUsageOID.CLIENT_AUTH in eku):
        return False
    flags = _binding_flags(cert)
    if flags.get("delegated_ca") is not True or flags.get("temporary"):
        return False
    root_fps = {fingerprint(r) for r in roots}
    if local_ca_only:
        return _local_chain_to_root(cert, subcas + roots, root_fps, now)
    for subca in subcas:
        try:
            cert.verify_directly_issued_by(subca)
            sub_bc = subca.extensions.get_extension_for_class(x509.BasicConstraints).value
            sub_ku = subca.extensions.get_extension_for_class(x509.KeyUsage).value
            if not (
                subca.not_valid_before_utc <= now <= subca.not_valid_after_utc and
                sub_bc.ca and sub_ku.key_cert_sign and
                (sub_bc.path_length is None or sub_bc.path_length >= 1)
            ):
                continue
        except (ValueError, TypeError, InvalidSignature, x509.ExtensionNotFound):
            continue
        for root in roots:
            try:
                subca.verify_directly_issued_by(root)
                root_bc = root.extensions.get_extension_for_class(x509.BasicConstraints).value
                root_ku = root.extensions.get_extension_for_class(x509.KeyUsage).value
                if not (
                    root.not_valid_before_utc <= now <= root.not_valid_after_utc and
                    root_bc.ca and root_ku.key_cert_sign and
                    (root_bc.path_length is None or root_bc.path_length >= 2)
                ):
                    continue
                _check_crl(cert, subca, tls_config, now)
                _check_crl(subca, root, tls_config, now)
                return True
            except (ValueError, TypeError, InvalidSignature, x509.ExtensionNotFound, ValidationError):
                continue
    return False


def _delegated_card_meta(owner_roles):
    if "superadmin_admin" in owner_roles:
        return "superadmin_admin_card", "超级特权卡"
    return "super_admin_card", "超管卡"


def collect_self_issuance_authorities(requester_user, tls_config, *, temporary):
    from .models import ClientCertificateIdentity
    from .roles import assigned_roles
    from .security_policy import suspended

    now = timezone.now()
    roots, subcas, site_cas, local_ca_only = _load_tls_certs(tls_config)

    site_pems = []
    site_descriptors = []
    for cert in site_cas:
        fp = fingerprint(cert)
        site_pems.append(cert.public_bytes(serialization.Encoding.PEM).decode())
        site_descriptors.append({
            "fingerprint": fp,
            "kind": "ca_card",
            "label": "CA 卡",
            "cn": _cert_cn(cert),
            "owner_name": "",
            "algorithm": _display_algorithm(cert.public_key()),
            "expires_at": cert.not_valid_after_utc.isoformat(),
            "temporary_only": False,
            "max_validity_days": None,
        })

    delegated_pems = []
    delegated_descriptors = []
    seen_fps = {d["fingerprint"] for d in site_descriptors}
    rows = (
        ClientCertificateIdentity.objects
        .select_related("user", "user__permission")
        .filter(revoked_at__isnull=True, is_ca=True, is_temporary=False, expires_at__gt=now)
        .exclude(user_id=requester_user.pk)
        .exclude(certificate_pem="")
    )
    for row in rows:
        owner = row.user
        if not owner.is_currently_active or suspended(owner):
            continue
        owner_roles = assigned_roles(owner.permission)
        if not (owner_roles & {"super_admin", "superadmin_admin"}):
            continue
        try:
            cert = x509.load_pem_x509_certificates(row.certificate_pem.encode())[0]
        except Exception:
            continue
        fp = fingerprint(cert)
        if fp in seen_fps:
            continue
        if not _verify_delegated_ca_cert(cert, roots, subcas, local_ca_only, tls_config, now):
            continue
        seen_fps.add(fp)
        kind, label = _delegated_card_meta(owner_roles)
        delegated_pems.append(cert.public_bytes(serialization.Encoding.PEM).decode())
        delegated_descriptors.append({
            "fingerprint": fp,
            "kind": kind,
            "label": label,
            "cn": _cert_cn(cert),
            "owner_name": owner.real_name or owner.username,
            "algorithm": _display_algorithm(cert.public_key()),
            "expires_at": cert.not_valid_after_utc.isoformat(),
            "temporary_only": True,
            "max_validity_days": 36,
        })

    authorities = delegated_pems + site_pems if temporary else site_pems
    authority_descriptors = delegated_descriptors + site_descriptors if temporary else site_descriptors
    delegated_fps = [d["fingerprint"] for d in delegated_descriptors] if temporary else []
    availability = {
        "site_ca_count": len(site_descriptors),
        "super_admin_card_count": sum(1 for d in delegated_descriptors if d["kind"] == "super_admin_card"),
        "superadmin_admin_card_count": sum(1 for d in delegated_descriptors if d["kind"] == "superadmin_admin_card"),
        "all_descriptors": site_descriptors + delegated_descriptors,
    }
    return {
        "authorities": authorities,
        "authority_descriptors": authority_descriptors,
        "delegated_fps": delegated_fps,
        "roots": [c.public_bytes(serialization.Encoding.PEM).decode() for c in roots],
        "availability": availability,
    }


def validate_target_csr(job, csr_pem, card, existing_jobs):
    try:
        if not isinstance(csr_pem, str) or len(csr_pem) > 16000:
            raise ValueError("CSR 大小无效")
        if not isinstance(card, dict):
            raise ValueError("设备信息格式错误")
        if set(card) - {"reader", "atr", "provider", "transport", "protocol", "slot", "algorithm", "on_card_generation", "platform", "browser_keystore"}:
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
        if not isinstance(job.get("real_name"), str) or not job["real_name"].strip():
            raise ValueError("目标实名不能为空")
        if csr.subject != x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, job["real_name"])]):
            raise ValueError("CSR 实名不匹配")
        expected = canonical(card_binding(job, card))
        if csr.extensions.get_extension_for_oid(BINDING_OID).value.value != expected:
            raise ValueError("CSR 任务绑定不匹配")
        for text_field in ("reader", "atr", "provider", "platform"):
            if text_field in card and card[text_field] is not None:
                if not isinstance(card[text_field], str) or len(card[text_field]) > 256:
                    raise ValueError("设备元信息格式无效")
        provider_lower = str(card.get("provider") or "").lower()
        if (card.get("transport") == "browser" or card.get("protocol") == "WebCrypto" or
                card.get("browser_keystore") or card.get("on_card_generation") is not True or
                ".p12" in provider_lower or "pkcs12" in provider_lower):
            raise ValueError("不允许使用可导出的 .p12 或浏览器软密钥，证书私钥必须在智能卡或 TPM 安全芯片内生成")
        if card.get("transport") == "tpm":
            if (card.get("protocol") != "TPM-CNG" or card.get("platform") not in {"windows", "desktop"} or
                    card.get("provider") != "Microsoft Platform Crypto Provider" or slot != "9a"):
                raise ValueError("TPM 密钥参数无效，必须使用硬件 TPM 安全芯片")
        elif (card.get("transport") not in {"usb", "contact", "nfc"} or
                card.get("protocol") not in {"T=0", "T=1", "ISO-DEP", "WebUSB"} or
                (card.get("protocol") == "ISO-DEP" and card.get("transport") != "nfc") or
                (card.get("protocol") == "WebUSB" and
                 (card.get("transport") != "usb" or card.get("platform") != "browser"))):
            raise ValueError("智能卡参数无效")
        pub_sha = digest_key(csr.public_key())
        ca_keys = {
            digest_key(x509.load_pem_x509_certificate(p.encode()).public_key())
            for p in job.get("authorities", []) + job.get("roots", [])
        }
        if pub_sha in ca_keys:
            raise ValueError("签发 CA 公钥不能作为客户端公钥")
        for old in existing_jobs:
            if old.get("issuance_id") == job.get("issuance_id"):
                continue
            if old.get("public_key_sha256") == pub_sha:
                raise ValueError("新证书必须生成全新的密钥对")
            pending_csr = (old.get("target_csr") or {}).get("csr_pem")
            if isinstance(pending_csr, str):
                try:
                    if digest_key(x509.load_pem_x509_csr(pending_csr.encode()).public_key()) == pub_sha:
                        raise ValueError("新证书必须生成全新的密钥对")
                except ValueError:
                    raise
                except Exception:
                    pass
        return pub_sha
    except (ValueError, TypeError, KeyError, AttributeError, InvalidSignature, x509.ExtensionNotFound) as exc:
        raise ValidationError(f"公钥请求验证失败：{exc}") from exc


def validate_target_proof(job, proof_b64, card_slot=None, chain_slots=None, raw_chain=None):
    try:
        raw_chain = raw_chain if raw_chain is not None else job.get("signed_chain_pem")
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


def validate_signed_chain(job, raw_chain, tls_config, *, requester_user):
    from .models import ClientCertificateIdentity
    from .roles import assigned_roles
    from .security_policy import suspended

    now = timezone.now()
    try:
        if (not isinstance(raw_chain, list) or not 2 <= len(raw_chain) <= 8 or
                any(not isinstance(p, str) or len(p) > 16000 for p in raw_chain)):
            raise ValueError("证书链长度或格式无效")
        certs = [x509.load_pem_x509_certificate(p.encode()) for p in raw_chain]
        leaf, chain = certs[0], certs[1:]
        csr = x509.load_pem_x509_csr(job["csr_pem"].encode())
        if spki(leaf.public_key()) != spki(csr.public_key()) or leaf.subject != csr.subject:
            raise ValueError("证书公钥或实名与 CSR 不匹配")
        if leaf.extensions.get_extension_for_oid(BINDING_OID).value.value != canonical({**card_binding(job), "write_nonce": job["write_nonce"]}):
            raise ValueError("证书任务绑定不匹配")
        if not issuer_matches(leaf.public_key(), chain[0].public_key()):
            raise ValueError("签发 CA 算法与目标公钥不匹配")
        for cert in certs:
            if not (cert.not_valid_before_utc <= now <= cert.not_valid_after_utc):
                raise ValueError("证书链尚未生效或已过期")
        if leaf.not_valid_after_utc > min(c.not_valid_after_utc for c in chain):
            raise ValueError("客户端证书有效期超过了签发 CA")
        eku = leaf.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        if ExtendedKeyUsageOID.CLIENT_AUTH not in eku:
            raise ValueError("客户端证书缺少 CLIENT_AUTH 用途")
        ku = leaf.extensions.get_extension_for_class(x509.KeyUsage).value
        bc = leaf.extensions.get_extension_for_class(x509.BasicConstraints).value
        if not ku.digital_signature:
            raise ValueError("客户端证书缺少数字签名用途")
        if job.get("temporary"):
            days = job.get("validity_days")
            max_span = timedelta(days=int(days)) if type(days) is int and 1 <= days <= 36 else timedelta(days=36)
            if bc.ca or ku.key_cert_sign or (leaf.not_valid_after_utc - leaf.not_valid_before_utc) >= timedelta(days=37):
                raise ValueError("临时证书必须为 CA:FALSE 的最终证书，且有效期必须短于 37 天")
            if leaf.not_valid_after_utc - now > max_span + timedelta(minutes=10):
                raise ValueError("临时证书有效期超过了申请天数")
        elif job.get("delegated_ca"):
            if not (bc.ca and bc.path_length == 0 and ku.key_cert_sign):
                raise ValueError("标准超管/超级特权证书必须带有 CA:TRUE pathLen=0")
        else:
            if bc.ca or ku.key_cert_sign:
                raise ValueError("普通特权证书不得带有 CA 签发属性")
        perm = getattr(requester_user, "permission", None)
        priv_exp = getattr(perm, "privileged_expires_at", None)
        if priv_exp is not None:
            if not job.get("temporary") or job.get("delegated_ca"):
                raise ValueError("临时特权账号不得签发长期或超管 CA 证书")
            if priv_exp <= now or leaf.not_valid_after_utc > priv_exp:
                raise ValueError("临时特权账号证书有效期不得超过特权到期时间")
        for idx, (child, issuer) in enumerate(zip(certs, chain)):
            child.verify_directly_issued_by(issuer)
            ibc = issuer.extensions.get_extension_for_class(x509.BasicConstraints).value
            iku = issuer.extensions.get_extension_for_class(x509.KeyUsage).value
            required_path = idx + (1 if bc.ca else 0)
            if not (ibc.ca and iku.key_cert_sign and (ibc.path_length is None or ibc.path_length >= required_path)):
                raise ValueError("证书链包含无签发权限或路径深度越界的 CA")
    except (ValueError, TypeError, KeyError, AttributeError, InvalidSignature, x509.ExtensionNotFound) as exc:
        raise ValidationError(f"证书链验证失败：{exc}") from exc

    roots, subcas, site_cas, local_ca_only = _load_tls_certs(tls_config)
    root_fps = {fingerprint(r) for r in roots}
    if fingerprint(chain[-1]) not in root_fps:
        raise ValidationError("证书链未连接到站点信任根证书")

    issuer_fp = fingerprint(chain[0])
    site_fps = {fingerprint(c) for c in site_cas}
    if issuer_fp in site_fps:
        if not local_ca_only:
            for child, issuer in zip(certs, chain):
                _check_crl(child, issuer, tls_config, now)
        return leaf, chain, "ca_card", "CA 卡"

    if job.get("temporary") and issuer_fp in set(job.get("delegated_authorities", [])):
        row = (
            ClientCertificateIdentity.objects
            .select_related("user", "user__permission")
            .filter(
                fingerprint=issuer_fp,
                revoked_at__isnull=True,
                is_ca=True,
                is_temporary=False,
                expires_at__gt=now,
            )
            .first()
        )
        if not row or row.user_id == requester_user.pk or not row.user.is_currently_active or suspended(row.user):
            raise ValidationError("所选超管/超级特权 CA 证书已失效或不可用于本人自签")
        owner_roles = assigned_roles(row.user.permission)
        if not (owner_roles & {"super_admin", "superadmin_admin"}):
            raise ValidationError("所选签发者不具备超管或超级特权角色")
        if not _verify_delegated_ca_cert(chain[0], roots, subcas, local_ca_only, tls_config, now):
            raise ValidationError("所选超管/超级特权 CA 证书链或撤销状态校验未通过")
        issuer_kind, issuer_label = _delegated_card_meta(owner_roles)
        return leaf, chain, issuer_kind, issuer_label

    raise ValidationError("签发 CA 不在本次任务的允许签发者列表内")
