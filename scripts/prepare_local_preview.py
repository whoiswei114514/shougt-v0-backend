"""Create missing local preview data only. Never reset accounts, keys or certificates."""
import json
import os
import sys
from pathlib import Path
from datetime import timedelta
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID

base = Path(__file__).resolve().parents[1]
directory = base / ".local-preview"
directory.mkdir(exist_ok=True)
(directory / "mail").mkdir(exist_ok=True)
(directory / "piv").mkdir(exist_ok=True)
trust = directory / "fido-trust.json"
if not trust.exists():
    trust.write_text("[]\n", encoding="utf-8")
os.environ["SHOUGT_MODE"] = "dev"
os.environ["SHOUGT_LOCAL_PREVIEW"] = "1"
os.environ["DJANGO_SETTINGS_MODULE"] = "gt.local_preview_settings"
sys.path.insert(0, str(base))
import django
django.setup()
from django.core.management import call_command
from django.db import connection
from django.utils import timezone
from gt_auth.models import User, Permission, Privacy, Quota, Role, RoleMember
from gt_coin.models import Coin
from gt_forum.models import Post, PostVersion

call_command("migrate", verbosity=0, interactive=False)
call_command("createcachetable", "dev_cache", verbosity=0)
with connection.cursor() as cursor:
    cursor.execute("PRAGMA journal_mode=WAL")
user, created = User.objects.get_or_create(username="local_user", defaults={
    "real_name": "", "email": "local_user@st.shou.edu.cn", "email_verified_at": timezone.now(),
    "school": "shou", "identity": "学生", "permission": Permission.objects.create(),
    "privacy": Privacy.objects.create(), "quota": Quota.objects.create(), "coin": Coin.objects.create(),
}) if not User.objects.filter(username="local_user").exists() else (User.objects.get(username="local_user"), False)
if created:
    user.set_password("GuaTian!Local-2026")
    user.save()
    role = Role.objects.create(name="海边的同学")
    RoleMember.objects.create(user=user, role=role, is_owner=True)
    user.primary_role = role
    user.save(update_fields=["primary_role"])
    samples = [
        (2, 0, "欢迎来到 shou瓜田", "这里是 shou瓜田的本地预览。\n\n分享校园见闻，记录课程笔记，和同学聊聊最近的生活。\n\n打开设置中的第五项“安全”，就可以绑定自己的安全密钥或通行密钥。", True),
        (1, 0, "", "图书馆窗边的位置，今天刚好能看到一片蓝天。有没有一起整理笔记的同学？", False),
        (1, -3, "", "这是一条角色成员可见的私密讨论。回复会使用你当前选择的角色。", False),
    ]
    for index, (kind, share, title, content, pinned) in enumerate(samples):
        date = timezone.now() - timedelta(minutes=index * 12)
        post = Post.objects.create(author=role, title=title, content=content, type=kind, share_with=share,
                                   review_status=0, pinned=pinned, create_time=date, edit_time=date, source="web")
        PostVersion.objects.create(post=post, user=user, title=title, content=content, images=[], share_with=share,
                                   review_status=0, create_time=date, version=1)

source_ca = Path(os.environ.get("SHOUGT_LOCAL_PIV_CA", r"D:\downloads\w.crt"))
raw = source_ca.read_bytes()
root = x509.load_pem_x509_certificate(raw) if b"-----BEGIN CERTIFICATE-----" in raw else x509.load_der_x509_certificate(raw)
if not root.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
    raise ValueError("The supplied PIV trust certificate must be a CA")
root_path = directory / "piv/root-ca.pem"
root_path.write_bytes(root.public_bytes(serialization.Encoding.PEM))
issuers = []
for path in (directory / "piv").glob("*.pem"):
    if path == root_path:
        continue
    try:
        cert = x509.load_pem_x509_certificate(path.read_bytes())
        cert.verify_directly_issued_by(root)
        if cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
            issuers.append(str(path))
    except (ValueError, TypeError, x509.ExtensionNotFound):
        pass

server_cert, server_key = directory / "server.pem", directory / "server-key.pem"
if not server_cert.exists() or not server_key.exists():
    private = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "privileged.localhost")])
    now = timezone.now()
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(private.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(minutes=5)).not_valid_after(now + timedelta(days=90))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("privileged.localhost")]), critical=False)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .sign(private, hashes.SHA256()))
    server_key.write_bytes(private.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    server_cert.write_bytes(cert.public_bytes(serialization.Encoding.PEM))

config = {"origin":"https://privileged.localhost:18443", "main_origin":"http://localhost:15173", "host":"127.0.0.1", "port":18443,
          "database":{"engine":"sqlite", "path":str(directory / "forum.sqlite3"),
                      "local_key_pins":str(directory / "fido-local-pins.json")},
          "tls":{"certificate":str(server_cert), "private_key":str(server_key), "ca_bundle":str(root_path),
                 "allowed_subcas":issuers, "local_ca_only":True}}
ca_client = directory / "piv/ca-client.json"
if ca_client.exists():
    config["tls"]["local_ca_client"] = json.loads(ca_client.read_text(encoding="utf-8"))
(directory / "console.json").write_text(json.dumps(config, ensure_ascii=False, indent=2), encoding="utf-8")
print("Local database ready; existing users and real FIDO credentials preserved.")
print("PIV trust CA SHA-256:", root.fingerprint(hashes.SHA256()).hex())
