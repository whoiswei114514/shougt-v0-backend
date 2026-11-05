import base64
import hashlib
import json
import os
import tempfile
from pathlib import Path
from datetime import timedelta

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import NameOID
from django.conf import settings
from django.utils import timezone
from fido2.cose import ES256
from fido2.webauthn import AttestedCredentialData, AuthenticatorData, AttestationObject, CollectedClientData

from gt_coin.models import Coin
from .models import User, Quota, Permission, Privacy, Role, RoleMember
from .sessions import create_session, authorization
from .webauthn import b64, unb64, begin_registration, finish_registration


PASSWORD = "GuaTian!Secure-2026"
_test_attestation = None


def test_attestation_authority():
    global _test_attestation
    if _test_attestation is None:
        directory = tempfile.TemporaryDirectory(prefix="shou-attestation-", dir=os.environ.get("SHOUGT_TEST_TMP"))
        private = ec.generate_private_key(ec.SECP256R1())
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "shou TEST attestation root")])
        now = timezone.now()
        root = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(private.public_key())
                .serial_number(x509.random_serial_number()).not_valid_before(now-timedelta(days=1)).not_valid_after(now+timedelta(days=10))
                .add_extension(x509.BasicConstraints(ca=True,path_length=1),critical=True).sign(private,hashes.SHA256()))
        path = Path(directory.name)/'root.pem';path.write_bytes(root.public_bytes(serialization.Encoding.PEM))
        _test_attestation = (private,root,directory,path)
    private,root,directory,path = _test_attestation
    if not any(item.get('id')=='local-test-hardware' for item in settings.FIDO_ATTESTATION_TRUST):
        settings.FIDO_ATTESTATION_TRUST.append({'id':'local-test-hardware','aaguids':['00000000-0000-0000-0000-000000000000'],
            'assurance':'standard','attachment':'cross-platform','metadata_reference':'LOCAL TEST FIXTURE ONLY',
            'root_pem':str(path),'valid_until':(timezone.now()+timedelta(days=2)).isoformat()})
    return private,root


def make_user(username="student", roles=(), verified=True):
    permission = Permission.objects.create(**{role: True for role in roles})
    user = User.objects.create_user(
        username=username, password=PASSWORD, email=f"{username}@st.shou.edu.cn",
        real_name="测试用户" + username, identity="学生", school="shou",
        email_verified_at=timezone.now() if verified else None,
        real_name_verified_at=timezone.now() if roles else None,
        advanced_verified_at=timezone.now() if roles else None,
        quota=Quota.objects.create(), permission=permission, privacy=Privacy.objects.create(), coin=Coin.objects.create(),
    )
    role = Role.objects.create(name=username + "角色")
    RoleMember.objects.create(user=user, role=role, is_owner=True)
    user.primary_role = role
    user.save(update_fields=["primary_role"])
    return user, role


class VirtualKey:
    """A test authenticator which signs real WebAuthn challenges with a local ES256 key."""
    def __init__(self, user, *, backup=False):
        self.user = user
        self.private_key = ec.generate_private_key(ec.SECP256R1())
        self.id = os.urandom(32)
        self.data = AttestedCredentialData.create(bytes(16), self.id, ES256.from_cryptography_key(self.private_key.public_key()))
        self.counter, self.backup = 1, backup

    def registration(self, options, *, origin="http://localhost:15173", uv=True, cross_origin=False, attestation=True):
        client = CollectedClientData.create("webauthn.create", options["publicKey"]["challenge"], origin, cross_origin=cross_origin)
        flags = AuthenticatorData.FLAG.UP | AuthenticatorData.FLAG.AT
        if uv: flags |= AuthenticatorData.FLAG.UV
        if self.backup: flags |= AuthenticatorData.FLAG.BE
        auth = AuthenticatorData.create(hashlib.sha256(b"localhost").digest(), flags, self.counter, self.data)
        attestation_object = AttestationObject.create("none", auth, {})
        if attestation and not self.backup:
            root_key, root = test_attestation_authority()
            signer = ec.generate_private_key(ec.SECP256R1())
            name = x509.Name([x509.NameAttribute(NameOID.COUNTRY_NAME,'CN'), x509.NameAttribute(NameOID.ORGANIZATION_NAME,'Local test fixture'),
                             x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME,'Authenticator Attestation'),x509.NameAttribute(NameOID.COMMON_NAME,'Virtual key')])
            leaf = (x509.CertificateBuilder().subject_name(name).issuer_name(root.subject).public_key(signer.public_key())
                    .serial_number(x509.random_serial_number()).not_valid_before(timezone.now()-timedelta(days=1)).not_valid_after(timezone.now()+timedelta(days=2))
                    .add_extension(x509.BasicConstraints(ca=False,path_length=None),critical=True).sign(root_key,hashes.SHA256()))
            statement = {'alg':-7,'sig':signer.sign(bytes(auth)+client.hash,ec.ECDSA(hashes.SHA256())),
                         'x5c':[leaf.public_bytes(serialization.Encoding.DER),root.public_bytes(serialization.Encoding.DER)]}
            attestation_object = AttestationObject.create('packed',auth,statement)
        return {"id": b64(self.id), "rawId": b64(self.id), "type": "public-key", "authenticatorAttachment": "platform" if self.backup else "cross-platform",
                "clientExtensionResults": {}, "response": {"clientDataJSON": b64(client), "attestationObject": b64(attestation_object), "transports": ["internal" if self.backup else "usb"]}}

    def assertion(self, options, *, origin="http://localhost:15173", uv=True, rp="localhost", cross_origin=False):
        self.counter += 1
        client = CollectedClientData.create("webauthn.get", options["publicKey"]["challenge"], origin, cross_origin=cross_origin)
        flags = AuthenticatorData.FLAG.UP
        if uv: flags |= AuthenticatorData.FLAG.UV
        if self.backup: flags |= AuthenticatorData.FLAG.BE
        auth = AuthenticatorData.create(hashlib.sha256(rp.encode()).digest(), flags, self.counter)
        signature = self.private_key.sign(bytes(auth) + client.hash, ec.ECDSA(hashes.SHA256()))
        return {"id": b64(self.id), "rawId": b64(self.id), "type": "public-key", "authenticatorAttachment": "cross-platform",
                "clientExtensionResults": {}, "response": {"clientDataJSON": b64(client), "authenticatorData": b64(auth), "signature": b64(signature), "userHandle": b64(str(self.user.pk).encode())}}


def add_key(user, *, backup=False):
    virtual = VirtualKey(user, backup=backup)
    options = begin_registration(user, kind="passkey" if backup else "security_key")
    key = finish_registration(user, options["challenge_id"], virtual.registration(options))
    return key, virtual


def authenticate(client, user, role=None, *, key=None, methods=None, scope="full"):
    session = create_session(user, methods or (["fido2", "password"] if key else ["password"]), credential=key, scope=scope)
    auth = authorization(user, session)
    if role: auth["payload"]["role_id"] = role.pk
    token = base64.urlsafe_b64encode(json.dumps(auth["payload"]).encode()).decode() + "." + auth["signature"]
    client.credentials(HTTP_AUTHORIZATION="Bearer " + token)
    return session, token
