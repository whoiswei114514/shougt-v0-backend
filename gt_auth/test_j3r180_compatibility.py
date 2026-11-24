"""Compatibility and security boundary tests for NXP J3R180 (OpenFIPS201 + us.q3q.fido2 FIDO2Applet)."""
import base64
import hashlib
import os
import sys
import tempfile
import uuid
from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID, ObjectIdentifier
from django.conf import settings
from django.core.cache import cache
from django.test import TestCase, override_settings
from django.utils import timezone
from fido2.cose import ES256
from fido2.webauthn import AttestationObject, AttestedCredentialData, AuthenticatorData, CollectedClientData
from rest_framework.test import APIClient

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "shougt-sa"))
from backend.certificates import CertificateVerifier
from backend.piv_cli import make_certificate, make_csr
from backend.piv_crypto import write_proof
from backend.policy import Rejected
from backend.service import Service
from tests.certificates_fixture import PKI

from . import webauthn
from .models import Role, RoleMember
from .sessions import create_session
from .test_console import DjangoTestDatabase
from .test_support import PASSWORD, add_key, authenticate, make_user

FIDO_AAGUID_OID = ObjectIdentifier("1.3.6.1.4.1.45724.1.1.4")
J3R180_AAGUID = "4b5be07b-e6a6-4443-a190-3b201b27f1c5"
ALT_AAGUID = "2f8a5e10-91b3-4c22-8f11-123456789abc"
ZERO_AAGUID = "00000000-0000-0000-0000-000000000000"


def _build_ca(cn, issuer_cert=None, issuer_key=None, *, path_length=None):
    key = ec.generate_private_key(ec.SECP384R1())
    now = timezone.now()
    name = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "cn"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "w"),
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(issuer_cert.subject if issuer_cert else name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=path_length), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False, key_cert_sign=True, crl_sign=True,
                encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .sign(issuer_key or key, hashes.SHA384())
    )
    return key, cert


class J3R180VirtualCard:
    """Simulates a contact/NFC J3R180 FIDO2Applet producing packed 3-tier x5c attestation."""

    def __init__(self, *, aaguid=J3R180_AAGUID, ca_chain=()):
        self.aaguid = aaguid
        self.aaguid_bytes = uuid.UUID(aaguid).bytes
        self.ca_chain = list(ca_chain)  # [(issuer_key, issuer_cert), ..., root_cert_or_pair]
        self.credential_key = ec.generate_private_key(ec.SECP256R1())
        self.id = os.urandom(32)
        self.data = AttestedCredentialData.create(
            self.aaguid_bytes, self.id, ES256.from_cryptography_key(self.credential_key.public_key())
        )
        self.counter = 1

    def registration(self, options, *, origin="http://localhost:15173", attachment="cross-platform", transports=None):
        client = CollectedClientData.create("webauthn.create", options["publicKey"]["challenge"], origin, cross_origin=False)
        flags = AuthenticatorData.FLAG.UP | AuthenticatorData.FLAG.AT | AuthenticatorData.FLAG.UV
        auth = AuthenticatorData.create(hashlib.sha256(b"localhost").digest(), flags, self.counter, self.data)

        leaf_signer = ec.generate_private_key(ec.SECP256R1())
        issuer_key, issuer_cert = self.ca_chain[0]
        now = timezone.now()
        name = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "cn"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "w"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Authenticator Attestation"),
            x509.NameAttribute(NameOID.COMMON_NAME, "J3R180-FIDO2"),
        ])
        leaf = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(issuer_cert.subject)
            .public_key(leaf_signer.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(hours=1))
            .not_valid_after(now + timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.UnrecognizedExtension(FIDO_AAGUID_OID, b"\x04\x10" + self.aaguid_bytes), critical=False)
            .sign(issuer_key, hashes.SHA384())
        )
        x5c = [leaf.public_bytes(serialization.Encoding.DER)] + [
            cert.public_bytes(serialization.Encoding.DER) for _, cert in self.ca_chain
        ]
        stmt = {"alg": -7, "sig": leaf_signer.sign(bytes(auth) + client.hash, ec.ECDSA(hashes.SHA256())), "x5c": x5c}
        attestation_obj = AttestationObject.create("packed", auth, stmt)
        return {
            "id": webauthn.b64(self.id),
            "rawId": webauthn.b64(self.id),
            "type": "public-key",
            "authenticatorAttachment": attachment,
            "clientExtensionResults": {},
            "response": {
                "clientDataJSON": webauthn.b64(client),
                "attestationObject": webauthn.b64(attestation_obj),
                "transports": ["smart-card"] if transports is None else transports,
            },
        }

    def assertion(self, options, *, origin="http://localhost:15173", user_handle=None):
        self.counter += 3
        client = CollectedClientData.create("webauthn.get", options["publicKey"]["challenge"], origin, cross_origin=False)
        flags = AuthenticatorData.FLAG.UP | AuthenticatorData.FLAG.UV
        auth = AuthenticatorData.create(hashlib.sha256(b"localhost").digest(), flags, self.counter)
        sig = self.credential_key.sign(bytes(auth) + client.hash, ec.ECDSA(hashes.SHA256()))
        return {
            "id": webauthn.b64(self.id),
            "rawId": webauthn.b64(self.id),
            "type": "public-key",
            "authenticatorAttachment": "cross-platform",
            "clientExtensionResults": {},
            "response": {
                "clientDataJSON": webauthn.b64(client),
                "authenticatorData": webauthn.b64(auth),
                "signature": webauthn.b64(sig),
                "userHandle": user_handle,
            },
        }


class J3R180CompatibilityTests(TestCase):
    def setUp(self):
        cache.clear()
        self.tmp = tempfile.TemporaryDirectory(prefix="j3r180-compat-")
        self.addCleanup(self.tmp.cleanup)
        tdir = Path(self.tmp.name)

        self.root_key, self.root_cert = _build_ca("w", path_length=None)
        self.fidoca_key, self.fidoca_cert = _build_ca("SHOUGTFIDOCA", self.root_cert, self.root_key, path_length=0)
        self.other_sub_key, self.other_sub_cert = _build_ca("SHOUGT-SubCA", self.root_cert, self.root_key, path_length=0)

        self.root_pem = tdir / "root_w.pem"
        self.fidoca_pem = tdir / "shougtfidoca.pem"
        self.root_pem.write_bytes(self.root_cert.public_bytes(serialization.Encoding.PEM))
        self.fidoca_pem.write_bytes(self.fidoca_cert.public_bytes(serialization.Encoding.PEM))

        self.j3r_trust = [{
            "id": "shougt-j3r180-fidoca",
            "root_pem": str(self.root_pem),
            "intermediate_pem": str(self.fidoca_pem),
            "aaguids": [J3R180_AAGUID, "*"],
            "attachment": "cross-platform",
            "assurance": "fips140-2-level2",
            "allow_privileged_single_factor": False,
            "metadata_reference": "SHOUGTFIDOCA + w (NXP J3R180 Test)",
            "certification_reference": "SHOUGTFIDOCA-J3R180-FIPS140-2-L2",
            "valid_until": (timezone.now() + timedelta(days=365)).isoformat(),
            "revoked_certificates": [],
        }]

    def test_bundled_public_ca_defaults_and_real_card_chain_validity(self):
        entry = next((e for e in settings.FIDO_ATTESTATION_TRUST if e.get("id") == "shougt-j3r180-fidoca"), None)
        self.assertIsNotNone(entry)
        self.assertEqual(entry["assurance"], "fips140-2-level2")
        self.assertFalse(entry["allow_privileged_single_factor"])
        self.assertTrue(Path(entry["root_pem"]).exists())
        self.assertTrue(Path(entry["intermediate_pem"]).exists())

        fidoca = x509.load_pem_x509_certificate(Path(entry["intermediate_pem"]).read_bytes())
        root = x509.load_pem_x509_certificate(Path(entry["root_pem"]).read_bytes())
        fidoca.verify_directly_issued_by(root)
        self.assertEqual(fidoca.extensions.get_extension_for_class(x509.BasicConstraints).value.path_length, 0)

        leaf_env = os.environ.get("SHOUGT_J3R180_LEAF_PEM", "").strip()
        if leaf_env:
            leaf_path = Path(leaf_env)
            self.assertTrue(leaf_path.is_file(), f"SHOUGT_J3R180_LEAF_PEM not found: {leaf_path}")
            leaf = x509.load_pem_x509_certificate(leaf_path.read_bytes())
            leaf.verify_directly_issued_by(fidoca)
            self.assertEqual(leaf.extensions.get_extension_for_oid(FIDO_AAGUID_OID).value.value, b"\x04\x10" + uuid.UUID(J3R180_AAGUID).bytes)

    def test_intermediate_ca_pinning_rejects_other_subcas_direct_root_and_zero_aaguid(self):
        user, role = make_user("j3r_pin", roles=["base_admin"])
        client = APIClient()
        authenticate(client, user, role)

        with override_settings(FIDO_ATTESTATION_TRUST=self.j3r_trust):
            # 1. Exact J3R180 AAGUID via SHOUGTFIDOCA -> Root w: ACCEPTED as fips140-2-level2
            card_exact = J3R180VirtualCard(aaguid=J3R180_AAGUID, ca_chain=[(self.fidoca_key, self.fidoca_cert)])
            opts = webauthn.begin_registration(user, kind="security_key", name="J3R180 exact")
            key_exact = webauthn.finish_registration(user, opts["challenge_id"], card_exact.registration(opts))
            self.assertTrue(key_exact.attestation_verified)
            self.assertEqual(key_exact.assurance_level, "fips140-2-level2")
            self.assertEqual(webauthn.credential_assurance(key_exact)["label"], "FIPS 140-2 L2")

            # 2. Different valid non-zero UUID under pinned SHOUGTFIDOCA (wildcard "*"): ACCEPTED
            card_alt = J3R180VirtualCard(aaguid=ALT_AAGUID, ca_chain=[(self.fidoca_key, self.fidoca_cert), (self.root_key, self.root_cert)])
            opts_alt = webauthn.begin_registration(user, kind="security_key", name="J3R180 batch2")
            key_alt = webauthn.finish_registration(user, opts_alt["challenge_id"], card_alt.registration(opts_alt))
            self.assertTrue(key_alt.attestation_verified)
            self.assertEqual(key_alt.assurance_level, "fips140-2-level2")

            # 3. Zero AAGUID / direct root / other sub-CA: may enroll only as ordinary unattested key (never trusted/FIPS)
            for label, card in (
                ("zero", J3R180VirtualCard(aaguid=ZERO_AAGUID, ca_chain=[(self.fidoca_key, self.fidoca_cert)])),
                ("direct", J3R180VirtualCard(aaguid=J3R180_AAGUID, ca_chain=[(self.root_key, self.root_cert)])),
                ("other", J3R180VirtualCard(aaguid=J3R180_AAGUID, ca_chain=[(self.other_sub_key, self.other_sub_cert)])),
            ):
                u_bad, _ = make_user(f"j3r_{label}", roles=["base_admin"])
                opts_bad = webauthn.begin_registration(u_bad, kind="security_key", name=f"bad {label}")
                k_bad = webauthn.finish_registration(u_bad, opts_bad["challenge_id"], card.registration(opts_bad))
                self.assertFalse(k_bad.attestation_verified, label)
                self.assertEqual(k_bad.assurance_level, "standard", label)
                self.assertFalse(webauthn.trusted_hardware(k_bad), label)
                self.assertFalse(webauthn.credential_assurance(k_bad)["high_assurance"], label)

    def test_ordinary_manager_single_factor_vs_privileged_requires_second_factor_both_sides(self):
        # Ordinary manager (is_management=True, is_privileged=False)
        ord_user, ord_role = make_user("ord_j3r", roles=["base_admin"])
        ord_card = J3R180VirtualCard(aaguid=J3R180_AAGUID, ca_chain=[(self.fidoca_key, self.fidoca_cert)])
        with override_settings(FIDO_ATTESTATION_TRUST=self.j3r_trust):
            opts = webauthn.begin_registration(ord_user, kind="security_key", name="J3R180")
            ord_key = webauthn.finish_registration(ord_user, opts["challenge_id"], ord_card.registration(opts))

            c = APIClient()
            begin = c.post("/security/key-login-begin/", {"username": ord_user.username}, format="json").data
            resp = c.post("/security/key-login-finish/", {"challenge_id": begin["challenge_id"], "credential": ord_card.assertion(begin)}, format="json")
            self.assertEqual(resp.status_code, 200, resp.data)
            self.assertNotIn("factor_required", resp.data)
            self.assertTrue(resp.data["security"]["admin_access"])
            self.assertEqual(resp.data["security"]["session_key_assurance"]["level"], "fips140-2-level2")

        # Privileged roles all see FIPS 140-2 L2 badge, yet CANNOT log in single-factor
        for priv_role in ("super_admin", "admin_admin", "superadmin_admin", "global_reader"):
            cache.clear()
            with self.subTest(priv_role=priv_role), override_settings(FIDO_ATTESTATION_TRUST=self.j3r_trust):
                puser, prole = make_user("priv_" + priv_role, roles=[priv_role])
                pcard = J3R180VirtualCard(aaguid=J3R180_AAGUID, ca_chain=[(self.fidoca_key, self.fidoca_cert)])
                opts = webauthn.begin_registration(puser, kind="security_key", name="J3R180-Priv")
                pkey = webauthn.finish_registration(puser, opts["challenge_id"], pcard.registration(opts))

                # Optional second FIDO key from standard trusted test authority
                backup_key, backup_virtual = add_key(puser)

                client = APIClient()
                b1 = client.post("/security/key-login-begin/", {"username": puser.username}, format="json").data
                f1 = client.post("/security/key-login-finish/", {"challenge_id": b1["challenge_id"], "credential": pcard.assertion(b1)}, format="json")
                self.assertEqual(f1.status_code, 200, f1.data)
                self.assertTrue(f1.data.get("factor_required"), f"{priv_role} must require 2FA")
                self.assertIn("security_key", f1.data["methods"])

                # Reusing the SAME J3R180 key as second factor fails
                k2_opts = client.post("/security/factor-key-begin/", {"ticket": f1.data["ticket"]}, format="json").data
                same_fail = client.post("/security/factor-finish/", {"ticket": f1.data["ticket"], "method": "security_key", "challenge_id": k2_opts["challenge_id"], "credential": pcard.assertion(k2_opts)}, format="json")
                self.assertEqual(same_fail.status_code, 400)

                # Using password factor completes privileged login & shows FIPS 140-2 L2
                b2 = client.post("/security/key-login-begin/", {"username": puser.username}, format="json").data
                f2 = client.post("/security/key-login-finish/", {"challenge_id": b2["challenge_id"], "credential": pcard.assertion(b2)}, format="json")
                done_pw = client.post("/security/factor-finish/", {"ticket": f2.data["ticket"], "method": "password", "password": PASSWORD}, format="json")
                self.assertEqual(done_pw.status_code, 200, done_pw.data)
                self.assertTrue(done_pw.data["security"]["admin_access"])
                self.assertEqual(done_pw.data["security"]["session_key_assurance"]["level"], "fips140-2-level2")

                # Using J3R180 as the SECOND FIDO key paired with another key also succeeds
                b3 = client.post("/security/key-login-begin/", {"username": puser.username}, format="json").data
                f3 = client.post("/security/key-login-finish/", {"challenge_id": b3["challenge_id"], "credential": backup_virtual.assertion(b3)}, format="json")
                self.assertTrue(f3.data.get("factor_required"))
                k2_j3r = client.post("/security/factor-key-begin/", {"ticket": f3.data["ticket"]}, format="json").data
                done_2k = client.post("/security/factor-finish/", {"ticket": f3.data["ticket"], "method": "security_key", "challenge_id": k2_j3r["challenge_id"], "credential": pcard.assertion(k2_j3r)}, format="json")
                self.assertEqual(done_2k.status_code, 200, done_2k.data)
                self.assertTrue(done_2k.data["security"]["admin_access"])

    def test_shougt_sa_double_enforces_no_single_factor_and_accepts_2fa(self):
        pki = PKI(Path(self.tmp.name) / "piv_pki", client_name="超级卡测试")
        suser, srole = make_user("sa_j3r", roles=["super_admin"])
        suser.real_name = "超级卡测试"
        suser.save(update_fields=["real_name"])
        scard = J3R180VirtualCard(aaguid=J3R180_AAGUID, ca_chain=[(self.fidoca_key, self.fidoca_cert)])

        with override_settings(FIDO_ATTESTATION_TRUST=self.j3r_trust):
            opts = webauthn.begin_registration(suser, kind="security_key", name="J3R180 SA")
            skey = webauthn.finish_registration(suser, opts["challenge_id"], scard.registration(opts))
            from .models import ClientCertificateIdentity
            cert_info = CertificateVerifier(pki.config).verify(pki.client.public_bytes(serialization.Encoding.DER))
            ClientCertificateIdentity.objects.create(
                fingerprint=cert_info["fingerprint"],
                user=suser,
                real_name=suser.real_name,
                issuer_fingerprint=cert_info["issuer_fingerprint"],
                serial_number=cert_info["serial_number"],
                expires_at=cert_info["expires_at"],
            )
            service = Service(
                SimpleNamespace(database={}, tls=pki.config, session_minutes=15, main_origin="http://localhost:15173", console_origin="https://privileged.localhost:18443"),
                database=DjangoTestDatabase(),
                verifier=CertificateVerifier(pki.config),
            )

            # A forged/stale single-factor fido2 session for J3R180 must still be rejected by shougt-sa
            api = APIClient()
            authenticate(api, suser, srole, key=skey, methods=["fido2"])
            b1 = api.post("/security/console-begin/").data
            # Even main-site console-begin denies privileged session without 2FA
            self.assertNotIn("challenge_id", b1)

            stale_session = create_session(suser, ["fido2"], credential=skey, scope="full")
            from .models import ConsoleTicket
            raw_tok = "stale-single-factor-j3r-token"
            ConsoleTicket.objects.create(
                token_hash=hashlib.sha256(raw_tok.encode()).hexdigest(),
                session=stale_session,
                expires_at=timezone.now() + timedelta(minutes=2),
            )
            with self.assertRaisesRegex(Rejected, "独立验证"):
                service.login(raw_tok, cert_info)

            # With 2FA (fido2 + password), both main-site console handoff AND shougt-sa login succeed!
            authenticate(api, suser, srole, key=skey, methods=["fido2", "password"])
            cb = api.post("/security/console-begin/", format="json")
            self.assertEqual(cb.status_code, 200, cb.data)
            cf = api.post("/security/console-finish/", {"challenge_id": cb.data["challenge_id"], "credential": scard.assertion(cb.data)}, format="json")
            self.assertEqual(cf.status_code, 200, cf.data)
            tok = cf.data["url"].split("#ticket=", 1)[1]
            sess = service.login(tok, cert_info)
            info = service.info(sess["session_token"], cert_info)
            self.assertEqual(info["user_id"], suser.pk)
            self.assertIn("super_admin", info["roles"])

    def test_admin_setup_finish_respects_j3r180_role_single_factor_policy(self):
        with override_settings(FIDO_ATTESTATION_TRUST=self.j3r_trust):
            # Case 1: Ordinary manager (base_admin) completes onboarding single-factor via J3R180
            ord_user, ord_role = make_user("ord_onboard_j3r", roles=["base_admin"])
            ord_card = J3R180VirtualCard(aaguid=J3R180_AAGUID, ca_chain=[(self.fidoca_key, self.fidoca_cert)])
            opts_ord = webauthn.begin_registration(ord_user, kind="security_key", name="J3R180 Ord")
            ord_key = webauthn.finish_registration(ord_user, opts_ord["challenge_id"], ord_card.registration(opts_ord))
            ord_user.admin_onboarding_required = True
            ord_user.save(update_fields=["admin_onboarding_required"])

            ord_api = APIClient()
            authenticate(ord_api, ord_user, ord_role, key=ord_key, methods=["fido2"])
            begin_ord = ord_api.post("/security/admin-setup-begin/", {}, format="json")
            self.assertEqual(begin_ord.status_code, 200, begin_ord.data)
            finish_ord = ord_api.post(
                "/security/admin-setup-finish/",
                {"challenge_id": begin_ord.data["challenge_id"], "credential": ord_card.assertion(begin_ord.data)},
                format="json",
            )
            self.assertEqual(finish_ord.status_code, 200, finish_ord.data)
            self.assertFalse(finish_ord.data["security"]["admin_onboarding_required"])
            self.assertTrue(finish_ord.data["security"]["admin_access"])
            ord_user.refresh_from_db()
            self.assertFalse(ord_user.admin_onboarding_required)

            # Case 2: Privileged manager (super_admin) is blocked single-factor (403) and succeeds with 2FA
            cache.clear()
            priv_user, priv_role = make_user("priv_onboard_j3r", roles=["super_admin"])
            priv_card = J3R180VirtualCard(aaguid=J3R180_AAGUID, ca_chain=[(self.fidoca_key, self.fidoca_cert)])
            opts_priv = webauthn.begin_registration(priv_user, kind="security_key", name="J3R180 Priv")
            priv_key = webauthn.finish_registration(priv_user, opts_priv["challenge_id"], priv_card.registration(opts_priv))
            priv_user.admin_onboarding_required = True
            priv_user.save(update_fields=["admin_onboarding_required"])

            priv_api = APIClient()
            authenticate(priv_api, priv_user, priv_role, key=priv_key, methods=["fido2"])
            begin_sf = priv_api.post("/security/admin-setup-begin/", {}, format="json")
            self.assertEqual(begin_sf.status_code, 200, begin_sf.data)
            finish_sf = priv_api.post(
                "/security/admin-setup-finish/",
                {"challenge_id": begin_sf.data["challenge_id"], "credential": priv_card.assertion(begin_sf.data)},
                format="json",
            )
            self.assertEqual(finish_sf.status_code, 403, finish_sf.data)
            priv_user.refresh_from_db()
            self.assertTrue(priv_user.admin_onboarding_required)

            authenticate(priv_api, priv_user, priv_role, key=priv_key, methods=["fido2", "password"])
            begin_2fa = priv_api.post("/security/admin-setup-begin/", {}, format="json")
            self.assertEqual(begin_2fa.status_code, 200, begin_2fa.data)
            finish_2fa = priv_api.post(
                "/security/admin-setup-finish/",
                {"challenge_id": begin_2fa.data["challenge_id"], "credential": priv_card.assertion(begin_2fa.data)},
                format="json",
            )
            self.assertEqual(finish_2fa.status_code, 200, finish_2fa.data)
            self.assertFalse(finish_2fa.data["security"]["admin_onboarding_required"])
            self.assertTrue(finish_2fa.data["security"]["admin_access"])
            priv_user.refresh_from_db()
            self.assertFalse(priv_user.admin_onboarding_required)

    def test_mobile_nfc_null_attachment_non_discoverable_and_empty_user_handle(self):
        with override_settings(FIDO_ATTESTATION_TRUST=self.j3r_trust):
            user, role = make_user("mobile_j3r", roles=["base_admin"])
            api = APIClient()
            authenticate(api, user, role, methods=["password", "email"], scope="enrollment")

            # 1. resident_key="discouraged" + authenticatorAttachment=None + transports=["nfc"] succeeds via API
            begin = api.post(
                "/security/key-register-begin/",
                {"kind": "security_key", "name": "Mobile NFC Card", "resident_key": "discouraged"},
                format="json",
            )
            self.assertEqual(begin.status_code, 200, begin.data)
            self.assertEqual(begin.data["publicKey"]["authenticatorSelection"]["residentKey"], "discouraged")

            card = J3R180VirtualCard(aaguid=J3R180_AAGUID, ca_chain=[(self.fidoca_key, self.fidoca_cert)])
            fin = api.post(
                "/security/key-register-finish/",
                {
                    "challenge_id": begin.data["challenge_id"],
                    "credential": card.registration(begin.data, attachment=None, transports=["nfc"]),
                },
                format="json",
            )
            self.assertEqual(fin.status_code, 200, fin.data)
            key = user.security_keys.get(pk=fin.data["id"])
            self.assertTrue(key.is_security_key)
            self.assertTrue(key.attestation_verified)
            self.assertEqual(key.assurance_level, "fips140-2-level2")

            # 2. authenticatorAttachment="platform" MUST still be rejected for security_key
            authenticate(api, user, role, key=key, methods=["fido2"])
            begin_plat = api.post(
                "/security/key-register-begin/",
                {"kind": "security_key", "name": "Platform Key", "resident_key": "discouraged"},
                format="json",
            )
            self.assertEqual(begin_plat.status_code, 200, begin_plat.data)
            bad_plat = api.post(
                "/security/key-register-finish/",
                {
                    "challenge_id": begin_plat.data["challenge_id"],
                    "credential": card.registration(begin_plat.data, attachment="platform", transports=["internal"]),
                },
                format="json",
            )
            self.assertEqual(bad_plat.status_code, 400)

            # 3. Non-discoverable assertion with empty userHandle ("") AND None both succeed, wrong handle fails
            anon = APIClient()
            l1 = anon.post("/security/key-login-begin/", {"username": user.username}, format="json")
            self.assertEqual(l1.status_code, 200)
            r1 = anon.post(
                "/security/key-login-finish/",
                {"challenge_id": l1.data["challenge_id"], "credential": card.assertion(l1.data, user_handle="")},
                format="json",
            )
            self.assertEqual(r1.status_code, 200, r1.data)

            l2 = anon.post("/security/key-login-begin/", {"username": user.username}, format="json")
            r2 = anon.post(
                "/security/key-login-finish/",
                {"challenge_id": l2.data["challenge_id"], "credential": card.assertion(l2.data, user_handle=None)},
                format="json",
            )
            self.assertEqual(r2.status_code, 200, r2.data)

            l3 = anon.post("/security/key-login-begin/", {"username": user.username}, format="json")
            r3 = anon.post(
                "/security/key-login-finish/",
                {
                    "challenge_id": l3.data["challenge_id"],
                    "credential": card.assertion(l3.data, user_handle=webauthn.b64(b"999999")),
                },
                format="json",
            )
            self.assertEqual(r3.status_code, 400)

    def test_super_admin_shougtkey_plus_unattested_ordinary_second_key_works_both_sides(self):
        from .test_support import VirtualKey
        pki = PKI(Path(self.tmp.name) / "piv_pki_combo", client_name="组合双钥超管")
        suser, srole = make_user("sa_combo", roles=["super_admin"])
        suser.real_name = "组合双钥超管"
        suser.save(update_fields=["real_name"])
        scard = J3R180VirtualCard(aaguid=J3R180_AAGUID, ca_chain=[(self.fidoca_key, self.fidoca_cert)])
        ordin = VirtualKey(suser)

        with override_settings(FIDO_ATTESTATION_TRUST=self.j3r_trust):
            opts1 = webauthn.begin_registration(suser, kind="security_key", name="J3R180 Primary")
            skey = webauthn.finish_registration(suser, opts1["challenge_id"], scard.registration(opts1))
            opts2 = webauthn.begin_registration(suser, kind="security_key", name="Ordinary Backup")
            okey = webauthn.finish_registration(suser, opts2["challenge_id"], ordin.registration(opts2, attestation=False))
            self.assertFalse(okey.attestation_verified)
            self.assertEqual(okey.assurance_level, "standard")

            client = APIClient()
            b1 = client.post("/security/key-login-begin/", {"username": suser.username}, format="json").data
            f1 = client.post("/security/key-login-finish/", {"challenge_id": b1["challenge_id"], "credential": scard.assertion(b1)}, format="json")
            self.assertEqual(f1.status_code, 200, f1.data)
            self.assertTrue(f1.data.get("factor_required"))
            self.assertIn("security_key", f1.data["methods"])

            fk = client.post("/security/factor-key-begin/", {"ticket": f1.data["ticket"]}, format="json").data
            done = client.post(
                "/security/factor-finish/",
                {"ticket": f1.data["ticket"], "method": "security_key", "challenge_id": fk["challenge_id"], "credential": ordin.assertion(fk)},
                format="json",
            )
            self.assertEqual(done.status_code, 200, done.data)
            self.assertTrue(done.data["security"]["admin_access"])
            self.assertEqual(done.data["security"]["second_key_id"], okey.pk)

            # Verify shougt-sa accepts the shougtkey + unattested 2nd external key session
            from .models import ClientCertificateIdentity, ConsoleTicket
            cert_info = CertificateVerifier(pki.config).verify(pki.client.public_bytes(serialization.Encoding.DER))
            ClientCertificateIdentity.objects.create(
                fingerprint=cert_info["fingerprint"],
                user=suser,
                real_name=suser.real_name,
                issuer_fingerprint=cert_info["issuer_fingerprint"],
                serial_number=cert_info["serial_number"],
                expires_at=cert_info["expires_at"],
            )
            service = Service(
                SimpleNamespace(database={}, tls=pki.config, session_minutes=15, main_origin="http://localhost:15173", console_origin="https://privileged.localhost:18443"),
                database=DjangoTestDatabase(),
                verifier=CertificateVerifier(pki.config),
            )
            import base64 as _b64, json as _json
            auth_data = done.data["authorization"]
            bearer = _b64.urlsafe_b64encode(_json.dumps(auth_data["payload"]).encode()).decode() + "." + auth_data["signature"]
            client.credentials(HTTP_AUTHORIZATION="Bearer " + bearer)
            cb = client.post("/security/console-begin/", format="json")
            self.assertEqual(cb.status_code, 200, cb.data)
            cf = client.post("/security/console-finish/", {"challenge_id": cb.data["challenge_id"], "credential": scard.assertion(cb.data)}, format="json")
            self.assertEqual(cf.status_code, 200, cf.data)
            tok = cf.data["url"].split("#ticket=", 1)[1]
            sess = service.login(tok, cert_info)
            info = service.info(sess["session_token"], cert_info)
            self.assertEqual(info["user_id"], suser.pk)
            self.assertIn("super_admin", info["roles"])
