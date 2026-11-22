"""Integration tests for Feature 1 (Role Admins), Feature 2 (Temp Bans), Feature 4 (Temp SuperAdmin Certs), and Feature 5 (Browser Self-Service Issuance)."""
import base64
import sys
import tempfile
from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from django.core.cache import cache
from django.test import TestCase
from django.utils import timezone
from rest_framework.test import APIClient

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "shougt-sa"))
from backend.certificates import CertificateVerifier
from backend.issuance import execute_issuance
from backend.piv_cli import make_certificate, make_csr
from backend.piv_crypto import write_proof
from backend.policy import LABELS
from tests.certificates_fixture import PKI

from .models import ClientCertificateIdentity, Role, RoleMember, User, active_role_q
from .roles import assigned_roles
from .test_console import DjangoTestDatabase
from .test_support import add_key, authenticate, make_user


def sign_ec(key):
    return lambda msg: key.sign(msg, ec.ECDSA(hashes.SHA384()))


class RoleAdminAndTempBanTests(TestCase):
    def setUp(self):
        cache.clear()
        self.owner, self.owner_role = make_user("owner1", verified=True)
        self.admin_user, admin_primary = make_user("radmin1", verified=True)
        self.member_user, member_primary = make_user("rmem1", verified=True)
        self.extra_user, extra_primary = make_user("rextra1", verified=True)
        self.hidden_user, _ = make_user("rhidden1", verified=True)
        for user in (self.admin_user, self.member_user, self.extra_user):
            user.privacy.accept_join_role = True
            user.privacy.allow_show_in_list = True
            user.privacy.save(update_fields=["accept_join_role", "allow_show_in_list"])
        self.hidden_user.privacy.accept_join_role = False
        self.hidden_user.privacy.save(update_fields=["accept_join_role"])
        self.site_admin, self.site_admin_role = make_user("sadmin1", roles=["admin_user", "admin_role"], verified=True)
        self.site_key, _ = add_key(self.site_admin)
        self.shared_role = Role.objects.create(name="社团官方号", is_shared=True, editable=True)
        RoleMember.objects.create(role=self.shared_role, user=self.owner, is_owner=True)
        RoleMember.objects.create(role=self.shared_role, user=self.admin_user, is_admin=True)

    def _auth_client(self, user, role, key=None):
        client = APIClient()
        authenticate(client, user, role, key=key)
        return client

    def test_role_admin_member_management_and_boundaries(self):
        owner_client = self._auth_client(self.owner, self.owner_role)
        # Owner designates admin_user and member_user
        r_owner = owner_client.put(
            f"/role/{self.shared_role.pk}/",
            {
                "name": "社团官方号",
                "is_shared": True,
                "members_id": [self.admin_user.pk, self.member_user.pk],
                "admins_id": [self.admin_user.pk],
                "external_links": {},
            },
            format="json",
        )
        self.assertEqual(r_owner.status_code, 200, r_owner.data)
        self.assertTrue(r_owner.data["data"]["is_owner"])
        self.assertEqual([u["id"] for u in r_owner.data["data"]["admins"]], [self.admin_user.pk])

        # Owner cannot appoint non-member as role admin
        r_bad_admin = owner_client.put(
            f"/role/{self.shared_role.pk}/",
            {
                "name": "社团官方号",
                "is_shared": True,
                "members_id": [self.admin_user.pk],
                "admins_id": [self.admin_user.pk, self.extra_user.pk],
                "external_links": {},
            },
            format="json",
        )
        self.assertEqual(r_bad_admin.status_code, 400)

        # Role admin reads role and sees is_admin=True, is_owner=False
        ra_client = self._auth_client(self.admin_user, self.shared_role)
        r_get = ra_client.get(f"/role/{self.shared_role.pk}/")
        self.assertEqual(r_get.status_code, 200)
        self.assertTrue(r_get.data["data"]["is_admin"])
        self.assertFalse(r_get.data["data"]["is_owner"])

        # Role admin adds extra_user and removes member_user via PATCH members_id
        r_patch = ra_client.patch(
            f"/role/{self.shared_role.pk}/",
            {"members_id": [self.admin_user.pk, self.extra_user.pk]},
            format="json",
        )
        self.assertEqual(r_patch.status_code, 200, r_patch.data)
        self.assertEqual(
            set(RoleMember.objects.filter(role=self.shared_role, is_owner=False).values_list("user_id", flat=True)),
            {self.admin_user.pk, self.extra_user.pk},
        )

        # Role admin cannot add non-discoverable private user
        r_hidden = ra_client.patch(
            f"/role/{self.shared_role.pk}/",
            {"members_id": [self.admin_user.pk, self.extra_user.pk, self.hidden_user.pk]},
            format="json",
        )
        self.assertEqual(r_hidden.status_code, 400)

        # Role admin cannot change role name or admins_id or delete role
        r_forbidden_put = ra_client.put(
            f"/role/{self.shared_role.pk}/",
            {"name": "篡改名称", "is_shared": True, "members_id": [self.admin_user.pk]},
            format="json",
        )
        self.assertEqual(r_forbidden_put.status_code, 403)
        r_forbidden_patch = ra_client.patch(
            f"/role/{self.shared_role.pk}/",
            {"name": "篡改名称", "members_id": [self.admin_user.pk]},
            format="json",
        )
        self.assertEqual(r_forbidden_patch.status_code, 403)
        ra_primary_client = self._auth_client(self.admin_user, self.admin_user.primary_role)
        self.assertIn(ra_primary_client.delete(f"/role/{self.shared_role.pk}/").status_code, (400, 403))
        self.assertTrue(Role.objects.filter(pk=self.shared_role.pk, deleted=False).exists())

        # Role admin cannot remove another role admin
        RoleMember.objects.create(role=self.shared_role, user=self.member_user, is_admin=True)
        r_remove_admin = ra_client.patch(
            f"/role/{self.shared_role.pk}/",
            {"members_id": [self.admin_user.pk]},
            format="json",
        )
        self.assertEqual(r_remove_admin.status_code, 400)
        self.assertTrue(RoleMember.objects.filter(role=self.shared_role, user=self.member_user, is_admin=True).exists())

    def test_temporary_ban_user_and_role_expiration(self):
        admin_client = self._auth_client(self.site_admin, self.site_admin_role, key=self.site_key)
        # Temp ban user for 2 hours
        r_ban = admin_client.post(
            f"/admin/user/{self.member_user.pk}/ban/",
            {"duration_minutes": 120},
            format="json",
        )
        self.assertEqual(r_ban.status_code, 200, r_ban.data)
        self.member_user.refresh_from_db()
        self.assertTrue(self.member_user.is_active)
        self.assertFalse(self.member_user.is_currently_active)

        # Temp-banned user JWT session is rejected immediately
        mem_client = self._auth_client(self.member_user, self.member_user.primary_role)
        self.assertEqual(mem_client.get("/user/info/").status_code, 401)

        # Once banned_until passes into the past, access automatically recovers
        self.member_user.banned_until = timezone.now() - timedelta(minutes=1)
        self.member_user.save(update_fields=["banned_until"])
        self.member_user.refresh_from_db()
        self.assertTrue(self.member_user.is_currently_active)
        self.assertEqual(mem_client.get("/user/info/").status_code, 200)

        # Temp ban role for 2 hours -> disappears from active role query until expiry
        r_rban = admin_client.post(
            f"/admin/role/{self.shared_role.pk}/ban/",
            {"duration_minutes": 120},
            format="json",
        )
        self.assertEqual(r_rban.status_code, 200, r_rban.data)
        self.shared_role.refresh_from_db()
        self.assertFalse(self.shared_role.is_currently_active)
        self.assertNotIn(
            self.shared_role.pk,
            Role.objects.filter(pk=self.shared_role.pk).filter(active_role_q()).values_list("pk", flat=True),
        )
        # Auto recovery when role banned_until expires
        self.shared_role.banned_until = timezone.now() - timedelta(seconds=5)
        self.shared_role.save(update_fields=["banned_until"])
        self.shared_role.refresh_from_db()
        self.assertTrue(self.shared_role.is_currently_active)


class BrowserSelfServiceIssuanceAndTempRoleTests(TestCase):
    def setUp(self):
        cache.clear()
        self.tmp = tempfile.TemporaryDirectory(prefix="shou-browser-piv-")
        self.addCleanup(self.tmp.cleanup)
        self.pki = PKI(self.tmp.name, client_name="超级签发官")
        self.verifier = CertificateVerifier(self.pki.config)
        self.config = SimpleNamespace(tls=self.pki.config)

        self.sa, self.sa_role = make_user("sa_issuer", roles=["super_admin"], verified=True)
        self.sa.real_name = "超级签发官"
        self.sa.real_name_verified_at = timezone.now()
        self.sa.advanced_verified_at = timezone.now()
        self.sa.email_verified_at = timezone.now()
        self.sa.save()
        self.sa_key, _ = add_key(self.sa)

        self.target, self.target_role = make_user("target_temp", verified=True)
        self.target.real_name = "受权读者"
        self.target.real_name_verified_at = timezone.now()
        self.target.advanced_verified_at = timezone.now()
        self.target.email_verified_at = timezone.now()
        self.target.save()
        self.target_key, _ = add_key(self.target)
        self.target_client = APIClient()

    def test_cross_device_browser_issuance_and_privileged_expiry(self):
        cols = ",".join(["p." + k for k in LABELS] + ["p.privileged_expires_at"])
        with DjangoTestDatabase().transaction() as db:
            actor_row = db.one(
                f"SELECT u.*, {cols} FROM gt_auth_user u JOIN gt_auth_permission p ON p.id=u.permission_id WHERE u.id=?",
                (self.sa.pk,),
            )
            # 1. SuperAdmin starts <37-day temporary issuance
            job = execute_issuance(
                db, actor_row, "issuance_begin",
                {"user_id": self.target.pk, "roles": ["global_reader"], "temporary": True, "validity_days": 10},
                self.config, self.verifier,
            )[0]["job"]

        # 2. Target authenticates with FIDO2 on main site and polls /security/issuance-pending/
        authenticate(self.target_client, self.target, self.target_role, key=self.target_key)
        pending = self.target_client.get("/security/issuance-pending/")
        self.assertEqual(pending.status_code, 200)
        self.assertEqual(len(pending.data["jobs"]), 1)
        pjob = pending.data["jobs"][0]
        self.assertTrue(pjob["temporary"])
        self.assertEqual(pjob["validity_days"], 10)

        # 3. Target browser generates WebCrypto keypair and submits CSR
        t_priv = ec.generate_private_key(ec.SECP384R1())
        csr = make_csr({**pjob, "card": {"slot": "9a"}}, t_priv.public_key(), sign_ec(t_priv))
        browser_card = {
            "reader": "Browser WebCrypto", "slot": "9a", "algorithm": "P-384",
            "transport": "browser", "protocol": "WebCrypto", "platform": "browser",
            "on_card_generation": False, "browser_keystore": True,
        }
        csr_resp = self.target_client.post(
            "/security/issuance-csr/",
            {"issuance_id": pjob["issuance_id"], "csr_pem": csr.public_bytes(serialization.Encoding.PEM).decode(), "card": browser_card},
            format="json",
        )
        self.assertEqual(csr_resp.status_code, 200, csr_resp.data)
        self.assertTrue(csr_resp.data["job"]["has_target_csr"])

        # 4. SuperAdmin approves issuance_key & signs with CA -> issuance_sign publishes chain
        with DjangoTestDatabase().transaction() as db:
            status_job = execute_issuance(db, actor_row, "issuance_status", {"issuance_id": pjob["issuance_id"]}, self.config, self.verifier)[0]["job"]
            job_ready = execute_issuance(
                db, actor_row, "issuance_key",
                {"issuance_id": status_job["issuance_id"], **status_job["target_csr"]},
                self.config, self.verifier,
            )[0]["job"]
            chain = [self.pki.sub, self.pki.root]
            leaf = make_certificate(job_ready, self.pki.sub, chain, sign_ec(self.pki.sub_key))
            chain_pem = [c.public_bytes(serialization.Encoding.PEM).decode() for c in [leaf] + chain]
            execute_issuance(
                db, actor_row, "issuance_sign",
                {"issuance_id": job_ready["issuance_id"], "chain_pem": chain_pem, "issuer_slot": "p12"},
                self.config, self.verifier,
            )

        # 5. Target fetches signed_chain_pem, creates proof using non-extractable key, submits /security/issuance-proof/
        pending2 = self.target_client.get("/security/issuance-pending/")
        pjob2 = pending2.data["jobs"][0]
        self.assertEqual(pjob2["signed_chain_pem"], chain_pem)
        proof_b64 = base64.b64encode(sign_ec(t_priv)(write_proof(pjob2, leaf, chain))).decode()
        proof_resp = self.target_client.post(
            "/security/issuance-proof/",
            {"issuance_id": pjob2["issuance_id"], "proof": proof_b64, "card_slot": "9a"},
            format="json",
        )
        self.assertEqual(proof_resp.status_code, 200, proof_resp.data)

        # 6. SuperAdmin calls issuance_finish -> target gets global_reader with privileged_expires_at & temporary cert record
        with DjangoTestDatabase().transaction() as db:
            final_status = execute_issuance(db, actor_row, "issuance_status", {"issuance_id": pjob["issuance_id"]}, self.config, self.verifier)[0]["job"]
            execute_issuance(
                db, actor_row, "issuance_finish",
                {"issuance_id": final_status["issuance_id"], "chain_pem": final_status["signed_chain_pem"], **final_status["target_proof"]},
                self.config, self.verifier,
            )

        self.target.refresh_from_db()
        self.target.permission.refresh_from_db()
        self.assertIn("global_reader", assigned_roles(self.target.permission))
        self.assertIsNotNone(self.target.permission.privileged_expires_at)
        cert_row = ClientCertificateIdentity.objects.get(user=self.target)
        self.assertTrue(cert_row.is_temporary)
        self.assertFalse(cert_row.is_ca)

        # 7. Once privileged_expires_at expires, assigned_roles & User.has_permission("global_reader") revoke automatically
        self.target.permission.privileged_expires_at = timezone.now() - timedelta(minutes=1)
        self.target.permission.save(update_fields=["privileged_expires_at"])
        self.target.refresh_from_db()
        self.assertNotIn("global_reader", assigned_roles(self.target.permission))
        self.assertFalse(User.has_permission(self.target, "global_reader"))
