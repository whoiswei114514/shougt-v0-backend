import hashlib
import json
import tempfile
from datetime import timedelta
from pathlib import Path
from unittest.mock import patch

from django.core.cache import cache
from django.test import TestCase, override_settings
from django.utils import timezone
from rest_framework.test import APIClient

from . import webauthn
from .models import RoleMember
from .security_policy import high_assurance
from .test_support import make_user, VirtualKey, authenticate, PASSWORD


class LocalPreviewTests(TestCase):
    def setUp(self):
        cache.clear()
        self.client = APIClient()
        self.user, self.role = make_user("preview")
        self.virtual = VirtualKey(self.user)
        options = webauthn.begin_registration(self.user)
        self.key = webauthn.finish_registration(self.user, options["challenge_id"],
                                               self.virtual.registration(options, attestation=False))
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "pins.json"
        self.pin = {"user_id": self.user.pk, "credential_id": self.key.pk,
                    "public_data_sha256": hashlib.sha256(self.key.credential_data.encode()).hexdigest(),
                    "expires_at": (timezone.now() + timedelta(days=1)).isoformat()}
        self.write_pin()
        self.override = override_settings(DEBUG=True, LOCAL_PREVIEW_MODE=True,
                                          LOCAL_PREVIEW_KEY_PINS_FILE=str(self.path), FIDO_ATTESTATION_TRUST=[])
        self.override.enable()
        self.addCleanup(self.override.disable)

    def write_pin(self):
        self.path.write_text(json.dumps([self.pin]), encoding="utf-8")

    def test_local_pin_cannot_claim_fips_or_enable_production_trust(self):
        self.assertTrue(webauthn.trusted_hardware(self.key))
        self.assertFalse(self.key.attestation_verified)
        self.assertFalse(high_assurance(self.key))
        self.assertEqual(webauthn.credential_assurance(self.key), {
            "level": "standard", "label": "标准验证", "high_assurance": False, "certifications": [],
        })
        for overrides in ({"DEBUG": False}, {"LOCAL_PREVIEW_MODE": False},
                          {"WEBAUTHN_RP_ID": "example.edu.cn"}, {"LOCAL_PREVIEW_KEY_PINS_FILE": ""}):
            with self.subTest(overrides=overrides), override_settings(**overrides):
                self.assertFalse(webauthn.trusted_hardware(self.key))

    def test_pin_binds_key_owner_public_key_and_expiry(self):
        for name, value in (("user_id", self.user.pk + 100), ("credential_id", self.key.pk + 100),
                            ("public_data_sha256", "wrong"),
                            ("expires_at", (timezone.now() - timedelta(seconds=1)).isoformat())):
            original = self.pin[name]
            self.pin[name] = value
            self.write_pin()
            self.assertFalse(webauthn.trusted_hardware(self.key), name)
            self.pin[name] = original
        self.write_pin()
        self.key.backup_eligible = True
        self.assertFalse(webauthn.trusted_hardware(self.key))
        self.key.backup_eligible = False
        self.key.revoked_at = timezone.now()
        self.assertFalse(webauthn.trusted_hardware(self.key))

    def test_pinned_admin_still_needs_valid_signature_and_second_factor(self):
        self.user.permission.super_admin = True
        self.user.permission.save()
        self.user.refresh_from_db()
        self.user.real_name_verified_at = self.user.advanced_verified_at = timezone.now()
        self.user.save()
        options = self.client.post("/security/key-login-begin/", {"username": self.user.username}, format="json").data
        bad = self.virtual.assertion(options)
        bad["response"]["signature"] = webauthn.b64(b"not a signature")
        response = self.client.post("/security/key-login-finish/", {"challenge_id": options["challenge_id"], "credential": bad}, format="json")
        self.assertEqual(response.status_code, 400)
        options = self.client.post("/security/key-login-begin/", {"username": self.user.username}, format="json").data
        response = self.client.post("/security/key-login-finish/", {"challenge_id": options["challenge_id"],
                                    "credential": self.virtual.assertion(options)}, format="json")
        self.assertTrue(response.data["factor_required"])
        response = self.client.post("/security/factor-finish/", {"ticket": response.data["ticket"],
                                    "method": "password", "password": PASSWORD}, format="json")
        self.assertTrue(response.data["security"]["admin_access"])
        self.key.refresh_from_db()
        self.assertFalse(self.key.attestation_verified)
        self.assertEqual(self.key.assurance_level, "standard")

    def test_create_role_locally_without_cloud_moderation(self):
        authenticate(self.client, self.user, self.role)
        with patch("gt_forum.tasks.ali_client.text_moderation_with_options") as cloud:
            response = self.client.post("/role/", {"name": "本地角色测试"}, format="json")
        self.assertEqual(response.status_code, 201, response.data)
        self.assertTrue(RoleMember.objects.filter(user=self.user, role_id=response.data["data"]["id"], is_owner=True).exists())
        cloud.assert_not_called()
