from datetime import timedelta

from django.conf import settings
from django.core.cache import cache
from django.test import TestCase, override_settings
from django.utils import timezone
from rest_framework.test import APIClient

from gt_forum.models import Post, PostComment
from . import webauthn
from .models import Role, RoleMember
from .test_support import make_user, add_key, authenticate


class CertificationTests(TestCase):
    def setUp(self):
        cache.clear()
        self.api = APIClient()
        self.public = APIClient()
        self.user, self.primary = make_user("certified_admin", roles=["super_admin"])
        self.key, _ = add_key(self.user)
        authenticate(self.api, self.user, self.primary, key=self.key)

    def trust(self, **updates):
        return [dict(entry, **updates) for entry in settings.FIDO_ATTESTATION_TRUST]

    def public_role(self):
        response = self.public.get(f"/role/{self.primary.pk}/")
        self.assertEqual(response.status_code, 200, response.data)
        return response.data["data"]

    def test_fips_and_cc_display_uses_current_verified_metadata(self):
        trust = self.trust(assurance="fips140-2-level2", certification_reference="TEST FIPS record",
                           certifications=[{"standard": "CC", "level": "EAL4+", "reference": "TEST CC record"}])
        with override_settings(FIDO_ATTESTATION_TRUST=trust):
            data = self.api.get("/security/status/").data
            assurance = data["session_key_assurance"]
            self.assertTrue(assurance["high_assurance"])
            self.assertEqual(assurance["level"], "fips140-2-level2")
            self.assertEqual(assurance["certifications"], ["FIPS 140-2 L2", "CC EAL4+"])
            self.assertEqual(data["keys"][0]["assurance"], assurance)
        data = self.api.get("/security/status/").data
        self.assertFalse(data["session_key_assurance"]["high_assurance"])
        self.assertEqual(data["session_key_assurance"]["certifications"], [])

    def test_equivalent_assurance_and_display_labels_are_separate(self):
        cc = [{"standard": "CC", "level": "EAL4+", "reference": "TEST CC record"}]
        for level, gold in (("standard", False), ("equivalent-level2", True)):
            trust = self.trust(assurance=level, certification_reference="TEST reviewed equivalence", certifications=cc)
            with self.subTest(level=level), override_settings(FIDO_ATTESTATION_TRUST=trust):
                assurance = webauthn.credential_assurance(self.key)
                self.assertEqual(assurance["high_assurance"], gold)
                self.assertEqual(assurance["label"], "CC EAL4+")
        trust = self.trust(assurance="equivalent-level2", certification_reference="TEST reviewed equivalence",
                           certifications=[{"standard": "CC", "level": "EAL4+"}])
        with override_settings(FIDO_ATTESTATION_TRUST=trust):
            self.assertEqual(webauthn.credential_assurance(self.key)["label"], "同等级 L2")

    def test_untrusted_or_revoked_credentials_cannot_claim_gold(self):
        trust = self.trust(assurance="fips140-3-level3", certification_reference="TEST FIPS record")
        self.key.name = "FIPS 140-3 L3 CC EAL7+"
        self.key.assurance_level = "fips140-3-level3"
        with override_settings(FIDO_ATTESTATION_TRUST=trust):
            for field, value in (("attestation_verified", False), ("backup_eligible", True),
                                 ("is_security_key", False), ("revoked_at", timezone.now())):
                original = getattr(self.key, field)
                setattr(self.key, field, value)
                self.assertFalse(webauthn.credential_assurance(self.key)["high_assurance"], field)
                setattr(self.key, field, original)
        trust[0]["valid_until"] = (timezone.now() - timedelta(seconds=1)).isoformat()
        with override_settings(FIDO_ATTESTATION_TRUST=trust):
            self.assertFalse(webauthn.credential_assurance(self.key)["high_assurance"])

    def test_password_session_does_not_display_unused_key_as_login_method(self):
        user, role = make_user("ordinary_certified")
        add_key(user)
        authenticate(self.api, user, role)
        with override_settings(FIDO_ATTESTATION_TRUST=self.trust(
                assurance="fips140-2-level2", certification_reference="TEST FIPS record")):
            data = self.api.get("/security/status/").data
            self.assertIsNone(data["session_key_assurance"])
            self.assertTrue(data["keys"][0]["assurance"]["high_assurance"])

    def test_hiding_real_name_preserves_primary_badges_in_roles_posts_and_comments(self):
        alternate = Role.objects.create(name="其他个人角色")
        RoleMember.objects.create(user=self.user, role=alternate, is_owner=True)
        authenticate(self.api, self.user, alternate, key=self.key)
        post = Post.objects.create(author=self.primary, type=1, content="主角色发言", share_with=0, review_status=0)
        comment = PostComment.objects.create(post=post, author=self.primary, user=self.user,
                                             content="主角色回复", review_status=0)
        for show in (True, False):
            with self.subTest(show=show):
                response = self.api.post("/security/privacy/", {"show_real_name": show}, format="json")
                self.assertEqual(response.status_code, 200, response.data)
                role = self.public_role()
                self.assertEqual(role["badges"], [{"role": "super_admin", "label": "超级管理员"}])
                if show:
                    self.assertEqual(role["user_info"]["real_name"], self.user.real_name)
                else:
                    self.assertIsNone(role["user_info"])
                self.assertEqual(self.api.get("/security/status/").data["show_real_name"], show)
                self.assertEqual(self.public.get(f"/post/{post.pk}/").data["author"]["badges"], role["badges"])
                self.assertEqual(self.public.get(f"/comment/{comment.pk}/").data["author"]["badges"], role["badges"])
        self.assertEqual(self.public.get(f"/role/{alternate.pk}/").data["data"]["badges"], [])
        self.assertEqual(self.api.post("/security/privacy/", {"hide_admin_badges": True}, format="json").status_code, 400)

    def test_special_manager_badges_are_always_visible_on_primary_role(self):
        for role, label in (("base_admin", "实习管理员"), ("admin_user", "用户管理员"),
                            ("admin_admin", "特权管理员"), ("superadmin_admin", "特权超级管理员")):
            user, primary = make_user(role, roles=[role])
            self.assertFalse(primary.show_user_info)
            self.assertEqual(primary.badges, [{"role": role, "label": label}])

    def test_primary_role_privacy_is_shared_with_role_settings(self):
        for value in (True, False):
            response = self.api.patch(f"/role/{self.primary.pk}/", {"show_user_info": value}, format="json")
            self.assertEqual(response.status_code, 200, response.data)
            data = self.api.get("/security/status/").data
            self.assertEqual(data["show_real_name"], value)
            self.assertEqual(data["primary_role_id"], self.primary.pk)
            self.assertEqual(self.public_role()["badges"][0]["role"], "super_admin")

    def test_primary_role_is_stable_and_cannot_be_shared_anonymized_or_deleted(self):
        for update in ({"is_private": True}, {"is_shared": True}, {"members_id": [self.user.pk]}):
            response = self.api.patch(f"/role/{self.primary.pk}/", update, format="json")
            self.assertEqual(response.status_code, 400, response.data)
        self.assertEqual(self.api.delete(f"/role/{self.primary.pk}/").status_code, 400)
        response = self.api.post("/role/", {"name": "伪造主角色", "is_primary": True}, format="json")
        self.assertEqual(response.status_code, 201, response.data)
        self.assertFalse(Role.objects.get(pk=response.data["data"]["id"]).is_primary)
        response = self.api.patch(f"/role/{self.primary.pk}/", {"name": "重命名主角色"}, format="json")
        self.assertEqual(response.status_code, 200, response.data)
        count = self.user.roles.count()
        self.assertEqual(Role.generate_default_role(self.user).pk, self.primary.pk)
        self.assertEqual(self.user.roles.count(), count)
