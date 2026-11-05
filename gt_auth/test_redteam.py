"""Local adversarial regressions: isolated accounts, no external services."""
import base64
from datetime import timedelta
from unittest.mock import patch

from django.core.cache import cache
from django.test import TestCase
from django.utils import timezone
from rest_framework.test import APIClient
from rest_framework.exceptions import ValidationError

from gt_auth.models import Role, RoleMember, TrustedUser
from gt_auth.test_support import PASSWORD, add_key, authenticate, make_user
from gt_file.models import Image
from gt_forum.models import Post, PostVersion
from gt_admin.models import Report
from gt_coin.models import Coin, CoinRecordRealtime, CoinRecordType


class AccountBoundaryRedTeamTests(TestCase):
    def setUp(self):
        cache.clear()
        self.client = APIClient()
        self.attacker, self.role = make_user("audit_attacker")
        self.victim, _ = make_user("audit_victim")
        self.victim.student_id = "shou-private-identity"
        self.victim.save(update_fields=["student_id"])
        self.team = Role.objects.create(name="审计共享角色", is_shared=True)
        RoleMember.objects.create(user=self.attacker, role=self.team, is_owner=True)
        authenticate(self.client, self.attacker, self.role)

    def test_guessed_user_id_cannot_force_membership_or_reveal_identity(self):
        response = self.client.patch(f"/role/{self.team.pk}/", {"members_id": [self.victim.pk]}, format="json")
        self.assertEqual(response.status_code, 400)
        self.assertFalse(RoleMember.objects.filter(role=self.team, user=self.victim).exists())
        self.assertNotIn(self.victim.real_name, str(response.data))

    def test_invitation_consent_allows_membership_without_publishing_hidden_identity(self):
        self.victim.privacy.accept_join_role = True
        self.victim.privacy.save()
        response = self.client.patch(f"/role/{self.team.pk}/", {"members_id": [self.victim.pk]}, format="json")
        self.assertEqual(response.status_code, 200, response.data)
        self.assertTrue(RoleMember.objects.filter(role=self.team, user=self.victim).exists())
        self.assertNotIn(self.victim.real_name, str(response.data))
        self.assertNotIn(self.victim.student_id, str(response.data))

    def test_trust_is_directional_and_explicit_target_trust_allows_invitation(self):
        TrustedUser.objects.create(user=self.victim, trusted_user=self.attacker)
        response = self.client.patch(f"/role/{self.team.pk}/", {"members_id": [self.victim.pk]}, format="json")
        self.assertEqual(response.status_code, 200, response.data)
        self.assertIn(self.victim.real_name, str(response.data))

    def test_bad_member_lists_are_rejected_without_partial_edits(self):
        for members in ([True], [self.victim.pk, self.victim.pk], [999999], [-1]):
            with self.subTest(members=members):
                response = self.client.patch(f"/role/{self.team.pk}/", {
                    "members_id": members, "show_user_info": True,
                }, format="json")
                self.assertEqual(response.status_code, 400)
                self.team.refresh_from_db()
                self.assertFalse(self.team.show_user_info)

    def test_visible_account_can_be_added_to_a_trust_list(self):
        self.victim.privacy.allow_show_in_list = True
        self.victim.privacy.save()
        response = self.client.put("/user/setting/privacy/", {"trusted_users": [self.victim.pk]}, format="json")
        self.assertEqual(response.status_code, 200, response.data)
        self.assertTrue(TrustedUser.objects.filter(user=self.attacker, trusted_user=self.victim).exists())

    def test_trusting_a_private_user_does_not_authorize_reading_their_identity(self):
        response = self.client.put("/user/setting/privacy/", {"trusted_users": [self.victim.pk]}, format="json")
        self.assertEqual(response.status_code, 400)
        self.assertFalse(TrustedUser.objects.filter(user=self.attacker, trusted_user=self.victim).exists())
        self.assertNotIn(self.victim.real_name, str(response.data))

    def test_existing_trust_list_respects_a_targets_current_privacy(self):
        TrustedUser.objects.create(user=self.attacker, trusted_user=self.victim)
        response = self.client.get("/user/setting/privacy/")
        self.assertEqual(response.status_code, 200)
        self.assertNotIn(self.victim.real_name, str(response.data))
        self.assertNotIn(self.victim.student_id, str(response.data))

    def test_forwarded_for_rotation_cannot_reset_the_anonymous_auth_limit(self):
        self.client.credentials()
        for index in range(41):
            response = self.client.post("/security/key-login-begin/", {"username": "unknown"},
                                        format="json", HTTP_X_FORWARDED_FOR=f"198.51.100.{index}")
        self.assertEqual(response.status_code, 429)

    def test_authentication_rejects_non_object_json_without_server_errors(self):
        for path in ("/security/password-login/", "/security/key-login-begin/", "/security/key-login-finish/",
                     "/security/register-code/", "/security/factor-finish/", "/user/login/"):
            for body in ([], "invalid", 123):
                with self.subTest(path=path, body=body):
                    response = self.client.post(path, body, format="json")
                    self.assertEqual(response.status_code, 400)

    def test_nested_bearer_payload_is_rejected_without_server_errors(self):
        encoded = base64.urlsafe_b64encode(("[" * 5000 + "0" + "]" * 5000).encode()).decode().rstrip("=")
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {encoded}.invalid")
        self.assertEqual(self.client.get("/user/info/").status_code, 401)

    def test_nested_json_is_rejected_on_authentication_and_media_endpoints(self):
        body = "[" * 5000 + "0" + "]" * 5000
        for path in ("/security/key-login-begin/", "/image/"):
            with self.subTest(path=path):
                response = self.client.post(path, body, content_type="application/json")
                self.assertEqual(response.status_code, 400)

    def test_hidden_or_nonexistent_user_lookup_has_the_same_not_found_response(self):
        for reference in (self.victim.pk, self.victim.username, 999999, "does-not-exist"):
            self.assertEqual(self.client.get(f"/user/{reference}/").status_code, 404)

    def test_password_change_accepts_the_verified_old_password_after_session_age(self):
        session, _ = authenticate(self.client, self.attacker, self.role)
        session.verified_at = timezone.now() - timedelta(minutes=10)
        session.save(update_fields=["verified_at"])
        response = self.client.post("/user/setting/password/", {
            "old_password": PASSWORD, "new_password": "Replacement!Password-2026",
        }, format="json")
        self.assertEqual(response.status_code, 200, response.data)

    def test_guessing_a_transfer_recipient_cannot_disclose_hidden_identity(self):
        self.attacker.coin.total = 10
        self.attacker.coin.save(update_fields=["total"])
        response = self.client.post("/coin/transfer/", {"to_user_id": self.victim.pk, "amount": 1}, format="json")
        self.assertEqual(response.status_code, 404)
        self.assertFalse(CoinRecordRealtime.objects.filter(detail__contains=self.victim.real_name).exists())
        self.attacker.coin.refresh_from_db()
        self.assertEqual(self.attacker.coin.total, 10)

    def test_report_response_does_not_publish_a_private_moderators_real_name(self):
        report = Report.objects.create(user=self.attacker, operator=self.victim, content_id=1, content_type="post")
        response = self.client.get(f"/report/{report.pk}/")
        self.assertEqual(response.status_code, 200)
        self.assertNotIn(self.victim.real_name, str(response.data))
        self.assertNotIn(self.victim.student_id, str(response.data))

    def test_user_manager_cannot_take_over_an_exempt_administrator_by_password_reset(self):
        manager, role = make_user("audit_user_manager", roles=["admin_user"])
        key, _ = add_key(manager)
        target, _ = make_user("audit_exempt_moderator", roles=["admin_forum"])
        add_key(target)
        target.security_key_exempt_until = timezone.now() + timedelta(days=1)
        target.save(update_fields=["security_key_exempt_until"])
        authenticate(self.client, manager, role, key=key)
        response = self.client.post(f"/admin/user/{target.pk}/change-password/", {
            "password": "Attacker!Chosen-Password-2026",
        }, format="json")
        self.assertEqual(response.status_code, 403)
        target.refresh_from_db()
        self.assertTrue(target.check_password(PASSWORD))

    def test_stale_balance_cannot_spend_the_same_coins_twice(self):
        Coin.objects.filter(pk=self.attacker.coin_id).update(total=10)
        first = Coin.objects.get(pk=self.attacker.coin_id)
        stale = Coin.objects.get(pk=self.attacker.coin_id)
        first.add_record(-8, CoinRecordType.TRANSFER)
        with self.assertRaises(ValidationError):
            stale.add_record(-8, CoinRecordType.TRANSFER)
        self.attacker.coin.refresh_from_db()
        self.assertEqual(self.attacker.coin.total, 2)

    def test_visible_recipient_transfer_preserves_balances_and_hides_names_in_ledger(self):
        Coin.objects.filter(pk=self.attacker.coin_id).update(total=10)
        self.victim.privacy.allow_show_in_list = True
        self.victim.privacy.save()
        response = self.client.post("/coin/transfer/", {"to_user_id": self.victim.pk, "amount": 2}, format="json")
        self.assertEqual(response.status_code, 200, response.data)
        self.attacker.coin.refresh_from_db()
        self.assertEqual(self.attacker.coin.total, 8)
        self.assertFalse(CoinRecordRealtime.objects.filter(detail__contains=self.victim.real_name).exists())


class MediaBoundaryRedTeamTests(TestCase):
    def setUp(self):
        cache.clear()
        self.client = APIClient()
        self.owner, _ = make_user("audit_image_owner")
        self.attacker, self.role = make_user("audit_image_attacker")
        self.image = Image.objects.create(user=self.owner, name="private.png", key="private/image.png",
                                          md5="a" * 32, size=64, content_type="image/png", create_time=timezone.now())
        authenticate(self.client, self.attacker, self.role)

    def test_hash_only_upload_cannot_read_another_uploaders_private_identity(self):
        response = self.client.post("/image/", {"md5": self.image.md5}, format="json")
        self.assertEqual(response.status_code, 400)
        self.assertNotIn(self.owner.real_name, str(response.data))
        self.assertNotIn(self.image.key, str(response.data))

    def test_guessed_image_id_cannot_be_published_or_used_to_reveal_its_storage_key(self):
        response = self.client.post("/post/", {
            "title": "", "content": "local audit", "post_type": 1, "media_type": 0,
            "images": [self.image.pk], "video_id": None, "share_with": -3, "allow_comment": True,
        }, format="json")
        self.assertEqual(response.status_code, 400, response.data)
        self.assertFalse(Post.objects.exists())
        self.assertFalse(PostVersion.objects.exists())

    def test_negative_image_size_cannot_bypass_quota(self):
        with patch("gt_file.views.sign_upload", return_value={}) as signer:
            response = self.client.post("/image/", {
                "name": "bad.png", "md5": "b" * 32, "content_type": "image/png", "size": -1, "scene": "post",
            }, format="json")
        self.assertEqual(response.status_code, 400, response.data)
        signer.assert_not_called()

    def test_image_deduplication_is_scoped_to_the_uploader(self):
        body = {"name": "same.png", "md5": self.image.md5, "size": 64, "content_type": "image/png", "scene": "post"}
        with patch("gt_file.views.sign_upload", return_value={"url": "local-test-upload"}) as signer:
            response = self.client.post("/image/", body, format="json")
            self.assertEqual(response.status_code, 200, response.data)
            owned = response.data["data"][0]["data"]
            self.assertEqual(owned["user"]["id"], self.attacker.pk)
            self.assertNotEqual(owned["id"], self.image.pk)
            self.assertNotEqual(owned["key"], self.image.key)
            self.assertNotIn(self.owner.real_name, str(response.data))
            repeated = self.client.post("/image/", body, format="json")
            self.assertEqual(repeated.status_code, 200, repeated.data)
            self.assertEqual(repeated.data["data"][0]["data"]["id"], owned["id"])
            self.assertIsNone(repeated.data["data"][0]["upload_data"])
            self.assertEqual(signer.call_count, 1)

    def test_invalid_image_metadata_never_reaches_upload_signing(self):
        body = {"name": "same.png", "md5": "b" * 32, "size": 64, "content_type": "image/png", "scene": "post"}
        cases = ({"md5": "../../invalid"}, {"content_type": "image/svg+xml"}, {"size": 0}, {"size": 10**12})
        with patch("gt_file.views.sign_upload") as signer:
            for changes in cases:
                with self.subTest(changes=changes):
                    self.assertEqual(self.client.post("/image/", {**body, **changes}, format="json").status_code, 400)
            signer.assert_not_called()

    def test_shared_author_can_keep_existing_images_but_cannot_inject_new_ones(self):
        team = Role.objects.create(name="媒体审计共享角色", is_shared=True)
        RoleMember.objects.create(user=self.owner, role=team, is_owner=True)
        RoleMember.objects.create(user=self.attacker, role=team)
        post = Post.objects.create(author=team, type=1, content="existing", images=[self.image.pk], share_with=-3)
        authenticate(self.client, self.attacker, team)
        body = {"title": "", "content": "edited", "post_type": 1, "media_type": 0,
                "images": [self.image.pk], "video_id": None, "share_with": -3, "allow_comment": True}
        response = self.client.put(f"/post/{post.pk}/", body, format="json")
        self.assertEqual(response.status_code, 200, response.data)
        post.refresh_from_db()
        self.assertEqual(post.images, [self.image.pk])
