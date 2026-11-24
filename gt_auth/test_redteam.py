"""Local adversarial regressions: isolated accounts, no external services."""
import base64
from datetime import timedelta
from unittest.mock import patch

from django.core.cache import cache
from django.test import TestCase
from django.utils import timezone
from rest_framework.test import APIClient
from rest_framework.exceptions import ValidationError

from gt_auth.models import AuthSession, ImpersonationTicket, Permission, Role, RoleMember, TrustedUser, User
from gt_auth.security_policy import admin_access_allowed
from gt_auth.sessions import create_session
from gt_auth.test_support import PASSWORD, add_key, authenticate, make_user
from gt_file.models import Image
from gt_forum.models import Post, PostVersion
from gt_admin.models import AdminAuditLog, Report
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


class AuthBoundaryRedTeamTests(TestCase):
    def setUp(self):
        cache.clear()
        self.client = APIClient()
        self.root, self.root_role = make_user("rt_root", roles=["super_admin"])
        self.root_key, _ = add_key(self.root)
        add_key(self.root)
        self.victim, self.victim_role = make_user("rt_victim")
        self.team = Role.objects.create(name="越权测试共享角色", is_shared=True)
        RoleMember.objects.create(user=self.victim, role=self.team, is_owner=True)

    def _start_impersonation(self, *, parent=None):
        if parent is None:
            parent = create_session(self.root, ["fido2", "password"], credential=self.root_key)
        child, token = authenticate(self.client, self.victim, self.victim_role, methods=["impersonation"], scope="impersonation")
        child.parent_session = parent
        child.impersonator_id = self.root.pk
        child.save(update_fields=["parent_session", "impersonator_id"])
        return parent, child, token

    def test_impersonation_cannot_mutate_privacy_roles_or_survive_expired_parent(self):
        parent, child, _ = self._start_impersonation()
        self.assertEqual(self.client.get("/user/info/").status_code, 200)
        self.assertEqual(self.client.get("/security/config/").status_code, 200)

        # Privacy settings & trusted user lists must not be read or mutated during impersonation.
        self.assertEqual(self.client.get("/user/setting/privacy/").status_code, 403)
        self.assertEqual(
            self.client.put("/user/setting/privacy/", {"allow_show_in_list": True, "accept_join_role": True}, format="json").status_code,
            403,
        )
        self.victim.privacy.refresh_from_db()
        self.assertFalse(self.victim.privacy.allow_show_in_list)
        self.assertFalse(self.victim.privacy.accept_join_role)

        # Role privacy (show_user_info) & role creation/editing/deletion must be blocked during impersonation.
        self.assertEqual(self.client.patch(f"/role/{self.victim_role.pk}/", {"show_user_info": True}, format="json").status_code, 403)
        self.victim_role.refresh_from_db()
        self.assertFalse(self.victim_role.show_user_info)
        self.assertEqual(self.client.post("/role/", {"name": "代登录创建角色"}, format="json").status_code, 403)
        self.assertEqual(self.client.delete(f"/role/{self.team.pk}/").status_code, 403)

        # Credentials, MFA, security center, and admin routes are all blocked.
        for path in ("/user/setting/password/", "/user/email_sendcode/", "/user/email_verifycode/",
                     "/security/privacy/", "/security/totp-begin/", "/security/totp-confirm/",
                     "/security/totp-remove/", "/security/key-register-begin/", "/security/key-remove/",
                     "/security/reauth-begin/", "/security/reauth-finish/", "/security/admin-setup-begin/",
                     "/security/console-begin/", "/security/django-admin/"):
            self.assertEqual(self.client.post(path, {}, format="json").status_code, 403, path)
        for path in ("/admin/user/", "/django-admin/", "/security/status/", "/security/watermark/"):
            self.assertEqual(self.client.get(path).status_code, 403, path)

        # Expiring the parent super_admin's temporary privilege immediately invalidates child impersonation.
        Permission.objects.filter(pk=self.root.permission_id).update(privileged_expires_at=timezone.now() - timedelta(seconds=1))
        self.assertEqual(self.client.get("/user/info/").status_code, 401)

    def test_impersonation_exchange_rejects_banned_or_revoked_target(self):
        import hashlib
        import secrets
        parent_client = APIClient()
        parent, _ = authenticate(parent_client, self.root, self.root_role, key=self.root_key)
        for reason in ("banned", "temp_banned", "revoked", "version_bump"):
            with self.subTest(reason=reason):
                target, _ = make_user(f"imp_{reason}")
                child = create_session(target, ["impersonation"], scope="impersonation")
                child.parent_session = parent
                child.impersonator_id = self.root.pk
                child.save(update_fields=["parent_session", "impersonator_id"])
                raw_ticket = secrets.token_urlsafe(32)
                ticket = ImpersonationTicket.objects.create(
                    token_hash=hashlib.sha256(raw_ticket.encode()).hexdigest(),
                    session=child,
                    expires_at=timezone.now() + timedelta(minutes=2),
                )
                if reason == "banned":
                    User.objects.filter(pk=target.pk).update(is_active=False)
                elif reason == "temp_banned":
                    User.objects.filter(pk=target.pk).update(banned_until=timezone.now() + timedelta(hours=1))
                elif reason == "revoked":
                    AuthSession.objects.filter(pk=child.pk).update(revoked_at=timezone.now())
                elif reason == "version_bump":
                    User.objects.filter(pk=target.pk).update(version=target.version + 1)

                res = parent_client.post("/security/impersonation-exchange/", {"ticket": raw_ticket}, format="json")
                self.assertEqual(res.status_code, 403)
                ticket.refresh_from_db()
                self.assertIsNone(ticket.consumed_at)

    def test_permission_guards_reject_banned_suspended_expired_onboarding_and_keyless(self):
        post = Post.objects.create(author=self.victim_role, type=1, content="audit post", share_with=0, review_status=0)
        for state in ("permanently_banned", "temp_banned", "suspended", "expired_privileged", "onboarding", "no_key"):
            with self.subTest(state=state):
                cache.clear()
                actor, actor_role = make_user(f"guard_{state}", roles=["super_admin"])
                k1, _ = add_key(actor)
                add_key(actor)
                client = APIClient()
                if state == "no_key":
                    session = create_session(actor, ["password"], scope="full")
                    from gt_auth.sessions import authorization
                    import json as _json
                    auth = authorization(actor, session)
                    tok = base64.urlsafe_b64encode(_json.dumps(auth["payload"]).encode()).decode() + "." + auth["signature"]
                    client.credentials(HTTP_AUTHORIZATION="Bearer " + tok)
                else:
                    session, _ = authenticate(client, actor, actor_role, key=k1)

                if state == "permanently_banned":
                    User.objects.filter(pk=actor.pk).update(is_active=False)
                    expected = 401
                elif state == "temp_banned":
                    User.objects.filter(pk=actor.pk).update(banned_until=timezone.now() + timedelta(days=1))
                    expected = 401
                elif state == "suspended":
                    User.objects.filter(pk=actor.pk).update(admin_suspended_until=timezone.now() + timedelta(hours=1))
                    expected = 403
                elif state == "expired_privileged":
                    Permission.objects.filter(pk=actor.permission_id).update(privileged_expires_at=timezone.now() - timedelta(seconds=1))
                    expected = 403
                elif state == "onboarding":
                    User.objects.filter(pk=actor.pk).update(admin_onboarding_required=True)
                    expected = 403
                else:
                    expected = 401

                actor.refresh_from_db()
                actor.permission.refresh_from_db()
                self.assertFalse(admin_access_allowed(actor, session))
                self.assertFalse(User.has_permission(actor, "super_admin"))

                user_list = client.get("/admin/user/")
                self.assertEqual(user_list.status_code, expected)
                if state == "suspended":
                    self.assertIn("X-Shou-Watermark", user_list)
                    self.assertTrue(AdminAuditLog.objects.filter(actor_id=actor.pk, outcome="denied").exists())
                self.assertEqual(client.get("/admin/role/").status_code, expected)
                self.assertEqual(client.post(f"/admin/post/{post.pk}/pin/", {"pinned": True}, format="json").status_code, expected)
                self.assertEqual(client.post(f"/admin/post/{post.pk}/review/", {"status": 1, "message": "ok"}, format="json").status_code, expected)
                self.assertEqual(client.get("/admin/comment/").status_code, expected)
                self.assertEqual(client.post("/security/console-begin/", {}, format="json").status_code, expected)
                self.assertEqual(client.get("/security/watermark/").status_code, expected)
                self.assertEqual(client.get("/django-admin/").status_code, 403)

        # Ordinary non-management key holders must also get False from admin_access_allowed and 403 on watermark.
        ordinary, ordinary_role = make_user("ord_no_admin")
        ordinary_key, _ = add_key(ordinary)
        ord_client = APIClient()
        ord_session, _ = authenticate(ord_client, ordinary, ordinary_role, key=ordinary_key)
        self.assertFalse(admin_access_allowed(ordinary, ord_session))
        self.assertEqual(ord_client.get("/security/watermark/").status_code, 403)
        self.assertEqual(ord_client.get("/django-admin/watermark/").status_code, 403)

    def test_have_role_or_read_only_and_has_permission_defense_in_depth(self):
        from rest_framework.test import APIRequestFactory
        from gt.permissions import HaveRoleOrReadOnly, HasPermission
        rf = APIRequestFactory()
        perm = HaveRoleOrReadOnly()
        req = rf.post("/post/")
        req.user = self.victim
        req.role = None
        self.assertFalse(perm.has_permission(req, None))

        req.role = self.victim_role
        self.assertTrue(perm.has_permission(req, None))
        self.victim_role.banned_until = timezone.now() + timedelta(hours=1)
        self.victim_role.save(update_fields=["banned_until"])
        self.assertFalse(perm.has_permission(req, None))
        self.victim_role.banned_until = None
        self.victim_role.deleted = True
        self.victim_role.save(update_fields=["banned_until", "deleted"])
        self.assertFalse(perm.has_permission(req, None))
        self.victim_role.deleted = False
        self.victim_role.save(update_fields=["deleted"])
        self.victim.is_active = False
        self.victim.save(update_fields=["is_active"])
        self.assertFalse(perm.has_permission(req, None))

        # Global reader cannot pass HasPermission on write methods even under force_authenticate.
        reader, reader_role = make_user("rt_reader", roles=["global_reader"])
        rk, _ = add_key(reader)
        add_key(reader)
        reader_session = create_session(reader, ["fido2", "password"], credential=rk)
        reader._security_session = reader_session
        write_req = rf.post("/admin/user/")
        write_req.user = reader
        self.assertFalse(HasPermission("admin_user")().has_permission(write_req, None))
        read_req = rf.get("/admin/user/")
        read_req.user = reader
        self.assertTrue(HasPermission("admin_user")().has_permission(read_req, None))

    def test_expired_temporary_global_reader_loses_badge_and_admin_audit_headers(self):
        reader, reader_role = make_user("exp_reader", roles=["global_reader"])
        rk, _ = add_key(reader)
        add_key(reader)
        Permission.objects.filter(pk=reader.permission_id).update(privileged_expires_at=timezone.now() - timedelta(minutes=1))
        reader.permission.refresh_from_db()

        client = APIClient()
        authenticate(client, reader, reader_role, key=rk)
        status_res = client.get("/security/status/")
        self.assertEqual(status_res.status_code, 200)
        self.assertEqual(status_res.data["badges"], [])
        self.assertFalse(status_res.data["is_management"])
        self.assertFalse(status_res.data["read_only"])

        public_role = APIClient().get(f"/role/{reader_role.pk}/")
        self.assertEqual(public_role.status_code, 200)
        self.assertEqual(public_role.data["data"]["badges"], [])

        # Because expired global_reader is no longer management, ordinary report read gets no admin watermark headers.
        report_res = client.get("/report/")
        self.assertEqual(report_res.status_code, 200)
        self.assertNotIn("X-Shou-Watermark", report_res)

    def test_revoked_global_reader_token_returns_401_without_oracle(self):
        reader, reader_role = make_user("rev_reader", roles=["global_reader"])
        rk, _ = add_key(reader)
        add_key(reader)
        session, _ = authenticate(self.client, reader, reader_role, key=rk)
        session.revoked_at = timezone.now()
        session.save(update_fields=["revoked_at"])
        res = self.client.post("/post/", {"content": "should return 401"}, format="json")
        self.assertEqual(res.status_code, 401)
