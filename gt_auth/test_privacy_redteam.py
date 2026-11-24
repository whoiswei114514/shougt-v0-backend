"""Privacy and object-authorization regressions with isolated local fixtures."""
from datetime import timedelta
from unittest.mock import patch

from django.core.cache import cache
from django.test import TestCase
from django.utils import timezone
from rest_framework.test import APIClient

from gt_admin.models import Report
from gt_auth.models import Follow, Notification, NotificationType, Role, RoleMember, User
from gt_auth.test_support import PASSWORD, add_key, authenticate, make_user
from gt_coin.models import Coin, CoinRecord
from gt_forum.models import Post, PostComment, PostLike, PostShareWithChoice, PostVersion


class PrivacyBoundaryRedTeamTests(TestCase):
    def setUp(self):
        cache.clear()
        self.client = APIClient()
        self.reader, self.reader_role = make_user("privacy_reader")
        self.owner, self.owner_role = make_user("privacy_owner")
        self.owner.student_id = "private-student-identity"
        self.owner.save(update_fields=["student_id"])
        self.private_role = Role.objects.create(name="private role", is_private=True)
        RoleMember.objects.create(user=self.owner, role=self.private_role, is_owner=True)
        self.private_post = Post.objects.create(
            author=self.owner_role, content="private discussion", type=1, share_with=-3,
        )
        self.private_comment = PostComment.objects.create(
            post=self.private_post, author=self.owner_role, user=self.owner,
            content="private reply",
        )
        authenticate(self.client, self.reader, self.reader_role)

    def shared_content(self):
        team = Role.objects.create(name="shared role", is_shared=True)
        RoleMember.objects.create(user=self.owner, role=team, is_owner=True)
        RoleMember.objects.create(user=self.reader, role=team)
        post = Post.objects.create(author=team, content="shared discussion", type=1, share_with=-3)
        PostVersion.objects.create(
            post=post, user=self.owner, content=post.content, images=[], share_with=-3,
        )
        comment = PostComment.objects.create(post=post, author=team, user=self.owner, content="shared reply")
        authenticate(self.client, self.reader, team)
        return team, post, comment

    def assert_private_identity_absent(self, response):
        self.assertEqual(response.status_code, 200, response.data)
        rendered = str(response.data)
        for value in (self.owner.username, self.owner.real_name, self.owner.student_id):
            self.assertNotIn(value, rendered)

    def test_missing_selected_role_does_not_own_orphaned_posts(self):
        orphan = Post.objects.create(author=None, content="orphaned secret", type=1, share_with=-3)
        PostVersion.objects.create(post=orphan, user=self.owner, content=orphan.content, images=[])
        authenticate(self.client, self.reader)
        listing = self.client.get("/admin/post/")
        self.assertEqual(listing.status_code, 200, listing.data)
        self.assertNotIn(orphan.pk, [post["id"] for post in listing.data["results"]])
        for path in (f"/admin/post/{orphan.pk}/", f"/admin/post/{orphan.pk}/version/1/"):
            with self.subTest(path=path):
                self.assertEqual(self.client.get(path).status_code, 404)

    def test_missing_selected_role_does_not_own_orphaned_comments(self):
        orphan = PostComment.objects.create(
            post=self.private_post, author=None, user=self.owner, content="orphaned secret reply",
        )
        authenticate(self.client, self.reader)
        response = self.client.get(f"/admin/comment/{orphan.pk}/")
        self.assertEqual(response.status_code, 404)

    def test_comment_management_hides_existence_from_other_roles(self):
        hidden = self.client.get(f"/admin/comment/{self.private_comment.pk}/")
        missing = self.client.get("/admin/comment/999999/")
        self.assertEqual(hidden.status_code, 404)
        self.assertEqual(hidden.data, missing.data)

    def test_shared_post_edit_view_does_not_disclose_the_previous_editors_account(self):
        _, post, _ = self.shared_content()
        self.assert_private_identity_absent(self.client.get(f"/post/{post.pk}/", {"for": "edit"}))

    def test_shared_post_version_list_does_not_disclose_other_members_accounts(self):
        _, post, _ = self.shared_content()
        self.assert_private_identity_absent(self.client.get(f"/admin/post/{post.pk}/"))

    def test_shared_post_version_detail_does_not_disclose_other_members_accounts(self):
        _, post, _ = self.shared_content()
        self.assert_private_identity_absent(self.client.get(f"/admin/post/{post.pk}/version/1/"))

    def test_shared_comment_management_does_not_disclose_the_posting_members_account(self):
        _, _, comment = self.shared_content()
        self.assert_private_identity_absent(self.client.get(f"/admin/comment/{comment.pk}/"))

    def test_shared_comment_does_not_reveal_a_now_inaccessible_parent_post(self):
        team, _, _ = self.shared_content()
        comment = PostComment.objects.create(
            post=self.private_post, author=team, user=self.owner, content="previously shared reply",
        )
        response = self.client.get(f"/admin/comment/{comment.pk}/")
        self.assertEqual(response.status_code, 404)

    def test_comment_review_history_hides_the_moderators_account_from_its_author(self):
        _, _, comment = self.shared_content()
        message = {"reviewer_type": "admin", "reviewer": self.owner.pk, "message": "reviewed", "status": 1}
        comment.review_message = [message]
        comment.save(update_fields=["review_message"])
        response = self.client.get(f"/admin/comment/{comment.pk}/")
        self.assertEqual(response.status_code, 200, response.data)
        self.assertNotIn("reviewer", response.data["review_message"][0])
        comment.refresh_from_db()
        self.assertEqual(comment.review_message, [message])

    def test_forum_moderator_can_review_orphaned_content_and_account_identity(self):
        moderator, role = make_user("privacy_moderator", roles=["admin_forum"])
        key, _ = add_key(moderator)
        add_key(moderator)
        authenticate(self.client, moderator, role, key=key)
        self.private_comment.author = None
        self.private_comment.save(update_fields=["author"])
        response = self.client.get(f"/admin/comment/{self.private_comment.pk}/")
        self.assertEqual(response.status_code, 200, response.data)
        self.assertEqual(response.data["user"]["real_name"], self.owner.real_name)

    def test_authenticated_author_can_still_read_their_own_edit_history(self):
        team, post, _ = self.shared_content()
        authenticate(self.client, self.owner, team)
        response = self.client.get(f"/admin/post/{post.pk}/version/1/")
        self.assertEqual(response.status_code, 200, response.data)
        self.assertEqual(response.data["user"]["real_name"], self.owner.real_name)

    def test_private_follow_graph_cannot_be_queried_by_guessed_role_id(self):
        Follow.objects.create(follower=self.private_role, following=self.reader_role)
        Follow.objects.create(follower=self.reader_role, following=self.private_role)
        for field in ("followers__follower", "followings__following"):
            with self.subTest(field=field):
                hidden = self.client.get("/role/", {field: self.private_role.pk})
                missing = self.client.get("/role/", {field: 999999})
                self.assertEqual(hidden.status_code, 200, hidden.data)
                self.assertEqual(hidden.data["results"], [])
                self.assertEqual(hidden.data, missing.data)

    def test_private_follow_graph_is_available_to_its_member(self):
        Follow.objects.create(follower=self.private_role, following=self.reader_role)
        authenticate(self.client, self.owner, self.private_role)
        response = self.client.get("/role/", {"followers__follower": self.private_role.pk})
        self.assertEqual(response.status_code, 200, response.data)
        self.assertIn(self.reader_role.pk, [role["id"] for role in response.data["results"]])

    def test_reports_cannot_probe_hidden_objects_or_create_unrelated_complaints(self):
        for kind, identifier in (("post", self.private_post.pk), ("comment", self.private_comment.pk),
                                 ("role", self.private_role.pk), ("user", self.owner.pk)):
            with self.subTest(kind=kind):
                hidden = self.client.post("/report/", {"content_type": kind, "content_id": identifier}, format="json")
                missing = self.client.post("/report/", {"content_type": kind, "content_id": 999999}, format="json")
                self.assertEqual(hidden.status_code, 404)
                self.assertEqual(hidden.data, missing.data)
        self.assertFalse(Report.objects.filter(user=self.reader).exists())

    def test_visible_content_can_still_be_reported(self):
        public_post = Post.objects.create(author=self.owner_role, content="public", type=1, share_with=0)
        public_comment = PostComment.objects.create(post=public_post, author=self.owner_role, user=self.owner, content="public reply")
        self.owner.privacy.allow_show_in_list = True
        self.owner.privacy.save()
        for kind, identifier in (("post", public_post.pk), ("comment", public_comment.pk),
                                 ("role", self.owner_role.pk), ("user", self.owner.pk)):
            with self.subTest(kind=kind):
                response = self.client.post("/report/", {"content_type": kind, "content_id": identifier}, format="json")
                self.assertEqual(response.status_code, 200, response.data)
        self.assertEqual(Report.objects.filter(user=self.reader).count(), 4)

    def test_personal_and_login_responses_cannot_be_stored_in_caches(self):
        for path in ("/user/info/", "/security/status/", "/role/"):
            with self.subTest(path=path):
                response = self.client.get(path)
                self.assertEqual(response.status_code, 200, response.data)
                self.assertIn("no-store", response.get("Cache-Control", ""))
        self.client.credentials()
        response = self.client.post("/security/password-login/", {
            "username": self.reader.username, "password": PASSWORD,
        }, format="json")
        self.assertEqual(response.status_code, 200, response.data)
        self.assertIn("no-store", response.get("Cache-Control", ""))

    def test_private_role_cannot_unmask_owner_or_probe_private_names(self):
        # Cannot create a private role with show_user_info=True or is_shared=True
        for payload in (
            {"name": "anon_leak", "is_private": True, "show_user_info": True},
            {"name": "anon_shared", "is_private": True, "is_shared": True},
        ):
            with self.subTest(payload=payload):
                self.assertEqual(self.client.post("/role/", payload, format="json").status_code, 400)

        # Even if DB has show_user_info=True on a private role, serializers never leak user_info
        Role.objects.filter(pk=self.private_role.pk).update(show_user_info=True)
        anon_post = Post.objects.create(
            author=self.private_role, content="anon post", type=1, share_with=PostShareWithChoice.PUBLIC,
        )
        post_detail = self.client.get(f"/post/{anon_post.pk}/")
        self.assertEqual(post_detail.status_code, 200, post_detail.data)
        self.assertIsNone(post_detail.data["author"]["id"])
        self.assertIsNone(post_detail.data["author"]["user_info"])
        authenticate(self.client, self.owner, self.private_role)
        role_detail = self.client.get(f"/role/{self.private_role.pk}/")
        self.assertEqual(role_detail.status_code, 200)
        self.assertEqual(role_detail.data["data"]["user_info"]["real_name"], self.owner.real_name)
        # Flipping is_private after creation is rejected
        self.assertEqual(self.client.patch(f"/role/{self.private_role.pk}/", {"is_private": False}, format="json").status_code, 400)

        # Creating a role with the same name as a private role does not disclose its existence
        authenticate(self.client, self.reader, self.reader_role)
        with patch("gt_auth.serializers.review_with_aliyun", return_value={"status": 1, "message": "OK"}):
            resp = self.client.post("/role/", {"name": self.private_role.name}, format="json")
            self.assertEqual(resp.status_code, 201, resp.data)
            # Updating show_user_info alone on a non-no_review role does not fail on empty name
            new_id = resp.data["data"]["id"]
            self.assertEqual(self.client.patch(f"/role/{new_id}/", {"show_user_info": False}, format="json").status_code, 200)

    def test_role_follow_requires_active_non_private_role_and_current_role(self):
        authenticate(self.client, self.reader)  # role=None
        self.assertEqual(self.client.post(f"/role/{self.owner_role.pk}/follow/").status_code, 403)
        authenticate(self.client, self.owner, self.owner_role)
        self.assertEqual(self.client.post(f"/role/{self.private_role.pk}/follow/").status_code, 400)
        self.reader_role.is_active = False
        self.reader_role.save(update_fields=["is_active"])
        self.assertEqual(self.client.post(f"/role/{self.reader_role.pk}/follow/").status_code, 400)

    def test_user_and_role_ordering_and_lookup_respect_privacy(self):
        self.owner.privacy.allow_show_in_list = False
        self.owner.privacy.save(update_fields=["allow_show_in_list"])
        for ref in (self.owner.pk, self.owner.username):
            self.assertEqual(self.client.get(f"/user/{ref}/").status_code, 404)
        res = self.client.get("/user/", {"ordering": "student_id", "search": self.owner.username})
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.data["results"], [])

    def test_impersonation_cannot_mutate_privacy_or_roles(self):
        sa, sa_role = make_user("imp_sa", roles=["super_admin"])
        key, _ = add_key(sa)
        add_key(sa)
        parent_session, _ = authenticate(APIClient(), sa, sa_role, key=key)
        from gt_auth.models import AuthSession
        imp_session = AuthSession.objects.create(
            user=self.reader, parent_session=parent_session, impersonator_id=sa.pk,
            methods=["impersonation"], scope="impersonation", user_version=self.reader.version,
            verified_at=timezone.now(), expires_at=timezone.now() + timedelta(minutes=10),
        )
        self.reader._security_session = imp_session
        self.client.force_authenticate(user=self.reader, token=imp_session)
        self.assertEqual(self.client.put("/user/setting/privacy/", {"allow_show_in_list": True}, format="json").status_code, 403)
        self.assertEqual(self.client.post("/role/", {"name": "imp_role"}, format="json").status_code, 403)
        self.assertEqual(self.client.patch(f"/role/{self.reader_role.pk}/", {"name": "changed"}, format="json").status_code, 403)
        self.assertEqual(self.client.delete(f"/role/{self.reader_role.pk}/").status_code, 403)

    def test_user_admin_retrieve_does_not_leak_private_roles_or_write_coin_record(self):
        manager, mrole = make_user("uadm_view", roles=["admin_user"])
        key, _ = add_key(manager)
        add_key(manager)
        authenticate(self.client, manager, mrole, key=key)
        before_coins = CoinRecord.objects.filter(user=self.owner).count()
        res = self.client.get(f"/admin/user/{self.owner.pk}/")
        self.assertEqual(res.status_code, 200, res.data)
        self.assertNotIn("roles", res.data)
        self.assertNotIn(self.private_role.name, str(res.data))
        self.assertNotIn("totp_enabled", res.data["security"])
        self.assertEqual(CoinRecord.objects.filter(user=self.owner).count(), before_coins)

    def test_protect_user_and_role_block_ordinary_admins_across_all_privileged_roles_and_expired_grants(self):
        user_mgr, um_role = make_user("umgr_prot", roles=["admin_user"])
        ukey, _ = add_key(user_mgr)
        add_key(user_mgr)
        role_mgr, rm_role = make_user("rmgr_prot", roles=["admin_role"])
        rkey, _ = add_key(role_mgr)
        add_key(role_mgr)

        targets = []
        for priv in ("super_admin", "admin_admin", "superadmin_admin", "global_reader"):
            u, r = make_user(f"priv_{priv}", roles=[priv])
            targets.append((u, r))
        expired_priv, expired_role = make_user("priv_expired", roles=["super_admin"])
        expired_priv.permission.privileged_expires_at = timezone.now() - timedelta(minutes=5)
        expired_priv.permission.save(update_fields=["privileged_expires_at"])
        targets.append((expired_priv, expired_role))

        u_client = APIClient()
        authenticate(u_client, user_mgr, um_role, key=ukey)
        r_client = APIClient()
        authenticate(r_client, role_mgr, rm_role, key=rkey)

        for target, trole in targets:
            with self.subTest(target=target.username):
                self.assertEqual(u_client.post(f"/admin/user/{target.pk}/ban/", {"is_active": False}, format="json").status_code, 403)
                self.assertEqual(u_client.post(f"/admin/user/{target.pk}/change-password/", {"password": PASSWORD + "!"}, format="json").status_code, 403)
                self.assertEqual(u_client.post(f"/admin/user/{target.pk}/coin/", {"change": 10, "type": "admin", "detail": "x"}, format="json").status_code, 403)
                self.assertEqual(u_client.put(f"/admin/user/{target.pk}/?type=permission", {"no_review": True}, format="json").status_code, 403)
                self.assertEqual(u_client.put(f"/admin/user/{target.pk}/?type=quota", {"role_count_limit": 20}, format="json").status_code, 403)
                self.assertEqual(r_client.patch(f"/admin/role/{trole.pk}/", {"editable": False}, format="json").status_code, 403)
                self.assertEqual(r_client.post(f"/admin/role/{trole.pk}/ban/", {"is_active": False}, format="json").status_code, 403)

    def test_global_reader_cannot_mutate_anywhere_even_bypassing_jwt_middleware(self):
        gr, gr_role = make_user("gr_ro", roles=["global_reader"])
        key, _ = add_key(gr)
        add_key(gr)
        pub_post = Post.objects.create(author=self.owner_role, content="pub", type=1, share_with=0)
        pub_comment = PostComment.objects.create(post=pub_post, author=self.owner_role, user=self.owner, content="c")
        report = Report.objects.create(user=self.reader, content_type="post", content_id=pub_post.pk)

        jwt_client = APIClient()
        authenticate(jwt_client, gr, gr_role, key=key)
        direct_client = APIClient()
        direct_client.force_authenticate(user=gr)

        mutations = [
            ("post", "/admin/user/", {"username": "x", "email": "x@st.shou.edu.cn", "password": PASSWORD}),
            ("post", f"/admin/user/{self.owner.pk}/ban/", {"is_active": False}),
            ("post", f"/admin/user/{self.owner.pk}/change-password/", {"password": PASSWORD}),
            ("post", f"/admin/user/{self.owner.pk}/coin/", {"change": 1, "type": "admin"}),
            ("put", f"/admin/user/{self.owner.pk}/?type=quota", {"role_count_limit": 20}),
            ("patch", f"/admin/role/{self.owner_role.pk}/", {"editable": False}),
            ("post", f"/admin/role/{self.owner_role.pk}/ban/", {"is_active": False}),
            ("post", f"/admin/post/{pub_post.pk}/pin/", {"pinned": True}),
            ("post", f"/admin/post/{pub_post.pk}/review/", {"status": 1, "message": "ok"}),
            ("post", f"/admin/comment/{pub_comment.pk}/review/", {"status": 1, "message": "ok"}),
            ("post", "/report/", {"content_type": "post", "content_id": pub_post.pk}),
            ("patch", f"/report/{report.pk}/", {"status": 1}),
            ("delete", f"/report/{report.pk}/", None),
            ("put", "/user/setting/privacy/", {"allow_show_in_list": True}),
            ("post", "/user/setting/password/", {"old_password": PASSWORD, "new_password": PASSWORD}),
            ("post", "/role/", {"name": "gr_new"}),
            ("post", "/notification/read_all/", {}),
        ]
        for client in (jwt_client, direct_client):
            for method, path, payload in mutations:
                with self.subTest(jwt=(client is jwt_client), method=method, path=path):
                    fn = getattr(client, method)
                    resp = fn(path, payload, format="json") if payload is not None else fn(path)
                    self.assertEqual(resp.status_code, 403, (path, resp.data))

    def test_report_idor_mutation_and_operator_masking(self):
        pub_post = Post.objects.create(author=self.owner_role, content="pub", type=1, share_with=0)
        mod, mod_role = make_user("rep_mod", roles=["admin_report"])
        mkey, _ = add_key(mod)
        add_key(mod)
        self.client.post("/report/", {"content_type": "post", "content_id": pub_post.pk, "explanation": "bad"}, format="json")
        own_report = Report.objects.get(user=self.reader)

        # Ordinary reporter cannot update/delete own report, nor read others' reports
        self.assertEqual(self.client.patch(f"/report/{own_report.pk}/", {"status": 1}, format="json").status_code, 403)
        self.assertEqual(self.client.delete(f"/report/{own_report.pk}/").status_code, 403)
        other_report = Report.objects.create(user=self.owner, content_type="post", content_id=pub_post.pk)
        self.assertEqual(self.client.get(f"/report/{other_report.pk}/").status_code, 404)

        # Moderator updates status only; immutable fields cannot be tampered
        mod_client = APIClient()
        authenticate(mod_client, mod, mod_role, key=mkey)
        res = mod_client.patch(f"/report/{own_report.pk}/", {"status": 1, "content_id": 99999, "explanation": "tampered"}, format="json")
        self.assertEqual(res.status_code, 200, res.data)
        own_report.refresh_from_db()
        self.assertEqual(own_report.status, 1)
        self.assertEqual(own_report.content_id, pub_post.pk)
        self.assertEqual(own_report.explanation, "bad")

        # Reporter sees operator=None so moderator identity is never exposed
        own_view = self.client.get(f"/report/{own_report.pk}/")
        self.assertEqual(own_view.status_code, 200)
        self.assertIsNone(own_view.data["operator"])

    def test_forum_post_like_filter_donate_admin_context_and_comment_masking(self):
        pub_post = Post.objects.create(author=self.owner_role, content="pub", type=1, share_with=0)
        PostVersion.objects.create(post=pub_post, user=self.owner, content="pub", images=[])
        # Unlike should not keep matching liked_by filter
        PostLike.objects.create(post=pub_post, role=self.reader_role, liked=False)
        self.assertEqual(self.client.get("/post/", {"liked_by": self.reader_role.pk}).data["count"], 0)

        # Private liker / visible_roles stay masked in PostAdminViewset when viewed by non-admin_forum co-author
        team, shared_post, _ = self.shared_content()
        shared_post.share_with = PostShareWithChoice.ROLES
        shared_post.save(update_fields=["share_with"])
        shared_post.visible_roles.add(self.private_role)
        PostLike.objects.create(post=shared_post, role=self.private_role, liked=True)
        authenticate(self.client, self.reader, team)
        admin_post_view = self.client.get(f"/admin/post/{shared_post.pk}/")
        self.assertEqual(admin_post_view.status_code, 200, admin_post_view.data)
        self.assertNotIn(self.private_role.pk, [r["id"] for r in admin_post_view.data["post"]["liked_by"]])
        self.assertNotIn(self.private_role.pk, [r["id"] for r in admin_post_view.data["post"]["visible_roles"]])

        # Self-donation and orphaned-author donation fail cleanly
        authenticate(self.client, self.owner, self.owner_role)
        Coin.objects.filter(pk=self.owner.coin_id).update(total=20)
        self.assertEqual(self.client.post(f"/post/{pub_post.pk}/donate/", {"amount": 5}, format="json").status_code, 400)
        orphan = Post.objects.create(author=None, content="orphan", type=1, share_with=0)
        self.assertEqual(self.client.post(f"/post/{orphan.pk}/donate/", {"amount": 5}, format="json").status_code, 400)

        # Comment deletion masks author, reply_to masks deleted parent author, and post author can delete replies
        c1 = PostComment.objects.create(post=pub_post, author=self.reader_role, user=self.reader, content="root")
        c2 = PostComment.objects.create(post=pub_post, author=self.owner_role, user=self.owner, parent=c1, reply_to=c1, depth=2, content="child")
        c3 = PostComment.objects.create(post=pub_post, author=self.reader_role, user=self.reader, parent=c1, reply_to=c2, depth=3, content="grandchild")
        # Post author deletes c1
        self.assertEqual(self.client.delete(f"/comment/{c1.pk}/").status_code, 200)
        # Third party cannot delete c2
        outsider, outsider_role = make_user("c_outsider")
        authenticate(self.client, outsider, outsider_role)
        self.assertEqual(self.client.delete(f"/comment/{c2.pk}/").status_code, 404)
        # Deleted c1 has author=None and content=None; liking/replying to deleted c1 is rejected
        listing = self.client.get("/comment/", {"post": pub_post.pk}).data["results"]
        self.assertIsNone(listing[0]["author"])
        self.assertIsNone(listing[0]["content"])
        self.assertEqual(self.client.post(f"/comment/{c1.pk}/like/").status_code, 400)
        self.assertEqual(self.client.post("/comment/", {"post": pub_post.pk, "content": "x", "reply_to": c1.pk}, format="json").status_code, 400)
        # Deleted c2 hides reply_to.author on c3
        c2.deleted = True
        c2.save(update_fields=["deleted"])
        replies = self.client.get("/comment/", {"post": pub_post.pk, "parent": c1.pk}).data["results"]
        grandchild = [item for item in replies if item["id"] == c3.pk][0]
        self.assertIsNone(grandchild["reply_to"]["author"])

    def test_notification_scoping(self):
        n_other = Notification.objects.create(role=self.owner_role, type=NotificationType.SYSTEM, content={"msg": "secret"})
        authenticate(self.client, self.reader)  # role=None
        self.assertEqual(self.client.get("/notification/").data["count"], 0)
        authenticate(self.client, self.reader, self.reader_role)
        self.assertEqual(self.client.post(f"/notification/{n_other.pk}/read/").status_code, 404)
