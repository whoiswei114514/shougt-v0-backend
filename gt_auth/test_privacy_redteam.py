"""Privacy and object-authorization regressions with isolated local fixtures."""
from django.core.cache import cache
from django.test import TestCase
from rest_framework.test import APIClient

from gt_admin.models import Report
from gt_auth.models import Follow, Role, RoleMember
from gt_auth.test_support import PASSWORD, add_key, authenticate, make_user
from gt_forum.models import Post, PostComment, PostVersion


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
