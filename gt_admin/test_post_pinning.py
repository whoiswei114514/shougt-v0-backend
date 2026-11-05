from django.core.cache import cache
from datetime import timedelta
from django.utils import timezone
from django.test import TestCase
from rest_framework.test import APIClient

from gt_auth.test_support import make_user, add_key, authenticate
from gt_forum.models import Post
from .models import AdminAuditLog


class PostPinningTests(TestCase):
    def setUp(self):
        cache.clear()
        self.api = APIClient()
        self.actor, self.role = make_user("forum_manager", roles=["admin_forum"])
        self.key, _ = add_key(self.actor)
        authenticate(self.api, self.actor, self.role, key=self.key)
        self.owner, self.owner_role = make_user("post_owner")
        self.post = Post.objects.create(author=self.owner_role, content="older post", type=1,
                                        create_time=timezone.now() - timedelta(days=1))
        self.later = Post.objects.create(author=self.owner_role, content="newer post", type=1)
        self.endpoint = f"/admin/post/{self.post.pk}/pin/"

    def test_manager_can_pin_and_unpin_idempotently_with_audit(self):
        before = self.post.update_time
        for value in (True, True, False):
            response = self.api.post(self.endpoint, {"pinned": value}, format="json")
            self.assertEqual(response.status_code, 200, response.data)
            self.assertEqual(response.data["pinned"], value)
            self.post.refresh_from_db()
            self.assertEqual(self.post.pinned, value)
            self.assertEqual(self.post.update_time, before)
        events = list(AdminAuditLog.objects.filter(object_type="post", object_id=str(self.post.pk)).order_by("id"))
        self.assertEqual([event.action for event in events], ["pin_post", "pin_post", "unpin_post"])
        self.assertEqual([event.details for event in events], [
            {"before": False, "after": True}, {"before": True, "after": True}, {"before": True, "after": False},
        ])
        self.assertTrue(all(event.actor_id == self.actor.pk and event.session_id for event in events))

    def test_pin_sorts_first_without_changing_visibility_or_moderation(self):
        visitor = APIClient()
        self.assertEqual(visitor.get("/post/").data["results"][0]["id"], self.later.pk)
        self.assertEqual(self.api.post(self.endpoint, {"pinned": True}, format="json").status_code, 200)
        self.assertEqual(visitor.get("/post/").data["results"][0]["id"], self.post.pk)
        for changes in ({"share_with": -3}, {"share_with": -1}, {"review_status": -1}):
            Post.objects.filter(pk=self.post.pk).update(**changes)
            response = self.api.post(self.endpoint, {"pinned": True, "share_with": 0, "review_status": 1}, format="json")
            self.assertEqual(response.status_code, 200, response.data)
            self.post.refresh_from_db()
            self.assertTrue(all(getattr(self.post, key) == value for key, value in changes.items()))
            self.assertNotIn(self.post.pk, [post["id"] for post in visitor.get("/post/").data["results"]])
            Post.objects.filter(pk=self.post.pk).update(share_with=0, review_status=0)

    def test_owner_and_other_admin_roles_cannot_pin(self):
        cases = [(self.owner, self.owner_role, None)]
        for permission in ("base_admin", "admin_user", "no_review"):
            user, role = make_user(permission, roles=[permission])
            key, _ = add_key(user)
            cases.append((user, role, key))
        for user, role, key in cases:
            with self.subTest(user=user.username):
                authenticate(self.api, user, role, key=key)
                self.assertEqual(self.api.post(self.endpoint, {"pinned": True}, format="json").status_code, 403)
        self.post.refresh_from_db()
        self.assertFalse(self.post.pinned)

    def test_invalid_values_and_deleted_posts_are_rejected(self):
        for value in (None, 1, "true", [], {}):
            with self.subTest(value=value):
                self.assertEqual(self.api.post(self.endpoint, {"pinned": value}, format="json").status_code, 400)
        Post.objects.filter(pk=self.post.pk).update(deleted=True, pinned=True)
        self.assertEqual(self.api.post(self.endpoint, {"pinned": True}, format="json").status_code, 400)
        self.assertEqual(self.api.post(self.endpoint, {"pinned": False}, format="json").status_code, 200)
        self.post.refresh_from_db()
        self.assertFalse(self.post.pinned)

    def test_super_admin_inherits_pinning(self):
        user, role = make_user("pin_super_admin", roles=["super_admin"])
        key, _ = add_key(user)
        authenticate(self.api, user, role, key=key)
        response = self.api.post(self.endpoint, {"pinned": True}, format="json")
        self.assertEqual(response.status_code, 200, response.data)
