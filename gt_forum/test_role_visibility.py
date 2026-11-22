"""Tests for Feature 3: Role-scoped post visibility (-4) and role ban interactions."""
from datetime import timedelta

from django.core.cache import cache
from django.test import TestCase
from django.utils import timezone
from rest_framework.test import APIClient

from gt_admin._models import ReviewStatusChoice
from gt_auth.models import Role, RoleMember
from gt_auth.test_support import authenticate, make_user
from gt_forum.models import Post, PostShareWithChoice


class RoleScopedPostVisibilityTests(TestCase):
    def setUp(self):
        cache.clear()
        self.author_user, self.author_primary = make_user("author1")
        self.member_user, self.member_primary = make_user("member1")
        self.outsider_user, self.outsider_primary = make_user("outsider1")

        self.team_a = Role.objects.create(name="实验室A", is_shared=True, editable=True)
        self.team_b = Role.objects.create(name="社团B", is_shared=True, editable=True)
        self.shared_joined = Role.objects.create(name="协作组C", is_shared=True, editable=True)
        RoleMember.objects.create(role=self.team_a, user=self.author_user, is_owner=True)
        RoleMember.objects.create(role=self.team_b, user=self.outsider_user, is_owner=True)
        RoleMember.objects.create(role=self.shared_joined, user=self.member_user, is_owner=True)
        RoleMember.objects.create(role=self.shared_joined, user=self.author_user)
        RoleMember.objects.create(role=self.team_a, user=self.member_user)

        self.author_client = self._auth(self.author_user, self.author_primary)
        self.member_client = self._auth(self.member_user, self.member_primary)
        self.outsider_client = self._auth(self.outsider_user, self.outsider_primary)

    def _auth(self, user, role):
        client = APIClient()
        authenticate(client, user, role)
        return client

    def test_author_can_scope_post_only_to_owned_or_joined_roles_and_visibility_enforced(self):
        # Cannot target a role the author neither owns nor belongs to (team_b)
        bad_resp = self.author_client.post(
            "/post/",
            {
                "author": self.author_primary.pk,
                "title": "越权指定角色",
                "content": "content",
                "post_type": 1,
                "media_type": 0,
                "share_with": PostShareWithChoice.ROLES,
                "visible_role_ids": [self.team_b.pk],
                "allow_comment": True,
                "images": [],
            },
            format="json",
        )
        self.assertEqual(bad_resp.status_code, 400)

        # Must provide at least one role when share_with == -4
        empty_resp = self.author_client.post(
            "/post/",
            {
                "author": self.author_primary.pk,
                "title": "未选角色",
                "content": "content",
                "post_type": 1,
                "media_type": 0,
                "share_with": PostShareWithChoice.ROLES,
                "visible_role_ids": [],
                "allow_comment": True,
                "images": [],
            },
            format="json",
        )
        self.assertEqual(empty_resp.status_code, 400)

        # Can select owned role (team_a) AND joined role (shared_joined)
        ok_resp = self.author_client.post(
            "/post/",
            {
                "author": self.author_primary.pk,
                "title": "内部通知",
                "content": "仅限指定角色查看",
                "post_type": 1,
                "media_type": 0,
                "share_with": PostShareWithChoice.ROLES,
                "visible_role_ids": [self.team_a.pk, self.shared_joined.pk],
                "allow_comment": True,
                "images": [],
            },
            format="json",
        )
        self.assertEqual(ok_resp.status_code, 200, ok_resp.data)
        post_id = ok_resp.data["data"]["id"]
        Post.objects.get(pk=post_id).update_review_status(ReviewStatusChoice.NO_NEED)

        # Author and active member of team_a/shared_joined can view; outsider and anon get 404 (not leaked)
        self.assertEqual(self.author_client.get(f"/post/{post_id}/").status_code, 200)
        member_get = self.member_client.get(f"/post/{post_id}/")
        self.assertEqual(member_get.status_code, 200)
        self.assertIn(self.outsider_client.get(f"/post/{post_id}/").status_code, (403, 404))
        self.assertIn(APIClient().get(f"/post/{post_id}/").status_code, (403, 404))

        # Update to team_a only -> approve new version -> member still sees while in active team_a
        self.author_client.put(
            f"/post/{post_id}/",
            {
                "author": self.author_primary.pk,
                "title": "仅限实验室A",
                "content": "更新内容",
                "post_type": 1,
                "media_type": 0,
                "share_with": PostShareWithChoice.ROLES,
                "visible_role_ids": [self.team_a.pk],
                "allow_comment": True,
                "images": [],
            },
            format="json",
        )
        Post.objects.get(pk=post_id).update_review_status(ReviewStatusChoice.NO_NEED)
        self.assertEqual(self.member_client.get(f"/post/{post_id}/").status_code, 200)

        # If team_a is temporarily banned, member_user loses access immediately
        self.team_a.banned_until = timezone.now() + timedelta(hours=1)
        self.team_a.save(update_fields=["banned_until"])
        self.assertIn(self.member_client.get(f"/post/{post_id}/").status_code, (403, 404))

        # Unban team_a, then remove member_user from RoleMember -> access lost
        self.team_a.banned_until = None
        self.team_a.save(update_fields=["banned_until"])
        self.assertEqual(self.member_client.get(f"/post/{post_id}/").status_code, 200)
        RoleMember.objects.filter(role=self.team_a, user=self.member_user).delete()
        self.assertIn(self.member_client.get(f"/post/{post_id}/").status_code, (403, 404))
