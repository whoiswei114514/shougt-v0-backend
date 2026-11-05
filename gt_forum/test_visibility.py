from django.core.cache import cache
from django.test import TestCase
from rest_framework.test import APIClient
from gt_auth.test_support import make_user, authenticate, add_key
from gt_auth.models import Role, RoleMember
from gt_admin._models import ReviewStatusChoice
from .models import Post, PostComment


class RoleVisibilityTests(TestCase):
    def setUp(self):
        cache.clear()
        self.client=APIClient()
        self.owner,self.owner_role=make_user('owner')
        self.member,self.current_role=make_user('member')
        self.outsider,self.outside_role=make_user('outside')
        self.team=Role.objects.create(name='共享角色',is_shared=True)
        RoleMember.objects.create(role=self.team,user=self.owner,is_owner=True)
        RoleMember.objects.create(role=self.team,user=self.member)
        self.post=Post.objects.create(author=self.team,content='private team discussion',type=1,share_with=-3,review_status=0)
        self.comment=PostComment.objects.create(post=self.post,author=self.owner_role,user=self.owner,content='team comment',review_status=0)
        authenticate(self.client,self.member,self.current_role)

    def test_member_sees_private_post_without_switching_roles(self):
        response=self.client.get(f'/post/{self.post.pk}/')
        self.assertEqual(response.status_code,200,response.data)
        self.assertIn(self.post.pk,[post['id'] for post in self.client.get('/post/').data['results']])

    def test_member_replies_using_current_role(self):
        response=self.client.post('/comment/',{'post':self.post.pk,'content':'reply as my current role','reply_to':None},format='json')
        self.assertEqual(response.status_code,200,response.data)
        comment=PostComment.objects.get(pk=response.data['data']['id'])
        self.assertEqual(comment.author_id,self.current_role.pk)
        self.assertNotEqual(comment.author_id,self.post.author_id)
        self.assertEqual(comment.review_status,ReviewStatusChoice.NO_NEED)

    def test_outsider_cannot_read_or_inject_private_comments(self):
        authenticate(self.client,self.outsider,self.outside_role)
        self.assertEqual(self.client.get(f'/post/{self.post.pk}/').status_code,404)
        self.assertEqual(self.client.get('/comment/',{'post':self.post.pk}).data['count'],0)
        self.assertEqual(self.client.get(f'/comment/{self.comment.pk}/').status_code,404)
        self.assertEqual(self.client.post('/comment/',{'post':self.post.pk,'content':'injected','reply_to':None},format='json').status_code,400)

    def test_membership_removal_immediately_revokes_visibility(self):
        RoleMember.objects.filter(role=self.team,user=self.member).delete()
        self.assertEqual(self.client.get(f'/post/{self.post.pk}/').status_code,404)
        self.assertEqual(self.client.get(f'/comment/{self.comment.pk}/').status_code,404)

    def test_reply_target_cannot_cross_posts(self):
        other=Post.objects.create(author=self.owner_role,content='public',type=1,share_with=0)
        unrelated=PostComment.objects.create(post=other,author=self.owner_role,user=self.owner,content='another thread',review_status=0)
        response=self.client.post('/comment/',{'post':self.post.pk,'content':'wrong parent','reply_to':unrelated.pk},format='json')
        self.assertEqual(response.status_code,400,response.data)

    def test_deleted_post_hides_its_comments(self):
        self.post.deleted=True;self.post.save()
        self.assertEqual(self.client.get(f'/comment/{self.comment.pk}/').status_code,404)

    def test_generic_comment_updates_cannot_change_content_or_moderation(self):
        for method in (self.client.put, self.client.patch):
            response = method(f'/comment/{self.comment.pk}/', {'content':'changed','review_status':1,'pinned':True}, format='json')
            self.assertEqual(response.status_code,405)
        self.comment.refresh_from_db()
        self.assertEqual(self.comment.content,'team comment')
        self.assertFalse(self.comment.pinned)

    def test_external_educational_users_do_not_gain_school_visibility(self):
        self.outsider.email='outside@mit.edu';self.outsider.identity='外校人士';self.outsider.school='external';self.outsider.save()
        self.post.share_with=-1;self.post.save()
        authenticate(self.client,self.outsider,self.outside_role)
        self.assertEqual(self.client.get(f'/post/{self.post.pk}/').status_code,404)

    def test_no_review_expands_post_quota_without_granting_admin(self):
        self.member.permission.no_review=True;self.member.permission.save();self.member.refresh_from_db()
        self.member.quota.post_24h_count_limit=1;self.member.quota.save()
        authenticate(self.client,self.member,self.current_role)
        body={'title':'','content':'private quota test','post_type':1,'media_type':0,'images':[],'share_with':-3,'allow_comment':True,'video_id':None}
        for _ in range(2):
            response=self.client.post('/post/',body,format='json');self.assertEqual(response.status_code,200,response.data)
        self.assertFalse(self.client.get('/user/info/').data['permission']['base_admin'])
