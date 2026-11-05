from django.core.cache import cache
from django.test import TestCase
from django.utils import timezone
from rest_framework.test import APIClient
from gt_auth.test_support import make_user,add_key,authenticate
from .models import Image,File,Video
from gt_forum.models import Post
from gt_auth.models import RoleMember


class MediaPermissionTests(TestCase):
    def setUp(self):
        cache.clear();self.client=APIClient()
        self.owner,_=make_user('owner')
        self.image=Image.objects.create(user=self.owner,name='photo',key='photo.png',md5='0'*32,content_type='image/png',size=42,create_time=timezone.now())
        self.file=File.objects.create(user=self.owner,name='document',content_type='application/pdf',size=42)
        self.video=Video.objects.create(user=self.owner,name='video',size=42)

    def test_file_manager_cannot_read_other_users_media_inventory(self):
        user,role=make_user('files',roles=['admin_file']);key,_=add_key(user);authenticate(self.client,user,role,key=key)
        self.assertEqual(self.client.get('/file/').data['count'],1)
        self.assertEqual(self.client.get('/image/').data['count'],0)
        self.assertEqual(self.client.get('/video/').data['count'],0)

    def test_image_manager_can_read_images_and_videos_but_not_files(self):
        user,role=make_user('images',roles=['admin_image']);key,_=add_key(user);authenticate(self.client,user,role,key=key)
        self.assertEqual(self.client.get('/image/').data['count'],1)
        self.assertEqual(self.client.get('/video/').data['count'],1)
        self.assertEqual(self.client.get('/file/').data['count'],0)

    def test_super_admin_inherits_both_inventory_permissions(self):
        user,role=make_user('root',roles=['super_admin']);key,_=add_key(user);authenticate(self.client,user,role,key=key)
        for path in ['/file/','/image/','/video/']:
            self.assertEqual(self.client.get(path).data['count'],1)

    def test_airdrop_endpoint_is_retired(self):
        authenticate(self.client,self.owner)
        self.assertEqual(self.client.get('/drop/').status_code,404)
        self.assertEqual(self.client.post('/drop/',{},format='json').status_code,404)

    def test_video_details_follow_private_post_membership(self):
        role = self.owner.roles.first().role
        self.video.is_active=True;self.video.save()
        post=Post.objects.create(author=role,content='private video',type=1,share_with=-3,review_status=0,video_id=self.video.pk)
        viewer,current=make_user('viewer');authenticate(self.client,viewer,current)
        self.assertEqual(self.client.get(f'/video/{self.video.pk}/').status_code,404)
        RoleMember.objects.create(user=viewer,role=role)
        self.assertEqual(self.client.get(f'/video/{self.video.pk}/').status_code,200)
        post.deleted=True;post.save()
        self.assertEqual(self.client.get(f'/video/{self.video.pk}/').status_code,404)

    def test_guessed_video_id_cannot_be_attached_to_another_post(self):
        user,role=make_user('attacker');authenticate(self.client,user,role)
        body={'title':'','content':'private','post_type':1,'media_type':2,'images':[],'share_with':-3,'allow_comment':True,'video_id':self.video.pk}
        response=self.client.post('/post/',body,format='json')
        self.assertEqual(response.status_code,400,response.data)
        self.assertFalse(Post.objects.filter(video_id=self.video.pk).exists())
