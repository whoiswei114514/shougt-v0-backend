from unittest.mock import patch
from django.core.cache import cache
from django.test import TestCase
from django.utils import timezone
from rest_framework.request import Request
from rest_framework.test import APIClient, APIRequestFactory
from gt_auth.test_support import make_user,add_key,authenticate
from .models import Image,File,Video
from .views import ImageUserIdSearchFilter, ImageViewset
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
        user,role=make_user('files',roles=['admin_file']);key,_=add_key(user);add_key(user);authenticate(self.client,user,role,key=key)
        self.assertEqual(self.client.get('/file/').data['count'],1)
        self.assertEqual(self.client.get('/image/').data['count'],0)
        self.assertEqual(self.client.get('/video/').data['count'],0)

    def test_image_manager_can_read_images_and_videos_but_not_files(self):
        user,role=make_user('images',roles=['admin_image']);key,_=add_key(user);add_key(user);authenticate(self.client,user,role,key=key)
        self.assertEqual(self.client.get('/image/').data['count'],1)
        self.assertEqual(self.client.get('/video/').data['count'],1)
        self.assertEqual(self.client.get('/file/').data['count'],0)

    def test_super_admin_inherits_both_inventory_permissions(self):
        user,role=make_user('root',roles=['super_admin']);key,_=add_key(user);add_key(user);authenticate(self.client,user,role,key=key)
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

    def test_image_user_id_search_filter_strictly_respects_scoping(self):
        attacker,role=make_user('img_attacker')
        own_image=Image.objects.create(user=attacker,name='mine.png',key='mine.png',md5='1'*32,content_type='image/png',size=10,create_time=timezone.now())
        authenticate(self.client,attacker,role)
        for query in (str(self.owner.pk), f'#{self.owner.pk}', self.owner.username, self.owner.real_name):
            with self.subTest(query=query):
                resp=self.client.get('/image/',{'search':query})
                self.assertEqual(resp.status_code,200)
                self.assertEqual(resp.data['count'],0)
        # Even direct filter invocation with an unfiltered queryset cannot bypass scoping
        req=Request(APIRequestFactory().get('/image/',{'search':f'#{self.owner.pk}'}))
        req._user=attacker
        view=ImageViewset()
        filtered=ImageUserIdSearchFilter().filter_queryset(req,Image.objects.all(),view)
        self.assertEqual(list(filtered.values_list('id',flat=True)),[])
        req_own=Request(APIRequestFactory().get('/image/',{'search':f'#{attacker.pk}'}))
        req_own._user=attacker
        filtered_own=ImageUserIdSearchFilter().filter_queryset(req_own,Image.objects.all(),view)
        self.assertEqual(list(filtered_own.values_list('id',flat=True)),[own_image.pk])

    def test_ordinary_users_cannot_retrieve_or_list_other_users_files_images_videos(self):
        attacker,role=make_user('media_attacker');authenticate(self.client,attacker,role)
        self.assertEqual(self.client.get('/image/').data['count'],0)
        self.assertEqual(self.client.get('/file/').data['count'],0)
        self.assertEqual(self.client.get('/video/').data['count'],0)
        self.assertEqual(self.client.get(f'/image/{self.image.pk}/').status_code,404)
        self.assertEqual(self.client.get(f'/file/{self.file.pk}/').status_code,404)
        self.assertEqual(self.client.get(f'/video/{self.video.pk}/').status_code,404)
        # Invalid ordering or callback UUID does not error or leak
        self.assertEqual(self.client.get('/image/',{'ordering':'user__student_id'}).status_code,200)
        self.assertEqual(self.client.get('/video/dogecloud_callback/',{'callbackString':'not-a-uuid'}).status_code,200)

    def test_file_and_video_upload_validation_and_global_reader_block(self):
        attacker,role=make_user('upload_tester');authenticate(self.client,attacker,role)
        # Atomic file batch validation prevents partial DB inserts
        res=self.client.post('/file/',[
            {'name':'a.pdf','content_type':'application/pdf','size':10,'expire_days':1},
            {'name':'b.pdf','content_type':'application/pdf','size':10,'expire_days':999},
        ],format='json')
        self.assertEqual(res.status_code,400)
        self.assertFalse(File.objects.filter(user=attacker).exists())
        # Video form/immutable data + quota enforcement
        attacker.quota.video_24h_count_limit=1;attacker.quota.save()
        with patch('gt_file.views.doge_api.get_video_upload_data',return_value={'VodUploadInfo':{'did':'d1'}}):
            ok=self.client.post('/video/',{'name':'v1.mp4','size':100,'content_type':'video/mp4'})
            self.assertEqual(ok.status_code,200,ok.data)
            over=self.client.post('/video/',{'name':'v2.mp4','size':100,'content_type':'video/mp4'})
            self.assertEqual(over.status_code,400)
        # Global reader cannot mutate via direct auth either
        gr,_=make_user('gr_media',roles=['global_reader'])
        self.client.force_authenticate(user=gr)
        self.assertEqual(self.client.post('/image/',{'name':'x.png','md5':'c'*32,'size':10,'content_type':'image/png','scene':'post'},format='json').status_code,403)
        self.assertEqual(self.client.post('/file/',{'name':'x.pdf','content_type':'application/pdf','size':10,'expire_days':1},format='json').status_code,403)
        self.assertEqual(self.client.post('/video/',{'name':'v.mp4','size':100,'content_type':'video/mp4'},format='json').status_code,403)
