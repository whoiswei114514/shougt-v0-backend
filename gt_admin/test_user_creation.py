import json
from django.core import mail
from django.core.cache import cache
from django.test import TestCase
from rest_framework.test import APIClient
from gt_auth.models import User, EmailChallenge
from gt_auth.test_support import make_user, add_key, authenticate, PASSWORD
from gt_admin.models import AdminAuditLog


class AdminUserCreationTests(TestCase):
    def setUp(self):
        cache.clear()
        self.api = APIClient()
        self.actor, role = make_user('user_manager', roles=['admin_user'])
        key, _ = add_key(self.actor)
        authenticate(self.api, self.actor, role, key=key)

    def form(self, name='created_student', email=None):
        return {'username': name, 'email': email or name + '@st.shou.edu.cn',
                'password': PASSWORD, 'real_name': '测试同学'}

    def test_create_without_code_ordinary_user_with_password_hash_and_audit(self):
        response = self.api.post('/admin/user/', self.form(), format='json')
        self.assertEqual(response.status_code, 201, response.data)
        user = User.objects.get(username='created_student')
        self.assertTrue(user.check_password(PASSWORD))
        self.assertIsNone(user.email_verified_at)
        self.assertIsNone(user.real_name_verified_at)
        self.assertIsNone(user.advanced_verified_at)
        self.assertEqual(user.student_id, 'shou-created_student')
        self.assertEqual((user.identity, user.school), ('学生', 'shou'))
        self.assertFalse(user.is_management)
        self.assertFalse(user.is_staff or user.is_superuser)
        self.assertEqual(user.roles.count(), 2)
        self.assertNotIn('authorization', response.data)
        self.assertNotIn('password', response.data['data'])
        self.assertFalse(EmailChallenge.objects.exists())
        self.assertFalse(mail.outbox)
        log = AdminAuditLog.objects.get(action='create_user', object_id=str(user.pk))
        self.assertEqual(log.actor_id, self.actor.pk)
        self.assertFalse(log.details['email_verified'])
        self.assertNotIn(PASSWORD, json.dumps(log.details))

    def test_cannot_inject_permissions_or_verified_identity(self):
        form = self.form()
        for field, value in [('is_superuser', True), ('permission', {'super_admin': True}),
                             ('real_name_verified_at', 'now'), ('email_verified_at', 'now'),
                             ('school', 'shou'), ('student_id', 'spoofed')]:
            response = self.api.post('/admin/user/', dict(form, **{field: value}), format='json')
            self.assertEqual(response.status_code, 400)
        self.assertFalse(User.objects.filter(username=form['username']).exists())
        self.assertEqual(self.api.post('/admin/user/', form, format='json').status_code, 201)

    def test_duplicate_username_and_owned_email_rejected(self):
        self.assertEqual(self.api.post('/admin/user/', self.form(), format='json').status_code, 201)
        self.assertEqual(self.api.post('/admin/user/', self.form(), format='json').status_code, 400)
        self.assertEqual(self.api.post('/admin/user/', self.form('other', self.actor.email), format='json').status_code, 400)

    def test_unauthorized_user_cannot_create_accounts(self):
        student, role = make_user('ordinary')
        authenticate(self.api, student, role)
        self.assertEqual(self.api.post('/admin/user/', self.form(), format='json').status_code, 403)
        self.assertFalse(User.objects.filter(username='created_student').exists())

    def test_rejects_invalid_email_password_and_classifies_teachers(self):
        self.assertEqual(self.api.post('/admin/user/', self.form('bad', 'bad@gmail.com'), format='json').status_code, 400)
        form = self.form('teacher_account', 'new_teacher@shou.edu.cn')
        self.assertEqual(self.api.post('/admin/user/', dict(form, password='123'), format='json').status_code, 400)
        self.assertEqual(self.api.post('/admin/user/', form, format='json').status_code, 201)
        user = User.objects.get(username='teacher_account')
        self.assertEqual((user.identity, user.school, user.student_id), ('教师', 'shou', 'shou-new_teacher'))

    def test_created_user_can_login_then_verify_own_email(self):
        self.assertEqual(self.api.post('/admin/user/', self.form(), format='json').status_code, 201)
        self.api.credentials()
        response = self.api.post('/security/password-login/',
                                 {'username': 'created_student', 'password': PASSWORD}, format='json')
        self.assertEqual(response.status_code, 200, response.data)
        self.assertFalse(response.data['security']['email_verified'])
