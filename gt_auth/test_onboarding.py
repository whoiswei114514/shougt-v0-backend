from django.test import TestCase
from django.utils import timezone
from rest_framework.test import APIClient
from .models import User, AuthSession
from .test_support import make_user, add_key, authenticate, VirtualKey
from .security_policy import admin_access_allowed
from . import webauthn


class AdminOnboardingTests(TestCase):
    def setUp(self):
        self.api=APIClient();self.user,self.role=make_user('onboarding',roles=['super_admin'])
        self.key,self.virtual=add_key(self.user)
        add_key(self.user)
        self.user.admin_onboarding_required=True;self.user.save(update_fields=['admin_onboarding_required'])
        self.session,_=authenticate(self.api,self.user,self.role,key=self.key)

    def begin(self):
        result=self.api.post('/security/admin-setup-begin/',{},format='json')
        self.assertEqual(result.status_code,200,result.data);return result.data

    def finish(self,options=None):
        options=options or self.begin()
        return self.api.post('/security/admin-setup-finish/',{'challenge_id':options['challenge_id'],
            'credential':self.virtual.assertion(options)},format='json')

    def test_new_admin_is_limited_until_fresh_key_proof_completes_onboarding(self):
        self.assertEqual(self.session.scope,'enrollment')
        self.assertFalse(admin_access_allowed(self.user,self.session))
        self.assertEqual(self.api.get('/admin/post/').status_code,403)
        self.assertEqual(self.api.post('/security/console-begin/',{},format='json').status_code,403)
        result=self.finish();self.assertEqual(result.status_code,200,result.data)
        self.assertFalse(result.data['security']['admin_onboarding_required'])
        self.assertTrue(result.data['security']['admin_access'])
        self.user.refresh_from_db();self.assertFalse(self.user.admin_onboarding_required)

    def test_changed_account_or_revoked_key_cannot_complete_pending_setup(self):
        options=self.begin();self.key.revoked_at=timezone.now();self.key.save()
        self.assertEqual(self.finish(options).status_code,400)
        self.user.refresh_from_db();self.assertTrue(self.user.admin_onboarding_required)

    def test_setup_proof_is_bound_to_session_and_cannot_be_replayed(self):
        options=self.begin();authenticate(self.api,self.user,self.role,key=self.key)
        self.assertEqual(self.finish(options).status_code,403)
        options=self.begin();self.assertEqual(self.finish(options).status_code,200)
        self.assertEqual(self.finish(options).status_code,400)

    def test_missing_identity_or_independent_factor_does_not_unlock(self):
        AuthSession.objects.filter(pk=self.session.pk).update(methods=['fido2'])
        self.assertEqual(self.finish().status_code,403)
        AuthSession.objects.filter(pk=self.session.pk).update(methods=['fido2','password'])
        User.objects.filter(pk=self.user.pk).update(advanced_verified_at=None)
        self.assertEqual(self.finish().status_code,403)

    def test_keyless_administrator_can_bind_then_finish_from_email_setup_session(self):
        self.user.security_keys.all().delete()
        authenticate(self.api,self.user,self.role,methods=['password','email'],scope='enrollment')
        self.assertEqual(self.api.post('/security/admin-setup-begin/',{},format='json').status_code,403)
        options=self.api.post('/security/key-register-begin/',{'kind':'security_key'},format='json').data
        self.virtual=VirtualKey(self.user)
        registered=self.api.post('/security/key-register-finish/',{'challenge_id':options['challenge_id'],
            'credential':self.virtual.registration(options)},format='json')
        self.assertEqual(registered.status_code,200,registered.data)
        self.assertFalse(registered.data['admin_keys_satisfied'])
        self.assertEqual(self.finish().status_code,403)
        options2=self.api.post('/security/key-register-begin/',{'kind':'security_key','name':'备用密钥'},format='json')
        self.assertEqual(options2.status_code,200,options2.data)
        virtual2=VirtualKey(self.user)
        registered2=self.api.post('/security/key-register-finish/',{'challenge_id':options2.data['challenge_id'],
            'credential':virtual2.registration(options2.data)},format='json')
        self.assertEqual(registered2.status_code,200,registered2.data)
        self.assertTrue(registered2.data['admin_keys_satisfied'])
        self.assertEqual(self.finish().status_code,200)

    def test_permission_promotion_marks_onboarding_and_invalidates_old_sessions(self):
        normal,role=make_user('new_manager');session,_=authenticate(APIClient(),normal,role)
        normal.permission.admin_user=True;normal.permission.save();normal.refresh_from_db()
        self.assertTrue(normal.admin_onboarding_required)
        self.assertNotEqual(normal.version,session.user_version)

    def test_global_reader_can_complete_own_setup_but_cannot_write_business_data(self):
        user,role=make_user('reader_setup',roles=['global_reader']);key,virtual=add_key(user);add_key(user)
        user.admin_onboarding_required=True;user.save()
        authenticate(self.api,user,role,key=key)
        self.virtual=virtual
        self.assertEqual(self.finish().status_code,200)
        self.assertEqual(self.api.post('/post/',{'content':'forbidden'},format='json').status_code,403)

    def test_unknown_or_reauth_session_scopes_are_rejected_and_cannot_bypass_onboarding(self):
        self.user.admin_onboarding_required = False
        self.user.save(update_fields=['admin_onboarding_required'])
        for bad_scope in ('reauth', 'onboarding', 'limited'):
            with self.subTest(bad_scope=bad_scope):
                bad_client = APIClient()
                bad_session, _ = authenticate(bad_client, self.user, self.role, scope=bad_scope)
                self.assertFalse(admin_access_allowed(self.user, bad_session))
                for path in ('/user/info/', '/admin/user/', '/admin/post/', '/security/status/', '/post/'):
                    self.assertEqual(bad_client.get(path).status_code, 401, (bad_scope, path))

    def test_enrollment_scope_and_onboarding_flag_block_admin_and_issuance_endpoints(self):
        # Even if admin_onboarding_required is False, an enrollment-scoped session cannot escape /security/.
        self.user.admin_onboarding_required = False
        self.user.save(update_fields=['admin_onboarding_required'])
        enr_client = APIClient()
        enr_session, _ = authenticate(enr_client, self.user, self.role, key=self.key, scope='enrollment')
        self.assertFalse(admin_access_allowed(self.user, enr_session))
        for path in ('/admin/user/', '/admin/post/', '/post/', '/user/setting/privacy/', '/security/issuance-pending/'):
            self.assertEqual(enr_client.get(path).status_code, 403, path)
        for path in ('/security/console-begin/', '/security/django-admin/'):
            self.assertEqual(enr_client.post(path, {}, format='json').status_code, 403, path)

        # Even if a session row has scope='full', admin_onboarding_required=True traps it and blocks admin/issuance.
        self.user.admin_onboarding_required = True
        self.user.save(update_fields=['admin_onboarding_required'])
        full_client = APIClient()
        full_session, _ = authenticate(full_client, self.user, self.role, key=self.key, scope='full')
        AuthSession.objects.filter(pk=full_session.pk).update(scope='full')
        full_session.refresh_from_db()
        self.assertFalse(admin_access_allowed(self.user, full_session))
        self.assertFalse(User.has_permission(self.user, 'super_admin'))
        for path in ('/admin/user/', '/admin/post/', '/post/', '/user/setting/privacy/', '/security/watermark/', '/security/issuance-pending/'):
            self.assertEqual(full_client.get(path).status_code, 403, path)
        for path in ('/security/console-begin/', '/security/django-admin/', '/security/issuance-csr/', '/security/issuance-proof/'):
            self.assertEqual(full_client.post(path, {}, format='json').status_code, 403, path)
