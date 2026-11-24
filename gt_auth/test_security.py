import base64
import hashlib
import hmac
import json
import re
import sys
import tempfile
from datetime import timedelta
from pathlib import Path
from unittest.mock import patch

from django.core import mail
from django.core.cache import cache
from django.core.exceptions import ImproperlyConfigured
from django.conf import settings
from django.db import IntegrityError, transaction
from django.test import TestCase, RequestFactory, override_settings
from django.utils import timezone
from rest_framework.test import APIClient
from rest_framework.exceptions import ValidationError

from gt_admin.models import AdminAuditLog
from .models import AuthSession, EmailChallenge, Permission, User, SecurityChallenge, AdvancedVerification
from .education import normalize_education_email, education_identity, send_email_code, consume_email_code
from .roles import effective_roles, visible_badges, validate_roles, may_assign
from .security_policy import admin_access_allowed, high_assurance
from .sessions import authorization
from . import webauthn, totp
from .test_support import make_user, add_key, authenticate, PASSWORD, VirtualKey


class SecurityTests(TestCase):
    def setUp(self):
        cache.clear()
        self.client = APIClient()
        self.user, self.role = make_user()
        self.request = RequestFactory().post("/", REMOTE_ADDR="127.0.0.1")

    def code(self):
        return re.search(r"\b[0-9]{6}\b", mail.outbox[-1].body).group()

    def test_human_verification_setting_controls_login_and_user_info(self):
        with override_settings(HCCAPTCHA_REQUIRED=False), patch("gt.permissions.post") as verify:
            config = self.client.get("/security/config/")
            self.assertIs(config.data["captcha_required"], False)
            response = self.client.post("/security/password-login/", {
                "username": self.user.username, "password": PASSWORD,
            }, format="json")
            self.assertEqual(response.status_code, 200, response.data)
            self.assertIs(response.data["captcha_required"], False)
            self.assertEqual(response.data["captcha_expire_time"], 0)
            authenticate(self.client, self.user, self.role)
            info = self.client.get("/user/info/")
            self.assertEqual(info.status_code, 200, info.data)
            self.assertIs(info.data["captcha_required"], False)
            verify.assert_not_called()

        with override_settings(HCCAPTCHA_REQUIRED=True), patch("gt.permissions.post") as verify:
            self.assertIs(self.client.get("/user/info/").data["captcha_required"], True)
            self.client.credentials()
            self.assertIs(self.client.get("/security/config/").data["captcha_required"], True)
            response = self.client.post("/security/password-login/", {
                "username": self.user.username, "password": PASSWORD,
            }, format="json")
            self.assertEqual(response.status_code, 401)
            verify.assert_not_called()

    def test_education_domain_boundaries_and_classification(self):
        cases = {"a@st.shou.edu.cn": ("学生", "shou"), "a@shou.edu.cn": ("教师", "shou"),
                 "a@dept.shou.edu.cn": ("教师", "shou"), "a@mit.edu": ("外校人士", "external"),
                 "a@ox.ac.uk": ("外校人士", "external"), "a@evilshou.edu.cn": ("外校人士", "external")}
        for email, identity in cases.items():
            with self.subTest(email=email): self.assertEqual(education_identity(email), identity)
        self.assertEqual(normalize_education_email(" A@ST.SHOU.EDU.CN "), "a@st.shou.edu.cn")
        for email in ("a@gmail.com", "a@st.shou.edu.cn.evil.org", "a@edu.cn", "a@shou.edu.cn\nBcc:x@y.edu", "a@edu"):
            with self.subTest(email=email), self.assertRaises(ValidationError): normalize_education_email(email)

    def test_email_code_is_scoped_and_single_use(self):
        data = send_email_code("new@st.shou.edu.cn", "register", self.request)
        with self.assertRaises(ValidationError): consume_email_code(data["challenge_id"], self.code(), "bind", user=self.user)
        self.assertEqual(consume_email_code(data["challenge_id"], self.code(), "register"), "new@st.shou.edu.cn")
        with self.assertRaises(ValidationError): consume_email_code(data["challenge_id"], self.code(), "register")

    @override_settings(DEBUG=True, LOCAL_PREVIEW_MODE=True, LOCAL_PREVIEW_EMAIL_CODE='123456')
    def test_fixed_local_preview_code_is_scoped_and_never_allowed_remotely(self):
        result=send_email_code('fixed@st.shou.edu.cn','register',self.request)
        self.assertEqual(self.code(),'123456')
        self.assertEqual(consume_email_code(result['challenge_id'],'123456','register'),'fixed@st.shou.edu.cn')
        with override_settings(DEBUG=False), self.assertRaises(ImproperlyConfigured):
            send_email_code('production@st.shou.edu.cn','register',self.request)
        remote=RequestFactory().post('/',REMOTE_ADDR='192.0.2.10')
        with self.assertRaises(ImproperlyConfigured):send_email_code('remote@st.shou.edu.cn','register',remote)

    def test_email_code_attempts_persist(self):
        data = send_email_code("new@st.shou.edu.cn", "register", self.request)
        correct = self.code()
        for _ in range(5):
            with self.assertRaises(ValidationError): consume_email_code(data["challenge_id"], "wrong", "register")
        self.assertEqual(EmailChallenge.objects.get(pk=data["challenge_id"]).attempts, 5)
        with self.assertRaises(ValidationError): consume_email_code(data["challenge_id"], correct, "register")

    def test_email_expiration_and_address_binding(self):
        data = send_email_code("new@st.shou.edu.cn", "register", self.request)
        with self.assertRaises(ValidationError): consume_email_code(data["challenge_id"], self.code(), "register", email="other@st.shou.edu.cn")
        EmailChallenge.objects.filter(pk=data["challenge_id"]).update(expires_at=timezone.now()-timedelta(seconds=1))
        with self.assertRaises(ValidationError): consume_email_code(data["challenge_id"], self.code(), "register")

    def test_registration_verifies_email_and_cannot_assign_roles(self):
        response = self.client.post("/security/register-code/", {"email": "new@st.shou.edu.cn"})
        self.assertEqual(response.status_code, 200, response.data)
        response = self.client.post("/security/register/", {"username":"new", "email":"new@st.shou.edu.cn", "password":PASSWORD,
                                    "code":self.code(), "challenge_id":response.data["challenge_id"], "super_admin":True, "identity":"教师"}, format="json")
        self.assertEqual(response.status_code, 200, response.data)
        user=User.objects.get(username="new")
        self.assertEqual(user.identity, "学生")
        self.assertIsNotNone(user.email_verified_at)
        self.assertFalse(user.permission.super_admin)
        self.assertIsNotNone(user.primary_role_id)
        self.assertFalse(user.primary_role.is_private)

    def test_real_webauthn_signature_and_challenge_replay(self):
        key, virtual = add_key(self.user)
        options = webauthn.begin_assertion("login", user=self.user, keys=[key])
        credential = virtual.assertion(options)
        verified, _ = webauthn.finish_assertion(options["challenge_id"], "login", credential)
        self.assertEqual(verified.pk, key.pk)
        with self.assertRaises(ValidationError): webauthn.finish_assertion(options["challenge_id"], "login", credential)

    def test_webauthn_rejects_wrong_origin_rp_uv_and_cross_origin(self):
        key, virtual = add_key(self.user)
        for kwargs in ({"origin":"https://evil.example"}, {"rp":"wrong.example"}, {"uv":False}, {"cross_origin":True}):
            with self.subTest(kwargs=kwargs):
                options=webauthn.begin_assertion("login",user=self.user,keys=[key])
                with self.assertRaises(ValidationError): webauthn.finish_assertion(options["challenge_id"],"login",virtual.assertion(options,**kwargs))

    def test_forged_signature_and_wrong_key_are_rejected(self):
        key, virtual=add_key(self.user)
        other, other_virtual=add_key(self.user)
        options=webauthn.begin_assertion("login",user=self.user,keys=[key])
        with self.assertRaises(ValidationError): webauthn.finish_assertion(options["challenge_id"],"login",other_virtual.assertion(options))
        options=webauthn.begin_assertion("login",user=self.user,keys=[key])
        response=virtual.assertion(options);response["response"]["signature"]=webauthn.b64(b"forged")
        with self.assertRaises(ValidationError): webauthn.finish_assertion(options["challenge_id"],"login",response)

    def test_synced_passkey_cannot_be_a_security_key(self):
        virtual=VirtualKey(self.user,backup=True)
        options=webauthn.begin_registration(self.user,kind="security_key")
        with self.assertRaises(ValidationError): webauthn.finish_registration(self.user,options["challenge_id"],virtual.registration(options))

    def test_attestation_flags_or_product_name_do_not_grant_fips(self):
        key,_=add_key(self.user)
        key.name="YubiKey 5 FIPS";key.attestation_verified=True;key.assurance_level="fips140-3-level3";key.save()
        self.assertFalse(high_assurance(key))

    def test_unattested_external_key_can_enroll_and_requires_two_keys_or_high_assurance(self):
        from .security_policy import enrollment_complete, admin_keys_satisfied
        user, role = make_user('root', roles=['super_admin'])
        v1 = VirtualKey(user)
        opt1 = webauthn.begin_registration(user, kind='security_key', name='Ordinary #1')
        k1 = webauthn.finish_registration(user, opt1['challenge_id'], v1.registration(opt1, attestation=False))
        self.assertTrue(k1.is_security_key)
        self.assertFalse(k1.attestation_verified)
        self.assertEqual(k1.assurance_level, 'standard')
        self.assertFalse(high_assurance(k1))
        self.assertFalse(admin_keys_satisfied(user))
        self.assertFalse(enrollment_complete(user))

        # 1 ordinary key cannot log in single-factor or complete onboarding
        b1 = self.client.post('/security/key-login-begin/', {'username': user.username}, format='json').data
        f1 = self.client.post('/security/key-login-finish/', {'challenge_id': b1['challenge_id'], 'credential': v1.assertion(b1)}, format='json')
        self.assertEqual(f1.status_code, 200, f1.data)
        self.assertTrue(f1.data.get('factor_required'))

        # Binding 2nd distinct unattested external key satisfies admin policy
        v2 = VirtualKey(user)
        opt2 = webauthn.begin_registration(user, kind='security_key', name='Ordinary #2')
        k2 = webauthn.finish_registration(user, opt2['challenge_id'], v2.registration(opt2, attestation=False))
        self.assertTrue(admin_keys_satisfied(user))
        self.assertTrue(enrollment_complete(user))

        # Login via 2 unattested ordinary keys succeeds
        b2 = self.client.post('/security/key-login-begin/', {'username': user.username}, format='json').data
        f2 = self.client.post('/security/key-login-finish/', {'challenge_id': b2['challenge_id'], 'credential': v1.assertion(b2)}, format='json')
        self.assertIn('security_key', f2.data['methods'])
        fk = self.client.post('/security/factor-key-begin/', {'ticket': f2.data['ticket']}, format='json').data
        done = self.client.post('/security/factor-finish/', {'ticket': f2.data['ticket'], 'method': 'security_key', 'challenge_id': fk['challenge_id'], 'credential': v2.assertion(fk)}, format='json')
        self.assertEqual(done.status_code, 200, done.data)
        self.assertTrue(done.data['security']['admin_access'])
        self.assertTrue(done.data['security']['admin_keys_satisfied'])
        self.assertEqual(done.data['security']['external_key_count'], 2)

        # Onboarded admin cannot revoke down to 1 ordinary key
        client = APIClient()
        authenticate(client, user, role, key=k1, methods=['fido2', 'password'])
        rm = client.post('/security/key-remove/', {'key_id': k2.pk}, format='json')
        self.assertEqual(rm.status_code, 403, rm.data)
        k2.refresh_from_db()
        self.assertIsNone(k2.revoked_at)

    def test_verified_hardware_trust_must_remain_current(self):
        from django.conf import settings
        key,_=add_key(self.user)
        self.assertTrue(webauthn.trusted_hardware(key))
        with override_settings(FIDO_ATTESTATION_TRUST=[]):
            self.assertFalse(webauthn.trusted_hardware(key))

    def test_trusted_fips_and_equivalent_key_login_skip_second_factor(self):
        user,role=make_user('certified',roles=['super_admin']);key,virtual=add_key(user)
        for level in ('fips140-2-level2','fips140-3-level3','fips140-3-level4','equivalent-level2'):
            trust=[dict(item,assurance=level,certification_reference='LOCAL TEST CERTIFICATION') for item in settings.FIDO_ATTESTATION_TRUST]
            with self.subTest(level=level), override_settings(FIDO_ATTESTATION_TRUST=trust):
                options=self.client.post('/security/key-login-begin/',{'username':user.username},format='json').data
                response=self.client.post('/security/key-login-finish/',{'challenge_id':options['challenge_id'],'credential':virtual.assertion(options)},format='json')
                self.assertEqual(response.status_code,200,response.data)
                self.assertNotIn('factor_required',response.data)
                self.assertTrue(response.data['security']['admin_access'])
                key.refresh_from_db();self.assertEqual(key.assurance_level,level)
        options=webauthn.begin_assertion('login',user=user,keys=[key])
        webauthn.finish_assertion(options['challenge_id'],'login',virtual.assertion(options))
        key.refresh_from_db();self.assertEqual(key.assurance_level,'standard')

    def test_revoked_attestation_metadata_updates_console_snapshot(self):
        key,virtual=add_key(self.user)
        with override_settings(FIDO_ATTESTATION_TRUST=[]):
            options=webauthn.begin_assertion('login',user=self.user,keys=[key])
            webauthn.finish_assertion(options['challenge_id'],'login',virtual.assertion(options))
            key.refresh_from_db();self.assertFalse(key.attestation_verified)

    def test_totp_enabled_password_login_requires_an_independent_factor(self):
        setup=totp.prepare(self.user)
        code=totp.generate_code(setup['secret'],int(timezone.now().timestamp())//30)
        self.assertTrue(totp.verify(self.user,code,confirm=True))
        response=self.client.post('/user/login/',{'username':self.user.username,'password':PASSWORD})
        self.assertTrue(response.data['factor_required'])
        self.assertNotIn('password',response.data['methods'])
        response=self.client.post('/security/factor-finish/',{'ticket':response.data['ticket'],'method':'password','password':PASSWORD},format='json')
        self.assertEqual(response.status_code,403)

    def test_privileged_login_requires_second_factor(self):
        user,role=make_user("root",roles=["super_admin"]);key,virtual=add_key(user);add_key(user)
        options=self.client.post('/security/key-login-begin/',{"username":"root"},format="json").data
        response=self.client.post('/security/key-login-finish/',{"challenge_id":options["challenge_id"],"credential":virtual.assertion(options)},format="json")
        self.assertEqual(response.status_code,200,response.data);self.assertTrue(response.data["factor_required"])
        self.assertFalse(AuthSession.objects.filter(user=user).exists())
        result=self.client.post('/security/factor-finish/',{"ticket":response.data["ticket"],"method":"password","password":PASSWORD},format="json")
        self.assertEqual(result.status_code,200,result.data);self.assertTrue(result.data["permission"]["super_admin"])
        self.assertEqual(set(AuthSession.objects.get(user=user).methods),{"fido2","password"})

    def test_admin_password_login_cannot_skip_key(self):
        user,_=make_user("moderator",roles=["admin_forum"]);add_key(user)
        response=self.client.post('/user/login/',{"username":user.username,"password":PASSWORD})
        self.assertEqual(response.status_code,403);self.assertTrue(response.data["security_key_required"])

    def test_migration_enrollment_cannot_enter_admin_routes(self):
        user,role=make_user("oldadmin",roles=["admin_user"])
        response=self.client.post('/user/login/',{"username":user.username,"password":PASSWORD})
        self.assertTrue(response.data["enrollment"])
        session,_=authenticate(self.client,user,role,scope="enrollment",methods=["password","email"])
        self.assertEqual(self.client.get('/admin/user/').status_code,403)
        self.assertEqual(self.client.get('/security/status/').status_code,200)

    def test_user_admin_cannot_assign_management_or_impersonate(self):
        user,role=make_user("users",roles=["admin_user"]);key,_=add_key(user);add_key(user);authenticate(self.client,user,role,key=key)
        response=self.client.put(f'/admin/user/{self.user.pk}/?type=permission',{"admin_forum":True},format="json")
        self.assertEqual(response.status_code,400,response.data)
        response=self.client.put(f'/admin/user/{self.user.pk}/?type=permission',{"no_review":True},format="json")
        self.assertEqual(response.status_code,200,response.data)
        before=AuthSession.objects.count();detail=self.client.get(f'/admin/user/{self.user.pk}/')
        self.assertIsNone(detail.data['authorization']);self.assertEqual(AuthSession.objects.count(),before)
        self.assertEqual(self.client.post('/security/console-begin/').status_code,403)

    def test_protected_accounts_cannot_be_modified_by_user_admin(self):
        actor,role=make_user("users",roles=["admin_user"]);key,_=add_key(actor);add_key(actor);authenticate(self.client,actor,role,key=key)
        target,_=make_user("root",roles=["super_admin"])
        self.assertEqual(self.client.post(f'/admin/user/{target.pk}/ban/',{"is_active":False},format="json").status_code,403)
        self.assertEqual(self.client.post(f'/admin/user/{target.pk}/change-password/',{"password":PASSWORD},format="json").status_code,403)

    def test_expired_password_exemption_is_enforced_on_existing_session(self):
        user,role=make_user("moderator",roles=["admin_forum"]);add_key(user)
        user.security_key_exempt_until=timezone.now()+timedelta(days=1);user.save()
        session,_=authenticate(self.client,user,role)
        self.assertEqual(self.client.get('/admin/post/').status_code,200)
        User.objects.filter(pk=user.pk).update(security_key_exempt_until=timezone.now()-timedelta(seconds=1))
        self.assertEqual(self.client.get('/admin/post/').status_code,401)

    def test_token_claims_cannot_be_forged_but_owned_role_can_change(self):
        session,token=authenticate(self.client,self.user,self.role)
        data,signature=token.split('.');payload=json.loads(base64.urlsafe_b64decode(data))
        payload['user_version']=-1
        forged=base64.urlsafe_b64encode(json.dumps(payload).encode()).decode()+'.'+signature
        self.client.credentials(HTTP_AUTHORIZATION='Bearer '+forged)
        self.assertEqual(self.client.get('/user/info/').status_code,401)

    def test_last_admin_key_cannot_be_revoked(self):
        user,role=make_user("moderator",roles=["admin_forum"]);key,_=add_key(user);authenticate(self.client,user,role,key=key)
        self.assertEqual(self.client.post('/security/key-remove/',{"key_id":key.pk},format="json").status_code,403)
        key.refresh_from_db();self.assertIsNone(key.revoked_at)

    def test_django_admin_has_no_password_only_entry(self):
        self.assertEqual(self.client.post('/django-admin/login/',{"username":"student","password":PASSWORD}).status_code,403)

    def test_django_user_admin_is_readonly_and_does_not_expose_password(self):
        actor,role=make_user('root',roles=['super_admin']);key,_=add_key(actor);add_key(actor)
        session,_=authenticate(self.client,actor,role,key=key)
        self.client.force_login(actor)
        browser_session=self.client.session;browser_session['shou_security_session']=str(session.pk);browser_session.save()
        path=f'/django-admin/gt_auth/user/{self.user.pk}/change/'
        response=self.client.get(path)
        self.assertEqual(response.status_code,200)
        self.assertNotContains(response,self.user.password)
        self.assertNotContains(response,'name="_save"')
        self.assertContains(response,'shou-watermark')
        from gt_admin.models import AdminAuditLog
        before = AdminAuditLog.objects.count()
        frame = self.client.get('/django-admin/watermark/')
        self.assertEqual(frame.status_code, 200)
        self.assertEqual(frame.json()["actor_id"], actor.pk)
        self.assertEqual(AdminAuditLog.objects.count(), before)
        self.assertIn("no-store", frame["Cache-Control"])
        self.assertEqual(self.client.post(path,{'is_superuser':True}).status_code,403)

    def test_totp_code_replay_is_rejected(self):
        setup=totp.prepare(self.user)
        code=totp.generate_code(setup['secret'],int(timezone.now().timestamp())//30)
        self.assertTrue(totp.verify(self.user,code,confirm=True));self.assertFalse(totp.verify(self.user,code))

    def test_role_inheritance_and_certification_labels(self):
        self.assertEqual(effective_roles(Permission(no_review=True)), {'no_review'})
        self.assertEqual(effective_roles(Permission(admin_user=True)), {'admin_user','admin_role','base_admin'})
        self.assertEqual([x['label'] for x in visible_badges(Permission(admin_user=True,admin_role=True,base_admin=True))], ['用户管理员'])
        self.assertEqual([x['label'] for x in visible_badges(Permission(super_admin=True))], ['超级管理员'])
        self.assertEqual([x['label'] for x in visible_badges(Permission(admin_admin=True))], ['特权管理员'])
        with self.assertRaises(ValueError):validate_roles({'admin_admin','admin_forum'})
        with self.assertRaises(ValueError):may_assign({'admin_admin'},{'super_admin'},set())
        self.assertTrue(may_assign({'superadmin_admin'},set(),{'super_admin'}))
        with self.assertRaises(ValueError):may_assign({'super_admin'},set(),{'admin_user'},is_self=True)

    def test_database_rejects_incompatible_privileged_roles(self):
        for exclusive in ('admin_admin','superadmin_admin'):
            with self.subTest(role=exclusive), self.assertRaises(IntegrityError), transaction.atomic():
                Permission.objects.filter(pk=self.user.permission_id).update(**{exclusive:True,'admin_image':True})

    def test_advanced_challenge_requires_signed_registered_email(self):
        from .advanced_views import accept_verified_mail
        self.user.admin_candidate_until=timezone.now()+timedelta(days=1);self.user.save()
        key,virtual=add_key(self.user);authenticate(self.client,self.user,self.role,key=key)
        response=self.client.post('/security/advanced/begin/',{'real_name':'测试用户'},format='json')
        self.assertEqual(response.status_code,200,response.data)
        options=response.data
        signed=self.client.post('/security/advanced/finish/',{'challenge_id':options['challenge_id'],'credential':virtual.assertion(options)},format='json')
        self.assertEqual(signed.status_code,200,signed.data)
        event={'recipient':'renzheng@shouguatian.com','authenticated_sender':'wrong@st.shou.edu.cn',
               'from_header':f'测试用户 <{self.user.email}>','dmarc_pass':True,'received_at':timezone.now().isoformat(),'message_id':'local-test','body':signed.data['body']}
        with self.assertRaises(ValidationError):accept_verified_mail(event)
        event['authenticated_sender']=self.user.email;record=accept_verified_mail(event)
        self.assertEqual(record.status,'awaiting_review')
        with self.assertRaises(ValidationError):accept_verified_mail(event)
        self.assertIsNone(User.objects.get(pk=self.user.pk).advanced_verified_at)

    def test_ordinary_users_do_not_need_or_access_advanced_verification(self):
        key,_=add_key(self.user);authenticate(self.client,self.user,self.role,key=key)
        self.assertEqual(self.client.post('/security/advanced/begin/',{'real_name':'测试用户'},format='json').status_code,403)

    def test_unsigned_mail_webhook_is_rejected(self):
        self.assertEqual(self.client.post('/security/mail-ingest/',{},format='json').status_code,403)

    @override_settings(ADVANCED_MAIL_INGEST_SECRET='test-only-mail-adapter-secret')
    def test_authenticated_mail_adapter_binds_the_exact_request_body(self):
        self.user.admin_candidate_until=timezone.now()+timedelta(days=1);self.user.save()
        key,virtual=add_key(self.user);authenticate(self.client,self.user,self.role,key=key)
        options=self.client.post('/security/advanced/begin/',{'real_name':'测试用户'},format='json').data
        signed=self.client.post('/security/advanced/finish/',{'challenge_id':options['challenge_id'],'credential':virtual.assertion(options)},format='json').data
        event={'recipient':'renzheng@shouguatian.com','authenticated_sender':self.user.email,'dmarc_pass':True,
               'from_header':f'测试用户 <{self.user.email}>','received_at':timezone.now().isoformat(),'message_id':'signed-adapter-event','body':signed['body']}
        raw=json.dumps(event).encode();stamp=str(int(timezone.now().timestamp()))
        signature=hmac.new(settings.ADVANCED_MAIL_INGEST_SECRET.encode(),stamp.encode()+b'.'+raw,hashlib.sha256).hexdigest()
        headers={'HTTP_X_SHOU_MAIL_TIME':stamp,'HTTP_X_SHOU_MAIL_SIGNATURE':signature}
        self.assertEqual(self.client.post('/security/mail-ingest/',data=raw+b' ',content_type='application/json',**headers).status_code,403)
        response=self.client.post('/security/mail-ingest/',data=raw,content_type='application/json',**headers)
        self.assertEqual(response.status_code,200,response.data)
        self.assertEqual(response.data['status'],'awaiting_review')

    def test_impersonation_cannot_be_used_for_security_or_management(self):
        from .sessions import create_session
        actor,actor_role=make_user('root',roles=['super_admin']);key,_=add_key(actor);add_key(actor)
        parent=create_session(actor,['fido2','password'],credential=key)
        child,_=authenticate(self.client,self.user,self.role,methods=['impersonation'],scope='impersonation')
        child.parent_session=parent;child.impersonator_id=actor.pk;child.save()
        self.assertEqual(self.client.get('/user/info/').status_code,200)
        self.assertEqual(self.client.post('/security/key-register-begin/',{'password':PASSWORD},format='json').status_code,403)
        self.assertEqual(self.client.post('/user/setting/password/',{'old_password':PASSWORD,'new_password':PASSWORD},format='json').status_code,403)
        self.assertTrue(AdminAuditLog.objects.filter(actor_id=actor.pk,action__startswith='impersonation:').exists())
        parent.revoked_at=timezone.now();parent.save()
        self.assertEqual(self.client.get('/user/info/').status_code,401)

    def test_fido_fresh_seconds_and_second_key_registration_without_reauth(self):
        admin, admin_role = make_user('sec_admin', roles=['super_admin'])
        key, virtual = add_key(admin)
        session, _ = authenticate(self.client, admin, admin_role, key=key, methods=['fido2', 'password'])

        status_res = self.client.get('/security/status/')
        self.assertEqual(status_res.status_code, 200)
        self.assertGreater(status_res.data['fido_fresh_seconds'], 0)

        begin_res = self.client.post('/security/key-register-begin/', {'kind': 'security_key', 'name': '备用密钥'}, format='json')
        self.assertEqual(begin_res.status_code, 200)

        session.verified_at = timezone.now() - timedelta(minutes=6)
        session.save(update_fields=['verified_at'])

        expired_status = self.client.get('/security/status/')
        self.assertEqual(expired_status.status_code, 200)
        self.assertEqual(expired_status.data['fido_fresh_seconds'], 0)
        self.assertEqual(self.client.post('/security/key-register-begin/', {'kind': 'security_key', 'name': '备用密钥'}, format='json').status_code, 403)

        reauth_begin = self.client.post('/security/reauth-begin/', {}, format='json')
        self.assertEqual(reauth_begin.status_code, 200)
        reauth_finish = self.client.post(
            '/security/reauth-finish/',
            {'challenge_id': reauth_begin.data['challenge_id'], 'credential': virtual.assertion(reauth_begin.data)},
            format='json',
        )
        self.assertEqual(reauth_finish.status_code, 200)
        self.assertEqual(reauth_finish.data['fido_fresh_seconds'], 300)
        self.assertEqual(self.client.post('/security/key-register-begin/', {'kind': 'security_key', 'name': '备用密钥'}, format='json').status_code, 200)

    def test_reauth_accepts_second_external_key_and_preserves_two_key_login(self):
        from .sessions import authorization, create_session
        admin, admin_role = make_user('reauth_two_keys', roles=['super_admin'])
        k1, _ = add_key(admin)
        k2, v2 = add_key(admin)
        session = create_session(admin, ['fido2', 'fido2_second'], credential=k1, second_credential=k2)
        auth = authorization(admin, session)
        auth['payload']['role_id'] = admin_role.pk
        tok = base64.urlsafe_b64encode(json.dumps(auth['payload']).encode()).decode() + '.' + auth['signature']
        self.client.credentials(HTTP_AUTHORIZATION='Bearer ' + tok)

        reauth_begin = self.client.post('/security/reauth-begin/', {}, format='json')
        self.assertEqual(reauth_begin.status_code, 200, reauth_begin.data)
        reauth_finish = self.client.post(
            '/security/reauth-finish/',
            {'challenge_id': reauth_begin.data['challenge_id'], 'credential': v2.assertion(reauth_begin.data)},
            format='json',
        )
        self.assertEqual(reauth_finish.status_code, 200, reauth_finish.data)
        session.refresh_from_db()
        self.assertEqual(session.credential_id, k2.pk)
        self.assertEqual(session.second_credential_id, k1.pk)
        self.assertTrue(self.client.get('/security/status/').data['admin_access'])

    def test_privileged_certificate_status_and_auto_issuance_flag(self):
        from .models import ClientCertificateIdentity
        normal, normal_role = make_user('cert_normal')
        authenticate(self.client, normal, normal_role)
        s0 = self.client.get('/security/status/').data
        self.assertEqual(s0['certificate_status'], 'not_required')
        self.assertFalse(s0['needs_certificate_issuance'])

        sa, sa_role = make_user('cert_sa', roles=['super_admin'])
        k1, _ = add_key(sa)
        add_key(sa)
        authenticate(self.client, sa, sa_role, key=k1, methods=['fido2', 'password'])
        s_missing = self.client.get('/security/status/').data
        self.assertEqual(s_missing['certificate_status'], 'missing')
        self.assertTrue(s_missing['needs_certificate_issuance'])

        expired = ClientCertificateIdentity.objects.create(
            fingerprint='1' * 64, user=sa, real_name=sa.real_name,
            issuer_fingerprint='a' * 64, serial_number='101',
            expires_at=timezone.now() - timedelta(days=1),
        )
        s_expired = self.client.get('/security/status/').data
        self.assertEqual(s_expired['certificate_status'], 'expired')
        self.assertTrue(s_expired['needs_certificate_issuance'])

        valid = ClientCertificateIdentity.objects.create(
            fingerprint='2' * 64, user=sa, real_name=sa.real_name,
            issuer_fingerprint='a' * 64, serial_number='102',
            expires_at=timezone.now() + timedelta(days=30),
        )
        s_valid = self.client.get('/security/status/').data
        self.assertEqual(s_valid['certificate_status'], 'valid')
        self.assertFalse(s_valid['needs_certificate_issuance'])

        expired.delete()
        valid.revoked_at = timezone.now()
        valid.save(update_fields=['revoked_at'])
        s_revoked = self.client.get('/security/status/').data
        self.assertEqual(s_revoked['certificate_status'], 'missing')
        self.assertTrue(s_revoked['needs_certificate_issuance'])

    def test_unverified_email_account_cannot_bypass_totp_or_key_2fa_via_email_factor(self):
        unverified, _ = make_user('totp_no_email', verified=False)
        setup = totp.prepare(unverified)
        code = totp.generate_code(setup['secret'], int(timezone.now().timestamp()) // 30)
        self.assertTrue(totp.verify(unverified, code, confirm=True))

        login = self.client.post('/security/password-login/', {'username': unverified.username, 'password': PASSWORD}, format='json')
        self.assertEqual(login.status_code, 200, login.data)
        self.assertTrue(login.data['factor_required'])
        self.assertNotIn('email', login.data['methods'])
        self.assertFalse(login.data['needs_email'])

        ticket = login.data['ticket']
        self.assertEqual(
            self.client.post('/security/factor-email/', {'ticket': ticket, 'email': 'attacker@mit.edu'}, format='json').status_code,
            403,
        )
        email_ch = send_email_code('attacker@mit.edu', 'login_factor', self.request, user=unverified, binding=ticket)
        self.assertEqual(
            self.client.post('/security/factor-finish/', {
                'ticket': ticket, 'method': 'email',
                'email_challenge_id': email_ch['challenge_id'], 'code': self.code(),
            }, format='json').status_code,
            403,
        )
        unverified.refresh_from_db()
        self.assertIsNone(unverified.email_verified_at)

        # Management user with key but unverified email also cannot bypass 2FA via factor-email.
        priv_unv, _ = make_user('priv_no_email', roles=['super_admin'], verified=False)
        _, priv_v = add_key(priv_unv)
        add_key(priv_unv)
        b = self.client.post('/security/key-login-begin/', {'username': priv_unv.username}, format='json').data
        f = self.client.post('/security/key-login-finish/', {'challenge_id': b['challenge_id'], 'credential': priv_v.assertion(b)}, format='json')
        self.assertTrue(f.data['factor_required'])
        self.assertNotIn('email', f.data['methods'])
        self.assertEqual(
            self.client.post('/security/factor-email/', {'ticket': f.data['ticket'], 'email': 'attacker@mit.edu'}, format='json').status_code,
            403,
        )

    def test_enrollment_factor_ticket_never_upgrades_to_full_scope_without_fido2(self):
        mgr, _ = make_user('enr_no_key', roles=['admin_user'])
        login = self.client.post('/security/password-login/', {'username': mgr.username, 'password': PASSWORD}, format='json')
        self.assertTrue(login.data['enrollment'])
        ticket = login.data['ticket']

        # Even if two keys are bound before factor-finish completes, password+email enrollment ticket stays scope='enrollment'.
        add_key(mgr)
        add_key(mgr)
        self.client.post('/security/factor-email/', {'ticket': ticket}, format='json')
        em_ch = EmailChallenge.objects.filter(user=mgr, purpose='login_factor').latest('created_at')
        fin = self.client.post('/security/factor-finish/', {
            'ticket': ticket, 'method': 'email',
            'email_challenge_id': str(em_ch.pk), 'code': self.code(),
        }, format='json')
        self.assertEqual(fin.status_code, 200, fin.data)
        self.assertEqual(fin.data['security']['session_scope'], 'enrollment')
        self.assertFalse(fin.data['security']['admin_access'])

    def test_passkeys_rejected_for_privileged_auth_and_promoted_registration_race(self):
        from .models import WebAuthnCredential
        # 1. Promoted ordinary user cannot finish an in-flight passkey registration.
        candidate, c_role = make_user('promoted_race')
        authenticate(self.client, candidate, c_role)
        reg_opts = self.client.post('/security/key-register-begin/', {'kind': 'passkey', 'name': '手机通行密钥', 'password': PASSWORD}, format='json')
        self.assertEqual(reg_opts.status_code, 200, reg_opts.data)
        candidate.permission.admin_forum = True
        candidate.permission.save()
        candidate.refresh_from_db()
        # Re-authenticate with updated version for enrollment session to attempt key-register-finish.
        authenticate(self.client, candidate, c_role, methods=['password', 'email'], scope='enrollment')
        v_pass = VirtualKey(candidate, backup=True)
        fin = self.client.post('/security/key-register-finish/', {
            'challenge_id': reg_opts.data['challenge_id'],
            'credential': v_pass.registration(reg_opts.data),
            'password': PASSWORD,
        }, format='json')
        self.assertEqual(fin.status_code, 403)
        self.assertFalse(candidate.security_keys.exists())

        # 2. Passkey (backup_eligible=True or is_security_key=False) cannot be used for privileged auth.
        sa, sa_role = make_user('passkey_sa', roles=['super_admin'])
        k1, _ = add_key(sa)
        add_key(sa)
        pv = VirtualKey(sa, backup=True)
        passkey_row = WebAuthnCredential.objects.create(
            user=sa, credential_id=webauthn.b64(pv.id), credential_data=webauthn.b64(pv.data),
            name='Synced Passkey', aaguid=str(pv.data.aaguid), is_security_key=False, backup_eligible=True,
        )
        login_opts = self.client.post('/security/key-login-begin/', {'username': sa.username}, format='json').data
        allowed_ids = {item['id'] for item in login_opts['publicKey']['allowCredentials']}
        self.assertNotIn(webauthn.b64(pv.id), allowed_ids)
        self.assertEqual(
            self.client.post('/security/key-login-finish/', {'challenge_id': login_opts['challenge_id'], 'credential': pv.assertion(login_opts)}, format='json').status_code,
            400,
        )
        disc_opts = self.client.post('/security/key-login-begin/', {}, format='json').data
        self.assertEqual(
            self.client.post('/security/key-login-finish/', {'challenge_id': disc_opts['challenge_id'], 'credential': pv.assertion(disc_opts)}, format='json').status_code,
            403,
        )
        # Even if a session were forged with passkey credential, JWTAuthentication, require_key_session & admin_access_allowed reject it.
        from rest_framework.exceptions import PermissionDenied as ApiPermissionDenied
        from .security_policy import require_key_session
        passkey_session, _ = authenticate(self.client, sa, sa_role, key=passkey_row, methods=['fido2', 'password'])
        self.assertFalse(admin_access_allowed(sa, passkey_session))
        with self.assertRaises(ApiPermissionDenied):
            require_key_session(sa, passkey_session)
        self.assertEqual(self.client.post('/security/console-begin/', {}, format='json').status_code, 401)
        self.assertEqual(self.client.post('/security/advanced/begin/', {}, format='json').status_code, 401)

        # From a valid external-key session, reauth-finish also rejects passkey assertions.
        authenticate(self.client, sa, sa_role, key=k1, methods=['fido2', 'password'])
        reauth_opts = self.client.post('/security/reauth-begin/', {}, format='json')
        self.assertEqual(reauth_opts.status_code, 200)
        self.assertEqual(
            self.client.post('/security/reauth-finish/', {'challenge_id': reauth_opts.data['challenge_id'], 'credential': pv.assertion(reauth_opts.data)}, format='json').status_code,
            400,
        )

    def test_key_remove_validates_id_and_revokes_bound_or_subthreshold_sessions(self):
        sa, sa_role = make_user('kr_sa', roles=['super_admin'])
        k1, _ = add_key(sa)
        k2, _ = add_key(sa)
        k3, _ = add_key(sa)
        c1 = APIClient()
        s1, _ = authenticate(c1, sa, sa_role, key=k1, methods=['fido2', 'password'])
        c2 = APIClient()
        s2, _ = authenticate(c2, sa, sa_role, key=k3, methods=['fido2', 'password'])
        c_dual = APIClient()
        from .sessions import create_session
        s_dual = create_session(sa, ['fido2', 'fido2_second'], credential=k1, second_credential=k3)
        auth_d = authorization(sa, s_dual)
        c_dual.credentials(HTTP_AUTHORIZATION='Bearer ' + base64.urlsafe_b64encode(json.dumps(auth_d['payload']).encode()).decode() + '.' + auth_d['signature'])

        # Malformed or bool key_id cannot 500 or coerce True -> pk=1.
        for bad_id in ('invalid', True, -1, 0):
            self.assertEqual(c1.post('/security/key-remove/', {'key_id': bad_id}, format='json').status_code, 400, bad_id)

        # Removing k3 leaves 2 ordinary keys; sessions bound via credential=k3 OR second_credential=k3 are revoked.
        res = c1.post('/security/key-remove/', {'key_id': k3.pk}, format='json')
        self.assertEqual(res.status_code, 200, res.data)
        self.assertEqual(c2.get('/security/status/').status_code, 401)
        self.assertEqual(c_dual.get('/security/status/').status_code, 401)
        self.assertEqual(c1.get('/security/status/').status_code, 200)

        # Cannot remove k2 below the 2-ordinary-key threshold once onboarded.
        self.assertEqual(c1.post('/security/key-remove/', {'key_id': k2.pk}, format='json').status_code, 403)

        # If admin_onboarding_required=True and removing k2 drops below threshold, any non-enrollment session is revoked.
        sa.admin_onboarding_required = True
        sa.save(update_fields=['admin_onboarding_required'])
        leftover_full = create_session(sa, ['fido2', 'password'], credential=k1, scope='full')
        AuthSession.objects.filter(pk=leftover_full.pk).update(scope='full')
        c_enr = APIClient()
        authenticate(c_enr, sa, sa_role, key=k1, scope='enrollment')
        self.assertEqual(c_enr.post('/security/key-remove/', {'key_id': k2.pk}, format='json').status_code, 200)
        leftover_full.refresh_from_db()
        self.assertIsNotNone(leftover_full.revoked_at)

    def test_totp_cannot_be_reconfirmed_and_key_login_begin_handles_invalid_usernames(self):
        setup = totp.prepare(self.user)
        code = totp.generate_code(setup['secret'], int(timezone.now().timestamp()) // 30)
        authenticate(self.client, self.user, self.role)
        self.assertEqual(self.client.post('/security/totp-confirm/', {'code': code, 'password': PASSWORD}, format='json').status_code, 200)
        next_code = totp.generate_code(setup['secret'], int(timezone.now().timestamp()) // 30 + 1)
        self.assertEqual(self.client.post('/security/totp-confirm/', {'code': next_code, 'password': PASSWORD}, format='json').status_code, 400)

        anon = APIClient()
        none_user, _ = make_user('None')
        add_key(none_user)
        none_opts = anon.post('/security/key-login-begin/', {'username': None}, format='json')
        self.assertEqual(none_opts.status_code, 200)
        self.assertNotIn('allowCredentials', none_opts.data['publicKey'])
        self.assertEqual(anon.post('/security/key-login-begin/', {'username': 12345}, format='json').status_code, 400)

        banned, _ = make_user('banned_key_user')
        add_key(banned)
        banned.is_active = False
        banned.save(update_fields=['is_active'])
        banned_opts = anon.post('/security/key-login-begin/', {'username': banned.username}, format='json').data
        missing_opts = anon.post('/security/key-login-begin/', {'username': 'no_such_user_xyz'}, format='json').data
        self.assertEqual(banned_opts['publicKey']['allowCredentials'], [])
        self.assertEqual(missing_opts['publicKey']['allowCredentials'], [])

    def test_local_preview_strict_isolation_when_disabled(self):
        import importlib
        import os
        from .local_preview_keys import allowed_local_key

        # Importing gt.local_preview_settings without SHOUGT_LOCAL_PREVIEW=1 must fail.
        saved_mod = sys.modules.pop('gt.local_preview_settings', None)
        try:
            with patch.dict(os.environ, {}, clear=False):
                os.environ.pop('SHOUGT_LOCAL_PREVIEW', None)
                with self.assertRaises(RuntimeError):
                    importlib.import_module('gt.local_preview_settings')
        finally:
            sys.modules.pop('gt.local_preview_settings', None)
            if saved_mod is not None:
                sys.modules['gt.local_preview_settings'] = saved_mod

        # Default settings must never use fixed email code or accept local pin files.
        self.assertFalse(getattr(settings, 'LOCAL_PREVIEW_MODE', False))
        self.assertIsNone(getattr(settings, 'LOCAL_PREVIEW_EMAIL_CODE', None))
        ch = send_email_code('normal@st.shou.edu.cn', 'register', self.request)
        if self.code() == '123456':
            # Re-check with another address to avoid 1-in-10^6 false failure
            ch = send_email_code('normal2@st.shou.edu.cn', 'register', self.request)
        self.assertNotEqual(self.code(), '123456')
        with self.assertRaises(ValidationError):
            consume_email_code(ch['challenge_id'], '123456', 'register')
        with override_settings(LOCAL_PREVIEW_EMAIL_CODE='123456', LOCAL_PREVIEW_MODE=False):
            with self.assertRaises(ImproperlyConfigured):
                send_email_code('blocked@st.shou.edu.cn', 'register', self.request)

        key, _ = add_key(self.user)
        with tempfile.TemporaryDirectory() as tmpdir:
            pins_path = Path(tmpdir) / 'pins.json'
            pins_path.write_text(json.dumps([{
                'user_id': self.user.pk, 'credential_id': key.pk,
                'public_data_sha256': hashlib.sha256(key.credential_data.encode()).hexdigest(),
                'expires_at': (timezone.now() + timedelta(days=1)).isoformat(),
            }]), encoding='utf-8')
            with override_settings(LOCAL_PREVIEW_KEY_PINS_FILE=str(pins_path), LOCAL_PREVIEW_MODE=False):
                self.assertFalse(allowed_local_key(key))
            # Even when preview mode is enabled in tests, bool True cannot match id=1.
            pins_path.write_text(json.dumps([{
                'user_id': True, 'credential_id': True,
                'public_data_sha256': hashlib.sha256(key.credential_data.encode()).hexdigest(),
                'expires_at': (timezone.now() + timedelta(days=1)).isoformat(),
            }]), encoding='utf-8')
            with override_settings(DEBUG=True, LOCAL_PREVIEW_MODE=True, LOCAL_PREVIEW_KEY_PINS_FILE=str(pins_path)):
                self.assertFalse(allowed_local_key(key))


class SelfIssuanceTests(TestCase):
    def setUp(self):
        cache.clear()
        sa_root = str(Path(__file__).resolve().parents[2] / "shougt-sa")
        if sa_root not in sys.path:
            sys.path.insert(0, sa_root)
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography import x509 as cx509
        from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
        from tests.certificates_fixture import PKI
        from backend.piv_cli import make_csr, make_certificate
        from backend.piv_crypto import write_proof
        from .models import ClientCertificateIdentity
        from .piv_public import BINDING_OID, canonical, fingerprint

        self.ec = ec
        self.hashes = hashes
        self.serialization = serialization
        self.cx509 = cx509
        self.NameOID = NameOID
        self.ExtendedKeyUsageOID = ExtendedKeyUsageOID
        self.make_csr = make_csr
        self.make_certificate = make_certificate
        self.write_proof = write_proof
        self.ClientCertificateIdentity = ClientCertificateIdentity
        self.BINDING_OID = BINDING_OID
        self.canonical = canonical
        self.fingerprint = fingerprint

        self.tmp = tempfile.TemporaryDirectory(prefix="shou-self-issuance-")
        self.addCleanup(self.tmp.cleanup)
        self.pki = PKI(self.tmp.name, client_name="测试现场超管")

        self.sa, self.sa_role = make_user("self_sa", roles=["super_admin"], verified=True)
        self.sa.real_name = "测试现场超管"
        self.sa.save(update_fields=["real_name"])
        self.sa_key, _ = add_key(self.sa)
        add_key(self.sa)

        self.other_sa, _ = make_user("other_sa", roles=["super_admin"], verified=True)
        self.other_sa.real_name = "其他超级管理员"
        self.other_sa.save(update_fields=["real_name"])
        self.other_sap, _ = make_user("other_sap", roles=["superadmin_admin"], verified=True)
        self.other_sap.real_name = "其他特权超管"
        self.other_sap.save(update_fields=["real_name"])

        self.reader, self.reader_role = make_user("self_reader", roles=["global_reader"], verified=True)
        self.reader.real_name = "全局读者测试"
        self.reader.save(update_fields=["real_name"])
        self.reader_key, _ = add_key(self.reader)
        add_key(self.reader)

        self.other_sa_key, self.other_sa_cert, self.other_sa_row = self._issue_delegated_ca(self.other_sa)
        self.other_sap_key, self.other_sap_cert, self.other_sap_row = self._issue_delegated_ca(self.other_sap)

    def _sign_ec(self, key):
        return lambda msg: key.sign(msg, self.ec.ECDSA(self.hashes.SHA384()))

    def _issue_delegated_ca(self, owner, *, days=180):
        now = timezone.now()
        key = self.ec.generate_private_key(self.ec.SECP384R1())
        builder = (
            self.cx509.CertificateBuilder()
            .subject_name(self.cx509.Name([self.cx509.NameAttribute(self.NameOID.COMMON_NAME, owner.real_name)]))
            .issuer_name(self.pki.sub.subject)
            .public_key(key.public_key())
            .serial_number(self.cx509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=2))
            .not_valid_after(now + timedelta(days=days))
            .add_extension(self.cx509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(self.cx509.KeyUsage(
                digital_signature=True, content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False, key_cert_sign=True,
                crl_sign=False, encipher_only=False, decipher_only=False,
            ), critical=True)
            .add_extension(self.cx509.ExtendedKeyUsage([self.ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
            .add_extension(self.cx509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
            .add_extension(self.cx509.AuthorityKeyIdentifier.from_issuer_public_key(self.pki.sub_key.public_key()), critical=False)
            .add_extension(self.cx509.UnrecognizedExtension(
                self.BINDING_OID, self.canonical({"delegated_ca": True, "user_id": owner.pk}),
            ), critical=False)
        )
        cert = builder.sign(self.pki.sub_key, self.hashes.SHA384())
        pem_str = cert.public_bytes(self.serialization.Encoding.PEM).decode()
        row = self.ClientCertificateIdentity.objects.create(
            fingerprint=self.fingerprint(cert),
            user=owner,
            real_name=owner.real_name,
            issuer_fingerprint=self.fingerprint(self.pki.sub),
            serial_number=str(cert.serial_number),
            expires_at=cert.not_valid_after_utc,
            is_ca=True,
            is_temporary=False,
            certificate_pem=pem_str,
        )
        return key, cert, row

    def _tpm_card(self, slot="9a"):
        return {
            "reader": "Windows TPM 2.0 (Microsoft Platform Crypto Provider)",
            "provider": "Microsoft Platform Crypto Provider",
            "slot": slot,
            "algorithm": "P-384",
            "transport": "tpm",
            "protocol": "TPM-CNG",
            "platform": "windows",
            "on_card_generation": True,
        }

    def _smartcard(self, slot="9a"):
        return {
            "reader": "Microsoft Usbccid Smartcard Reader (WUDF)",
            "slot": slot,
            "algorithm": "P-384",
            "transport": "contact",
            "protocol": "T=1",
            "on_card_generation": True,
        }

    def test_self_issuance_info_lists_card_types_and_excludes_self(self):
        client = APIClient()
        authenticate(client, self.sa, self.sa_role, key=self.sa_key, methods=["fido2", "password"])
        # Even if sa also holds an active CA cert, their own card must not be offered as self-signer.
        self._issue_delegated_ca(self.sa)
        with override_settings(PIV_TLS_CONFIG=self.pki.config):
            res = client.get("/security/self-issuance-info/")
            self.assertEqual(res.status_code, 200, res.data)
            self.assertTrue(res.data["available"])
            self.assertEqual(res.data["site_ca_count"], 2)
            self.assertEqual(res.data["super_admin_card_count"], 1)
            self.assertEqual(res.data["superadmin_admin_card_count"], 1)
            labels = {d["label"] for d in res.data["authorities_summary"]}
            self.assertEqual(labels, {"CA 卡", "超管卡", "超级特权卡"})
            fps = {d["fingerprint"] for d in res.data["authorities_summary"]}
            self.assertIn(self.fingerprint(self.other_sa_cert), fps)
            self.assertIn(self.fingerprint(self.other_sap_cert), fps)
            own_fps = set(self.ClientCertificateIdentity.objects.filter(user=self.sa).values_list("fingerprint", flat=True))
            self.assertFalse(fps & own_fps)

    def test_site_ca_standard_long_term_self_issuance(self):
        client = APIClient()
        authenticate(client, self.sa, self.sa_role, key=self.sa_key, methods=["fido2", "password"])
        with override_settings(PIV_TLS_CONFIG=self.pki.config):
            self.assertEqual(client.get("/security/status/").data["certificate_status"], "missing")
            self.assertTrue(client.get("/security/status/").data["self_issuance_available"])

            begin = client.post("/security/self-issuance-begin/", {"temporary": False}, format="json")
            self.assertEqual(begin.status_code, 200, begin.data)
            job = begin.data["job"]
            self.assertTrue(job["delegated_ca"])
            self.assertFalse(job["temporary"])
            self.assertEqual({d["kind"] for d in job["authority_descriptors"]}, {"ca_card"})

            target_key = self.ec.generate_private_key(self.ec.SECP384R1())
            csr = self.make_csr({**job, "card": {"slot": "9a"}}, target_key.public_key(), self._sign_ec(target_key))
            key_res = client.post("/security/self-issuance-key/", {
                "issuance_id": job["issuance_id"],
                "csr_pem": csr.public_bytes(self.serialization.Encoding.PEM).decode(),
                "card": self._tpm_card(),
            }, format="json")
            self.assertEqual(key_res.status_code, 200, key_res.data)
            job = key_res.data["job"]

            chain = [self.pki.sub, self.pki.root]
            leaf = self.make_certificate(job, self.pki.sub, chain, self._sign_ec(self.pki.sub_key))
            chain_pem = [c.public_bytes(self.serialization.Encoding.PEM).decode() for c in [leaf] + chain]
            proof = base64.b64encode(self._sign_ec(target_key)(self.write_proof(job, leaf, chain))).decode()

            finish = client.post("/security/self-issuance-finish/", {
                "issuance_id": job["issuance_id"],
                "chain_pem": chain_pem,
                "proof": proof,
                "readback_verified": True,
                "onsite_confirmed": True,
                "card_slot": "9a",
            }, format="json")
            self.assertEqual(finish.status_code, 200, finish.data)
            self.assertEqual(finish.data["certificate"]["issuer_kind"], "ca_card")
            self.assertEqual(finish.data["certificate"]["issuer_label"], "CA 卡")
            self.assertTrue(finish.data["certificate"]["is_ca"])
            self.assertFalse(finish.data["certificate"]["is_temporary"])

            self.sa.refresh_from_db()
            self.assertFalse(self.sa.admin_onboarding_required)
            cert_row = self.ClientCertificateIdentity.objects.get(fingerprint=finish.data["certificate"]["fingerprint"])
            self.assertTrue(cert_row.is_ca)
            self.assertFalse(cert_row.is_temporary)
            self.assertEqual(client.get("/security/status/").data["certificate_status"], "valid")

    def test_delegated_superadmin_and_superadmin_admin_temporary_self_issuance(self):
        client = APIClient()
        authenticate(client, self.sa, self.sa_role, key=self.sa_key, methods=["fido2", "password"])
        with override_settings(PIV_TLS_CONFIG=self.pki.config):
            begin = client.post("/security/self-issuance-begin/", {"temporary": True, "validity_days": 36}, format="json")
            self.assertEqual(begin.status_code, 200, begin.data)
            job = begin.data["job"]
            self.assertTrue(job["temporary"])
            self.assertFalse(job["delegated_ca"])
            self.assertIn(self.other_sa_cert.public_bytes(self.serialization.Encoding.PEM).decode(), job["authorities"])

            target_key = self.ec.generate_private_key(self.ec.SECP384R1())
            csr = self.make_csr({**job, "card": {"slot": "9a"}}, target_key.public_key(), self._sign_ec(target_key))
            job = client.post("/security/self-issuance-key/", {
                "issuance_id": job["issuance_id"],
                "csr_pem": csr.public_bytes(self.serialization.Encoding.PEM).decode(),
                "card": self._smartcard(),
            }, format="json").data["job"]

            chain = [self.other_sa_cert, self.pki.sub, self.pki.root]
            leaf = self.make_certificate(job, self.other_sa_cert, chain, self._sign_ec(self.other_sa_key))
            chain_pem = [c.public_bytes(self.serialization.Encoding.PEM).decode() for c in [leaf] + chain]
            proof = base64.b64encode(self._sign_ec(target_key)(self.write_proof(job, leaf, chain))).decode()

            finish = client.post("/security/self-issuance-finish/", {
                "issuance_id": job["issuance_id"],
                "chain_pem": chain_pem,
                "proof": proof,
                "readback_verified": True,
                "onsite_confirmed": True,
                "card_slot": "9a",
            }, format="json")
            self.assertEqual(finish.status_code, 200, finish.data)
            self.assertEqual(finish.data["certificate"]["issuer_kind"], "super_admin_card")
            self.assertEqual(finish.data["certificate"]["issuer_label"], "超管卡")
            self.assertFalse(finish.data["certificate"]["is_ca"])
            self.assertTrue(finish.data["certificate"]["is_temporary"])

            # Also verify read-only privileged global_reader can self-issue with 超级特权卡 (read_only allowlist)
            r_client = APIClient()
            authenticate(r_client, self.reader, self.reader_role, key=self.reader_key, methods=["fido2", "password"])
            r_begin = r_client.post("/security/self-issuance-begin/", {"temporary": True, "validity_days": 14}, format="json")
            self.assertEqual(r_begin.status_code, 200, r_begin.data)
            r_job = r_begin.data["job"]
            r_key = self.ec.generate_private_key(self.ec.SECP384R1())
            r_csr = self.make_csr({**r_job, "card": {"slot": "9a"}}, r_key.public_key(), self._sign_ec(r_key))
            r_job = r_client.post("/security/self-issuance-key/", {
                "issuance_id": r_job["issuance_id"],
                "csr_pem": r_csr.public_bytes(self.serialization.Encoding.PEM).decode(),
                "card": self._tpm_card(),
            }, format="json").data["job"]
            r_chain = [self.other_sap_cert, self.pki.sub, self.pki.root]
            r_leaf = self.make_certificate(r_job, self.other_sap_cert, r_chain, self._sign_ec(self.other_sap_key))
            r_chain_pem = [c.public_bytes(self.serialization.Encoding.PEM).decode() for c in [r_leaf] + r_chain]
            r_proof = base64.b64encode(self._sign_ec(r_key)(self.write_proof(r_job, r_leaf, r_chain))).decode()
            r_finish = r_client.post("/security/self-issuance-finish/", {
                "issuance_id": r_job["issuance_id"],
                "chain_pem": r_chain_pem,
                "proof": r_proof,
                "readback_verified": True,
                "onsite_confirmed": True,
                "card_slot": "9a",
            }, format="json")
            self.assertEqual(r_finish.status_code, 200, r_finish.data)
            self.assertEqual(r_finish.data["certificate"]["issuer_kind"], "superadmin_admin_card")
            self.assertEqual(r_finish.data["certificate"]["issuer_label"], "超级特权卡")

    def test_self_issuance_security_boundaries_and_rejections(self):
        # 1. Ordinary user cannot access self-issuance
        ordinary, ord_role = make_user("ord_self")
        ok, _ = add_key(ordinary)
        ord_client = APIClient()
        authenticate(ord_client, ordinary, ord_role, key=ok, methods=["fido2", "password"])
        with override_settings(PIV_TLS_CONFIG=self.pki.config):
            self.assertEqual(ord_client.get("/security/self-issuance-info/").status_code, 403)
            self.assertEqual(ord_client.post("/security/self-issuance-begin/", {"temporary": False}, format="json").status_code, 403)

        client = APIClient()
        session, _ = authenticate(client, self.sa, self.sa_role, key=self.sa_key, methods=["fido2", "password"])
        own_key, own_cert, _ = self._issue_delegated_ca(self.sa)

        with override_settings(PIV_TLS_CONFIG=self.pki.config):
            # 2. >= 37 days rejected
            self.assertEqual(client.post("/security/self-issuance-begin/", {"temporary": True, "validity_days": 37}, format="json").status_code, 400)
            self.assertEqual(client.post("/security/self-issuance-begin/", {"temporary": True, "validity_days": 0}, format="json").status_code, 400)

            # 3. Standard long-term job rejects browser .p12 and software KSP, and rejects delegated superadmin CA
            std_job = client.post("/security/self-issuance-begin/", {"temporary": False}, format="json").data["job"]
            k_std = self.ec.generate_private_key(self.ec.SECP384R1())
            csr_std = self.make_csr({**std_job, "card": {"slot": "9a"}}, k_std.public_key(), self._sign_ec(k_std))
            browser_soft = {
                "reader": "Browser WebCrypto", "slot": "9a", "algorithm": "P-384",
                "transport": "browser", "protocol": "WebCrypto", "platform": "browser",
                "on_card_generation": False, "browser_keystore": True,
            }
            self.assertEqual(client.post("/security/self-issuance-key/", {
                "issuance_id": std_job["issuance_id"],
                "csr_pem": csr_std.public_bytes(self.serialization.Encoding.PEM).decode(),
                "card": browser_soft,
            }, format="json").status_code, 400)
            software_ksp = {**self._tpm_card(), "provider": "Microsoft Software Key Storage Provider"}
            self.assertEqual(client.post("/security/self-issuance-key/", {
                "issuance_id": std_job["issuance_id"],
                "csr_pem": csr_std.public_bytes(self.serialization.Encoding.PEM).decode(),
                "card": software_ksp,
            }, format="json").status_code, 400)
            std_job = client.post("/security/self-issuance-key/", {
                "issuance_id": std_job["issuance_id"],
                "csr_pem": csr_std.public_bytes(self.serialization.Encoding.PEM).decode(),
                "card": self._tpm_card(),
            }, format="json").data["job"]
            bad_chain = [self.other_sa_cert, self.pki.sub, self.pki.root]
            bad_leaf = self.make_certificate(std_job, self.other_sa_cert, bad_chain, self._sign_ec(self.other_sa_key))
            bad_pem = [c.public_bytes(self.serialization.Encoding.PEM).decode() for c in [bad_leaf] + bad_chain]
            bad_proof = base64.b64encode(self._sign_ec(k_std)(self.write_proof(std_job, bad_leaf, bad_chain))).decode()
            self.assertEqual(client.post("/security/self-issuance-finish/", {
                "issuance_id": std_job["issuance_id"], "chain_pem": bad_pem,
                "proof": bad_proof, "readback_verified": True, "onsite_confirmed": True,
            }, format="json").status_code, 400)

            # 4. Temporary job signed by OWN delegated CA is rejected
            tmp_job = client.post("/security/self-issuance-begin/", {"temporary": True, "validity_days": 7}, format="json").data["job"]
            k_tmp = self.ec.generate_private_key(self.ec.SECP384R1())
            csr_tmp = self.make_csr({**tmp_job, "card": {"slot": "9a"}}, k_tmp.public_key(), self._sign_ec(k_tmp))
            tmp_job = client.post("/security/self-issuance-key/", {
                "issuance_id": tmp_job["issuance_id"],
                "csr_pem": csr_tmp.public_bytes(self.serialization.Encoding.PEM).decode(),
                "card": self._smartcard(),
            }, format="json").data["job"]
            own_chain = [own_cert, self.pki.sub, self.pki.root]
            own_leaf = self.make_certificate(tmp_job, own_cert, own_chain, self._sign_ec(own_key))
            own_pem = [c.public_bytes(self.serialization.Encoding.PEM).decode() for c in [own_leaf] + own_chain]
            own_proof = base64.b64encode(self._sign_ec(k_tmp)(self.write_proof(tmp_job, own_leaf, own_chain))).decode()
            self.assertEqual(client.post("/security/self-issuance-finish/", {
                "issuance_id": tmp_job["issuance_id"], "chain_pem": own_pem,
                "proof": own_proof, "readback_verified": True, "onsite_confirmed": True,
            }, format="json").status_code, 400)

            # 5. Wrong possession proof & revoked delegated CA rejected
            valid_chain = [self.other_sa_cert, self.pki.sub, self.pki.root]
            valid_leaf = self.make_certificate(tmp_job, self.other_sa_cert, valid_chain, self._sign_ec(self.other_sa_key))
            valid_pem = [c.public_bytes(self.serialization.Encoding.PEM).decode() for c in [valid_leaf] + valid_chain]
            valid_proof = base64.b64encode(self._sign_ec(k_tmp)(self.write_proof(tmp_job, valid_leaf, valid_chain))).decode()

            wrong_proof = base64.b64encode(b"bad-sig").decode()
            self.assertEqual(client.post("/security/self-issuance-finish/", {
                "issuance_id": tmp_job["issuance_id"], "chain_pem": valid_pem,
                "proof": wrong_proof, "readback_verified": True, "onsite_confirmed": True,
            }, format="json").status_code, 400)

            self.other_sa_row.revoked_at = timezone.now()
            self.other_sa_row.save(update_fields=["revoked_at"])
            self.assertEqual(client.post("/security/self-issuance-finish/", {
                "issuance_id": tmp_job["issuance_id"], "chain_pem": valid_pem,
                "proof": valid_proof, "readback_verified": True, "onsite_confirmed": True,
            }, format="json").status_code, 400)

            # 6. Stale FIDO session rejected (403)
            session.verified_at = timezone.now() - timedelta(minutes=6)
            session.save(update_fields=["verified_at"])
            self.assertEqual(client.post("/security/self-issuance-begin/", {"temporary": False}, format="json").status_code, 403)

    def test_temporary_privileged_user_cannot_self_issue_long_term_or_exceed_expiry(self):
        client = APIClient()
        Permission.objects.filter(pk=self.sa.permission_id).update(privileged_expires_at=timezone.now() + timedelta(days=10))
        self.sa.permission.refresh_from_db()
        authenticate(client, self.sa, self.sa_role, key=self.sa_key, methods=["fido2", "password"])

        with override_settings(PIV_TLS_CONFIG=self.pki.config):
            self.assertEqual(client.post("/security/self-issuance-begin/", {"temporary": False}, format="json").status_code, 403)
            self.assertEqual(client.post("/security/self-issuance-begin/", {"temporary": True, "validity_days": 11}, format="json").status_code, 400)

            begin = client.post("/security/self-issuance-begin/", {"temporary": True, "validity_days": 5}, format="json")
            self.assertEqual(begin.status_code, 200, begin.data)
            job = begin.data["job"]
            priv = self.ec.generate_private_key(self.ec.SECP384R1())
            csr = self.make_csr({**job, "card": {"slot": "9a"}}, priv.public_key(), self._sign_ec(priv))
            job = client.post("/security/self-issuance-key/", {
                "issuance_id": job["issuance_id"],
                "csr_pem": csr.public_bytes(self.serialization.Encoding.PEM).decode(),
                "card": self._tpm_card(),
            }, format="json").data["job"]

            # Shorten privileged_expires_at to 2 days (still active, no version bump) -> finish rejects 5-day leaf.
            chain = [self.other_sa_cert, self.pki.sub, self.pki.root]
            leaf = self.make_certificate(job, self.other_sa_cert, chain, self._sign_ec(self.other_sa_key))
            chain_pem = [c.public_bytes(self.serialization.Encoding.PEM).decode() for c in [leaf] + chain]
            proof = base64.b64encode(self._sign_ec(priv)(self.write_proof(job, leaf, chain))).decode()
            Permission.objects.filter(pk=self.sa.permission_id).update(privileged_expires_at=timezone.now() + timedelta(days=2))
            self.assertEqual(client.post("/security/self-issuance-finish/", {
                "issuance_id": job["issuance_id"],
                "chain_pem": chain_pem,
                "proof": proof,
                "readback_verified": True,
                "onsite_confirmed": True,
            }, format="json").status_code, 400)

    def test_issuance_csr_and_proof_bind_real_name_and_prevent_proof_overwrite(self):
        from .models import SiteSecuritySetting
        from .piv_public import storage_key
        import uuid as _uuid

        target, target_role = make_user("issuance_bind", verified=True)
        target.real_name = "原实名用户"
        target.real_name_verified_at = timezone.now()
        target.advanced_verified_at = timezone.now()
        target.save()
        tk, _ = add_key(target)
        add_key(target)
        client = APIClient()
        authenticate(client, target, target_role, key=tk)

        issuance_id = str(_uuid.uuid4())
        priv = self.ec.generate_private_key(self.ec.SECP384R1())
        job = {
            "issuance_id": issuance_id,
            "nonce": "nonce-1",
            "write_nonce": "wn-1",
            "user_id": target.pk,
            "user_version": target.version,
            "real_name": "原实名用户",
            "roles": ["global_reader"],
            "temporary": True,
            "validity_days": 7,
            "delegated_ca": False,
            "state": "requested",
            "expires_at": (timezone.now() + timedelta(minutes=30)).isoformat(),
            "algorithms": ["P-384"],
            "card": self._tpm_card(),
            "authorities": [],
            "roots": [],
        }
        SiteSecuritySetting.objects.create(key=storage_key(issuance_id), value=job)

        csr = self.make_csr({**job, "card": {"slot": "9a"}}, priv.public_key(), self._sign_ec(priv))
        target.real_name = "已改名用户"
        target.save(update_fields=["real_name"])
        self.assertEqual(client.post("/security/issuance-csr/", {
            "issuance_id": issuance_id,
            "csr_pem": csr.public_bytes(self.serialization.Encoding.PEM).decode(),
            "card": self._tpm_card(),
        }, format="json").status_code, 400)

        target.real_name = "原实名用户"
        target.save(update_fields=["real_name"])
        from .piv_public import digest_key
        job.update(
            csr_pem=csr.public_bytes(self.serialization.Encoding.PEM).decode(),
            public_key_sha256=digest_key(priv.public_key()),
        )
        chain = [self.other_sa_cert, self.pki.sub, self.pki.root]
        leaf = self.make_certificate(job, self.other_sa_cert, chain, self._sign_ec(self.other_sa_key))
        chain_pem = [c.public_bytes(self.serialization.Encoding.PEM).decode() for c in [leaf] + chain]
        proof = base64.b64encode(self._sign_ec(priv)(self.write_proof(job, leaf, chain))).decode()
        job.update(state="key_ready", signed_chain_pem=chain_pem)
        SiteSecuritySetting.objects.filter(pk=storage_key(issuance_id)).update(value=job)

        self.assertEqual(client.post("/security/issuance-proof/", {
            "issuance_id": issuance_id, "proof": proof, "card_slot": "9a",
        }, format="json").status_code, 200)
        # Re-submitting target_proof must be rejected instead of overwriting.
        self.assertEqual(client.post("/security/issuance-proof/", {
            "issuance_id": issuance_id, "proof": proof, "card_slot": "9a",
        }, format="json").status_code, 400)
