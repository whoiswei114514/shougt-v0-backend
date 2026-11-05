import base64
import hashlib
import hmac
import json
import re
from datetime import timedelta
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

    def test_unattested_attachment_claim_cannot_enroll_as_admin_key(self):
        user,_=make_user('root',roles=['super_admin']);virtual=VirtualKey(user)
        options=webauthn.begin_registration(user,kind='security_key')
        with self.assertRaises(ValidationError):webauthn.finish_registration(user,options['challenge_id'],virtual.registration(options,attestation=False))

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
        user,role=make_user("root",roles=["super_admin"]);key,virtual=add_key(user)
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
        user,role=make_user("users",roles=["admin_user"]);key,_=add_key(user);authenticate(self.client,user,role,key=key)
        response=self.client.put(f'/admin/user/{self.user.pk}/?type=permission',{"admin_forum":True},format="json")
        self.assertEqual(response.status_code,400,response.data)
        response=self.client.put(f'/admin/user/{self.user.pk}/?type=permission',{"no_review":True},format="json")
        self.assertEqual(response.status_code,200,response.data)
        before=AuthSession.objects.count();detail=self.client.get(f'/admin/user/{self.user.pk}/')
        self.assertIsNone(detail.data['authorization']);self.assertEqual(AuthSession.objects.count(),before)
        self.assertEqual(self.client.post('/security/console-begin/').status_code,403)

    def test_protected_accounts_cannot_be_modified_by_user_admin(self):
        actor,role=make_user("users",roles=["admin_user"]);key,_=add_key(actor);authenticate(self.client,actor,role,key=key)
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
        actor,role=make_user('root',roles=['super_admin']);key,_=add_key(actor)
        session,_=authenticate(self.client,actor,role,key=key)
        self.client.force_login(actor)
        browser_session=self.client.session;browser_session['shou_security_session']=str(session.pk);browser_session.save()
        path=f'/django-admin/gt_auth/user/{self.user.pk}/change/'
        response=self.client.get(path)
        self.assertEqual(response.status_code,200)
        self.assertNotContains(response,self.user.password)
        self.assertNotContains(response,'name="_save"')
        self.assertContains(response,'shou-watermark')
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
        actor,actor_role=make_user('root',roles=['super_admin']);key,_=add_key(actor)
        parent=create_session(actor,['fido2','password'],credential=key)
        child,_=authenticate(self.client,self.user,self.role,methods=['impersonation'],scope='impersonation')
        child.parent_session=parent;child.impersonator_id=actor.pk;child.save()
        self.assertEqual(self.client.get('/user/info/').status_code,200)
        self.assertEqual(self.client.post('/security/key-register-begin/',{'password':PASSWORD},format='json').status_code,403)
        self.assertEqual(self.client.post('/user/setting/password/',{'old_password':PASSWORD,'new_password':PASSWORD},format='json').status_code,403)
        self.assertTrue(AdminAuditLog.objects.filter(actor_id=actor.pk,action__startswith='impersonation:').exists())
        parent.revoked_at=timezone.now();parent.save()
        self.assertEqual(self.client.get('/user/info/').status_code,401)
