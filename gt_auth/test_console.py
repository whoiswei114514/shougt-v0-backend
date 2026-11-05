import hashlib
import json
import secrets
import sys
import tempfile
from contextlib import contextmanager
from datetime import datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

from django.core.cache import cache
from django.conf import settings
from django.db import connection, transaction
from django.test import TestCase, override_settings
from django.utils import timezone
from rest_framework.test import APIClient

sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'shougt-sa'))
from backend.db import Connection
from backend.service import Service,IdentityMismatch
from backend.policy import Rejected
from gt_admin.models import AdminAuditLog
from .models import ConsoleTicket,ClientCertificateIdentity,PrivilegedOperation,User,AuthSession,ConsoleSession
from .test_support import make_user,add_key,authenticate


class DjangoTestDatabase:
    @contextmanager
    def transaction(self):
        security_error=None
        with transaction.atomic():
            try:
                yield Connection(connection.connection,'sqlite')
            except IdentityMismatch as exc:
                security_error=exc
        if security_error:raise security_error


class ConsoleIntegrationTests(TestCase):
    def setUp(self):
        cache.clear();self.api=APIClient()
        self.actor,self.role=make_user('root',roles=['super_admin'])
        self.key,self.virtual=add_key(self.actor)
        self.session,_=authenticate(self.api,self.actor,self.role,key=self.key)
        self.config=SimpleNamespace(database={},tls={},origin='https://privileged.localhost:18443',main_origin='http://localhost:15173',session_minutes=30,mismatch_suspension_hours=24)
        self.service=Service(self.config,database=DjangoTestDatabase(),verifier=object())
        self.cert=self.certificate(self.actor,'a')
        self.login()

    def certificate(self,user,seed):
        fingerprint=hashlib.sha256(seed.encode()).hexdigest()
        result={'fingerprint':fingerprint,'issuer_fingerprint':'b'*64,'serial_number':str(user.pk),'real_name':user.real_name,'expires_at':timezone.now()+timedelta(days=1)}
        ClientCertificateIdentity.objects.create(user=user,**result)
        return result

    def ticket(self):
        token=secrets.token_urlsafe(32)
        ConsoleTicket.objects.create(token_hash=hashlib.sha256(token.encode()).hexdigest(),session=self.session,expires_at=timezone.now()+timedelta(minutes=2))
        return token

    def login(self):
        data=self.service.login(self.ticket(),self.cert)
        self.token,self.csrf=data['session_token'],data['csrf']

    def prepare(self,action,payload=None):
        return self.service.prepare(self.token,self.cert,self.csrf,action,payload or {})

    def approve(self,operation,key=None):
        prefix=f"/security/operation/{operation['operation_id']}/"
        response=self.api.post(prefix+'begin/',{},format='json')
        self.assertEqual(response.status_code,200,response.data)
        options=response.data
        result=self.api.post(prefix+'finish/',{'challenge_id':options['challenge_id'],'credential':(key or self.virtual).assertion(options)},format='json')
        self.assertEqual(result.status_code,200,result.data)

    def execute(self,operation):
        return self.service.execute(self.token,self.cert,self.csrf,operation['operation_id'])

    def action(self,action,payload=None):
        operation=self.prepare(action,payload);self.approve(operation);return self.execute(operation)

    def switch_actor(self,role_name):
        self.actor,self.role=make_user('actor'+role_name,roles=[role_name]);self.key,self.virtual=add_key(self.actor)
        self.session,_=authenticate(self.api,self.actor,self.role,key=self.key);self.cert=self.certificate(self.actor,role_name);self.login()

    def target(self,roles=('base_admin',)):
        user,role=make_user('target',roles=roles);add_key(user);return user

    def test_ticket_is_single_use(self):
        token=self.ticket();self.service.login(token,self.cert)
        with self.assertRaises(Rejected):self.service.login(token,self.cert)

    def test_local_ca_alias_binds_exact_account_and_expires(self):
        ca = dict(self.cert, real_name='SHOUGT-SubCA', local_preview_ca=True)
        self.config.tls = {'local_ca_only':True, 'local_ca_client':{
            'sha256':ca['fingerprint'], 'user_id':self.actor.pk, 'account_name':self.actor.real_name,
            'expires_at':(timezone.now()+timedelta(days=1)).isoformat()}}
        self.service.login(self.ticket(),ca)
        self.config.tls['local_ca_client']['expires_at']=(timezone.now()-timedelta(seconds=1)).isoformat()
        with self.assertRaises(IdentityMismatch): self.service.login(self.ticket(),ca)

    def test_verified_fips_metadata_snapshot_controls_console_second_factor(self):
        from . import webauthn
        self.session.methods=['fido2'];self.session.save()
        with self.assertRaises(Rejected):self.login()
        trust=[dict(item,assurance='fips140-2-level2',certification_reference='LOCAL TEST ONLY') for item in settings.FIDO_ATTESTATION_TRUST]
        with override_settings(FIDO_ATTESTATION_TRUST=trust):
            options=webauthn.begin_assertion('reauth',user=self.actor,keys=[self.key])
            webauthn.finish_assertion(options['challenge_id'],'reauth',self.virtual.assertion(options))
            self.login()
            self.assertEqual(self.service.info(self.token,self.cert)['user_id'],self.actor.pk)
        options=webauthn.begin_assertion('reauth',user=self.actor,keys=[self.key])
        webauthn.finish_assertion(options['challenge_id'],'reauth',self.virtual.assertion(options))
        with self.assertRaises(Rejected):self.service.info(self.token,self.cert)

    def test_login_identity_mismatch_freezes_both_accounts(self):
        other,_=make_user('other',roles=['base_admin']);cert=self.certificate(other,'other')
        with self.assertRaises(IdentityMismatch):self.service.login(self.ticket(),cert)
        self.actor.refresh_from_db();other.refresh_from_db()
        self.assertGreater(self.actor.admin_suspended_until,timezone.now());self.assertGreater(other.admin_suspended_until,timezone.now())
        self.assertTrue(AdminAuditLog.objects.filter(action='certificate_identity_mismatch').exists())

    def test_operation_requires_fido_and_is_single_use(self):
        operation=self.prepare('list_users')
        with self.assertRaises(Rejected):self.execute(operation)
        self.approve(operation)
        self.assertIn('users',self.execute(operation))
        with self.assertRaises(Rejected):self.execute(operation)

    def test_operation_content_cannot_be_swapped_after_approval(self):
        operation=self.prepare('list_users');self.approve(operation)
        PrivilegedOperation.objects.filter(pk=operation['operation_id']).update(action='list_logs')
        with self.assertRaises(Rejected):self.execute(operation)

    def test_approval_requires_the_original_login_key(self):
        another,virtual=add_key(self.actor)
        operation=self.prepare('list_users');prefix=f"/security/operation/{operation['operation_id']}/"
        options=self.api.post(prefix+'begin/',{},format='json').data
        response=self.api.post(prefix+'finish/',{'challenge_id':options['challenge_id'],'credential':virtual.assertion(options)},format='json')
        self.assertEqual(response.status_code,400,response.data)

    def test_identical_operations_have_distinct_fido_challenges(self):
        first=self.prepare('list_users');prefix=f"/security/operation/{first['operation_id']}/"
        options1=self.api.post(prefix+'begin/',{},format='json').data
        self.service.cancel(self.token,self.cert,self.csrf,first['operation_id'])
        second=self.prepare('list_users');prefix=f"/security/operation/{second['operation_id']}/"
        options2=self.api.post(prefix+'begin/',{},format='json').data
        self.assertNotEqual(options1['publicKey']['challenge'],options2['publicKey']['challenge'])

    def test_csrf_and_session_certificate_binding(self):
        with self.assertRaises(Rejected):self.service.prepare(self.token,self.cert,'bad','list_users',{})
        unbound=dict(self.cert,fingerprint='f'*64)
        with self.assertRaises(Rejected):self.service.info(self.token,unbound)

    def test_privileged_admin_only_manages_ordinary_roles(self):
        target=self.target();self.switch_actor('admin_admin')
        self.action('assign_roles',{'user_id':target.pk,'roles':['admin_user'],'reason':'测试普通岗位任命'})
        target.permission.refresh_from_db();self.assertTrue(target.permission.admin_user)
        with self.assertRaises(Rejected):self.prepare('list_logs')
        with self.assertRaises(Rejected):self.prepare('password_hash',{'user_id':target.pk})
        operation=self.prepare('assign_roles',{'user_id':target.pk,'roles':['super_admin'],'reason':'测试拒绝越权任命'});self.approve(operation)
        with self.assertRaises(Rejected):self.execute(operation)

    def test_superprivileged_admin_can_assign_super_but_not_read_logs(self):
        target=self.target();self.switch_actor('superadmin_admin')
        self.action('assign_roles',{'user_id':target.pk,'roles':['super_admin'],'reason':'测试超级管理员任命'})
        target.refresh_from_db();target.permission.refresh_from_db()
        self.assertTrue(target.permission.super_admin);self.assertTrue(target.is_superuser);self.assertTrue(target.is_staff)
        with self.assertRaises(Rejected):self.prepare('list_logs')

    def test_self_assignment_and_incompatible_roles_are_rejected(self):
        for target_id,roles in [(self.actor.pk,['admin_user'])]:
            operation=self.prepare('assign_roles',{'user_id':target_id,'roles':roles,'reason':'测试禁止自身任命'});self.approve(operation)
            with self.assertRaises(Rejected):self.execute(operation)
        self.service.cancel(self.token,self.cert,self.csrf,operation['operation_id'])
        target=self.target()
        operation=self.prepare('assign_roles',{'user_id':target.pk,'roles':['admin_admin','admin_file'],'reason':'测试互斥岗位拒绝'});self.approve(operation)
        with self.assertRaises(Rejected):self.execute(operation)

    def test_super_admin_can_read_hash_and_salt_without_logging_values(self):
        target=self.target()
        result=self.action('password_hash',{'user_id':target.pk,'reason':'核验密码存储格式'})
        self.assertEqual(result['encoded'],target.password);self.assertIn('salt',result)
        entry=AdminAuditLog.objects.filter(action='password_hash').get()
        self.assertNotIn(target.password,json.dumps(entry.details))

    def test_exemptions_only_apply_to_non_privileged_admins(self):
        target=self.target();self.action('set_exemption',{'user_id':target.pk,'days':2,'reason':'测试短期设备更换'})
        target.refresh_from_db();self.assertGreater(target.security_key_exempt_until,timezone.now())
        self.action('assign_roles',{'user_id':target.pk,'roles':['super_admin'],'reason':'测试强权限安全要求'})
        operation=self.prepare('set_exemption',{'user_id':target.pk,'days':2,'reason':'测试拒绝超管豁免'});self.approve(operation)
        with self.assertRaises(Rejected):self.execute(operation)

    def test_profile_changes_reset_identity_verification(self):
        target=self.target();self.action('update_user',{'user_id':target.pk,'updates':{'real_name':'修改后实名','identity':'教师'},'reason':'测试实名分组调整'})
        target.refresh_from_db();self.assertEqual(target.real_name,'修改后实名');self.assertEqual(target.identity,'教师')
        self.assertIsNone(target.real_name_verified_at);self.assertIsNone(target.advanced_verified_at)

    def test_material_contact_changes_are_public_and_audited(self):
        self.action('set_contact',{'contact':'审核联系 test@shouguatian.com','reason':'测试审核联系方式调整'})
        self.assertEqual(self.api.get('/security/config/').data['material_review_contact'],'审核联系 test@shouguatian.com')
        self.assertTrue(AdminAuditLog.objects.filter(action='set_contact').exists())

    def test_impersonation_is_short_lived_and_tied_to_super_admin(self):
        target=self.target();response=self.action('impersonate',{'user_id':target.pk,'reason':'排查用户界面问题'})
        ticket=response['url'].split('#ticket=')[1]
        result=self.api.post('/security/impersonation-exchange/',{'ticket':ticket},format='json')
        self.assertEqual(result.status_code,200,result.data)
        self.assertEqual(result.data['security']['session_scope'],'impersonation')
        self.assertFalse(result.data['permission']['base_admin'])
        session=AuthSession.objects.get(pk=result.data['authorization']['payload']['session_id'])
        self.assertEqual(session.impersonator_id,self.actor.pk)
        self.assertLessEqual(session.expires_at,timezone.now()+timedelta(minutes=15))
        self.assertLessEqual(datetime.fromisoformat(response['ticket_expires_at']), session.expires_at)
        self.assertEqual(self.api.post('/security/impersonation-exchange/',{'ticket':ticket},format='json').status_code,403)

    def test_impersonation_handoff_cannot_outlive_the_management_session(self):
        deadline = timezone.now() + timedelta(seconds=40)
        ConsoleSession.objects.filter(session=self.session).update(expires_at=deadline)
        target = self.target()
        response = self.action('impersonate', {'user_id':target.pk, 'reason':'检查临近到期的代登录入口'})
        self.assertEqual(datetime.fromisoformat(response['ticket_expires_at']), deadline)
        self.assertEqual(datetime.fromisoformat(response['expires_at']), deadline)
