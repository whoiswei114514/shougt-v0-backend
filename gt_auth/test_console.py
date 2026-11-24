import hashlib
import base64
import json
import secrets
import sys
import tempfile
from contextlib import contextmanager
from datetime import datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

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
from .models import ConsoleTicket,ClientCertificateIdentity,PrivilegedOperation,User,AuthSession,ConsoleSession,WebAuthnCredential
from .test_support import make_user,add_key,authenticate,VirtualKey
from .webauthn import b64,unb64


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
        add_key(self.actor)
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
        self.actor,self.role=make_user('actor'+role_name,roles=[role_name]);self.key,self.virtual=add_key(self.actor);add_key(self.actor)
        self.session,_=authenticate(self.api,self.actor,self.role,key=self.key);self.cert=self.certificate(self.actor,role_name);self.login()

    def target(self,roles=('base_admin',)):
        user,role=make_user('target',roles=roles);add_key(user);add_key(user);return user

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

    def test_reasonless_operation_still_requires_fido_is_single_use_and_is_audited(self):
        target = self.target()
        operation = self.prepare('nominate', {'user_id': target.pk})
        with self.assertRaises(Rejected):
            self.execute(operation)
        self.approve(operation)
        self.execute(operation)
        target.refresh_from_db()
        self.assertGreater(target.admin_candidate_until, timezone.now())
        entry = AdminAuditLog.objects.get(action='nominate')
        self.assertEqual(entry.actor_id, self.actor.pk)
        self.assertEqual(entry.object_id, str(target.pk))
        self.assertEqual(entry.details['reason'], '')
        self.assertTrue(entry.session_id)
        self.assertTrue(entry.watermark_id)
        self.assertEqual(str(entry.details['operation_id']).replace('-', ''), operation['operation_id'].replace('-', ''))
        with self.assertRaises(Rejected):
            self.execute(operation)

    def test_omitting_reason_does_not_grant_other_privileged_roles_super_actions(self):
        for role in ('admin_admin', 'superadmin_admin'):
            self.switch_actor(role)
            with self.assertRaises(Rejected):
                self.prepare('password_hash', {'user_id': self.actor.pk})

    def test_operation_content_cannot_be_swapped_after_approval(self):
        operation=self.prepare('list_users');self.approve(operation)
        PrivilegedOperation.objects.filter(pk=operation['operation_id']).update(action='list_logs')
        with self.assertRaises(Rejected):self.execute(operation)

    def test_approval_and_console_login_accept_any_bound_external_security_key(self):
        another,virtual=add_key(self.actor)
        operation=self.prepare('list_users');prefix=f"/security/operation/{operation['operation_id']}/"
        options=self.api.post(prefix+'begin/',{},format='json').data
        allowed_ids={bytes(item['id']) if isinstance(item['id'],(bytes,bytearray,memoryview)) else unb64(item['id'])
                     for item in options['publicKey']['allowCredentials']}
        self.assertIn(self.virtual.id,allowed_ids)
        self.assertIn(virtual.id,allowed_ids)
        response=self.api.post(prefix+'finish/',{'challenge_id':options['challenge_id'],'credential':virtual.assertion(options)},format='json')
        self.assertEqual(response.status_code,200,response.data)
        self.assertIn('users',self.execute(operation))
        approved_log=AdminAuditLog.objects.get(action='console_operation_approved')
        self.assertEqual(approved_log.details.get('credential_id'),another.pk)

        cb=self.api.post('/security/console-begin/',{},format='json')
        self.assertEqual(cb.status_code,200,cb.data)
        cf=self.api.post('/security/console-finish/',{'challenge_id':cb.data['challenge_id'],'credential':virtual.assertion(cb.data)},format='json')
        self.assertEqual(cf.status_code,200,cf.data)

    def test_approval_rejects_other_users_revoked_and_non_external_keys(self):
        other,_=make_user('other_key_user',roles=['super_admin'])
        _,other_virtual=add_key(other)
        revoked_key,revoked_virtual=add_key(self.actor)
        revoked_key.revoked_at=timezone.now();revoked_key.save(update_fields=['revoked_at'])
        passkey=VirtualKey(self.actor,backup=True)
        WebAuthnCredential.objects.create(
            user=self.actor,credential_id=b64(passkey.id),credential_data=b64(passkey.data),
            name='备用通行密钥',aaguid=str(passkey.data.aaguid),is_security_key=False,backup_eligible=True,
        )
        operation=self.prepare('list_users');prefix=f"/security/operation/{operation['operation_id']}/"
        options=self.api.post(prefix+'begin/',{},format='json').data
        allowed_ids={bytes(item['id']) if isinstance(item['id'],(bytes,bytearray,memoryview)) else unb64(item['id'])
                     for item in options['publicKey']['allowCredentials']}
        self.assertNotIn(passkey.id,allowed_ids)
        self.assertNotIn(revoked_virtual.id,allowed_ids)
        for bad_virtual in (other_virtual,revoked_virtual,passkey):
            with self.subTest(bad=bad_virtual.id.hex()[:8]):
                resp=self.api.post(prefix+'finish/',{'challenge_id':options['challenge_id'],'credential':bad_virtual.assertion(options)},format='json')
                self.assertEqual(resp.status_code,400,resp.data)
                options=self.api.post(prefix+'begin/',{},format='json').data

    def test_operation_cross_session_returns_clear_403_and_other_user_returns_404(self):
        operation=self.prepare('list_users');prefix=f"/security/operation/{operation['operation_id']}/"
        authenticate(self.api,self.actor,self.role,key=self.key)
        mismatch=self.api.get(prefix)
        self.assertEqual(mismatch.status_code,403,mismatch.data)
        self.assertIn('不一致',str(mismatch.data))
        other,other_role=make_user('other_sa',roles=['super_admin'])
        ok,_=add_key(other);add_key(other)
        authenticate(self.api,other,other_role,key=ok)
        missing=self.api.get(prefix)
        self.assertEqual(missing.status_code,404)

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
        self.action('assign_roles',{'user_id':target.pk,'roles':['admin_user']})
        target.permission.refresh_from_db();self.assertTrue(target.permission.admin_user)
        with self.assertRaises(Rejected):self.prepare('list_logs')
        with self.assertRaises(Rejected):self.prepare('password_hash',{'user_id':target.pk})
        operation=self.prepare('assign_roles',{'user_id':target.pk,'roles':['super_admin'],'reason':'测试拒绝越权任命'});self.approve(operation)
        with self.assertRaises(Rejected):self.execute(operation)

    def test_superprivileged_admin_requires_issuance_to_assign_super_and_cannot_read_logs(self):
        target=self.target();self.switch_actor('superadmin_admin')
        with self.assertRaisesMessage(Rejected, '现场制卡'):
            self.action('assign_roles',{'user_id':target.pk,'roles':['super_admin']})
        target.refresh_from_db();target.permission.refresh_from_db()
        self.assertFalse(target.permission.super_admin);self.assertFalse(target.is_superuser)
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
        result=self.action('password_hash',{'user_id':target.pk})
        self.assertEqual(result['encoded'],target.password);self.assertIn('salt',result)
        entry=AdminAuditLog.objects.filter(action='password_hash').get()
        self.assertNotIn(target.password,json.dumps(entry.details))

    def test_exemptions_only_apply_to_non_privileged_admins(self):
        target=self.target();self.action('set_exemption',{'user_id':target.pk,'days':2})
        target.refresh_from_db();self.assertGreater(target.security_key_exempt_until,timezone.now())
        target.permission.super_admin=True;target.permission.save()
        operation=self.prepare('set_exemption',{'user_id':target.pk,'days':2,'reason':'测试拒绝超管豁免'});self.approve(operation)
        with self.assertRaises(Rejected):self.execute(operation)

    def test_profile_changes_reset_identity_verification(self):
        target=self.target();self.action('update_user',{'user_id':target.pk,'updates':{'real_name':'修改后实名','identity':'教师'}})
        target.refresh_from_db();self.assertEqual(target.real_name,'修改后实名');self.assertEqual(target.identity,'教师')
        self.assertIsNone(target.real_name_verified_at);self.assertIsNone(target.advanced_verified_at)

    def test_material_contact_changes_are_public_and_audited(self):
        self.action('set_contact',{'contact':'审核联系 test@shouguatian.com'})
        self.assertEqual(self.api.get('/security/config/').data['material_review_contact'],'审核联系 test@shouguatian.com')
        self.assertTrue(AdminAuditLog.objects.filter(action='set_contact').exists())

    def test_impersonation_is_short_lived_and_tied_to_super_admin(self):
        target=self.target();response=self.action('impersonate',{'user_id':target.pk})
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

    def watermark_request(self, content=b"isolated watermark evidence"):
        return {"kind":"text", "file_name":"evidence.txt", "byte_count":len(content),
                "file_sha256":hashlib.sha256(content).hexdigest()}

    def watermark_report(self, marker, *, complete=True):
        if complete:
            return {"kind":"text", "text":{"markers":[{"id":marker,"count":1}]}}
        return {"kind":"image", "frequency":{"state":"inconclusive","candidates":[
            {"id":marker,"reliable_bits":65}]}}

    def trace_log(self, actor, marker, **kwargs):
        return AdminAuditLog.objects.create(actor_id=actor.pk, actor_name=actor.username,
            roles=["admin_user"], action="GET /admin/user/", session_id="historical-session",
            watermark_id=marker, details={"private":"not included in attribution"}, **kwargs)

    def inspect_report(self, operation, report, content=b"isolated watermark evidence"):
        with patch("backend.watermark_provenance.analyze_evidence", return_value=report):
            return self.service.inspect_watermark(self.token,self.cert,self.csrf,
                                                  operation["operation_id"],content)

    def test_watermark_trace_matches_original_actor_not_the_inspecting_super_admin(self):
        target=self.target();marker="a1"*12;entry=self.trace_log(target,marker)
        operation=self.prepare("inspect_watermark",self.watermark_request());self.approve(operation)
        result=self.inspect_report(operation,self.watermark_report(marker))
        association=result["association"]
        self.assertEqual(association["status"],"matched")
        found=association["markers"][0]
        self.assertEqual(found["administrators"][0]["user_id"],target.pk)
        self.assertNotEqual(found["administrators"][0]["user_id"],self.actor.pk)
        self.assertEqual(found["logs"][0]["id"],entry.pk)
        self.assertNotIn("private",json.dumps(found,default=str))
        log=AdminAuditLog.objects.get(action="inspect_watermark")
        self.assertEqual(log.actor_id,self.actor.pk)
        self.assertEqual(log.details["file_sha256"],self.watermark_request()["file_sha256"])
        self.assertNotIn("isolated watermark evidence",json.dumps(log.details))

    def test_watermark_file_is_bound_to_approved_digest_and_is_single_use(self):
        operation=self.prepare("inspect_watermark",self.watermark_request())
        with self.assertRaises(Rejected):
            self.service.watermark_upload(self.token,self.cert,self.csrf,operation["operation_id"])
        self.approve(operation)
        with self.assertRaises(Rejected):
            self.service.inspect_watermark(self.token,self.cert,self.csrf,operation["operation_id"],
                b"altered  watermark evidence")
        with self.assertRaises(Rejected):self.execute(operation)
        self.inspect_report(operation,self.watermark_report("a1"*12))
        with self.assertRaises(Rejected):
            self.inspect_report(operation,self.watermark_report("a1"*12))

    def test_watermark_trace_is_super_admin_only(self):
        for role in ("admin_admin","superadmin_admin"):
            self.switch_actor(role)
            with self.assertRaises(Rejected):
                self.prepare("inspect_watermark",self.watermark_request())

    def test_watermark_upload_rechecks_csrf_certificate_and_action(self):
        operation=self.prepare("inspect_watermark",self.watermark_request());self.approve(operation)
        with self.assertRaises(Rejected):
            self.service.watermark_upload(self.token,self.cert,"invalid",operation["operation_id"])
        with self.assertRaises(Rejected):
            self.service.watermark_upload(self.token,dict(self.cert,fingerprint="f"*64),self.csrf,
                                          operation["operation_id"])
        self.service.cancel(self.token,self.cert,self.csrf,operation["operation_id"])
        another=self.prepare("list_users");self.approve(another)
        with self.assertRaises(Rejected):
            self.service.watermark_upload(self.token,self.cert,self.csrf,another["operation_id"])

    def test_watermark_trace_preserves_deleted_account_and_renamed_history(self):
        marker="b2"*12;target=self.target();self.trace_log(target,marker)
        old_name=target.username;User.objects.filter(pk=target.pk).update(username="renamed")
        operation=self.prepare("inspect_watermark",self.watermark_request());self.approve(operation)
        result=self.inspect_report(operation,self.watermark_report(marker))
        actor=result["association"]["markers"][0]["administrators"][0]
        self.assertEqual(actor["username"],"renamed");self.assertEqual(actor["recorded_name"],old_name)
        deleted_marker="c3"*12
        AdminAuditLog.objects.create(actor_id=99999,actor_name="removed-account",watermark_id=deleted_marker,
                                     action="GET /admin/user/")
        operation=self.prepare("inspect_watermark",self.watermark_request());self.approve(operation)
        result=self.inspect_report(operation,self.watermark_report(deleted_marker))
        actor=result["association"]["markers"][0]["administrators"][0]
        self.assertEqual(actor["user_id"],99999);self.assertTrue(actor["account_deleted"])
        self.assertEqual(actor["recorded_name"],"removed-account")

    def test_watermark_unknown_and_conflicting_markers_are_not_assigned_to_current_actor(self):
        unknown=self.prepare("inspect_watermark",self.watermark_request());self.approve(unknown)
        result=self.inspect_report(unknown,self.watermark_report("d4"*12))
        self.assertEqual(result["association"]["status"],"not_found")
        self.assertEqual(result["association"]["markers"][0]["administrators"],[])
        marker="e5"*12;target=self.target();self.trace_log(target,marker);self.trace_log(self.actor,marker)
        operation=self.prepare("inspect_watermark",self.watermark_request());self.approve(operation)
        result=self.inspect_report(operation,self.watermark_report(marker))
        self.assertEqual(result["association"]["status"],"conflict")

    def test_weak_watermark_match_is_only_a_candidate(self):
        target=self.target();marker="f6"*12;self.trace_log(target,marker)
        operation=self.prepare("inspect_watermark",self.watermark_request());self.approve(operation)
        result=self.inspect_report(operation,self.watermark_report(marker,complete=False))
        self.assertEqual(result["association"]["status"],"candidate")

    def test_watermark_decode_does_not_skip_final_session_revocation_check(self):
        operation=self.prepare("inspect_watermark",self.watermark_request());self.approve(operation)
        def revoke(*args):
            ConsoleSession.objects.filter(session=self.session).update(revoked_at=timezone.now())
            return self.watermark_report("a1"*12)
        with patch("backend.watermark_provenance.analyze_evidence",side_effect=revoke):
            with self.assertRaises(Rejected):
                self.service.inspect_watermark(self.token,self.cert,self.csrf,operation["operation_id"],
                                               b"isolated watermark evidence")
        self.assertFalse(AdminAuditLog.objects.filter(action="inspect_watermark").exists())

    def test_watermark_parameters_cannot_accept_forged_administrator_or_payloads(self):
        for changes in ({"actor_id":self.actor.pk},{"kind":[]},{"alignment":[]},
                        {"scale":"nan"},{"file_sha256":"bad"},{"byte_count":True}):
            with self.subTest(changes=changes):
                with self.assertRaises(Rejected):
                    self.prepare("inspect_watermark",{**self.watermark_request(),**changes})

    def signed_frame(self):
        import os
        with patch.dict(os.environ, {"SHOU_ADMIN_WATERMARK_SIGNING_KEY": base64.b64encode(b"k"*32).decode()}):
            return self.service.watermark_frame(self.token, self.cert)

    def test_signed_frame_contains_current_actor_and_exact_latest_operation_time(self):
        self.action("list_users")
        frame = self.signed_frame()
        log = AdminAuditLog.objects.get(action="list_users")
        self.assertEqual(frame["actor_id"], self.actor.pk)
        self.assertEqual(frame["username"], self.actor.username)
        self.assertEqual(frame["audit_id"], log.pk)
        self.assertEqual(int(datetime.fromisoformat(frame["operation_at"]).timestamp()*1000),
                         int(log.created_at.timestamp()*1000))
        self.assertGreaterEqual(frame["issued_at"], frame["operation_at"])
        self.assertNotIn(self.token, json.dumps(frame))
        AuthSession.objects.filter(pk=self.session.pk).update(revoked_at=timezone.now())
        with self.assertRaises(Rejected): self.signed_frame()

    def test_signed_payload_is_verified_against_registered_key_and_exact_audit(self):
        self.action("list_users")
        frame = self.signed_frame()
        bits = "".join(f"{byte:08b}" for byte in base64.b64decode(frame["token"]))
        text = "\u2063\u2063" + bits.replace("0", "\u200b").replace("1", "\u200c") + "\u2063\u2063"
        content = text.encode("utf-8")
        operation = self.prepare("inspect_watermark", self.watermark_request(content)); self.approve(operation)
        result = self.inspect_report(operation, {"kind":"text", "text":{
            "markers":[], "payloads":[{"token":frame["token"]}]}}, content)
        payload = result["association"]["payloads"][0]
        self.assertEqual(payload["signature_status"], "verified")
        self.assertEqual(payload["audit_status"], "matched")
        self.assertEqual(payload["operation"]["action"], "list_users")
        self.assertEqual(result["association"]["status"], "matched")

    def test_signed_frame_endpoint_only_exposes_own_management_session(self):
        self.action("list_users")
        response = self.api.get("/security/watermark/", {"user_id": 99999})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["actor_id"], self.actor.pk)
        user, role = make_user("not_a_manager")
        authenticate(self.api, user, role)
        self.assertEqual(self.api.get("/security/watermark/").status_code, 403)

    def test_watermark_signatures_and_operation_mismatches_do_not_create_verified_attribution(self):
        import struct
        import zlib
        from backend.watermark_provenance import associate
        self.action("list_users")
        frame = self.signed_frame()
        packet = bytearray(base64.b64decode(frame["token"]))
        packet[-20] ^= 1
        packet[-4:] = struct.pack(">I", zlib.crc32(packet[:-4]))
        bad = base64.b64encode(packet).decode()
        with self.service.database.transaction() as db:
            result = associate(db, {"payloads":[{"token":bad,"sources":["lsb_v2"]}]})
        self.assertEqual(result["payloads"][0]["signature_status"], "invalid")
        self.assertEqual(result["markers"], [])
        AdminAuditLog.objects.filter(pk=frame["audit_id"]).update(actor_id=99999)
        with self.service.database.transaction() as db:
            result = associate(db, {"payloads":[{"token":frame["token"],"sources":["frequency_v2"]}]})
        self.assertEqual(result["payloads"][0]["audit_status"], "mismatch")
        self.assertEqual(result["status"], "conflict")

    def test_compact_micro_payload_associates_full_user_and_rejects_mismatches(self):
        from backend import watermark_codec as codec
        from backend.watermark_provenance import associate
        self.action("list_users")
        frame = self.signed_frame()
        micro = codec.decode_micro(base64.b64decode(frame["micro"]))
        self.assertIsNotNone(micro)
        with self.service.database.transaction() as db:
            result = associate(db, {"payloads":[{"token":micro["token"],
                                                 "sources":["frequency_micro","spatial_micro"]}]})
        payload = result["payloads"][0]
        self.assertEqual(payload["signature_status"], "compact")
        self.assertEqual(payload["audit_status"], "matched")
        self.assertEqual(payload["username"], self.actor.username)
        self.assertEqual(payload["real_name"], self.actor.real_name)
        self.assertEqual(payload["operation"]["action"], "list_users")
        self.assertEqual(result["status"], "matched")

        bad_user_b64 = codec.encode_micro(
            {"id": self.actor.pk, "username": "wrong"},
            {"id": frame["audit_id"], "created_at": frame["operation_at"]},
            frame["watermark_id"], "console", int(datetime.fromisoformat(frame["issued_at"]).timestamp()*1000),
        )
        bad_user = codec.decode_micro(base64.b64decode(bad_user_b64))
        with self.service.database.transaction() as db:
            mismatch = associate(db, {"payloads":[{"token":bad_user["token"],"sources":["spatial_micro"]}]})
        self.assertEqual(mismatch["payloads"][0]["audit_status"], "mismatch")
        self.assertEqual(mismatch["status"], "conflict")

        AdminAuditLog.objects.filter(pk=frame["audit_id"]).update(actor_id=99999)
        with self.service.database.transaction() as db:
            conflict = associate(db, {"payloads":[{"token":micro["token"],"sources":["frequency_micro"]}]})
        self.assertEqual(conflict["payloads"][0]["audit_status"], "mismatch")
        self.assertEqual(conflict["status"], "conflict")

    def test_list_users_supports_exact_id_hash_id_and_empty_pagination(self):
        from backend import actions
        u1, _ = make_user('preview_check_7')
        u2, _ = make_user('1_prefix_user')
        u3, _ = make_user('alice_special')
        User.objects.filter(pk=u1.pk).update(student_id='20260001')
        User.objects.filter(pk=u2.pk).update(student_id='20260002')
        User.objects.filter(pk=u3.pk).update(real_name='张特例', student_id='S9988')
        self.action('browse_access', {'window_minutes': 3})

        by_num = self.service.browse(self.token, self.cert, self.csrf, 'list_users', {'search': str(u3.pk)})
        self.assertGreaterEqual(len(by_num['users']), 1)
        self.assertEqual(by_num['users'][0]['id'], u3.pk)

        by_one = self.service.browse(self.token, self.cert, self.csrf, 'list_users', {'search': '1'})
        self.assertEqual(by_one['users'][0]['id'], self.actor.pk)
        returned_ids = [item['id'] for item in by_one['users']]
        self.assertIn(u1.pk, returned_ids)
        self.assertIn(u2.pk, returned_ids)
        self.assertEqual(by_one['total'], len(returned_ids))

        by_student = self.service.browse(self.token, self.cert, self.csrf, 'list_users', {'search': 'S9988'})
        self.assertEqual([item['id'] for item in by_student['users']], [u3.pk])

        exact_only = self.service.browse(self.token, self.cert, self.csrf, 'list_users', {'search': f'#{u3.pk}'})
        self.assertEqual([item['id'] for item in exact_only['users']], [u3.pk])
        self.assertEqual(exact_only['total'], 1)
        self.assertIsNone(exact_only['next_after'])

        with patch.object(actions, 'USER_PAGE_SIZE', 2):
            page1 = self.service.browse(self.token, self.cert, self.csrf, 'list_users', {'search': '', 'after': 0})
            self.assertEqual(len(page1['users']), 2)
            self.assertIsNotNone(page1['next_after'])
            page2 = self.service.browse(self.token, self.cert, self.csrf, 'list_users', {'search': '', 'after': page1['next_after']})
            self.assertEqual(len(page2['users']), 2)
            self.assertIsNone(page2['next_after'])
            self.assertEqual(len({u['id'] for u in page1['users'] + page2['users']}), 4)

            u4, _ = make_user(f'later_{u3.pk}_match')
            User.objects.filter(pk=u2.pk).update(username=f'early_{u3.pk}_match')
            id_page1 = self.service.browse(self.token, self.cert, self.csrf, 'list_users', {'search': str(u3.pk), 'after': 0})
            self.assertEqual([item['id'] for item in id_page1['users']], [u3.pk, u2.pk])
            self.assertEqual(id_page1['next_after'], u2.pk)
            id_page2 = self.service.browse(self.token, self.cert, self.csrf, 'list_users', {'search': str(u3.pk), 'after': id_page1['next_after']})
            self.assertEqual([item['id'] for item in id_page2['users']], [u4.pk])
            self.assertIsNone(id_page2['next_after'])

    def test_browse_requires_fido_grant_allows_multiple_reads_within_three_minutes_and_expires(self):
        target = self.target()
        with self.assertRaises(Rejected) as ctx:
            self.service.browse(self.token, self.cert, self.csrf, 'list_users', {'search': ''})
        self.assertEqual(ctx.exception.code, 'browse_auth_required')

        with self.assertRaises(Rejected):
            self.prepare('browse_access', {'window_minutes': 10})
        with self.assertRaises(Rejected):
            self.prepare('browse_access', {'window_minutes': 3, 'extra': True})

        grant_result = self.action('browse_access', {'window_minutes': 3})
        self.assertEqual(grant_result['window_seconds'], 180)
        self.assertIsNotNone(self.service.info(self.token, self.cert)['browse_until'])

        listed = self.service.browse(self.token, self.cert, self.csrf, 'list_users', {'search': ''})
        detail = self.service.browse(self.token, self.cert, self.csrf, 'user_detail', {'user_id': target.pk})
        certs = self.service.browse(self.token, self.cert, self.csrf, 'list_certificates', {'user_id': target.pk})
        self.assertEqual(detail['user']['id'], target.pk)
        self.assertEqual(certs['certificates'], [])
        self.assertGreaterEqual(len(listed['users']), 2)

        detail_log = AdminAuditLog.objects.filter(action='user_detail', object_id=str(target.pk)).get()
        self.assertIn('browse_grant_id', detail_log.details)

        for disallowed, payload in (
            ('password_hash', {'user_id': target.pk}),
            ('impersonate', {'user_id': target.pk}),
            ('assign_roles', {'user_id': target.pk, 'roles': ['admin_user']}),
            ('update_user', {'user_id': target.pk, 'updates': {'real_name': 'Blocked'}}),
        ):
            with self.subTest(action=disallowed), self.assertRaises(Rejected):
                self.service.browse(self.token, self.cert, self.csrf, disallowed, payload)

        PrivilegedOperation.objects.filter(action='browse_access').update(
            approved_at=timezone.now() - timedelta(seconds=181)
        )
        self.assertIsNone(self.service.info(self.token, self.cert)['browse_until'])
        with self.assertRaises(Rejected) as expired_ctx:
            self.service.browse(self.token, self.cert, self.csrf, 'list_users', {'search': ''})
        self.assertEqual(expired_ctx.exception.code, 'browse_auth_required')

    def test_browse_respects_role_boundaries_for_admin_admin(self):
        target = self.target()
        self.switch_actor('admin_admin')
        self.action('browse_access', {'window_minutes': 3})
        self.assertIn('users', self.service.browse(self.token, self.cert, self.csrf, 'list_users', {'search': ''}))
        for forbidden, payload in (('user_detail', {'user_id': target.pk}), ('list_logs', {}), ('password_hash', {'user_id': target.pk})):
            with self.subTest(action=forbidden), self.assertRaises(Rejected):
                self.service.browse(self.token, self.cert, self.csrf, forbidden, payload)

    def test_admin_user_list_api_searches_by_exact_id_and_hash_id(self):
        u_one, _ = make_user('admin_match_user')
        target, _ = make_user('ordinary_alpha')
        make_user(f'prefix_{target.pk}_user')
        bare = self.api.get('/admin/user/', {'search': str(target.pk)})
        self.assertEqual(bare.status_code, 200, bare.data)
        self.assertEqual(bare.data['results'][0]['id'], target.pk)
        self.assertGreaterEqual(len(bare.data['results']), 2)
        hashed = self.api.get('/admin/user/', {'search': f'#{target.pk}'})
        self.assertEqual(hashed.status_code, 200, hashed.data)
        self.assertEqual([row['id'] for row in hashed.data['results']], [target.pk])
        all_users = self.api.get('/admin/user/')
        self.assertEqual(all_users.status_code, 200)
        self.assertIn(u_one.pk, [row['id'] for row in all_users.data['results']])

    def test_browse_window_invalidated_immediately_by_revocation_version_ban_suspension_and_temp_expiry(self):
        from .models import Permission
        target = self.target()
        self.action('browse_access', {'window_minutes': 3})
        self.assertIsNotNone(self.service.info(self.token, self.cert)['browse_until'])
        self.assertIn('users', self.service.browse(self.token, self.cert, self.csrf, 'list_users', {'search': ''}))

        # 1. Revoking ConsoleSession immediately invalidates browse window
        ConsoleSession.objects.filter(session=self.session).update(revoked_at=timezone.now())
        with self.assertRaises(Rejected):
            self.service.browse(self.token, self.cert, self.csrf, 'list_users', {'search': ''})
        ConsoleSession.objects.filter(session=self.session).update(revoked_at=None)

        # 2. Revoking AuthSession immediately invalidates browse window
        AuthSession.objects.filter(pk=self.session.pk).update(revoked_at=timezone.now())
        with self.assertRaises(Rejected):
            self.service.browse(self.token, self.cert, self.csrf, 'list_users', {'search': ''})
        AuthSession.objects.filter(pk=self.session.pk).update(revoked_at=None)

        # 3. Bumping user.version immediately invalidates browse window
        orig_ver = self.actor.version
        User.objects.filter(pk=self.actor.pk).update(version=orig_ver + 1)
        with self.assertRaises(Rejected):
            self.service.browse(self.token, self.cert, self.csrf, 'list_users', {'search': ''})
        User.objects.filter(pk=self.actor.pk).update(version=orig_ver)

        # 4. Suspending admin_suspended_until immediately invalidates browse window
        User.objects.filter(pk=self.actor.pk).update(admin_suspended_until=timezone.now() + timedelta(hours=2))
        with self.assertRaises(Rejected):
            self.service.browse(self.token, self.cert, self.csrf, 'list_users', {'search': ''})
        User.objects.filter(pk=self.actor.pk).update(admin_suspended_until=None)

        # 5. Temporary ban (banned_until) & deactivation (is_active=False) immediately invalidate
        User.objects.filter(pk=self.actor.pk).update(banned_until=timezone.now() + timedelta(hours=2))
        with self.assertRaises(Rejected):
            self.service.browse(self.token, self.cert, self.csrf, 'list_users', {'search': ''})
        User.objects.filter(pk=self.actor.pk).update(banned_until=None, is_active=False)
        with self.assertRaises(Rejected):
            self.service.browse(self.token, self.cert, self.csrf, 'list_users', {'search': ''})
        User.objects.filter(pk=self.actor.pk).update(is_active=True)

        # 6. Expiring privileged_expires_at immediately invalidates browse window
        Permission.objects.filter(pk=self.actor.permission_id).update(privileged_expires_at=timezone.now() - timedelta(seconds=1))
        with self.assertRaises(Rejected):
            self.service.browse(self.token, self.cert, self.csrf, 'list_users', {'search': ''})
        Permission.objects.filter(pk=self.actor.permission_id).update(privileged_expires_at=None)

        # 7. Tampered browse_access payload (even with matching digest) is ignored
        bad_payload = {'window_minutes': 3, 'extra': True}
        from backend.audit import canonical as sa_canonical
        bad_digest = hashlib.sha256(sa_canonical({'action': 'browse_access', 'payload': bad_payload}).encode()).hexdigest()
        PrivilegedOperation.objects.filter(action='browse_access').update(payload=bad_payload, digest=bad_digest)
        self.assertIsNone(self.service.info(self.token, self.cert)['browse_until'])
        with self.assertRaises(Rejected):
            self.service.browse(self.token, self.cert, self.csrf, 'user_detail', {'user_id': target.pk})

    def test_browse_rbac_pii_minimization_and_rejected_operations(self):
        from backend.policy import ISSUANCE_ACTIONS
        target = self.target()
        User.objects.filter(pk=target.pk).update(mobile='13800138000')
        self.action('browse_access', {'window_minutes': 3})
        listed = self.service.browse(self.token, self.cert, self.csrf, 'list_users', {'search': ''})
        allowed_keys = {'id', 'username', 'real_name', 'student_id', 'roles', 'verified', 'active', 'is_active', 'banned_until'}
        for item in listed['users']:
            self.assertEqual(set(item), allowed_keys)
            for pii in ('email', 'mobile', 'password', 'admin_suspended_until', 'security_key_exempt_until', 'privileged_expires_at'):
                self.assertNotIn(pii, item)
        self.assertNotIn('13800138000', json.dumps(listed))
        self.assertNotIn(target.password, json.dumps(listed))

        # /api/browse strictly rejects non-browse reads, impersonation, writes, and issuance actions
        for blocked in (
            'password_hash', 'impersonate', 'inspect_watermark', 'assign_roles', 'nominate',
            'update_user', 'set_exemption', 'review_verification', 'set_contact',
            'browse_access', 'bind_certificate', *ISSUANCE_ACTIONS,
        ):
            with self.subTest(action=blocked), self.assertRaises(Rejected):
                self.service.browse(self.token, self.cert, self.csrf, blocked, {'user_id': target.pk})

        # Both admin_admin and superadmin_admin cannot inspect user_detail, certificates, logs, verifications, or contact
        for role in ('admin_admin', 'superadmin_admin'):
            self.switch_actor(role)
            self.action('browse_access', {'window_minutes': 3})
            admin_list = self.service.browse(self.token, self.cert, self.csrf, 'list_users', {'search': ''})
            for item in admin_list['users']:
                self.assertEqual(set(item), allowed_keys)
            for forbidden, payload in (
                ('user_detail', {'user_id': target.pk}),
                ('list_certificates', {'user_id': target.pk}),
                ('list_logs', {}),
                ('list_verifications', {}),
                ('get_contact', {}),
            ):
                with self.subTest(role=role, via='prepare', action=forbidden), self.assertRaises(Rejected):
                    self.prepare(forbidden, payload)
                with self.subTest(role=role, via='browse', action=forbidden), self.assertRaises(Rejected):
                    self.service.browse(self.token, self.cert, self.csrf, forbidden, payload)

    def test_impersonate_handoff_django_admin_isolation_and_watermark_details_redaction(self):
        from django.test import RequestFactory
        from .django_admin import SecurityAdminMiddleware
        target = self.target()
        imp_res = self.action('impersonate', {'user_id': target.pk, 'reason': '检查代登录隔离与权限边界'})
        ticket = imp_res['url'].split('#ticket=')[1]
        exchanged = self.api.post('/security/impersonation-exchange/', {'ticket': ticket}, format='json')
        self.assertEqual(exchanged.status_code, 200, exchanged.data)
        auth = exchanged.data['authorization']
        imp_token = base64.urlsafe_b64encode(json.dumps(auth['payload']).encode()).decode() + '.' + auth['signature']
        imp_client = APIClient()
        imp_client.credentials(HTTP_AUTHORIZATION='Bearer ' + imp_token)
        for path, method in (
            ('/security/console-begin/', 'post'),
            ('/security/self-issuance-begin/', 'post'),
            ('/admin/user/', 'get'),
            ('/django-admin/', 'get'),
            ('/user/setting/password/', 'post'),
            ('/user/setting/privacy/', 'post'),
            ('/user/email_sendcode/', 'post'),
        ):
            resp = getattr(imp_client, method)(path, {}, format='json')
            self.assertEqual(resp.status_code, 403, f'{path} unexpectedly returned {resp.status_code}')

        # SecurityAdminMiddleware rejects malformed UUID cleanly (403, no 500) and blocks mutations on gt_auth
        from django.http import HttpResponse
        middleware = SecurityAdminMiddleware(lambda _req: HttpResponse('ok'))
        rf = RequestFactory()
        req_bad_uuid = rf.get('/django-admin/')
        req_bad_uuid.user = self.actor
        req_bad_uuid.session = {'shou_security_session': 'not-a-valid-uuid'}
        self.assertEqual(middleware(req_bad_uuid).status_code, 403)

        req_write_auth = rf.post('/django-admin/gt_auth/user/')
        req_write_auth.user = self.actor
        req_write_auth.session = {'shou_security_session': str(self.session.pk)}
        self.assertEqual(middleware(req_write_auth).status_code, 403)

        # inspect_watermark never leaks raw AdminAuditLog.details private strings or private_key values
        marker = 'b2' * 12
        self.trace_log(target, marker)
        AdminAuditLog.objects.filter(watermark_id=marker).update(details={'private_key': '-----BEGIN PRIVATE KEY-----SECRET', 'raw_token': 'AUDIT_SECRET_LEAK'})
        op = self.prepare('inspect_watermark', self.watermark_request())
        self.approve(op)
        wm_res = self.inspect_report(op, self.watermark_report(marker))
        serialized_wm = json.dumps(wm_res, default=str)
        self.assertNotIn('AUDIT_SECRET_LEAK', serialized_wm)
        self.assertNotIn('BEGIN PRIVATE KEY', serialized_wm)
        self.assertNotIn('private_key', serialized_wm)

        # OperationViewset.finish fails if ConsoleSession is revoked before approval completes
        op2 = self.prepare('list_users')
        prefix = f"/security/operation/{op2['operation_id']}/"
        opts = self.api.post(prefix + 'begin/', {}, format='json').data
        ConsoleSession.objects.filter(session=self.session).update(revoked_at=timezone.now())
        fin = self.api.post(prefix + 'finish/', {'challenge_id': opts['challenge_id'], 'credential': self.virtual.assertion(opts)}, format='json')
        self.assertEqual(fin.status_code, 400, fin.data)
