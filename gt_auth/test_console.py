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
