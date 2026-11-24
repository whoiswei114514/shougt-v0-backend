"""Adversarial regression: read-only boundaries, two keys, and onsite issuance."""
import base64
import hashlib
import json
import tempfile
from datetime import timedelta
from unittest.mock import patch
from django.test import TestCase
from django.core.exceptions import ValidationError
from django.utils import timezone
from rest_framework.exceptions import ValidationError as DRFValidationError
from rest_framework.test import APIClient
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding
from .test_support import make_user, add_key, authenticate, VirtualKey
from .models import AuthSession, ClientCertificateIdentity, SiteSecuritySetting, User, PrivilegedOperation
from . import webauthn
from .security_policy import admin_access_allowed
from . import test_console as console_tests
from backend.policy import Rejected, READ_ACTIONS, SUPER_ACTIONS, COMMON_ACTIONS
from backend.certificates import CertificateVerifier
from backend.piv_cli import make_csr, make_certificate
from backend.piv_crypto import write_proof
from tests.certificates_fixture import PKI


class DualKeyTests(TestCase):
    def setUp(self):
        self.client=APIClient()
        self.user,self.role=make_user('dual',roles=['super_admin'])
        self.first,self.virtual=add_key(self.user)
        self.second,self.other=add_key(self.user)

    def ticket(self):
        options=self.client.post('/security/key-login-begin/',{'username':self.user.username},format='json').data
        response=self.client.post('/security/key-login-finish/',{'challenge_id':options['challenge_id'],'credential':self.virtual.assertion(options)},format='json')
        self.assertEqual(response.status_code,200,response.data)
        self.assertIn('security_key',response.data['methods'])
        return response.data['ticket']

    def finish(self,ticket,virtual=None):
        response=self.client.post('/security/factor-key-begin/',{'ticket':ticket},format='json')
        self.assertEqual(response.status_code,200,response.data)
        options=response.data
        return self.client.post('/security/factor-finish/',{'ticket':ticket,'method':'security_key',
            'challenge_id':options['challenge_id'],'credential':(virtual or self.other).assertion(options)},format='json')

    def test_two_distinct_keys_satisfy_second_factor_and_revocation_invalidates_access(self):
        result=self.finish(self.ticket())
        self.assertEqual(result.status_code,200,result.data)
        session=AuthSession.objects.get(user=self.user)
        self.assertEqual(session.second_credential_id,self.second.pk)
        self.assertTrue(admin_access_allowed(self.user,session))
        self.second.revoked_at=timezone.now();self.second.save()
        session=AuthSession.objects.get(pk=session.pk)
        self.assertFalse(admin_access_allowed(self.user,session))

    def test_first_key_cannot_be_reused_as_second(self):
        self.assertEqual(self.finish(self.ticket(),self.virtual).status_code,400)
        self.assertFalse(AuthSession.objects.filter(user=self.user).exists())

    def test_another_accounts_key_is_rejected(self):
        outsider,_=make_user('outside');_,key=add_key(outsider)
        self.assertEqual(self.finish(self.ticket(),key).status_code,400)

    def test_factor_ticket_cannot_be_replayed(self):
        ticket=self.ticket();self.assertEqual(self.finish(ticket).status_code,200)
        result=self.client.post('/security/factor-key-begin/',{'ticket':ticket},format='json')
        self.assertEqual(result.status_code,401)

    def test_second_key_assertion_cannot_be_moved_to_another_factor_ticket(self):
        first_ticket=self.ticket();other_ticket=self.ticket()
        options=self.client.post('/security/factor-key-begin/',{'ticket':first_ticket},format='json').data
        result=self.client.post('/security/factor-finish/',{'ticket':other_ticket,'method':'security_key',
            'challenge_id':options['challenge_id'],'credential':self.other.assertion(options)},format='json')
        self.assertEqual(result.status_code,401)
        self.assertFalse(AuthSession.objects.filter(user=self.user).exists())

    def test_distinct_credential_ids_with_same_public_key_are_not_two_keys(self):
        from fido2.webauthn import AttestedCredentialData
        self.other.private_key=self.virtual.private_key
        self.other.data=AttestedCredentialData.create(bytes(16),self.other.id,webauthn.credential_data(self.first).public_key)
        self.second.credential_data=webauthn.b64(self.other.data);self.second.save(update_fields=['credential_data'])
        self.assertEqual(self.finish(self.ticket()).status_code,401)
        self.assertFalse(AuthSession.objects.filter(user=self.user).exists())

    def test_revoked_first_key_and_changed_account_version_reject_pending_factor(self):
        ticket=self.ticket();self.first.revoked_at=timezone.now();self.first.save()
        self.assertEqual(self.client.post('/security/factor-key-begin/',{'ticket':ticket},format='json').status_code,403)
        self.first.revoked_at=None;self.first.save();ticket=self.ticket()
        User.objects.filter(pk=self.user.pk).update(version=self.user.version+1)
        self.assertEqual(self.client.post('/security/factor-key-begin/',{'ticket':ticket},format='json').status_code,401)

    def test_registration_finish_enforces_three_key_limit_after_parallel_begins(self):
        one=VirtualKey(self.user);two=VirtualKey(self.user)
        a=webauthn.begin_registration(self.user);b=webauthn.begin_registration(self.user)
        webauthn.finish_registration(self.user,a['challenge_id'],one.registration(a))
        from rest_framework.exceptions import ValidationError as ApiValidationError
        with self.assertRaises(ApiValidationError): webauthn.finish_registration(self.user,b['challenge_id'],two.registration(b))
        self.assertEqual(self.user.security_keys.filter(revoked_at__isnull=True).count(),3)

    def test_ordinary_account_with_multiple_keys_needs_only_one(self):
        normal,_=make_user('normal');key,virtual=add_key(normal);add_key(normal)
        options=self.client.post('/security/key-login-begin/',{'username':normal.username},format='json').data
        result=self.client.post('/security/key-login-finish/',{'challenge_id':options['challenge_id'],'credential':virtual.assertion(options)},format='json')
        self.assertEqual(result.status_code,200,result.data)
        self.assertNotIn('factor_required',result.data)
        self.assertEqual(AuthSession.objects.get(user=normal).credential_id,key.pk)


class ReaderTests(TestCase):
    # Reuse fixture helpers without inheriting and re-running all unrelated tests.
    setUp=console_tests.ConsoleIntegrationTests.setUp
    certificate=console_tests.ConsoleIntegrationTests.certificate;ticket=console_tests.ConsoleIntegrationTests.ticket;login=console_tests.ConsoleIntegrationTests.login
    prepare=console_tests.ConsoleIntegrationTests.prepare;approve=console_tests.ConsoleIntegrationTests.approve;execute=console_tests.ConsoleIntegrationTests.execute
    action=console_tests.ConsoleIntegrationTests.action;switch_actor=console_tests.ConsoleIntegrationTests.switch_actor;target=console_tests.ConsoleIntegrationTests.target

    def test_reader_can_read_super_data_but_every_mutation_is_denied(self):
        target=self.target();self.switch_actor('global_reader')
        self.assertTrue(self.service.info(self.token,self.cert)['read_only'])
        for action,payload in [('list_users',{}),('user_detail',{'user_id':target.pk}),('password_hash',{'user_id':target.pk}),
                               ('list_logs',{}),('list_verifications',{}),('get_contact',{}),('list_certificates',{'user_id':target.pk})]:
            self.action(action,payload)
        for action in (SUPER_ACTIONS|COMMON_ACTIONS|{'issuance_begin','issuance_key','issuance_finish','bind_certificate'})-READ_ACTIONS:
            with self.subTest(action=action),self.assertRaises(Rejected): self.prepare(action,{'user_id':target.pk})
        self.actor.refresh_from_db();self.assertTrue(self.actor.is_staff);self.assertFalse(self.actor.is_superuser)

    def test_reader_main_api_rejects_mutation_and_django_is_view_only(self):
        self.switch_actor('global_reader')
        self.assertEqual(self.api.get('/admin/post/').status_code,200)
        self.assertEqual(self.api.post('/security/privacy/',{'show_real_name':True},format='json').status_code,403)
        self.assertEqual(self.api.post('/post/',{'content':'forbidden'},format='json').status_code,403)
        self.actor._security_session=self.session
        self.assertTrue(self.actor.has_perm('gt_auth.view_user'))
        self.assertFalse(self.actor.has_perm('gt_auth.change_user'))
        result=self.api.post('/security/django-admin/',{},format='json');self.assertEqual(result.status_code,200,result.data)
        self.assertEqual(self.api.get('/django-admin/').status_code,200)
        self.assertEqual(self.api.post('/django-admin/gt_forum/post/',{'action':'delete_selected'},format='json').status_code,403)

    def test_reader_cannot_approve_injected_mutation(self):
        self.switch_actor('global_reader');operation=self.prepare('list_users')
        row=PrivilegedOperation.objects.get(pk=operation['operation_id']);row.action='set_contact'
        from backend.audit import canonical
        row.digest=hashlib.sha256(canonical({'action':row.action,'payload':row.payload}).encode()).hexdigest();row.save()
        self.assertEqual(self.api.post(f'/security/operation/{row.pk}/begin/',{},format='json').status_code,403)

    def test_reader_is_exclusive_and_cannot_be_granted_via_raw_assignment(self):
        target=self.target()
        with self.assertRaises(Rejected):self.action('assign_roles',{'user_id':target.pk,'roles':['global_reader']})
        target.permission.global_reader=True
        with self.assertRaises(ValidationError):target.permission.save()

    def test_existing_ca_test_certificates_can_never_write_even_as_super_admin(self):
        self.cert['local_preview_ca']=True
        self.assertTrue(self.service.info(self.token,self.cert)['read_only'])
        self.action('list_logs')
        with self.assertRaises(Rejected):self.prepare('set_contact',{'contact':'changed'})
        self.cert.pop('local_preview_ca')
        self.config.tls={'issuer_test_clients':[{'sha256':self.cert['fingerprint'],'user_id':self.actor.pk,
            'account_name':self.actor.real_name,'expires_at':(timezone.now()+timedelta(days=1)).isoformat()}]}
        with self.assertRaises(Rejected):self.prepare('assign_roles')

    def test_reader_can_use_browse_access_window_and_still_cannot_mutate(self):
        target=self.target();self.switch_actor('global_reader')
        grant=self.action('browse_access',{'window_minutes':3})
        self.assertIn('browse_until',grant)
        for action,payload in [('list_users',{'search':''}),('user_detail',{'user_id':target.pk}),
                               ('list_logs',{}),('list_verifications',{}),('get_contact',{}),
                               ('list_certificates',{'user_id':target.pk})]:
            self.service.browse(self.token,self.cert,self.csrf,action,payload)
        for forbidden,payload in [('password_hash',{'user_id':target.pk}),('assign_roles',{'user_id':target.pk,'roles':['admin_user']}),
                                  ('update_user',{'user_id':target.pk,'updates':{'real_name':'Blocked'}})]:
            with self.assertRaises(Rejected):self.service.browse(self.token,self.cert,self.csrf,forbidden,payload)


class IssuanceTests(ReaderTests):
    # Hide inherited reader tests here; they run once in ReaderTests.
    test_reader_can_read_super_data_but_every_mutation_is_denied=None
    test_reader_main_api_rejects_mutation_and_django_is_view_only=None
    test_reader_cannot_approve_injected_mutation=None
    test_reader_is_exclusive_and_cannot_be_granted_via_raw_assignment=None
    test_existing_ca_test_certificates_can_never_write_even_as_super_admin=None
    test_reader_can_use_browse_access_window_and_still_cannot_mutate=None

    def setUp(self):
        super().setUp()
        self.temp=tempfile.TemporaryDirectory(prefix='shou-issuance-');self.addCleanup(self.temp.cleanup)
        self.pki=PKI(self.temp.name)
        self.service.verifier=CertificateVerifier(self.pki.config)
        self.recipient=self.target()

    def request(self,algorithm='P-384',slot='9a',transport='nfc',protocol='T=1',platform=None):
        job=self.action('issuance_begin',{'user_id':self.recipient.pk,'roles':['global_reader']})['job']
        key=rsa.generate_private_key(public_exponent=65537,key_size=int(algorithm.split('-')[1])) if algorithm.startswith('RSA-') else ec.generate_private_key(ec.SECP384R1())
        sign=lambda data:key.sign(data,padding.PKCS1v15(),hashes.SHA384()) if algorithm.startswith('RSA-') else key.sign(data,ec.ECDSA(hashes.SHA384()))
        csr=make_csr({**job,'card':{'slot':slot}},key.public_key(),sign)
        payload={'issuance_id':job['issuance_id'],'csr_pem':csr.public_bytes(serialization.Encoding.PEM).decode(),
                 'card':{'slot':slot,'algorithm':algorithm,'transport':transport,'protocol':protocol,'on_card_generation':True}}
        if platform is not None:
            payload['card']['platform']=platform
        return job,key,sign,payload

    def receipt(self,algorithm='P-384',**options):
        job,key,sign,payload=self.request(algorithm,**options)
        job=self.action('issuance_key',payload)['job']
        ca,ca_key=(self.pki.rsa_sub,self.pki.rsa_sub_key) if algorithm.startswith('RSA-') else (self.pki.sub,self.pki.sub_key)
        chain=[ca,self.pki.root]
        ca_sign=lambda data:ca_key.sign(data,padding.PKCS1v15(),hashes.SHA384()) if algorithm.startswith('RSA-') else ca_key.sign(data,ec.ECDSA(hashes.SHA384()))
        certificate=make_certificate(job,ca,chain,ca_sign)
        receipt={'issuance_id':job['issuance_id'],'chain_pem':[c.public_bytes(serialization.Encoding.PEM).decode() for c in [certificate]+chain],
                 'proof':base64.b64encode(sign(write_proof(job,certificate,chain))).decode(),'readback_verified':True,'onsite_confirmed':True}
        return job,receipt

    def test_complete_p384_ceremony_registers_certificate_grants_reader_and_prevents_replay(self):
        job,receipt=self.receipt();result=self.action('issuance_finish',receipt)
        self.assertEqual(result['job']['state'],'complete')
        self.recipient.refresh_from_db();self.recipient.permission.refresh_from_db()
        self.assertTrue(self.recipient.permission.global_reader);self.assertFalse(self.recipient.is_superuser)
        self.assertTrue(ClientCertificateIdentity.objects.filter(user=self.recipient).exists())
        with self.assertRaises(Rejected):self.action('issuance_finish',receipt)

    def test_complete_rsa3072_ceremony(self):
        _,receipt=self.receipt('RSA-3072');self.assertEqual(self.action('issuance_finish',receipt)['job']['state'],'complete')

    def test_rsa2048_javacard_and_alternative_slot_complete_ceremony(self):
        _,receipt=self.receipt('RSA-2048',slot='9c',transport='usb')
        self.assertEqual(self.action('issuance_finish',receipt)['job']['card']['slot'],'9c')

    def test_isodep_piv_card_completes_ceremony(self):
        _,receipt=self.receipt(protocol='ISO-DEP')
        self.assertEqual(self.action('issuance_finish',receipt)['job']['state'],'complete')

    def test_browser_webusb_card_completes_ceremony(self):
        _,receipt=self.receipt(slot='9c',transport='usb',protocol='WebUSB',platform='browser')
        self.assertEqual(self.action('issuance_finish',receipt)['job']['card']['protocol'],'WebUSB')

    def test_webusb_requires_usb_transport_and_browser_metadata(self):
        _,_,_,payload=self.request(transport='usb',protocol='WebUSB')
        with self.assertRaises(Rejected):self.action('issuance_key',payload)
        self.service.cancel(self.token,self.cert,self.csrf,self.pending_id())
        payload['card'].update(platform='browser',transport='nfc')
        with self.assertRaises(Rejected):self.action('issuance_key',payload)

    def test_changed_slot_and_invalid_isodep_transport_are_rejected(self):
        _,_,_,payload=self.request()
        payload['card']['slot']='9c'
        with self.assertRaises(Rejected):self.action('issuance_key',payload)
        self.service.cancel(self.token,self.cert,self.csrf,self.pending_id())
        payload['card'].update(slot='9a',transport='usb',protocol='ISO-DEP')
        with self.assertRaises(Rejected):self.action('issuance_key',payload)

    def test_installation_proof_cannot_be_moved_to_another_slot(self):
        _,receipt=self.receipt(slot='9c');receipt['card_slot']='9a'
        with self.assertRaises(Rejected):self.action('issuance_finish',receipt)
        self.assertFalse(ClientCertificateIdentity.objects.filter(user=self.recipient).exists())

    def test_wrong_csr_task_binding_and_missing_card_confirmation_rejected(self):
        job,key,sign,payload=self.request();payload['card']['on_card_generation']=False
        with self.assertRaises(Rejected):self.action('issuance_key',payload)
        self.service.cancel(self.token,self.cert,self.csrf,self.pending_id())
        payload['card']['on_card_generation']=True
        job['nonce']='tampered';payload['csr_pem']=make_csr(job,key.public_key(),sign).public_bytes(serialization.Encoding.PEM).decode()
        with self.assertRaises(Rejected):self.action('issuance_key',payload)

    def pending_id(self):
        return str(PrivilegedOperation.objects.filter(executed_at__isnull=True).latest('expires_at').pk)

    def test_tampered_installation_proof_does_not_grant_or_bind(self):
        job,receipt=self.receipt();receipt['proof']=base64.b64encode(b'wrong').decode()
        with self.assertRaises(Rejected):self.action('issuance_finish',receipt)
        self.assertFalse(ClientCertificateIdentity.objects.filter(user=self.recipient).exists())
        self.recipient.permission.refresh_from_db();self.assertFalse(self.recipient.permission.global_reader)

    def test_account_change_expires_inflight_issuance(self):
        job,receipt=self.receipt();User.objects.filter(pk=self.recipient.pk).update(version=self.recipient.version+1)
        with self.assertRaises(Rejected):self.action('issuance_finish',receipt)

    def test_missing_writeback_confirmation_or_chain_is_rejected(self):
        job,receipt=self.receipt();receipt['readback_verified']=False
        with self.assertRaises(Rejected):self.action('issuance_finish',receipt)
        self.service.cancel(self.token,self.cert,self.csrf,self.pending_id())
        receipt['readback_verified']=True;receipt['chain_pem']=receipt['chain_pem'][:1]
        with self.assertRaises(Rejected):self.action('issuance_finish',receipt)

    def test_reader_protocol_allows_self_issuance_cancel_and_rejects_arbitrary_writes(self):
        from .read_only import reader_protocol_allowed
        self.assertTrue(reader_protocol_allowed('/security/self-issuance-cancel/'))
        self.assertTrue(reader_protocol_allowed('/api/security/self-issuance-cancel/'))
        self.assertFalse(reader_protocol_allowed('/security/issuance-sign-submit/'))
        self.assertFalse(reader_protocol_allowed('/admin/user/'))

    def test_piv_public_csr_chain_cap_pathlen_and_temp_privilege_enforcement(self):
        import uuid
        from cryptography import x509
        from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
        from .piv_public import validate_target_csr, validate_signed_chain, BINDING_OID, canonical, card_binding, digest_key
        from .models import Permission
        from tests.certificates_fixture import issue

        sub_pem = self.pki.sub.public_bytes(serialization.Encoding.PEM).decode()
        root_pem = self.pki.root.public_bytes(serialization.Encoding.PEM).decode()
        job = {
            'issuance_id': str(uuid.uuid4()),
            'user_id': self.recipient.pk,
            'user_version': self.recipient.version,
            'real_name': self.recipient.real_name,
            'roles': ['global_reader'],
            'temporary': True,
            'validity_days': 5,
            'delegated_ca': False,
            'delegated_authorities': [],
            'nonce': 'n1',
            'write_nonce': 'w1',
            'algorithms': ['P-384', 'RSA-2048', 'RSA-3072'],
            'authorities': [sub_pem],
            'roots': [root_pem],
            'format_version': 2,
        }
        key = ec.generate_private_key(ec.SECP384R1())
        sign = lambda d: key.sign(d, ec.ECDSA(hashes.SHA384()))
        csr = make_csr({**job, 'card': {'slot': '9a'}}, key.public_key(), sign)
        csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode()
        ok_card = {'slot': '9a', 'algorithm': 'P-384', 'transport': 'usb', 'protocol': 'T=1', 'on_card_generation': True}

        # Reject soft/.p12 provider metadata, oversized reader name, blank target real_name, and pending target_csr key reuse
        with self.assertRaises(DRFValidationError):
            validate_target_csr(job, csr_pem, {**ok_card, 'provider': 'export.p12'}, [])
        with self.assertRaises(DRFValidationError):
            validate_target_csr(job, csr_pem, {**ok_card, 'reader': 'R' * 300}, [])
        with self.assertRaises(DRFValidationError):
            validate_target_csr({**job, 'real_name': '   '}, csr_pem, ok_card, [])
        other_job = {'issuance_id': str(uuid.uuid4()), 'target_csr': {'csr_pem': csr_pem}}
        with self.assertRaises(DRFValidationError):
            validate_target_csr(job, csr_pem, ok_card, [other_job])

        # Own job entry is skipped cleanly
        job['public_key_sha256'] = validate_target_csr(job, csr_pem, ok_card, [job])
        job['csr_pem'] = csr_pem
        job['card'] = ok_card

        # Reject temporary cert exceeding job.validity_days even when < 37 days
        now = timezone.now()
        binding_ext = canonical({**card_binding(job), 'write_nonce': job['write_nonce']})
        excessive_cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, job['real_name'])]))
            .issuer_name(self.pki.sub.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=5))
            .not_valid_after(now + timedelta(days=10))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=False, data_encipherment=False, key_agreement=False, key_cert_sign=False, crl_sign=False, encipher_only=False, decipher_only=False), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
            .add_extension(x509.UnrecognizedExtension(BINDING_OID, binding_ext), critical=False)
            .sign(self.pki.sub_key, hashes.SHA384())
        )
        excessive_chain = [c.public_bytes(serialization.Encoding.PEM).decode() for c in (excessive_cert, self.pki.sub, self.pki.root)]
        with self.assertRaises(DRFValidationError):
            validate_signed_chain(job, excessive_chain, self.pki.config, requester_user=self.recipient)

        # Reject temporary privileged user receiving cert exceeding privileged_expires_at or permanent cert
        ok_cert = make_certificate(job, self.pki.sub, [self.pki.sub, self.pki.root],
                                   lambda d: self.pki.sub_key.sign(d, ec.ECDSA(hashes.SHA384())))
        ok_chain = [c.public_bytes(serialization.Encoding.PEM).decode() for c in (ok_cert, self.pki.sub, self.pki.root)]
        Permission.objects.filter(pk=self.recipient.permission_id).update(privileged_expires_at=timezone.now() + timedelta(days=2))
        self.recipient.refresh_from_db()
        with self.assertRaises(DRFValidationError):
            validate_signed_chain(job, ok_chain, self.pki.config, requester_user=self.recipient)
        Permission.objects.filter(pk=self.recipient.permission_id).update(privileged_expires_at=None)
        self.recipient.refresh_from_db()
        leaf, _, kind, _ = validate_signed_chain(job, ok_chain, self.pki.config, requester_user=self.recipient)
        self.assertEqual(kind, 'ca_card')

        # Reject CRL-revoked intermediate CA across chain
        self.pki.write_crls(sub_revoked=True)
        with self.assertRaises(DRFValidationError):
            validate_signed_chain(job, ok_chain, self.pki.config, requester_user=self.recipient)
        self.pki.write_crls(sub_revoked=False)

        # Reject delegated_ca signed by pathLen=0 subCA
        sub0_key, sub0 = issue('ZeroSub', issuer=self.pki.root, issuer_key=self.pki.root_key, ca=True, path_length=0,
                               key=ec.generate_private_key(ec.SECP384R1()))
        sub0_pem = sub0.public_bytes(serialization.Encoding.PEM).decode()
        deleg_job = {
            **job,
            'issuance_id': str(uuid.uuid4()),
            'roles': ['super_admin'],
            'temporary': False,
            'validity_days': None,
            'delegated_ca': True,
            'authorities': [sub0_pem],
        }
        d_key = ec.generate_private_key(ec.SECP384R1())
        d_csr = make_csr({**deleg_job, 'card': {'slot': '9a'}}, d_key.public_key(), lambda d: d_key.sign(d, ec.ECDSA(hashes.SHA384())))
        deleg_job['csr_pem'] = d_csr.public_bytes(serialization.Encoding.PEM).decode()
        deleg_job['public_key_sha256'] = digest_key(d_key.public_key())
        deleg_cert = make_certificate(deleg_job, sub0, [sub0, self.pki.root], lambda d: sub0_key.sign(d, ec.ECDSA(hashes.SHA384())))
        deleg_chain = [c.public_bytes(serialization.Encoding.PEM).decode() for c in (deleg_cert, sub0, self.pki.root)]
        sub0_path = self.pki.path / 'sub0.pem'
        sub0_path.write_text(sub0_pem, encoding='utf-8')
        local_cfg = {**self.pki.config, 'local_ca_only': True, 'allowed_subcas': [str(sub0_path)]}
        with self.assertRaises(DRFValidationError):
            validate_signed_chain(deleg_job, deleg_chain, local_cfg, requester_user=self.recipient)
