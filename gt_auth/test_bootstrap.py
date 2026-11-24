"""Integration tests of the separate app's local-only initialization contract."""
import sys
import tempfile
from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace

from django.core.cache import cache
from django.test import TestCase
from django.utils import timezone
from rest_framework.test import APIClient

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'shougt-sa'))
from backend.cli import initialize
from backend.certificates import CertificateVerifier
from backend.policy import Rejected
from tests.certificates_fixture import PKI

from gt_admin.audit import record
from gt_admin.models import AdminAuditLog
from .advanced_views import accept_verified_mail
from .models import AdvancedVerification, ClientCertificateIdentity, SiteSecuritySetting
from .test_console import DjangoTestDatabase
from .test_support import make_user, add_key, authenticate


class BootstrapTests(TestCase):
    def setUp(self):
        cache.clear()
        self.api=APIClient()
        self.user,self.role=make_user('initial')
        self.user.admin_candidate_until=timezone.now()+timedelta(days=1);self.user.save()
        self.key,self.virtual=add_key(self.user)
        add_key(self.user)
        self.temp=tempfile.TemporaryDirectory(prefix='shou-bootstrap-');self.addCleanup(self.temp.cleanup)
        self.pki=PKI(self.temp.name,client_name=self.user.real_name)
        self.config=SimpleNamespace(database={},tls=self.pki.config)

    def pending_verification(self, *, receive=True):
        authenticate(self.api,self.user,self.role,key=self.key)
        options=self.api.post('/security/advanced/begin/',{'real_name':self.user.real_name},format='json').data
        signed=self.api.post('/security/advanced/finish/',{'challenge_id':options['challenge_id'],'credential':self.virtual.assertion(options)},format='json')
        self.assertEqual(signed.status_code,200,signed.data)
        if receive:
            accept_verified_mail({'recipient':'renzheng@shouguatian.com','authenticated_sender':self.user.email,
                                  'from_header':f'{self.user.real_name} <{self.user.email}>','dmarc_pass':True,
                                  'received_at':timezone.now().isoformat(),'body':signed.data['body']})
        return signed.data['id']

    def run_bootstrap(self, verification, command='bootstrap-first', **kwargs):
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        from backend.piv_cli import make_csr, make_certificate
        from backend.piv_crypto import write_proof
        import base64
        common=dict(database=DjangoTestDatabase(),verifier=CertificateVerifier(self.pki.config))
        reason='已当面核验首次管理身份材料'
        job=initialize(self.config,command,self.user.username,reason,verification_id=verification,
                       real_name_reviewed=True,prepare=True,**common)['job']
        key=ec.generate_private_key(ec.SECP384R1())
        sign=lambda message:key.sign(message,ec.ECDSA(hashes.SHA384()))
        csr=make_csr(job,key.public_key(),sign)
        result={'issuance_id':job['issuance_id'],'csr_pem':csr.public_bytes(serialization.Encoding.PEM).decode(),
                'card':{'slot':'9a','algorithm':'P-384','transport':'contact','protocol':'T=1','on_card_generation':True}}
        job=initialize(self.config,command,self.user.username,reason,key_result=result,**common)['job']
        chain=[self.pki.sub,self.pki.root]
        cert=make_certificate(job,self.pki.sub,chain,lambda message:self.pki.sub_key.sign(message,ec.ECDSA(hashes.SHA384())))
        result={'issuance_id':job['issuance_id'],'chain_pem':[c.public_bytes(serialization.Encoding.PEM).decode() for c in [cert]+chain],
                'proof':base64.b64encode(sign(write_proof(job,cert,chain))).decode(),'readback_verified':True,'onsite_confirmed':True}
        if kwargs.get('tamper_proof'):result['proof']='AAAA'
        return initialize(self.config,command,self.user.username,reason,install_result=result,**common)

    def test_first_bootstrap_requires_mail_key_real_name_and_matching_certificate(self):
        verification=self.pending_verification()
        self.run_bootstrap(verification)
        self.user.refresh_from_db();self.user.permission.refresh_from_db()
        self.assertTrue(self.user.permission.super_admin);self.assertTrue(self.user.is_superuser)
        self.assertIsNotNone(self.user.advanced_verified_at)
        self.assertEqual(self.user.student_id, 'shou-initial')
        self.assertTrue(ClientCertificateIdentity.objects.filter(user=self.user).exists())
        self.assertTrue(SiteSecuritySetting.objects.filter(key='privileged_bootstrap_completed').exists())
        self.assertTrue(AdminAuditLog.objects.filter(action='bootstrap_super_admin').exists())
        with self.assertRaises(Rejected):self.run_bootstrap(verification)

    def test_unreceived_or_revoked_key_verification_cannot_initialize(self):
        verification=self.pending_verification(receive=False)
        with self.assertRaises(Rejected):self.run_bootstrap(verification)
        verification=self.pending_verification()
        self.key.revoked_at=timezone.now();self.key.save()
        with self.assertRaises(Rejected):self.run_bootstrap(verification)
        self.assertFalse(SiteSecuritySetting.objects.filter(key='privileged_bootstrap_completed').exists())

    def test_legacy_superuser_can_complete_first_security_enrollment(self):
        self.user.permission.super_admin=True;self.user.permission.save();self.user.refresh_from_db()
        self.assertIsNone(self.user.advanced_verified_at)
        verification=self.pending_verification()
        with self.assertRaises(Rejected):self.run_bootstrap(verification)
        self.run_bootstrap(verification,command='bootstrap-legacy')
        self.assertTrue(AdminAuditLog.objects.filter(action='bootstrap_legacy_super_admin').exists())

    def test_normal_user_cannot_use_legacy_path_and_prior_console_closes_bootstrap(self):
        verification=self.pending_verification()
        with self.assertRaises(Rejected):self.run_bootstrap(verification,command='bootstrap-legacy')
        record(self.user,'console_login')
        with self.assertRaises(Rejected):self.run_bootstrap(verification)

    def test_bad_installation_proof_never_grants_bootstrap_role(self):
        verification=self.pending_verification()
        with self.assertRaises(Rejected):self.run_bootstrap(verification,tamper_proof=True)
        self.user.refresh_from_db();self.user.permission.refresh_from_db()
        self.assertFalse(self.user.permission.super_admin)
        self.assertFalse(ClientCertificateIdentity.objects.filter(user=self.user).exists())
        self.assertFalse(SiteSecuritySetting.objects.filter(key='privileged_bootstrap_completed').exists())

    def test_old_raw_certificate_bootstrap_is_closed(self):
        verification=self.pending_verification()
        with self.assertRaises(Rejected):
            initialize(self.config,'bootstrap-first',self.user.username,'拒绝直接导入证书',verification_id=verification,
                       certificate_pem=(self.pki.path/'client.pem').read_text(),real_name_reviewed=True,
                       database=DjangoTestDatabase(),verifier=CertificateVerifier(self.pki.config))
