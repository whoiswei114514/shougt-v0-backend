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
        return initialize(self.config,command,self.user.username,'已当面核验首次管理身份材料',verification_id=verification,
                          certificate_pem=(self.pki.path/'client.pem').read_text(),real_name_reviewed=True,
                          database=DjangoTestDatabase(),verifier=CertificateVerifier(self.pki.config),**kwargs)

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

    def test_certificate_mismatch_rolls_back_identity_review(self):
        verification=self.pending_verification()
        self.pki=PKI(self.temp.name,client_name='另一位管理员')
        self.config.tls=self.pki.config
        with self.assertRaises(Rejected):self.run_bootstrap(verification)
        self.assertEqual(AdvancedVerification.objects.get(pk=verification).status,'awaiting_review')
        self.user.refresh_from_db();self.assertIsNone(self.user.advanced_verified_at)
