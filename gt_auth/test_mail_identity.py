import json
from datetime import timedelta
from email.header import Header
from django.core.cache import cache
from django.test import TestCase, SimpleTestCase, override_settings
from django.utils import timezone
from rest_framework.exceptions import ValidationError
from rest_framework.test import APIClient
from .advanced_views import accept_verified_mail
from .education import education_student_id, bind_verified_email
from .mail_identity import verified_sender_identity
from .models import AdvancedVerification
from .test_support import make_user, add_key, authenticate
from .test_console import DjangoTestDatabase
from backend.actions import reviewed_identity
from backend.policy import Rejected


class SenderIdentityParsingTests(SimpleTestCase):
    def event(self, header):
        return {'authenticated_sender': '2531231@st.shou.edu.cn', 'from_header': header}

    def test_sender_name_and_school_mailbox_identifier(self):
        for header in ('魏子力<2531231@st.shou.edu.cn>',
                       Header('魏子力', 'utf-8').encode() + ' <2531231@st.shou.edu.cn>'):
            identity = verified_sender_identity(self.event(header))
            self.assertEqual(identity['real_name'], '魏子力')
            self.assertEqual(identity['student_id'], 'shou-2531231')
        self.assertEqual(verified_sender_identity({'authenticated_sender': '魏子力<2531231@st.shou.edu.cn>'})['real_name'], '魏子力')

    def test_missing_name_ambiguous_header_and_spoofed_mailbox_rejected(self):
        for header in ('2531231@st.shou.edu.cn', '魏子力 <someone@st.shou.edu.cn>',
                       '魏子力 <2531231@st.shou.edu.cn>, 他人 <else@shou.edu.cn>',
                       '组: 魏子力 <2531231@st.shou.edu.cn>;',
                       '魏子力 <2531231@st.shou.edu.cn>\r\nBcc: evil@example.edu',
                       '\u2063魏子力 <2531231@st.shou.edu.cn>'):
            with self.subTest(header=header), self.assertRaises(ValidationError):
                verified_sender_identity(self.event(header))

    def test_institution_prefixes_domains_and_long_mailbox_not_truncated(self):
        for address, expected in [('staff@shou.edu.cn', 'shou-staff'),
                                  ('a123@physics.ox.ac.uk', 'ox-a123'),
                                  ('researcher@mit.edu', 'mit-researcher'),
                                  ('a' * 64 + '@st.shou.edu.cn', 'shou-' + 'a' * 64)]:
            self.assertEqual(education_student_id(address), expected)
        with override_settings(EDUCATION_INSTITUTION_ALIASES={'ox.ac.uk': 'oxford'}):
            self.assertEqual(education_student_id('a@math.ox.ac.uk'), 'oxford-a')
            self.assertEqual(education_student_id('a@notox.ac.uk'), 'notox-a')


class MailIdentityFlowTests(TestCase):
    def setUp(self):
        cache.clear()
        self.api = APIClient()
        self.user, self.role = make_user('mail_identity')
        self.user.email = '2531231@st.shou.edu.cn'
        self.user.admin_candidate_until = timezone.now() + timedelta(days=1)
        self.user.save()
        self.key, self.virtual = add_key(self.user)
        authenticate(self.api, self.user, self.role, key=self.key)
        response = self.api.post('/security/advanced/begin/', {'real_name': '不能覆盖来信姓名'}, format='json')
        self.assertEqual(response.status_code, 200, response.data)
        options = response.data
        self.assertNotIn('real_name', json.loads(options['payload']))
        signed = self.api.post('/security/advanced/finish/',
                               {'challenge_id': options['challenge_id'], 'credential': self.virtual.assertion(options)}, format='json')
        self.assertEqual(signed.status_code, 200, signed.data)
        self.row = AdvancedVerification.objects.get(pk=signed.data['id'])
        self.event = {'recipient': 'renzheng@shouguatian.com', 'authenticated_sender': self.user.email,
                      'from_header': '魏子力<2531231@st.shou.edu.cn>', 'dmarc_pass': True,
                      'received_at': timezone.now().isoformat(), 'body': signed.data['body']}

    def test_receive_then_review_commits_sender_name_and_derived_id(self):
        original = (self.user.real_name, self.user.student_id)
        row = accept_verified_mail(self.event)
        self.assertEqual((row.real_name, row.student_id, row.status), ('魏子力', 'shou-2531231', 'awaiting_review'))
        self.assertEqual(row.payload, self.row.payload)
        self.user.refresh_from_db()
        self.assertEqual((self.user.real_name, self.user.student_id), original)
        reviewer, _ = make_user('reviewer', roles=['super_admin'])
        with DjangoTestDatabase().transaction() as db:
            reviewed_identity(db, row.pk, reviewer.pk, '已核对邮件发件人和材料')
        self.user.refresh_from_db()
        self.assertEqual((self.user.real_name, self.user.student_id), ('魏子力', 'shou-2531231'))
        self.assertTrue(self.user.real_name_verified_at and self.user.advanced_verified_at)
        with self.assertRaises(ValidationError):
            accept_verified_mail(dict(self.event, from_header='别名 <2531231@st.shou.edu.cn>'))

    def test_missing_name_does_not_advance_request_and_legacy_missing_evidence_cannot_be_reviewed(self):
        with self.assertRaises(ValidationError):
            accept_verified_mail({key: value for key, value in self.event.items() if key != 'from_header'})
        self.row.refresh_from_db()
        self.assertEqual(self.row.status, 'awaiting_email')
        row = accept_verified_mail(self.event)
        AdvancedVerification.objects.filter(pk=row.pk).update(mail_from='')
        with self.assertRaises(Rejected), DjangoTestDatabase().transaction() as db:
            reviewed_identity(db, row.pk, None, '缺少邮件称呼，不能通过')
        # A still-valid legacy mail can be enriched by the trusted adapter once.
        self.assertEqual(accept_verified_mail(self.event).mail_from, '魏子力 <2531231@st.shou.edu.cn>')

    def test_binding_new_email_recomputes_student_identifier(self):
        bind_verified_email(self.user, 'staff.member@shou.edu.cn')
        self.user.refresh_from_db()
        self.assertEqual(self.user.student_id, 'shou-staff.member')
        self.assertIsNone(self.user.advanced_verified_at)
