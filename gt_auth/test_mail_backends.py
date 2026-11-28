from unittest.mock import MagicMock, patch

from django.core.exceptions import ImproperlyConfigured
from django.core.mail import EmailMultiAlternatives, send_mail
from django.test import SimpleTestCase, override_settings

from gt.mail_backends import ResendEmailBackend


class ResendEmailBackendTests(SimpleTestCase):
    @override_settings(
        EMAIL_BACKEND="gt.mail_backends.ResendEmailBackend",
        RESEND_API_KEY="re_test_key_only",
        RESEND_API_URL="https://api.resend.com/emails",
        DEFAULT_FROM_EMAIL="noreply@shouguatian.com",
        EMAIL_TIMEOUT=10,
    )
    @patch("gt.mail_backends.requests.post")
    def test_send_mail_posts_expected_payload_to_resend(self, mock_post):
        mock_post.return_value = MagicMock(status_code=200)
        count = send_mail(
            "shou瓜田 · 邮箱验证码",
            "您的验证码为 123456，10 分钟内有效。",
            None,
            ["example001@st.shou.edu.cn"],
            fail_silently=False,
        )
        self.assertEqual(count, 1)
        mock_post.assert_called_once()
        args, kwargs = mock_post.call_args
        self.assertEqual(args[0], "https://api.resend.com/emails")
        self.assertEqual(kwargs["headers"]["Authorization"], "Bearer re_test_key_only")
        self.assertEqual(kwargs["timeout"], 10)
        self.assertEqual(
            kwargs["json"],
            {
                "from": "noreply@shouguatian.com",
                "to": ["example001@st.shou.edu.cn"],
                "subject": "shou瓜田 · 邮箱验证码",
                "text": "您的验证码为 123456，10 分钟内有效。",
            },
        )

    @patch("gt.mail_backends.requests.post")
    def test_multipart_reply_to_cc_bcc_and_error_handling(self, mock_post):
        mock_post.return_value = MagicMock(status_code=200)
        backend = ResendEmailBackend(api_key="re_secret_never_leak", timeout=12)
        message = EmailMultiAlternatives(
            subject="Subject",
            body="Plain body",
            from_email="noreply@shouguatian.com",
            to=["a@st.shou.edu.cn"],
            cc=["cc@shou.edu.cn"],
            bcc=["bcc@shou.edu.cn"],
            reply_to=["admin@shouguatian.com"],
        )
        message.attach_alternative("<p>HTML body</p>", "text/html")
        self.assertEqual(backend.send_messages([message]), 1)
        payload = mock_post.call_args.kwargs["json"]
        self.assertEqual(payload["html"], "<p>HTML body</p>")
        self.assertEqual(payload["cc"], ["cc@shou.edu.cn"])
        self.assertEqual(payload["bcc"], ["bcc@shou.edu.cn"])
        self.assertEqual(payload["reply_to"], ["admin@shouguatian.com"])

        mock_post.return_value = MagicMock(status_code=422)
        with self.assertRaises(RuntimeError) as ctx:
            backend.send_messages([message])
        self.assertIn("HTTP 422", str(ctx.exception))
        self.assertNotIn("re_secret_never_leak", str(ctx.exception))

        silent = ResendEmailBackend(fail_silently=True, api_key="re_secret_never_leak")
        self.assertEqual(silent.send_messages([message]), 0)

    def test_missing_api_key_behavior(self):
        message = EmailMultiAlternatives(subject="S", body="B", to=["a@st.shou.edu.cn"])
        with self.assertRaises(ImproperlyConfigured):
            ResendEmailBackend(api_key="").send_messages([message])
        self.assertEqual(ResendEmailBackend(fail_silently=True, api_key="").send_messages([message]), 0)
