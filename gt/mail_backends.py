"""HTTP email backend for Resend API (HTTPS 443, no outbound SMTP ports required)."""
import requests
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from django.core.mail.backends.base import BaseEmailBackend


class ResendEmailBackend(BaseEmailBackend):
    """Send Django email messages over HTTPS via the Resend REST API."""

    def __init__(self, fail_silently=False, api_key=None, api_url=None, timeout=None, **kwargs):
        super().__init__(fail_silently=fail_silently, **kwargs)
        self.api_key = api_key if api_key is not None else getattr(settings, "RESEND_API_KEY", "")
        self.api_url = api_url or getattr(settings, "RESEND_API_URL", "https://api.resend.com/emails")
        self.timeout = timeout if timeout is not None else getattr(settings, "EMAIL_TIMEOUT", 15)

    def _build_payload(self, message):
        payload = {
            "from": message.from_email or settings.DEFAULT_FROM_EMAIL,
            "to": list(message.to or []),
            "subject": message.subject,
            "text": message.body,
        }
        for content, mimetype in getattr(message, "alternatives", None) or []:
            if mimetype == "text/html":
                payload["html"] = content
                break
        if message.cc:
            payload["cc"] = list(message.cc)
        if message.bcc:
            payload["bcc"] = list(message.bcc)
        if getattr(message, "reply_to", None):
            payload["reply_to"] = list(message.reply_to)
        return payload

    def send_messages(self, email_messages):
        if not email_messages:
            return 0
        if not self.api_key:
            if self.fail_silently:
                return 0
            raise ImproperlyConfigured("RESEND_API_KEY / SHOUGT_RESEND_API_KEY is required")

        sent = 0
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        for message in email_messages:
            if not message.recipients():
                continue
            if not message.to:
                if self.fail_silently:
                    continue
                raise ValueError("Resend requires at least one 'to' recipient")
            try:
                response = requests.post(
                    self.api_url,
                    json=self._build_payload(message),
                    headers=headers,
                    timeout=self.timeout,
                )
                if response.status_code >= 400:
                    raise RuntimeError(f"Resend API error: HTTP {response.status_code}")
                sent += 1
            except Exception:
                if not self.fail_silently:
                    raise
        return sent
