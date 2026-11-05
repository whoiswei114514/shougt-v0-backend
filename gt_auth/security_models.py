import uuid
from django.conf import settings
from django.db import models


class EmailChallenge(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, null=True)
    email = models.EmailField(max_length=254)
    purpose = models.CharField(max_length=32)
    binding = models.CharField(max_length=64, default="")
    code_hash = models.CharField(max_length=64)
    ip_hash = models.CharField(max_length=64)
    attempts = models.PositiveSmallIntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    consumed_at = models.DateTimeField(null=True)

    class Meta:
        indexes = [models.Index(fields=["email", "created_at"]), models.Index(fields=["ip_hash", "created_at"])]


class WebAuthnCredential(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="security_keys")
    credential_id = models.CharField(max_length=1400, unique=True)
    credential_data = models.TextField()
    name = models.CharField(max_length=80)
    aaguid = models.CharField(max_length=36, default="")
    sign_count = models.PositiveBigIntegerField(default=0)
    transports = models.JSONField(default=list)
    is_security_key = models.BooleanField(default=False)
    backup_eligible = models.BooleanField(default=False)
    attestation_verified = models.BooleanField(default=False)
    assurance_level = models.CharField(max_length=64, default="standard")
    attestation_evidence = models.JSONField(default=dict)
    created_at = models.DateTimeField(auto_now_add=True)
    last_used_at = models.DateTimeField(null=True)
    revoked_at = models.DateTimeField(null=True)


class SecurityChallenge(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, null=True)
    purpose = models.CharField(max_length=32)
    state = models.JSONField(default=dict)
    expires_at = models.DateTimeField()
    consumed_at = models.DateTimeField(null=True)
    attempts = models.PositiveSmallIntegerField(default=0)


class AuthSession(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="security_sessions")
    credential = models.ForeignKey(WebAuthnCredential, on_delete=models.SET_NULL, null=True)
    methods = models.JSONField(default=list)
    scope = models.CharField(max_length=24, default="full")
    user_version = models.PositiveIntegerField()
    created_at = models.DateTimeField(auto_now_add=True)
    verified_at = models.DateTimeField()
    expires_at = models.DateTimeField()
    revoked_at = models.DateTimeField(null=True)
    impersonator_id = models.BigIntegerField(null=True)
    parent_session = models.ForeignKey("self", on_delete=models.SET_NULL, null=True)


class TotpDevice(models.Model):
    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="totp_device")
    encrypted_secret = models.TextField()
    confirmed_at = models.DateTimeField(null=True)
    last_counter = models.BigIntegerField(default=-1)


class AdvancedVerification(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="advanced_requests")
    credential = models.ForeignKey(WebAuthnCredential, on_delete=models.PROTECT)
    email = models.EmailField()
    real_name = models.CharField(max_length=40, blank=True, default="")
    student_id = models.CharField(max_length=128, blank=True, default="")
    mail_from = models.CharField(max_length=512, blank=True, default="")
    nonce = models.CharField(max_length=128)
    issued_at = models.DateTimeField()
    expires_at = models.DateTimeField()
    payload = models.TextField()
    assertion = models.JSONField(default=dict)
    status = models.CharField(max_length=32, default="awaiting_signature")
    signed_at = models.DateTimeField(null=True)
    mail_received_at = models.DateTimeField(null=True)
    mail_message_id = models.CharField(max_length=255, blank=True, default="")
    reviewed_at = models.DateTimeField(null=True)
    reviewer_id = models.BigIntegerField(null=True)
    review_note = models.CharField(max_length=1000, default="", blank=True)


class ConsoleTicket(models.Model):
    token_hash = models.CharField(max_length=64, unique=True)
    session = models.ForeignKey(AuthSession, on_delete=models.CASCADE)
    expires_at = models.DateTimeField()
    consumed_at = models.DateTimeField(null=True)


class ImpersonationTicket(models.Model):
    token_hash = models.CharField(max_length=64, unique=True)
    session = models.ForeignKey(AuthSession, on_delete=models.CASCADE)
    expires_at = models.DateTimeField()
    consumed_at = models.DateTimeField(null=True)


class ConsoleSession(models.Model):
    token_hash = models.CharField(max_length=64, unique=True)
    session = models.ForeignKey(AuthSession, on_delete=models.CASCADE)
    certificate_fingerprint = models.CharField(max_length=64)
    csrf_hash = models.CharField(max_length=64)
    expires_at = models.DateTimeField()
    revoked_at = models.DateTimeField(null=True)


class PrivilegedOperation(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    session = models.ForeignKey(AuthSession, on_delete=models.CASCADE)
    console_session = models.ForeignKey(ConsoleSession, on_delete=models.CASCADE)
    action = models.CharField(max_length=64)
    payload = models.JSONField(default=dict)
    digest = models.CharField(max_length=64)
    expires_at = models.DateTimeField()
    approved_at = models.DateTimeField(null=True)
    executed_at = models.DateTimeField(null=True)


class ClientCertificateIdentity(models.Model):
    fingerprint = models.CharField(max_length=64, unique=True)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT)
    real_name = models.CharField(max_length=40)
    issuer_fingerprint = models.CharField(max_length=64)
    serial_number = models.CharField(max_length=128)
    expires_at = models.DateTimeField()
    revoked_at = models.DateTimeField(null=True)


class SiteSecuritySetting(models.Model):
    key = models.CharField(max_length=64, primary_key=True)
    value = models.JSONField(default=dict)
    updated_at = models.DateTimeField(auto_now=True)
