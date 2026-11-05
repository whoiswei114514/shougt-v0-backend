import hashlib
import hmac
import json
import secrets
from datetime import datetime, timedelta

from django.conf import settings
from django.core.exceptions import ValidationError as DjangoValidationError
from django.db import transaction
from django.shortcuts import get_object_or_404
from django.utils import timezone
from rest_framework.decorators import action, api_view, authentication_classes, permission_classes
from rest_framework.exceptions import PermissionDenied, ValidationError
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.viewsets import GenericViewSet

from gt_admin.audit import record
from gt.parsers import AUTH_PARSERS
from .models import AdvancedVerification, PrivilegedOperation
from .education import education_student_id
from .mail_identity import verified_sender_identity
from .security_policy import require_key_session
from .security_views import SecurityRateThrottle
from . import webauthn


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


class AdvancedViewset(GenericViewSet):
    permission_classes = [IsAuthenticated]
    throttle_classes = [SecurityRateThrottle]
    parser_classes = AUTH_PARSERS

    @action(detail=False, methods=["get"])
    def status(self, request):
        row = request.user.advanced_requests.order_by("-issued_at").first()
        if not row:
            return Response({"status": "not_started"})
        status = row.status
        if row.expires_at <= timezone.now() and status in {"awaiting_signature", "awaiting_email"}:
            status = "expired"
        return Response({"id": str(row.pk), "status": status, "issued_at": row.issued_at,
                         "expires_at": row.expires_at, "mail_received_at": row.mail_received_at,
                         "reviewed_at": row.reviewed_at, "review_note": row.review_note,
                         "real_name": row.real_name, "student_id": row.student_id,
                         "mail_from": row.mail_from})

    @action(detail=False, methods=["post"])
    def begin(self, request):
        user, session = request.user, request.security_session
        require_key_session(user, session)
        candidate = user.admin_candidate_until and user.admin_candidate_until > timezone.now()
        if not user.is_management and not candidate:
            raise PermissionDenied("高级认证仅对管理员及已提名的管理员候选人开放")
        if not user.email_verified_at:
            raise PermissionDenied("请先验证教育邮箱")
        student_id = education_student_id(user.email)
        now, nonce = timezone.now(), secrets.token_urlsafe(32)
        payload = canonical({"purpose": "shou-advanced-v2", "user_id": user.pk, "user_version": user.version,
                             "email": user.email, "identity_source": "verified-mail-from",
                             "student_id": student_id, "nonce": nonce, "issued_at": now.isoformat()})
        row = AdvancedVerification.objects.create(
            user=user, credential=session.credential, email=user.email, student_id=student_id,
            nonce=nonce, issued_at=now, expires_at=now + timedelta(hours=24), payload=payload,
        )
        options = webauthn.begin_assertion("advanced", user=user, keys=[session.credential],
                                          challenge=hashlib.sha256(payload.encode()).digest(),
                                          state={"verification_id": str(row.pk), "session_id": str(session.pk)})
        return Response({**options, "verification_id": str(row.pk), "nonce": nonce,
                         "issued_at": now, "expires_at": row.expires_at, "payload": payload})

    @action(detail=False, methods=["post"])
    def finish(self, request):
        require_key_session(request.user, request.security_session)
        key, challenge = webauthn.finish_assertion(request.data.get("challenge_id"), "advanced",
                                                  request.data.get("credential"), user=request.user)
        if challenge.state["session_id"] != str(request.security_session.pk):
            raise PermissionDenied("登录会话不匹配")
        with transaction.atomic():
            row = AdvancedVerification.objects.select_for_update().get(pk=challenge.state["verification_id"], user=request.user)
            if row.status != "awaiting_signature" or row.expires_at <= timezone.now() or row.credential_id != key.pk:
                raise ValidationError("高级认证请求已失效")
            row.assertion = request.data["credential"]
            row.status, row.signed_at = "awaiting_email", timezone.now()
            row.save(update_fields=["assertion", "status", "signed_at"])
            envelope = webauthn.b64(canonical({"request_id": str(row.pk), "payload": row.payload, "assertion": row.assertion}).encode())
            body = (f"shou瓜田高级认证\n账号：{request.user.username}\n"
                    f"实名以本邮件发件人称呼为准\n学号：{row.student_id or education_student_id(row.email)}\n"
                    f"随机字符串：{row.nonce}\n签发时间：{row.issued_at.isoformat()}\n\nSHOU-VERIFY:{envelope}\n")
            record(request.user, "advanced_signed", object_type="advanced", object_id=row.pk, session=request.security_session)
        return Response({"id": str(row.pk), "recipient": settings.ADVANCED_VERIFICATION_EMAIL,
                         "from_email": row.email, "subject": f"shou瓜田高级认证 {row.pk}",
                         "body": body, "expires_at": row.expires_at})


def accept_verified_mail(event):
    """Called only by an authenticated, DMARC-aware receiving mail system."""
    if not isinstance(event, dict):
        raise ValidationError("邮件事件必须是 JSON 对象")
    if event.get("dmarc_pass") is not True or event.get("recipient") != settings.ADVANCED_VERIFICATION_EMAIL:
        raise ValidationError("收件地址或邮件域名认证不通过")
    identity = verified_sender_identity(event)
    sender = identity["email"]
    try:
        received_at = datetime.fromisoformat(event["received_at"].replace("Z", "+00:00"))
        body = event["body"]
        marker = next(line.strip()[12:] for line in body.splitlines() if line.strip().startswith("SHOU-VERIFY:"))
        envelope = json.loads(webauthn.unb64(marker))
        if not received_at.tzinfo:
            raise ValueError("Missing timezone")
    except (KeyError, ValueError, StopIteration, TypeError, UnicodeError) as exc:
        raise ValidationError("认证邮件格式不正确") from exc
    with transaction.atomic():
        try:
            row = AdvancedVerification.objects.select_for_update().select_related("user").get(pk=envelope["request_id"])
        except (AdvancedVerification.DoesNotExist, ValueError, KeyError, DjangoValidationError) as exc:
            raise ValidationError("认证请求不存在") from exc
        can_receive = row.status == "awaiting_email" or (row.status == "awaiting_review" and not row.mail_from)
        signed_payload = json.loads(row.payload)
        if (not can_receive or not row.signed_at or
            not row.signed_at <= received_at <= row.expires_at or received_at > timezone.now() + timedelta(minutes=1) or
            timezone.now() - received_at > timedelta(days=2) or sender != row.email or
            sender != row.user.email.lower() or not row.user.email_verified_at or
            signed_payload["user_version"] != row.user.version or
            (signed_payload.get("student_id") and signed_payload["student_id"] != identity["student_id"]) or
            envelope.get("payload") != row.payload or envelope.get("assertion") != row.assertion):
            raise ValidationError("邮箱、签名或 24 小时有效期校验失败")
        row.status = "awaiting_review"
        row.real_name, row.student_id, row.mail_from = identity["real_name"], identity["student_id"], identity["mail_from"]
        row.mail_received_at = received_at
        row.mail_message_id = str(event.get("message_id", ""))[:255]
        row.save(update_fields=["status", "real_name", "student_id", "mail_from", "mail_received_at", "mail_message_id"])
        record(row.user, "advanced_mail_received", object_type="advanced", object_id=row.pk,
               details={"identity_source": "verified-mail-from", "real_name": row.real_name,
                        "student_id": row.student_id})
    return row


@api_view(["POST"])
@authentication_classes([])
@permission_classes([AllowAny])
def verified_mail_webhook(request):
    secret = settings.ADVANCED_MAIL_INGEST_SECRET
    stamp = request.headers.get("X-Shou-Mail-Time", "")
    signature = request.headers.get("X-Shou-Mail-Signature", "")
    if not secret or len(request.body) > 100000:
        raise PermissionDenied("邮件接收接口不可用")
    try:
        valid_time = abs(timezone.now().timestamp() - int(stamp)) <= 300
    except ValueError:
        valid_time = False
    expected = hmac.new(secret.encode(), stamp.encode() + b"." + request.body, hashlib.sha256).hexdigest()
    if not valid_time or not hmac.compare_digest(expected, signature):
        raise PermissionDenied("邮件接收签名无效")
    row = accept_verified_mail(request.data)
    return Response({"id": str(row.pk), "status": row.status})


class OperationViewset(GenericViewSet):
    permission_classes = [IsAuthenticated]
    throttle_classes = [SecurityRateThrottle]
    parser_classes = AUTH_PARSERS

    def operation(self):
        require_key_session(self.request.user, self.request.security_session, privileged=True)
        operation = get_object_or_404(PrivilegedOperation, pk=self.kwargs["pk"], session=self.request.security_session)
        if (operation.expires_at <= timezone.now() or operation.executed_at or
            operation.console_session.expires_at <= timezone.now() or operation.console_session.revoked_at):
            raise ValidationError("管理操作已失效")
        expected = hashlib.sha256(canonical({"action": operation.action, "payload": operation.payload}).encode()).hexdigest()
        if not hmac.compare_digest(expected, operation.digest):
            raise PermissionDenied("操作内容不匹配")
        return operation

    def retrieve(self, request, *args, **kwargs):
        operation = self.operation()
        return Response({"action": operation.action, "payload": operation.payload, "expires_at": operation.expires_at})

    @action(detail=True, methods=["post"])
    def begin(self, request, pk=None):
        operation = self.operation()
        if operation.approved_at:
            raise ValidationError("此操作已经授权")
        return Response(webauthn.begin_assertion("console_operation", user=request.user,
                        keys=[request.security_session.credential],
                        challenge=hashlib.sha256((str(operation.pk) + ":" + operation.digest + ":" + secrets.token_hex(32)).encode()).digest(),
                        state={"operation_id": str(operation.pk), "session_id": str(request.security_session.pk)}))

    @action(detail=True, methods=["post"])
    def finish(self, request, pk=None):
        operation = self.operation()
        key, challenge = webauthn.finish_assertion(request.data.get("challenge_id"), "console_operation",
                                                  request.data.get("credential"), user=request.user)
        if (challenge.state["operation_id"] != str(operation.pk) or key.pk != request.security_session.credential_id or
            challenge.state["session_id"] != str(request.security_session.pk)):
            raise PermissionDenied("操作或本次登录密钥不匹配")
        if not PrivilegedOperation.objects.filter(pk=operation.pk, approved_at__isnull=True,
                                                  executed_at__isnull=True, expires_at__gt=timezone.now()).update(approved_at=timezone.now()):
            raise ValidationError("此操作已授权或过期")
        record(request.user, "console_operation_approved", object_type="operation", object_id=operation.pk,
               details={"action": operation.action, "digest": operation.digest}, session=request.security_session)
        return Response({"msg": "操作已授权", "operation_id": str(operation.pk)})
