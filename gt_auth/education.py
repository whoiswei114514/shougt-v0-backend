import hashlib
import hmac
import re
import secrets
from datetime import timedelta

from django.conf import settings
from django.core.exceptions import ValidationError as DjangoValidationError
from django.core.exceptions import ImproperlyConfigured
from django.core.mail import send_mail
from django.core.validators import validate_email
from django.db import transaction
from django.utils import timezone
from rest_framework.exceptions import ValidationError, Throttled

from .models import EmailChallenge, User, IdentityChoice, SchoolChoice


def normalize_education_email(value):
    if not isinstance(value, str) or len(value) > 254:
        raise ValidationError("请输入有效的教育邮箱")
    value = value.strip().lower()
    try:
        validate_email(value)
    except DjangoValidationError as exc:
        raise ValidationError("邮箱格式不正确") from exc
    domain = value.rsplit("@", 1)[1]
    if not domain.isascii() or not any(domain.endswith("." + suffix) and domain != suffix
                                      for suffix in settings.EDUCATION_EMAIL_SUFFIXES):
        raise ValidationError("仅接受受支持的教育邮箱（edu.cn、edu、ac.uk 等）")
    return value


def education_identity(email):
    domain = normalize_education_email(email).rsplit("@", 1)[1]
    if domain == "st.shou.edu.cn":
        return IdentityChoice.STUDENT, SchoolChoice.SHOU
    if domain == "shou.edu.cn" or domain.endswith(".shou.edu.cn"):
        return IdentityChoice.TEACHER, SchoolChoice.SHOU
    return IdentityChoice.EXTERNAL, SchoolChoice.EXTERNAL


def education_student_id(email):
    """Institution domain label (or configured alias) plus the whole mailbox prefix."""
    local, domain = normalize_education_email(email).rsplit("@", 1)
    aliases = getattr(settings, "EDUCATION_INSTITUTION_ALIASES", {})
    matches = [key for key in aliases if domain == key or domain.endswith("." + key)]
    if matches:
        institution = aliases[max(matches, key=len)]
    else:
        suffix = next(suffix for suffix in sorted(settings.EDUCATION_EMAIL_SUFFIXES, key=len, reverse=True)
                      if domain.endswith("." + suffix))
        institution = domain[:-(len(suffix) + 1)].rsplit(".", 1)[-1]
    if not isinstance(institution, str) or not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", institution):
        raise ImproperlyConfigured("院校邮箱缩写必须为 1 至 63 位小写字母、数字或连字符")
    value = f"{institution}-{local}"
    if len(local) > 64 or len(value) > 128:
        raise ValidationError("教育邮箱前缀过长，无法生成学号")
    return value


def digest(value):
    return hmac.new(settings.SECRET_KEY.encode(), value.encode(), hashlib.sha256).hexdigest()


def send_email_code(email, purpose, request, *, user=None, binding=""):
    email = normalize_education_email(email)
    now = timezone.now()
    ip_hash = digest(request.META.get("REMOTE_ADDR", "unknown"))
    # Count every issuance, including used challenges, so verifying cannot reset the limit.
    if EmailChallenge.objects.filter(email=email, created_at__gt=now - timedelta(seconds=60)).exists():
        raise Throttled(wait=60, detail="请稍后再获取验证码")
    if (EmailChallenge.objects.filter(email=email, created_at__gt=now - timedelta(hours=1)).count() >= 8 or
        EmailChallenge.objects.filter(ip_hash=ip_hash, created_at__gt=now - timedelta(hours=1)).count() >= 30):
        raise Throttled(wait=3600, detail="验证码请求过于频繁")
    if purpose in {"register", "bind"}:
        existing = User.objects.filter(email__iexact=email, email_verified_at__isnull=False)
        if user:
            existing = existing.exclude(pk=user.pk)
        if existing.exists():
            raise ValidationError("该教育邮箱已绑定其他账号")
    fixed_code = getattr(settings, "LOCAL_PREVIEW_EMAIL_CODE", None)
    if fixed_code is not None:
        if not (settings.DEBUG and getattr(settings, "LOCAL_PREVIEW_MODE", False) and
                settings.WEBAUTHN_RP_ID == "localhost" and
                request.META.get("REMOTE_ADDR") in {"127.0.0.1", "::1"} and
                isinstance(fixed_code, str) and len(fixed_code) == 6 and fixed_code.isascii() and fixed_code.isdigit()):
            raise ImproperlyConfigured("固定验证码仅允许在本机预览模式使用")
        code = fixed_code
    else:
        code = f"{secrets.randbelow(1000000):06d}"
    challenge = EmailChallenge.objects.create(
        user=user, email=email, purpose=purpose, binding=str(binding), code_hash="",
        ip_hash=ip_hash, expires_at=now + timedelta(minutes=10),
    )
    challenge.code_hash = digest(f"{challenge.id}:{code}")
    challenge.save(update_fields=["code_hash"])
    try:
        send_mail("shou瓜田 · 邮箱验证码", f"您的验证码为 {code}，10 分钟内有效。请勿转发。\n如非本人操作，请忽略本邮件。",
                  settings.DEFAULT_FROM_EMAIL, [email], fail_silently=False)
    except Exception:
        challenge.consumed_at = now
        challenge.save(update_fields=["consumed_at"])
        raise ValidationError("邮件暂时无法发送，请稍后重试")
    return {"challenge_id": str(challenge.id), "expires_in": 600, "resend_after": 60}


def consume_email_code(challenge_id, code, purpose, *, user=None, email=None, binding=""):
    # Persist failed attempts before raising; do not roll them back with the error.
    accepted = False
    with transaction.atomic():
        try:
            row = EmailChallenge.objects.select_for_update().filter(pk=challenge_id).first()
        except (ValueError, DjangoValidationError):
            row = None
        if (row and row.purpose == purpose and row.user_id == (user.pk if user else None) and
            row.binding == str(binding) and (email is None or row.email == email) and
            not row.consumed_at and row.expires_at > timezone.now() and row.attempts < 5):
            row.attempts += 1
            accepted = isinstance(code, str) and hmac.compare_digest(row.code_hash, digest(f"{row.id}:{code}"))
            if accepted or row.attempts >= 5:
                row.consumed_at = timezone.now()
            row.save(update_fields=["attempts", "consumed_at"])
    if not accepted:
        raise ValidationError("验证码错误、过期或尝试次数过多")
    return row.email


def bind_verified_email(user, email):
    user.email = normalize_education_email(email)
    user.identity, user.school = education_identity(email)
    user.student_id = education_student_id(email)
    user.email_verified_at = timezone.now()
    user.real_name_verified_at = None
    user.advanced_verified_at = None
    user.version += 1
    user.save()
