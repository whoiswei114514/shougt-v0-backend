"""Parse identity only from a sender header supplied by the trusted mail adapter."""
import unicodedata
from email import policy
from email.headerregistry import Address
from email.parser import Parser

from rest_framework.exceptions import ValidationError
from .education import education_student_id, normalize_education_email


def normalize_name(value):
    if not isinstance(value, str):
        raise ValidationError("认证邮件需要包含发件人称呼")
    name = " ".join(unicodedata.normalize("NFKC", value).strip().split())
    if not 2 <= len(name) <= 40 or any(unicodedata.category(char).startswith("C") for char in name):
        raise ValidationError("认证邮件的发件人称呼须为 2 至 40 字的姓名")
    return name


def single_sender(value):
    if not isinstance(value, str) or not value or len(value) > 1024 or "\r" in value or "\n" in value:
        raise ValidationError("认证邮件的发件人格式不正确")
    try:
        header = Parser(policy=policy.default).parsestr("From: " + value + "\n\n")["From"]
        if header.defects or len(header.addresses) != 1 or any(group.display_name for group in header.groups):
            raise ValueError("Exactly one mailbox is required")
        address = header.addresses[0]
        email = normalize_education_email(address.addr_spec)
    except (ValueError, TypeError, IndexError, AttributeError) as exc:
        raise ValidationError("认证邮件必须包含唯一有效的教育邮箱发件人") from exc
    return address.display_name, email


def verified_sender_identity(event):
    authenticated = event.get("authenticated_sender")
    _, authenticated_email = single_sender(authenticated)
    # Full authenticated_sender is supported for adapters that already pass a
    # verified From mailbox; the preferred contract keeps address and header apart.
    display_name, from_email = single_sender(event.get("from_header", authenticated))
    if from_email != authenticated_email:
        raise ValidationError("发件人地址必须与收件系统认证的教育邮箱相同")
    name = normalize_name(display_name)
    canonical_from = str(Address(display_name=name, addr_spec=from_email))
    if len(canonical_from) > 512:
        raise ValidationError("认证邮件的发件人信息过长")
    return {"email": from_email, "real_name": name,
            "student_id": education_student_id(from_email), "mail_from": canonical_from}
