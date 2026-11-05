import base64
import hashlib
import hmac
import re
from datetime import datetime, timezone
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured


def hex_to_base64(hex_digest: str) -> str:
    hash_bytes = bytes.fromhex(hex_digest)
    base64_encoded = base64.b64encode(hash_bytes)
    return base64_encoded.decode("utf-8")


def sha256(data: str) -> str:
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def hmac_sha256(key: bytes, data: str) -> bytes:
    return hmac.new(key, data.encode("utf-8"), hashlib.sha256).digest()


def time_iso8601() -> str:
    return datetime.now(timezone.utc)


def time_yyyymmdd() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%d")


def sign_upload(
    key: str, file_md5: str, content_length: int, content_type: str, time: datetime
):
    bucket, region = settings.ALI_OSS_BUCKET, settings.ALI_OSS_REGION
    if not (re.fullmatch(r"[a-z0-9][a-z0-9-]{1,61}[a-z0-9]", bucket) and re.fullmatch(r"[a-z0-9-]+", region)):
        raise ImproperlyConfigured("请配置本站的 ali_oss_bucket 与 ali_oss_region")
    host = f"{bucket}.oss-{region}.aliyuncs.com"
    md5 = hex_to_base64(file_md5)
    time_iso8601 = time.strftime("%Y%m%dT%H%M%SZ")
    time_yyyymmdd = time.strftime("%Y%m%d")

    CanonicalRequest = f"""PUT
/{bucket}/{key}

content-length:{content_length}
content-md5:{md5}
content-type:{content_type}
host:{host}
x-oss-content-sha256:UNSIGNED-PAYLOAD
x-oss-date:{time_iso8601}
x-oss-forbid-overwrite:true

content-length;host
UNSIGNED-PAYLOAD"""

    StringToSign = (
        "OSS4-HMAC-SHA256\n"
        + time_iso8601
        + "\n"
        + f"{time_yyyymmdd}/{region}/oss/aliyun_v4_request"
        + "\n"
        + sha256(CanonicalRequest)
    )

    dateKey = hmac_sha256(
        ("aliyun_v4" + settings.ALI_ACCESS_SECRET).encode("utf-8"), time_yyyymmdd
    )
    dateRegionKey = hmac_sha256(dateKey, region)
    dateRegionServiceKey = hmac_sha256(dateRegionKey, "oss")
    signingKey = hmac_sha256(dateRegionServiceKey, "aliyun_v4_request")

    result = hmac_sha256(signingKey, StringToSign)
    signature = result.hex()

    authorization = (
        "OSS4-HMAC-SHA256 "
        + f"Credential={settings.ALI_ACCESS_KEY}/{time_yyyymmdd}/{region}/oss/aliyun_v4_request,"
        + "AdditionalHeaders=content-length;host,"
        + "Signature="
        + signature
    )

    upload_headers = {
        "Authorization": authorization,
        "Content-Length": str(content_length),
        "Content-MD5": md5,
        "Content-Type": content_type,
        "X-Oss-Content-Sha256": "UNSIGNED-PAYLOAD",
        "X-Oss-Date": time_iso8601,
        "X-Oss-Forbid-Overwrite": "true",
    }

    return {
        "url": f"https://{host}/{key}",
        "headers": upload_headers,
    }
