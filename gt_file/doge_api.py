import base64
import hmac
import json
import time
import urllib.parse
from hashlib import md5 as _md5, sha1

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from django.conf import settings
from requests import post

from .models import File, Video


def md5(data: str):
    return _md5(data.encode("utf-8")).hexdigest()


def dogecloud_api(api_path, data={}, json_mode=True):
    body = ""
    mime = ""
    if json_mode:
        body = json.dumps(data)
        mime = "application/json"
    else:
        body = urllib.parse.urlencode(data)
        mime = "application/x-www-form-urlencoded"
    sign_str = api_path + "\n" + body
    signed_data = hmac.new(
        settings.DOGE_SECRET.encode("utf-8"), sign_str.encode("utf-8"), sha1
    )
    sign = signed_data.digest().hex()
    authorization = "TOKEN " + settings.DOGE_ACCESS + ":" + sign
    response = post(
        "https://api.dogecloud.com" + api_path,
        data=body,
        headers={"Authorization": authorization, "Content-Type": mime},
        timeout=15,
    )
    return response.json()


def get_upload_data(_file: File | list[File]):
    if isinstance(_file, File):
        files = [_file]
    else:
        files = _file
    scopes = [file.key for file in files]
    r = dogecloud_api(
        "/auth/tmp_token.json",
        {
            "channel": "OSS_UPLOAD",
            "scopes": [f"{settings.DOGE_FILE_BUCKET}:{i}" for i in scopes],
            "ttl": 3600,
        },
    )
    if r["code"] != 200:
        return r["msg"]
    r = r["data"]
    r["scopes"] = scopes
    return r


def get_video_upload_data(video: Video):
    r = dogecloud_api(
        "/auth/tmp_token.json",
        {
            "channel": "VOD_UPLOAD",
            "vodConfig": {
                "filename": video.name,
                "vn": f"{video.id}.{video.name}",
                "sizelimit": video.size,
                "cid": settings.DOGE_VIDEO_CATEGORY_ID,
                "callbackString": video.uuid,
            },
            "ttl": 3600,
        },
    )
    if r["code"] != 200:
        return r["msg"]
    r = r["data"]
    return r


def get_cdn_authkey(path: str, ttl: int = 30, data: str = "0", uid: int = 0):
    parsed_url = urllib.parse.urlparse(path)
    file_path = urllib.parse.quote(parsed_url.path)
    expires = int(time.time()) + ttl

    string_to_sign = f"{file_path}-{expires}-{data}-{uid}-{settings.DOGE_FILE_CDNKEY}"

    md5hash = md5(string_to_sign)
    auth_key = f"{expires}-{data}-{uid}-{md5hash}"
    return auth_key


def generate_playtoken(vcode: str):
    secret_key = settings.DOGE_SECRET.encode("utf-8")
    policy = json.dumps({"e": int(time.time()) + 30, "v": vcode, "full": True})

    iv = get_random_bytes(16)

    cipher = AES.new(secret_key, AES.MODE_CFB, iv, segment_size=128)
    encrypted_data = cipher.encrypt(policy.encode())

    encoded_data = base64.b64encode(encrypted_data).decode()
    encoded_iv = base64.b64encode(iv).decode()

    hashed_data = base64.b64encode(
        hmac.new(secret_key, policy.encode(), sha1).digest()
    ).decode()

    playToken = f"{encoded_data}:{encoded_iv}:{hashed_data}"

    playToken = playToken.replace("+", "-").replace("/", "_")

    return playToken
