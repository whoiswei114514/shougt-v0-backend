# Generated public wire codec; source: shougt-sa/backend/watermark_codec.py.
"""Public v2 wire format. Contains provenance, never authentication credentials."""
import base64
import hashlib
import struct
import zlib
from datetime import datetime, timezone

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from reedsolo import RSCodec, ReedSolomonError

MAGIC = b"SW2!"
DOMAIN = b"shou-management-watermark-v2\0"
BODY = struct.Struct(">B12sQQQQHH")
MAX_PACKET = 1200
MAX_BODY = 1024
CHUNK_BYTES = 178
KEY_PREFIX = "watermark_public_key."
PILOT_BYTES = bytes.fromhex("53484f5532a56c39db8117ee")
SOURCES = {1: "main", 2: "console"}
SOURCE_IDS = {value: key for key, value in SOURCES.items()}


def _render_mask():
    state, output = 0x53484F55, bytearray()
    for _ in range(255):
        state = (state * 1664525 + 1013904223) & 0xffffffff
        output.append(state >> 24)
    return bytes(output)


RENDER_MASK = _render_mask()


def signing_key(seed):
    return Ed25519PrivateKey.from_private_bytes(hashlib.sha256(DOMAIN + seed).digest())


def public_identity(key):
    public = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return hashlib.sha256(public).hexdigest()[:16], base64.b64encode(public).decode("ascii")


def millis(value):
    if value is None:
        return 0
    if isinstance(value, str):
        value = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return int(value.timestamp() * 1000)


def iso(value):
    return datetime.fromtimestamp(value / 1000, timezone.utc).isoformat() if value else None


def encode_frame(actor, operation, marker, source, key, *, issued_at=None):
    issued_ms = millis(issued_at or datetime.now(timezone.utc))
    username, name = actor["username"].encode("utf-8"), actor["real_name"].encode("utf-8")
    if len(username) > 600 or len(name) > 160:
        raise ValueError("Watermark identity exceeds the database contract")
    body = BODY.pack(SOURCE_IDS[source], bytes.fromhex(marker), actor["id"],
                     operation["id"] if operation else 0,
                     millis(operation["created_at"]) if operation else 0,
                     issued_ms, len(username), len(name)) + username + name
    compressed = zlib.compress(body, 9)
    key_id, _ = public_identity(key)
    message = MAGIC + bytes.fromhex(key_id) + struct.pack(">H", len(compressed)) + compressed
    signed = message + key.sign(DOMAIN + message)
    packet = signed + struct.pack(">I", zlib.crc32(signed))
    if len(packet) > MAX_PACKET:
        raise ValueError("Watermark packet exceeds its size limit")
    token = base64.b64encode(packet).decode("ascii")
    result = decode_packet(token)
    result.pop("token")
    return {**result, "token": token, "shards": encode_shards(packet),
            "refresh_after_ms": 5000}


def decode_packet(token):
    if not isinstance(token, str) or len(token) > MAX_PACKET * 4 // 3 + 4:
        raise ValueError("Invalid watermark token")
    packet = base64.b64decode(token, validate=True)
    if not 82 <= len(packet) <= MAX_PACKET or packet[:4] != MAGIC:
        raise ValueError("Invalid watermark packet")
    length = struct.unpack(">H", packet[12:14])[0]
    if length + 82 != len(packet) or zlib.crc32(packet[:-4]) != struct.unpack(">I", packet[-4:])[0]:
        raise ValueError("Damaged watermark packet")
    engine = zlib.decompressobj()
    body = engine.decompress(packet[14:14 + length], MAX_BODY + 1)
    if (len(body) > MAX_BODY or not engine.eof or engine.unused_data or engine.unconsumed_tail
            or len(body) < BODY.size):
        raise ValueError("Invalid watermark body")
    source, marker, actor, audit, operation_ms, issued_ms, ulen, nlen = BODY.unpack(body[:BODY.size])
    if (source not in SOURCES or not actor or ulen > 600 or nlen > 160
            or len(body) != BODY.size + ulen + nlen or not issued_ms
            or issued_ms > 253402300799000 or operation_ms > issued_ms
            or bool(audit) != bool(operation_ms)):
        raise ValueError("Invalid watermark provenance")
    username = body[BODY.size:BODY.size + ulen].decode("utf-8")
    name = body[BODY.size + ulen:].decode("utf-8")
    if len(username) > 150 or len(name) > 40:
        raise ValueError("Invalid watermark identity")
    return {"version": 2, "source": SOURCES[source], "key_id": packet[4:12].hex(),
            "watermark_id": marker.hex(), "actor_id": actor, "username": username,
            "real_name": name, "audit_id": audit or None, "operation_at": iso(operation_ms),
            "issued_at": iso(issued_ms), "token": token}


def verify_packet(token, public_key, source):
    decoded = decode_packet(token)
    public = base64.b64decode(public_key, validate=True)
    if (len(public) != 32 or hashlib.sha256(public).hexdigest()[:16] != decoded["key_id"]
            or decoded["source"] != source):
        return False
    packet = base64.b64decode(token, validate=True)
    try:
        Ed25519PublicKey.from_public_bytes(public).verify(packet[-68:-4], DOMAIN + packet[:-68])
    except InvalidSignature:
        return False
    return True


def encode_shards(packet):
    count = (len(packet) + CHUNK_BYTES - 1) // CHUNK_BYTES
    digest = hashlib.sha256(packet).digest()[:8]
    codec = RSCodec(64)
    shards = []
    for index in range(count):
        chunk = packet[index * CHUNK_BYTES:(index + 1) * CHUNK_BYTES]
        data = b"W2" + bytes([index, count, len(chunk)]) + digest + chunk
        shards.append(base64.b64encode(bytes(codec.encode(data.ljust(191, b"\0")))).decode("ascii"))
    return shards


def decode_shard(codeword, *, erasures=()):
    if len(codeword) != 255:
        return None
    try:
        data, _, corrected = RSCodec(64).decode(codeword, erase_pos=list(erasures))
    except (ReedSolomonError, ValueError, IndexError):
        return None
    data = bytes(data)
    index, count, length = data[2:5]
    if (data[:2] != b"W2" or not 1 <= count <= 8 or index >= count
            or not 1 <= length <= CHUNK_BYTES or any(data[13 + length:])):
        return None
    return {"index": index, "count": count, "digest": data[5:13].hex(),
            "chunk": data[13:13 + length], "corrected_bytes": len(corrected)}


def assemble_shards(shards):
    groups = {}
    for shard in shards:
        group = groups.setdefault((shard["digest"], shard["count"]), {})
        old = group.get(shard["index"])
        if old and old["chunk"] != shard["chunk"]:
            continue
        if not old or shard["corrected_bytes"] < old["corrected_bytes"]:
            group[shard["index"]] = shard
    results = []
    for (digest, count), group in groups.items():
        if len(group) != count:
            continue
        packet = b"".join(group[index]["chunk"] for index in range(count))
        if hashlib.sha256(packet).hexdigest()[:16] != digest:
            continue
        try:
            result = decode_packet(base64.b64encode(packet).decode("ascii"))
        except (ValueError, UnicodeError, struct.error, zlib.error):
            continue
        result["corrected_bytes"] = sum(shard["corrected_bytes"] for shard in group.values())
        results.append(result)
    return results
