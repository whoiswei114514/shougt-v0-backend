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

MICRO_MAGIC = b"M3"
MICRO_BODY = struct.Struct(">2sB12sIIII")
MICRO_USERNAME_MAX = 5
MICRO_DATA_BYTES = 38
MICRO_PARITY_BYTES = 18
MICRO_CODEWORD_BYTES = 56
MICRO_PILOT_BYTES = bytes.fromhex("53484f33a5c3")
LSB_TILE_MAGIC = b"SL2!"


def _render_mask(seed=0x53484F55, length=255):
    state, output = seed, bytearray()
    for _ in range(length):
        state = (state * 1664525 + 1013904223) & 0xffffffff
        output.append(state >> 24)
    return bytes(output)


RENDER_MASK = _render_mask()
MICRO_RENDER_MASK = _render_mask(0x53484F33, MICRO_CODEWORD_BYTES)


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
            "micro": encode_micro(actor, operation, marker, source, issued_ms),
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


def crc16_ccitt(data):
    """Compute CRC-16/CCITT-FALSE checksum for compact provenance blocks."""
    crc = 0xFFFF
    for byte in data:
        crc ^= byte << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) & 0xFFFF if (crc & 0x8000) else (crc << 1) & 0xFFFF
    return crc


def truncate_utf8(text, limit):
    """Truncate text on UTF-8 character boundaries so encoded bytes <= limit."""
    out = bytearray()
    for char in text:
        encoded = char.encode("utf-8")
        if len(out) + len(encoded) > limit:
            break
        out.extend(encoded)
    return bytes(out)


def _parse_micro_data(data, *, corrected_bytes=0):
    if len(data) != MICRO_DATA_BYTES or data[:2] != MICRO_MAGIC:
        return None
    if struct.unpack(">H", data[36:38])[0] != crc16_ccitt(data[:36]):
        return None
    _magic, hdr, marker, actor_id, audit_id, issued_sec, op_sec = MICRO_BODY.unpack(data[:31])
    source_id = hdr & 0x03
    has_audit = bool(hdr & 0x04)
    uname_len = (hdr >> 4) & 0x0F
    if (source_id not in SOURCES or not actor_id or uname_len > MICRO_USERNAME_MAX
            or any(data[31 + uname_len:36]) or not issued_sec or issued_sec > 253402300799
            or op_sec > issued_sec or has_audit != bool(audit_id) or has_audit != bool(op_sec)):
        return None
    try:
        username_hint = data[31:31 + uname_len].decode("utf-8")
    except UnicodeDecodeError:
        return None
    micro_token = "M3:" + base64.b64encode(data).decode("ascii")
    return {
        "version": 2,
        "compact": True,
        "source": SOURCES[source_id],
        "key_id": None,
        "watermark_id": marker.hex(),
        "actor_id": actor_id,
        "username": username_hint,
        "real_name": "",
        "audit_id": audit_id or None,
        "operation_at": iso(op_sec * 1000) if op_sec else None,
        "issued_at": iso(issued_sec * 1000),
        "token": micro_token,
        "corrected_bytes": corrected_bytes,
    }


def encode_micro(actor, operation, marker, source, issued_ms):
    """Encode an RS(56, 38) compact provenance block for small-region recovery."""
    actor_id = int(actor["id"])
    audit_id = int(operation["id"]) if operation else 0
    issued_sec = int(issued_ms) // 1000
    op_sec = (millis(operation["created_at"]) // 1000) if operation else 0
    if not 1 <= actor_id <= 0xFFFFFFFF or not 0 <= audit_id <= 0xFFFFFFFF:
        raise ValueError("Compact watermark identifier exceeds uint32 range")
    if not 1 <= issued_sec <= 0xFFFFFFFF or not 0 <= op_sec <= issued_sec:
        raise ValueError("Compact watermark timestamp out of range")
    uname = truncate_utf8(actor["username"], MICRO_USERNAME_MAX)
    hdr = (SOURCE_IDS[source] & 0x03) | ((1 if audit_id else 0) << 2) | ((len(uname) & 0x0F) << 4)
    body = (MICRO_BODY.pack(MICRO_MAGIC, hdr, bytes.fromhex(marker), actor_id,
                            audit_id, issued_sec, op_sec)
            + uname.ljust(MICRO_USERNAME_MAX, b"\0"))
    msg = body + struct.pack(">H", crc16_ccitt(body))
    return base64.b64encode(bytes(RSCodec(MICRO_PARITY_BYTES).encode(msg))).decode("ascii")


def decode_micro(codeword, *, erasures=()):
    """Decode and CRC-verify an RS(56, 38) compact provenance codeword."""
    if len(codeword) != MICRO_CODEWORD_BYTES:
        return None
    try:
        data, _, corrected = RSCodec(MICRO_PARITY_BYTES).decode(codeword, erase_pos=list(erasures))
    except (ReedSolomonError, ValueError, IndexError):
        return None
    return _parse_micro_data(bytes(data), corrected_bytes=len(corrected))


def decode_micro_token(token):
    """Parse and validate a serialized M3: compact provenance token."""
    if not isinstance(token, str) or not token.startswith("M3:"):
        raise ValueError("Invalid compact watermark token")
    try:
        raw = base64.b64decode(token[3:], validate=True)
    except (ValueError, TypeError) as error:
        raise ValueError("Invalid compact watermark token") from error
    decoded = _parse_micro_data(raw)
    if decoded is None:
        raise ValueError("Invalid compact watermark token")
    return decoded
