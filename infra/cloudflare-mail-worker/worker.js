/**
 * Cloudflare Email Worker for renzheng@shouguatian.com.
 *
 * Verifies Cloudflare's topmost Authentication-Results header (mx.cloudflare.net + dmarc=pass),
 * decodes the single From header (RFC 2047 UTF-8/GBK/GB18030) and plain-text MIME body,
 * and posts an HMAC-SHA256 signed JSON event to the backend /security/mail-ingest/ endpoint.
 */

const MAX_RAW_BYTES = 1_048_576;
const MAX_INGEST_BYTES = 100_000;

const HEADER_END_CRLF = new Uint8Array([13, 10, 13, 10]);
const HEADER_END_LF = new Uint8Array([10, 10]);

function findByteSequence(haystack, needle, start = 0) {
  outer: for (let i = start; i <= haystack.length - needle.length; i++) {
    for (let j = 0; j < needle.length; j++) {
      if (haystack[i + j] !== needle[j]) continue outer;
    }
    return i;
  }
  return -1;
}

function splitHeaderAndBodyBytes(rawBytes) {
  const crlfIdx = findByteSequence(rawBytes, HEADER_END_CRLF);
  const lfIdx = findByteSequence(rawBytes, HEADER_END_LF);
  if (crlfIdx !== -1 && (lfIdx === -1 || crlfIdx <= lfIdx)) {
    return {
      headerBytes: rawBytes.subarray(0, crlfIdx),
      bodyBytes: rawBytes.subarray(crlfIdx + 4),
    };
  }
  if (lfIdx !== -1) {
    return {
      headerBytes: rawBytes.subarray(0, lfIdx),
      bodyBytes: rawBytes.subarray(lfIdx + 2),
    };
  }
  return { headerBytes: rawBytes, bodyBytes: new Uint8Array(0) };
}

function normalizeCharset(charset) {
  const lower = (charset || "utf-8").trim().replace(/^["']|["']$/g, "").toLowerCase();
  if (lower === "gbk" || lower === "gb2312" || lower === "cp936" || lower === "x-gbk") {
    return "gb18030";
  }
  if (lower === "us-ascii" || lower === "ascii") {
    return "utf-8";
  }
  return lower || "utf-8";
}

function decodeBytes(bytes, charset = "utf-8") {
  const normalized = normalizeCharset(charset);
  try {
    return new TextDecoder(normalized, { fatal: false }).decode(bytes);
  } catch {
    return new TextDecoder("utf-8", { fatal: false }).decode(bytes);
  }
}

function decodeBase64ToBytes(input) {
  const cleaned = (input || "").replace(/[\r\n\s]+/g, "").replace(/-/g, "+").replace(/_/g, "/");
  if (!cleaned) return new Uint8Array(0);
  const padLen = (4 - (cleaned.length % 4)) % 4;
  const padded = cleaned + "=".repeat(padLen);
  const bin = atob(padded);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) {
    out[i] = bin.charCodeAt(i);
  }
  return out;
}

function decodeQuotedPrintableToBytes(input, underscoreAsSpace = false) {
  const stripped = (input || "").replace(/=\r?\n/g, "");
  const out = [];
  for (let i = 0; i < stripped.length; i++) {
    const ch = stripped[i];
    if (underscoreAsSpace && ch === "_") {
      out.push(0x20);
      continue;
    }
    if (ch === "=" && i + 2 < stripped.length && /^[0-9a-fA-F]{2}$/.test(stripped.slice(i + 1, i + 3))) {
      out.push(parseInt(stripped.slice(i + 1, i + 3), 16));
      i += 2;
      continue;
    }
    const code = stripped.charCodeAt(i);
    if (code <= 0xff) {
      out.push(code);
    } else {
      const encoded = new TextEncoder().encode(ch);
      for (const b of encoded) out.push(b);
    }
  }
  return new Uint8Array(out);
}

export function decodeRfc2047(value) {
  if (typeof value !== "string") return "";
  const tokenRe = /=\?([^?]+)\?([bBqQ])\?([^?]*)\?=/g;
  const normalized = value.replace(/\?=\s+=\?/g, "?==?");
  return normalized.replace(tokenRe, (full, charset, encoding, text) => {
    try {
      const bytes =
        encoding.toUpperCase() === "B"
          ? decodeBase64ToBytes(text)
          : decodeQuotedPrintableToBytes(text, true);
      return decodeBytes(bytes, charset);
    } catch {
      return full;
    }
  });
}

export function parseRawHeaders(rawHeaderText) {
  const lines = (rawHeaderText || "").split(/\r?\n/);
  const headers = [];
  let currentName = null;
  let currentValue = "";
  for (const line of lines) {
    if (!line) continue;
    if (/^[ \t]/.test(line) && currentName !== null) {
      currentValue += " " + line.trim();
      continue;
    }
    if (currentName !== null) {
      headers.push([currentName, currentValue.trim()]);
    }
    const colon = line.indexOf(":");
    if (colon === -1) {
      currentName = null;
      currentValue = "";
      continue;
    }
    currentName = line.slice(0, colon).trim().toLowerCase();
    currentValue = line.slice(colon + 1).trim();
  }
  if (currentName !== null) {
    headers.push([currentName, currentValue.trim()]);
  }
  return headers;
}

export function verifyCloudflareDmarc(headers) {
  const firstAuth = headers.find(([name]) => name === "authentication-results");
  if (!firstAuth) return false;
  const val = firstAuth[1].trim();
  if (!/^(?:[a-z0-9-]+\.)?mx\.cloudflare\.net\b/i.test(val)) return false;
  if (!/\bdmarc=pass\b/i.test(val)) return false;
  if (/\bdmarc=(?:fail|none|temperror|permerror|bestguesspass)\b/i.test(val)) return false;
  return true;
}

function parseContentType(value) {
  const raw = (value || "text/plain; charset=utf-8").trim();
  const [mimePart, ...paramParts] = raw.split(";");
  const mime = mimePart.trim().toLowerCase() || "text/plain";
  const params = {};
  for (const part of paramParts) {
    const eq = part.indexOf("=");
    if (eq === -1) continue;
    const k = part.slice(0, eq).trim().toLowerCase();
    let v = part.slice(eq + 1).trim();
    if ((v.startsWith('"') && v.endsWith('"')) || (v.startsWith("'") && v.endsWith("'"))) {
      v = v.slice(1, -1);
    }
    params[k] = v;
  }
  return { mime, params };
}

function parseSingleFromHeader(headers) {
  const fromHeaders = headers.filter(([name]) => name === "from");
  if (fromHeaders.length !== 1) {
    throw new Error("Exactly one From header is required");
  }
  const decoded = decodeRfc2047(fromHeaders[0][1]).replace(/[\r\n]+/g, " ").trim();
  if (!decoded || decoded.length > 1024) {
    throw new Error("Invalid From header");
  }
  const emailMatches = decoded.match(/[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+/g) || [];
  if (emailMatches.length !== 1) {
    throw new Error("From header must contain exactly one email address");
  }
  const authenticatedSender = emailMatches[0].toLowerCase();
  const angleMatch = decoded.match(/^(.*?)<\s*([^<>\s]+@[^<>\s]+)\s*>$/);
  let fromHeader = decoded;
  if (angleMatch) {
    let displayName = angleMatch[1].trim();
    if (displayName.startsWith('"') && displayName.endsWith('"') && displayName.length >= 2) {
      displayName = displayName.slice(1, -1).replace(/\\"/g, '"').trim();
    }
    if (!displayName) {
      throw new Error("From header display name is required");
    }
    const safeDisplay = /[",;<>()[\]:@\\]/.test(displayName)
      ? `"${displayName.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`
      : displayName;
    fromHeader = `${safeDisplay} <${authenticatedSender}>`;
  } else {
    throw new Error("From header must include display name");
  }
  return { authenticatedSender, fromHeader };
}

function decodeBodyBytes(bodyBytes, encoding, charset) {
  const enc = (encoding || "7bit").trim().toLowerCase();
  if (enc === "base64") {
    const rawAscii = new TextDecoder("latin1").decode(bodyBytes);
    return decodeBytes(decodeBase64ToBytes(rawAscii), charset);
  }
  if (enc === "quoted-printable") {
    const rawAscii = new TextDecoder("latin1").decode(bodyBytes);
    return decodeBytes(decodeQuotedPrintableToBytes(rawAscii, false), charset);
  }
  return decodeBytes(bodyBytes, charset);
}

function stripHtmlToText(html) {
  return html
    .replace(/<style[\s\S]*?<\/style>/gi, " ")
    .replace(/<script[\s\S]*?<\/script>/gi, " ")
    .replace(/<(?:br|\/p|\/div|\/li|\/tr)\b[^>]*>/gi, "\n")
    .replace(/<[^>]+>/g, "")
    .replace(/&nbsp;/gi, " ")
    .replace(/&lt;/gi, "<")
    .replace(/&gt;/gi, ">")
    .replace(/&amp;/gi, "&")
    .replace(/\r\n/g, "\n")
    .trim();
}

function splitMultipartBytes(bodyBytes, boundary) {
  const markerBytes = new TextEncoder().encode(`--${boundary}`);
  const parts = [];
  let pos = findByteSequence(bodyBytes, markerBytes, 0);
  while (pos !== -1) {
    let after = pos + markerBytes.length;
    if (bodyBytes[after] === 45 && bodyBytes[after + 1] === 45) break; // -- closing
    if (bodyBytes[after] === 13 && bodyBytes[after + 1] === 10) after += 2;
    else if (bodyBytes[after] === 10) after += 1;
    const nextPos = findByteSequence(bodyBytes, markerBytes, after);
    if (nextPos === -1) break;
    let end = nextPos;
    if (end >= 2 && bodyBytes[end - 2] === 13 && bodyBytes[end - 1] === 10) end -= 2;
    else if (end >= 1 && bodyBytes[end - 1] === 10) end -= 1;
    parts.push(bodyBytes.subarray(after, end));
    pos = nextPos;
  }
  return parts;
}

export function extractPlainTextBody(rawBytes) {
  const { headerBytes, bodyBytes } = splitHeaderAndBodyBytes(rawBytes);
  const headers = parseRawHeaders(new TextDecoder("latin1").decode(headerBytes));
  const ctHeader = headers.find(([name]) => name === "content-type")?.[1];
  const cteHeader = headers.find(([name]) => name === "content-transfer-encoding")?.[1];
  const { mime, params } = parseContentType(ctHeader);

  if (mime.startsWith("multipart/") && params.boundary) {
    const subParts = splitMultipartBytes(bodyBytes, params.boundary);
    let htmlFallback = "";
    for (const partBytes of subParts) {
      const partText = extractPlainTextBody(partBytes);
      if (partText && partText.split(/\r?\n/).some((line) => line.trim().startsWith("SHOU-VERIFY:"))) {
        return partText;
      }
      if (!htmlFallback && partText) {
        htmlFallback = partText;
      }
    }
    return htmlFallback;
  }

  const decoded = decodeBodyBytes(bodyBytes, cteHeader, params.charset || "utf-8").replace(/\r\n/g, "\n");
  if (mime === "text/html") {
    return stripHtmlToText(decoded);
  }
  if (mime.startsWith("text/") || !ctHeader) {
    return decoded;
  }
  return "";
}

export async function signPayload(secret, timestamp, rawJsonBody) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw",
    enc.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const sigBuf = await crypto.subtle.sign("HMAC", key, enc.encode(`${timestamp}.${rawJsonBody}`));
  return Array.from(new Uint8Array(sigBuf))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

export function buildMailIngestEvent({ rawBytes, recipient, receivedAt = new Date().toISOString() }) {
  if (!(rawBytes instanceof Uint8Array)) {
    throw new Error("rawBytes must be Uint8Array");
  }
  if (rawBytes.length === 0 || rawBytes.length > MAX_RAW_BYTES) {
    throw new Error("Email size out of allowed bounds");
  }
  const { headerBytes } = splitHeaderAndBodyBytes(rawBytes);
  const headers = parseRawHeaders(new TextDecoder("latin1").decode(headerBytes));
  if (!verifyCloudflareDmarc(headers)) {
    throw new Error("DMARC authentication failed");
  }
  const { authenticatedSender, fromHeader } = parseSingleFromHeader(headers);
  const messageId = (headers.find(([name]) => name === "message-id")?.[1] || "").slice(0, 255);
  const body = extractPlainTextBody(rawBytes).trim();
  const hasMarker = body.split(/\r?\n/).some((line) => line.trim().startsWith("SHOU-VERIFY:"));
  if (!hasMarker) {
    throw new Error("Missing verification marker");
  }
  const event = {
    recipient,
    authenticated_sender: authenticatedSender,
    from_header: fromHeader,
    dmarc_pass: true,
    received_at: receivedAt,
    message_id: messageId,
    body,
  };
  const rawJson = JSON.stringify(event);
  if (new TextEncoder().encode(rawJson).length > MAX_INGEST_BYTES) {
    throw new Error("Verification payload exceeds 100000 bytes");
  }
  return { event, rawJson };
}

async function readStreamWithLimit(stream, limit) {
  const reader = stream.getReader();
  const chunks = [];
  let total = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > limit) {
      throw new Error("Email exceeds maximum allowed size");
    }
    chunks.push(value);
  }
  const merged = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    merged.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return merged;
}

export default {
  async email(message, env, ctx) {
    const ingestUrl = (env.INGEST_URL || "").trim();
    const secret = env.SHOUGT_MAIL_INGEST_SECRET || "";
    const expectedRecipient = (env.EXPECTED_RECIPIENT || "renzheng@shouguatian.com").trim().toLowerCase();
    if (!ingestUrl || !secret) {
      message.setReject("Verification ingest not configured");
      return;
    }
    const recipient = (message.to || "").trim().toLowerCase();
    if (recipient !== expectedRecipient) {
      message.setReject("Recipient not accepted");
      return;
    }
    if (typeof message.rawSize === "number" && message.rawSize > MAX_RAW_BYTES) {
      message.setReject("Email too large");
      return;
    }

    let rawJson;
    try {
      const rawBytes = await readStreamWithLimit(message.raw, MAX_RAW_BYTES);
      ({ rawJson } = buildMailIngestEvent({ rawBytes, recipient }));
    } catch (err) {
      message.setReject(err?.message || "Invalid verification email");
      return;
    }

    const timestamp = String(Math.floor(Date.now() / 1000));
    const signature = await signPayload(secret, timestamp, rawJson);
    const response = await fetch(ingestUrl, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Shou-Mail-Time": timestamp,
        "X-Shou-Mail-Signature": signature,
      },
      body: rawJson,
    });
    if (response.status >= 400 && response.status < 500) {
      message.setReject("Verification rejected by backend");
      return;
    }
    if (!response.ok) {
      throw new Error(`Backend ingest failed with HTTP ${response.status}`);
    }
  },
};
