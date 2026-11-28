import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import worker, {
  buildMailIngestEvent,
  decodeRfc2047,
  extractPlainTextBody,
  parseRawHeaders,
  signPayload,
  verifyCloudflareDmarc,
} from "./worker.js";

function toStream(strOrBytes) {
  const bytes = typeof strOrBytes === "string" ? new TextEncoder().encode(strOrBytes) : strOrBytes;
  return new ReadableStream({
    start(controller) {
      controller.enqueue(bytes);
      controller.close();
    },
  });
}

test("verifyCloudflareDmarc trusts only the topmost mx.cloudflare.net header", () => {
  const valid = parseRawHeaders(
    "Authentication-Results: mx.cloudflare.net; spf=pass; dkim=pass; dmarc=pass\r\n" +
      "From: 示例用户 <example001@st.shou.edu.cn>\r\n",
  );
  assert.equal(verifyCloudflareDmarc(valid), true);

  const spoofedSecondHeader = parseRawHeaders(
    "Authentication-Results: mx.cloudflare.net; spf=fail; dkim=none; dmarc=fail\r\n" +
      "Authentication-Results: mx.cloudflare.net; spf=pass; dkim=pass; dmarc=pass\r\n",
  );
  assert.equal(verifyCloudflareDmarc(spoofedSecondHeader), false);

  const nonCloudflareTop = parseRawHeaders(
    "Authentication-Results: evil.attacker.example; dmarc=pass\r\n" +
      "Authentication-Results: mx.cloudflare.net; dmarc=pass\r\n",
  );
  assert.equal(verifyCloudflareDmarc(nonCloudflareTop), false);
});

test("decodeRfc2047 decodes UTF-8 and GB18030 Base64 display names", () => {
  const utf8Name = Buffer.from("示例用户", "utf8").toString("base64");
  assert.equal(
    decodeRfc2047(`=?UTF-8?B?${utf8Name}?= <example001@st.shou.edu.cn>`),
    "示例用户 <example001@st.shou.edu.cn>",
  );
  // GBK/GB2312 bytes for "示例用户"
  const gbkHex = Buffer.from([0xca, 0xbe, 0xc0, 0xfd, 0xd3, 0xc3, 0xbb, 0xa7]).toString("base64");
  assert.equal(
    decodeRfc2047(`=?gb2312?B?${gbkHex}?= <example001@st.shou.edu.cn>`),
    "示例用户 <example001@st.shou.edu.cn>",
  );
});

test("buildMailIngestEvent rejects duplicate From headers", () => {
  const raw =
    "Authentication-Results: mx.cloudflare.net; spf=pass; dkim=pass; dmarc=pass\r\n" +
    "From: 示例用户 <example001@st.shou.edu.cn>\r\n" +
    "From: 他人 <other@st.shou.edu.cn>\r\n" +
    "Message-ID: <dup@st.shou.edu.cn>\r\n" +
    "Content-Type: text/plain; charset=utf-8\r\n\r\n" +
    "SHOU-VERIFY:abc123\r\n";
  assert.throws(
    () => buildMailIngestEvent({ rawBytes: new TextEncoder().encode(raw), recipient: "renzheng@shouguatian.com" }),
    /Exactly one From header/,
  );
});

test("extractPlainTextBody handles multipart/alternative base64 and quoted-printable", () => {
  const plainB64 = Buffer.from("shou瓜田高级认证\nSHOU-VERIFY:test-envelope-1\n", "utf8").toString("base64");
  const rawMultipart =
    "Content-Type: multipart/alternative; boundary=\"bnd-123\"\r\n\r\n" +
    "--bnd-123\r\n" +
    "Content-Type: text/plain; charset=utf-8\r\n" +
    "Content-Transfer-Encoding: base64\r\n\r\n" +
    `${plainB64}\r\n` +
    "--bnd-123\r\n" +
    "Content-Type: text/html; charset=utf-8\r\n\r\n" +
    "<p>ignored</p>\r\n" +
    "--bnd-123--\r\n";
  assert.equal(
    extractPlainTextBody(new TextEncoder().encode(rawMultipart)).trim(),
    "shou瓜田高级认证\nSHOU-VERIFY:test-envelope-1",
  );

  const rawQp =
    "Content-Type: text/plain; charset=utf-8\r\n" +
    "Content-Transfer-Encoding: quoted-printable\r\n\r\n" +
    "SHOU-VERIFY:=61=62=63=\r\n123\r\n";
  assert.equal(extractPlainTextBody(new TextEncoder().encode(rawQp)).trim(), "SHOU-VERIFY:abc123");
});

test("signPayload produces exact HMAC-SHA256 hex matching Node crypto", async () => {
  const secret = "test-secret-0123456789";
  const ts = "1795843200";
  const body = '{"hello":"world"}';
  const expected = crypto.createHmac("sha256", secret).update(`${ts}.${body}`).digest("hex");
  const actual = await signPayload(secret, ts, body);
  assert.equal(actual, expected);
});

test("worker.email posts signed event for valid mail and rejects invalid DMARC", async () => {
  const utf8From = Buffer.from("示例用户", "utf8").toString("base64");
  const validRaw =
    "Authentication-Results: mx.cloudflare.net; spf=pass; dkim=pass; dmarc=pass\r\n" +
    `From: =?UTF-8?B?${utf8From}?= <example001@st.shou.edu.cn>\r\n` +
    "Message-ID: <msg-001@st.shou.edu.cn>\r\n" +
    "Content-Type: text/plain; charset=utf-8\r\n\r\n" +
    "shou瓜田高级认证\r\nSHOU-VERIFY:envelope-xyz\r\n";

  const calls = [];
  const origFetch = globalThis.fetch;
  globalThis.fetch = async (url, init) => {
    calls.push({ url, init });
    return new Response(JSON.stringify({ id: "1", status: "awaiting_review" }), { status: 200 });
  };
  try {
    let rejected = null;
    await worker.email(
      {
        to: "renzheng@shouguatian.com",
        raw: toStream(validRaw),
        rawSize: validRaw.length,
        setReject(reason) {
          rejected = reason;
        },
      },
      {
        INGEST_URL: "https://shouguatian.com/api/security/mail-ingest/",
        EXPECTED_RECIPIENT: "renzheng@shouguatian.com",
        SHOUGT_MAIL_INGEST_SECRET: "unit-test-secret",
      },
      {},
    );
    assert.equal(rejected, null);
    assert.equal(calls.length, 1);
    assert.equal(calls[0].url, "https://shouguatian.com/api/security/mail-ingest/");
    const parsed = JSON.parse(calls[0].init.body);
    assert.equal(parsed.recipient, "renzheng@shouguatian.com");
    assert.equal(parsed.authenticated_sender, "example001@st.shou.edu.cn");
    assert.equal(parsed.from_header, "示例用户 <example001@st.shou.edu.cn>");
    assert.equal(parsed.dmarc_pass, true);
    assert.equal(parsed.message_id, "<msg-001@st.shou.edu.cn>");
    assert.match(parsed.body, /SHOU-VERIFY:envelope-xyz/);

    const ts = calls[0].init.headers["X-Shou-Mail-Time"];
    const expectedSig = crypto
      .createHmac("sha256", "unit-test-secret")
      .update(`${ts}.${calls[0].init.body}`)
      .digest("hex");
    assert.equal(calls[0].init.headers["X-Shou-Mail-Signature"], expectedSig);

    // Invalid DMARC must reject without calling fetch
    const badRaw = validRaw.replace("dmarc=pass", "dmarc=fail");
    let badRejected = null;
    await worker.email(
      {
        to: "renzheng@shouguatian.com",
        raw: toStream(badRaw),
        rawSize: badRaw.length,
        setReject(reason) {
          badRejected = reason;
        },
      },
      {
        INGEST_URL: "https://shouguatian.com/api/security/mail-ingest/",
        EXPECTED_RECIPIENT: "renzheng@shouguatian.com",
        SHOUGT_MAIL_INGEST_SECRET: "unit-test-secret",
      },
      {},
    );
    assert.equal(badRejected, "DMARC authentication failed");
    assert.equal(calls.length, 1);
  } finally {
    globalThis.fetch = origFetch;
  }
});
