/**
 * NoAS DoH 网关模板（构建时注入规则，纯标准 Web API，可跑在 Worker / Node 任意环境）
 *
 * 注入占位：
 *   __TIER1__ 小档（跨源共识 ≥3，约 3.4k）
 *   __TIER2__ 中档（跨源共识 ≥2，约 29k）
 *   __ALLOW__ 白名单（含父域保护）
 *   __VERSION__ 构建版本
 */
const TIER1 = new Set(__TIER1__.map((x) => x.toLowerCase()));
const TIER2 = new Set(__TIER2__.map((x) => x.toLowerCase()));
const ALLOW = new Set(__ALLOW__.map((x) => x.toLowerCase()));
const ENDPOINTS = new Set(__ENDPOINTS__.map((x) => x.toLowerCase()));
const VERSION = __VERSION__;

const UPSTREAM = [
  "https://dns.alidns.com/dns-query",
  "https://doh.pub/dns-query",
  "https://dns.360.cn/dns-query",
];

function json(obj, status = 200) {
  return new Response(JSON.stringify(obj, null, 2), {
    status,
    headers: { "content-type": "application/json; charset=utf-8" },
  });
}

function allowed(name) {
  if (!name) return false;
  if (ALLOW.has(name)) return true;
  const parts = name.split(".");
  for (let i = 1; i < parts.length - 1; i++) {
    if (ALLOW.has(parts.slice(i).join("."))) return true;
  }
  return false;
}

function isEndpoint(name) {
  if (ENDPOINTS.has(name)) return true;
  const parts = name.split(".");
  for (let i = 1; i < parts.length - 1; i++) {
    if (ENDPOINTS.has(parts.slice(i).join("."))) return true;
  }
  return false;
}

function blocked(name, tier) {
  if (!name) return false;
  // 端点例外：人工审计过的纯广告端点，父域在白名单里也照拦
  if (isEndpoint(name)) return true;
  if (allowed(name)) return false;
  const set = tier >= 2 ? TIER2 : TIER1;
  if (set.has(name)) return true;
  const parts = name.split(".");
  for (let i = 1; i < parts.length - 1; i++) {
    if (set.has(parts.slice(i).join("."))) return true;
  }
  return false;
}

function parseQuery(bytes) {
  const dv = new DataView(bytes.buffer || bytes, bytes.byteOffset || 0);
  let off = 12;
  const labels = [];
  while (off < dv.byteLength) {
    const len = dv.getUint8(off);
    if (len === 0) { off += 1; break; }
    if ((len & 0xc0) === 0xc0) { off += 2; break; }
    const chunk = new Uint8Array(dv.buffer, dv.byteOffset + off + 1, len);
    labels.push(String.fromCharCode(...chunk));
    off += len + 1;
  }
  const qtype = dv.getUint16(off);
  return { name: labels.join(".").toLowerCase(), qtype, end: off + 4 };
}

function b64urlToBytes(s) {
  s = s.replace(/-/g, "+").replace(/_/g, "/");
  while (s.length % 4) s += "=";
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

/** 合成"拦截"应答：A→0.0.0.0，AAAA→::，其它类型→NXDOMAIN 风格空答 */
function blockedResponse(query, qtype, end) {
  const head = new Uint8Array(query.slice(0, end));   // 头部 + 问题区原样带回
  const answer = (qtype === 1 || qtype === 28) ? 1 : 0;
  head[2] = 0x81; head[3] = 0x80;                     // QR=1 RD=1 RA=1
  head[6] = 0; head[7] = answer ? 1 : 0;
  head[8] = 0; head[9] = 0; head[10] = 0; head[11] = 0;
  if (!answer) {
    head[3] = 0x83;                                   // NXDOMAIN
    return head;
  }
  const out = new Uint8Array(head.length + 16);
  out.set(head, 0);
  const p = head.length;
  out[p] = 0xc0; out[p + 1] = 0x0c;                    // 指向问题区的名字
  out[p + 2] = qtype === 1 ? 0x00 : 0x1c;              // TYPE
  out[p + 3] = 0x01;
  out[p + 4] = 0x00; out[p + 5] = 0x00; out[p + 6] = 0x00; out[p + 7] = 60;  // TTL 60
  out[p + 8] = 0x00; out[p + 9] = qtype === 1 ? 4 : 16;
  return out;
}

async function upstream(bytes) {
  for (const u of UPSTREAM) {
    try {
      const r = await fetch(u, {
        method: "POST",
        headers: { "content-type": "application/dns-message", accept: "application/dns-message" },
        body: bytes,
      });
      if (r.ok) return await r.arrayBuffer();
    } catch (e) { /* 换下一个 */ }
  }
  return null;
}

async function handle(request, env, ctx) {
  const url = new URL(request.url);

  if (url.pathname === "/health") {
    return json({ ok: true, version: VERSION, tier1: TIER1.size, tier2: TIER2.size,
                  allowlist: ALLOW.size, endpoints: ENDPOINTS.size, upstream: UPSTREAM.length });
  }
  if (url.pathname === "/check") {
    const q = (url.searchParams.get("q") || "").toLowerCase();
    const tier = Number(url.searchParams.get("tier") || 1);
    return json({ domain: q, blocked: blocked(q, tier), tier, version: VERSION });
  }
  if (!/^\/dns-query$/.test(url.pathname)) {
    return new Response("NoAS · /dns-query 或 /check 或 /health", {
      status: 404, headers: { "content-type": "text/plain; charset=utf-8" },
    });
  }

  let bytes;
  if (request.method === "POST") {
    bytes = new Uint8Array(await request.arrayBuffer());
  } else {
    const dns = url.searchParams.get("dns");
    if (!dns) return json({ error: "缺少 dns 参数（DoH 要求 GET ?dns=<base64url> 或 POST）" }, 400);
    bytes = b64urlToBytes(dns);
  }
  if (bytes.byteLength < 17) return json({ error: "报文过短" }, 400);

  const { name, qtype, end } = parseQuery(bytes);
  const tier = Number(url.searchParams.get("tier") || 1);
  if (!name) return new Response("bad query", { status: 400 });

  if (blocked(name, tier)) {
    if (ctx && ctx.waitUntil) ctx.waitUntil(Promise.resolve());
    return new Response(blockedResponse(bytes, qtype, end), {
      headers: { "content-type": "application/dns-message", "x-noas": "blocked", "x-noas-ver": VERSION },
    });
  }
  const buf = await upstream(bytes);
  if (!buf) {
    return new Response("上游不可用", { status: 502, headers: { "x-noas": "upstream-fail" } });
  }
  return new Response(buf, {
    headers: { "content-type": "application/dns-message", "x-noas": "pass", "x-noas-ver": VERSION },
  });
}

export default { fetch: handle };
