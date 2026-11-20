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
const WILD = (__WILD__ || []).map((x) => x.toLowerCase());
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

function matchSet(set, name) {
  if (set.has(name)) return true;
  const parts = name.split(".");
  for (let i = 1; i < parts.length - 1; i++) {
    if (set.has(parts.slice(i).join("."))) return true;
  }
  // 通配规则：*.example.com 命中其任意多级子域
  for (const w of WILD) {
    const suffix = w.slice(2);
    if (name.endsWith("." + suffix) && name.length > suffix.length + 1) return true;
  }
  return false;
}

function cnameTargets(buf) {
  // 扫描应答里的 CNAME（type=5）记录，返回链上的所有目标域
  const out = [];
  try {
    const dv = new DataView(buf.buffer || buf, buf.byteOffset || 0);
    const total = dv.byteLength;
    let off = 12, qd = dv.getUint16(4);
    for (let i = 0; i < qd && off < total; i++) {
      off = skipName(dv, off) + 4;
    }
    const an = dv.getUint16(6);
    for (let i = 0; i < an && off < total; i++) {
      off = skipName(dv, off);
      const type = dv.getUint16(off); off += 8;              // type/class + ttl
      const rdlen = dv.getUint16(off); off += 2;
      if (type === 5) {
        const t = readName(dv, off);
        if (t) out.push(t.toLowerCase());
      }
      off += rdlen;
    }
  } catch (e) { /* 报文异常就放弃反隐蔽，不影响正常解析 */ }
  return out;
}

function readName(dv, off) {
  const labels = [];
  let p = off, jumps = 0;
  while (p < dv.byteLength && jumps < 8) {
    const len = dv.getUint8(p);
    if (len === 0) break;
    if ((len & 0xc0) === 0xc0) {
      p = dv.getUint16(p) & 0x3fff; jumps++;
      continue;
    }
    labels.push(String.fromCharCode(...new Uint8Array(dv.buffer, dv.byteOffset + p + 1, len)));
    p += len + 1;
  }
  return labels.join(".").toLowerCase();
}

function skipName(dv, off) {
  let p = off, jumps = 0;
  while (p < dv.byteLength && jumps < 8) {
    const len = dv.getUint8(p);
    if (len === 0) return p + 1;
    if ((len & 0xc0) === 0xc0) return p + 2;
    p += len + 1;
  }
  return p;
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
  return matchSet(set, name);
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
    const cn = (url.searchParams.get("cname") || "").toLowerCase();
    const viaCname = cn ? blocked(cn, tier) : false;
    return json({ domain: q, blocked: blocked(q, tier), cname: cn || null,
                  cname_blocked: cn ? viaCname : null, tier, version: VERSION });
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
  // CNAME 反隐蔽：第一方子域 CNAME 到追踪者时，按追踪者判定并直接拦掉
  const chain = cnameTargets(buf);
  for (const t of chain) {
    if (blocked(t, tier)) {
      return new Response(blockedResponse(bytes, qtype, end), {
        headers: { "content-type": "application/dns-message", "x-noas": "blocked-cname",
                   "x-noas-target": t, "x-noas-ver": VERSION },
      });
    }
  }
  return new Response(buf, {
    headers: { "content-type": "application/dns-message", "x-noas": "pass", "x-noas-ver": VERSION },
  });
}

export default { fetch: handle };
