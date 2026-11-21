// Pages Function：/dns-query 的 DoH 端点。
//
// 为什么需要这一层：workers.dev 子域在国内被阻断（实测 curl 000/超时 6.2s），
// 而 pages.dev 可达（200）。用 Pages 这个"可达域名"做前端。
//
// 两级处理，为的是把最常见的那类请求（查广告域）彻底留在边缘：
//   ① lite 命中 → 这里直接回 0.0.0.0，不跳 Worker。广告域占查询量的多数，
//      而 lite 是零误伤最小集，命中即拦与 Worker 判定结果一致，省掉一整跳。
//   ② lite 未命中 → 转发 Worker，走全量规则（mid 21 万条）+ 缓存 + 上游竞速。
//
// lite 列表走同 zone 静态文件（CDN 缓存 + isolate 内存 10 分钟），冷启动一次 ~30ms，
// 之后命中判定 0ms。白名单已在构建期排除，lite 与本域白名单无直接交集（16 条白名单
// 父域下的纯广告端点是端点例外语义，本就应该拦），因此这里不需要再查白名单。
const LITE_URL = "https://noas-cdn.pages.dev/subs/lite/domains.txt";
const WORKER_URL = "https://noas-doh.199999510.workers.dev";
const LITE_TTL_MS = 600000;

let LITE = null;
let LITE_AT = 0;

// isolate 内结果缓存：手机端高频域名（同一个 App 反复查同一域）第二次直接命中，
// 完全不再跳 Worker。只在 isolate 存活期内有效，30 秒过期 —— 宁可多回源，不吃旧 IP。
const MEM_MAX = 800;
const MEM_TTL_MS = 30000;
const MEM = new Map();

function memGet(key) {
  const e = MEM.get(key);
  if (!e) return null;
  if (Date.now() > e.exp) { MEM.delete(key); return null; }
  return e.buf;
}

function memPut(key, buf) {
  if (MEM.size >= MEM_MAX) {
    const oldest = MEM.keys().next().value;
    if (oldest !== undefined) MEM.delete(oldest);
  }
  MEM.set(key, { buf, exp: Date.now() + MEM_TTL_MS });
}

async function liteSet() {
  if (LITE && Date.now() - LITE_AT < LITE_TTL_MS) return LITE;
  try {
    const r = await fetch(LITE_URL, { cf: { cacheTtl: 600, cacheEverything: true } });
    if (!r.ok) return LITE;
    const txt = await r.text();
    const s = new Set();
    for (const line of txt.split("\n")) {
      const d = line.trim();
      if (d && d[0] !== "#") s.add(d);
    }
    if (s.size > 9000) {          // 规模异常就当没拿到，整条退回 Worker 判定，绝不误拦
      LITE = s;
      LITE_AT = Date.now();
    }
  } catch (e) { /* 拉不到就整条透传 Worker */ }
  return LITE;
}

function parseQuery(bytes) {
  if (bytes.length < 12) return null;
  const qd = (bytes[4] << 8) | bytes[5];
  if (qd < 1) return null;
  const labels = [];
  let off = 12;
  while (off < bytes.length) {
    const len = bytes[off];
    if (len === 0) { off += 1; break; }
    if (len > 63 || off + 1 + len > bytes.length) return null;
    labels.push(String.fromCharCode(...bytes.slice(off + 1, off + 1 + len)));
    off += 1 + len;
  }
  if (!labels.length) return null;
  const qtype = off + 2 <= bytes.length ? (bytes[off] << 8) | bytes[off + 1] : 1;
  return { name: labels.join(".").toLowerCase(), qtype, end: off + 4 };
}

// lite 是"域后缀"语义：a.b.tracker.com 命中 tracker.com 也算拦
function hitLite(set, name) {
  if (!name) return false;
  let d = name;
  for (let i = 0; i < 6; i++) {
    if (set.has(d)) return true;
    const p = d.indexOf(".");
    if (p < 0) break;
    d = d.slice(p + 1);
  }
  return false;
}

function blockedResponse(bytes, qtype, end) {
  const head = bytes.slice(0, end);
  const withA = qtype === 1 || qtype === 28;
  const out = new Uint8Array(head.length + (withA ? 16 : 0));
  out.set(head, 0);
  const flags = 0x8180;                       // QR | RD | RA，NOERROR
  out[2] = (flags >> 8) & 0xff; out[3] = flags & 0xff;
  out[6] = 0; out[7] = withA ? 1 : 0;         // ANCOUNT
  out[8] = 0; out[9] = 0; out[10] = 0; out[11] = 0;
  if (withA) {
    const o = head.length;
    out[o] = 0xc0; out[o + 1] = 0x0c;         // 指回 question 的名字
    out[o + 2] = 0; out[o + 3] = qtype === 1 ? 1 : 28;
    out[o + 4] = 0; out[o + 5] = 1;           // IN
    out[o + 6] = 0; out[o + 7] = 0; out[o + 8] = 0; out[o + 9] = 60;   // TTL 60s
    out[o + 10] = 0;
    out[o + 11] = qtype === 1 ? 4 : 16;       // rdlength
    // A 记录全 0 = 0.0.0.0；AAAA 记录全 0 = ::，两者都是"黑洞"语义，客户端会直接失败
  }
  return out;
}

export async function onRequest(context) {
  const { request, next } = context;
  const url = new URL(request.url);
  if (url.pathname !== "/dns-query") return next();

  const pr = url.searchParams.get("probe");
  if (pr) {                                   // 诊断通道：读 Worker 的边缘视角
    const res = await fetch(WORKER_URL + "/health?probe=" + encodeURIComponent(pr), {
      headers: { "user-agent": "NoAS-pages" }, cache: "no-store",
    });
    return proxied(res);
  }

  const ck = request.method === "GET" ? request.url : null;
  if (ck && typeof caches !== "undefined" && caches.default) {
    try {
      const hit = await caches.default.match(ck);
      if (hit) return withPath(hit, "pages-cache");
    } catch (e) { /* 缓存不可用就当没命中 */ }
  }

  let bytes;
  if (request.method === "POST") {
    bytes = new Uint8Array(await request.arrayBuffer());
  } else {
    const dns = url.searchParams.get("dns");
    if (!dns) return new Response("缺少 dns 参数（RFC8484 要求 GET ?dns= 或 POST）", { status: 400 });
    const b64 = dns.replace(/-/g, "+").replace(/_/g, "/");
    const pad = b64.length % 4 ? "=".repeat(4 - (b64.length % 4)) : "";
    const bin = atob(b64 + pad);
    bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  }
  if (bytes.length < 17) return new Response("报文过短", { status: 400 });

  const q = parseQuery(bytes);
  if (q) {
    const mem = memGet(q.name + "|" + q.qtype);
    if (mem) return new Response(mem, {
      headers: { "content-type": "application/dns-message", "x-noas": "cache-hit",
                 "x-noas-path": "pages-mem", "x-noas-ver": "lite" },
    });
  }
  const set = await liteSet();
  if (q && set && hitLite(set, q.name)) {
    return new Response(blockedResponse(bytes, q.qtype, q.end), {
      headers: {
        "content-type": "application/dns-message",
        "x-noas": "blocked", "x-noas-path": "pages-local", "x-noas-ver": "lite",
      },
    });
  }

  const res = await fetch(WORKER_URL + "/dns-query" + url.search, {
    method: request.method,
    headers: {
      "content-type": request.headers.get("content-type") || "application/dns-message",
      accept: "application/dns-message",
      "user-agent": "NoAS-pages",
    },
    body: request.method === "POST" ? bytes : undefined,
    cache: "no-store",
  });
  const headers = pickHeaders(res);
  const buf = await res.arrayBuffer();
  const ok = res.status === 200 && buf.byteLength > 17;
  if (ok && q) memPut(q.name + "|" + q.qtype, buf);
  const out = new Response(buf, { status: res.status, headers });
  if (ok && ck && typeof caches !== "undefined" && caches.default && context.waitUntil) {
    try {
      const ch = new Headers(headers);          // Headers 不能展开成对象，必须显式 copy
      ch.set("cache-control", "max-age=60");
      const copy = new Response(buf, { headers: ch });
      context.waitUntil(caches.default.put(ck, copy));
    } catch (e) { /* 写缓存失败不影响应答 */ }
  }
  return out;
}

function pickHeaders(res) {
  const out = new Headers();
  for (const [k, v] of res.headers) {
    if (k === "content-type" || k.toLowerCase().startsWith("x-noas")) out.set(k, v);
  }
  if (!out.has("content-type")) out.set("content-type", "application/dns-message");
  if (!out.has("x-noas-path")) out.set("x-noas-path", "pages");   // 标记经过 Pages 层
  return out;
}

function withPath(res, path) {
  const h = new Headers(res.headers);
  h.set("x-noas-path", path);
  return new Response(res.body, { status: res.status, headers: h });
}

async function proxied(res) {
  return new Response(res.body, { status: res.status, headers: pickHeaders(res) });
}
