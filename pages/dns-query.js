// Pages Function：DoH 端点，按「档位」服务。
//
// 为什么要有档位：客户端配置里写死一条 URL 最省事，但设备能力和需求差别很大——
// 路由器/AGH 能吞 3 万条，手机 Private DNS 只需要 2 万，低配设备只想 1 万。
// 所以把档位做成端点属性，客户端「说自己用哪档」，服务端就只按那档判定：
//
//   /dns-query            → 自动（UA / 记忆 / 请求头推断）
//   /dns-query/lite       → 1 万条，零误伤最小集
//   /dns-query/mid        → 2 万条，手机默认档
//   /dns-query/full       → 3 万条，路由器 / 桌面
//   /dns-query/auto       → 同自动
//   任意档 + ?tier=full   → 显式覆盖并记住
//   任意档 + x-noas-tier  → 同上（客户端可在请求头里声明）
//
// 「记住」用 STATS KV（noas-logkv，与 Worker 的热规则 KV 隔离，避免写爆影响热更新）。
// 写入只在该客户端第一次出现或显式改档时发生，之后只读 —— 免费 1000 写/天足够。
//
// 响应头 x-noas-tier / x-noas-tier-count 会回显实际用的档与条数，
// GET /tier 返回同一份 JSON，客户端和人都能自查「我现在走的是哪一档」。
const BASE = "https://noas-cdn.pages.dev";
const WORKER_URL = "https://noas-doh.199999510.workers.dev";
const TIERS = ["lite", "mid", "full"];
const MIN = { lite: 9000, mid: 17000, full: 25000 };   // 低于这个数说明没拉到，整条退 Worker
const LABEL = { lite: "1万", mid: "2万", full: "3万" };
const TIER_NUM = { lite: 1, mid: 2, full: 3 };   // Worker 内嵌档位用 1/2/3
const TTL_MS = 600000;

const SETS = new Map();      // tier → { s, at, count }
let LAST_ERR = "";
function setErr(m) { LAST_ERR = m; }
const TIER_MEM = new Map();  // ipHash → { tier, at }
const TIER_MEM_TTL = 600000;

const MEM_MAX = 800;
const MEM_TTL_MS = 30000;
const MEM = new Map();

// 客户端子网（/24 v4、/48 v6）：缓存必须按子网分段，否则不同地域共用同一条应答
function netKey(cip) {
  if (!cip) return "n";
  if (cip.includes(".")) return cip.split(".").slice(0, 3).join(".");
  return cip.split(":").slice(0, 3).join(":");
}

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

async function tierSet(tier, env) {
  const e = SETS.get(tier);
  if (e && Date.now() - e.at < TTL_MS) return e.s;

  // KV 里是 Worker cron 写的 JSON（{ver,count,compact:"|a|b|c"}），静态文件是纯文本行。
  // 原来的文本解析把整段 JSON 当成"一行"，size=1 永远不达标 → lite 每次冷启动都回源 195KB。
  const parse = (txt) => {
    if (!txt) return null;
    const t = String(txt).trim();
    if (t[0] === "{") {
      try {
        const j = JSON.parse(t);
        if (j && typeof j.compact === "string" && j.compact) {
          const set = new Set();
          for (const d of j.compact.split("|")) {
            const v = d.trim();
            if (v) set.add(v);
          }
          return set.size > MIN[tier] ? set : null;
        }
      } catch (x) { /* 不是 JSON 就落回文本解析 */ }
    }
    const set = new Set();
    for (const line of t.split("\n")) {
      const d = line.trim();
      if (d && d[0] !== "#") set.add(d);
    }
    return set.size > MIN[tier] ? set : null;
  };
  const adopt = (set) => {
    SETS.set(tier, { s: set, at: Date.now(), count: set.size });
    return set;
  };

  // ① lite 优先吃 Worker cron 写进 KV 的热规则（更新更快，不用等部署）
  if (tier === "lite" && env && env.RULES) {
    try {
      const kv = await env.RULES.get("lite_v1", { type: "text" });
      const set = parse(kv);
      if (set) return adopt(set);
      if (kv) setErr("kv lite_v1 不可用（" + kv.length + " 字节）");
    } catch (x) { setErr("kv " + (x && x.message ? x.message : String(x))); }
  }

  // ② 回源同 zone 静态文件（KV 没拿到或不达标时不放弃，必须再试这一条）
  try {
    const r = await fetch(BASE + "/subs/" + tier + "/domains.txt");
    if (!r.ok) { setErr("http " + r.status + " " + tier); return e ? e.s : null; }
    const txt = await r.text();
    const set = parse(txt);
    if (set) return adopt(set);
    const lines = txt.split("\n").length;
    setErr("size 不足 " + tier + "：" + lines + " 行（阈值 " + MIN[tier] + "）");
  } catch (x) {
    setErr("fetch " + tier + ": " + (x && x.message ? x.message : String(x)));
  }
  return e ? e.s : null;
}

function ipHash(request) {
  const ip = request.headers.get("cf-connecting-ip") || request.headers.get("x-real-ip") || "0.0.0.0";
  let h = 0x811c9dc5;
  for (let i = 0; i < ip.length; i++) { h ^= ip.charCodeAt(i); h = (h * 0x01000193) >>> 0; }
  return h.toString(36);
}

function uaHash(request) {
  const ua = request.headers.get("user-agent") || "";
  let h = 0x811c9dc5;
  for (let i = 0; i < ua.length; i++) { h ^= ua.charCodeAt(i); h = (h * 0x01000193) >>> 0; }
  return h.toString(36);
}

function uaTier(ua) {
  const s = (ua || "").toLowerCase();
  if (/adguard|sing-box|clash|mihomo|surge|quantumult|openwrt|router|dnsmasq|unbound|stubby/.test(s)) return "full";
  if (/android|iphone|ipad|ios|darwin|macintosh|windows/.test(s)) return "mid";
  return "lite";
}

// 档位来源：显式声明 > UA 推断。不读 KV —— 共享出口 IP 上读到别人写的档会串档，
// 而 UA 本身就能区分手机(2万)/路由器(3万)/其它(1万)，稳定且零延迟。
// KV 只在"客户端显式声明档位"时写一笔，纯粹留痕审计用，不参与判定。
async function pickTier(request, url, pathTier) {
  const explicit = (pathTier || url.searchParams.get("tier") ||
                    request.headers.get("x-noas-tier") || "").toLowerCase();
  if (TIERS.includes(explicit)) return { tier: explicit, how: "explicit", persist: true };
  return { tier: uaTier(request.headers.get("user-agent")), how: "ua", persist: false };
}

function isPreview(request) {
  try {
    const h = new URL(request.url).hostname;
    // 生产域恒为 noas-cdn.pages.dev；任何"前缀.生产域"都是预览分支
    return h !== "noas-cdn.pages.dev";
  } catch (e) { return true; }
}

async function persistTier(request, tier, env) {
  if (!env || !env.STATS) return;
  if (isPreview(request)) return;   // 预览环境与生产共用同一 KV，写入会污染生产统计：预览一律只读
  const key = "v2:t:" + ipHash(request) + ":" + uaHash(request);
  if (TIER_MEM.get(key) && TIER_MEM.get(key).tier === tier) {
    // isolate 内已记，只有首次或改档才写
    if (TIER_MEM.get(key).written) return;
  }
  try {
    await env.STATS.put(key, tier, { expirationTtl: 259200 });
    const e = TIER_MEM.get(key) || {};
    TIER_MEM.set(key, { ...e, tier, at: Date.now(), written: true });
  } catch (x) { /* 写失败不影响本次判定 */ }
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

// 后缀语义：a.b.tracker.com 命中 tracker.com 也算拦
function hitSet(set, name) {
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

function blockedResponse(bytes, qtype, end, mode) {
  const head = new Uint8Array(bytes.slice(0, end));      // 头部 + 问题区原样带回
  const nx = mode === "nxdomain";
  const refused = mode === "refused";
  const servfail = mode === "servfail";
  const answer = (nx || refused || servfail) ? 0 : ((qtype === 1 || qtype === 28) ? 1 : 0);
  const rc = nx ? 3 : refused ? 5 : servfail ? 2 : 0;
  head[2] = 0x81; head[3] = 0x80 | rc;                               // QR=1 RD=1 RA=1 + RCODE
  head[6] = 0; head[7] = answer ? 1 : 0;
  head[8] = 0; head[9] = 0; head[10] = 0; head[11] = 0;
  if (!answer) return head;
  // ANSWER 区：NAME(2)+TYPE(2)+CLASS(2)+TTL(4)+RDLEN(2)+RDATA(4 或 16)
  // 之前这里固定按 16 字节总长分配，AAAA 只写出 4 字节 rdata，报文是残的。
  const rdlen = qtype === 1 ? 4 : 16;
  const out = new Uint8Array(head.length + 12 + rdlen);  // RDATA 全 0 → A=0.0.0.0 / AAAA=::
  out.set(head, 0);
  const p = head.length;
  out[p] = 0xc0; out[p + 1] = 0x0c;
  out[p + 2] = 0x00; out[p + 3] = qtype === 1 ? 0x01 : 0x1c;
  out[p + 4] = 0x00; out[p + 5] = 0x01;
  out[p + 6] = 0x00; out[p + 7] = 0x00; out[p + 8] = 0x00; out[p + 9] = 0x3c;   // TTL 60s
  out[p + 10] = 0x00; out[p + 11] = rdlen;
  return out;
}

function pickHeaders(res) {
  const out = new Headers();
  for (const [k, v] of res.headers) {
    if (k === "content-type" || k.toLowerCase().startsWith("x-noas")) out.set(k, v);
  }
  if (!out.has("content-type")) out.set("content-type", "application/dns-message");
  if (!out.has("x-noas-path")) out.set("x-noas-path", "pages");
  return out;
}

function withPath(res, path, tier, count) {
  const h = new Headers(res.headers);
  h.set("x-noas-path", path);
  if (tier) h.set("x-noas-tier", tier);
  if (count) h.set("x-noas-tier-count", String(count));
  return new Response(res.body, { status: res.status, headers: h });
}

function proxied(res, tier, count) {
  const h = pickHeaders(res);
  if (tier) h.set("x-noas-tier", tier);
  if (count) h.set("x-noas-tier-count", String(count));
  return new Response(res.body, { status: res.status, headers: h });
}

const TIER_JSON_H = { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" };

export async function onRequest(context) {
  const { request, params, env, next, waitUntil } = context;
  const url = new URL(request.url);
  // [[tier]] 在 Pages 里可能是字符串，也可能被解析成数组/含斜杠的 catch-all 值，
  // 统一收敛成单段小写字符串，避免 toLowerCase 打在数组上变成 500。
  let pathTier = params && params.tier;
  if (Array.isArray(pathTier)) pathTier = pathTier[0];
  pathTier = String(pathTier == null ? "" : pathTier).split("/")[0].trim().toLowerCase();
  const cip = request.headers.get("cf-connecting-ip") || "";

  // 自查端点：/tier 或 /dns-query/...?info=1
  if (url.pathname === "/tier" || url.searchParams.get("info") === "1") {
    const p = await pickTier(request, url, pathTier);
    const set = await tierSet(p.tier, env);
    return new Response(JSON.stringify({
      tier: p.tier, label: LABEL[p.tier], count: set ? set.size : 0,
      set_loaded: !!set, err: LAST_ERR,
      source: p.how, tiers: TIERS.map(t => ({ tier: t, label: LABEL[t], path: "/dns-query/" + t })),
      ua: request.headers.get("user-agent") || "",
      hint: "配置 URL 里带上 /dns-query/<档位> 即可固定档位；不带则由 UA 自动判定",
    }, null, 1), { headers: TIER_JSON_H });
  }

  // /why 自查：Worker 才有规则分层信息，Pages 原样转发
  if (url.pathname === "/why") {
    const res = await fetch(WORKER_URL + "/why" + url.search, {
      headers: { "user-agent": "NoAS-pages", "x-noas-cip": cip }, cache: "no-store",
    });
    return proxied(res);
  }

  if (!url.pathname.startsWith("/dns-query")) return next();

  const pr = url.searchParams.get("probe");
  if (pr) {
    const res = await fetch(WORKER_URL + "/health?probe=" + encodeURIComponent(pr), {
      headers: { "user-agent": "NoAS-pages" }, cache: "no-store",
    });
    return proxied(res);
  }

  const p = await pickTier(request, url, pathTier);
  if (p.persist && waitUntil) {
    try { waitUntil(persistTier(request, p.tier, env).catch(() => {})); } catch (x) {}
  }

  const ck = request.method === "GET" ? request.url + "#" + p.tier + "#" + netKey(cip) : null;
  if (ck && typeof caches !== "undefined" && caches.default) {
    try {
      const hit = await caches.default.match(ck);
      if (hit) return withPath(hit, "pages-cache", p.tier);
    } catch (e) { /* 缓存不可用 */ }
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
    const mem = memGet(p.tier + "|" + q.name + "|" + q.qtype + "|" + netKey(cip));
    if (mem) return new Response(mem, {
      headers: { "content-type": "application/dns-message", "x-noas": "cache-hit",
                 "x-noas-path": "pages-mem", "x-noas-ver": "lite", "x-noas-tier": p.tier },
    });
  }

  const set = await tierSet(p.tier, env);
  if (q && set && hitSet(set, q.name)) {
    return new Response(blockedResponse(bytes, q.qtype, q.end, url.searchParams.get("mode") || ""), {
      headers: {
        "content-type": "application/dns-message",
        "x-noas": "blocked", "x-noas-path": "pages-local", "x-noas-ver": p.tier,
        "x-noas-tier": p.tier, "x-noas-tier-count": String(set.size),
      },
    });
  }

  // 未命中本档 → 透传 Worker（Worker 内嵌 mid 兜底 + 上游竞速 + 缓存）
  const fwd = new URL(WORKER_URL + "/dns-query");
  for (const [k, v] of url.searchParams) {
    if (k === "tier" || k === "dns") continue;   // dns 走 POST body，避免参数重编码
    fwd.searchParams.set(k, v);
  }
  fwd.searchParams.set("tier", "2");
  const res = await fetch(fwd.toString(), {
    method: "POST",                             // 恒用 POST 转发，报文不走查询串
    headers: {
      "content-type": "application/dns-message",
      accept: "application/dns-message",
      "user-agent": "NoAS-pages",
      // Worker 侧看不到真实客户端 IP（只剩 Pages 出口），显式带过去给 ECS 用
      "x-noas-cip": cip,
    },
    body: bytes,
    cache: "no-store",
  });
  const headers = pickHeaders(res);
  const buf = await res.arrayBuffer();
  const ok = res.status === 200 && buf.byteLength > 17;
  if (ok && q) memPut(p.tier + "|" + q.name + "|" + q.qtype + "|" + netKey(cip), buf);
  const out = new Response(buf, { status: res.status, headers });
  if (ok && ck && typeof caches !== "undefined" && caches.default && waitUntil) {
    try {
      const ch = new Headers(headers);
      ch.set("cache-control", "max-age=60");
      waitUntil(caches.default.put(ck, new Response(buf, { headers: ch })));
    } catch (e) { /* 写缓存失败不影响应答 */ }
  }
  return out;
}
