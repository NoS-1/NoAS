/**
 * NoAS DoH 网关模板（构建时注入规则，纯标准 Web API，可跑在 Worker / Node 任意环境）
 *
 * 规则以换行分隔纯文本内嵌，模块级同步切分成 Set。
 * 不解压、不用顶层 await（CF 禁止全局作用域做异步 I/O）。
 */
const T1_TEXT = __T1__;
const T2_TEXT = __T2__;
const ALLOW_TEXT = __ALLOW_TEXT__;
const EP_TEXT = __EP_TEXT__;
const WILD_TEXT = __WILD_TEXT__;
const VERSION = __VERSION__;

const splitLines = (t) => (t ? t.split("\n") : []);
const TIER1 = new Set(splitLines(T1_TEXT));
const TIER2 = new Set(splitLines(T2_TEXT));
const ALLOW = new Set(splitLines(ALLOW_TEXT));
const ENDPOINTS = new Set(splitLines(EP_TEXT));
const WILD = splitLines(WILD_TEXT);

const UPSTREAM = [
  "https://dns.alidns.com/dns-query",
  "https://doh.pub/dns-query",
  "https://dns.360.cn/dns-query",
];

// 版本哨兵：CF 侧唯一"从仓库拿的东西"就是这一份构建指纹（几 KB）。
// 拉不到就保持 null，绝不影响解析；规则本体已内嵌，运行期不依赖 GitHub。
const MANIFEST_URL = "https://raw.githubusercontent.com/NoS-1/NoAS/main/state/build_manifest.json";
const WILD_SUFFIX = new Set(WILD.map((w) => w.replace(/^\*\./, "")));

// ── 额度熔断（防止免费额度被超）──────────────────────────────────────────
// Workers Free：10 万请求/天（北京 08:00 重置）。到 90% 进入"降级"：
// 跳过规则匹配、直接转发上游，客户端不断服；恢复由 UTC 换日自动完成。
// 计数只放 isolate 内存，绝不碰 KV/D1（用 KV 计数会把 1000 写/天瞬间打爆）。
const FREE_DAILY = 100000;
const SOFT_RATIO = 0.9;
const PER_IP_PER_MIN = 300;        // 共享出口 IP（校园网/运营商 NAT）友好，避免误伤整条链路
const UPSTREAM_TIMEOUT_MS = 5000;

let degraded = "";                 // 非空 = 正在降级；/health 可见
let upstreamFails = 0;
let lastUpstreamOk = 0;
let rulesStale = null;             // null=还没校验过
let canaryOk = null;               // cron 规则金丝雀：内置表还能不能拦住已知广告域
let upOrder = null;                // 上游自适应顺序（最近成功的排前面），isolate 内有效

// 金丝雀：只用内置规则判定（纯函数、零网络），断言"规则没被构建搞坏"
const CANARY_DOMAINS = ["doubleclick.net", "googleadservices.com", "googletagmanager.com"];

// ── Analytics Engine（可选绑定 AE）────────────────────────────────────────
// 只写数据点，不碰 D1：D1 的行读额度（500 万行/天）留给配置与状态。
// 免费额度 1 亿点/月，按当前量级（万级/天）约用掉 3% 以内。
// 绑定缺失时静默跳过 —— 没绑 AE 也必须照常解析，绝不能让日志拖垮服务。
function logHit(env, kind, name, tier, extra) {
  const ae = env && env.AE;
  if (!ae || !name) return;
  try {
    ae.writeDataPoint({
      blobs: [kind, name, "t" + tier, extra || ""],
      doubles: [1],
      indexes: [kind],          // 用 kind 而非域名：域名做 index 基数爆炸，白烧 AE 元数据
    });
  } catch (e) { /* 记录失败不影响 DNS 应答 */ }
}

let dayKey = "";
let dayCount = 0;
const ipWindow = new Map();

const utcDay = () => new Date().toISOString().slice(0, 10);

function takeQuota() {
  const d = utcDay();
  if (d !== dayKey) {
    dayKey = d;
    dayCount = 0;
    if (ipWindow.size > 2000) ipWindow.clear();
  }
  dayCount += 1;
  return dayCount <= FREE_DAILY * SOFT_RATIO;
}

function ipBurst(ip) {
  if (ipWindow.size > 2000) ipWindow.clear();
  const minute = Math.floor(Date.now() / 60000);
  const rec = ipWindow.get(ip);
  if (!rec || rec.m !== minute) {
    ipWindow.set(ip, { m: minute, n: 1 });
    return false;
  }
  rec.n += 1;
  return rec.n > PER_IP_PER_MIN;
}

function degrade(reason) {
  degraded = reason;
}

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
    const parent = parts.slice(i).join(".");
    if (set.has(parent)) return true;
    if (WILD_SUFFIX.has(parent)) return true;   // *.parent 命中其任意（含多级）子域
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

/** 合成"拦截"应答：A→0.0.0.0，AAAA→::，其它类型→NOERROR 空答（NXDOMAIN 会误伤邮件/校验类客户端） */
function blockedResponse(query, qtype, end) {
  const head = new Uint8Array(query.slice(0, end));   // 头部 + 问题区原样带回
  const answer = (qtype === 1 || qtype === 28) ? 1 : 0;
  head[2] = 0x81; head[3] = 0x80;                     // QR=1 RD=1 RA=1 NOERROR
  head[6] = 0; head[7] = answer ? 1 : 0;
  head[8] = 0; head[9] = 0; head[10] = 0; head[11] = 0;
  if (!answer) return head;
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
  const list = upOrder || (upOrder = UPSTREAM.slice());
  for (const u of list) {
    try {
      let signal;
      try { signal = AbortSignal.timeout(UPSTREAM_TIMEOUT_MS); } catch (e) { signal = undefined; }
      const r = await fetch(u, {
        method: "POST",
        headers: { "content-type": "application/dns-message", accept: "application/dns-message" },
        body: bytes,
        signal,
      });
      if (r.ok) {
        upstreamFails = 0;
        lastUpstreamOk = Date.now();
        if (list[0] !== u) {                  // 把当前可用上游提到第一位，下个请求直接命中
          list.splice(list.indexOf(u), 1);
          list.unshift(u);
        }
        return await r.arrayBuffer();
      }
    } catch (e) { /* 超时/被拒：换下一个上游 */ }
  }
  upstreamFails += 1;
  return null;
}

/** 构造一条最小的 A 查询报文（cron 自检用，不经过自己的 DoH，避免自增计数） */
function mkQuery(name) {
  const labels = name.split(".");
  const len = 12 + labels.reduce((a, l) => a + l.length + 1, 0) + 1 + 4;
  const b = new Uint8Array(len);
  const dv = new DataView(b.buffer);
  dv.setUint16(0, 0x4e41); dv.setUint16(2, 0x0100); dv.setUint16(4, 1);
  let off = 12;
  for (const l of labels) {
    b[off++] = l.length;
    for (let i = 0; i < l.length; i++) b[off++] = l.charCodeAt(i);
  }
  b[off++] = 0;
  dv.setUint16(off, 1); dv.setUint16(off + 2, 1);      // A / IN
  return b;
}

async function handle(request, env, ctx) {
  const url = new URL(request.url);

  if (url.pathname === "/health") {
    return json({ ok: true, version: VERSION, tier1: TIER1.size, tier2: TIER2.size,
                  allowlist: ALLOW.size, endpoints: ENDPOINTS.size, wildcards: WILD_SUFFIX.size,
                  upstream: UPSTREAM.length, upstream_fails: upstreamFails,
                  last_upstream_ok: lastUpstreamOk,
                  ae: !!(env && env.AE),
                  canary: canaryOk,
                  degraded: degraded || null,
                  rules_stale: rulesStale, rules_manifest: MANIFEST_URL,
                  upstream_order: (upOrder || UPSTREAM),
                  quota: { day: dayKey || utcDay(), used: dayCount, free_daily: FREE_DAILY,
                           soft_limit: Math.round(FREE_DAILY * SOFT_RATIO) } });
  }
  if (url.pathname === "/check") {
    const q = (url.searchParams.get("q") || "").toLowerCase();
    const tier = Number(url.searchParams.get("tier") || 2);   // 默认走 mid：lite 只是零误伤最小集
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

  // 熔断不返回 503：503 会让客户端直接断服。改为"降级直转"——
  // 跳过规则匹配省 CPU，DNS 照常应答，恢复靠 UTC 换日 + cron 自检复位。
  const ip = request.headers.get("cf-connecting-ip") || "unknown";
  if (ipBurst(ip)) degrade("ip-burst " + PER_IP_PER_MIN + "/min");
  if (!takeQuota()) degrade("quota 90%");
  const skipRules = !!degraded;

  let bytes;
  if (request.method === "POST") {
    bytes = new Uint8Array(await request.arrayBuffer());
  } else {
    const dns = url.searchParams.get("dns");
    if (!dns) return json({ error: "缺少 dns 参数（DoH 要求 GET ?dns=<base64url> 或 POST）" }, 400);
    bytes = b64urlToBytes(dns);
  }
  if (bytes.byteLength < 17) return json({ error: "报文过短" }, 400);

  let parsed;
  try { parsed = parseQuery(bytes); } catch (e) { return json({ error: "报文无法解析" }, 400); }
  const { name, qtype, end } = parsed;
  const tier = Number(url.searchParams.get("tier") || 2);   // 默认走 mid：lite 只是零误伤最小集
  if (!name) return new Response("bad query", { status: 400 });

  if (!skipRules && blocked(name, tier)) {
    logHit(env, "block", name, tier, "");
    return new Response(blockedResponse(bytes, qtype, end), {
      headers: { "content-type": "application/dns-message", "x-noas": "blocked", "x-noas-ver": VERSION },
    });
  }
  const buf = await upstream(bytes);
  if (!buf) {
    degrade("upstream-down");
    return new Response("上游不可用", { status: 502, headers: { "x-noas": "upstream-fail" } });
  }
  if (!skipRules) {
    // CNAME 反隐蔽：第一方子域 CNAME 到追踪者时，按追踪者判定并直接拦掉
    const chain = cnameTargets(buf);
    for (const t of chain) {
      if (blocked(t, tier)) {
        logHit(env, "cname", name, tier, t);
        return new Response(blockedResponse(bytes, qtype, end), {
          headers: { "content-type": "application/dns-message", "x-noas": "blocked-cname",
                     "x-noas-target": t, "x-noas-ver": VERSION },
        });
      }
    }
    if (Math.random() < 0.1) logHit(env, "pass", name, tier, "");   // 放行只留 10% 样本，省 AE 点数
  }
  return new Response(buf, {
    headers: { "content-type": "application/dns-message",
               "x-noas": skipRules ? "degraded" : "pass", "x-noas-ver": VERSION },
  });
}

// 免费 Cron Trigger（每账户 5 个额度）：CF 侧自持的自治循环——
// 心跳 + 规则新鲜度哨兵 + 上游自检复位，GitHub Actions 挂了也照样运转。
async function scheduled(event, env, ctx) {
  logHit(env, "cron", "heartbeat", 0, "v" + VERSION);

  // 规则金丝雀：纯本地判定（零网络），确认内置表真的还能拦住已知广告域。
  const miss = CANARY_DOMAINS.filter((d) => !blocked(d, 2));
  canaryOk = miss.length === 0;
  if (!canaryOk) logHit(env, "canary", "miss", 0, miss.join(","));

  // 规则新鲜度：只读仓库里的构建指纹（KB 级），不拉规则本体。
  // 拉不到＝未知，保持 null，不制造假告警。
  try {
    const r = await fetch(MANIFEST_URL, { headers: { "cache-control": "no-cache" } });
    if (r.ok) {
      const m = await r.json();
      const fresh = !!(m && m.version === VERSION);
      rulesStale = !fresh;
      if (!fresh) logHit(env, "stale", "manifest", 0, String((m && m.version) || ""));
      // 漂移检测：版本相同但条数不符 = 构建/注入出过岔子
      if (m && m.counts) {
        const drift = [];
        if (m.counts.t1 && m.counts.t1 !== TIER1.size) drift.push("t1");
        if (m.counts.t2 && m.counts.t2 !== TIER2.size) drift.push("t2");
        if (m.counts.allow && m.counts.allow !== ALLOW.size) drift.push("allow");
        if (drift.length) logHit(env, "drift", "count-mismatch", 0, drift.join(","));
      }
    } else {
      rulesStale = null;
    }
  } catch (e) { rulesStale = null; }

  // 上游自检：内置最小报文直问上游，绕过自己的规则层（不占自身请求计数）
  const probe = await upstream(mkQuery("example.com"));
  if (probe) {
    degraded = "";                        // 上游恢复＝解降级
    logHit(env, "cron", "upstream-ok", 0, "");
  } else {
    degrade("upstream-down");
    logHit(env, "cron", "upstream-dead", 0, "");
  }
}

export default { fetch: handle, scheduled };
