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

// 上游顺序＝"正确性优先、尾部兜底快"：
//   alidns  / doh.pub  国内直连最准（10-30ms），但 CF 边缘在海外时跨境可能 3-5s 甚至 502；
//   cloudflare-dns.com 是 CF 自家 DoH，从任何边缘访问都在同网内（通常 <10ms），
//   300ms 时并发发出，专门接住"国内上游跨境失败/慢"的尾部。
const UPSTREAM = [
  "https://dns.alidns.com/dns-query",
  "https://cloudflare-dns.com/dns-query",
  "https://doh.pub/dns-query",
];

// 版本哨兵：CF 侧唯一"从仓库拿的东西"就是这一份构建指纹（几 KB）。
// 两个免费来源：自建 Pages 优先（不限带宽、无匿名限流），GitHub raw 兜底。
// 拉不到就保持 null，绝不影响解析；规则本体已内嵌，运行期不依赖 GitHub。
const MANIFEST_URLS = [
  "https://noas-cdn.pages.dev/state/build_manifest.json",
  "https://raw.githubusercontent.com/NoS-1/NoAS/main/state/build_manifest.json",
];
const WILD_SUFFIX = new Set(WILD.map((w) => w.replace(/^\*\./, "")));

// ── 热规则（CF 独立运行的核心）──────────────────────────────────────────
// CF 侧唯一从仓库拿的"数据"就是这份 lite 文本。cron 拉取 → 校验（条数 + 金丝雀）→ 存 KV，
// 请求路径按 isolate 内存缓存命中；拉不到/校验不过就丢弃，永远保留内嵌规则兜底。
// 智能约束：热规则只做"增量补充"（union），绝不删除内嵌规则，也不越过白名单。
const HOT_URLS = [
  "https://noas-cdn.pages.dev/subs/lite/domains.txt",
  "https://raw.githubusercontent.com/NoS-1/NoAS/main/subs/lite/domains.txt",
];
const HOT_MIN = 8000;            // 少于 8000 条＝上游残缺，拒收
const HOT_MAX = 10500;           // 多于 10500 条＝超 lite 上限，拒收
let hot = null;                  // { ver, count, compact }；compact 形如 |a.com|b.com|
let lastManifest = null;

// 顺序取第一个能用的源。raw.githubusercontent 从 2025-05 起对匿名请求
// 压到约 60 次/小时/IP，不能当主源；Pages 是自己的，随时可拉。
async function fetchFirst(urls, asJson) {
  for (const u of urls) {
    try {
      const r = await fetch(u, { cache: "no-store" });
      if (!r.ok) continue;
      return asJson ? await r.json() : await r.text();
    } catch (e) { /* 换下一个源 */ }
  }
  return null;
}

// ── 额度熔断（防止免费额度被超）──────────────────────────────────────────
// Workers Free：10 万请求/天（北京 08:00 重置）。到 90% 进入"降级"：
// 跳过规则匹配、直接转发上游，客户端不断服；恢复由 UTC 换日自动完成。
// 计数只放 isolate 内存，绝不碰 KV/D1（用 KV 计数会把 1000 写/天瞬间打爆）。
const FREE_DAILY = 100000;
const SOFT_RATIO = 0.9;
const PER_IP_PER_MIN = 300;        // 共享出口 IP（校园网/运营商 NAT）友好，避免误伤整条链路
// 被拦应答的缓存时长：客户端 5 分钟内不再重复问同一域名，直接省下 Worker 请求额度。
// 代价是解封/纠错最迟 5 分钟生效，对每天重建一次的规则表完全可接受。
const BLOCK_TTL = 300;
const UPSTREAM_TIMEOUT_MS = 5000;

let degraded = "";                 // 非空 = 正在降级；/health 可见
let upstreamFails = 0;
let lastUpstreamOk = 0;
let rulesStale = null;             // null=还没校验过
let manifestCheckedAt = 0;         // 上次新鲜度校验时间，避免 /health 被刷时反复拉
let canaryOk = null;               // cron 规则金丝雀：内置表还能不能拦住已知广告域
let upOrder = null;                // 上游自适应顺序（最近成功的排前面），isolate 内有效
let cacheHits = 0;                 // 缓存命中数（fresh+stale），/health 可见

// 金丝雀：只用内置规则判定（纯函数、零网络），断言"规则没被构建搞坏"
const CANARY_DOMAINS = ["doubleclick.net", "googleadservices.com", "googletagmanager.com"];

// 上游断线兜底：最近成功的应答按 qname+qtype 缓存 60s，上游全挂时直接回缓存。
// Cache API 免费且不计 Worker 请求额度，是"独立可用"的最后一道。
const CACHE_BASE = "https://noas-cache.internal/";
// 放行应答缓存双层：fresh 300s 内直接命中；stale 24h 内先返旧值、后台刷新。
// 缓存命中不写 AE（否则额度会被高频命中打爆），只在 /health 里给个内存计数。
const CACHE_FRESH_S = 300;
const CACHE_STALE_S = 86400;

// ── Analytics Engine（可选绑定 AE）────────────────────────────────────────
// 只写数据点，不碰 D1：D1 的行读额度（500 万行/天）留给配置与状态。
// 免费额度 1 亿点/月，按当前量级（万级/天）约用掉 3% 以内。
// 绑定缺失时静默跳过 —— 没绑 AE 也必须照常解析，绝不能让日志拖垮服务。
// 免费额度实测（2026-11 官方）：Analytics Engine 10 万数据点/天 + 1 万读查询/天。
// 不是"1 亿点/月"。高峰时 block 全量 + pass 采样足以打满日额度，所以自己再压一道：
// 到 9 万点就静默丢弃，宁可少日志，也不能让写点失败拖慢 DNS 应答。
const AE_DAILY_CAP = 90000;
let aeDay = "";
let aePoints = 0;

function logHit(env, kind, name, tier, extra) {
  const ae = env && env.AE;
  if (!ae || !name) return;
  const d = utcDay();
  if (d !== aeDay) { aeDay = d; aePoints = 0; }
  if (aePoints >= AE_DAILY_CAP) return;
  aePoints += 1;
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

// 限流优先用平台原生 Rate Limiting binding（Free 计划可用、不额外计费）：
// 它按 colo 精确计数，不像内存计数那样每个 isolate 各算一份。
// 绑定缺失或调用异常时退回本地令牌计数，保证任何情况下都有限流。
async function ipLimited(env, ip) {
  if (!ip || ip === "unknown") return false;
  const lim = env && env.LIMITER;
  if (lim && lim.limit) {
    try {
      const r = await lim.limit({ key: ip });
      return !r.success;
    } catch (e) { /* 退回内存计数 */ }
  }
  return ipBurst(ip);
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

function hotHit(name) {
  if (!hot) return false;
  const c = hot.compact;
  if (c.includes("|" + name + "|")) return true;
  const parts = name.split(".");
  for (let i = 1; i < parts.length - 1; i++) {
    if (c.includes("|" + parts.slice(i).join(".") + "|")) return true;
  }
  return false;
}

async function loadHot(env) {
  // 冷启动只读一次 KV（10 万读/天额度足够），之后全走 isolate 内存
  if (hot || !env || !env.RULES) return;
  try {
    // cacheTtl 300s：KV 免费只有 10 万读/天，默认 60s 边缘缓存太短，
    // 每个新 isolate 都会真读一次。规则一天只更新两次，5 分钟可见完全够。
    const rec = await env.RULES.get("lite_v1", { type: "json", cacheTtl: 300 });
    if (rec && rec.compact && rec.count >= HOT_MIN && rec.count <= HOT_MAX
        && CANARY_DOMAINS.every((d) => rec.compact.includes("|" + d + "|"))) {
      hot = rec;
    }
  } catch (e) { /* KV 不可用＝退回内嵌规则 */ }
}

function blocked(name, tier) {
  if (!name) return false;
  // 端点例外：人工审计过的纯广告端点，父域在白名单里也照拦
  if (isEndpoint(name)) return true;
  if (allowed(name)) return false;
  const set = tier >= 2 ? TIER2 : TIER1;
  if (matchSet(set, name)) return true;
  return hotHit(name);          // 云端热规则只做增量补充
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
  const rdlen = qtype === 1 ? 4 : 16;
  const out = new Uint8Array(head.length + 12 + rdlen);
  out.set(head, 0);
  const p = head.length;
  // ANSWER 区布局：NAME(2) TYPE(2) CLASS(2) TTL(4) RDLEN(2) RDATA(4|16)
  out[p] = 0xc0; out[p + 1] = 0x0c;                    // 指向问题区的名字
  out[p + 2] = 0x00; out[p + 3] = qtype === 1 ? 0x01 : 0x1c;   // TYPE A=1 / AAAA=28
  out[p + 4] = 0x00; out[p + 5] = 0x01;                // CLASS IN=1（写 0 会被严格解析器丢弃）
  out[p + 6] = (BLOCK_TTL >>> 24) & 0xff; out[p + 7] = (BLOCK_TTL >>> 16) & 0xff;
  out[p + 8] = (BLOCK_TTL >>> 8) & 0xff;  out[p + 9] = BLOCK_TTL & 0xff;   // TTL 大端
  out[p + 10] = 0x00; out[p + 11] = rdlen;             // RDLEN 必须与实际数据区一致
  return out;                                          // RDATA 全 0 → A=0.0.0.0 / AAAA=::
}

// 阶梯竞速（hedged requests）：原实现是"一个上游 5s 超时才换下一个"，
// 一旦主上游抽风，用户要等满 5 秒。改为错峰并发：
//   0ms 发 A，300ms 未回再发 B，800ms 未回再发 C；先回来且 HTTP 200 的那份胜出，
//   其余立刻 abort。常态仍然只打 1 个上游，尾部延迟从 5000ms 压到 ~800ms。
const HEDGE_MS = [0, 300, 900];

function fetchUpstream(u, bytes, ctrl) {
  return fetch(u, {
    method: "POST",
    headers: { "content-type": "application/dns-message", accept: "application/dns-message" },
    body: bytes,
    signal: ctrl.signal,
  }).then(async (r) => {
    if (!r.ok) throw new Error("HTTP " + r.status);
    return await r.arrayBuffer();
  });
}

async function upstream(bytes) {
  const list = upOrder || (upOrder = UPSTREAM.slice());
  const ctrls = list.map(() => new AbortController());
  const hard = setTimeout(() => ctrls.forEach((c) => c.abort()), UPSTREAM_TIMEOUT_MS);
  try {
    const attempts = list.map((u, i) => new Promise((resolve, reject) => {
      const delay = HEDGE_MS[i] !== undefined ? HEDGE_MS[i] : i * 500;
      const kick = () => {
        fetchUpstream(u, bytes, ctrls[i]).then(
          (buf) => resolve({ u, buf }),
          (e) => reject(e),
        );
      };
      if (delay) setTimeout(kick, delay); else kick();
    }));
    const win = await Promise.any(attempts);
    ctrls.forEach((c, i) => { if (list[i] !== win.u) { try { c.abort(); } catch (e) {} } });
    upstreamFails = 0;
    lastUpstreamOk = Date.now();
    if (list[0] !== win.u) {                 // 把当前可用上游提到第一位，下个请求直接命中
      list.splice(list.indexOf(win.u), 1);
      list.unshift(win.u);
    }
    return win.buf;
  } catch (e) {
    upstreamFails += 1;
    return null;
  } finally {
    clearTimeout(hard);
  }
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
    // 新 isolate 首次访问时 rules_stale 还是 null：补一次校验（60s 节流），
    // 让 /health 一次就能回答"线上规则到底新不新"，不必等 cron。
    if (rulesStale === null && Date.now() - manifestCheckedAt > 60000) {
      try { await checkManifest(env); } catch (e) {}
    }
    // ?probe=1：从"这个边缘节点"出发，并发量每家上游各一次的真实耗时。
    // 外部测的 RTT 含客户端→CF 的网络，这里量到的才是我们能优化的那段。
    let probe = null;
    if (url.searchParams.get("probe")) {
      const q = mkQuery("example.com");
      probe = await Promise.all(UPSTREAM.map(async (u) => {
        const t0 = Date.now();
        const c = new AbortController();
        const tm = setTimeout(() => { try { c.abort(); } catch (e) {} }, 5000);
        try {
          const r = await fetchUpstream(u, q, c);
          clearTimeout(tm);
          return { url: u, ms: Date.now() - t0, ok: true, bytes: r.byteLength };
        } catch (e) {
          clearTimeout(tm);
          return { url: u, ms: Date.now() - t0, ok: false, why: String(e).slice(0, 80) };
        }
      }));
    }
    return json({ ok: true, version: VERSION, tier1: TIER1.size, tier2: TIER2.size,
                  allowlist: ALLOW.size, endpoints: ENDPOINTS.size, wildcards: WILD_SUFFIX.size,
                  upstream: UPSTREAM.length, upstream_fails: upstreamFails,
                  last_upstream_ok: lastUpstreamOk,
                  ae: !!(env && env.AE),
                  canary: canaryOk,
                  degraded: degraded || null,
                  rules_stale: rulesStale, rules_manifest: MANIFEST_URLS[0],
                  hot: hot ? { ver: hot.ver, count: hot.count } : null, hot_url: HOT_URLS[0],
                  ae_points_local: aePoints, ae_cap_per_isolate: AE_DAILY_CAP,
                  limiter: !!(env && env.LIMITER),
                  cache: hasCache(), cache_hits: cacheHits,
                  cache_ttl_s: [CACHE_FRESH_S, CACHE_STALE_S],
                  upstream_order: (upOrder || UPSTREAM), probe: probe,
                  quota: { day: dayKey || utcDay(), used: dayCount, free_daily: FREE_DAILY,
                           soft_limit: Math.round(FREE_DAILY * SOFT_RATIO) } });
  }
  if (url.pathname === "/check") {
    // 调试端点也按 IP 限速：只对有真实来源 IP 的线上请求生效，本地/CI 测试不受影响
    const cip = request.headers.get("cf-connecting-ip");
    if (cip && await ipLimited(env, cip)) {
      return json({ error: "rate-limited", retry_after_s: 60 }, 429);
    }
    const q = (url.searchParams.get("q") || "").toLowerCase();
    const tier = Number(url.searchParams.get("tier") || 2);   // 默认走 mid：lite 只是零误伤最小集
    const cn = (url.searchParams.get("cname") || "").toLowerCase();
    await loadHot(env);
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
  if (await ipLimited(env, ip)) degrade("ip-burst " + PER_IP_PER_MIN + "/min");
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

  if (!skipRules) await loadHot(env);
  if (!skipRules && blocked(name, tier)) {
    logHit(env, "block", name, tier, "");
    return new Response(blockedResponse(bytes, qtype, end), {
      headers: { "content-type": "application/dns-message", "x-noas": "blocked", "x-noas-ver": VERSION },
    });
  }
  // 缓存优先：fresh 命中直接返（0 上游 RTT）；stale 命中先返旧值、后台刷新。
  // 旧实现只有"上游全挂"才读缓存，等于每次解析都白付 10-110ms 的上游往返。
  const cached = await cacheLookup(name, qtype);
  if (cached && !cached.stale) {
    cacheHits += 1;
    return dnsReply(cached.buf, "cache-hit");
  }
  if (cached && cached.stale) {
    cacheHits += 1;
    if (ctx && ctx.waitUntil) {
      ctx.waitUntil((async () => {
        try {
          const b = await upstream(bytes);
          if (b) await cachePut(name, qtype, b);
        } catch (e) { /* 后台刷新失败保留旧值 */ }
      })());
    }
    return dnsReply(cached.buf, "cache-stale");
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
    if (Math.random() < 0.05) logHit(env, "pass", name, tier, "");   // 放行只留 5% 样本，省 AE 点数
  }
  if (ctx && ctx.waitUntil && !skipRules) ctx.waitUntil(cachePut(name, qtype, buf.slice(0)));
  return new Response(buf, {
    headers: { "content-type": "application/dns-message",
               "x-noas": skipRules ? "degraded" : "pass", "x-noas-ver": VERSION },
  });
}

function cacheKey(name, qtype) {
  return CACHE_BASE + encodeURIComponent(name) + "/" + qtype;
}

let cacheReady = null;
function hasCache() {
  if (cacheReady === null) {
    try { cacheReady = !!(typeof caches !== "undefined" && caches.default); }
    catch (e) { cacheReady = false; }
  }
  return cacheReady;
}

async function cacheLookup(name, qtype) {
  if (!hasCache()) return null;
  try {
    const fresh = await caches.default.match(cacheKey(name, qtype));
    if (fresh) return { buf: await fresh.arrayBuffer(), stale: false };
  } catch (e) { /* 继续尝试 stale */ }
  try {
    const old = await caches.default.match(cacheKey(name, qtype) + "#swr");
    if (old) return { buf: await old.arrayBuffer(), stale: true };
  } catch (e) { /* 无缓存 */ }
  return null;
}

async function cachePut(name, qtype, buf) {
  if (!hasCache()) return;
  // 两份：fresh 300s（命中直返）+ stale 24h（fresh 过期后先返旧值、后台刷新）
  const put = (key, maxAge) => caches.default.put(key, new Response(buf.slice(0), {
    headers: { "content-type": "application/dns-message", "cache-control": "max-age=" + maxAge },
  }));
  try { await put(cacheKey(name, qtype), CACHE_FRESH_S); } catch (e) { /* 忽略 */ }
  try { await put(cacheKey(name, qtype) + "#swr", CACHE_STALE_S); } catch (e) { /* 忽略 */ }
}

function dnsReply(buf, tag) {
  return new Response(buf, {
    headers: { "content-type": "application/dns-message", "x-noas": tag, "x-noas-ver": VERSION },
  });
}

// 规则新鲜度：只读构建指纹（KB 级），不拉规则本体。
// 拉不到＝未知，保持 null，不制造假告警。cron 与 /health 首次访问共用。
async function checkManifest(env) {
  manifestCheckedAt = Date.now();
  try {
    const m = await fetchFirst(MANIFEST_URLS, true);
    if (m) {
      lastManifest = m;
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
  await checkManifest(env);

  // 热规则自更新：只在版本变化或缺缓存时才拉 lite 文本（约 140KB）
  if (env && env.RULES) {
    const need = !hot || (lastManifest && lastManifest.version && lastManifest.version !== hot.ver);
    if (need) {
      try {
        const text = await fetchFirst(HOT_URLS, false);
        if (text) {
          // Free 计划的 cron 也只有 10ms CPU：不 split 成数组再 join，
          // 一次正则替换 + 数换行就够，避免上万行的中间对象分配。
          const raw = text.trim();
          const compact = "|" + raw.replace(/\r/g, "").replace(/\n/g, "|") + "|";
          let count = 1;
          for (let i = raw.indexOf("\n"); i !== -1; i = raw.indexOf("\n", i + 1)) count += 1;
          const okCount = count >= HOT_MIN && count <= HOT_MAX;
          const okCanary = CANARY_DOMAINS.every((d) => compact.includes("|" + d + "|"));
          if (okCount && okCanary) {
            hot = { ver: (lastManifest && lastManifest.version) || VERSION,
                    count, compact };
            await env.RULES.put("lite_v1", JSON.stringify(hot));
            logHit(env, "hot", "updated", 0, String(count));
          } else {
            logHit(env, "hot", "rejected", 0,
                   (okCount ? "" : "count=" + count) + (okCanary ? "" : " canary"));
          }
        }
      } catch (e) { logHit(env, "hot", "fetch-fail", 0, ""); }
    }
  }

  // 上游自检：内置最小报文直问上游，绕过自己的规则层（不占自身请求计数）
  const probe = await upstream(mkQuery("example.com"));
  if (probe) {
    degraded = "";                        // 上游恢复＝解降级
    logHit(env, "cron", "upstream-ok", 0, "");
  } else {
    degrade("upstream-down");
    logHit(env, "cron", "upstream-dead", 0, "");
  }

  // 每天 0 点这一轮做一次内存自检：只读本 isolate 状态，不发任何外部请求。
  // 一条 diag 就能在 AE 里回答"线上到底装的是哪个版本、规则条数对不对、有没有在降级"。
  const now = new Date();
  if (now.getUTCHours() === 0 && now.getUTCMinutes() < 15) {
    logHit(env, "diag", "selfcheck", 0,
           ["t1=" + TIER1.size, "t2=" + TIER2.size, "allow=" + ALLOW.size,
            "hot=" + (hot ? hot.count : 0), "ver=" + VERSION,
            "fails=" + upstreamFails, "degraded=" + (degraded || "-")].join(" "));
  }
}

export default { fetch: handle, scheduled };
