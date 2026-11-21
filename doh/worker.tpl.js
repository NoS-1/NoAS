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
let degradedUntil = 0;             // 降级到期时间：上游抖一次不能让整个 isolate 长期不拦广告
let upstreamFails = 0;
let lastHandlerErr = "";        // 最近一次 handler 抛异常的位置，/health 可见
let lastUpstreamErr = "";      // 最近一次竞速全败的原因，/health 可见
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
const CACHE_FRESH_S = 600;
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

function degrade(reason, ms = 120000) {
  degraded = reason;
  degradedUntil = Date.now() + ms;
}

/** 带自愈的降级判断：到期自动恢复，避免一次上游抖动导致后续请求全跳过规则 */
function isDegraded() {
  if (degraded && Date.now() > degradedUntil) { degraded = ""; degradedUntil = 0; }
  return !!degraded;
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

// 把应答解析成结构化记录（/resolve 与 dns-json 用）
function rrList(buf, qend) {
  const out = [];
  try {
    const dv = new DataView(buf.buffer || buf, buf.byteOffset || 0);
    const total = dv.byteLength;
    let off = qend;
    const an = dv.getUint16(6);
    for (let i = 0; i < an && off < total; i++) {
      const name = readName(dv, off);
      off = skipName(dv, off);
      const type = dv.getUint16(off);
      const ttl = dv.getUint32(off + 4);
      const rdlen = dv.getUint16(off + 8);
      const rd = off + 10;
      let data = "";
      if (type === 1 && rdlen === 4) data = Array.from(new Uint8Array(dv.buffer, dv.byteOffset + rd, 4)).join(".");
      else if (type === 28 && rdlen === 16) {
        const b = new Uint8Array(dv.buffer, dv.byteOffset + rd, 16);
        const seg = [];
        for (let k = 0; k < 16; k += 2) seg.push(((b[k] << 8) | b[k + 1]).toString(16));
        data = seg.join(":");
      } else if (type === 5) data = readName(dv, rd);
      else if (type === 16) data = String.fromCharCode(...new Uint8Array(dv.buffer, dv.byteOffset + rd, Math.min(rdlen, 40)));
      else data = Buffer.from ? "" : "";
      out.push({ name, type, ttl, data });
      off = rd + rdlen;
    }
  } catch (e) { /* 畸形报文就返回已解析部分 */ }
  return out;
}

// 自建最小查询（用于 CNAME 深追）：RD=1，问题区 1 条，其余留空
function buildProbe(name, qtype, ecs, edns) {
  const head = new Uint8Array(12);
  head[2] = 0x01;                        // RD
  head[5] = 1;                           // QDCOUNT
  const labels = name.split(".").filter(Boolean);
  let len = 12 + 1 + 4;
  for (const l of labels) len += l.length + 1;
  const out = new Uint8Array(len);
  out.set(head, 0);
  let o = 12;
  for (const l of labels) { out[o++] = l.length; for (let i = 0; i < l.length; i++) out[o++] = l.charCodeAt(i); }
  out[o++] = 0;
  out[o++] = (qtype >> 8) & 0xff; out[o++] = qtype & 0xff;
  out[o++] = 0; out[o++] = 1;
  return applyEdns(out, ecs, edns);
}

// CNAME 多跳反隐蔽（P0）：
//   上游通常把整条链放在 ANSWER 段，一轮就够；只返一跳时再自建查询追，
//   最多 4 跳并带 seen 集合防环 —— 否则 first-party 子域 → 中间域 → 追踪域这种
//   三段链只要上游偷懒只给一段，就会被绕过。
async function cnameDeep(baseBuf, name, qtype, tier, ip, edns) {
  const seen = new Set([name]);
  let pending = name, buf = baseBuf;
  for (let hop = 0; hop < 4; hop++) {
    const targets = cnameTargets(buf);
    for (const t of targets) if (blocked(t, tier)) return t;
    const next = targets.length ? targets[targets.length - 1] : null;
    if (!next || seen.has(next)) return null;
    seen.add(next);
    pending = next;
    buf = await upstream(buildProbe(pending, qtype, edns && edns.ecs, edns), pending, ip, edns);
    if (!buf) return null;
  }
  return null;
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

// 给 /why 用：命中理由分层，运维排查时不用再翻规则表
function blockedInfo(name, tier) {
  const out = { domain: name || null, tier, blocked: false, why: "none", layer: null, source: null };
  if (!name) return out;
  if (isEndpoint(name)) {
    out.blocked = true; out.why = "endpoint"; out.layer = "L1-embedded"; out.source = "ad_endpoints/cn_ad_endpoints/layer_backfill";
    return out;
  }
  if (allowed(name)) { out.why = "allowlist"; out.layer = "allow"; return out; }
  const set = tier >= 2 ? TIER2 : TIER1;
  if (matchSet(set, name)) {
    out.blocked = true; out.why = "rule"; out.layer = "L" + (tier >= 2 ? 2 : 1) + "-embedded";
    out.source = tier >= 2 ? "tier2/mid+full" : "tier1/lite";
    return out;
  }
  if (hotHit(name)) {
    out.blocked = true; out.why = "hot"; out.layer = "hot-KV";
    return out;
  }
  return out;
}

// 从应答报文反推问题区结束位置（缓存里只有整包，没有 parseQuery 的结果）
function qendOf(buf) {
  try { return parseQuery(new Uint8Array(buf)).end; } catch (e) { return 12 + 5; }
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
function blockedResponse(query, qtype, end, mode) {
  const head = new Uint8Array(query.slice(0, end));   // 头部 + 问题区原样带回
  // ?mode=nxdomain：回 NXDOMAIN(3) 而不是 0.0.0.0。少数客户端对 0.0.0.0 会回退 IPv6 或重试，
  // NXDOMAIN 是"域名不存在"的确定性答案，重试更少；默认仍用 0.0.0.0（可用性更宽）。
  const nx = mode === "nxdomain";
  const refused = mode === "refused";      // RCODE 5：明确"策略拒绝"，比 SERVFAIL 更少被重试
  const servfail = mode === "servfail";    // RCODE 2：部分解析器把 NXDOMAIN 当"域名不存在"而永久负缓存
  const answer = (nx || refused || servfail) ? 0 : ((qtype === 1 || qtype === 28) ? 1 : 0);
  const rc = nx ? 3 : refused ? 5 : servfail ? 2 : 0;
  head[2] = 0x81; head[3] = 0x80 | rc;
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

// 边缘实测（?probe=1）：CF 边缘 → cloudflare-dns.com = 1ms，→ 阿里 600ms，→ 腾讯 943ms。
// 结论：国内上游在"境外边缘"身上是跨境链路，快不了；但它的解析结果对国内站点更准。
// 所以按域名分流，各自把最快的那家放第一：
//   · .cn 域名 → 阿里优先（结果为准），150ms 时 CF 兜底（避免用户等满 600ms）
//   · 其他域名 → CF 优先（1ms 出结果），150ms 时阿里兜底
const HEDGE_MS = [0, 120, 300];   // 收紧错峰窗口：实测边缘→CF DoH 只要 3~5ms，150/450 太保守
const CF_UP = "https://cloudflare-dns.com/dns-query";
const CN_TLDS = new Set(["cn"]);
// 国内大站多是 .com，但它们的 CDN 靠 GeoDNS 调度：从境外递归会拿到境外节点，
// 用户访问反而更慢。这些根域一律走阿里（国内递归出口，答案更准），
// 解析多等几百 ms只有一次（随后缓存 10 分钟），换来每次访问都快，这个账是划算的。
const CN_HINT = new Set([
  "baidu.com", "qq.com", "taobao.com", "tmall.com", "jd.com", "weibo.com", "bilibili.com",
  "iqiyi.com", "youku.com", "zhihu.com", "douyin.com", "alipay.com", "alipay.cn",
  "sina.com.cn", "sohu.com", "163.com", "meituan.com", "ctrip.com", "58.com",
  "kuaishou.com", "xiaohongshu.com", "toutiao.com", "huawei.com", "xiaomi.com", "mi.com",
  "tencent.com", "qidian.com", "douban.com", "126.com", "youku.com",
]);

function rootOfName(name) {
  const p = (name || "").split(".");
  return p.length > 2 ? p.slice(-2).join(".") : (name || "");
}

function preference(name) {
  const tld = (name || "").split(".").pop() || "";
  if (CN_TLDS.has(tld) || CN_HINT.has(rootOfName(name))) {
    return [UPSTREAM[0], CF_UP, UPSTREAM[2]];
  }
  return [CF_UP, UPSTREAM[0], UPSTREAM[2]];
}

function hostOf(u) { try { return new URL(u).host.replace(".dns-query", ""); } catch (e) { return u; } }

function bytesToB64url(b) {
  let s = "";
  for (let i = 0; i < b.length; i++) s += String.fromCharCode(b[i]);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

// ── 解析质量：ECS / TTL 钳制 / 负缓存 / AAAA 策略 ──────────────────────
// ECS：把客户端前 24 位（IPv6 前 48 位）带给上游，否则国内 CDN 按解析器出口返回
// 远端节点，手机拿到跨省 IP，首屏明显变慢。只在报文无 OPT 时追加，不破坏已有 EDNS 参数。
const TTL_MIN_S = 60;
const TTL_MAX_S = 3600;
const NEG_TTL_S = 300;          // NXDOMAIN 负缓存（RFC 2308，取保守值）
const V6_DEFAULT = "pass";      // pass | v4only
const TTL_MIN = 60;             // 上游给更短就抬到 60s，挡缓存风暴
const TTL_MAX = 3600;           // 上游给更长就压到 1h，挡 IP 漂移
const ECS_CACHE = new Map();    // ip 前缀 → {family,prefix,addr}
const ECS_BROKEN = new Map();   // 上游 host → true（该上游对 ECS 回 FORMERR，之后不再加）

function clientPrefix(ip) {
  if (!ip) return null;
  const cached = ECS_CACHE.get(ip);
  if (cached) return cached;
  let ecs = null;
  const v4 = ip.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (v4) {
    ecs = { family: 1, prefix: 24,
            addr: [Number(v4[1]) & 0xff, Number(v4[2]) & 0xff, Number(v4[3]) & 0xff, 0] };
  } else if (ip.includes(":")) {
    const head = ip.split("::")[0].split(":").filter(Boolean);
    const g = [0, 1, 2].map((i) => parseInt(head[i] || "0", 16) & 0xffff);
    const addr = [];
    for (const x of g) addr.push((x >> 8) & 0xff, x & 0xff);
    while (addr.length < 16) addr.push(0);
    ecs = { family: 2, prefix: 48, addr: addr.slice(0, 16) };
  }
  if (ecs) {
    if (ECS_CACHE.size > 2000) ECS_CACHE.clear();
    ECS_CACHE.set(ip, ecs);
  }
  return ecs;
}

// ── EDNS(0) 解析（RFC 6891 / ECS RFC 7871）──────────────────────────────
// 客户端自带 ECS 时必须沿用它的子网，而不是用自己的 cf-connecting-ip 覆盖 ——
// 覆盖会让上游按错误的地区返回 IP，CDN 就近调度直接失效（这是最难察觉的一类问题）。
function parseEdns(bytes, qend) {
  const dv = new DataView(bytes.buffer || bytes, bytes.byteOffset || 0);
  const res = { present: false, doBit: 0, ecs: null, optStart: -1, optRdlen: 0, tail: true, version: 0 };
  if (bytes.byteLength < 12) return res;
  const ar = dv.getUint16(10);
  if (!ar) return res;
  const skipName = (o) => {
    while (o < bytes.byteLength) {
      const l = bytes[o];
      if (l === 0) return o + 1;
      if ((l & 0xc0) === 0xc0) return o + 2;
      o += l + 1;
    }
    return bytes.byteLength;
  };
  const counts = [dv.getUint16(6), dv.getUint16(8), ar];
  let off = qend;
  for (let sec = 0; sec < 3; sec++) {
    for (let i = 0; i < counts[sec]; i++) {
      off = skipName(off);
      if (off + 10 > bytes.byteLength) return res;
      const type = dv.getUint16(off);
      const rdlen = dv.getUint16(off + 8);
      const rdStart = off + 10;
      if (sec === 2 && type === 41) {
        res.present = true;
        res.optStart = off;
        res.optRdlen = rdlen;
        res.doBit = (dv.getUint32(off + 4) >> 15) & 1;
        // OPT 的 TTL 四字节 = ext-rcode(1) + version(1) + flags(2)，version 在第 2 字节
        res.version = dv.getUint8(off + 5);
        res.tail = rdStart + rdlen === bytes.byteLength;
        let o = rdStart;
        while (o + 4 <= rdStart + rdlen) {
          const code = dv.getUint16(o);
          const len = dv.getUint16(o + 2);
          if (code === 8 && len >= 4) {
            const fam = dv.getUint16(o + 4);
            res.ecs = {
              family: fam,
              prefix: bytes[o + 6],
              scope: bytes[o + 7],
              addr: Array.from(bytes.slice(o + 8, o + 8 + Math.min(len - 4, 16))),
            };
          }
          o += 4 + len;
        }
      }
      off = rdStart + rdlen;
    }
  }
  return res;
}

// 把 ECS 写进 outgoing 报文：客户端自带就沿用，没有就补，完全没有 OPT 就新建。
// ?ecs=off 用：把客户端报文里的 ECS option 真删掉（只置空 ecs 变量并不够，原报文仍会透传）
function stripEcs(bytes, edns) {
  if (!edns || !edns.present || !edns.optRdlen) return bytes;
  const src = new DataView(bytes.buffer || bytes, bytes.byteOffset || 0);
  const rd = edns.optStart + 10;
  const rdEnd = rd + edns.optRdlen;
  const keep = [];
  let o = rd;
  while (o + 4 <= rdEnd) {
    const code = src.getUint16(o), len = src.getUint16(o + 2);
    if (o + 4 + len > rdEnd) break;
    if (code !== 8) keep.push([o, 4 + len]);
    o += 4 + len;
  }
  const out = new Uint8Array(bytes.byteLength);
  out.set(new Uint8Array(bytes.buffer || bytes, bytes.byteOffset || 0, bytes.byteLength), 0);
  const dv = new DataView(out.buffer, out.byteOffset, out.byteLength);
  let w = rd;
  for (const [off, len] of keep) {
    out.copyWithin ? out.set(out.subarray(off, off + len), w) : 0;
    w += len;
  }
  dv.setUint16(edns.optStart + 8, w - rd);
  return out.subarray(0, w);
}

function applyEdns(bytes, ecs, edns) {
  if (!ecs) return bytes;
  if (edns && edns.ecs) return bytes;                 // 客户端已声明 ECS，原样透传
  const addrLen = ecs.family === 2 ? 16 : 4;
  const build = (base, extra) => {
    const out = new Uint8Array(base.byteLength + extra);
    out.set(base, 0);
    return out;
  };
  if (edns && edns.present && edns.tail) {
    // OPT 在报文末尾：直接把它后面追加一个 ECS option（改 RDLEN 与 OPTION-LEN）
    const optlen = 4 + 4 + addrLen;
    const out = build(bytes, optlen);
    const o = edns.optStart;
    const rdl = edns.optRdlen + optlen;
    const dv = new DataView(out.buffer);
    dv.setUint16(o + 8, rdl);
    const po = o + 10 + edns.optRdlen;
    dv.setUint16(po, 8);
    dv.setUint16(po + 2, 4 + addrLen);
    dv.setUint16(po + 4, ecs.family);
    out[po + 6] = ecs.prefix;
    out[po + 7] = ecs.prefix;         // SCOPE PREFIX-LENGTH 回填：应答只对该网段有效，客户端按同粒度缓存
    out.set(new Uint8Array(ecs.addr.slice(0, addrLen)), po + 8);
    return out;
  }
  if (edns && edns.present) return bytes;             // OPT 不在末尾：不动，宁可少 ECS 也不破坏报文
  const optlen = 4 + 4 + addrLen;
  const out = build(bytes, 11 + optlen);
  const o = bytes.byteLength;
  const dv = new DataView(out.buffer);
  out[o] = 0;
  dv.setUint16(o + 1, 41);                 // TYPE OPT
  dv.setUint16(o + 3, 4096);               // CLASS = UDP payload 4096（EDNS0 推荐值）
  dv.setUint16(o + 5, 0);                  // ext-rcode / version
  dv.setUint16(o + 7, 0);                  // flags：DO=0
  dv.setUint16(o + 9, optlen);
  dv.setUint16(o + 11, 8);                 // OPTION-CODE ECS
  dv.setUint16(o + 13, 4 + addrLen);
  dv.setUint16(o + 15, ecs.family);
  out[o + 17] = ecs.prefix;
  out[o + 18] = 0;
  out.set(new Uint8Array(ecs.addr.slice(0, addrLen)), o + 19);
  dv.setUint16(10, 1);                     // ARCOUNT = 1
  return out;
}

// ── TTL 钳制（RFC 1035 的 RR 布局；跳过压缩名）────────────────────────
// 上游给 5s → 缓存风暴；给 7 天 → IP 换了还发旧地址。统一压到 [60, 3600]。
function clampTTL(buf, qend, lo, hi) {
  let dv;
  try { dv = new DataView(buf.buffer || buf, buf.byteOffset || 0); } catch (e) { return null; }
  if (buf.byteLength < 12) return null;
  const counts = [dv.getUint16(6), dv.getUint16(8), dv.getUint16(10)];
  const skipName = (o) => {
    let guard = 0;
    while (o < buf.byteLength && guard++ < 40) {
      const l = buf[o];
      if (l === 0) return o + 1;
      if ((l & 0xc0) === 0xc0) return o + 2;
      o += l + 1;
    }
    return buf.byteLength;
  };
  let off = qend;
  let minRaw = null;
  for (let sec = 0; sec < 3; sec++) {
    for (let i = 0; i < counts[sec]; i++) {
      off = skipName(off);
      if (off + 10 > buf.byteLength) return minRaw;
      const type = dv.getUint16(off);
      const rdStart = off + 10;
      if (!(sec === 2 && type === 41)) {          // OPT 的 TTL 字段是 flags，不能改
        const ttl = dv.getUint32(off + 4);
        if (minRaw === null || ttl < minRaw) minRaw = ttl;
        dv.setUint32(off + 4, Math.max(lo, Math.min(hi, ttl)));
      }
      off = rdStart + dv.getUint16(off + 8);
    }
  }
  return minRaw;
}

// NXDOMAIN 的负缓存时长取 SOA minimum（RFC 2308），拿不到就 300s
function soaMin(buf, qend) {
  const dv = new DataView(buf.buffer || buf, buf.byteOffset || 0);
  const an = dv.getUint16(6);
  const ns = dv.getUint16(8);
  if (!ns) return 0;
  const skipName = (o) => {
    let guard = 0;
    while (o < buf.byteLength && guard++ < 40) {
      const l = buf[o];
      if (l === 0) return o + 1;
      if ((l & 0xc0) === 0xc0) return o + 2;
      o += l + 1;
    }
    return buf.byteLength;
  };
  let off = qend;
  for (let i = 0; i < an; i++) {
    off = skipName(off);
    if (off + 10 > buf.byteLength) return 0;
    off += 10 + dv.getUint16(off + 8);
  }
  for (let i = 0; i < ns; i++) {
    off = skipName(off);
    if (off + 10 > buf.byteLength) return 0;
    const type = dv.getUint16(off);
    const rdlen = dv.getUint16(off + 8);
    if (type === 6 && rdlen >= 20) {
      // SOA RDATA 最后 4 字节是 minimum
      return dv.getUint32(off + 10 + rdlen - 4);
    }
    off += 10 + rdlen;
  }
  return 0;
}

function doBitOf(buf) {
  try { return ((new DataView(buf).getUint16(2) >> 4) & 1) === 1; } catch (e) { return false; }
}

function rcodeOf(buf) {
  try { return new DataView(buf.buffer || buf, buf.byteOffset || 0).getUint16(2) & 0x000f; }
  catch (e) { return 0; }
}

// AAAA 策略 v4only：直接回 NOERROR + 0 条答案，客户端立刻回退 A 记录，
// 不会在 IPv6 黑洞网络里干等 30 秒。
function emptyAnswer(bytes, end) {
  const head = bytes.slice(0, end);
  const out = new Uint8Array(head.length);
  out.set(head, 0);
  out[2] = 0x81; out[3] = 0x80;
  for (let i = 6; i < 12; i++) out[i] = 0;
  return out;
}

function fetchUpstream(u, bytes, ctrl) {
  const h = hostOf(u);
  if (!ECS_BROKEN.get(h)) {
    bytes = applyEdns(bytes, bytes.__ecs, bytes.__edns);
  }
  // 用 RFC 8484 的 GET 形态而不是 POST：报文进 ?dns= 查询串，没有请求体。
  // 实测 POST body 从 Pages Function 中转过来后，三家上游一致回 400——
  // 报文本身没坏（hex 已核对），是中转链路上请求体被改写；GET 彻底绕开这一步。
  // 附带好处：GET 可被 CDN 缓存，上游 RTT 更低。
  const url = u + (u.includes("?") ? "&" : "?") + "dns=" + bytesToB64url(bytes);
  return fetch(url, {
    method: "GET",
    headers: { accept: "application/dns-message" },
    signal: ctrl.signal,
    cf: { cacheTtl: 300, cacheEverything: true },
  }).then(async (r) => {
    if (!r.ok) throw new Error("HTTP " + r.status);
    return await r.arrayBuffer();
  });
}

async function upstream(bytes, qname, ip, edns) {
  // 客户端自带 ECS（RFC 7871）优先：那是它自己声明的地理位置，比我们按出口 IP 猜的准
  const ecs = (edns && edns.ecs) ? edns.ecs : clientPrefix(ip);
  const send = new Uint8Array(bytes);
  send.__edns = edns || null;
  if (ecs) send.__ecs = ecs;
  const t0 = Date.now();
  const list = preference(qname).slice();
  const ctrls = list.map(() => new AbortController());
  const errs = [];                        // 与 try 同级：catch 里要读它，放 try 内会掉进 TDZ
  const hard = setTimeout(() => ctrls.forEach((c) => c.abort()), UPSTREAM_TIMEOUT_MS);
  try {
    const attempts = list.map((u, i) => new Promise((resolve, reject) => {
      const delay = HEDGE_MS[i] !== undefined ? HEDGE_MS[i] : i * 500;
      const kick = () => {
        fetchUpstream(u, send, ctrls[i]).then(
          (buf) => resolve({ u, buf }),
          (e) => { errs[i] = hostOf(u) + ":" + String(e).slice(0, 60); reject(e); },
        );
      };
      if (delay) setTimeout(kick, delay); else kick();
    }));
    const win = await Promise.any(attempts);
    ctrls.forEach((c, i) => { if (list[i] !== win.u) { try { c.abort(); } catch (e) {} } });
    upstreamFails = 0;
    lastUpstreamOk = Date.now();
    if (degraded === "upstream-down") { degraded = ""; degradedUntil = 0; }
    if (list[0] !== win.u) {                 // 把当前可用上游提到第一位，下个请求直接命中
      list.splice(list.indexOf(win.u), 1);
      list.unshift(win.u);
    }
    return win.buf;
  } catch (e) {
    upstreamFails += 1;
    lastUpstreamErr = (Date.now() - t0) + "ms " + errs.filter(Boolean).join(" | ");
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
    let probeReal = null;
    if (url.searchParams.get("probe") === "2") {
      // 跑一次真实的解析路径（含错峰并发/中止），与上面的直连探测对比
      const t = Date.now();
      const b = await upstream(mkQuery("example.com"), "example.com");
      probeReal = { ok: !!b, ms: Date.now() - t, bytes: b ? b.byteLength : 0 };
    }
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
                  last_upstream_err: lastUpstreamErr || null,
                  last_upstream_ok: lastUpstreamOk,
                  ae: !!(env && env.AE), handler_err: lastHandlerErr || null,
                  canary: canaryOk,
                  degraded: isDegraded() ? degraded : null,
                  rules_stale: rulesStale, rules_manifest: MANIFEST_URLS[0],
                  hot: hot ? { ver: hot.ver, count: hot.count } : null, hot_url: HOT_URLS[0],
                  ae_points_local: aePoints, ae_cap_per_isolate: AE_DAILY_CAP,
                  limiter: !!(env && env.LIMITER),
                  cache: hasCache(), cache_hits: cacheHits,
                  cache_ttl_s: [CACHE_FRESH_S, CACHE_STALE_S],
                  upstream_order: preference(""), cn_order: preference("x.cn"), hedge_ms: HEDGE_MS, probe: probe, probe_real: probeReal,
                  quota: { day: dayKey || utcDay(), used: dayCount, free_daily: FREE_DAILY,
                           soft_limit: Math.round(FREE_DAILY * SOFT_RATIO) } });
  }
  // /resolve?name=&type=  或  /dns-query?name=&type=（Google JSON API 兼容）
  const jname = (url.searchParams.get("name") || "").toLowerCase();
  if (jname && (url.pathname === "/resolve" || url.pathname === "/dns-query")) {
    const TYPES = { a: 1, aaaa: 28, cname: 5, mx: 15, txt: 16, ns: 2, srv: 33, ptr: 12, soa: 6 };
    const tname = (url.searchParams.get("type") || "A").toLowerCase();
    const qtype = TYPES[tname] || 1;
    const tier = Number(url.searchParams.get("tier") || 2);
    const ipJ = request.headers.get("x-noas-cip") || request.headers.get("cf-connecting-ip") || "unknown";
    await loadHot(env);
    if (blocked(jname, tier)) {
      return json({ Status: 0, AD: false, blocked: true, tier,
                    Answer: qtype === 1 ? [{ name: jname, type: 1, TTL: 60, data: "0.0.0.0" }]
                          : qtype === 28 ? [{ name: jname, type: 28, TTL: 60, data: "::" }] : [] });
    }
    const edns2 = { present: false, doBit: 0, ecs: null };
    const probe = buildProbe(jname, qtype, null, edns2);
    const rbuf = await upstream(probe, jname, ipJ, edns2);
    if (!rbuf) return json({ Status: 2, error: "upstream-unavailable" }, 502);
    const rr = rrList(rbuf, qendOf(rbuf)).filter((r) => r.type === qtype || r.type === 5);
    return json({ Status: 0, AD: !!doBitOf(rbuf), tier, Answer: rr.map((r) => ({
      name: r.name, type: r.type, TTL: r.ttl, data: r.data })) });
  }
  if (url.pathname === "/why") {
    const d = (url.searchParams.get("d") || url.searchParams.get("domain") || "").toLowerCase();
    const tier = Number(url.searchParams.get("tier") || 2);
    await loadHot(env);
    const info = blockedInfo(d, tier);
    const cname = (url.searchParams.get("cname") || "").toLowerCase();
    if (cname) info.cname = cname;
    info.version = VERSION;
    return json(info);
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
    return new Response("NoAS · /dns-query 或 /check 或 /why 或 /health", {
      status: 404, headers: { "content-type": "text/plain; charset=utf-8" },
    });
  }

  // 熔断不返回 503：503 会让客户端直接断服。改为"降级直转"——
  // 跳过规则匹配省 CPU，DNS 照常应答，恢复靠 UTC 换日 + cron 自检复位。
  // Pages 转发时 Worker 只看到 Pages 自己的出口 IP，真实客户端 IP 由 x-noas-cip 带过来；
  // 用错 IP 会让 ECS 声明错地域，上游按错误地区返回 CDN 节点。
  const ip = request.headers.get("x-noas-cip") || request.headers.get("cf-connecting-ip") || "unknown";
  if (await ipLimited(env, ip)) degrade("ip-burst " + PER_IP_PER_MIN + "/min");
  if (!takeQuota()) degrade("quota 90%", 3600000);
  const skipRules = isDegraded();

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

  // EDNS(0)：解析客户端 OPT —— ECS 子网（RFC 7871）与 DO 位（RFC 3225）都在这里
  const mode = url.searchParams.get("mode") || "";   // "" | nxdomain | refused | servfail
  const edns = parseEdns(bytes, end);
  // ?ecs=off：尊重客户端"不要带我的网络前缀"的要求（隐私优先），代价可能拿到较远的 CDN 节点
  const ecsOff = url.searchParams.get("ecs") === "off";
  const ecs = ecsOff ? null : (edns.ecs || clientPrefix(ip) || null);
  let qbytes = bytes;
  if (ecsOff) qbytes = stripEcs(bytes, edns);
  const doBit = edns.doBit;

  // EDNS version > 0：RFC 6891 要求回 BADVERS(ext-rcode 16)，否则客户端会反复重试
  if (edns.version > 0) {
    const q = new Uint8Array(bytes.slice(0, end));
    const total = end + 11;
    const out = new Uint8Array(total);
    out.set(q, 0);
    out[2] = 0x81; out[3] = 0x80;                 // QR=1 RD=1 RA=1，低 4 位 RCODE=0
    out[6] = 0; out[7] = 0; out[8] = 0; out[9] = 0;
    out[10] = 0; out[11] = 1;                     // ARCOUNT=1
    const p = end;
    out[p] = 0;                                   // root
    out[p + 1] = 0; out[p + 2] = 41;              // TYPE=OPT
    out[p + 3] = 0x10; out[p + 4] = 0x00;         // CLASS=4096
    out[p + 5] = 0x01; out[p + 6] = 0x00;         // ext-rcode=1 → 1<<4 = 16
    out[p + 7] = 0; out[p + 8] = 0;               // version=0, flags=0
    out[p + 9] = 0; out[p + 10] = 0;              // RDLEN=0
    return new Response(out, { headers: { "content-type": "application/dns-message",
      "x-noas": "badvers", "x-noas-ver": VERSION } });
  }

  // ANY / CHAOS：经典反射放大面，直接 NOTIMP(4)，不花上游往返也不进规则判定
  if (qtype === 255 || qtype === 3) {
    const head = new Uint8Array(bytes.slice(0, end));
    head[2] = 0x81; head[3] = 0x84;      // QR=1 RD=1 RA=1 RCODE=4
    for (let i = 6; i < 12; i++) head[i] = 0;
    return new Response(head, { headers: { "content-type": "application/dns-message",
      "x-noas": "notimp", "x-noas-ver": VERSION } });
  }

  // AAAA 策略：v4only 时回 NOERROR 空答，客户端立刻回退 A，不在 IPv6 黑洞里干等
  const v6mode = url.searchParams.get("v6") || V6_DEFAULT;
  if (qtype === 28 && v6mode === "v4only") {
    const empty = emptyAnswer(bytes, end);
    return new Response(empty, { headers: { "content-type": "application/dns-message",
      "x-noas": "v4only", "x-noas-ver": VERSION } });
  }

  if (!skipRules) await loadHot(env);
  if (!skipRules && blocked(name, tier)) {
    logHit(env, "block", name, tier, "");
    return new Response(blockedResponse(bytes, qtype, end, mode), {
      headers: { "content-type": "application/dns-message", "x-noas": "blocked", "x-noas-ver": VERSION },
    });
  }
  // 缓存优先：fresh 命中直接返（0 上游 RTT）；stale 命中先返旧值、后台刷新。
  // 旧实现只有"上游全挂"才读缓存，等于每次解析都白付 10-110ms 的上游往返。
  const cached = await cacheLookup(name, qtype, ecs, doBit);
  if (cached && !cached.stale) {
    cacheHits += 1;
    return dnsReply(cached.buf, "cache-hit");
  }
  if (cached && cached.stale) {
    cacheHits += 1;
    if (ctx && ctx.waitUntil) {
      ctx.waitUntil((async () => {
        try {
          const b = await upstream(qbytes, name, ip, edns);
          if (b) await cachePut(name, qtype, b, ecs, doBit);
        } catch (e) { /* 后台刷新失败保留旧值 */ }
      })());
    }
    return dnsReply(cached.buf, "cache-stale");
  }
  const buf = await upstream(qbytes, name, ip, edns);
  if (!buf) {
    degrade("upstream-down");
    const h = { "x-noas": "upstream-fail" };
    if (url.searchParams.get("debug")) {
      h["x-noas-err"] = (lastUpstreamErr || "no-detail").slice(0, 240);
      h["x-noas-req"] = bytes.byteLength + "B " +
        Array.from(bytes.slice(0, 14)).map((b) => b.toString(16).padStart(2, "0")).join("");
    }
    return new Response("上游不可用", { status: 502, headers: h });
  }
  if (!skipRules) {
    // CNAME 反隐蔽：第一方子域 CNAME 到追踪者时，按追踪者判定并直接拦掉（支持多跳）
    const t = await cnameDeep(buf, name, qtype, tier, ip, edns);
    if (t) {
      logHit(env, "cname", name, tier, t);
      return new Response(blockedResponse(bytes, qtype, end, mode), {
        headers: { "content-type": "application/dns-message", "x-noas": "blocked-cname",
                   "x-noas-target": t, "x-noas-ver": VERSION },
      });
    }
    if (Math.random() < 0.05) logHit(env, "pass", name, tier, "");   // 放行只留 5% 样本，省 AE 点数
  }
  // TTL 钳制（60s ~ 3600s）：压掉 5s 的缓存风暴与 7 天的 IP 漂移
  const rc = rcodeOf(buf);
  let finalBuf = buf;
  let clamped = null;
  if (rc === 0 || rc === 3) {
    try {
      const copy = new Uint8Array(buf.slice(0));
      clamped = clampTTL(copy, end, TTL_MIN, TTL_MAX);
      finalBuf = copy;
    } catch (e) { finalBuf = buf; }
  }
  const neg = rc === 3 || rc === 2;
  if (ctx && ctx.waitUntil && !skipRules) ctx.waitUntil(cachePut(name, qtype, finalBuf.slice(0), ecs, doBit));
  return new Response(finalBuf, {
    headers: { "content-type": "application/dns-message",
               "x-noas": skipRules ? "degraded" : (neg ? "negcache" : "pass"),
               "x-noas-ttl": clamped === null ? "-" : String(clamped),
               "x-noas-ecs": ecs ? String(ecs.family) + "/" + String(ecs.prefix) : "-",
               "x-noas-ver": VERSION },
  });
}

function ecsKey(ecs) {
  if (!ecs) return "e:n";
  const a = (ecs.addr || []).slice(0, ecs.family === 2 ? 8 : 3)
    .map((x) => (x | 0).toString(16).padStart(2, "0")).join("");
  return "e:" + ecs.family + "-" + ecs.prefix + "-" + a;
}

// 缓存键必须带 ECS 子网与 DO 位：
//   · 不同子网 → 上游可能返回不同 CDN 节点，共用缓存会把别人的地址发给你
//   · DO=0/1 → DNSSEC 视图不同（AD 位、RRSIG 有无），共用会把 RRSIG 塞给不识 DNSSEC 的客户端
function cacheKey(name, qtype, ecs, doBit) {
  return CACHE_BASE + encodeURIComponent(name) + "/" + qtype + "/" + ecsKey(ecs) + "/d" + (doBit ? 1 : 0);
}

let cacheReady = null;
function hasCache() {
  if (cacheReady === null) {
    try { cacheReady = !!(typeof caches !== "undefined" && caches.default); }
    catch (e) { cacheReady = false; }
  }
  return cacheReady;
}

async function cacheLookup(name, qtype, ecs, doBit) {
  if (!hasCache()) return null;
  try {
    const fresh = await caches.default.match(cacheKey(name, qtype, ecs, doBit));
    if (fresh) return { buf: await fresh.arrayBuffer(), stale: false };
  } catch (e) { /* 继续尝试 stale */ }
  try {
    const old = await caches.default.match(cacheKey(name, qtype, ecs, doBit) + "#swr");
    if (old) return { buf: await old.arrayBuffer(), stale: true };
  } catch (e) { /* 无缓存 */ }
  return null;
}

async function cachePut(name, qtype, buf, ecs, doBit) {
  if (!hasCache()) return;
  // 负缓存（NXDOMAIN / SERVFAIL）用短 TTL：上游说"没有"不代表永远没有，别把故障固化一天
  const rc = rcodeOf(buf);
  const neg = rc === 3 || rc === 2;
  let fresh = CACHE_FRESH_S;
  if (neg) {
    const m = soaMin(buf, qendOf(buf));
    fresh = Math.max(60, Math.min(600, m || 300));
  }
  // 两份：fresh（命中直返）+ stale 24h（fresh 过期后先返旧值、后台刷新）
  const put = (key, maxAge) => caches.default.put(key, new Response(buf.slice(0), {
    headers: { "content-type": "application/dns-message", "cache-control": "max-age=" + maxAge },
  }));
  try { await put(cacheKey(name, qtype, ecs, doBit), fresh); } catch (e) { /* 忽略 */ }
  try { await put(cacheKey(name, qtype, ecs, doBit) + "#swr", neg ? 3600 : CACHE_STALE_S); } catch (e) { /* 忽略 */ }
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
            "fails=" + upstreamFails, "degraded=" + (isDegraded() ? degraded : "-")].join(" "));
  }
}

async function guarded(request, env, ctx) {
  try {
    return await handle(request, env, ctx);
  } catch (e) {
    const msg = String((e && (e.stack || e.message)) || e).replace(/\s+/g, " ").slice(0, 260);
    lastHandlerErr = msg;
    const dbg = new URL(request.url).searchParams.get("debug");
    const h = { "x-noas": "error", "content-type": "text/plain; charset=utf-8" };
    if (dbg) h["x-noas-err"] = msg;
    // 畸形/截断报文（越界读）属于客户端错误：回 400，不要伪装成服务端故障刷告警
    const isBadReq = e instanceof RangeError || /out of ?range|offset|bounds|detached|undefined is not|Cannot read/i.test(msg);
    return new Response(isBadReq ? "报文无法解析" : "内部错误",
      { status: isBadReq ? 400 : 500, headers: isBadReq ? { ...h, "x-noas": "bad-request" } : h });
  }
}

export default { fetch: guarded, scheduled };
