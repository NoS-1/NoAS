// DNS 层新功能回归：ECS 透传/自动补 OPT、TTL 钳制、负缓存、AAAA v4only、ANY 拒绝、/why
import fs from 'fs';
import path from 'path';

const ROOT = path.resolve(import.meta.dirname, '..');
const mod = await import(path.join(ROOT, 'doh/worker.js'));
const handler = mod.default.fetch;
const ctx = { waitUntil(p) { return p; } };

let pass = 0, fail = [];
const ok = (c, m) => { if (c) pass++; else fail.push(m); };

// ── 报文构造 ─────────────────────────────────────────
const nameWire = (n) => Buffer.concat(n.split('.').map((l) => Buffer.concat([Buffer.from([l.length]), Buffer.from(l, 'latin1')]).subarray(0)).concat([Buffer.from([0])]));
function query(n, qtype = 1, { edns = false, doBit = false, ecs = null } = {}) {
  const q = nameWire(n);
  const head = Buffer.alloc(12);
  head.writeUInt16BE(0x0100, 2); head.writeUInt16BE(1, 4); head.writeUInt16BE(0, 10);
  let ar = 0, opt = Buffer.alloc(0);
  if (edns) {
    ar = 1;
    const opts = [];
    if (ecs) {
      const e = Buffer.from([0, 8]);                       // OPTION-CODE 8 (ECS)
      const fam = ecs.family || 1, pref = ecs.prefix, ip = ecs.addr;
      const pl = Buffer.from([0, fam, pref, 0].concat(ip));
      const o = Buffer.alloc(4 + pl.length);
      o.writeUInt16BE(8, 0); o.writeUInt16BE(pl.length, 2); pl.copy(o, 4);
      opts.push(o);
    }
    const optBody = Buffer.concat(opts);
    opt = Buffer.alloc(11 + optBody.length);
    opt[0] = 0;                                          // root name
    opt.writeUInt16BE(41, 1);                            // TYPE=OPT
    opt.writeUInt16BE(4096, 3);                          // CLASS=udp size
    opt.writeUInt32BE(doBit ? 0x8000 : 0, 5);            // TTL 高 16 位承载 flags
    opt.writeUInt16BE(optBody.length, 9);
    optBody.copy(opt, 11);
  }
  head.writeUInt16BE(ar, 10);
  return Buffer.concat([head, q, Buffer.from([(qtype >> 8) & 0xff, qtype & 0xff]), Buffer.from([0, 1]), opt]);
}
function answer(n, qtype, ttl, { rcode = 0, answers = 1, minSOA = null } = {}) {
  const q = query(n, qtype);
  const h = q.subarray(0, q.length).subarray(0, 12 + nameWire(n).length + 4);
  const head = Buffer.from(h);
  head.writeUInt16BE(0x8180 | rcode, 2);
  head.writeUInt16BE(answers, 6); head.writeUInt16BE(minSOA ? 1 : 0, 8); head.writeUInt16BE(0, 10);
  const rrName = Buffer.from([0xc0, 0x0c]);
  const parts = [head];
  for (let i = 0; i < answers; i++) {
    const rd = qtype === 28 ? Buffer.alloc(16) : Buffer.from([0, 0, 0, 0]);
    const rr = Buffer.alloc(10);
    rr.writeUInt16BE(qtype, 0); rr.writeUInt16BE(1, 2); rr.writeUInt32BE(ttl, 4);
    rr.writeUInt16BE(rd.length, 8);
    parts.push(rrName, rr, rd);
  }
  if (minSOA) {
    const rd = Buffer.alloc(4 + 4 + 20);
    rd.writeUInt32BE(minSOA, 20);
    const rr = Buffer.alloc(10);
    rr.writeUInt16BE(6, 0); rr.writeUInt16BE(1, 2); rr.writeUInt32BE(ttl, 4); rr.writeUInt16BE(rd.length, 8);
    parts.push(Buffer.from([0xc0, 0x0c]), rr, rd);
  }
  return Buffer.concat(parts);
}
const doh = (bytes, extra = '') => {
  const r = new Request('https://x.dev/dns-query' + extra, { method: 'POST', body: bytes,
    headers: { 'content-type': 'application/dns-message', 'cf-connecting-ip': '203.0.113.77' } });
  return handler(r, {}, ctx);
};
// 解出上游收到的报文
let seen = [];
const origFetch = globalThis.fetch;
const mock = (resp) => { globalThis.fetch = async (u, init) => {
  let b = new Uint8Array(0);
  try {
    // worker 上游走 RFC 8484 的 GET 形态，报文在 ?dns= base64url 里
    const url = typeof u === 'string' ? u : (u.url || '');
    const d = new URL(url).searchParams.get('dns');
    if (d) b = new Uint8Array(Buffer.from(d.replace(/-/g, '+').replace(/_/g, '/'), 'base64'));
  } catch (e) { b = new Uint8Array(0); }
  seen.push(b);
  const body = typeof resp === 'function' ? resp() : resp;
  return new Response(body.slice ? body.slice(0) : body, { headers: { 'content-type': 'application/dns-message' } });
}; };

const hasECS = (b) => { try {
  // 扫 AR 段找 type 41 且内含 option 8
  const dv = new DataView(b.buffer, b.byteOffset, b.byteLength);
  let off = 12;
  while (b[off]) off += b[off] + 1; off += 5;
  const cnt = dv.getUint16(6) + dv.getUint16(8) + dv.getUint16(10);
  for (let i = 0; i < cnt; i++) {
    while (off < b.length && b[off] && (b[off] & 0xc0) !== 0xc0) off += b[off] + 1;
    off += (b[off] & 0xc0) === 0xc0 ? 2 : 1;
    const type = dv.getUint16(off);
    const rdlen = dv.getUint16(off + 8);
    if (type === 41) {
      let p = off + 10, e = p + rdlen;
      while (p + 4 <= e) {
        const code = dv.getUint16(p), len = dv.getUint16(p + 2);
        if (code === 8) return { family: dv.getUint16(p + 4), prefix: dv.getUint8(p + 6) };
        p += 4 + len;
      }
    }
    off += 10 + rdlen;
  }
  } catch (e) { return null; }
  return null;
};
const ttls = (buf, qend) => {
  const dv = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  let off = qend;
  const cnt = dv.getUint16(6);
  const out = [];
  for (let i = 0; i < cnt; i++) {
    let jumped = false;
    while (off < buf.length && buf[off]) {
      if ((buf[off] & 0xc0) === 0xc0) { off += 2; jumped = true; break; }
      off += buf[off] + 1;
    }
    if (!jumped && buf[off] === 0) off += 1;
    const t = dv.getUint32(off + 4); out.push(t);
    off += 10 + dv.getUint16(off + 8);
  }
  return out;
};

// 1) 客户端自带 ECS 必须原样透传（/24），不能被出口 IP 覆盖
mock(answer('a.example.com', 1, 300));
seen = []; await doh(query('a.example.com', 1, { edns: true, ecs: { family: 1, prefix: 24, addr: [198, 51, 100] } }));
{ const e = hasECS(seen.at(-1)); ok(e && e.prefix === 24 && e.family === 1, 'ECS 透传 /24'); }

// 2) 无 OPT 的查询：自动补 OPT+ECS（按 cf-connecting-ip /24）
seen = []; await doh(query('b.example.com', 1, { edns: false }));
{ const e = hasECS(seen.at(-1)); ok(e && e.prefix === 24, '无 OPT 自动补 ECS /24'); }

// 3) TTL 钳制：上游 5s → 60s，上游 86400 → 3600
mock(answer('c.example.com', 1, 5));
{ const r = await doh(query('c.example.com', 1)); const b = new Uint8Array(await r.arrayBuffer());
  const ts = ttls(b, 12 + nameWire('c.example.com').length + 4);
  ok(ts.every((t) => t === 60), 'TTL 下限抬到 60'); }
mock(answer('d.example.com', 1, 86400));
{ const r = await doh(query('d.example.com', 1)); const b = new Uint8Array(await r.arrayBuffer());
  ok(ttls(b, 12 + nameWire('d.example.com').length + 4).every((t) => t === 3600), 'TTL 上限压到 3600'); }

// 4) NXDOMAIN：SOA minimum 决定负缓存 TTL，响应头标 negcache
mock(answer('e.example.com', 1, 3600, { rcode: 3, answers: 0, minSOA: 120 }));
{ const r = await doh(query('e.example.com', 1));
  ok(r.headers.get('x-noas') === 'negcache', 'NXDOMAIN 标记 negcache'); }

// 5) AAAA v4only → NOERROR 0 答案
mock(answer('f.example.com', 28, 300));
{ const r = await doh(query('f.example.com', 28, { edns: true }), '?v6=v4only');
  const b = new Uint8Array(await r.arrayBuffer());
  ok(new DataView(b.buffer).getUint16(6) === 0 && r.headers.get('x-noas') === 'v4only', 'AAAA v4only 空答'); }

// 6) ANY → NOTIMP(4)，不走上游
seen = []; await doh(query('g.example.com', 255, { edns: true }), '');
{ ok(seen.length === 0, 'ANY 不打上游'); }

// 6.5) ?mode=nxdomain → RCODE 3 且无答案
{ const r = await doh(query('doubleclick.net', 1), '?mode=nxdomain');
  const b = new Uint8Array(await r.arrayBuffer());
  ok((b[3] & 0xf) === 3 && new DataView(b.buffer).getUint16(6) === 0, 'mode=nxdomain 回 NXDOMAIN'); }

// 7) /why 分层理由
{ const r = await handler(new Request('https://x.dev/why?d=doubleclick.net&tier=2'), {}, ctx);
  const j = await r.json(); ok(j.blocked === true && j.why === 'rule', '/why 命中 rule 层'); }
{ const r = await handler(new Request('https://x.dev/why?d=www.qq.com&tier=2'), {}, ctx);
  const j = await r.json(); ok(j.blocked === false, '/why 白名单放行'); }

// 统一的上游打桩：记录收到的报文，并返回固定应答
const recMock = (mk) => { globalThis.fetch = async (u) => {
  const url = typeof u === 'string' ? u : (u.url || '');
  let b = new Uint8Array(0);
  try { const d = new URL(url).searchParams.get('dns'); if (d) b = new Uint8Array(Buffer.from(d.replace(/-/g, '+').replace(/_/g, '/'), 'base64')); } catch (e) {}
  seen.push(b);
  return new Response(mk(), { headers: { 'content-type': 'application/dns-message' } });
}; };

// 8) CNAME 多跳：上游第一次只给一跳（中间域不在规则里），第二跳才到追踪域 → 必须拦
{
  const qn = (b) => { let o = 12, l = []; while (b[o]) { l.push(Buffer.from(b.slice(o + 1, o + 1 + b[o])).toString('latin1')); o += b[o] + 1; } return l.join('.').toLowerCase(); };
  const cn = (name, target, ttl = 300) => {
    const q = nameWire(name);
    const head = Buffer.alloc(12); head.writeUInt16BE(0x8180, 2); head.writeUInt16BE(1, 4); head.writeUInt16BE(1, 6);
    const rr = Buffer.alloc(10); rr.writeUInt16BE(5, 0); rr.writeUInt16BE(1, 2); rr.writeUInt32BE(ttl, 4);
    const rd = nameWire(target); rr.writeUInt16BE(rd.length, 8);
    return Buffer.concat([head, q, Buffer.from([0, 1, 0, 1]), Buffer.from([0xc0, 0x0c]), rr, rd]);
  };
  globalThis.fetch = async (u) => {
    const d = new URL(typeof u === 'string' ? u : u.url).searchParams.get('dns');
    const b = new Uint8Array(Buffer.from(d.replace(/-/g, '+').replace(/_/g, '/'), 'base64'));
    const q = qn(b);
    const body = q === 'lp.example.com' ? cn('lp.example.com', 'mid.hop.example.net') : cn(q, 'adsrvr.org');
    return new Response(body, { headers: { 'content-type': 'application/dns-message' } });
  };
  const r = await doh(query('lp.example.com', 1));
  ok(r.headers.get('x-noas') === 'blocked-cname' && r.headers.get('x-noas-target') === 'adsrvr.org', 'CNAME 多跳反隐蔽');
}

// 9) EDNS version>0 → BADVERS(ext-rcode 高位 1)，不转上游
{
  const q0 = query('v.example.com', 1, { edns: true });
  const b = Buffer.from(q0); b.writeUInt32BE(0x00010000, b.length - 11 + 5);   // version=1
  seen = [];
  const r = await handler(new Request('https://x.dev/dns-query', { method: 'POST', body: b,
    headers: { 'cf-connecting-ip': '198.51.100.9' } }), {}, ctx);
  const rb = Buffer.from(await r.arrayBuffer());
  const opt = rb.readUInt16BE(10) ? rb.length - 11 : -1;
  const hiBit = opt >= 0 ? (rb[opt + 5] & 0x01) : 0;
  ok(r.headers.get('x-noas') === 'badvers' && seen.length === 0 && hiBit === 1, 'EDNS BADVERS 回 ext-rcode=16 且不转上游');
}

// 10) ?ecs=off → 上游查询不得带 ECS；默认必须带
recMock(() => answer('p.example.com', 1, 300));
{
  seen = [];
  await doh(query('p.example.com', 1, { edns: true, ecs: { prefix: 24, addr: [203, 0, 113, 7] } }), '?ecs=off');
  ok(seen.length > 0 && !hasECS(seen.at(-1)), '?ecs=off 不向上游泄露子网');
}
{ seen = [];
  await doh(query('p.example.com', 1, { edns: true, ecs: { prefix: 24, addr: [203, 0, 113, 7] } }), '');
  ok(seen.length > 0 && !!hasECS(seen.at(-1)), '默认仍透传 ECS'); }

// 11) /resolve 与 dns-json
{ const r = await handler(new Request('https://x.dev/resolve?name=doubleclick.net&type=A&tier=2'), {}, ctx);
  const j = await r.json();
  ok(j.blocked === true && j.Answer[0].data === '0.0.0.0', '/resolve 命中返回 0.0.0.0'); }
{ const r = await handler(new Request('https://x.dev/dns-query?name=doubleclick.net&type=AAAA'), {}, ctx);
  const j = await r.json();
  ok(j.Status === 0 && j.Answer[0].data === '::', 'dns-json AAAA 命中返回 ::'); }
{ recMock(() => answer('www.qq.com', 1, 300));
  const r = await handler(new Request('https://x.dev/resolve?name=www.qq.com&type=A&tier=2'), {}, ctx);
  ok(r.status === 200, '/resolve 200');
  const j = await r.json();
  ok(j.blocked !== true && j.Status === 0 && /^\d+\.\d+\.\d+\.\d+$/.test(j.Answer[0].data) && j.Answer[0].TTL === 300,
     '/resolve 解析 A 记录与 TTL');
  globalThis.fetch = origFetch; }

globalThis.fetch = origFetch;
console.log(`${pass} 项通过｜失败 ${fail.length}`);
if (fail.length) { console.log('FAIL: ' + fail.join(' / ')); process.exit(1); }
