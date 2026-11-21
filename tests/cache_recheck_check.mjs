// 缓存二次校验回归：规则移除后，缓存里的旧"拦截应答"不得继续生效（否则误拦最长 24h）
import fs from 'fs';
import path from 'path';
const ROOT = path.resolve(import.meta.dirname, '..');
import { makeEnv } from './_rules_env.mjs';

let pending = null;
globalThis.caches = { default: { async match() { return pending; }, async put() { return; } } };

const ENV = makeEnv();
const mod = await import(path.join(ROOT, 'doh/worker.js'));
const handler = mod.default.fetch;
const ctx = { waitUntil(p) { return p; } };

let pass = 0, fail = [];
const ok = (c, m) => { if (c) pass++; else fail.push(m); };

const nameWire = (n) => Buffer.concat(n.split('.').map((l) => Buffer.concat([Buffer.from([l.length]), Buffer.from(l, 'latin1')])).concat([Buffer.from([0])]));
function query(n, qtype = 1) {
  const h = Buffer.alloc(12);
  h.writeUInt16BE(0x0100, 2); h.writeUInt16BE(1, 4);
  const q = Buffer.alloc(4); q.writeUInt16BE(qtype, 0); q.writeUInt16BE(1, 2);
  return Buffer.concat([h, nameWire(n), q]);
}
// 构造一条 A 应答（答案 RDATA = ip4）
function answerADDR(n, ip4) {
  const q = Buffer.concat([nameWire(n), Buffer.from([0, 1, 0, 1])]);
  const h = Buffer.alloc(12);
  h.writeUInt16BE(0x8180, 2); h.writeUInt16BE(1, 4); h.writeUInt16BE(1, 6);
  const ans = Buffer.concat([Buffer.from([0xc0, 0x0c]), Buffer.from([0, 1, 0, 1]),
    Buffer.from([0, 0, 0, 60]), Buffer.from([0, 4]), Buffer.from(ip4)]);
  return Buffer.concat([h, q, ans]);
}
const rdata = (buf) => Array.from(buf.slice(buf.length - 4)).join('.');
const req = (n) => handler(new Request('https://x.dev/dns-query', { method: 'POST', body: query(n),
  headers: { 'content-type': 'application/dns-message' } }), ENV, ctx);

// ① 打白名单域（规则不拦），缓存里却是旧拦截应答 → 必须丢缓存，不能返回 0.0.0.0
pending = new Response(answerADDR('www.baidu.com', [0, 0, 0, 0]));
{
  const r = await req('www.baidu.com');
  // 旧拦截应答必须被丢弃：x-noas 不能是 cache-hit（走上游后是 pass）
  ok(r.headers.get('x-noas') !== 'cache-hit', '旧拦截应答仍被当缓存返回（规则已放行）');
}

// ② 正常缓存应答（非零）不受影响，仍由缓存直返
pending = new Response(answerADDR('cache-ok.example', [1, 2, 3, 4]));
{
  const r = await req('cache-ok.example');
  const b = Buffer.from(await r.arrayBuffer());
  ok(r.headers.get('x-noas') === 'cache-hit' && rdata(b) === '1.2.3.4',
     '正常缓存应答被误丢弃或未按缓存直返');
}

// ③ 规则仍在拦的域：缓存怎样都无所谓，必须拦
pending = new Response(answerADDR('adx.alimama.com', [1, 2, 3, 4]));
{
  const r = await req('adx.alimama.com');
  ok(r.headers.get('x-noas') === 'blocked', '规则内域名被缓存放行');
}

pending = null;
console.log(fail.length ? `FAIL ${fail.join('｜')}` : `PASS 缓存二次校验 ${pass} 项`);
process.exit(fail.length ? 1 : 0);
