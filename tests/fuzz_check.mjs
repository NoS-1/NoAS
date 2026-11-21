// 畸形报文不崩：随机截断/越界/随机字节，任何输入都不能返回 500
import path from 'path';
const ROOT = path.resolve(import.meta.dirname, '..');
const mod = await import(path.join(ROOT, 'doh/worker.js'));
const h = mod.default.fetch;
const ctx = { waitUntil() {} };
globalThis.fetch = async () => { throw new Error('no upstream'); };

const rnd = (n) => { const b = new Uint8Array(n); for (let i = 0; i < n; i++) b[i] = Math.floor(Math.random() * 256); return b; };
const base = (() => {
  const name = 'fuzz.example.com'.split('.').flatMap((l) => [l.length, ...l.split('').map((c) => c.charCodeAt(0))]);
  return new Uint8Array([0x12,0x34,0x01,0x00,0,1,0,0,0,0,0,0, ...name, 0, 0,1, 0,1]);
})();

let bad = 0, n = 0;
const cases = [];
for (let i = 1; i <= 200; i++) cases.push(base.slice(0, Math.min(i, base.length)));
for (let i = 0; i < 200; i++) cases.push(rnd(12 + (i % 40)));
for (let i = 0; i < 100; i++) {           // 正常头 + 随机尾
  const c = new Uint8Array(base.length + 20); c.set(base, 0);
  const tail = rnd(20); c.set(tail, base.length); cases.push(c);
}
// 每个畸形报文都会触发一次上游解析（失败约 160ms），500 例串行要 80s。
// 改成 50 并发抢队列：仍跑满 500 例，门禁一条不少，耗时降到 3s 级。
const runOne = async (c) => {
  n++;
  try {
    const r = await h(new Request('https://x.dev/dns-query', {
      method: 'POST', body: c, headers: { 'cf-connecting-ip': '198.51.100.9' } }), {}, ctx);
    // 只有"未捕获异常"(x-noas=error) 或真的抛出来才算失败；502 upstream-fail 是本次 mock 上游断开的预期语义
    if (r.headers.get('x-noas') === 'error') { bad++; const t = await r.text(); if (bad <= 3) console.log('SAMPLE', r.status, r.headers.get('x-noas-err'), t.slice(0,60)); }
  } catch (e) { bad++; }
};
let cursor = 0;
await Promise.all(Array.from({ length: 50 }, async () => {
  while (cursor < cases.length) {
    const c = cases[cursor++];
    await runOne(c);
  }
}));
console.log(`${n} 个畸形输入｜500 或抛异常 ${bad}`);
if (bad) { console.log('FAIL'); process.exit(1); }
console.log('PASS 模糊测试');
