// 真产物回归：lite 全量 + mid 抽样必须拦得住，良性域必须放行。
import fs from 'fs';
import path from 'path';

const ROOT = path.resolve(import.meta.dirname, '..');
const mod = await import(path.join(ROOT, 'doh/worker.js'));
const handler = mod.default.fetch;
const ctx = { waitUntil() {} };
const load = (f) => fs.readFileSync(path.join(ROOT, f), 'utf8').split('\n')
  .map((x) => x.trim()).filter((x) => x && !x.startsWith('#') && !x.startsWith('!'));

const lite = load('subs/lite/domains.txt');
const mid = load('subs/mid/domains.txt');
const benign = load('tests/benign_baseline.txt');
const endpoints = new Set(load('lists/ad_endpoints.txt'));

let miss = [], fp = [];
for (const d of lite) {
  const r = await handler(new Request(`https://x.dev/check?q=${d}&tier=1`), {}, ctx);
  if (!(await r.json()).blocked) miss.push('lite:' + d);
}
const sample = [...mid.slice(0, 300), ...mid.slice(-300)];
for (const d of sample) {
  const r = await handler(new Request(`https://x.dev/check?q=${d}&tier=2`), {}, ctx);
  if (!(await r.json()).blocked) miss.push('mid:' + d);
}
for (const d of benign) {
  if (endpoints.has(d)) continue;   // 端点表是"父域在白名单里也照拦"的人工例外
  for (const t of [1, 2]) {
    const r = await handler(new Request(`https://x.dev/check?q=${d}&tier=${t}`), {}, ctx);
    if ((await r.json()).blocked) fp.push(`t${t}:${d}`);
  }
}

console.log(`lite ${lite.length} 全量｜mid 抽样 ${sample.length}｜良性 ${benign.length}`);
console.log(`漏放 ${miss.length}｜误拦 ${fp.length}`);
if (miss.length) console.log('漏放示例', miss.slice(0, 6));
if (fp.length) console.log('误拦示例', fp.slice(0, 6));
console.log(miss.length || fp.length ? 'FAIL' : 'PASS');
process.exit(miss.length || fp.length ? 1 : 0);
