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
const benign = [...load('tests/benign_baseline.txt'), ...load('lists/benign_top.txt')];
const endpoints = new Set([
  ...load('lists/ad_endpoints.txt'),
  ...load('lists/cn_ad_endpoints.txt'),
  ...load('lists/layer_backfill.txt'),   // L2/L3 回灌的端点例外，与 compile 同口径
]);

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

// CNAME 反隐蔽：第一方子域 CNAME 到广告域时，必须判为拦截
const cn = await handler(new Request('https://x.dev/check?q=stats.someblog.org&cname=doubleclick.net&tier=1'), {}, ctx);
const cnj = await cn.json();
if (cnj.cname_blocked !== true) { miss.push('cname:doubleclick.net'); }
const cn2 = await handler(new Request('https://x.dev/check?q=stats.someblog.org&cname=api.someblog.org&tier=1'), {}, ctx);
if ((await cn2.json()).cname_blocked !== false) { fp.push('cname-benign'); }

// 通配回归：纯广告网根域的深层子域必须拦；白名单父域下的子域必须放
const wc = await handler(new Request('https://x.dev/check?q=a.b.c.doubleclick.net&tier=1'), {}, ctx);
if (!(await wc.json()).blocked) miss.push('wild:deep-subdomain');
const wok = await handler(new Request('https://x.dev/check?q=a.b.taobao.com&tier=1'), {}, ctx);
if ((await wok.json()).blocked) fp.push('wild:benign-subdomain');

console.log(`lite ${lite.length} 全量｜mid 抽样 ${sample.length}｜良性 ${benign.length}`);
console.log(`漏放 ${miss.length}｜误拦 ${fp.length}`);
if (miss.length) console.log('漏放示例', miss.slice(0, 6));
if (fp.length) console.log('误拦示例', fp.slice(0, 6));
console.log(miss.length || fp.length ? 'FAIL' : 'PASS');
process.exit(miss.length || fp.length ? 1 : 0);
