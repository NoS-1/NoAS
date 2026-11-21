// 缓存必须按 ECS 子网与 DO 位分段：不同客户端子网不能共用同一条应答
import path from 'path';
const ROOT = path.resolve(import.meta.dirname, '..');
const mod = await import(path.join(ROOT, 'doh/worker.js'));
const h = mod.default.fetch;
const ctx = { waitUntil(p) { return p; } };

const store = new Map();
globalThis.caches = { default: {
  async match(k) { return store.get(typeof k === 'string' ? k : k.url); },
  async put(k, v) { store.set(typeof k === 'string' ? k : k.url, v); },
} };
let upstreamHits = 0;
globalThis.fetch = async () => { upstreamHits++; return new Response(new Uint8Array([0,0,0,0]), { headers: { 'content-type': 'application/dns-message' } }); };

const q = (name, ip, doBit) => {
  const labels = name.split('.').flatMap((l) => [l.length, ...l.split('').map((c) => c.charCodeAt(0))]);
  const head = new Uint8Array([0x12,0x34,0x01,0x00,0,1,0,0,0,0,0,(doBit ? 1 : 0)]);
  const body = new Uint8Array([...labels, 0, 0,1, 0,1]);
  let opt = new Uint8Array(0);
  if (doBit) {
    opt = new Uint8Array(11);
    opt[1] = 41; opt[3] = 0x10; opt[5] = 0x00; opt[6] = 0x00; opt[8] = 0x80; opt[10] = 0;
  }
  return new Uint8Array([...head, ...body, ...opt]);
};

const urls = [];
for (const ip of ['203.0.113.10', '198.51.100.20']) {
  const r = await h(new Request('https://x.dev/dns-query', { method: 'POST', body: q('iso.example.com', ip, false),
    headers: { 'cf-connecting-ip': ip } }), {}, ctx);
  await r.arrayBuffer();
  urls.push([...store.keys()]);
}
const keys = [...store.keys()];
console.log('缓存键数量', keys.length, '上游调用', upstreamHits);
console.log(keys.map((k) => k.slice(-40)).join('\n'));
const ok = upstreamHits >= 2 && keys.length >= 2 && new Set(keys.map((k) => k.split('/').pop())).size >= 2;
console.log(ok ? 'PASS 缓存按子网分段' : 'FAIL 不同子网共用缓存');
process.exit(ok ? 0 : 1);
