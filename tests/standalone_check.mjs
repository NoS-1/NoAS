// 自建形态回归：起 Node 服务，验拦截/放行/令牌，以及真实 DoH 报文路径。
import { spawn } from 'node:child_process';
import path from 'node:path';

const ROOT = path.resolve(import.meta.dirname, '..');
const PORT = 18053;
const BASE = `http://127.0.0.1:${PORT}`;
const wait = (ms) => new Promise((r) => setTimeout(r, ms));

function dnsQuery(name) {
  const parts = [Buffer.from([0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])];
  for (const l of name.split('.')) parts.push(Buffer.from([l.length]), Buffer.from(l, 'ascii'));
  parts.push(Buffer.from([0x00, 0x00, 0x01, 0x00, 0x01]));
  return Buffer.concat(parts).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

const proc = spawn(process.execPath, [path.join(ROOT, 'serve/standalone.mjs')], {
  env: { ...process.env, PORT: String(PORT) }, stdio: ['ignore', 'pipe', 'pipe'],
});
let out = '';
proc.stdout.on('data', (d) => { out += d; });
proc.stderr.on('data', (d) => { out += d; });

let fail = 0;
try {
  for (let i = 0; i < 40; i++) {
    try { await fetch(BASE + '/health'); break; } catch { await wait(200); }
  }
  const health = await fetch(BASE + '/health').then((r) => r.json());
  console.log(`OK /health：lite ${health.tier1} / mid ${health.tier2} / 版本 ${health.version}`);

  const blocked = await fetch(BASE + '/check?q=doubleclick.net&tier=1').then((r) => r.json());
  if (!blocked.blocked) { console.log('FAIL 广告域未拦'); fail++; } else console.log('OK 广告域被拦');

  const pass = await fetch(BASE + '/check?q=www.baidu.com&tier=2').then((r) => r.json());
  if (pass.blocked) { console.log('FAIL 正常域被拦'); fail++; } else console.log('OK 正常域放行');

  const q = dnsQuery('doubleclick.net');
  const dns = await fetch(`${BASE}/dns-query?dns=${q}`);
  const hdr = dns.headers.get('x-noas') || '';
  if (dns.status !== 200 || hdr !== 'blocked') { console.log(`FAIL DoH 报文路径 status=${dns.status} x-noas=${hdr}`); fail++; }
  else console.log('OK DoH 报文返回拦截应答（0.0.0.0）');
} catch (e) {
  console.log('FAIL 异常：' + (e.message || e));
  console.log(out.slice(-400));
  fail++;
} finally {
  proc.kill();
}
console.log(fail ? `FAIL 自建回归 ${fail} 项` : 'PASS 自建回归');
process.exit(fail ? 1 : 0);
