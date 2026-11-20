#!/usr/bin/env node
/**
 * NoAS 自建 DoH 服务（零平台依赖，Node 18+）
 * 直接加载构建产物 ../doh/worker.js，一份规则两种形态，不会出现"线上/自建不一致"。
 *
 *   node serve/standalone.mjs                 # 监听 0.0.0.0:8053
 *   DOH_TOKEN=xxx PORT=443 node serve/standalone.mjs
 */
import http from 'node:http';
import path from 'node:path';

const ROOT = path.resolve(import.meta.dirname, '..');
const mod = await import(path.join(ROOT, 'doh', 'worker.js'));
const handler = mod.default.fetch || mod.default;

const PORT = Number(process.env.PORT || 8053);
const HOST = process.env.HOST || '0.0.0.0';
const TOKEN = process.env.DOH_TOKEN || '';

const server = http.createServer(async (req, res) => {
  try {
    const chunks = [];
    if (req.method !== 'GET' && req.method !== 'HEAD') {
      for await (const c of req) chunks.push(c);
    }
    const body = chunks.length ? Buffer.concat(chunks) : undefined;
    const host = req.headers.host || `127.0.0.1:${PORT}`;
    const request = new Request(`http://${host}${req.url}`, {
      method: req.method, headers: req.headers, body,
    });
    // 令牌校验只在 /dns-query 上生效，健康检查与 /check 不需要（方便本机自测）
    if (TOKEN && new URL(request.url).pathname === '/dns-query') {
      const t = new URL(request.url).searchParams.get('token') || req.headers['x-noas-token'] || '';
      if (t !== TOKEN) {
        res.writeHead(401, { 'content-type': 'text/plain; charset=utf-8' });
        res.end('unauthorized：缺少有效令牌');
        return;
      }
    }
    const r = await handler(request, {}, { waitUntil() {} });
    res.writeHead(r.status, Object.fromEntries(r.headers));
    res.end(Buffer.from(await r.arrayBuffer()));
  } catch (e) {
    res.writeHead(500, { 'content-type': 'text/plain; charset=utf-8' });
    res.end('NoAS 服务内部错误：' + (e?.message || e));
  }
});

server.listen(PORT, HOST, () => {
  console.log(`NoAS 独立 DoH 已启动：http://${HOST}:${PORT}/dns-query（健康检查 /health）`);
});
for (const s of ['SIGINT', 'SIGTERM']) process.on(s, () => server.close(() => process.exit(0)));
