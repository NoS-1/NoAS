// Pages Function：把 /dns-query 转发给自建 Worker。
//
// 为什么需要这一层：workers.dev 子域在国内被阻断（本机实测 curl 直接 000/超时 6.2s），
// 而 pages.dev 可达（200）。用 Pages 这个"可达域名"做前端、把请求送进 Worker，
// Pages→Worker 是 CF 内部调用，不走公网，因此不受阻断影响。
// 代价：一次解析会计 2 次免费请求额度（Pages Function + Worker），用量小，可接受。
export async function onRequest(context) {
  const { request, next } = context;
  const url = new URL(request.url);
  if (url.pathname !== "/dns-query") return next();

  const target = "https://noas-doh.199999510.workers.dev/dns-query" + url.search;
  // ?probe=1 借这条通道读 Worker 的 /health?probe=1：从 Worker 所在边缘量三家上游耗时。
  // workers.dev 在国内不可达，这是唯一能从国内触发诊断的路子。
  const pr = url.searchParams.get("probe");
  const endpoint = pr
    ? "https://noas-doh.199999510.workers.dev/health?probe=" + encodeURIComponent(pr)
    : target;
  const body = request.method === "POST" ? await request.arrayBuffer() : undefined;
  const res = await fetch(endpoint, {
    method: request.method,
    headers: {
      "content-type": request.headers.get("content-type") || "application/dns-message",
      accept: "application/dns-message",
      "user-agent": "NoAS-pages",
    },
    body,
    cache: "no-store",
  });

  const out = new Headers();
  for (const [k, v] of res.headers) {
    if (k === "content-type" || k.toLowerCase().startsWith("x-noas")) out.set(k, v);
  }
  if (!out.has("content-type")) out.set("content-type", "application/dns-message");
  out.set("x-noas-path", "pages");   // 标记这次应答经过 Pages 层，便于两端对比
  return new Response(res.body, { status: res.status, headers: out });
}
