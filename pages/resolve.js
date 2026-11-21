// /resolve?name=&type=[&tier=N]：JSON 视图（解析逻辑与规则集都在 Worker 里，Pages 只做转发）
const WORKER_URL = "https://noas-doh.199999510.workers.dev";

export async function onRequest(context) {
  const url = new URL(context.request.url);
  // /dns-query?name= 也走这里：Google DoH JSON 兼容形态
  const res = await fetch(WORKER_URL + "/resolve" + url.search, {
    headers: {
      "user-agent": context.request.headers.get("user-agent") || "NoAS-pages",
      "x-noas-cip": context.request.headers.get("cf-connecting-ip") || "",
    },
    cf: { cacheTtl: 0 },
  });
  return new Response(res.body, {
    status: res.status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
      "x-noas-path": "pages-resolve",
    },
  });
}
