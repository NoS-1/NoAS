// /why?d=xxx[&tier=N][&cname=y]：规则命中自查（分层理由只有 Worker 知道）
const WORKER_URL = "https://noas-doh.199999510.workers.dev";

export async function onRequest(context) {
  const url = new URL(context.request.url);
  const res = await fetch(WORKER_URL + "/why" + url.search, {
    headers: {
      "user-agent": context.request.headers.get("user-agent") || "NoAS-pages",
      "x-noas-cip": context.request.headers.get("cf-connecting-ip") || "",
    },
    cache: "no-store",
  });
  return new Response(res.body, {
    status: res.status,
    headers: {
      "content-type": res.headers.get("content-type") || "application/json; charset=utf-8",
      "cache-control": "no-store",
      "x-noas-path": "pages-why",
    },
  });
}
