// /tier：客户端与人的自查入口，等价于 /dns-query?info=1
export async function onRequest(context) {
  const url = new URL(context.request.url);
  url.pathname = "/dns-query";
  url.searchParams.set("info", "1");
  return fetch(url.toString(), {
    headers: { "user-agent": context.request.headers.get("user-agent") || "" },
  });
}
