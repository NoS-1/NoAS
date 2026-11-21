#!/usr/bin/env python3
"""6.9 · Analytics Engine 自检（每天只花 1 个数据点）。

做两件事：
1. 从构建机（海外）发一个真实 DoH 查询，确认 worker 在线且返回 x-noas 头；
2. 用 Analytics Engine SQL API 查最近 15 分钟的数据点，确认写点真的落库。

任何失败都不打红构建：日志类能力不能反过来卡住发布。
"""
import json
import os
import struct
import sys
import urllib.error
import urllib.request

TOK = os.environ.get("CF_API_TOKEN", "").strip()
ACC = os.environ.get("CF_ACCOUNT_ID", "226431c8f431ebb75d82dd5dbd5e8d86").strip()
SCRIPT = os.environ.get("DOH_SCRIPT", "noas-doh").strip()
DATASET = os.environ.get("DOH_AE_DATASET", "noas_dns").strip()
HOST = os.environ.get("DOH_HOST", "").strip()


def subdomain():
    r = urllib.request.Request(
        "https://api.cloudflare.com/client/v4/accounts/%s/workers/subdomain" % ACC,
        headers={"Authorization": "Bearer " + TOK})
    return json.load(urllib.request.urlopen(r, timeout=20))["result"]["subdomain"]


def dns_query(name, qtype=1):
    out = struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
    for lab in name.split("."):
        out += bytes([len(lab)]) + lab.encode()
    out += b"\x00" + struct.pack(">HH", qtype, 1)
    return out


def parse_a(buf):
    """极简 DNS 解析：只取应答里的 A 记录，用来断言"真拦成 0.0.0.0"。"""
    if len(buf) < 12:
        return []
    qd, an = struct.unpack(">HH", buf[4:8])

    def skip(o):
        while o < len(buf):
            ln = buf[o]
            if ln == 0:
                return o + 1
            if ln & 0xC0 == 0xC0:
                return o + 2
            o += ln + 1
        return o

    off = 12
    for _ in range(qd):
        off = skip(off) + 4
    ips = []
    for _ in range(an):
        off = skip(off)
        rtype = struct.unpack(">H", buf[off:off + 2])[0]
        off += 8
        rdlen = struct.unpack(">H", buf[off:off + 2])[0]
        off += 2
        if rtype == 1 and rdlen == 4:
            ips.append(".".join(str(b) for b in buf[off:off + 4]))
        off += rdlen
    return ips


UA = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
      "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0 Safari/537.36")


def get_health(host):
    req = urllib.request.Request("https://%s/health" % host, headers={"user-agent": UA})
    return json.loads(urllib.request.urlopen(req, timeout=25).read())


def ae_sql(query):
    r = urllib.request.Request(
        "https://api.cloudflare.com/client/v4/accounts/%s/analytics_engine/sql" % ACC,
        data=query.encode(),
        headers={"Authorization": "Bearer " + TOK})
    return json.load(urllib.request.urlopen(r, timeout=25))


def main():
    if not TOK:
        print("跳过 AE 自检：未配置 CF_API_TOKEN")
        return 0
    try:
        host = HOST or "%s.%s.workers.dev" % (SCRIPT, subdomain())
    except Exception as e:
        print("取 worker 子域失败（跳过）：%s" % e)
        return 0

    body = dns_query("doubleclick.net")
    req = urllib.request.Request(
        "https://%s/dns-query" % host, data=body,
        headers={"content-type": "application/dns-message",
                 "accept": "application/dns-message",
                 "user-agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                               "AppleWebKit/537.36 (KHTML, like Gecko) "
                               "Chrome/141.0 Safari/537.36"})
    try:
        resp = urllib.request.urlopen(req, timeout=25)
        raw = resp.read()
        ips = parse_a(raw)
        blocked_ok = bool(ips) and all(ip == "0.0.0.0" for ip in ips)
        print("DoH 应答：HTTP %s ／ x-noas=%s ／ %d 字节 ／ A=%s ／ 拦截%s" % (
            resp.status, resp.headers.get("x-noas"), len(raw), ", ".join(ips) or "-",
            "生效" if blocked_ok else "未生效⚠️"))
    except urllib.error.HTTPError as e:
        snippet = ""
        try:
            snippet = e.read()[:160].decode("utf-8", "ignore").replace("\n", " ")
        except Exception:
            pass
        print("DoH 应答：HTTP %s ／ x-noas=%s ／ body=%s" % (
            e.code, e.headers.get("x-noas"), snippet))
    except Exception as e:
        print("DoH 请求失败（不影响构建）：%s" % e)
        return 0

    try:
        h = get_health(host)
        hh = h.get("hot") or {}
        print("health：ver=%s degraded=%s rules_stale=%s upstream_fails=%s ae=%s limiter=%s cache=%s hot=%s" % (
            h.get("version"), h.get("degraded"), h.get("rules_stale"),
            h.get("upstream_fails"), h.get("ae"), h.get("limiter"),
            h.get("cache"), ("%s/%s" % (hh.get("ver"), hh.get("count"))) if hh else None))
        if h.get("limiter") is not True:
            print("⚠️ 原生限流未绑定，已退回 isolate 内存计数（多 isolate 合计会偏松）")
        if h.get("cache") is not True:
            print("⚠️ Cache API 不可用，上游全挂时没有兜底缓存")
        if h.get("degraded"):
            print("⚠️ 线上处于降级：%s" % h.get("degraded"))
        if h.get("rules_stale"):
            print("⚠️ 线上规则落后于仓库，需要重新部署 worker")
    except Exception as e:
        print("health 读取失败（不影响构建）：%s" % e)

    try:
        d = ae_sql("SELECT count() AS n FROM %s WHERE timestamp > NOW() - INTERVAL '15' MINUTE" % DATASET)
        rows = d.get("data") or [{}]
        n = int(rows[0].get("n") or 0)
        print("AE 近 15 分钟数据点：%d" % n)
        if n <= 0:
            print("⚠️ AE 暂无写入（绑定生效或传播延迟），下一轮复查")
    except Exception as e:
        print("AE SQL 查询失败（不影响构建）：%s" % e)
    return 0


if __name__ == "__main__":
    sys.exit(main())
