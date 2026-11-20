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
                 "accept": "application/dns-message"})
    try:
        resp = urllib.request.urlopen(req, timeout=25)
        print("DoH 应答：HTTP %s ／ x-noas=%s ／ %d 字节" % (
            resp.status, resp.headers.get("x-noas"), len(resp.read())))
    except urllib.error.HTTPError as e:
        print("DoH 应答：HTTP %s ／ x-noas=%s" % (e.code, e.headers.get("x-noas")))
    except Exception as e:
        print("DoH 请求失败（不影响构建）：%s" % e)
        return 0

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
