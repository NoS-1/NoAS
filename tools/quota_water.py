#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""quota_water.py —— 免费额度水位：把"离撞墙还有多远"变成每天一个数字。

Code 3 个硬顶（Workers Free 全账号合计）：
  · 请求      100,000 / 天（UTC 重置，超了 Error 1027）
  · KV 读     100,000 / 天（写 1,000 / 天）
  · AE 写点   100,000 / 天
数据来自 Cloudflare GraphQL Analytics（免费、只读）。拿不到数据就明确写 unknown，
绝不拿估算值冒充实测——水位失真比没有水位更危险。

用法：python3 tools/quota_water.py [--warn-at 80] [--mode required|soft]
输出：state/quota.json；任一维度 ≥ warn-at% 打印 WARN，required 模式下 exit 1。
"""
import argparse
import datetime
import json
import os
import sys

LIMITS = {
    "requests": 100000,   # Workers + Pages Functions 共用这一个池
    "kv_requests": 100000,
    "ae_points": 100000,
    # D1 免费口径是"行读/行写"，GraphQL 这里拿到的是查询次数，只能当参考水位，不当硬阈值
    "d1_queries": 5000000,
}

GQL = "https://api.cloudflare.com/client/v4/graphql"
Q = """
query($acc: String!, $from: String!, $to: String!) {
  viewer { accounts(filter: {accountTag: $acc}) {
    workersInvocationsAdaptive(limit: 1000, filter: {date_geq: $from, date_leq: $to}) {
      sum { requests subrequests errors } quantiles { cpuTimeP50 cpuTimeP99 }
      dimensions { date scriptName } }
    kvOperationsAdaptiveGroups(limit: 1000, filter: {date_geq: $from, date_leq: $to}) {
      sum { requests } dimensions { date } }
    workersAnalyticsEngineAdaptiveGroups(limit: 1000, filter: {date_geq: $from, date_leq: $to}) {
      count dimensions { date dataset } }
    d1AnalyticsAdaptiveGroups(limit: 1000, filter: {date_geq: $from, date_leq: $to}) {
      count dimensions { date } }
  } }
}
"""


def fetch():
    import requests
    acc = os.environ.get("CF_ACCOUNT_ID") or "226431c8f431ebb75d82dd5dbd5e8d86"
    tok = os.environ.get("CF_API_TOKEN") or os.environ.get("CF_TOKEN")
    if not acc or not tok:
        return None, "缺少 CF_ACCOUNT_ID / CF_API_TOKEN"
    today = datetime.datetime.now(datetime.timezone.utc).date()
    payload = {"query": Q, "variables": {"acc": acc,
                                         "from": str(today), "to": str(today)}}
    r = requests.post(GQL, headers={"Authorization": "Bearer " + tok,
                                    "content-type": "application/json"},
                      json=payload, timeout=30)
    d = r.json()
    if d.get("errors"):
        return None, str(d["errors"])[:200]
    accs = (d.get("data") or {}).get("viewer", {}).get("accounts") or []
    if not accs:
        return None, "GraphQL 未返回账号数据"
    a = accs[0]
    req = sub = err = 0
    by_script = {}
    cpu50 = cpu99 = None
    for x in a.get("workersInvocationsAdaptive") or []:
        s = x.get("sum") or {}
        n = int(s.get("requests") or 0)
        req += n
        sub += int(s.get("subrequests") or 0)
        err += int(s.get("errors") or 0)
        nm = (x.get("dimensions") or {}).get("scriptName") or "?"
        by_script[nm] = by_script.get(nm, 0) + n
        qq = x.get("quantiles") or {}
        if qq.get("cpuTimeP99") and nm == "noas-doh":
            cpu50, cpu99 = qq.get("cpuTimeP50"), qq.get("cpuTimeP99")
    kv = sum(int((x.get("sum") or {}).get("requests") or 0)
             for x in a.get("kvOperationsAdaptiveGroups") or [])
    ae = sum(int(x.get("count") or 0) for x in a.get("workersAnalyticsEngineAdaptiveGroups") or [])
    d1 = sum(int(x.get("count") or 0) for x in a.get("d1AnalyticsAdaptiveGroups") or [])
    return {"requests": req, "subrequests": sub, "errors": err,
            "kv_requests": kv, "ae_points": ae, "d1_queries": d1, "by_script": by_script,
            "cpu_ms_p50": round((cpu50 or 0) / 1000, 2), "cpu_ms_p99": round((cpu99 or 0) / 1000, 2)}, None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--warn-at", type=int, default=80)
    ap.add_argument("--mode", default="soft", choices=["required", "soft"])
    a = ap.parse_args()

    got, err = fetch()
    now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    if not got:
        out = {"at": now, "ok": False, "error": err, "note": "额度数据不可用，请勿据此判断水位"}
        os.makedirs("state", exist_ok=True)
        open("state/quota.json", "w", encoding="utf-8").write(json.dumps(out, ensure_ascii=False, indent=1) + "\n")
        print(f"WARN 额度水位未知：{err}")
        return

    pct = {k: round(got[k] / LIMITS[k] * 100, 1) for k in LIMITS}
    out = {"at": now, "ok": True, "utc_day_used": True,
           "used": {k: got[k] for k in LIMITS}, "limits": LIMITS, "pct": pct,
           "headroom": {k: LIMITS[k] - got[k] for k in LIMITS},
           "subrequests": got["subrequests"], "errors": got["errors"],
           "cpu_ms_p50": got["cpu_ms_p50"], "cpu_ms_p99": got["cpu_ms_p99"],
           "cpu_limit_ms": 10,
           "by_script": got["by_script"],
           # 观测口径：本表全部来自 Workers 的 workersInvocationsAdaptive 数据集。
           # 实测发 30 次 Pages /why 后该数据集零增长 → Pages Functions 的调用量不在此口径内，
           # 若真实用户主要走 Pages 入口，这里的 requests/KV 水位会**低估**，不能当唯一依据。
           "coverage": {"workers_dataset": True,
                        "pages_functions": "不在 workersInvocationsAdaptive 口径内（实测零计数）"}}
    os.makedirs("state", exist_ok=True)
    open("state/quota.json", "w", encoding="utf-8").write(json.dumps(out, ensure_ascii=False, indent=1) + "\n")

    print("按脚本：" + "、".join(f"{k}={v}" for k, v in (got["by_script"] or {}).items()))
    for k, v in pct.items():
        flag = "WARN" if v >= a.warn_at else "OK  "
        print(f"{flag} {k:12s} {got[k]:>7d} / {LIMITS[k]:>7d}  {v:5.1f}%")
    print(f"OK   cpu_p50      {got['cpu_ms_p50']:>7.2f}ms / 10.00ms   （p99 {got['cpu_ms_p99']:.2f}ms，超 10ms 会被限流）")
    hot = [k for k, v in pct.items() if v >= a.warn_at]
    if got["cpu_ms_p99"] >= 10:
        print(f"WARN cpu_p99 {got['cpu_ms_p99']:.2f}ms ≥ 10ms 免费上限：命中冷启动/慢路径，需继续压")
    if hot and a.mode == "required":
        print("额度接近上限：" + "、".join(hot) + "（需分流或降采样）")
        sys.exit(1)


if __name__ == "__main__":
    main()
