#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""kv_push.py —— 把 mid / full 档规则推进 Workers KV。

为什么要有这一步：Worker 体积上限 1MB，三档全内嵌只能做到 3 万条左右（646KB）就撞墙。
所以内嵌只留 lite（保底 + 零依赖），mid/full 走 KV：
  · Worker 冷启动读一次（cacheTtl 300），KV 免费 10 万读/天，实测日读 400 左右
  · 改规则不用重新部署 Worker，只改 KV —— 分发与代码彻底解耦
  · KV 不可用时 tier2/3 自动退化成 lite（降级不挂）

用法：
  python3 tools/kv_push.py                 # 推送并回读校验
  python3 tools/kv_push.py --dry-run       # 只算体积，不发请求
"""
import argparse
import datetime
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SUBS = os.path.join(ROOT, "subs")
NS = "1e20a4a1c8de4dc892e40ab2ec176f7e"   # 与 Worker 的 RULES 绑定同一个 namespace
API = "https://api.cloudflare.com/client/v4/accounts/{acc}/storage/kv/namespaces/{ns}/values/{key}"


def domains(path):
    out = []
    if not os.path.exists(path):
        return out
    for line in open(path, encoding="utf-8", errors="ignore"):
        s = line.split("#", 1)[0].strip()
        if not s or s.startswith("!"):
            continue
        if s.startswith("||"):
            s = s[2:].rstrip("^")
        if s.startswith("0.0.0.0 "):
            s = s.split()[-1]
        if "." in s and "/" not in s:
            out.append(s.lower())
    return out


def payload(tier):
    ds = sorted(set(domains(os.path.join(SUBS, tier, "domains.txt"))))
    ver = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d-%H%M")
    return {"ver": ver, "tier": tier, "count": len(ds),
            "compact": "|" + "|".join(ds) + "|" if ds else ""}, ds


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args()

    # CI 里 CF_ACCOUNT_ID 是 vars、令牌有时叫 CF_TOKEN：两种都接，账号回退到仓库已知值
    acc = os.environ.get("CF_ACCOUNT_ID") or "226431c8f431ebb75d82dd5dbd5e8d86"
    tok = os.environ.get("CF_API_TOKEN") or os.environ.get("CF_TOKEN")
    if not a.dry_run and (not acc or not tok):
        print("FAIL 缺少 CF_ACCOUNT_ID / CF_API_TOKEN")
        sys.exit(1)

    import requests
    fails = []
    for tier in ("mid", "full"):
        body, ds = payload(tier)
        key = f"{tier}_v1"
        raw = json.dumps(body, ensure_ascii=False).encode("utf-8")
        print(f"{tier}: {len(ds)} 条 / {len(raw)//1024} KB → KV {key}")
        if a.dry_run:
            continue
        if not ds:
            fails.append(f"{tier}：本地 domains.txt 为空，拒绝用空表覆盖线上")
            continue
        r = requests.put(API.format(acc=acc, ns=NS, key=key), headers={"Authorization": "Bearer " + tok},
                         data=raw, timeout=60)
        if r.status_code not in (200, 201):
            fails.append(f"{tier}：写入失败 HTTP {r.status_code} {r.text[:120]}")
            continue
        # 回读校验：拿回 count，确认不是半截 write
        g = requests.get(API.format(acc=acc, ns=NS, key=key), headers={"Authorization": "Bearer " + tok},
                         timeout=60)
        if g.status_code != 200:
            fails.append(f"{tier}：回读失败 HTTP {g.status_code}")
            continue
        try:
            back = g.json()
            if int(back.get("count", -1)) != len(ds):
                fails.append(f"{tier}：回读 count {back.get('count')} ≠ 本地 {len(ds)}")
            else:
                print(f"{tier}: 回读 OK ({back.get('count')} 条, ver {back.get('ver')})")
        except Exception as e:
            fails.append(f"{tier}：回读解析失败 {e}")

    json.dump({"at": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
               "namespace": NS, "ok": not fails, "fails": fails},
              open(os.path.join(ROOT, "state", "kv_push.json"), "w", encoding="utf-8"),
              ensure_ascii=False, indent=1)
    for f in fails:
        print("FAIL " + f)
    if fails:
        sys.exit(1)
    print("KV 分档推送完成")


if __name__ == "__main__":
    main()
