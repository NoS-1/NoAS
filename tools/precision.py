#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""precision.py —— 误伤审计：宁可少拦，也不乱拦。

两道判断：
  1. 注册域保护：一个待拦域，若它属于良性大盘里的站点（如 shop.taobao.com 之于 taobao.com），
     默认不拦——除非它在人工审计过的广告端点表里（如 pos.baidu.com）。
  2. 逐条审计：对每档产物，统计"踩到良性大盘"的条数。必须为 0，否则判红。

产出 history/precision.json，供站点展示与 guard 使用。
"""
import json
import os
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TIERS = ("lite", "mid", "full")


def load(p):
    out = set()
    if not os.path.exists(p):
        return out
    for line in open(p, encoding="utf-8"):
        d = line.split("#", 1)[0].strip().lower()
        if d and "." in d:
            out.add(d)
    return out


def registrable(d):
    parts = d.split(".")
    if len(parts) < 2:
        return d
    # 常见两段式公共后缀
    cc2 = {"com.cn", "net.cn", "org.cn", "gov.cn", "co.uk", "com.au", "co.jp", "co.kr",
           "com.br", "com.mx", "com.tr", "com.tw", "com.hk", "com.sg", "com.my"}
    if len(parts) >= 3 and ".".join(parts[-2:]) in cc2:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def risky(d, benign, endpoints):
    if d in endpoints:
        return None
    reg = registrable(d)
    if reg in benign:
        return reg
    # 子域本身就在良性大盘里（如 mail.google.com 被单独列进大盘）也算
    if d in benign:
        return d
    return None


def main():
    benign = load(os.path.join(ROOT, "lists", "benign_top.txt")) | \
        load(os.path.join(ROOT, "lists", "whitelist.txt")) | \
        load(os.path.join(ROOT, "tests", "benign_baseline.txt"))
    endpoints = load(os.path.join(ROOT, "lists", "ad_endpoints.txt"))

    report = {}
    total_risky = 0
    for tier in TIERS:
        p = os.path.join(ROOT, "subs", tier, "domains.txt")
        if not os.path.exists(p):
            continue
        doms = load(p)
        hits = []
        for d in doms:
            r = risky(d, benign, endpoints)
            if r:
                hits.append((d, r))
        total_risky += len(hits)
        report[tier] = {"count": len(doms), "risky": len(hits), "samples": hits[:8]}

    out = {"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
           "benign_size": len(benign), "tiers": report, "risky_total": total_risky}
    os.makedirs(os.path.join(ROOT, "history"), exist_ok=True)
    json.dump(out, open(os.path.join(ROOT, "history", "precision.json"), "w", encoding="utf-8"),
              ensure_ascii=False, indent=1)

    for tier, r in report.items():
        print("%s：%d 条，踩良性大盘 %d 条" % (tier, r["count"], r["risky"]))
        for d, reg in r["samples"]:
            print("   · " + d + "（属于 " + reg + "）")
    if total_risky:
        print("FAIL 误伤审计：共 " + str(total_risky) + " 条")
        return 1
    print("PASS 误伤审计：0 条")
    return 0


if __name__ == "__main__":
    sys.exit(main())
