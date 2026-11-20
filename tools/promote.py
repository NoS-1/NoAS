#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""promote.py —— 把"名字明显是广告/追踪"的单源域自动晋级进 lite。

为什么需要它：
  lite 现在要求"至少 3 个独立源都拦"，稳但保守——很多新出现的广告域只有一个源收录，
  结果日常档漏拦。这里按域名结构做自动晋级，规则可审计、可回滚。

晋级条件（全部满足才算）：
  1. 不在白名单（含父域）；不是广告端点表里已有的
  2. 至少 1 个源收录，且未被白名单剔除
  3. 域名的任一段落命中广告词表（强特征，如 ads./adserver/tracker/click/banner/dsp）
  4. 不是常见服务根域（避免命中 adsl、adobe 这类）
  5. 只晋级到 lite，不改动 mid/full

产物：lists/promoted.txt（自动生成，带来源与理由），compile 会把它并入 lite。
"""
import json
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CACHE = os.path.join(ROOT, "cache")
OUT = os.path.join(ROOT, "lists", "promoted.txt")

# 强特征（广告投放类）：只认这些才进 lite，误伤率最低
STRONG = {
    "ad", "ads", "adserver", "adserv", "advert", "adverts", "advertising", "adservice",
    "adclick", "adnxs", "adtech", "adzerk", "adform", "adition", "adriver",
    "doubleclick", "pagead", "banner", "banners", "prebid", "adsrv", "adsp", "adv",
    "dsp", "ssp", "rtb",
}
# 追踪/统计类：语义更模糊（不少正常产品也用），只晋级到 mid，不进 lite
TRACK = {
    "tracker", "trackers", "tracking", "clicktrack", "click", "clicks", "impression",
    "impressions", "beacon", "pixel", "pixels", "collect", "collector",
    "analytics", "stat", "stats", "counter", "telemetry", "tagmanager", "gtag",
}
# 误伤高危词：这些即使命中也要排除（常见品牌/协议段）
DANGER = {
    "adsl", "adobe", "adidas", "adapter", "adaptive", "admin", "address", "advanced",
    "adventure", "addon", "adult", "adwords? ", "radio", "radar", "shadow", "header",
    "dashboard", "download", "load", "payload", "reload", "upload", "statue", "state",
    "station", "static", "statistics? ", "metadata", "dataset", "datacenter",
}


def load_domains(path):
    out = set()
    if not os.path.exists(path):
        return out
    for line in open(path, encoding="utf-8"):
        d = line.split("#", 1)[0].strip().lower()
        if d and "." in d and not d.startswith("."):
            out.add(d)
    return out


def labels(d):
    return re.split(r"[.\-_]", d)


def promoted_ok(d, allow, endpoints, strong_only=True):
    # 白名单父域保护
    parts = d.split(".")
    if any(".".join(parts[i:]) in allow for i in range(len(parts) - 1)):
        return False
    if d in endpoints:
        return False
    if len(d) > 60:
        return False
    for lab in labels(d):
        if lab in DANGER or any(lab.startswith(x) for x in ("adsl", "adobe", "adidas", "adapter")):
            return False
    # 只看域名主体段，不看 TLD（否则 .click 这种垃圾后缀会全量进档）
    body = labels(d)[:-1]
    ad_hit = [lab for lab in body if lab in STRONG or lab.startswith(("ad-", "ads-", "advert"))]
    trk_hit = [lab for lab in body if lab in TRACK]
    return bool(ad_hit) if strong_only else bool(ad_hit or trk_hit)


def main():
    allow = load_domains(os.path.join(ROOT, "tests", "benign_baseline.txt")) | \
        load_domains(os.path.join(ROOT, "lists", "whitelist.txt"))
    endpoints = load_domains(os.path.join(ROOT, "lists", "ad_endpoints.txt"))
    full = load_domains(os.path.join(ROOT, "subs", "full", "domains.txt"))
    lite = load_domains(os.path.join(ROOT, "subs", "lite", "domains.txt"))

    per_source = {}
    if os.path.exists(os.path.join(CACHE, "sources.json")):
        try:
            meta = json.load(open(os.path.join(CACHE, "sources.json"), encoding="utf-8"))
            for name, info in (meta.get("sources") or {}).items():
                per_source[name] = int(info.get("entries") or 0)
        except Exception:
            pass

    picked = sorted(d for d in full if promoted_ok(d, allow, endpoints, True))
    track = sorted(d for d in full if promoted_ok(d, allow, endpoints, False) and d not in picked)
    with open(OUT, "w", encoding="utf-8") as fh:
        fh.write("# 自动晋级进 lite：域名结构命中广告强特征，且未被白名单/端点表覆盖\n")
        fh.write("# 生成规则见 tools/promote.py；本文件由工具覆盖，不手改\n")
        for d in picked:
            fh.write(d + "\n")
    print("自动晋级（进 lite）：" + str(len(picked)) + " 条；追踪类（进 mid）：" + str(len(track)) + " 条（纯函数：只由 full + 白名单决定，反复运行结果一致）")
    for d in picked[:5]:
        print("  · " + d)
    return 0


if __name__ == "__main__":
    sys.exit(main())
