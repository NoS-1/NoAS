#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""probe.py —— 域名落点探针（从 discover_cn_ads.py 抽出来的公共能力）。

两个用途：
  1. 解析链判定：给一串 CNAME 链，判断它是"广告落点"、"停放页"还是"说不清"；
  2. HTTP 指纹：抓首页，看是否停放页/广告落地页/跳转链。

设计原则：**只做否定，不做肯定**。探针说"这是停放页"可以直接丢；探针说"像广告"只加分，
最终是否算广告还要多信号合计（见 reputation.py）。宁可漏判，绝不误判。
网络不可达时一律返回 unknown，绝不因为探测失败就给域名定罪。
"""
import os
import re
import urllib.request

AD_CHAIN_HINTS = (
    "doubleclick", "googlesyndication", "googleadservices", "adnxs", "adsrvr", "adform",
    "criteo", "taboola", "outbrain", "pubmatic", "rubiconproject", "smartadserver",
    "mopub", "applovin", "ironsource", "unityads", "mintegral", "vungle", "chartboost",
    "pangolin", "pangle", "gdt.qq.com", "admaster", "miaozhen", "iresearch", "talkingdata",
    "umeng", "appsflyer", "adjust.com", "kochava", "branch.io", "sensorsdata", "growingio",
    "scorecardresearch", "moatads", "adsystem", "amazon-adsystem", "casalemedia",
)
PARKING_HINTS = ("overdue", "parking", "sedo", "above.com", "buydomains", "expired",
                 "domainmarket", "hugedomains", "afternic", "godaddy", "dan.com",
                 "undeveloped", "bodis", "parklogic")

# 首页指纹：命中即"这是广告落地页/跳转页"的强证据
HTML_AD_HINTS = (
    "googletagmanager", "googlesyndication", "doubleclick", "adsbygoogle",
    "pagead2", "adserver", "prebid", "criteo", "taboola", "outbrain",
    "propellerads", "popads", "adcash", "exoclick", "juicyads",
)
HTML_PARK_HINTS = ("domain is for sale", "buy this domain", "this domain may be for sale",
                   "parked domain", "域名出售", "该域名可出售", "sedoparking")

OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def classify_chain(chain):
    """chain: CNAME 链的域名列表。返回 (kind, hint)。

    kind ∈ {"parking", "ad", "unknown"}。parking 可以直接判死，ad 只算加分项。
    """
    text = " ".join(chain or []).lower()
    if not text:
        return "unknown", ""
    for p in PARKING_HINTS:
        if p in text:
            return "parking", p
    for h in AD_CHAIN_HINTS:
        if h in text:
            return "ad", h
    return "unknown", ""


def http_probe(host, timeout=6):
    """抓首页做指纹判定。返回 dict：{ok, status, ad_hints, park_hints, title}。

    任何异常都返回 ok=False，调用方必须把 ok=False 当"未知"而不是"干净"。
    """
    out = {"ok": False, "status": 0, "ad_hints": [], "park_hints": [], "title": ""}
    for scheme in ("https://", "http://"):
        try:
            req = urllib.request.Request(scheme + host + "/", method="GET",
                                         headers={"User-Agent": "Mozilla/5.0 NoAS-probe"})
            with OPENER.open(req, timeout=timeout) as r:
                body = r.read(200000).decode("utf-8", "ignore").lower()
                out["status"] = r.status
                out["ok"] = True
                out["ad_hints"] = [h for h in HTML_AD_HINTS if h in body]
                out["park_hints"] = [h for h in HTML_PARK_HINTS if h in body]
                m = re.search(r"<title>(.{0,120}?)</title>", body)
                out["title"] = (m.group(1).strip() if m else "")
                return out
        except Exception:
            continue
    return out


if __name__ == "__main__":
    import json
    import sys
    for h in sys.argv[1:]:
        print(json.dumps({"host": h, "probe": http_probe(h)}, ensure_ascii=False))
