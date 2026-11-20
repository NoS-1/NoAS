#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""guard.py —— 发布前的硬校验与自愈护栏。

订阅发错一次，用户正常网站就打不开，而且他很难定位原因。所以这里只查"能直接判死"的项：
  1. 七个格式条数必须一致（渲染路径漏一条就判红）
  2. 任何一条都不得命中白名单（含父域保护）
  3. 不许有重复条目 / 非法字符
  4. meta 里的 sha256 必须与真实文件一致
  5. 抽查：已知广告域必须拦，已知正常域必须放行
  6. 规模突变护栏：比上一轮少 15% 以上 → 判红（多半是上游集体失效，宁可停发也不发残包）
"""
import hashlib
import json
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SUBS = os.path.join(ROOT, "subs")
TIERS = ("lite", "mid", "full")
FILES = ["adguard.txt", "domains.txt", "hosts.txt", "dnsmasq.conf",
         "clash.yaml", "surge.list", "singbox.json"]

MUST_BLOCK_LITE = ["doubleclick.net", "googlesyndication.com", "applovin.com"]
MUST_NOT_BLOCK = ["www.baidu.com", "github.com", "www.bilibili.com", "api.weixin.qq.com",
                  "www.taobao.com", "mp.weixin.qq.com", "www.zhihu.com"]


def load_allow():
    allow = set()
    for rel in ("tests/benign_baseline.txt", "lists/whitelist.txt"):
        p = os.path.join(ROOT, rel)
        if os.path.exists(p):
            for line in open(p, encoding="utf-8"):
                line = line.split("#", 1)[0].strip().lower()
                if line and "." in line:
                    allow.add(line)
    return allow


def protected(d, allow):
    parts = d.split(".")
    return any(".".join(parts[i:]) in allow for i in range(len(parts) - 1))


def domains_of(tier, name):
    p = os.path.join(SUBS, tier, name)
    if not os.path.exists(p):
        return None
    text = open(p, encoding="utf-8").read()
    if name == "singbox.json":
        return json.loads(text)["rules"][0]["domain_suffix"]
    out = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line[0] in "#!" or line.startswith("payload:"):
            continue
        for pat in (r"^\|\|(.+?)\^$", r"^0\.0\.0\.0\s+(\S+)$",
                    r"^address=/(\S+)/0\.0\.0\.0$", r"^(?:- +)?DOMAIN-SUFFIX,(\S+)$"):
            m = re.match(pat, line)
            if m:
                line = m.group(1)
                break
        out.append(line.lower())
    return out


def main():
    fails = []
    allow = load_allow()
    summary = {}

    for tier in TIERS:
        base = domains_of(tier, "domains.txt")
        if base is None:
            fails.append("%s：缺少 domains.txt" % tier)
            continue
        counts = {}
        for f in FILES:
            d = domains_of(tier, f)
            if d is None:
                fails.append("%s：缺少 %s" % (tier, f))
                continue
            counts[f] = len(d)
            if len(d) != len(set(d)):
                fails.append("%s/%s 有重复 %d 条" % (tier, f, len(d) - len(set(d))))
        if len(set(counts.values())) != 1:
            fails.append("%s：七格式条数不一致 %s" % (tier, counts))
        if len(base) < 100:
            fails.append("%s：条数过少 %d" % (tier, len(base)))
        hit = sorted({d for d in set(base) if protected(d, allow)})
        if hit:
            fails.append("%s：混入白名单域 %d 条：%s" % (tier, len(hit), ", ".join(hit[:5])))
        bad = [d for d in set(base) if not re.match(r"^[a-z0-9][a-z0-9.\-]*$", d)]
        if bad:
            fails.append("%s：非法域名 %d 条：%s" % (tier, len(bad), ", ".join(bad[:5])))
        mp = os.path.join(SUBS, tier, "meta.json")
        if not os.path.exists(mp):
            fails.append("%s：缺少 meta.json" % tier)
        else:
            meta = json.load(open(mp, encoding="utf-8"))
            if meta.get("count") != len(base):
                fails.append("%s：meta.count=%s 与实际 %d 不符" % (tier, meta.get("count"), len(base)))
            for f in FILES:
                p = os.path.join(SUBS, tier, f)
                if not os.path.exists(p):
                    continue
                real = hashlib.sha256(open(p, "rb").read()).hexdigest()
                if meta.get("files", {}).get(f, {}).get("sha256") != real:
                    fails.append("%s/%s sha256 与 meta 不一致" % (tier, f))
                if os.path.getsize(p) > 40 * 1024 * 1024:
                    fails.append("%s/%s 超过 40MB" % (tier, f))
        summary[tier] = len(base)

    lite = set(domains_of("lite", "domains.txt") or [])
    for d in MUST_BLOCK_LITE:
        if d not in lite:
            fails.append("lite 缺已知广告域：%s" % d)
    for d in MUST_NOT_BLOCK:
        if d in lite:
            fails.append("lite 误收录正常域：%s" % d)

    # 规模突变护栏：与上一轮（history/scale.json）比较
    hist = os.path.join(ROOT, "history", "scale.json")
    prev = {}
    if os.path.exists(hist):
        try:
            prev = json.load(open(hist, encoding="utf-8"))
        except Exception:
            prev = {}
    for tier, n in summary.items():
        old = prev.get(tier)
        if old and n < old * 0.85:
            fails.append("%s 规模骤降：%d → %d（超过 15%%，疑似上游失效）" % (tier, old, n))
    os.makedirs(os.path.dirname(hist), exist_ok=True)
    json.dump(summary, open(hist, "w", encoding="utf-8"), ensure_ascii=False, indent=1)

    if fails:
        print("FAIL 发布校验 %d 项：" % len(fails))
        for f in fails:
            print("  · " + f)
        return 1
    print("PASS 发布校验：%s｜白名单无冲突｜七格式一致｜meta 校验通过" % summary)
    return 0


if __name__ == "__main__":
    sys.exit(main())
