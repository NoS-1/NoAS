#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""build_gkd.py —— 构建 NoAS 自带的 GKD 远程订阅（L4 无障碍点击层）。

规则来源：@gkd-kit/subscription（MIT，GKD 官方默认订阅）。
本工具只做封装与再发布，不改写任何选择器/规则：
  · 保留上游 categories / globalGroups / apps 原样
  · 重写订阅外壳（id / name / version / 地址 / 反馈入口）
  · 上游拉取失败时沿用上一轮产物，不发空包；一轮都没有才判失败

产物：
  subs/gkd/noas-gkd.json5          完整订阅
  subs/gkd/noas-gkd.version.json5  仅 id + version（GKD 增量更新探测用）
  out/gkd.json                     本轮统计（应用/规则数、上游版本、校验值）
"""
import hashlib
import json
import json5
import os
import sys
import time
import urllib.error
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "subs", "gkd")
STATE = os.path.join(ROOT, "out", "gkd.json")
REPO = os.environ.get("NOAS_REPO", "NoS-1/NoAS")

# 固定订阅 id（正整数；GKD 靠 id 识别同一订阅，换 id 会被当成新订阅）
OUR_ID = 20261120
PAGES_BASE = "https://nos-1.github.io/NoAS"
UA = "NoAS-build-gkd/1.0 (+https://github.com/%s)" % REPO

# 主源 GitHub 原生；备用 npmmirror 镜像。都不带凭证。
SOURCES = [
    "https://raw.githubusercontent.com/gkd-kit/subscription/main/dist/gkd.json5",
    "https://registry.npmmirror.com/@gkd-kit/subscription/latest/files/dist/gkd.json5",
]


def fetch(url):
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "*/*"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        return resp.read().decode("utf-8")


def count_rules(apps):
    groups = 0
    rules = 0
    for app in apps:
        for g in app.get("groups", []) or []:
            groups += 1
            rs = g.get("rules", [])
            if isinstance(rs, list):
                rules += len(rs)
            elif rs:
                rules += 1
    return groups, rules


def main():
    os.makedirs(OUT, exist_ok=True)
    prev = os.path.join(OUT, "noas-gkd.json5")

    raw = None
    last_err = None
    for url in SOURCES:
        try:
            raw = fetch(url)
            break
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            last_err = e
            continue

    if raw is None:
        if os.path.exists(prev):
            print("上游 GKD 规则拉取失败，沿用上一轮产物：%s" % last_err)
            return 0
        print("FAIL：GKD 上游全部失败，且无历史产物可用：%s" % last_err)
        return 1

    try:
        src = json5.loads(raw)
    except Exception as e:
        if os.path.exists(prev):
            print("上游 GKD 规则解析失败，沿用上一轮产物：%s" % e)
            return 0
        print("FAIL：GKD 上游解析失败：%s" % e)
        return 1

    apps = src.get("apps", []) or []
    global_groups = src.get("globalGroups", []) or []
    categories = src.get("categories", []) or []
    if not apps:
        print("FAIL：上游 GKD 订阅为空，拒绝发布")
        return 1

    version = int(src.get("version", 0) or 0)
    groups, rules = count_rules(apps)

    out = {
        "id": OUR_ID,
        "name": "NoAS GKD 订阅（开屏/弹窗跳过）",
        "version": version,
        "author": "NoAS（规则源：@gkd-kit/subscription，MIT）",
        "updateUrl": PAGES_BASE + "/subs/gkd/noas-gkd.json5",
        "checkUpdateUrl": PAGES_BASE + "/subs/gkd/noas-gkd.version.json5",
        "supportUri": "https://github.com/%s/issues" % REPO,
        "categories": categories,
        "globalGroups": global_groups,
        "apps": apps,
    }

    body = json5.dumps(out, ensure_ascii=False, indent=2, quote_keys=False)
    header = ("// NoAS GKD 订阅 · 每日随流水线重建\n"
              "// 规则来源 @gkd-kit/subscription（MIT），NoAS 未改写选择器\n")
    text = header + body + "\n"

    with open(prev, "w", encoding="utf-8") as f:
        f.write(text)

    version_pkt = {"id": OUR_ID, "version": version}
    with open(os.path.join(OUT, "noas-gkd.version.json5"), "w", encoding="utf-8") as f:
        f.write(json5.dumps(version_pkt, ensure_ascii=False, indent=2) + "\n")

    digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
    stats = {
        "source": "@gkd-kit/subscription (MIT)",
        "source_version": version,
        "apps": len(apps),
        "groups": groups,
        "rules": rules,
        "bytes": len(text.encode("utf-8")),
        "sha256": digest,
        "generated_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    os.makedirs(os.path.dirname(STATE), exist_ok=True)
    json.dump(stats, open(STATE, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    print("GKD 订阅已生成：%d 应用 / %d 规则组 / %d 规则（上游 v%d）" % (
        len(apps), groups, rules, version))
    return 0


if __name__ == "__main__":
    sys.exit(main())
