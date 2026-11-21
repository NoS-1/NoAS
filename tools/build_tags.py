#!/usr/bin/env python3
"""build_tags.py —— 给每条规则打标签，产出 lists/tags.tsv 与 out/tags.json。

为什么需要：把"为什么拦这条"变成可追溯的字段。
现在订阅里只有域名，出问题只能靠猜；有了标签，可以逐条解释来源，
也能按 SDK / 类别统计占比、做分模块订阅。

标签优先级（同一域可带多个）：
  cn-endpoint   人工审计或自动发现的国内首方广告端点（全档强制）
  cn-watch      观察池（仅 mid/full）
  ad-network    核心广告网络根域
  ad-label      域名结构本身即广告（ad/ads/splash/gromore…）
  sdk           第三方广告 SDK 域
  video         长视频贴片广告域
  miner         加密挖矿域
  affiliate     联盟跳转短链
  telemetry     系统遥测域
  consensus     仅靠多源共识
"""
import json
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LISTS = ROOT / "lists"
SUBS = ROOT / "subs"
OUT = ROOT / "out"
AD_LABELS = {"ad", "ads", "adx", "adserver", "adservice", "adapi", "adlog",
             "adstat", "adsdk", "splash", "splashad", "gromore", "pangolin",
             "pangle", "openads", "mobads", "union", "track", "tracker",
             "stat", "stats", "analytics", "metrics", "beacon"}


def lines_of(p):
    if not p.exists():
        return []
    out = []
    for line in p.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.split("#", 1)[0].strip()
        if line and "." in line and "/" not in line:
            out.append(line.split("\t")[0].strip().lower())
    return out


def main():
    lite = set(lines_of(SUBS / "lite" / "domains.txt"))
    mid = set(lines_of(SUBS / "mid" / "domains.txt"))
    full = set(lines_of(SUBS / "full" / "domains.txt"))
    ep = set(lines_of(LISTS / "ad_endpoints.txt")) | set(lines_of(LISTS / "cn_ad_endpoints.txt"))
    watch = set(lines_of(LISTS / "cn_ad_watch.txt"))
    core = set(lines_of(LISTS / "core_ad_networks.txt"))
    miner = set(lines_of(LISTS / "miner.txt"))
    aff = set(lines_of(LISTS / "affiliate.txt"))
    tel = set(lines_of(LISTS / "telemetry.txt"))
    sdk = set(lines_of(LISTS / "sdk_ads.txt"))
    video = set(lines_of(LISTS / "video_ads.txt"))
    sdk = set(lines_of(LISTS / "sdk_ads.txt"))
    video = set(lines_of(LISTS / "video_ads.txt"))

    # 只给"需要解释来源"的域打标签，避免把 41 万条长尾全写进台账（仓库体积会爆）：
    # 全 lite + 端点/观察池/核心网/分类表 + 命名结构即广告的长尾
    # 定档后档位是有上限的子集，台账必须覆盖每个已发布域，否则"拦了某条却查不到出处"
    all_doms = (set(lite) | set(mid) | set(full) | set(ep) | set(watch) | set(core)
                | set(miner) | set(aff) | set(tel) | set(sdk) | set(video))
    for d in (mid | full):
        labels = d.split(".")[:-2]
        if any(x in AD_LABELS for x in labels):
            all_doms.add(d)
    tags = {}

    def add(d, tag):
        tags.setdefault(d, set()).add(tag)

    for d in all_doms:
        labels = d.split(".")[:-2]
        if any(x in AD_LABELS for x in labels):
            add(d, "ad-label")
        if d in ep:
            add(d, "cn-endpoint")
        if d in watch:
            add(d, "cn-watch")
        if d in core:
            add(d, "ad-network")
        if d in miner:
            add(d, "miner")
        if d in aff:
            add(d, "affiliate")
        if d in tel:
            add(d, "telemetry")
        if d in sdk:
            add(d, "sdk")
        if d in video:
            add(d, "video")
        if d in sdk:
            add(d, "sdk")
        if d in video:
            add(d, "video")
        if not tags.get(d):
            add(d, "consensus")

    # 只保留真实存在于档位里的域：端点/核心网可能被白名单剔除或 children 合并而消失
    instock = lite | mid | full
    rows = sorted((d, ",".join(sorted(t))) for d, t in tags.items() if d in instock)
    with open(LISTS / "tags.tsv", "w", encoding="utf-8") as f:
        f.write("# NoAS 规则标签台账：域名 <TAB> 标签（逗号分隔）\n")
        f.write("# 自动生成，勿手改；改分类请动 lists/*.txt 与 tools/build_tags.py\n")
        for d, t in rows:
            f.write("%s\t%s\n" % (d, t))

    counts = {}
    for _, t in rows:
        for tag in t.split(","):
            counts[tag] = counts.get(tag, 0) + 1
    tiers = {"lite": len(lite), "mid": len(mid), "full": len(full)}
    os.makedirs(OUT, exist_ok=True)
    (OUT / "tags.json").write_text(json.dumps(
        {"counts": counts, "tiers": tiers, "total": len(rows)}, ensure_ascii=False, indent=1) + "\n",
        encoding="utf-8")
    print("标签台账：%d 条 ／分类 %s" % (len(rows), json.dumps(counts, ensure_ascii=False)))


if __name__ == "__main__":
    main()
