#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""report.py —— 把构建结果变成站点数据（docs/data.json）与 Pages 镜像通道。

只输出事实，不写营销话术：
  · 三档当前条数、版本、生成时间
  · 每档 7 个格式的字节数与 sha256（前端可直接下载校验）
  · 源健康度（history/health.json）
  · 自我成长记录（history/evolution.json，最近 30 次事件）
  · 交付通道清单（raw / Pages / Release），全部是 GitHub 自家
"""
import json
import os
import shutil
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SUBS = os.path.join(ROOT, "subs")
DOCS = os.path.join(ROOT, "docs")
TIERS = ("lite", "mid", "full")
REPO = os.environ.get("NOAS_REPO", "NoS-1/NoAS")


def read_json(path, default):
    try:
        return json.load(open(path, encoding="utf-8"))
    except Exception:
        return default


def main():
    os.makedirs(DOCS, exist_ok=True)

    # Pages 镜像通道：把 lite 档复制进站点目录，Pages 带宽免费、与 raw 互为备份
    src = os.path.join(SUBS, "lite")
    dst = os.path.join(DOCS, "subs", "lite")
    if os.path.isdir(src):
        shutil.copytree(src, dst, dirs_exist_ok=True)

    # 路径层与 uBO 规则同样镜像进站点，国内访问 Pages 比 raw 稳
    p_src = os.path.join(SUBS, "paths")
    if os.path.isdir(p_src):
        shutil.copytree(p_src, os.path.join(DOCS, "subs", "paths"), dirs_exist_ok=True)

    tiers = {}
    for t in TIERS:
        meta = read_json(os.path.join(SUBS, t, "meta.json"), {})
        files = meta.get("files", {})
        tiers[t] = {
            "count": meta.get("count"),
            "version": meta.get("version"),
            "wildcards": meta.get("wildcards", 0),
            "generated_utc": meta.get("generated_utc"),
            "files": {k: {"bytes": v.get("bytes"), "sha256": v.get("sha256")} for k, v in files.items()},
        }

    compile_report = read_json(os.path.join(ROOT, "out", "compile.json"), {})
    health = read_json(os.path.join(ROOT, "history", "health.json"), {})
    evo = read_json(os.path.join(ROOT, "history", "evolution.json"), [])
    scale = read_json(os.path.join(ROOT, "history", "scale.json"), {})

    data = {
        "repo": REPO,
        "updated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "tiers": tiers,
        "sources": {
            "count": len(compile_report.get("sources", {})),
            "whitelist_blocked": compile_report.get("whitelist_blocked"),
            "ad_endpoints": compile_report.get("ad_endpoints"),
            "per_source": compile_report.get("sources", {}),
        },
        "health": health,
        "evolution": (evo or [])[-6:],
        "scale": scale,
        "channels": [
            {"name": "raw.githubusercontent.com", "note": "GitHub 原生文件通道，随仓库更新即生效"},
            {"name": "GitHub Pages", "note": "站点镜像通道，与 raw 互为备份，带宽由 GitHub 承担"},
            {"name": "Release 资产", "note": "单包下载通道（lite+mid+full+DoH 产物打包），长期留档"},
        ],
    }
    out = os.path.join(DOCS, "data.json")
    json.dump(data, open(out, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    print("已生成 docs/data.json：" + "、".join(
        t + " " + str(tiers[t]["count"]) for t in TIERS if tiers[t]["count"]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
