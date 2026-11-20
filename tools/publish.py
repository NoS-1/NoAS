#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""publish.py —— 把 mid/full 两档大列表发到 `data` 分支（单 commit 强制推送）。

为什么单独一条分支：
  · full 档 27 万条、7 个格式 ≈ 55 MB。每天都提交进 main，git 历史会按天膨胀（每月 1.6 GB），
    仓库很快不可用。`data` 分支每次强制推成"只有一个 commit"，历史永远不增长。
  · mid/full 用 jsDelivr 拉 `@data` 分支，带宽免费无限，且不占 API 配额。
  · lite 留在 main（体积小），跟着代码一起走，克隆下来就能用。

用法：
  python3 tools/publish.py --token $GITHUB_TOKEN          # 推 data 分支
  python3 tools/publish.py                                # 只本地打包，不推
"""
import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SUBS = os.path.join(ROOT, "subs")
REPO = os.environ.get("NOAS_REPO", "NoS-1/NoAS")


def run(args, cwd, env=None):
    r = subprocess.run(args, cwd=cwd, capture_output=True, text=True, env=env)
    if r.returncode != 0:
        print(r.stdout[-400:])
        print(r.stderr[-400:])
        raise SystemExit("命令失败：%s" % " ".join(args))
    return r.stdout


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--token", default=os.environ.get("GITHUB_TOKEN", ""))
    ap.add_argument("--branch", default="data")
    ap.add_argument("--repo", default=REPO)
    args = ap.parse_args()

    payload = {}
    for tier in ("mid", "full"):
        d = os.path.join(SUBS, tier)
        if os.path.isdir(d):
            payload[tier] = d
    if not payload:
        print("没有 mid/full 可发布")
        return 0

    tmp = tempfile.mkdtemp(prefix="noas-data-")
    dt = tmp
    run(["git", "init", "-q", "-b", args.branch], dt)
    run(["git", "config", "user.name", "github-actions[bot]"], dt)
    run(["git", "config", "user.email", "41898282+github-actions[bot]@users.noreply.github.com"], dt)
    for tier, src in payload.items():
        shutil.copytree(src, os.path.join(dt, "subs", tier), dirs_exist_ok=True)
    total = sum(os.path.getsize(os.path.join(dp, f))
                for dp, _, fs in os.walk(os.path.join(dt, "subs")) for f in fs)
    json.dump({"updated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
               "tiers": sorted(payload), "bytes": total},
              open(os.path.join(dt, "subs", "data.json"), "w", encoding="utf-8"),
              ensure_ascii=False, indent=1)
    run(["git", "add", "-A"], dt)
    run(["git", "commit", "-q", "-m", "data: mid/full 规则快照（强制单 commit，避免历史膨胀）"], dt)

    if not args.token:
        print("已本地打包到 %s（%.1f MB），未推送（没有 token）" % (dt, total / 1024 / 1024))
        return 0
    url = "https://x-access-token:%s@github.com/%s.git" % (args.token, args.repo)
    run(["git", "push", "-f", "-q", url, "%s:%s" % (args.branch, args.branch)], dt)
    print("已发布 %s 分支：%s ｜%.1f MB" % (args.branch, ",".join(sorted(payload)), total / 1024 / 1024))
    shutil.rmtree(dt, ignore_errors=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
