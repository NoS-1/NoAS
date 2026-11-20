#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""rollback.py —— 从 known-good 快照一键恢复产物。

用法：
  python3 tools/rollback.py                 # 恢复到 latest 快照
  python3 tools/rollback.py <版本号>         # 恢复到指定快照
  python3 tools/rollback.py --check         # 只校验当前产物是否与快照一致，不覆盖

典型场景：guard 判红但已经推了产物、或线上订阅出现大面积误拦，
直接回滚，避免"越修越坏"。
"""
import hashlib
import json
import os
import shutil
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SUBS = os.path.join(ROOT, "subs")
KG = os.path.join(ROOT, "state", "known_good")


def sha(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def resolve(ver):
    if ver:
        p = os.path.join(KG, ver)
    else:
        lp = os.path.join(KG, "latest.json")
        if not os.path.exists(lp):
            return None
        p = os.path.join(KG, json.load(open(lp, encoding="utf-8"))["latest"])
    return p if os.path.isdir(p) else None


def main():
    args = sys.argv[1:]
    check = "--check" in args
    ver = next((a for a in args if not a.startswith("--")), None)
    src = resolve(ver)
    if not src:
        print("找不到快照（state/known_good/ 为空或版本不存在）")
        return 1
    man = os.path.join(src, "manifest.json")
    if not os.path.exists(man):
        print("快照缺 manifest.json，拒绝使用（可能已损坏）")
        return 1
    files = json.load(open(man, encoding="utf-8"))["files"]

    bad = []
    for rel, want in files.items():
        cur = os.path.join(SUBS, rel)
        if not os.path.exists(cur) or sha(cur) != want:
            bad.append(rel)
    print("快照 %s：%d 个文件，当前产物与之一致 %d，不一致 %d"
          % (os.path.basename(src), len(files), len(files) - len(bad), len(bad)))
    if check or not bad:
        return 0

    for rel in bad:
        dst = os.path.join(SUBS, rel)
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        shutil.copy2(os.path.join(src, rel), dst)
    # 恢复后再验一次
    still = [r for r in bad if sha(os.path.join(SUBS, r)) != files[r]]
    if still:
        print("回滚后仍有 %d 个文件校验失败：%s" % (len(still), ", ".join(still[:5])))
        return 1
    print("回滚完成：恢复 %d 个文件" % len(bad))
    return 0


if __name__ == "__main__":
    sys.exit(main())
