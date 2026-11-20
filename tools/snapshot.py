#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""snapshot.py —— 发布前给当前产物拍快照（known-good），供 rollback.py 一键回滚。

为什么要它：构建失败或发布后才发现误拦时，需要一个"确认能用的上一版"可以立刻退回去。
没有快照就只能重跑全链，而全链里可能有已经坏掉的源。

快照内容：subs/ 下的规则产物 + 通道产物 + 关键台账（不含 68MB 的 CDN 大包）。
存放：state/known_good/<版本号>/，并维护 state/known_good/latest.json 指向最近一次。
"""
import hashlib
import json
import os
import shutil
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SUBS = os.path.join(ROOT, "subs")
KG = os.path.join(ROOT, "state", "known_good")
KEEP = 2   # 只留最近 2 个快照：lite + 通道足够回退，mid/full 从 data 分支取，不占仓库

# 只快照"发布用的产物"，不碰 mid/full 大文本全集以外的缓存
PATTERNS = ("lite", "channels")


def sha(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def main():
    if not os.path.isdir(SUBS):
        print("没有 subs/，无法拍快照")
        return 1
    ver = time.strftime("%Y%m%d-%H%M%S")
    dst = os.path.join(KG, ver)
    manifest = {}
    n = 0
    for pack in PATTERNS:
        src = os.path.join(SUBS, pack)
        if not os.path.isdir(src):
            continue
        for name in sorted(os.listdir(src)):
            fp = os.path.join(src, name)
            if not os.path.isfile(fp) or os.path.getsize(fp) > 30 * 1024 * 1024:
                continue
            rel = os.path.join(pack, name)
            target = os.path.join(dst, pack, name)
            os.makedirs(os.path.dirname(target), exist_ok=True)
            shutil.copy2(fp, target)
            manifest[rel] = sha(fp)
            n += 1
    if n == 0:
        print("没有可快照的产物")
        return 1
    json.dump({"version": ver, "at": time.strftime("%Y-%m-%d %H:%M:%S"),
               "files": manifest}, open(os.path.join(dst, "manifest.json"), "w", encoding="utf-8"),
              ensure_ascii=False, indent=1)
    os.makedirs(KG, exist_ok=True)
    json.dump({"latest": ver, "at": time.strftime("%Y-%m-%d %H:%M:%S")},
              open(os.path.join(KG, "latest.json"), "w", encoding="utf-8"))

    # 清理旧快照
    snaps = sorted(d for d in os.listdir(KG) if os.path.isdir(os.path.join(KG, d)))
    for old in snaps[:-KEEP]:
        shutil.rmtree(os.path.join(KG, old), ignore_errors=True)
        print("清理旧快照 %s" % old)
    print("快照完成：%s，%d 个文件" % (ver, n))
    return 0


if __name__ == "__main__":
    sys.exit(main())
