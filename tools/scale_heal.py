#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""scale_heal.py —— 编译后规模骤降的自动重抓（构建层自愈）。

背景：上游 CDN 偶发返回半截内容（HTTP 200 但字节数少一半）。fetch.py 已加了
单源"缩水 30% 就换条件头重试"，但多源合计抖动仍可能让 full/mid 整体掉 15%+，
guard 会照常判红、当天不发布。护栏是对的，但如果只是网络抖动，重抓一次就能恢复。

策略：
1. 读 subs/*/meta.json 的本轮条数，与 history/scale.json 的上轮比；
2. 某档跌超 15%（lite 处于硬上限内属策略截断，不算）→ 清 cache/ 强制全量重抓
   → evolve → promote → compile；
3. 重抓后仍不达标就原样返回 0，让 guard 照常判红（绝不掩盖上游真实失效）。
"""
import json
import os
import shutil
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SUBS = os.path.join(ROOT, "subs")
SCALE = os.path.join(ROOT, "history", "scale.json")
TIERS = ("lite", "mid", "full")
LITE_CAP = 10000


def counts():
    out = {}
    for t in TIERS:
        p = os.path.join(SUBS, t, "meta.json")
        try:
            out[t] = int(json.load(open(p, encoding="utf-8")).get("count") or 0)
        except Exception:
            out[t] = 0
    return out


def dropped(prev, cur):
    bad = []
    for t in TIERS:
        old, new = prev.get(t) or 0, cur.get(t) or 0
        cap = {"lite": 10000, "mid": 20000, "full": 30000}.get(t)
        if cap and new and new < cap * 0.9:
            bad.append("%s 仅 %d 条（目标 %d）" % (t, new, cap))
        elif old and new and new < old * 0.85 and not (t == "lite" and new <= LITE_CAP):
            bad.append("%s %d → %d" % (t, old, new))
    return bad


def run(script, *args):
    cmd = [sys.executable, os.path.join(ROOT, "tools", script)] + list(args)
    print("· %s %s" % (script, " ".join(args)))
    t = time.time()
    rc = subprocess.run(cmd, cwd=ROOT).returncode
    print("  → exit %d（%.1fs）" % (rc, time.time() - t))
    return rc


def main():
    try:
        prev = json.load(open(SCALE, encoding="utf-8"))
    except Exception:
        print("无上轮规模台账，跳过自愈")
        return 0
    cur = counts()
    bad = dropped(prev, cur)
    if not bad:
        print("规模正常：%s" % cur)
        return 0
    print("规模骤降（%s），触发重抓自愈" % "；".join(bad))
    shutil.rmtree(os.path.join(ROOT, "cache"), ignore_errors=True)
    for step, args in (("fetch.py", ()), ("evolve.py", ()), ("promote.py", ()),
                       ("compile.py", ("--force",))):
        if run(step, *args) != 0:
            print("自愈中止：%s 失败，保留现状交由 guard 判定" % step)
            return 0
    cur2 = counts()
    bad2 = dropped(prev, cur2)
    if bad2:
        print("重抓后仍偏低（%s）：可能是上游真的失效，保留现状交由 guard 判红" % "；".join(bad2))
    else:
        print("自愈成功：%s" % cur2)
    return 0


if __name__ == "__main__":
    sys.exit(main())
