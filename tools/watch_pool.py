#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""watch_pool.py —— 观察池影子计时器：低置信域必须先"观察"够久才准晋级。

问题：cn_ad_watch.txt 原来只进不出，也没有时间戳。一个词元碰巧命中 ad 的子域会永久
留在 mid/full 里，长期累积成误拦。

规则（对应企业界 shadow mode 的通行做法：观察够久、误报为 0 才执行）：
  · 新域首次出现 → 只记 first_seen，不晋级（影子期）
  · 在池内 >= SHADOW_DAYS(14) 天，且至少被 2 轮独立发现复现 → 晋级 cn_ad_endpoints.txt
  · 在池内 > EXPIRE_DAYS(30) 天仍未复现（hits <= 1）→ 退役，写 watch_retired.txt
  · 每次实锤复现（本轮重新解析到）hits += 1

元数据存 state/watch_pool.json（权威）。cn_ad_watch.txt 仍由 discover 覆盖写，
本工具在其后运行，负责补时间戳、晋级、退役，不改变 discover 的写入格式。
"""
import json
import os
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LISTS = os.path.join(ROOT, "lists")
STATE = os.path.join(ROOT, "state", "watch_pool.json")
WATCH = os.path.join(LISTS, "cn_ad_watch.txt")
EP = os.path.join(LISTS, "cn_ad_endpoints.txt")
RETIRED = os.path.join(LISTS, "watch_retired.txt")

SHADOW_DAYS = 14
EXPIRE_DAYS = 30
PROMOTE_HITS = 2
RETIRE_HITS = 1


def days_between(a, b):
    try:
        ta = time.mktime(time.strptime(a, "%Y-%m-%d"))
        tb = time.mktime(time.strptime(b, "%Y-%m-%d"))
        return int((tb - ta) // 86400)
    except Exception:
        return 0


def load_watch():
    out = {}
    if not os.path.exists(WATCH):
        return out
    for line in open(WATCH, encoding="utf-8"):
        if line.startswith("#") or not line.strip():
            continue
        cols = line.rstrip("\n").split("\t")
        if len(cols) >= 1 and "." in cols[0]:
            out[cols[0].lower()] = (cols[1] if len(cols) > 1 else "",
                                    cols[2] if len(cols) > 2 else "prev")
    return out


def load_ep():
    out = set()
    if os.path.exists(EP):
        for line in open(EP, encoding="utf-8"):
            if line.startswith("#"):
                continue
            cols = line.rstrip("\n").split("\t")
            if cols and "." in cols[0]:
                out.add(cols[0].lower())
    return out


def main():
    today = time.strftime("%Y-%m-%d")
    watch = load_watch()
    ep = load_ep()

    # 自相矛盾先纠正：已经实证进 lite 的域不该还挂"低置信观察"的身份。
    # 观察到 lite 是最强的晋级证据，直接出池，留在 lite 里不动。
    lite_now = set()
    lp = os.path.join(ROOT, "subs", "lite", "domains.txt")
    if os.path.exists(lp):
        for line in open(lp, encoding="utf-8"):
            x = line.split("#", 1)[0].strip().lower()
            if x and "." in x:
                lite_now.add(x.split("\t")[0])
    conflict = [d for d in watch if d in lite_now]
    if conflict:
        keep = []
        for line in open(WATCH, encoding="utf-8"):
            if line.startswith("#"):
                keep.append(line)
                continue
            if line.split("\t")[0].strip().lower() in conflict:
                continue
            keep.append(line)
        open(WATCH, "w", encoding="utf-8").writelines(keep)
        for d in conflict:
            watch.pop(d, None)
        print("观察池与 lite 冲突 %d 条，已按 lite 为准出池：%s" % (len(conflict), ", ".join(conflict[:5])))

    pool = {}
    if os.path.exists(STATE):
        try:
            pool = json.load(open(STATE, encoding="utf-8"))
        except Exception:
            pool = {}

    promoted, retired, fresh, kept = [], [], 0, 0
    for dom, (token, mark) in watch.items():
        rec = pool.get(dom)
        if not rec:
            pool[dom] = {"first_seen": today, "last_seen": today, "hits": 1,
                         "token": token, "last_mark": mark}
            fresh += 1
            continue
        rec["token"] = token or rec.get("token", "")
        rec.setdefault("first_seen", today)
        rec["last_mark"] = mark
        # 关键：只有"本轮真解析到"才算复现。历史保留（prev）不动 hits，
        # 否则没复现的域也会攒够次数被晋级——那就是把误拦放了进来。
        if mark == "probe":
            rec["last_seen"] = today
            rec["hits"] = int(rec.get("hits", 1)) + 1

        age = days_between(rec["first_seen"], today)
        if age >= SHADOW_DAYS and rec["hits"] >= PROMOTE_HITS and dom not in ep:
            promoted.append(dom)
        elif age > EXPIRE_DAYS and rec["hits"] <= RETIRE_HITS:
            retired.append(dom)
        else:
            kept += 1

    # 晋级：追加到端点表（不重写，避免破坏 discover 的注释与列结构）
    if promoted:
        with open(EP, "a", encoding="utf-8") as f:
            for d in promoted:
                f.write("%s\t%s\twatch-promoted\n" % (d, pool[d].get("token", "")))
                pool.pop(d, None)

    # 退役：写退役名单 + 从 watch 文件移除（discover 下轮会读退役名单跳过）
    if retired:
        existing = set()
        if os.path.exists(RETIRED):
            for line in open(RETIRED, encoding="utf-8"):
                if not line.startswith("#") and line.strip():
                    existing.add(line.split("\t")[0].lower())
        with open(RETIRED, "a", encoding="utf-8") as f:
            for d in retired:
                if d not in existing:
                    f.write("%s\t%s\t未复现退役\n" % (d, today))
                pool.pop(d, None)
        keep_lines = []
        for line in open(WATCH, encoding="utf-8"):
            if line.startswith("#"):
                keep_lines.append(line)
                continue
            d = line.split("\t")[0].strip().lower()
            if d in retired:
                continue
            keep_lines.append(line)
        open(WATCH, "w", encoding="utf-8").writelines(keep_lines)

    os.makedirs(os.path.dirname(STATE), exist_ok=True)
    json.dump(pool, open(STATE, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    print("观察池：在池 %d｜新增 %d｜晋级 %d｜退役 %d（影子期 %d 天 / 复现 %d 轮才晋级）"
          % (len(pool), fresh, len(promoted), len(retired), SHADOW_DAYS, PROMOTE_HITS))
    return 0


if __name__ == "__main__":
    sys.exit(main())
