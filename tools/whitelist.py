#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""whitelist.py —— 白名单台账：唯一真源 + 只增不减 + 误报留痕。

账本格式（lists/whitelist.tsv，制表符分隔）：
  domain<TAB>since<TAB>source<TAB>reason
  source ∈ baseline（初始基线）| incident（误报）| manual（人工判断）

两个镜像由台账生成，不手改：
  tests/benign_baseline.txt   ← 回归测试读取
  lists/whitelist.txt         ← 编译期读取
guard.py 会校验台账与镜像一致，防止漂移。

用法：
  python3 tools/whitelist.py sync
  python3 tools/whitelist.py add example.com --reason "误伤：登录页打不开" --source incident
  python3 tools/whitelist.py check
"""
import argparse
import os
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LEDGER = os.path.join(ROOT, "lists", "whitelist.tsv")
MIRROR_T = os.path.join(ROOT, "tests", "benign_baseline.txt")
MIRROR_L = os.path.join(ROOT, "lists", "whitelist.txt")
HEAD = ("# 自动生成，请勿手改。真源：lists/whitelist.tsv；用 tools/whitelist.py add/sync 修改\n"
        "# 域及其所有子域受保护：写 baidu.com 则 *.baidu.com 全部不拦\n")


def read_ledger():
    rows = []
    if not os.path.exists(LEDGER):
        return rows
    for i, line in enumerate(open(LEDGER, encoding="utf-8"), 1):
        s = line.rstrip("\n")
        if not s.strip() or s.lstrip().startswith("#"):
            continue
        parts = s.split("\t")
        if len(parts) < 3:
            print("台账第 " + str(i) + " 行字段不足，需 domain<TAB>since<TAB>source<TAB>reason")
            return None
        dom = parts[0].strip().lower()
        rows.append({"domain": dom, "since": parts[1], "source": parts[2],
                     "reason": parts[3] if len(parts) > 3 else ""})
    return rows


def write_ledger(rows):
    rows = sorted(rows, key=lambda r: (r["source"], r["domain"]))
    with open(LEDGER, "w", encoding="utf-8") as fh:
        fh.write("# NoAS 白名单台账（append-only）\n")
        fh.write("# domain\tsince\tsource\treason\n")
        for r in rows:
            fh.write("\t".join([r["domain"], r["since"], r["source"], r["reason"]]) + "\n")


def sync():
    rows = read_ledger()
    if rows is None:
        return 2
    doms = [r["domain"] for r in rows]
    for p in (MIRROR_T, MIRROR_L):
        with open(p, "w", encoding="utf-8") as fh:
            fh.write(HEAD)
            fh.write("\n".join(doms) + "\n")
    print("已同步镜像，共 " + str(len(doms)) + " 条：tests/benign_baseline.txt, lists/whitelist.txt")
    return 0


def check():
    rows = read_ledger()
    if rows is None:
        return 2
    fail = 0
    seen = {}
    for r in rows:
        d = r["domain"]
        if "." not in d or d.startswith(".") or " " in d or "/" in d:
            print("非法域：" + repr(d))
            fail += 1
        if d in seen:
            print("重复条目：" + d)
            fail += 1
        seen[d] = r
        if r["source"] not in ("baseline", "incident", "manual"):
            print("未知来源标签：" + r["source"] + "（" + d + "）")
            fail += 1
    for p in (MIRROR_T, MIRROR_L):
        got = set()
        if os.path.exists(p):
            for line in open(p, encoding="utf-8"):
                s = line.split("#", 1)[0].strip().lower()
                if s and "." in s:
                    got.add(s)
        if got != set(seen):
            diff = sorted(got.symmetric_difference(set(seen)))[:4]
            print("镜像与台账不一致：" + os.path.relpath(p, ROOT)
                  + "（镜像 " + str(len(got)) + " / 台账 " + str(len(seen)) + "，差异 " + str(diff) + "）")
            fail += 1
    if fail:
        print("白名单台账异常，共 " + str(fail) + " 项")
        return 1
    print("白名单台账 OK，共 " + str(len(rows)) + " 条")
    return 0


def add(domain, reason, source):
    rows = read_ledger() or []
    d = domain.strip().lower().rstrip(".")
    if not d or "." not in d:
        print("域不合法：" + repr(domain))
        return 2
    if any(r["domain"] == d for r in rows):
        print("已在台账中：" + d)
        return 0
    rows.append({"domain": d, "since": time.strftime("%Y-%m-%d"), "source": source,
                 "reason": (reason.replace("\t", " ").strip() or "-")})
    write_ledger(rows)
    rc = sync()
    print("已记入：" + d + "（" + source + "）")
    return rc


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("sync")
    sub.add_parser("check")
    a = sub.add_parser("add")
    a.add_argument("domain")
    a.add_argument("--reason", default="")
    a.add_argument("--source", default="manual", choices=["baseline", "incident", "manual"])
    args = ap.parse_args()
    if args.cmd == "sync":
        return sync()
    if args.cmd == "check":
        return check()
    return add(args.domain, args.reason, args.source)


if __name__ == "__main__":
    sys.exit(main())
