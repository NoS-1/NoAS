#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""死域周扫：每周抽样解析一批域名，只把"确认无解析 + 仅单源背书"的候选写进 lists/dead.txt。

安全边界（保证误伤仍为 0）：
  · 抽样而非全量：按域名 hash 分成 30 个桶，每天轮一个桶，单次 ≤ 4000 条，避免打爆 DNS；
  · 只记录不直接删：dead.txt 仅作候选；compile 只会丢弃"共识=1"的条目，多源背书的永不删；
  · 白名单/本地 allow 一律跳过；
  · 解析超时/网络错误不算死亡，只有明确的 NXDOMAIN（EAI_NONAME）才记录。
"""
import concurrent.futures as cf
import datetime
import hashlib
import json
import os
import socket
import sys
import urllib.error

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEAD = os.path.join(ROOT, "lists", "dead.txt")
SUBS = os.path.join(ROOT, "subs")
CAP = 4000


def read_lines(p):
    out = []
    if os.path.exists(p):
        for line in open(p, encoding="utf-8"):
            line = line.split("#", 1)[0].strip().lower()
            if line and "." in line:
                out.append(line)
    return out


def main():
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--list", default=os.path.join(SUBS, "full", "domains.txt"))
    args = ap.parse_args()
    day = datetime.datetime.utcnow().timetuple().tm_yday
    doms = read_lines(args.list)
    wl = set(read_lines(os.path.join(ROOT, "lists", "whitelist.txt")))
    wl |= set(read_lines(os.path.join(ROOT, "allowlist.txt")))
    sample = [d for d in doms
              if d not in wl and int(hashlib.sha1(d.encode()).hexdigest(), 16) % 30 == day % 30][:CAP]
    print("死域抽样：%d 条（全量 %d）" % (len(sample), len(doms)))

    dead = []
    def probe(d):
        try:
            socket.setdefaulttimeout(3)
            socket.getaddrinfo(d, 443, proto=socket.IPPROTO_TCP)
            return None
        except socket.gaierror as e:
            if e.errno in (socket.EAI_NONAME, -2, 8):
                return d
            return None
        except Exception:
            return None

    with cf.ThreadPoolExecutor(max_workers=48) as ex:
        for r in ex.map(probe, sample):
            if r:
                dead.append(r)

    old = set(read_lines(DEAD))
    new = sorted((old | set(dead)) - set(sample) | set(dead))
    new = new[-20000:]
    os.makedirs(os.path.dirname(DEAD), exist_ok=True)
    with open(DEAD, "w", encoding="utf-8") as f:
        f.write("# NoAS 死域候选（仅单源背书才会被剔除；多源背书永不删）\n")
        for d in new:
            f.write(d + "\n")
    print("死域扫描：本轮 NXDOMAIN %d 条｜候选池 %d 条" % (len(dead), len(new)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
