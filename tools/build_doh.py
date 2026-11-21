#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""build_doh.py —— 把 lite+mid 规则注入 Worker 模板，产出可运行的 DoH 服务。

纯本地、零凭证：产物既能挂在任何支持 Web 标准的运行时上，也能被 serve/standalone.mjs 直接加载。
"""
import base64
import gzip
import hashlib
import json
import os
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SUBS = os.path.join(ROOT, "subs")
TPL = os.path.join(ROOT, "doh", "worker.tpl.js")


def read_list(path):
    if not os.path.exists(path):
        return []
    out = []
    for line in open(path, encoding="utf-8", errors="ignore"):
        line = line.split("#", 1)[0].strip()
        if not line or line.startswith("!"):
            continue
        if line.startswith("||"):
            line = line[2:].rstrip("^")
        if line.startswith("0.0.0.0 "):
            line = line.split()[-1]
        if "." in line and "/" not in line:
            out.append(line.lower())
    return out


def main():
    lite = read_list(os.path.join(SUBS, "lite", "domains.txt"))
    mid = read_list(os.path.join(SUBS, "mid", "domains.txt"))
    allow = [l.split("#", 1)[0].strip().lower()
             for l in open(os.path.join(ROOT, "tests", "benign_baseline.txt"), encoding="utf-8")]
    allow = [x for x in allow if x and "." in x]
    tp = os.path.join(ROOT, "lists", "whitelist.txt")
    if os.path.exists(tp):
        allow += [l.split("#", 1)[0].strip().lower() for l in open(tp, encoding="utf-8") if "." in l]
    allow = sorted(set(allow))

    # DoH 只带"高精度通配"（mid 档，纯广告网根域），避免把 40 万条通配塞进 worker
    wild = sorted({
        l.strip().lower()
        for l in open(os.path.join(SUBS, "mid", "wildcards.txt"), encoding="utf-8")
        if l.strip().startswith("*.")
    })
    ver = time.strftime("%Y%m%d-%H%M")
    payload = {
        "t1": sorted(set(lite)),
        "t2": sorted(set(mid)),
        "allow": allow,
        "wild": wild,
        "ep": sorted({
            l.split("#", 1)[0].strip().lower()
            for l in open(os.path.join(ROOT, "lists", "ad_endpoints.txt"), encoding="utf-8")
            if l.split("#", 1)[0].strip()}),
    }
    # 规则以换行分隔纯文本内嵌：模块级同步切分，避免顶层 await 异步 I/O（CF 禁止）
    js = (open(TPL, encoding="utf-8").read()
          .replace("__T1__", json.dumps("\n".join(payload["t1"]), ensure_ascii=False))
          .replace("__T2__", json.dumps("\n".join(payload["t2"]), ensure_ascii=False))
          .replace("__ALLOW_TEXT__", json.dumps("\n".join(payload["allow"]), ensure_ascii=False))
          .replace("__EP_TEXT__", json.dumps("\n".join(payload["ep"]), ensure_ascii=False))
          .replace("__WILD_TEXT__", json.dumps("\n".join(payload["wild"]), ensure_ascii=False))
          .replace("__VERSION__", json.dumps(ver)))
    os.makedirs(os.path.join(ROOT, "doh"), exist_ok=True)
    p = os.path.join(ROOT, "doh", "worker.js")
    open(p, "w", encoding="utf-8").write(js)

    # 构建指纹：CF 侧 cron 只读这一份（KB 级）判断"线上规则是否落后于仓库"。
    sha = hashlib.sha256(js.encode("utf-8")).hexdigest()[:16]
    manifest = {
        "version": ver,
        "sha256": sha,
        "bytes": len(js.encode("utf-8")),
        "counts": {k: len(payload[k]) for k in ("t1", "t2", "allow", "wild", "ep")},
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    sm = os.path.join(ROOT, "state", "build_manifest.json")
    os.makedirs(os.path.dirname(sm), exist_ok=True)
    open(sm, "w", encoding="utf-8").write(json.dumps(manifest, ensure_ascii=False, indent=1) + "\n")

    print("已生成 doh/worker.js：lite %d ／mid %d ／白名单 %d ／%d KB ／版本 %s ／sha %s" % (
        len(set(lite)), len(set(mid)), len(allow), len(js) // 1024, ver, sha))
    return 0


if __name__ == "__main__":
    sys.exit(main())
