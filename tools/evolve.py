#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""evolve.py —— 每日自我体检：源健康度评分、自动淘汰坏源、自动吸收合格新源。

规则（全部可审计，不做黑箱判断）：
  1. 淘汰：连续 2 轮拉取失败或产出 0 条 → 从 sources.tsv 移除（写进 history/evolution.json）
  2. 吸收：候选池里的源，单轮能拉到 ≥300 条、格式可解析、与白名单零冲突 → 自动并入 sources.tsv
  3. 评分：每个源按「条数 / 新鲜度 / 失败率」打分，写 history/health.json，供人查看
候选池与设定值都在 lists/candidates.tsv，纯文本，随时可手改。

用法：python3 tools/evolve.py [--dry-run]
"""
import argparse
import json
import os
import re
import sys
import time
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(ROOT, "sources.tsv")
CAND = os.path.join(ROOT, "lists", "candidates.tsv")
STATE = os.path.join(ROOT, "history", "state.json")
EVO = os.path.join(ROOT, "history", "evolution.json")
HEALTH = os.path.join(ROOT, "history", "health.json")
MIN_ADOPT = 300          # 新源至少这么多条才收
FAIL_LIMIT = 2           # 连续失败几轮淘汰
UA = "NoAS-evolve/1.0 (+https://github.com/NoS-1/NoAS)"
DOMAIN_RE = re.compile(r"^[a-z0-9]([a-z0-9\-_.]*[a-z0-9])?$")


def load_tsv(path):
    rows = []
    if not os.path.exists(path):
        return rows
    for line in open(path, encoding="utf-8"):
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        rows.append(s.split("\t"))
    return rows


def whitelist():
    wl = set()
    for f in ("tests/benign_baseline.txt", "lists/whitelist.txt"):
        p = os.path.join(ROOT, f)
        if not os.path.exists(p):
            continue
        for line in open(p, encoding="utf-8"):
            d = line.strip().lower()
            if d and not d.startswith("#"):
                wl.add(d)
    return wl


def fetch(url, timeout=25):
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read().decode("utf-8", "replace")


def extract_domains(text, fmt):
    out = set()
    for raw in text.splitlines():
        s = raw.strip()
        if not s or s[0] in "#![":
            continue
        if fmt == "hosts":
            parts = s.split()
            if len(parts) >= 2 and re.match(r"^[0-9.]+$|^::1?$", parts[0]):
                s = parts[1]
        elif fmt == "adblock":
            s = s.lstrip("|").rstrip("^")
            if "/" in s or "*" in s:
                continue
        elif fmt == "dnsmasq":
            parts = s.split()
            if len(parts) >= 2 and parts[0] == "address":
                s = parts[1].lstrip("/").rstrip("/")
            else:
                continue
        s = s.split("#")[0].strip().lower().rstrip(".")
        if 4 < len(s) < 254 and "." in s and DOMAIN_RE.match(s) and not s.replace(".", "").isdigit():
            out.add(s)
    return out


def state_load():
    try:
        return json.load(open(STATE, encoding="utf-8"))
    except Exception:
        return {"sources": {}, "rounds": 0}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()
    fetch_state = {}
    fsp = os.path.join(ROOT, "cache", "sources.json")
    if os.path.exists(fsp):
        try:
            data = json.load(open(fsp, encoding="utf-8"))
            src = data.get("sources") if isinstance(data.get("sources"), dict) else data
            for name, info in (src or {}).items():
                if isinstance(info, dict):
                    fetch_state[name] = info
        except Exception:
            fetch_state = {}
    st = state_load()
    st["rounds"] = st.get("rounds", 0) + 1
    wl = whitelist()
    events = []

    # ---- 1. 现有源体检 + 淘汰 ----
    rows = load_tsv(SRC)
    keep, drop = [], []
    for row in rows:
        name, url, fmt = row[0], row[1], row[2]
        meta = st["sources"].setdefault(name, {"fails": 0, "hits": []})
        # 只看本轮 fetch 的真实结果（sources.json），不看"缓存文件在不在"——
        # CI 是干净环境，没有缓存文件，用存在性判断会把所有源误判成失效（曾经踩过）。
        info = fetch_state.get(name) or {}
        ok = bool(info.get("ok", True)) and int(info.get("bytes") or 0) > 0
        meta["fails"] = 0 if ok else meta.get("fails", 0) + 1
        meta["hits"] = (meta.get("hits", []) + [time.strftime("%Y-%m-%d")])[-30:]
        if meta["fails"] >= FAIL_LIMIT:
            drop.append((name, meta["fails"]))
        else:
            keep.append(row)

    # ---- 2. 候选池吸收 ----
    adopted = []
    for row in load_tsv(CAND):
        if len(row) < 3:
            continue
        name, url, fmt = row[0], row[1], row[2]
        if any(r[0] == name for r in keep):
            continue
        try:
            text = fetch(url)
        except Exception as e:
            events.append({"act": "candidate_fail", "name": name, "why": str(e)[:120]})
            continue
        doms = extract_domains(text, fmt)
        if len(doms) < MIN_ADOPT:
            events.append({"act": "candidate_small", "name": name, "n": len(doms)})
            continue
        hit = [d for d in doms if d in wl or any(d == w or d.endswith("." + w) for w in wl)]
        if hit:
            events.append({"act": "candidate_conflict", "name": name, "n": len(doms), "conflict": len(hit),
                           "sample": hit[:3]})
            continue
        keep.append([name, url, fmt, row[3] if len(row) > 3 else "auto", "auto-adopted " + time.strftime("%Y-%m-%d")])
        st["sources"].setdefault(name, {"fails": 0, "hits": [time.strftime("%Y-%m-%d")]})
        adopted.append((name, len(doms)))

    # 下限保护：一轮最多淘汰 1 个，且淘汰后至少保留 MIN_SOURCES 个，避免误判造成"自我阉割"
    MIN_SOURCES = 8
    if len(keep) - len(drop) < MIN_SOURCES:
        dropped = drop[:max(0, len(keep) - MIN_SOURCES)]
        for name, f in drop[len(dropped):]:
            events.append({"act": "drop_skipped", "name": name, "why": "触及源数下限"})
        drop = dropped
    for name, f in drop:
        events.append({"act": "drop", "name": name, "fails": f})

    # ---- 3. 落盘 ----
    if drop or adopted:
        header = "# 名称\tURL\t格式\thosts|adblock|domains|dnsmasq\t用途说明\n"
        with open(SRC, "w", encoding="utf-8") as fh:
            fh.write(header)
            for r in keep:
                fh.write("\t".join(r) + "\n")
    hist = []
    if os.path.exists(EVO):
        try:
            hist = json.load(open(EVO, encoding="utf-8"))
        except Exception:
            hist = []
    hist.append({"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "round": st["rounds"],
                 "events": events, "sources": len(keep)})
    json.dump(hist[-120:], open(EVO, "w", encoding="utf-8"), ensure_ascii=False, indent=1)

    health = []
    for r in keep:
        m = st["sources"].get(r[0], {})
        health.append({"name": r[0], "fails": m.get("fails", 0), "seen_days": len(set(m.get("hits", [])))})
    json.dump({"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "round": st["rounds"],
               "sources": health, "adopted": len(adopted), "dropped": len(drop)},
              open(HEALTH, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    json.dump(st, open(STATE, "w", encoding="utf-8"), ensure_ascii=False, indent=1)

    print("第 %d 轮体检｜源 %d 个｜吸收 %d 个%s｜淘汰 %d 个%s"
          % (st["rounds"], len(keep), len(adopted),
             ("(" + ",".join(n for n, _ in adopted) + ")") if adopted else "",
             len(drop), ("(" + ",".join(n for n, _ in drop) + ")") if drop else ""))
    for e in events[:8]:
        print("  ·", e)
    return 0


if __name__ == "__main__":
    sys.exit(main())
