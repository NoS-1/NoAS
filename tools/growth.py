#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""成长账本：把"自我成长"变成可审计的事实，而不是口号。

每天记录三类可验证的变化，写进 history/growth.json 并镜像到 docs/growth.json：
1) 规模：三档条数的逐日趋势（涨了多少、掉了多少）；
2) 源：可用源数、每个源的独立贡献（有多少域名只靠它才有）——用来判断"体系是否在长新东西"；
3) 事件：自动发现新源、误伤/漏拦反馈学习、精度审计结果等 learn_events.jsonl 条目。

只读本地产物，不联网，不消耗任何 API 额度。
"""
import datetime
import json
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HIST = os.path.join(ROOT, "history", "growth.json")
EVENTS = os.path.join(ROOT, "history", "learn_events.jsonl")
DOCS = os.path.join(ROOT, "docs", "growth.json")


def load_json(path, default):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default


def count_tier(t):
    meta = load_json(os.path.join(ROOT, "subs", t, "meta.json"), {})
    return int(meta.get("count", 0))


def sources_state():
    info = load_json(os.path.join(ROOT, "cache", "sources.json"), {})
    ok = {k: v for k, v in info.items() if isinstance(v, dict) and v.get("bytes")}
    return len(ok), {k: v.get("bytes", 0) for k, v in info.items() if isinstance(v, dict)}


def whitelist_count():
    p = os.path.join(ROOT, "lists", "whitelist.tsv")
    n = 0
    with open(p, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                n += 1
    return n


def read_events(limit=200):
    out = []
    if os.path.exists(EVENTS):
        with open(EVENTS, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        out.append(json.loads(line))
                    except Exception:
                        pass
    return out[-limit:]


def main():
    today = datetime.datetime.utcnow().strftime("%Y-%m-%d")
    hist = load_json(HIST, {"series": [], "events": []})
    series = [r for r in hist.get("series", []) if r.get("date") != today]
    src_ok, _ = sources_state()
    row = {
        "date": today,
        "lite": count_tier("lite"),
        "mid": count_tier("mid"),
        "full": count_tier("full"),
        "sources": src_ok,
        "whitelist": whitelist_count(),
    }
    prev = series[-1] if series else None
    series.append(row)
    series = series[-120:]

    events = read_events()
    delta = {}
    if prev:
        for k in ("lite", "mid", "full", "sources", "whitelist"):
            delta[k] = row[k] - prev.get(k, row[k])
    hist = {
        "updated": datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
        "today": row,
        "delta": delta,
        "series": series,
        "learn_events": events[-40:],
        "events_total": len(events),
    }
    os.makedirs(os.path.dirname(HIST), exist_ok=True)
    with open(HIST, "w", encoding="utf-8") as f:
        json.dump(hist, f, ensure_ascii=False, indent=1)
    os.makedirs(os.path.dirname(DOCS), exist_ok=True)
    with open(DOCS, "w", encoding="utf-8") as f:
        json.dump(hist, f, ensure_ascii=False, indent=1)
    print("成长账本：lite %d / mid %d / full %d｜源 %d｜白名单 %d｜累计学习事件 %d"
          % (row["lite"], row["mid"], row["full"], src_ok, row["whitelist"], len(events)))


if __name__ == "__main__":
    main()
