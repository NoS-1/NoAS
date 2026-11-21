#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""fetch.py —— 并发拉取所有公开规则源，落 cache/ 并记录元信息。

设计要点：
  1. 全部走公开 raw / 直链，不带任何凭证（能公开拉取才算"零依赖"）
  2. 单源失败不影响整体：记录失败原因，下一轮重试；失败源沿用上一轮缓存
  3. 条件请求（If-None-Match / If-Modified-Since）省流量：304 就复用本地缓存
  4. 记录每个源的字节数/耗时/新鲜度，供"上游新鲜度"判定（源挂掉当天就能发现）
"""
import concurrent.futures as cf
import json
import os
import sys
import time
import urllib.error
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CACHE = os.path.join(ROOT, "cache")
STATE = os.path.join(CACHE, "sources.json")
UA = "NoAS-fetch/1.0 (+https://github.com/NoS-1/NoAS)"


def load_sources():
    out = []
    with open(os.path.join(ROOT, "sources.tsv"), encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split("\t")
            if len(parts) < 4:
                continue
            name, url, fmt, kind = parts[:4]
            note = parts[4] if len(parts) > 4 else ""
            out.append({"name": name, "url": url, "fmt": fmt, "kind": kind, "note": note})
    return out


def slug(name):
    return "".join(ch if ch.isalnum() or ch in "-_." else "_" for ch in name).lower()


def _get(url, headers, timeout=45):
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read(), (r.headers.get("ETag") or ""), (r.headers.get("Last-Modified") or "")


def fetch_one(src, state):
    dst = os.path.join(CACHE, slug(src["name"]) + ".txt")
    meta = state.get(src["name"]) or {}
    headers = {"User-Agent": UA, "Accept": "*/*"}
    if os.path.exists(dst) and meta.get("etag"):
        headers["If-None-Match"] = meta["etag"]
    if os.path.exists(dst) and meta.get("last_modified"):
        headers["If-Modified-Since"] = meta["last_modified"]
    t0 = time.time()
    try:
        body, etag, lm = _get(src["url"], headers)
        prev_bytes = meta.get("bytes") or 0
        shrunk = bool(prev_bytes) and len(body) < prev_bytes * 0.7
        if shrunk:
            # HTTP 200 但内容比上轮少三成以上：多半是 CDN 限流/截断（实测有源返回半截），
            # 去掉条件头、绕开缓存重试一次，取到更完整的那份。
            try:
                b2, etag2, lm2 = _get(src["url"], {"User-Agent": UA + " retry", "Accept": "*/*",
                                                   "Cache-Control": "no-cache"})
                if len(b2) > len(body):
                    body, etag, lm, shrunk = b2, etag2, lm2, (len(b2) < prev_bytes * 0.7)
            except Exception:
                pass
        if body and len(body) > 512:
            with open(dst, "wb") as f:
                f.write(body)
            return {**src, "ok": True, "bytes": len(body), "sec": round(time.time() - t0, 2),
                    "etag": etag, "last_modified": lm, "updated": int(time.time()), "new": True,
                    "shrunk": shrunk}
        return {**src, "ok": False, "why": "响应太小（疑似错误页）", "sec": round(time.time() - t0, 2)}
    except urllib.error.HTTPError as e:
        if e.code == 304 and os.path.exists(dst):
            return {**src, "ok": True, "bytes": os.path.getsize(dst), "sec": round(time.time() - t0, 2),
                    "cached": True, "updated": meta.get("updated", 0)}
        # 304 之外：沿用上一轮缓存，但标记 stale，让报告知道这个源今天没拉到
        if os.path.exists(dst):
            return {**src, "ok": True, "bytes": os.path.getsize(dst), "sec": round(time.time() - t0, 2),
                    "cached": True, "stale": True, "why": "HTTP %d" % e.code,
                    "updated": meta.get("updated", 0)}
        return {**src, "ok": False, "why": "HTTP %d" % e.code, "sec": round(time.time() - t0, 2)}
    except Exception as e:
        if os.path.exists(dst):
            return {**src, "ok": True, "bytes": os.path.getsize(dst), "sec": round(time.time() - t0, 2),
                    "cached": True, "stale": True, "why": str(e)[:80],
                    "updated": meta.get("updated", 0)}
        return {**src, "ok": False, "why": str(e)[:80], "sec": round(time.time() - t0, 2)}


def main():
    os.makedirs(CACHE, exist_ok=True)
    state = {}
    if os.path.exists(STATE):
        try:
            state = json.load(open(STATE, encoding="utf-8"))
        except Exception:
            state = {}
    sources = load_sources()
    results = []
    with cf.ThreadPoolExecutor(max_workers=8) as ex:
        futs = {ex.submit(fetch_one, s, state): s for s in sources}
        for fu in cf.as_completed(futs):
            results.append(fu.result())

    fresh, cached, failed = [], [], []
    for r in results:
        if not r.get("ok"):
            failed.append(r)
        elif r.get("cached"):
            cached.append(r)
        else:
            fresh.append(r)
    old_state = dict(state)   # 打印"上轮字节数"要用旧值，后面 state 会被覆盖
    for r in results:
        if r.get("ok"):
            state[r["name"]] = {k: r.get(k, "") for k in ("bytes", "etag", "last_modified", "updated")}
    json.dump(state, open(STATE, "w", encoding="utf-8"), ensure_ascii=False, indent=1)

    print("规则源：成功 %d（新拉 %d／缓存 %d）｜失败 %d／共 %d" % (
        len(fresh) + len(cached), len(fresh), len(cached), len(failed), len(results)))
    for r in failed:
        print("  ✗ %-22s %s" % (r["name"], r.get("why", "")))
    # 内容比上轮缩水三成以上的源：重试后仍未恢复就点名，构建层面还有规模自愈兜底
    for r in results:
        if r.get("ok") and r.get("shrunk"):
            print("  ⚠ %-22s 内容偏短 %d 字节（上轮 %d），重试后仍未恢复" % (
                r["name"], r.get("bytes") or 0, (old_state.get(r["name"]) or {}).get("bytes") or 0))
    if len(failed) >= len(results):
        print("FAIL：所有源都拉不到（网络受限或上游集体故障）")
        return 1
    if len(failed) > len(results) // 2:
        print("WARN：超过一半源失败，本轮规则会明显缩水")
    return 0


if __name__ == "__main__":
    sys.exit(main())
