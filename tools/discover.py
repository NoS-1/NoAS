#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""discover.py —— 自己去 GitHub 找新的规则源，验过才进候选池。

做法（不依赖任何第三方服务，只用 GitHub 自己的 API）：
  1. 仓库搜索：按 topic / 关键词找 dns-blocklist、pi-hole、adblock 相关仓库
  2. 探测常见文件路径：hosts / hosts.txt / domain-list.txt / blocked.txt / filter.txt
  3. 校验：能拉到、≥300 条可解析域、与白名单台账零冲突、域名合法
  4. 通过则追加到 lists/candidates.tsv（有 token 就走认证额度，30 次/分钟）

用法：
  GITHUB_TOKEN=xxx python3 tools/discover.py [--limit 6]
"""
import argparse
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "tools"))
from evolve import extract_domains, whitelist  # noqa: E402

CAND = os.path.join(ROOT, "lists", "candidates.tsv")
API = "https://api.github.com"
PATHS = ("hosts", "hosts.txt", "hostlist.txt", "domain-list.txt", "blocked.txt",
         "adblock.txt", "filter.txt", "domains.txt", "list.txt")
QUERIES = (
    "topic:dns-blocklist",
    "topic:pi-hole",
    "topic:adblock-list",
    "adblock dns in:name,description stars:>50",
)


def api(url, token):
    req = urllib.request.Request(url, headers={
        "Accept": "application/vnd.github+json",
        "User-Agent": "NoAS-discover",
        **({"Authorization": "Bearer " + token} if token else {}),
    })
    with urllib.request.urlopen(req, timeout=25) as r:
        return json.load(r)


def raw(url):
    req = urllib.request.Request(url, headers={"User-Agent": "NoAS-discover"})
    with urllib.request.urlopen(req, timeout=30) as r:
        return r.read().decode("utf-8", "replace")


def load_candidates():
    rows = []
    if os.path.exists(CAND):
        for line in open(CAND, encoding="utf-8"):
            s = line.rstrip("\n")
            if s.strip() and not s.lstrip().startswith("#"):
                rows.append(s.split("\t"))
    return rows


def append_candidate(name, url, fmt, note):
    with open(CAND, "a", encoding="utf-8") as fh:
        fh.write("\t".join([name, url, fmt, "block", note]) + "\n")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--limit", type=int, default=6, help="最多新增几个源")
    args = ap.parse_args()
    token = os.environ.get("GITHUB_TOKEN", "")
    wl = whitelist()
    seen_urls = {r[1] for r in load_candidates() if len(r) > 1}
    # 已在用的源也不算新
    srcp = os.path.join(ROOT, "sources.tsv")
    if os.path.exists(srcp):
        for line in open(srcp, encoding="utf-8"):
            s = line.strip()
            if s and not s.startswith("#") and "\t" in s:
                seen_urls.add(s.split("\t")[1])

    added = 0
    tried = 0
    for q in QUERIES:
        if added >= args.limit:
            break
        try:
            data = api("%s/search/repositories?q=%s&sort=updated&per_page=5" % (API, urllib.parse.quote(q)), token)
        except Exception as e:
            print("搜索失败：" + q + " -> " + str(e)[:80])
            continue
        for repo in data.get("items", []):
            if added >= args.limit:
                break
            full = repo["full_name"]
            branch = repo.get("default_branch") or "main"
            for p in PATHS:
                tried += 1
                url = "https://raw.githubusercontent.com/%s/%s/%s" % (full, branch, p)
                if url in seen_urls:
                    continue
                try:
                    text = raw(url)
                except Exception:
                    continue
                fmt = "hosts" if p.startswith("hosts") else ("adblock" if "filter" in p or "adblock" in p else "domains")
                doms = extract_domains(text, fmt)
                if len(doms) < 300:
                    continue
                hit = [d for d in doms if d in wl or any(d.endswith("." + w) for w in wl)]
                if hit:
                    print("跳过（与白名单冲突 %d 条）：%s" % (len(hit), url))
                    continue
                name = "auto-" + full.split("/")[-1].lower()[:24]
                append_candidate(name, url, fmt, "discovered " + full)
                seen_urls.add(url)
                added += 1
                print("新增候选：%s（%d 条，%s）" % (url, len(doms), fmt))
                break
    print("发现结束：新增 %d 个候选，探测 %d 次" % (added, tried))
    return 0


if __name__ == "__main__":
    sys.exit(main())
