#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""sources_guard.py —— 上游投毒防护：源清单与源内容的"形状"校验。

威胁模型：某个公共规则源被接管/误推，一次性灌入几十万条域名（或脏字符），
构建照收就会把全网打挂。这里不判断"这条规则对不对"（那做不到），只判断
**这次拉回来的东西还是不是那个源该有的形状**：

1. 清单卫生：URL 必须 https、域名在允许列表内、同一 URL 不得出现两次。
2. 内容形状：抽样域名必须匹配域名正则、长度合规、不含空白/控制字符。
3. 突变检测：单源条目数相对上一版（state/source_counts.json）超过 ±60% 直接判红，
   需要人工在 sources.tsv 里显式确认（写 `# allowjump` 行）才放行。

用法：python3 tools/sources_guard.py [--mode required|soft]
"""
import argparse
import json
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CACHE = os.path.join(ROOT, "cache")
STATE = os.path.join(ROOT, "state", "source_counts.json")

# 只信任这些公开托管域；新增源必须同时改这里，防止清单被悄悄改到攻击者域名
ALLOW_HOSTS = (
    "raw.githubusercontent.com", "cdn.jsdelivr.net", "adguard.com", "filters.adtidy.org",
    "easylist.to", "secure.fanboy.co.nz", "oisd.nl", "big.oisd.nl", "hagezi.de",
    "raw.gitmirror.com", "ghproxy.net", "mirror.ghproxy.com", "anti-ad.net",
    "1hosts.cf", "badmojr.github.io", "someonewhocares.org", "winhelp2002.mvps.org",
    "gitlab.com", "codeberg.org", "gitee.com", "aliyuncs.com",
    "github.io", "gitlab.io", "phishing.army",
)
DOMAIN_RE = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$")
LINE_NOISE = re.compile(r"^[!#;\[]")


def read_sources():
    out = []
    with open(os.path.join(ROOT, "sources.tsv"), encoding="utf-8") as f:
        for i, line in enumerate(f, 1):
            s = line.strip()
            if not s or s.startswith("#") or "\t" not in s:
                continue
            parts = s.split("\t")
            if len(parts) < 3:
                continue
            out.append({"line": i, "name": parts[0], "url": parts[1], "fmt": parts[2]})
    return out


def domains_of(path, fmt="hosts"):
    """从任意格式里抽出候选域名，抽样用（不追求全量抽取精度）。"""
    cand = []
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            for line in f:
                s = line.strip()
                if not s or LINE_NOISE.match(s):
                    continue
                if fmt == "clash":
                    # Clash 语法：- DOMAIN-SUFFIX,a.com / - DOMAIN,a.com；DOMAIN-KEYWORD 不是域名，跳过
                    m = re.match(r"^\s*(?:-\s*)?DOMAIN(?:-SUFFIX)?\s*,\s*([a-z0-9][a-z0-9.\-]*[a-z0-9])", s, re.I)
                    if m:
                        cand.append(m.group(1).lower())
                    continue
                if fmt == "adblock":
                    # uBO/EasyList：只有 ||domain^ 形态才是域名规则，元素隐藏/脚本规则一律不参与抽样
                    m = re.match(r"^\|\|([a-z0-9][a-z0-9.\-]*[a-z0-9])([\^/]|$)", s, re.I)
                    if m:
                        cand.append(m.group(1).lower())
                    continue
                # hosts: 0.0.0.0 a.com b.com / 其余：||a.com^ / a.com
                for tok in re.split(r"[ \t]+", s):
                    t = tok.strip("|^$*/. ,;()")
                    if "." in tok and re.search(r"[a-z]", t):
                        cand.append(t.lower())
                        break
    except FileNotFoundError:
        return None
    return cand


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", default="required", choices=["required", "soft"])
    a = ap.parse_args()
    problems, warns = [], []

    srcs = read_sources()
    if not srcs:
        problems.append("sources.tsv 为空或格式全错")
    seen_url = {}
    for s in srcs:
        host = re.sub(r"^https?://", "", s["url"]).split("/")[0].lower()
        if not s["url"].startswith("https://"):
            problems.append(f"第{s['line']}行 {s['name']}：非 https")
        if not any(host == h or host.endswith("." + h) for h in ALLOW_HOSTS):
            problems.append(f"第{s['line']}行 {s['name']}：域名 {host} 不在允许列表")
        if s["url"] in seen_url:
            problems.append(f"第{s['line']}行 {s['name']}：URL 重复（与第{seen_url[s['url']]}行相同）")
        seen_url[s["url"]] = s["line"]

    prev = {}
    if os.path.exists(STATE):
        try:
            prev = json.loads(open(STATE, encoding="utf-8").read())
        except Exception:
            prev = {}
    counts = {}
    allowjump = "# allowjump" in open(os.path.join(ROOT, "sources.tsv"), encoding="utf-8").read()

    for s in srcs:
        # 缓存文件名必须与 fetch.py 的 slug(name) 规则一致：
        # 早前按 URL 的 basename 找，21 个源里只有 3 个能命中，其余全部"无缓存文件"跳过，
        # 形状检查与突变检测等于只覆盖了 3/21，是防护形同虚设的根因。
        def _slug(n):
            return "".join(ch if ch.isalnum() or ch in "-_." else "_" for ch in n).lower()
        p = os.path.join(CACHE, _slug(s["name"]) + ".txt")
        if not os.path.exists(p):
            p = os.path.join(CACHE, os.path.basename(s["url"].split("?")[0]) or s["name"])
        if not os.path.exists(p):
            p = os.path.join(CACHE, s["name"] + ".txt")
        ds = domains_of(p, s.get("fmt", "hosts"))
        if ds is None:
            warns.append(f"{s['name']}：无缓存文件，跳过形状检查")
            continue
        counts[s["name"]] = len(ds)
        bad = 0
        sample = ds[:200] + ds[len(ds) // 2:len(ds) // 2 + 200]
        for d in sample:
            if len(d) > 253 or not DOMAIN_RE.match(d):
                bad += 1
        if sample and bad / len(sample) > 0.2:
            problems.append(f"{s['name']}：抽样 {len(sample)} 条中 {bad} 条不是合法域名（疑似脏数据/投毒）")
        n0 = prev.get(s["name"])
        if n0 and len(ds) > 50:
            jump = abs(len(ds) - n0) / max(n0, 1)
            if jump > 0.6:
                msg = f"{s['name']}：条目数 {n0} → {len(ds)}（{jump:.0%} 突变）"
                (warns if allowjump else problems).append(msg + ("（已 allowjump 放行）" if allowjump else ""))

    os.makedirs(os.path.dirname(STATE), exist_ok=True)
    # 只在全部检查通过时推进基线，否则沿用旧基线，避免"污染值被记成新常态"
    if not problems:
        open(STATE, "w", encoding="utf-8").write(json.dumps(counts, ensure_ascii=False, indent=1) + "\n")

    for w in warns:
        print(f"WARN {w}")
    for p in problems:
        print(f"FAIL {p}")
    print(f"源清单 {len(srcs)} 条｜缓存命中 {len(counts)}｜问题 {len(problems)}｜提示 {len(warns)}")
    if problems and a.mode == "required":
        sys.exit(1)


if __name__ == "__main__":
    main()
