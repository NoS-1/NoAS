#!/usr/bin/env python3
"""build_all.py —— 只做 DNS 层：把黑白名单合成**一份**订阅。

用户要求（2026-11）：
  1. 只保留 DNS 层，路径层（L2 开屏）与内容层（L3 浏览器）不再并入订阅；
  2. 智能识别的结果直接落到黑白名单：广告/追踪域进黑名单，正常业务域进白名单；
  3. 一条订阅链接同时携带黑名单规则与 @@ 白名单例外，导入一次即生效。

产物（subs/all/）：
  adguard.txt  DNS 黑名单 + @@ 白名单例外
  domains.txt  纯黑名单（只吃域名的客户端）
  meta.json    条数统计
"""
import json
import pathlib
import re
from datetime import datetime, timezone

ROOT = pathlib.Path(__file__).resolve().parent.parent
SUBS = ROOT / "subs"
OUT = SUBS / "all"
LISTS = ROOT / "lists"
HOME = "https://github.com/NoS-1/NoAS"


def read_domains(path):
    out = []
    if not path.exists():
        return out
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        s = line.split("#", 1)[0].strip().lower()
        if s and "." in s and "/" not in s and not s.startswith("*"):
            out.append(s)
    return out


def read_blacklist():
    """DNS 黑名单：优先取 full 档的域名，回退到 full/adguard.txt 的规则行。"""
    doms = read_domains(SUBS / "full" / "domains.txt")
    if doms:
        return doms
    out = []
    p = SUBS / "full" / "adguard.txt"
    if p.exists():
        for line in p.read_text(encoding="utf-8", errors="ignore").splitlines():
            s = line.strip()
            if not s.startswith("!"):
                m = re.match(r"^\|\|([^\^]+)\^$", s)
                if m:
                    out.append(m.group(1).lower())
    return out


def read_whitelist():
    """白名单：人工台账 + 服务放行 + AI 精准识别出的正常域。"""
    wl = set()
    for fn in ("whitelist.txt", "service_allow.txt", "ai_whitelist.txt"):
        wl |= set(read_domains(LISTS / fn))
    # 回归基线也是硬白名单
    bp = ROOT / "tests" / "benign_baseline.txt"
    if bp.exists():
        for line in bp.read_text(encoding="utf-8", errors="ignore").splitlines():
            s = line.split("#", 1)[0].strip().lower()
            if s and "." in s:
                wl.add(s)
    return sorted(wl)


def main():
    black = read_blacklist()
    white = read_whitelist()
    # 白名单里精确落在黑名单的域要显式放行；其余靠客户端对 @@ 父域规则的理解
    wl_exceptions = [d for d in white if d in set(black)]

    OUT.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    head = [
        "! Title: NoAS DNS 拦截订阅",
        "! Description: 只做 DNS 层：广告/追踪/威胁域名进黑名单，正常业务域名进白名单，智能识别自动维护",
        "! Version: %s" % datetime.now(timezone.utc).strftime("%Y%m%d-%H%M"),
        "! Last modified: %s" % stamp,
        "! Expires: 6 hours",
        "! Homepage: %s" % HOME,
        "! 条数: 黑名单 %d ／白名单 %d（例外 %d）" % (len(black), len(white), len(wl_exceptions)),
        "",
    ]
    body = []
    body += ["||%s^" % d for d in sorted(set(black))]
    if wl_exceptions:
        body += [""]
        body += ["@@||%s^" % d for d in wl_exceptions]
    body += [""]
    (OUT / "adguard.txt").write_text("\n".join(head + body), encoding="utf-8")

    (OUT / "domains.txt").write_text("\n".join(sorted(set(black))) + "\n", encoding="utf-8")
    (OUT / "whitelist.txt").write_text("\n".join(white) + "\n", encoding="utf-8")

    meta = {
        "files": ["adguard.txt", "domains.txt", "whitelist.txt"],
        "blacklist": len(set(black)),
        "whitelist": len(white),
        "exceptions": len(wl_exceptions),
        "note": "单一 DNS 订阅：黑名单拦截 + @@ 白名单放行，只做 DNS 层",
        "generated_at": stamp,
    }
    (OUT / "meta.json").write_text(json.dumps(meta, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print("DNS 订阅：黑名单 %d ／白名单 %d（例外 %d）→ %s"
          % (len(set(black)), len(white), len(wl_exceptions), OUT))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
