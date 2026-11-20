#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""token_check.py —— 凭据健康检查：GitHub PAT 与 CF API Token 是否还有效。

为什么单独做一件事：令牌失效是最安静的故障。CI 里 CF 相关步骤历来是 continue-on-error，
一旦 token 过期，构建照样绿、线上照样跑旧规则，几天都不会有人发现。
这里把它变成一次显式校验，失效就让构建红。

凭据来源优先级：环境变量 > /home/user/.noas/creds.env（本机 600 文件）。
绝不在仓库里落任何令牌，也不打印令牌值。
"""
import json
import os
import sys
import urllib.error
import urllib.request

CREDS = "/home/user/.noas/creds.env"


def load_env():
    """从 creds.env 补环境变量，已存在的环境变量优先（CI 用 secrets 注入）。"""
    if not os.path.exists(CREDS):
        return
    for line in open(CREDS, encoding="utf-8"):
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        os.environ.setdefault(k.strip(), v.strip())


def req(url, token, extra=None):
    h = {"Authorization": "Bearer " + token, "User-Agent": "NoAS-token-check"}
    h.update(extra or {})
    r = urllib.request.Request(url, headers=h)
    with urllib.request.urlopen(r, timeout=20) as resp:
        return resp.status, json.loads(resp.read() or b"{}")


def check_github():
    tok = os.environ.get("GH_PAT") or os.environ.get("GITHUB_TOKEN") or ""
    if not tok:
        return "skip", "未配置 GH_PAT"
    try:
        st, _ = req("https://api.github.com/rate_limit", tok, {"Accept": "application/vnd.github+json"})
        return ("ok", "HTTP %d" % st) if st == 200 else ("fail", "HTTP %d" % st)
    except urllib.error.HTTPError as e:
        return "fail", "HTTP %d（401/403 基本就是令牌失效或被吊销）" % e.code
    except Exception as e:
        return "warn", "网络异常：%s" % str(e)[:60]


def check_cf():
    tok = os.environ.get("CF_API_TOKEN") or os.environ.get("CF_TOKEN") or ""
    acct = os.environ.get("CF_ACCOUNT_ID") or ""
    if not tok:
        return "skip", "未配置 CF_API_TOKEN"
    if not acct:
        return "skip", "未配置 CF_ACCOUNT_ID"
    try:
        st, d = req("https://api.cloudflare.com/client/v4/accounts/%s/tokens/verify" % acct, tok)
        status = ((d.get("result") or {}) or {}).get("status") or "-"
        return ("ok", "status=%s" % status) if d.get("success") and status == "active" else ("fail", "status=%s" % status)
    except urllib.error.HTTPError as e:
        return "fail", "HTTP %d（令牌失效或无权限）" % e.code
    except Exception as e:
        return "warn", "网络异常：%s" % str(e)[:60]


def main():
    load_env()
    bad = []
    for name, fn in (("GitHub PAT", check_github), ("CF API Token", check_cf)):
        state, detail = fn()
        mark = {"ok": "OK", "skip": "SKIP", "warn": "WARN", "fail": "FAIL"}[state]
        print("  %-13s %-4s %s" % (name, mark, detail))
        if state == "fail":
            bad.append(name)
    if bad:
        print("凭据失效：%s —— 请到后台重建，然后改写 /home/user/.noas/creds.env" % "、".join(bad))
        return 1
    print("凭据健康：全部有效")
    return 0


if __name__ == "__main__":
    sys.exit(main())
