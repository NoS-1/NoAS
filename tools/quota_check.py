#!/usr/bin/env python3
"""免费额度守门：Pages 每月 500 次部署是硬配额，用光就整月无法发布新规则。

只做一件事：数本月已用多少次，超过阈值就红。宁可构建红一次，也不要静默用光额度。
"""
import json
import os
import pathlib
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone

ACC = os.environ.get("CF_ACCOUNT_ID", "") or "226431c8f431ebb75d82dd5dbd5e8d86"
PROJECT = "noas-cdn"
WARN = int(os.environ.get("NOAS_PAGES_DEPLOY_WARN", "350"))
CREDS = pathlib.Path("/home/user/.noas/creds.env")


def token() -> str:
    for k in ("CF_API_TOKEN", "CF_TOKEN"):
        if os.environ.get(k):
            return os.environ[k]
    if CREDS.exists():
        for line in CREDS.read_text(encoding="utf-8").splitlines():
            if line.startswith("CF_API_TOKEN="):
                return line.split("=", 1)[1].strip()
    return ""


def lite_capacity() -> int:
    """lite 硬上限 1 万：逼近时要显式告警，否则新增规则只能偷偷挤掉低分项。"""
    p = pathlib.Path(__file__).resolve().parent.parent / "subs" / "lite" / "domains.txt"
    if not p.exists():
        return 0
    cap = 10000
    n = sum(1 for l in p.read_text(encoding="utf-8", errors="ignore").splitlines()
            if l.strip() and not l.strip().startswith("#"))
    print(f"· lite 容量：{n} / {cap}（余量 {cap - n}）")
    if n >= cap:
        print("✗ lite 已达上限：检查 compile 的淘汰逻辑是否在挤掉高分规则")
        return 1
    if cap - n < 100:
        print(f"⚠️ lite 余量仅 {cap - n} 条，濒临上限")
    return 0


def main() -> int:
    rc = lite_capacity()
    tok = token()
    if not tok:
        print("· 无 CF_API_TOKEN，跳过 Pages 额度检查")
        return rc

    month = datetime.now(timezone.utc).strftime("%Y-%m")
    used, page = 0, 1
    # 每页 25 条，上限 500 次/月 → 至少翻 20 页；原来只翻 12 页（300 条）会把 350 的告警线架空
    while page <= 30:
        req = urllib.request.Request(
            f"https://api.cloudflare.com/client/v4/accounts/{ACC}/pages/projects/{PROJECT}"
            f"/deployments?per_page=25&page={page}",
            headers={"Authorization": "Bearer " + tok})
        try:
            with urllib.request.urlopen(req, timeout=30) as f:
                body = json.load(f)
        except urllib.error.HTTPError as e:
            print(f"· 查询部署列表失败 HTTP {e.code}，跳过")
            return 0
        res = body.get("result") or []
        if not res:
            break
        for d in res:
            if (d.get("created_on") or "")[:7] == month:
                used += 1
        if (res[-1].get("created_on") or "")[:7] < month:
            break
        page += 1

    print(f"· 本月（{month}）Pages 部署：{used} 次 / 上限 500，告警线 {WARN}")
    if used >= WARN:
        print(f"✗ 已用 {used} 次，逼近上限：检查是否有空部署，或把每日轮次调少")
        return 1
    return rc


if __name__ == "__main__":
    sys.exit(main())
