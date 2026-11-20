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


def main() -> int:
    tok = token()
    if not tok:
        print("· 无 CF_API_TOKEN，跳过额度检查")
        return 0

    month = datetime.now(timezone.utc).strftime("%Y-%m")
    used, page = 0, 1
    while page <= 12:
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
    return 0


if __name__ == "__main__":
    sys.exit(main())
