#!/usr/bin/env python3
"""cdn_deploy.py —— 把规则产物推到 Cloudflare Pages（免费 CDN，不占 Workers 额度）。

为什么用 Pages 而不是 Worker：
  Worker 每请求都计 10 万/天的免费额度，做 CDN 分发会很快打满；
  Pages 是纯静态边缘节点，免费、带宽不限，适合当订阅分发层。

部署内容：lite 全格式 + mid 全格式 + L2 路径层 + 通道产物 + L1/L2 合并包 + 入口页。
full 档不上（单文件 27MB 超过 Pages 25MB 上限，继续走 GitHub data 分支）。

用法：
  CF_TOKEN=$(cat /tmp/.cftoken) python3 tools/cdn_deploy.py
"""
import hashlib
import json
import os
import sys
from pathlib import Path

import requests

ROOT = Path(__file__).resolve().parent.parent
ACCT = "226431c8f431ebb75d82dd5dbd5e8d86"
PROJECT = "noas-cdn"
BASE = f"https://api.cloudflare.com/client/v4/accounts/{ACCT}/pages/projects/{PROJECT}/deployments"

INDEX = """<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>NoAS · 规则分发（Cloudflare Pages）</title>
<style>
body{background:#0d1117;color:#e6edf3;font:16px/1.7 -apple-system,"Segoe UI",sans-serif;max-width:820px;margin:0 auto;padding:32px 20px}
a{color:#58a6ff}h1{font-size:24px}h2{font-size:17px;margin-top:28px;color:#8b949e}
code{background:#161b22;padding:2px 6px;border-radius:4px;word-break:break-all}
.card{background:#161b22;border:1px solid #30363d;border-radius:10px;padding:14px 16px;margin:10px 0}
</style></head><body>
<h1>NoAS · 规则分发节点</h1>
<p>Cloudflare Pages 静态分发，免费、带宽不限。规则每日重建。</p>

<h2>L1 DNS 规则</h2>
<div class="card">
<b>lite（零误伤最小集 · 9,962 条）</b><br>
AdGuard：<code>https://noas-cdn.pages.dev/subs/lite/adguard.txt</code><br>
domains：<code>https://noas-cdn.pages.dev/subs/lite/domains.txt</code>
</div>
<div class="card">
<b>mid（日常默认 · 184,941 条）</b><br>
AdGuard：<code>https://noas-cdn.pages.dev/subs/mid/adguard.txt</code><br>
domains：<code>https://noas-cdn.pages.dev/subs/mid/domains.txt</code>
</div>

<h2>L1+L2 合并包（一份搞定域名拦截 + 路径改写）</h2>
<div class="card">
Surge：<code>https://noas-cdn.pages.dev/subs/mixed/noas-all.sgmodule</code><br>
Loon：<code>https://noas-cdn.pages.dev/subs/mixed/noas-all.plugin</code><br>
Quantumult X：<code>https://noas-cdn.pages.dev/subs/mixed/noas-all.conf</code>
</div>

<h2>L2 路径层</h2>
<div class="card"><code>https://noas-cdn.pages.dev/subs/paths/core/noas-path.sgmodule</code></div>

<h2>DNS 通道</h2>
<div class="card">
DoH 清单：<code>https://noas-cdn.pages.dev/subs/channels/doh.txt</code><br>
DoT 清单：<code>https://noas-cdn.pages.dev/subs/channels/dot.txt</code><br>
aiodns 脚本：<code>https://noas-cdn.pages.dev/subs/channels/aiodns.sh</code>
</div>

<p style="color:#8b949e;font-size:13px;margin-top:32px">
full 档（415,758 条）体积超过本节点单文件上限，请走 GitHub data 分支。
</p>
</body></html>
"""


def collect():
    files = {}
    files["/index.html"] = INDEX.encode()
    # 站点页：实时任务看板（前端直连 GitHub API，无需 token）+ 零误拦闭环页
    for name in ("tasks.html", "precision.html"):
        p = ROOT / "docs" / name
        if p.exists():
            files["/" + name] = p.read_bytes()
    for tier in ("lite", "mid"):
        d = ROOT / "subs" / tier
        for f in sorted(d.iterdir()):
            if f.is_file():
                files[f"/subs/{tier}/{f.name}"] = f.read_bytes()
    for sub in ("paths", "channels", "mixed"):
        d = ROOT / "subs" / sub
        for f in sorted(d.rglob("*")):
            if f.is_file() and f.stat().st_size <= 25 * 1024 * 1024:
                rel = f.relative_to(ROOT / "subs").as_posix()
                files[f"/subs/{rel}"] = f.read_bytes()
    return files


def main():
    token = os.environ.get("CF_TOKEN") or ""
    if not token:
        print("缺 CF_TOKEN")
        return 2
    files = collect()
    total = sum(len(v) for v in files.values())
    manifest = {p: hashlib.sha256(v).hexdigest() for p, v in files.items()}
    print("待部署 %d 个文件，共 %.1f MB" % (len(files), total / 1048576))

    data = {"manifest": json.dumps(manifest), "branch": "main",
            "commit_message": "NoAS rules %s" % os.environ.get("NOAS_VER", "latest")}
    parts = []
    for path, content in files.items():
        ctype = "text/html; charset=utf-8" if path.endswith(".html") else "application/octet-stream"
        parts.append((path, (path.lstrip("/"), content, ctype)))

    r = requests.post(BASE, headers={"Authorization": "Bearer " + token},
                      data=data, files=parts, timeout=600)
    try:
        body = r.json()
    except Exception:
        print("HTTP", r.status_code, r.text[:400])
        return 1
    print("HTTP", r.status_code, "success", body.get("success"))
    res = body.get("result") or {}
    if res.get("url"):
        print("部署地址：", res.get("url"))
        # 留一份机器可读台账：生产别名固定不变，latest_deployment 用于回滚定位
        from datetime import datetime, timezone
        ledger = {
            "project": PROJECT,
            "production": f"https://{PROJECT}.pages.dev",
            "latest_deployment": res.get("url"),
            "files": len(files), "bytes": total,
            "updated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "entry": {
                "lite": f"https://{PROJECT}.pages.dev/subs/lite/adguard.txt",
                "mid": f"https://{PROJECT}.pages.dev/subs/mid/adguard.txt",
                "mixed_surge": f"https://{PROJECT}.pages.dev/subs/mixed/noas-all.sgmodule",
                "doh_list": f"https://{PROJECT}.pages.dev/subs/channels/doh.txt",
                "aiodns": f"https://{PROJECT}.pages.dev/subs/channels/aiodns.sh",
                "tasks": f"https://{PROJECT}.pages.dev/tasks.html",
            },
        }
        (ROOT / "subs" / "channels" / "cdn.json").write_text(
            json.dumps(ledger, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    for e in body.get("errors") or []:
        print("ERR", e.get("code"), e.get("message"))
    return 0 if body.get("success") else 1


if __name__ == "__main__":
    sys.exit(main())
