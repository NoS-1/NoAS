#!/usr/bin/env python3
"""把订阅产物推到 Cloudflare Pages（真增量：按内容哈希只上传变更文件）。

CF Pages direct upload 的正确姿势（2026-11 实测）：
  1) GET  /accounts/{acc}/pages/projects/{p}/upload-token   -> JWT（一次性，只管上传）
  2) POST /pages/assets/upload  body=[{key, value(base64), metadata:{contentType}}]
     key 必须与 final manifest 里的哈希一致；本项目统一用 sha256 hex（64 位），
     因为部署详情里的 files 记录就是 sha256，md5 提交上去会被判成空部署。
  3) POST /accounts/{acc}/pages/projects/{p}/deployments
     multipart，只提交 manifest（路径 -> 哈希），不带文件本体；data= urlencoded 会 400。
  4) 部署后回读 deployment.files 数量做自校验，少于预期即视为失败。

state/cdn_assets.json 记 path -> sha256，入库后 CI 每次只传变更，68MB 常态零上传。
"""
import base64
import hashlib
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

import requests

ROOT = Path(__file__).resolve().parent.parent
ACCT = os.environ.get("CF_ACCOUNT_ID", "226431c8f431ebb75d82dd5dbd5e8d86")
PROJECT = os.environ.get("CF_PROJECT", "noas-cdn")
ACC_BASE = f"https://api.cloudflare.com/client/v4/accounts/{ACCT}"
BASE = f"{ACC_BASE}/pages/projects/{PROJECT}/deployments"
ASSET_URL = "https://api.cloudflare.com/client/v4/pages/assets/upload"
STATE = ROOT / "state" / "cdn_assets.json"
BATCH = 8 * 1024 * 1024


def collect():
    """收集要发布的文件：页面 + 三档订阅 + 通道 + 路径 + 混合。排除 meta/history 之类。"""
    files = {}
    for f in sorted((ROOT / "docs").glob("*.html")):
        files[f"/{f.name}"] = f.read_bytes()
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


def ctype(path):
    if path.endswith(".html"):
        return "text/html; charset=utf-8"
    if path.endswith(".json"):
        return "application/json"
    if path.endswith(".txt") or path.endswith(".list") or path.endswith(".sh"):
        return "text/plain; charset=utf-8"
    return "application/octet-stream"


def main():
    token = os.environ.get("CF_TOKEN") or ""
    if not token:
        print("缺 CF_TOKEN")
        return 2

    files = collect()
    total = sum(len(v) for v in files.values())
    hashes = {p: hashlib.sha256(v).hexdigest() for p, v in files.items()}
    known = {}
    if STATE.exists():
        try:
            known = json.loads(STATE.read_text(encoding="utf-8"))
        except Exception:
            known = {}

    todo = [p for p in files if known.get(p) != hashes[p]]
    print("待部署 %d 个文件，共 %.1f MB｜需上传 %d 个，复用 %d 个"
          % (len(files), total / 1048576, len(todo), len(files) - len(todo)))

    auth = {"Authorization": "Bearer " + token}

    # 0) 干跑：只看差异，一个请求都不发（Pages 部署次数是硬配额，误触一次就是白花）
    if os.environ.get("NOAS_DRY") == "1":
        print("干跑模式：不部署")
        print("  差异文件：", [p for p in todo][:12], "共 %d 个" % len(todo))
        return 0

    # 1.5) 无变化就绝不发部署：Pages 每月 500 次部署是硬配额，空部署纯属浪费，
    #      也让"真的部署了"这件事失去信号价值。跳过前回读线上文件数，避免把故障盖住。
    if not todo:
        try:
            d = requests.get(f"{BASE}?per_page=1", headers=auth, timeout=60).json()
            latest = (d.get("result") or [{}])[0]
            if len(latest.get("files") or {}) == len(files):
                print("无变化且线上一致（%d 个文件），跳过部署以节省配额" % len(files))
                return 0
            print("台账无变化但线上只有 %d 个文件（预期 %d），继续部署"
                  % (len(latest.get("files") or {}), len(files)))
        except Exception as e:
            print("回读最新部署失败（%s），继续走正常部署" % type(e).__name__)

    # 2) 上传变更资产
    if todo:
        r = requests.get(f"{ACC_BASE}/pages/projects/{PROJECT}/upload-token", headers=auth, timeout=60)
        if r.status_code != 200:
            print("取 upload-token 失败", r.status_code, r.text[:300])
            return 1
        jwt = (r.json().get("result") or {}).get("jwt") or ""
        if not jwt:
            print("upload-token 为空")
            return 1

        batch, size = [], 0
        sent = 0

        def flush(batch, size):
            if not batch:
                return 0
            resp = requests.post(ASSET_URL, headers={"Authorization": "Bearer " + jwt},
                                 json=batch, timeout=600)
            if resp.status_code >= 300:
                print("资产上传失败 HTTP", resp.status_code, resp.text[:400])
                raise SystemExit(1)
            return len(batch)

        for p in todo:
            content = files[p]
            item = {"key": hashes[p],
                    "value": base64.b64encode(content).decode(),
                    "metadata": {"contentType": ctype(p)}}
            # base64 后体积约 1.34 倍，按原始字节预算分批
            if size and size + len(content) > BATCH:
                sent += flush(batch, size)
                batch, size = [], 0
            batch.append(item)
            size += len(content)
        sent += flush(batch, size)
        print("资产已上传 %d 个（sha256 键）" % sent)

    # 2) 只提交 manifest
    parts = [
        ("manifest", (None, json.dumps({p: hashes[p] for p in files}))),
        ("branch", (None, "main")),
        ("commit_message", (None, "NoAS rules %s" % os.environ.get("NOAS_VER", "latest"))),
    ]
    r = requests.post(BASE, headers=auth, files=parts, timeout=600)
    try:
        body = r.json()
    except Exception:
        print("HTTP", r.status_code, r.text[:400])
        return 1
    print("HTTP", r.status_code, "success", body.get("success"))
    res = body.get("result") or {}
    for e in body.get("errors") or []:
        print("ERR", e.get("code"), e.get("message"))
    if not body.get("success"):
        return 1

    url = res.get("url") or ""
    dep_id = res.get("id") or ""

    # 3) 回读 files 自校验：增量提交的 manifest 若没被接受，部署会是空的
    got = -1
    try:
        d = requests.get(f"{BASE}/{dep_id}", headers=auth, timeout=60).json()
        got = len((d.get("result") or {}).get("files") or {})
    except Exception as e:
        print("回读失败", e)
    print("部署地址：", url)
    print("内容校验：线上 %d 个文件 / 预期 %d 个 -> %s"
          % (got, len(files), "OK" if got == len(files) else "FAIL"))

    if got != len(files):
        print("增量提交没被接受，请回退全量脚本（/tmp/cdn_deploy_v1.py）")
        return 1

    # 4) 台账：资产哈希 + 部署信息
    STATE.parent.mkdir(parents=True, exist_ok=True)
    STATE.write_text(json.dumps(hashes, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")

    ledger = {
        "project": PROJECT,
        "production": f"https://{PROJECT}.pages.dev",
        "latest_deployment": url,
        "files": len(files), "bytes": total,
        "uploaded_this_run": len(todo),
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
    return 0


if __name__ == "__main__":
    sys.exit(main())
