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
import re
import shutil
import subprocess
import sys
import tempfile
import time
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
    # 构建指纹也发一份：Workers 的 cron 靠它判断规则新旧，比 GitHub raw 稳
    mf = ROOT / "state" / "build_manifest.json"
    if mf.exists():
        files["/state/build_manifest.json"] = mf.read_bytes()
    # Pages Function：/dns-query 代理到 Worker。workers.dev 国内不可达、pages.dev 可达，
    # 这是让国内用户真正能用上自建 DoH 的唯一免费通道。
    fn = ROOT / "pages" / "dns-query.js"
    if fn.exists():
        files["/functions/dns-query.js"] = fn.read_bytes()
    return files


def ctype(path):
    if path.endswith(".html"):
        return "text/html; charset=utf-8"
    if path.endswith(".json"):
        return "application/json"
    if path.endswith(".txt") or path.endswith(".list") or path.endswith(".sh"):
        return "text/plain; charset=utf-8"
    return "application/octet-stream"


def verify_doh(base):
    """确认 Pages Function 真的被编译上线了。

    静态文件能取到、deployment.files 是满的，都不代表 functions/ 被识别 ——
    wrangler 只从 cwd 找 functions/，跑错目录就整站退化成纯静态，POST 直接 405。
    所以部署完必须真打一次 DoH：200 且带 x-noas 头才算通过。"""
    import base64
    import struct
    q = struct.pack(">HHHHHH", 0x4e41, 0x0100, 1, 0, 0, 0)
    q += b"\x07example\x03com\x00" + struct.pack(">HH", 1, 1)
    url = base.rstrip("/") + "/dns-query?dns=" + base64.urlsafe_b64encode(q).decode().rstrip("=")
    for i in range(3):
        try:
            r = requests.get(url, timeout=30, proxies={"http": None, "https": None},
                             headers={"accept": "application/dns-message",
                                      "user-agent": "Mozilla/5.0 NoAS"})
            if r.status_code == 200 and r.headers.get("x-noas"):
                print("DoH 端点验证：%d / x-noas=%s / %d 字节 -> OK"
                      % (r.status_code, r.headers.get("x-noas"), len(r.content)))
                return True
            print("DoH 端点验证：HTTP %d（x-noas=%s）"
                  % (r.status_code, r.headers.get("x-noas")))
        except Exception as e:
            print("DoH 端点验证异常（%s）" % type(e).__name__)
        time.sleep(3)
    return False


def verify(url):
    """真的把文件取回来。deployment.files 只是 manifest 条目数，
    资产没被服务端接收时它照样是满的 —— 2026-11-21 的整站 500 就是这么骗过去的。"""
    for i in range(4):
        try:
            r = requests.get(url.rstrip("/") + "/subs/lite/domains.txt", timeout=60,
                             proxies={"http": None, "https": None})
            if r.status_code == 200 and len(r.content) > 1024:
                print("线上取文验证：%d 字节 -> OK" % len(r.content))
                return True
            print("线上取文验证：HTTP %d / %d 字节" % (r.status_code, len(r.content)))
        except Exception as e:
            print("线上取文异常（%s）" % type(e).__name__)
        if i < 3:
            time.sleep(3)
    return False


def deploy_wrangler(stage):
    """官方 CLI 是唯一被验证可行的 direct-upload 路径。
    手写 /pages/assets/upload + manifest 提交会被接受但落成 0 文件（assets 键对不上），
    所以这里不再自己拼协议。"""
    env = dict(os.environ)
    env["CLOUDFLARE_API_TOKEN"] = os.environ.get("CF_TOKEN") or os.environ.get("CF_API_TOKEN") or ""
    env["CLOUDFLARE_ACCOUNT_ID"] = ACCT
    env.setdefault("NO_COLOR", "1")
    cmd = ["npx", "-y", "wrangler@4", "pages", "deploy", ".",
           "--project-name", PROJECT, "--branch", "main", "--commit-dirty=true"]
    print("执行：", " ".join(cmd), "（cwd=%s）" % stage)
    try:
        # 关键：wrangler 是从 **cwd** 找 functions/ 目录来编译 Pages Functions。
        # 在仓库根跑会漏掉 stage 里的 functions/，整站就退化成纯静态。
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=900, env=env, cwd=str(stage))
    except subprocess.TimeoutExpired:
        print("wrangler 超时（900s）")
        return None
    out = (p.stdout or "") + (p.stderr or "")
    print(out.strip()[-1500:])
    if p.returncode != 0:
        return None
    m = re.search(r"https://([0-9a-z]{8})\.", out)
    return ("https://%s.noas-cdn.pages.dev" % m.group(1)) if m else None


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

    # 1.5) 无变化就不发部署：Pages 每月 500 次是硬配额。
    #      但"台账无变化"不等于"线上可用"——必须真的取一次文件再决定跳过。
    if not todo:
        try:
            v = requests.get(f"https://{PROJECT}.pages.dev/subs/lite/domains.txt", timeout=60,
                             proxies={"http": None, "https": None})
            if v.status_code == 200 and len(v.content) > 1024:
                print("无变化且线上可取文（%d 字节），跳过部署以节省配额" % len(v.content))
                return 0
            print("无变化但线上取文失败（HTTP %d / %d 字节），强制重发"
                  % (v.status_code, len(v.content)))
        except Exception as e:
            print("线上探测失败（%s），强制重发" % type(e).__name__)

    def flush(batch, jwt):
        if not batch:
            return 0
        resp = requests.post(ASSET_URL, headers={"Authorization": "Bearer " + jwt},
                             json=batch, timeout=600)
        if resp.status_code >= 300:
            print("资产上传失败 HTTP", resp.status_code, resp.text[:400])
            raise SystemExit(1)
        return len(batch)

    # 2) 上传资产 + 提交 manifest。做成可重入：Pages 的 assets 以 sha256 为键，
    #    服务端淘汰旧哈希后，纯增量 manifest 会落成 0 文件的空站点（线上 500）。
    def push(paths, tag):
        r = requests.get(f"{ACC_BASE}/pages/projects/{PROJECT}/upload-token", headers=auth, timeout=60)
        if r.status_code != 200:
            print("取 upload-token 失败", r.status_code, r.text[:300])
            return None
        jwt = (r.json().get("result") or {}).get("jwt") or ""
        if not jwt:
            print("upload-token 为空")
            return None

        sent = 0
        batch, size = [], 0
        for p in paths:
            content = files[p]
            # base64 后体积约 1.34 倍，按原始字节预算分批
            if size and size + len(content) > BATCH:
                sent += flush(batch, jwt)
                batch, size = [], 0
            batch.append({"key": hashes[p],
                          "value": base64.b64encode(content).decode(),
                          "metadata": {"contentType": ctype(p)}})
            size += len(content)
        sent += flush(batch, jwt)
        if paths:
            print("资产已上传 %d 个%s" % (sent, tag))

        parts = [
            ("manifest", (None, json.dumps({p: hashes[p] for p in files}))),
            ("branch", (None, "main")),
            ("commit_message", (None, "NoAS rules %s%s"
                                % (os.environ.get("NOAS_VER", "latest"), tag))),
        ]
        r = requests.post(BASE, headers=auth, files=parts, timeout=600)
        try:
            body = r.json()
        except Exception:
            print("HTTP", r.status_code, r.text[:400])
            return None
        print("HTTP", r.status_code, "success", body.get("success"))
        for e in body.get("errors") or []:
            print("ERR", e.get("code"), e.get("message"))
        if not body.get("success"):
            return None

        res = body.get("result") or {}
        print("部署地址：", res.get("url") or "")
        # 关键：deployment.files 只是 manifest 的条目数，资产被服务端淘汰时它照样是满的。
        # 只有真的把文件取回来，才能证明站点不是空的。
        base = res.get("url") or f"https://{PROJECT}.pages.dev"
        probe = "/subs/lite/domains.txt"
        ok = False
        for attempt in range(4):
            try:
                v = requests.get(base + probe, timeout=60)
                if v.status_code == 200 and len(v.content) > 1024:
                    ok = True
                    print("线上取文验证：%d 字节 -> OK" % len(v.content))
                    break
                print("线上取文验证：HTTP %d / %d 字节" % (v.status_code, len(v.content)))
            except Exception as e:
                print("线上取文异常（%s）" % type(e).__name__)
            if attempt < 3:
                time.sleep(3)
        return res if ok else None

    # 官方 wrangler 是唯一被验证能真正写入文件的路径。
    stage = Path(tempfile.mkdtemp(prefix="noas-pages-"))
    try:
        for p, b in files.items():
            f = stage / p.lstrip("/")
            f.parent.mkdir(parents=True, exist_ok=True)
            f.write_bytes(b)
        url = deploy_wrangler(stage) or ""
    finally:
        shutil.rmtree(stage, ignore_errors=True)

    ok = bool(url) and verify(url) and verify_doh(url)
    if not ok and verify(f"https://{PROJECT}.pages.dev"):
        url = url or f"https://{PROJECT}.pages.dev"
        ok = verify_doh(url)
    if not ok:
        print("wrangler 部署未生效，回退到直连 API 全量重试…")
        res = push(list(files), "-fallback") or {}
        url = res.get("url") or ""
        if not url or not verify(url if url.startswith("https://") else f"https://{PROJECT}.pages.dev"):
            print("Pages 两条部署路径都失败，需人工介入")
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
