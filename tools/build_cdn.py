#!/usr/bin/env python3
"""build_cdn.py —— 把订阅产物推到 Cloudflare Pages，做零额度 CDN。

为什么用 Pages 而不是 Worker：
  Pages 静态分发【不计请求额度、无带宽限制】，Worker 是 10 万请求/天。
  规则文件放 Pages，Worker 只留作 DoH 解析，额度就彻底分开了。

Direct Upload 协议（官方文档）：
  POST /accounts/{id}/pages/projects/{name}/deployments
  multipart：manifest = {"<path>": "<sha256 hex>"}，每个文件一个 part，part 名即路径。

幂等策略：项目不存在则创建；部署失败只报错不删任何东西。
"""
import hashlib
import json
import mimetypes
import os
import ssl
import sys
import urllib.request
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
API = "https://api.cloudflare.com/client/v4"
PROJECT = "noas-cdn"

# 只上"小体量、天天要用"的产物；mid/full 走 raw（data 分支），不进 CDN
SOURCES = [
    ("subs/lite", "subs/lite"),
    ("subs/paths/core", "subs/paths/core"),
    ("subs/paths/full", "subs/paths/full"),
    ("subs/channels", "subs/channels"),
    ("subs/mixed", "subs/mixed"),
]


def token():
    t = os.environ.get("CF_TOKEN") or ""
    if not t and Path("/tmp/.cftoken").exists():
        t = Path("/tmp/.cftoken").read_text().strip()
    return t


def api(method, path, body=None, token_value=None, content_type="application/json"):
    url = API + path
    data = None
    if body is not None:
        data = body if isinstance(body, bytes) else json.dumps(body).encode()
    req = urllib.request.Request(url, data=data, method=method,
                                 headers={"Authorization": "Bearer " + token_value,
                                          "content-type": content_type})
    ctx = ssl.create_default_context()
    with urllib.request.urlopen(req, timeout=120, context=ctx) as r:
        return json.loads(r.read().decode())


def ensure_project(acct, tk):
    try:
        d = api("GET", "/accounts/%s/pages/projects/%s" % (acct, PROJECT), token_value=tk)
        if d.get("success"):
            return d["result"]
    except Exception:
        pass
    d = api("POST", "/accounts/%s/pages/projects" % acct,
            {"name": PROJECT, "production_branch": "main"}, token_value=tk)
    if not d.get("success"):
        raise SystemExit("创建 Pages 项目失败：%s" % d.get("errors"))
    return d["result"]


def collect():
    files = {}
    for src, dest in SOURCES:
        base = ROOT / src
        if not base.is_dir():
            continue
        for p in sorted(base.rglob("*")):
            if not p.is_file() or p.stat().st_size > 25 * 1024 * 1024:
                continue
            if p.suffix in (".pyc",):
                continue
            rel = "%s/%s" % (dest, p.relative_to(base).as_posix())
            files["/" + rel] = p
    return files


def multipart(files, manifest, branch="main"):
    boundary = "----noas" + uuid.uuid4().hex
    body = []

    def add_field(name, value):
        body.append(("--" + boundary + "\r\n").encode())
        body.append(('Content-Disposition: form-data; name="%s"\r\n\r\n' % name).encode())
        body.append((value + "\r\n").encode())

    add_field("branch", branch)
    add_field("commit_message", "NoAS CDN 同步")
    add_field("manifest", json.dumps(manifest))

    for path, fp in files.items():
        ctype = mimetypes.guess_type(fp.name)[0] or "application/octet-stream"
        body.append(("--" + boundary + "\r\n").encode())
        body.append(('Content-Disposition: form-data; name="%s"; filename="%s"\r\n'
                     % (path, Path(path).name)).encode())
        body.append(("Content-Type: %s\r\n\r\n" % ctype).encode())
        body.append(fp.read_bytes())
        body.append(b"\r\n")
    body.append(("--" + boundary + "--\r\n").encode())
    return b"".join(body), "multipart/form-data; boundary=" + boundary


def main():
    acct = os.environ.get("CF_ACCT", "226431c8f431ebb75d82dd5dbd5e8d86")
    tk = token()
    if not tk:
        raise SystemExit("缺少 CF_TOKEN")
    ensure_project(acct, tk)

    files = collect()
    if not files:
        raise SystemExit("没有可上传的产物，先跑 compile / build_paths / gen_channels")
    manifest = {p: hashlib.sha256(fp.read_bytes()).hexdigest() for p, fp in files.items()}
    body, ctype = multipart(files, manifest)

    d = api("POST", "/accounts/%s/pages/projects/%s/deployments" % (acct, PROJECT),
            body, token_value=tk, content_type=ctype)
    if not d.get("success"):
        print("部署失败：%s" % json.dumps(d.get("errors"), ensure_ascii=False))
        return 1
    r = d["result"]
    url = r.get("url") or ("https://%s.pages.dev" % PROJECT)
    print("CDN 部署成功：%d 文件 ／ %s" % (len(files), url))
    print("  规则入口：%s/subs/lite/adguard.txt" % url.rstrip("/"))
    print("  通道入口：%s/subs/channels/doh.txt" % url.rstrip("/"))
    Path(ROOT / "subs" / "channels" / "cdn.json").write_text(json.dumps(
        {"url": url, "files": len(files), "project": PROJECT,
         "entry": {"lite": url.rstrip("/") + "/subs/lite/adguard.txt",
                   "channels": url.rstrip("/") + "/subs/channels/doh.txt"}},
        ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
