#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""gh_app_token.py —— 用 GitHub App 私钥现签一个 installation token（1 小时有效）。

双保险里的“首选”：有 App 就用它，没有就由调用方（git_token.sh / CI）回退到 PAT 或内置 GITHUB_TOKEN。

配置（任一来源）：
  环境变量 GH_APP_ID / GH_APP_PRIVATE_KEY（CI secret；私钥里的 \n 会转义成单行）
  或本机文件 /home/user/.noas/app_id、/home/user/.noas/app.pem

退出码：
  0 = 已签发（token 打到 stdout，或写入 GITHUB_OUTPUT）
  2 = 未配置 App（调用方应静默回退）
  1 = 配置了但签发失败
"""
import base64
import json
import os
import sys
import time
import urllib.request

APP_ID_FILE = "/home/user/.noas/app_id"
APP_PEM_FILE = "/home/user/.noas/app.pem"
API = "https://api.github.com"


def b64u(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def get_app_id():
    v = (os.environ.get("GH_APP_ID") or "").strip()
    if v:
        return v
    return open(APP_ID_FILE).read().strip() if os.path.exists(APP_ID_FILE) else ""


def get_pem():
    raw = os.environ.get("GH_APP_PRIVATE_KEY") or ""
    if not raw and os.path.exists(APP_PEM_FILE):
        raw = open(APP_PEM_FILE, encoding="utf-8").read()
    return raw.replace("\\n", "\n").strip() if raw else ""


def make_jwt(app_id, pem):
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding

    key = serialization.load_pem_private_key(pem.encode(), password=None)
    now = int(time.time())
    head = b64u(json.dumps({"alg": "RS256", "typ": "JWT"}, separators=(",", ":")).encode())
    body = b64u(json.dumps({"iat": now - 60, "exp": now + 540, "iss": app_id},
                           separators=(",", ":")).encode())
    sig = key.sign((head + "." + body).encode(), padding.PKCS1v15(), hashes.SHA256())
    return head + "." + body + "." + b64u(sig)


def call(url, jwt, method="GET"):
    req = urllib.request.Request(url, method=method, headers={
        "Authorization": "Bearer " + jwt,
        "Accept": "application/vnd.github+json",
        "User-Agent": "NoAS-gh-app",
    })
    with urllib.request.urlopen(req, timeout=25) as r:
        return json.loads(r.read() or b"{}")


def main():
    app_id, pem = get_app_id(), get_pem()
    if not app_id or not pem:
        print("未配置 App（GH_APP_ID / GH_APP_PRIVATE_KEY 或 app_id / app.pem）", file=sys.stderr)
        return 2
    jwt = make_jwt(app_id, pem)
    installs = call(API + "/app/installations", jwt)
    if not installs:
        print("App 未安装到任何仓库，先去 App 设置页 Install 一次", file=sys.stderr)
        return 1
    tok = call("%s/app/installations/%d/access_tokens" % (API, installs[0]["id"]), jwt, method="POST")
    token = tok.get("token") or ""
    if not token:
        print("签发失败：%s" % json.dumps(tok)[:200], file=sys.stderr)
        return 1
    if "--github-output" in sys.argv:
        out = os.environ.get("GITHUB_OUTPUT")
        if out:
            with open(out, "a", encoding="utf-8") as f:
                f.write("token=%s\n" % token)
            print("App 令牌已签发，有效期至 %s" % tok.get("expires_at", "?"))
            return 0
    print(token)
    return 0


if __name__ == "__main__":
    sys.exit(main())
