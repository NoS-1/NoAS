#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""gh_app_token.py —— 用 GitHub App 私钥现签一个 installation token（1 小时有效），替代长期 PAT。

为什么改用 App 而不是 PAT：
  PAT 是长期静态凭据，泄一次就得人工吊销重建，而且明文只存在一个地方；
  App 的签发凭据是"私钥 + App ID"，运行时现签 1 小时 token，既不落盘也不会被复用。
  唯一的人工成本是首次创建 App（1 分钟），之后永不手工轮换。

用法（CI 里）：
  python3 tools/gh_app_token.py                # 打印 token 到 stdout
  python3 tools/gh_app_token.py --github-output # 写成 GITHUB_OUTPUT 的 step 输出 token
  随后：git remote set-url origin https://x-access-token:$TOKEN@github.com/<owner>/<repo>.git

配置（任一来源）：
  环境变量 GH_APP_ID / GH_APP_PRIVATE_KEY（私钥内容，\n 已转义也可）
  或本机文件 /home/user/.noas/app_id、/home/user/.noas/app.pem
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
    return (os.environ.get("GH_APP_ID") or "").strip() or (
        open(APP_ID_FILE).read().strip() if os.path.exists(APP_ID_FILE) else "")


def get_pem():
    raw = os.environ.get("GH_APP_PRIVATE_KEY") or ""
    if not raw and os.path.exists(APP_PEM_FILE):
        raw = open(APP_PEM_FILE, encoding="utf-8").read()
    if not raw:
        return ""
    # secret 里存的常是带字面 \n 的单行，转回真实换行
    return raw.replace("\\n", "\n").strip()


def make_jwt(app_id, pem):
    """RS256 JWT：iat 提前 60s 容错，exp 9 分钟内（GitHub 上限 10 分钟）。"""
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding

    key = serialization.load_pem_private_key(pem.encode(), password=None)
    now = int(time.time())
    head = b64u(json.dumps({"alg": "RS256", "typ": "JWT"}, separators=(",", ":")).encode())
    body = b64u(json.dumps({"iat": now - 60, "exp": now + 540, "iss": app_id},
                           separators=(",", ":")).encode())
    signing_input = (head + "." + body).encode()
    sig = key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
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
    want_output = "--github-output" in sys.argv
    app_id, pem = get_app_id(), get_pem()
    if not app_id or not pem:
        print("未配置 GH_APP_ID / GH_APP_PRIVATE_KEY（或 /home/user/.noas/app_id、app.pem）", file=sys.stderr)
        return 2
    jwt = make_jwt(app_id, pem)
    try:
        installs = call(API + "/app/installations", jwt)
    except Exception as e:
        print("列出 installation 失败：%s" % e, file=sys.stderr)
        return 1
    if not installs:
        print("该 App 还没安装到任何仓库，先去 App 设置页 Install 一次", file=sys.stderr)
        return 1
    inst_id = installs[0]["id"]
    tok = call("%s/app/installations/%d/access_tokens" % (API, inst_id), jwt, method="POST")
    token = tok.get("token") or ""
    if not token:
        print("签发失败：%s" % json.dumps(tok)[:200], file=sys.stderr)
        return 1
    if want_output:
        out = os.environ.get("GITHUB_OUTPUT")
        if out:
            with open(out, "a", encoding="utf-8") as f:
                f.write("token=%s\n" % token)
            print("已写入 GITHUB_OUTPUT，有效期至 %s" % tok.get("expires_at", "?"))
            return 0
    print(token)
    return 0


if __name__ == "__main__":
    sys.exit(main())
