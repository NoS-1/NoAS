#!/usr/bin/env python3
"""把每一步写进一个固定的 GitHub Issue，让人在手机上就能看到进展。

用法：
  python3 tools/log_step.py "阶段" "做了什么 / 结论"

注意：本仓库是公开仓库，Issue 页面全世界可见。本脚本只接受状态性文字，
出现 ghp_ / cfat_ / cfut_ 等凭据形态会直接拒绝写入并报错退出。
"""
import json
import os
import pathlib
import re
import sys
import urllib.error
import urllib.request

REPO = "NoS-1/NoAS"
STATE = pathlib.Path(__file__).resolve().parent.parent / "state" / "board.json"
CREDS = pathlib.Path("/home/user/.noas/creds.env")
TITLE = "运行状态 · 每一步可见"
SECRET_RE = re.compile(r"(ghp_[A-Za-z0-9]{20,}|cfat_[A-Za-z0-9]{20,}|cfut_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})")


def pat() -> str:
    if CREDS.exists():
        for line in CREDS.read_text(encoding="utf-8").splitlines():
            if line.startswith("GH_PAT="):
                return line.split("=", 1)[1].strip()
    return os.environ.get("GH_PAT", "")


def api(method: str, path: str, token: str, body=None):
    req = urllib.request.Request(
        "https://api.github.com" + path, method=method,
        headers={"Authorization": "token " + token, "Accept": "application/vnd.github+json",
                 "Content-Type": "application/json"},
        data=json.dumps(body).encode() if body is not None else None,
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as f:
            return f.status, json.load(f)
    except urllib.error.HTTPError as e:
        return e.code, {}


def find_board(token: str) -> int | None:
    if STATE.exists():
        try:
            n = json.loads(STATE.read_text(encoding="utf-8")).get("issue")
            if n:
                return int(n)
        except Exception:
            pass
    s, d = api("GET", f"/repos/{REPO}/issues?state=open&per_page=50", token)
    if s != 200:
        return None
    for i in d:
        if i.get("title") == TITLE:
            return i["number"]
    return None


def save_board(n: int):
    STATE.parent.mkdir(parents=True, exist_ok=True)
    STATE.write_text(json.dumps({"issue": n}, ensure_ascii=False) + "\n", encoding="utf-8")


def main() -> int:
    if len(sys.argv) < 3:
        print('用法：log_step.py "阶段" "内容"')
        return 2
    step, detail = sys.argv[1].strip(), sys.argv[2].strip()
    if SECRET_RE.search(step + detail):
        print("拒绝写入：内容里含凭据形态，公开 Issue 不能出现")
        return 3

    tok = pat()
    if not tok:
        print("缺 GH_PAT")
        return 1
    n = find_board(tok)
    if n is None:
        s, d = api("POST", f"/repos/{REPO}/issues", tok, {
            "title": TITLE,
            "body": ("这里是 NoAS 的执行流水账：每完成一步追加一条评论，手机上直接可见。\n\n"
                     "- 只记录状态与结论，不含任何凭据值（仓库是公开的）\n"
                     "- 构建全貌仍看 [Actions](https://github.com/NoS-1/NoAS/actions)\n"
                     "- 误拦率看 [precision.html](https://nos-1.github.io/NoAS/precision.html)"),
        })
        if s not in (200, 201):
            print("建 Issue 失败", s, d)
            return 1
        n = d["number"]
    save_board(n)

    s, d = api("POST", f"/repos/{REPO}/issues/{n}/comments", tok, {"body": f"**{step}**\n\n{detail}"})
    if s not in (200, 201):
        print("写评论失败", s, d)
        return 1
    print(f"已记录到 Issue #{n}: {step}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
