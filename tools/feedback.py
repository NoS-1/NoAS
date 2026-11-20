#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""从用户反馈里学习（自我成长的闭环）。

仓库 Issue 就是"错误报告接口"，只认两个标签：
  · 误伤  —— 正常网站被误拦：直接写进白名单台账（source=incident），下一轮编译立刻放行；
  · 漏拦  —— 广告/追踪没拦住：只有域名本身带广告/追踪结构（ads./track./click. 等）才进
              ad_endpoints.txt，其余进 lists/misses.txt 观察池，绝不凭一个反馈就乱加黑，保证误伤仍为 0。

额度纪律：每次运行最多 2 次读 + 2N 次写（只处理未闭环的 Issue，最多 10 条），
平时一天 2 次请求，可忽略不计；结果写 learn_events.jsonl，出现在成长账本里。
"""
import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "tools"))
import whitelist  # noqa: E402

TOKEN = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN") or ""
REPO = os.environ.get("NOAS_REPO", "NoS-1/NoAS")
EVENTS = os.path.join(ROOT, "history", "learn_events.jsonl")
EP = os.path.join(ROOT, "lists", "ad_endpoints.txt")
MISS = os.path.join(ROOT, "lists", "misses.txt")
SKIP = {"github.com", "api.github.com", "raw.githubusercontent.com", "github.io",
        "doubao.com", "doubaoapp.com", "example.com"}
DOMAIN_RE = re.compile(r"(?<![a-z0-9-])((?:[a-z0-9][a-z0-9-]{0,61}\.)+[a-z]{2,12})(?![a-z0-9-])", re.I)
AD_LIKE = re.compile(
    r"^(ads?|ad|adserver|adservice|track|tracker|tracking|click|clicks|beacon|px|pixel|"
    r"telemetry|collect|collector|stat|stats|log|logs|metrics|promo|promos|banner|banners|"
    r"pop|popup|redirect|redirector)\.", re.I)


def api(path, method="GET", payload=None):
    url = "https://api.github.com" + path
    body = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(url, data=body, method=method)
    req.add_header("Accept", "application/vnd.github+json")
    req.add_header("User-Agent", "NoAS-feedback")
    if TOKEN:
        req.add_header("Authorization", "Bearer " + TOKEN)
    if body:
        req.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(req, timeout=20) as r:
        return json.loads(r.read().decode() or "{}")


def log_event(kind, detail):
    os.makedirs(os.path.dirname(EVENTS), exist_ok=True)
    import datetime
    with open(EVENTS, "a", encoding="utf-8") as f:
        f.write(json.dumps({"at": datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
                            "kind": kind, "detail": detail}, ensure_ascii=False) + "\n")


def pick_domain(text):
    for m in DOMAIN_RE.finditer(text or ""):
        d = m.group(1).lower().strip(".")
        if d in SKIP:
            continue
        if len(d) < 5 or d.count(".") < 1:
            continue
        return d
    return None


def add_endpoint(d):
    lines = []
    if os.path.exists(EP):
        with open(EP, encoding="utf-8") as f:
            lines = f.read().splitlines()
    if any(l.strip().lower() == d for l in lines):
        return False
    with open(EP, "a", encoding="utf-8") as f:
        f.write(d + "\n")
    return True


COOLDOWN = os.path.join(ROOT, "lists", "cooldown.txt")


def cooldown_add(d):
    """误伤域进冷却池：即使有人把它从白名单里手滑删掉，编译期依然豁免，不会复发。

    格式纪律：cooldown.txt 一行一个纯域名。compile.py 用 load_list_file 读整行，
    任何 tab 列都会让整串当成域名，冷却就失效——所以元数据另记 history/cooldown_log.jsonl。
    """
    lines = ""
    if os.path.exists(COOLDOWN):
        lines = open(COOLDOWN, encoding="utf-8").read()
    if any(l.split("#", 1)[0].strip().lower() == d for l in lines.splitlines()):
        return False
    if not lines.endswith("\n"):
        lines += "\n"
    lines += d + "\n"
    open(COOLDOWN, "w", encoding="utf-8").write(lines)
    return True


def add_miss(d, note):
    lines = []
    if os.path.exists(MISS):
        with open(MISS, encoding="utf-8") as f:
            lines = f.read().splitlines()
    if any(l.split("\t")[0] == d for l in lines):
        return False
    with open(MISS, "a", encoding="utf-8") as f:
        f.write("%s\t%s\n" % (d, note))
    return True


def main():
    if not TOKEN:
        print("无 GITHUB_TOKEN，跳过反馈学习（本地模式）")
        return 0
    issues = {}
    for label in ("误伤", "漏拦"):
        try:
            for it in api("/repos/%s/issues?state=open&labels=%s&per_page=10"
                          % (REPO, urllib.parse.quote(label))):
                issues[it["number"]] = it
        except Exception as e:
            print("读取 %s 标签失败：%s" % (label, e))
    if not issues:
        print("没有待处理的反馈 Issue")
        return 0

    learned = 0
    for num, it in sorted(issues.items()):
        labels = {l["name"] for l in it.get("labels", [])}
        d = pick_domain((it.get("title") or "") + "\n" + (it.get("body") or ""))
        if not d:
            print("#%d 未解析出域名，保留待人工处理" % num)
            continue
        try:
            if "误伤" in labels:
                whitelist.add(d, "误伤反馈 issue #%d" % num, "incident")
                cd = cooldown_add(d)
                log_event("fp_fix", {"domain": d, "issue": num, "cooldown": cd})
                msg = ("已学习：`%s` 进入白名单台账 **并加入冷却池**，下一轮编译立刻放行，"
                       "且以后即使白名单被误删也不会复发。（误伤优先，宁放不误拦）" % d)
            else:
                if AD_LIKE.match(d):
                    new = add_endpoint(d)
                    log_event("ad_endpoint", {"domain": d, "issue": num, "new": new})
                    msg = ("已学习：`%s` 具备广告/追踪结构，已作为审计端点强拦（优先于白名单）。" % d)
                else:
                    new = add_miss(d, "issue #%d" % num)
                    log_event("miss_candidate", {"domain": d, "issue": num, "new": new})
                    msg = ("已记录：`%s` 进入漏拦观察池（不凭单条反馈加黑，避免误伤；"
                           "待多源共识或人工审计后晋级）。" % d)
            api("/repos/%s/issues/%d/comments" % (REPO, num), "POST", {"body": msg})
            api("/repos/%s/issues/%d" % (REPO, num), "PATCH", {"state": "closed"})
            learned += 1
        except Exception as e:
            print("#%d 处理失败：%s" % (num, e))
    subprocess.run([sys.executable, os.path.join(ROOT, "tools", "whitelist.py"), "sync"],
                   check=False)
    print("反馈学习完成：处理 %d 条" % learned)
    return 0


if __name__ == "__main__":
    import urllib.parse
    raise SystemExit(main())
