#!/usr/bin/env python3
"""Gateway 小档重建：把 lite 全量对齐到 Gateway 免费 DoH 主通道。

为什么只做小档：
- Gateway 列表上限约 100 个、单片 1000 条；中/大档（16 万/38 万根域）放不进去，
  硬塞会让规则表达式超长，反而破坏主通道。中/大档继续由 Worker 承担。
- 小档是零误拦最小集，放进 Gateway 后，设备走 Gateway 也能拿到同样的拦截效果，
  且不消耗 Worker 的 10 万/天请求额度。

用法：
  python3 tools/gateway_sync.py            # 只算计划，不动线上
  python3 tools/gateway_sync.py --apply    # 真正写入（先备份规则）
"""
import hashlib
import json
import os
import pathlib
import sys
import urllib.error
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parent.parent
ACC = os.environ.get("CF_ACCOUNT_ID", "226431c8f431ebb75d82dd5dbd5e8d86").strip()
TOK = os.environ.get("CF_API_TOKEN", "").strip()
SHARD = 1000
RULE_NAME = "NoAS 小档拦截"
BASE = "https://api.cloudflare.com/client/v4/accounts/" + ACC


def call(method, path, body=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(BASE + path, method=method, data=data,
                                 headers={"Authorization": "Bearer " + TOK,
                                          "Content-Type": "application/json"})
    try:
        return json.load(urllib.request.urlopen(req, timeout=40)), None
    except urllib.error.HTTPError as e:
        return e.read()[:200].decode("utf-8", "ignore"), "HTTP %d" % e.code
    except Exception as e:
        return {}, str(e)


def read_lite():
    p = ROOT / "subs" / "lite" / "domains.txt"
    out = set()
    for line in p.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.split("#", 1)[0].strip().lower()
        if not line or line.startswith("!"):
            continue
        if line.startswith("||"):
            line = line[2:].rstrip("^")
        if line.startswith("0.0.0.0 "):
            line = line.split()[-1]
        if "." in line and "/" not in line:
            out.add(line)
    return sorted(out)


def sha(text):
    return hashlib.sha256(text.encode()).hexdigest()[:12]


def main():
    apply = "--apply" in sys.argv
    if not TOK:
        print("Gateway 同步跳过：未配置 CF_API_TOKEN")
        return 0

    lite = read_lite()
    shards = [lite[i:i + SHARD] for i in range(0, len(lite), SHARD)]
    print("lite %d 条 → %d 片（每片 ≤%d）" % (len(lite), len(shards), SHARD))
    if len(shards) > 12:
        print("分片数超 12，拒绝执行：规则表达式会过长，先降 lite 上限")
        return 1

    lists, err = call("GET", "/gateway/lists")
    if err:
        print("读列表失败：%s" % err)
        return 1
    exist = {x["name"]: x for x in (lists.get("result") or [])}
    old = sorted(n for n in exist if n.startswith("noas_t1_"))

    plan = []
    for idx, chunk in enumerate(shards, 1):
        text = "\n".join(chunk)
        sha_val = sha(text)
        reuse = old[idx - 1] if idx - 1 < len(old) else None
        name = reuse or ("noas_l1_%d" % idx)
        cur = exist.get(name)
        stale = True
        if cur and sha_val in (cur.get("description") or ""):
            stale = False
        plan.append({"name": name, "id": (cur or {}).get("id"), "sha": sha_val,
                     "count": len(chunk), "stale": stale, "chunk": chunk})
        print("  片 %-12s %4d 条  sha=%s  %s" % (name, len(chunk), sha_val,
                                              "需更新" if stale else "已一致"))

    if not apply:
        print("干跑结束。加 --apply 才会写线上。")
        return 0

    # 备份现有规则
    rules, err = call("GET", "/gateway/rules")
    if err:
        print("读规则失败：%s" % err)
        return 1
    rule = next((r for r in (rules.get("result") or []) if r.get("name") == RULE_NAME), None)
    if not rule:
        print("找不到规则「%s」，停止" % RULE_NAME)
        return 1
    (ROOT / "state" / "gateway_rules.bak.json").write_text(
        json.dumps(rules.get("result"), ensure_ascii=False, indent=1), encoding="utf-8")
    print("已备份现有 %d 条规则 → state/gateway_rules.bak.json" % len(rules.get("result") or []))

    ids = []
    for p in plan:
        body = {"name": p["name"], "type": "DOMAIN",
                "description": "NoAS 小档（%d 条）sha:%s" % (p["count"], p["sha"]),
                "items": [{"value": d} for d in p["chunk"]]}
        if p["id"]:
            res, err = call("PUT", "/gateway/lists/%s" % p["id"], body)
        else:
            res, err = call("POST", "/gateway/lists", body)
        if err:
            print("写列表 %s 失败：%s %s" % (p["name"], err, res))
            return 1
        lid = (res.get("result") or {}).get("id") or p["id"]
        ids.append(lid)
        print("  %s → %s" % (p["name"], lid))

    traffic = " or ".join("any(dns.domains[*] in $%s)" % i for i in ids)
    print("规则表达式长度 %d 字符，引用 %d 个列表" % (len(traffic), len(ids)))
    # override 动作必须原样带回 rule_settings（override_ips），否则 400（错误码 2049）
    body = {k: rule.get(k) for k in ("name", "description", "precedence", "enabled",
                                     "action", "filters", "rule_settings")}
    body["traffic"] = traffic
    res, err = call("PUT", "/gateway/rules/%s" % rule["id"], body)
    if err:
        print("更新规则失败：%s %s" % (err, res))
        return 1
    print("规则已更新，引用新分片")

    for n in old:
        if exist[n].get("id") and exist[n]["id"] not in ids:
            res, err = call("DELETE", "/gateway/lists/%s" % exist[n]["id"])
            print("  清理旧列表 %s：%s" % (n, err or "ok"))

    print("完成。请跑 tools/gateway_align.py 回读校验（小档应为 缺 0 / 多余 0）")
    return 0


if __name__ == "__main__":
    sys.exit(main())
