#!/usr/bin/env python3
"""Gateway 三档全量对齐：lite 1 万 / mid 2 万 / full 3 万全部铺进 Gateway 云列表。

定档后三档合计 6 万条 → 60 片 × 1000，免费上限 100 片，绰绰有余；
这意味 Gateway 通道（P50 88ms，最快的那条）能独立覆盖全档，
不再依赖 Worker 中转，也不用吃 Worker 的额度。

分批：t1=lite、t2=mid、t3=full，分片名 noas_l1_/noas_l2_/noas_l3_。
旧分片（noas_t1_/noas_t2_/noas_t3_ 与超量的 noas_l1_）在规则切换成功后清理。

用法：
  python3 tools/gateway_all.py            # 干跑，只打印计划
  python3 tools/gateway_all.py --apply    # 写入线上（先备份规则）
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
BASE = "https://api.cloudflare.com/client/v4/accounts/" + ACC

TIERS = [("lite", "t1", "NoAS 小档拦截", "小档"),
         ("mid", "t2", "NoAS 中档拦截", "中档"),
         ("full", "t3", "NoAS 大档拦截", "大档")]

# ☠️ 死循环保护：单片 1000，三档最多 60 片，留 40 片余量
MAX_LISTS = 100


def call(method, path, body=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(BASE + path, method=method, data=data,
                                 headers={"Authorization": "Bearer " + TOK,
                                          "Content-Type": "application/json"})
    try:
        return json.load(urllib.request.urlopen(req, timeout=60)), None
    except urllib.error.HTTPError as e:
        return e.read()[:300].decode("utf-8", "ignore"), "HTTP %d" % e.code
    except Exception as e:
        return {}, str(e)


def read_domains(tier):
    p = ROOT / "subs" / tier / "domains.txt"
    out = set()
    for line in p.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.split("#", 1)[0].strip().lower()
        if not line or line.startswith("!"):
            continue
        if line.startswith("||"):
            line = line[2:].rstrip("^")
        if line.startswith("0.0.0.0 "):
            line = line.split()[-1]
        if "." in line and "/" not in line and "*" not in line:
            out.add(line)
    return sorted(out)


def sha(text):
    return hashlib.sha256(text.encode()).hexdigest()[:12]


def main():
    apply = "--apply" in sys.argv
    if not TOK:
        print("跳过：未配置 CF_API_TOKEN")
        return 0

    lists, err = call("GET", "/gateway/lists?per_page=100")
    if err:
        print("读列表失败：%s" % err)
        return 1
    exist = {x["name"]: x for x in (lists.get("result") or [])}
    rules, err = call("GET", "/gateway/rules")
    if err:
        print("读规则失败：%s" % err)
        return 1
    all_rules = rules.get("result") or []

    plans = []
    total_shards = 0
    for tier, tag, rule_name, label in TIERS:
        doms = read_domains(tier)
        shards = [doms[i:i + SHARD] for i in range(0, len(doms), SHARD)]
        total_shards += len(shards)
        old = sorted(n for n in exist if n.startswith("noas_l%s_" % tag[1]))
        rule = next((r for r in all_rules if r.get("name") == rule_name), None)
        if not rule:
            print("⚠️ 找不到规则「%s」，该档跳过" % rule_name)
            continue
        plan = []
        for idx, chunk in enumerate(shards, 1):
            text = "\n".join(chunk)
            sv = sha(text)
            # 分片名必须是确定性的：按字典序复用旧名会把 l1_1/l1_10/l1_2 错位，
            # 导致第 1、2 片从没被写入却被清理掉（实测掉 2000 条）。
            name = "noas_l%s_%d" % (tag[1], idx)
            cur = exist.get(name)
            stale = not (cur and sv in (cur.get("description") or ""))
            plan.append({"name": name, "id": (cur or {}).get("id"), "sha": sv,
                         "count": len(chunk), "stale": stale, "chunk": chunk})
        plans.append({"tier": tier, "tag": tag, "rule": rule, "plan": plan,
                      "keep": {p["name"] for p in plan}})
        print("%s %d 条 → %d 片（需更新 %d）｜规则「%s」当前引用 %d 列表"
              % (label, len(doms), len(shards), sum(p["stale"] for p in plan),
                 rule_name, len([t for t in (rule.get("traffic") or "").split("$")[1:]])))

    if total_shards > MAX_LISTS - 5:
        print("分片总数 %d 超上限，拒绝执行" % total_shards)
        return 1

    if not apply:
        print("干跑结束（合计 %d 片）。加 --apply 才写线上。" % total_shards)
        return 0

    (ROOT / "state" / "gateway_rules.bak.json").write_text(
        json.dumps(all_rules, ensure_ascii=False, indent=1), encoding="utf-8")
    print("已备份 %d 条规则" % len(all_rules))

    deleted = set()
    for item in plans:
        ids = []
        for p in item["plan"]:
            # 幂等跳过：sha 一致且 id 在，就不重复上传（稳态下 6.88 从 20s 降到 1s 级）
            if p["id"] and not p["stale"]:
                ids.append(p["id"])
                continue
            body = {"name": p["name"], "type": "DOMAIN",
                    "description": "NoAS %s（%d 条）sha:%s"
                                   % (next(l for t, _, _, l in TIERS if t == item["tier"]),
                                      p["count"], p["sha"]),
                    "items": [{"value": d} for d in p["chunk"]]}
            if p["id"]:
                res, err = call("PUT", "/gateway/lists/%s" % p["id"], body)
            else:
                res, err = call("POST", "/gateway/lists", body)
            if err:
                print("写 %s 失败：%s %s" % (p["name"], err, res))
                return 1
            lid = (res.get("result") or {}).get("id") or p["id"]
            ids.append(lid)
        traffic = " or ".join("any(dns.domains[*] in $%s)" % i for i in ids)
        rule = item["rule"]
        if (rule.get("traffic") or "").strip() == traffic.strip() and not any(
                p["stale"] for p in item["plan"]):
            print("规则「%s」引用未变，跳过" % rule["name"])
            continue
        body = {k: rule.get(k) for k in ("name", "description", "precedence", "enabled",
                                         "action", "filters", "rule_settings")}
        body["traffic"] = traffic
        res, err = call("PUT", "/gateway/rules/%s" % rule["id"], body)
        if err:
            print("更新规则「%s」失败：%s %s" % (rule["name"], err, res))
            return 1
        print("规则「%s」→ %d 片，表达式 %d 字符" % (rule["name"], len(ids), len(traffic)))

    # 规则已全部切换成功，才清理旧分片
    for name, meta in exist.items():
        if not (name.startswith("noas_l1_") or name.startswith("noas_l2_")
                or name.startswith("noas_l3_") or name.startswith("noas_t1_")
                or name.startswith("noas_t2_") or name.startswith("noas_t3_")):
            continue
        if any(name in it["keep"] for it in plans):
            continue
        if meta.get("id") in deleted:
            continue
        res, err = call("DELETE", "/gateway/lists/%s" % meta["id"])
        print("  清理旧片 %s：%s" % (name, err or "ok"))
        deleted.add(meta["id"])

    print("完成。跑 tools/gateway_align.py 回读校验。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
