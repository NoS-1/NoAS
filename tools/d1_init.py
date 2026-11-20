#!/usr/bin/env python3
"""D1 初始化与构建状态同步（幂等、可反复跑）。

设计约束（免费额度按"行读取"计费，这是硬边界）：
1) 只执行 DDL + 写极少行，绝不把规则正文、查询日志灌进 D1；
2) 额度耗尽（错误码 7500）时静默跳过并 exit 0——D1 是可选的加速层，
   它挂了不能让每日构建跟着红；
3) 没配 secret 时同样 exit 0，本地跑也不会炸。

环境变量：CF_API_TOKEN / CF_ACCOUNT_ID / D1_DATABASE_ID
"""
import json, os, sys, urllib.request, urllib.error

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TOK = os.environ.get("CF_API_TOKEN", "").strip()
ACC = os.environ.get("CF_ACCOUNT_ID", "226431c8f431ebb75d82dd5dbd5e8d86").strip()
DB = os.environ.get("D1_DATABASE_ID", "6f7f3f3f-4ac3-4b28-8ca3-343811a92973").strip()


def query(sql):
    url = "https://api.cloudflare.com/client/v4/accounts/%s/d1/database/%s/query" % (ACC, DB)
    req = urllib.request.Request(
        url,
        data=json.dumps({"sql": sql}).encode("utf-8"),
        headers={"Authorization": "Bearer " + TOK, "Content-Type": "application/json"},
        method="POST",
    )
    try:
        body = json.loads(urllib.request.urlopen(req, timeout=45).read())
    except urllib.error.HTTPError as e:
        body = json.loads(e.read().decode("utf-8", "ignore") or "{}")
    except Exception as e:
        return None, "网络失败: %s" % e
    if not body.get("success"):
        errs = body.get("errors") or [{}]
        code = errs[0].get("code")
        msg = errs[0].get("message", "unknown")
        if code == 7500 or "row read limit" in str(msg).lower():
            return None, "D1 行读额度已用尽（7500），跳过"
        return None, "D1 错误 %s: %s" % (code, msg)
    return body.get("result") or [], None


def main():
    if not (TOK and ACC and DB):
        print("D1 跳过：未配置 CF_API_TOKEN / CF_ACCOUNT_ID / D1_DATABASE_ID")
        return 0

    schema = open(os.path.join(ROOT, "cloudflare", "schema.sql"), encoding="utf-8").read()
    _, err = query(schema)
    if err:
        print("D1 建表：%s" % err)
        return 0

    # 写构建状态：每次构建只更新一行
    meta = json.load(open(os.path.join(ROOT, "subs", "lite", "meta.json"), encoding="utf-8"))
    comp = json.load(open(os.path.join(ROOT, "out", "compile.json"), encoding="utf-8"))
    ver = str(meta.get("version", ""))
    built = str(meta.get("generated_utc", ""))
    lite = int(comp.get("lite") or 0)
    mid = int(comp.get("mid") or 0)
    full = int(comp.get("full") or 0)
    wild = int(comp.get("wildcards") or 0)
    sha = (meta.get("files", {}).get("adguard.txt") or {}).get("sha256", "")
    sql = (
        "INSERT OR REPLACE INTO build_state "
        "(id,version,built_at,lite_count,mid_count,full_count,wildcards,sha_lite,note) "
        "VALUES (1,'%s','%s',%d,%d,%d,%d,'%s','auto')"
        % (ver, built, lite, mid, full, wild, sha)
    )
    _, err = query(sql)
    if err:
        print("D1 写状态：%s" % err)
        return 0
    print("D1 就绪：build_state = %s ｜ lite %d / mid %d / full %d ／通配 %d" % (ver, lite, mid, full, wild))
    return 0


if __name__ == "__main__":
    sys.exit(main())
