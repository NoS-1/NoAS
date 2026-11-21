#!/usr/bin/env python3
"""Gateway 中/大档误拦剪枝：只删「命中本地白名单」的条目。

口径（保守，宁可少删）：
- 删除条件：域本身或根域出现在本地白名单（subs/*/allow.txt、lists/*allow*.txt）
  → 这些是确认正常的域，留在 Gateway 就是真误拦；
- 本地三档都没有、也不在白名单的条目（多为博彩/仿冒黑产历史资产）**保留**，
  它们拦得对，删掉只会降低防护，不算误拦清理。
默认干跑，--apply 才写回（PUT 整表替换）。
"""
import hashlib
import json
import os
import pathlib
import sys
import time
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parent.parent
STATE = ROOT / "state" / "gateway_prune.json"
FP = ROOT / "state" / "prune_fp.json"
SUFFIX2 = {"com.cn", "cn.com", "net.cn", "org.cn", "gov.cn", "edu.cn", "ac.cn",
           "com.hk", "com.tw", "co.uk", "co.jp", "com.au", "co.kr", "com.sg", "com.my"}


def reg(d):
    p = d.split(".")
    if len(p) >= 3 and ".".join(p[-2:]) in SUFFIX2:
        return ".".join(p[-3:])
    return ".".join(p[-2:]) if len(p) >= 2 else d


def norm(s):
    s = s.strip().lower()
    if s.startswith("@@"):
        s = s[2:]
    if s.startswith("||"):
        s = s[2:].split("^")[0]
    if s.startswith("*."):
        s = s[2:]
    return s.strip(".")


def load_local():
    doms = set()
    for f in ("lite", "mid", "full"):
        p = ROOT / "subs" / f / "domains.txt"
        if not p.exists():
            continue
        for line in p.read_text(encoding="utf-8", errors="ignore").splitlines():
            s = norm(line)
            if s and not s.startswith("#"):
                doms.add(s)
    allow = set()
    for p in list(ROOT.glob("subs/*/allow.txt")) + list(ROOT.glob("lists/*allow*.txt")):
        for line in p.read_text(encoding="utf-8", errors="ignore").splitlines():
            s = norm(line)
            if s and not s.startswith("#"):
                allow.add(s)
    roots = {reg(d) for d in doms}
    allow_roots = {reg(d) for d in allow}
    return doms, roots, allow, allow_roots


def load_creds():
    """凭据：环境变量优先，其次本地 600 文件（不存在就跳过，CI 只靠 Secrets）。"""
    env = {}
    p = pathlib.Path(os.environ.get("NOAS_CREDS", "/home/user/.noas/creds.env"))
    if p.exists():
        for line in p.read_text(encoding="utf-8").splitlines():
            if "=" in line and not line.strip().startswith("#"):
                k, v = line.split("=", 1)
                env[k.strip()] = v.strip()
    for k in ("CF_ACCOUNT_ID", "CF_API_TOKEN"):
        if os.environ.get(k):
            env[k] = os.environ[k]
    return env


def allow_fp():
    """白名单指纹：白名单不变就没必要每天翻 80 个分片（省 CF API 调用）。"""
    h = hashlib.sha256()
    for p in sorted(list(ROOT.glob("subs/*/allow.txt")) + list(ROOT.glob("lists/*allow*.txt"))):
        h.update(p.read_bytes())
    return h.hexdigest()[:16]


def main():
    apply = "--apply" in sys.argv
    fp_now = allow_fp()
    if apply and "--force" not in sys.argv:
        try:
            old = json.loads(FP.read_text(encoding="utf-8"))
        except Exception:
            old = {}
        if old.get("allow_fp") == fp_now:
            print("白名单未变（%s），跳过 Gateway 剪枝（--force 可强制）" % fp_now)
            return 0
    env = load_creds()
    if not env.get("CF_ACCOUNT_ID") or not env.get("CF_API_TOKEN"):
        print("缺少凭据：本地写 /home/user/.noas/creds.env，CI 配 CF_API_TOKEN / CF_ACCOUNT_ID secrets")
        return 2
    acct = env["CF_ACCOUNT_ID"]
    tok = env["CF_API_TOKEN"]
    base = "https://api.cloudflare.com/client/v4/accounts/%s" % acct

    def call(method, path, body=None):
        req = urllib.request.Request(
            base + path, method=method,
            data=json.dumps(body).encode() if body is not None else None,
            headers={"Authorization": "Bearer " + tok, "content-type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                return json.loads(r.read()), None
        except urllib.error.HTTPError as e:
            return {"raw": e.read().decode()[:300]}, e.code
        except Exception as e:
            return {}, str(e)[:120]

    doms, roots, allow, allow_roots = load_local()
    print("本地全集 %d 域 / 根域 %d；白名单 %d 域（只删与白名单冲突的条目）"
          % (len(doms), len(roots), len(allow)))

    lists, err = call("GET", "/gateway/lists")
    if err:
        print("拉列表失败：%s %s" % (err, lists))
        return 1
    by_name = {}
    for L in (lists.get("result") or []):
        n = L.get("name", "")
        by_name[n] = L

    out = {"local_domains": len(doms), "local_roots": len(roots), "tiers": {}, "applied": apply}
    rc = 0
    for tier, prefix in (("t2", "noas_l2_"), ("t3", "noas_l3_")):
        total = keep = pruned = orphan = 0
        pieces = sorted([n for n in by_name if n.startswith(prefix)],
                        key=lambda x: int(x.split("_")[-1]) if x.split("_")[-1].isdigit() else 0)
        for n in pieces:
            L = by_name[n]
            res, err = call("GET", "/gateway/lists/%s/items?limit=1000" % L["id"])
            if err:
                print("%s 读取失败 %s，跳过" % (n, err))
                rc = 1
                continue
            items = res.get("result") or []
            vals = [(i.get("value", "").lower().strip("."), i.get("type") or "DOMAIN") for i in items]
            # 只删「命中白名单」= 确认正常的域被拦，这是真误拦；
            # 本地三档没有的条目（多为博彩/仿冒黑产历史资产）保留，不删。
            pr = [(v, t) for v, t in vals if v in allow or reg(v) in allow_roots]
            orphan += sum(1 for v, t in vals if not (v in doms or reg(v) in roots))
            total += len(vals)
            keep += len(vals) - len(pr)
            pruned += len(pr)
            if pr and not apply:
                print("  冲突样本 %s：%s" % (n, ", ".join(v for v, _ in pr[:6])))
            if pr and apply:
                body = {"name": L["name"], "type": L.get("type", "DOMAIN"),
                        "description": L.get("description", "NoAS"),
                        "items": [{"value": v, "type": t} for v, t in vals if (v, t) not in pr]}
                r2, e2 = call("PUT", "/gateway/lists/%s" % L["id"], body)
                if e2:
                    print("%s 写回失败 %s %s" % (n, e2, r2))
                    rc = 1
                else:
                    print("%s 剪掉 %d 条" % (n, len(pr)))
        out["tiers"][tier] = {"pieces": len(pieces), "total": total, "keep": keep,
                              "pruned": pruned, "orphan_kept": orphan}
        print("%s：%d 片 / %d 条 / 白名单冲突 %d / 本地无(保留) %d / 保留 %d"
              % (tier, len(pieces), total, pruned, orphan, keep))

    STATE.parent.mkdir(parents=True, exist_ok=True)
    STATE.write_text(json.dumps(out, ensure_ascii=False, indent=1), encoding="utf-8")
    if apply and rc == 0:
        FP.write_text(json.dumps({"allow_fp": fp_now, "applied": True,
                                  "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())},
                                 ensure_ascii=False, indent=1), encoding="utf-8")
    if not apply:
        print("干跑完成（未写回）。加 --apply 才真正删。")
    return rc


if __name__ == "__main__":
    sys.exit(main())
