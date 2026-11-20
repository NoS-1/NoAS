#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""guard.py —— 发布前的硬校验与自愈护栏。

订阅发错一次，用户正常网站就打不开，而且他很难定位原因。所以这里只查"能直接判死"的项：
  1. 七个格式条数必须一致（渲染路径漏一条就判红）
  2. 任何一条都不得命中白名单（含父域保护）
  3. 不许有重复条目 / 非法字符
  4. meta 里的 sha256 必须与真实文件一致
  5. 抽查：已知广告域必须拦，已知正常域必须放行
  6. 规模突变护栏：比上一轮少 15% 以上 → 判红（多半是上游集体失效，宁可停发也不发残包）
"""
import hashlib
import json
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SUBS = os.path.join(ROOT, "subs")
TIERS = ("lite", "mid", "full")
# 与 compile.py 的 LITE_CAP 对齐：lite 处于硬上限内时，规模回落属于策略性截断，不判骤降
LITE_CAP = 10000
FILES = ["adguard.txt", "domains.txt", "hosts.txt", "dnsmasq.conf",
         "clash.yaml", "surge.list", "singbox.json", "qx.list",
         "rpz.zone", "wildcard.txt", "unbound.conf"]

MUST_BLOCK_LITE = ["doubleclick.net", "googlesyndication.com", "applovin.com"]
MUST_NOT_BLOCK = ["www.baidu.com", "github.com", "www.bilibili.com", "api.weixin.qq.com",
                  "www.taobao.com", "mp.weixin.qq.com", "www.zhihu.com"]


def check_precision():
    """误伤审计必须为 0：任何一档踩到良性大盘都判红。"""
    import subprocess
    rc = subprocess.run([sys.executable, os.path.join(ROOT, "tools", "precision.py")],
                        capture_output=True, text=True)
    if rc.returncode != 0:
        print(rc.stdout.strip()[-400:])
        return ["误伤审计未通过（存在踩良性大盘的条目）"]
    return []


def check_ledger():
    """白名单台账与镜像必须一致，且不得与"强制入 lite"的广告网根域自相矛盾。"""
    import subprocess
    rc = subprocess.run([sys.executable, os.path.join(ROOT, "tools", "whitelist.py"), "check"],
                        capture_output=True, text=True)
    if rc.returncode != 0:
        print(rc.stdout.strip())
        return ["白名单台账校验失败（镜像漂移或条目非法）"]
    allow = load_allow()

    def read_set(rel):
        out = set()
        p = os.path.join(ROOT, rel)
        if os.path.exists(p):
            for line in open(p, encoding="utf-8"):
                d = line.split("#", 1)[0].strip().lower()
                if d and "." in d:
                    out.add(d)
        return out

    endpoints = read_set("lists/ad_endpoints.txt")
    bad = []
    for d in read_set("lists/core_ad_networks.txt"):
        if d in endpoints:
            continue          # 审计过的广告端点：故意压过白名单，不算冲突
        if any(".".join(d.split(".")[i:]) in allow for i in range(len(d.split(".")) - 1)):
            bad.append(d)
    errs = ["核心广告域与白名单冲突：%s" % bad] if bad else []

    # 端点必须在 lite/mid/full 里真的生效（自身或其父域被拦即可）
    for d in sorted(endpoints):
        for tier in ("lite", "mid", "full"):
            sets = read_set(os.path.join("subs", tier, "domains.txt"))
            parts = d.split(".")
            if not any(".".join(parts[i:]) in sets for i in range(len(parts) - 1)):
                errs.append("广告端点 %s 在 %s 档未生效" % (d, tier))
    return errs


def load_allow():
    allow = set()
    for rel in ("tests/benign_baseline.txt", "lists/whitelist.txt"):
        p = os.path.join(ROOT, rel)
        if os.path.exists(p):
            for line in open(p, encoding="utf-8"):
                line = line.split("#", 1)[0].strip().lower()
                if line and "." in line:
                    allow.add(line)
    return allow


def protected(d, allow):
    parts = d.split(".")
    return any(".".join(parts[i:]) in allow for i in range(len(parts) - 1))


def domains_of(tier, name):
    p = os.path.join(SUBS, tier, name)
    if not os.path.exists(p):
        return None
    text = open(p, encoding="utf-8").read()
    if name == "singbox.json":
        return json.loads(text)["rules"][0]["domain_suffix"]
    out = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line[0] in "#!" or line.startswith("payload:"):
            continue
        for pat in (r"^\|\|(.+?)\^$", r"^0\.0\.0\.0\s+(\S+)$",
                    r"^address=/(\S+)/0\.0\.0\.0$", r"^(?:- +)?DOMAIN-SUFFIX,(\S+)$", r"^host-suffix, (\S+), reject$",
                    r"^(\S+) CNAME \.$", r"^\*\.(\S+)$",
                    r'^local-zone: "(\S+)" always_nxdomain$'):
            m = re.match(pat, line)
            if m:
                line = m.group(1)
                break
        out.append(line.lower())
    return out



def read_first_col(rel):
    p = os.path.join(ROOT, "lists", rel)
    out = set()
    if not os.path.exists(p):
        return out
    for line in open(p, encoding="utf-8"):
        x = line.split("#", 1)[0].split("\t")[0].strip().lower()
        if x and "." in x and "/" not in x:
            out.add(x)
    return out


def check_cooldown():
    """冷却池里的域一律不许出现在任何档位（误伤复发防线）。"""
    fails = []
    cooldown = read_first_col("cooldown.txt")
    if not cooldown:
        return fails
    for tier in TIERS:
        base = domains_of(tier, "domains.txt") or set()
        hit = sorted(set(base) & cooldown)
        if hit:
            fails.append("%s：混入冷却池域 %d 条：%s" % (tier, len(hit), ", ".join(hit[:5])))
    return fails


def check_threat_isolation():
    """挖矿/联盟/遥测分类只许进 full，绝不许漏进 lite/mid。"""
    fails = []
    cats = read_first_col("miner.txt") | read_first_col("affiliate.txt") | read_first_col("telemetry.txt")
    if not cats:
        return fails
    for tier in ("lite", "mid"):
        base = domains_of(tier, "domains.txt") or set()
        hit = sorted(set(base) & cats)
        if hit:
            fails.append("%s：混入威胁分类域 %d 条：%s" % (tier, len(hit), ", ".join(hit[:5])))
    full = set(domains_of("full", "domains.txt") or [])
    missing = sorted(set(cats) - set(full))
    if missing:
        fails.append("full：分类域缺失 %d 条（应全部强制进 full）：%s"
                     % (len(missing), ", ".join(missing[:5])))
    return fails


def check_sdk_video():
    """SDK / 贴片域必须在 mid 里真实存在：写了却因良性剔除而消失，就是假规则。"""
    fails = []
    cats = read_first_col("sdk_ads.txt") | read_first_col("video_ads.txt")
    if not cats:
        return fails
    mid = set(domains_of("mid", "domains.txt") or [])
    def covered(d):
        # 精确命中，或其父域在档（drop_children 会用父域覆盖子域，拦截同样生效）
        if d in mid:
            return True
        parts = d.split(".")
        return any(".".join(parts[i:]) in mid for i in range(1, len(parts) - 1))
    missing = sorted(d for d in cats if not covered(d))
    if missing:
        fails.append("mid 缺少 SDK/贴片域 %d 条（规则写了不生效）：%s"
                     % (len(missing), ", ".join(missing[:6])))
    return fails


def check_tags():
    """标签台账必须与当前规则对齐：条数一致、每条标签非空、被标记的域确实在规则里。"""
    fails = []
    tp = os.path.join(ROOT, "lists", "tags.tsv")
    if not os.path.exists(tp):
        return ["缺少 tags.tsv（标签台账）"]
    rows = 0
    bad = []
    for line in open(tp, encoding="utf-8"):
        if line.startswith("#") or not line.strip():
            continue
        cols = line.rstrip("\n").split("\t")
        if len(cols) != 2 or not cols[1].strip():
            bad.append(line.strip()[:40])
            continue
        rows += 1
    if bad:
        fails.append("tags.tsv 有 %d 行格式不对：%s" % (len(bad), "; ".join(bad[:3])))
    full = set(domains_of("full", "domains.txt") or [])
    lite = set(domains_of("lite", "domains.txt") or [])
    tagged = {l.split("\t")[0].strip().lower() for l in open(tp, encoding="utf-8")
              if not l.startswith("#") and "\t" in l}
    orphan = sorted(d for d in tagged if d not in full and d not in lite
                    and d not in (domains_of("mid", "domains.txt") or set()))
    if orphan:
        fails.append("tags.tsv 有 %d 条域名不在任何档位：%s" % (len(orphan), ", ".join(orphan[:5])))
    if rows < 1000:
        fails.append("tags.tsv 条数过少 %d" % rows)
    return fails



def check_channel_artifacts():
    """通道产物硬校验：空清单、bootstrap 用域名（鸡生蛋）、参数重复、yaml 缺键，一律 fail。"""
    fails = []
    base = os.path.join(SUBS, "channels")
    if not os.path.isdir(base):
        return ["缺少 subs/channels（通道产物未生成）"]

    def read_lines(name):
        fp = os.path.join(base, name)
        if not os.path.exists(fp):
            fails.append("缺少 %s" % name)
            return []
        return [l.strip() for l in open(fp, encoding="utf-8")
                if l.strip() and not l.lstrip().startswith("#")]

    doh = read_lines("doh.txt")
    dot = read_lines("dot.txt")
    if len(doh) < 1:
        fails.append("doh.txt 为空（主通道必须至少 1 条）")
    if len(dot) < 1:
        fails.append("dot.txt 为空（DoT 备用必须至少 1 条）")
    for u in doh:
        if not u.startswith("https://"):
            fails.append("doh.txt 非法条目：%s" % u)
    for d in dot:
        if not d.startswith("tls://"):
            fails.append("dot.txt 非法条目：%s" % d)

    sh = os.path.join(base, "aiodns.sh")
    if not os.path.exists(sh):
        fails.append("缺少 aiodns.sh")
    else:
        body = open(sh, encoding="utf-8").read()
        # bootstrap 必须是明文 IP：用域名会鸡生蛋，用 tls://IP 又可能证书不匹配
        boots = [l.split("--bootstrap")[1].split()[0]
                 for l in body.splitlines() if "--bootstrap" in l]
        for b in boots:
            if not re.match(r"^[0-9]{1,3}(\.(?:[0-9]{1,3})){3}", b.strip()):
                fails.append("aiodns.sh 的 --bootstrap 不是 IP：%s" % b.strip())
        if not boots:
            fails.append("aiodns.sh 缺少 --bootstrap（DoH/DoT 域名将无法解析）")
        # 参数不得重复（重复多半是模板拼接 bug）
        for flag in ("--upstream", "--special-upstream", "--fallback"):
            vals = [l.split(flag)[1].strip() for l in body.splitlines() if flag in l]
            for v in vals:
                if v.count("--upstream ") + v.count("--fallback ") + v.count("--bootstrap ") > 1:
                    fails.append("aiodns.sh 的 %s 一行写了多个值：%s" % (flag, v[:50]))
        if "--special-list" not in body:
            fails.append("aiodns.sh 缺少 --special-list（国内分流会失效）")

    sp = os.path.join(base, "aiodns.special.txt")
    if not os.path.exists(sp):
        fails.append("缺少 aiodns.special.txt")
    else:
        n = len([l for l in open(sp, encoding="utf-8")
                 if l.strip() and not l.lstrip().startswith("#")])
        if n < 50:
            fails.append("aiodns.special.txt 只有 %d 条国内域（应 >=50）" % n)

    yml = os.path.join(base, "adguardhome-upstream.yaml")
    if not os.path.exists(yml):
        fails.append("缺少 adguardhome-upstream.yaml")
    else:
        y = open(yml, encoding="utf-8").read()
        for key in ("upstream_dns:", "bootstrap_dns:"):
            if key not in y:
                fails.append("adguardhome-upstream.yaml 缺少 %s" % key)
        # 防止模板拼接出重复行
        ups = [l.strip() for l in y.splitlines() if l.strip().startswith("- http")]
        if len(ups) != len(set(ups)):
            fails.append("adguardhome-upstream.yaml 有重复上游条目")

    h = os.path.join(base, "health.json")
    if not os.path.exists(h):
        fails.append("缺少 health.json")
    else:
        try:
            hd = json.load(open(h, encoding="utf-8"))
            if hd.get("env") not in ("clean", "suspect"):
                fails.append("health.json env 非法：%s" % hd.get("env"))
        except Exception as e:
            fails.append("health.json 解析失败：%s" % e)
    return fails



def _first_col(path):
    out = set()
    if not os.path.exists(path):
        return out
    for line in open(path, encoding="utf-8"):
        x = line.split("#", 1)[0]
        if not x.strip():
            continue
        d = x.split("\t")[0].strip().lower()
        if d and "." in d:
            out.add(d)
    return out


def check_golden():
    """黄金回归：正常站点在 lite 档必须全部放行。

    lite 是手机默认档，它误拦一条就是用户网站打不开，所以这里判红（不是警告）。
    mid/full 是高召回档，允许有误拦，只记录误拦率，供用户选档时参考。
    """
    fails = []
    p = os.path.join(ROOT, "tests", "golden_set.txt")
    if not os.path.exists(p):
        return ["缺少 tests/golden_set.txt（黄金回归集），无法证明零误拦"]
    golden = set()
    for line in open(p, encoding="utf-8"):
        x = line.split("#", 1)[0].strip().lower()
        if x and "." in x:
            golden.add(x)
    if len(golden) < 2000:
        fails.append("黄金集只有 %d 条，低于 2000 条的覆盖要求" % len(golden))
    report = {}
    for tier in TIERS:
        base = set(domains_of(tier, "domains.txt") or [])
        hit = sorted(golden & base)
        report[tier] = {"total": len(golden), "hit": len(hit),
                        "rate": round(100.0 * len(hit) / max(1, len(golden)), 2),
                        "samples": hit[:10]}
        if tier == "lite" and hit:
            fails.append("lite 误拦黄金集 %d 条（必须为 0）：%s" % (len(hit), ", ".join(hit[:8])))
    os.makedirs(os.path.join(ROOT, "history"), exist_ok=True)
    json.dump(report, open(os.path.join(ROOT, "history", "golden.json"), "w", encoding="utf-8"),
              ensure_ascii=False, indent=1)
    return fails


def check_service_allow():
    """基础服务白名单：第一列必须是域名，且三档都不许出现。

    这条一旦失效，用户会遇到"微信登不上/支付转不动/推送收不到"，比误拦广告严重得多。
    """
    fails = []
    p = os.path.join(ROOT, "lists", "service_allow.txt")
    if not os.path.exists(p):
        return fails
    svc = set()
    bad_rows = []
    for line in open(p, encoding="utf-8"):
        if line.startswith("#") or not line.strip():
            continue
        cols = line.rstrip("\n").split("\t")
        d = cols[0].strip().lower()
        if "." not in d or not re.match(r"^[a-z0-9.\-]+$", d):
            bad_rows.append(line.rstrip("\n")[:40])
            continue
        svc.add(d)
    if bad_rows:
        fails.append("service_allow.txt 首列不是域名 %d 行：%s" % (len(bad_rows), bad_rows[:3]))
    if not svc:
        return fails
    for tier in TIERS:
        base = set(domains_of(tier, "domains.txt") or [])
        hit = sorted(svc & base)
        if hit:
            fails.append("%s 混入基础服务域 %d 条（登录/支付会坏）：%s" % (tier, len(hit), ", ".join(hit[:5])))
    return fails


def check_reputation():
    """信誉评分台账：格式必须可解析，档位建议必须与 lite 实际一致。"""
    fails = []
    p = os.path.join(ROOT, "lists", "reputation.tsv")
    if not os.path.exists(p):
        return ["缺少 lists/reputation.tsv（信誉评分未生成）"]
    rows = {}
    bad = 0
    for line in open(p, encoding="utf-8"):
        if line.startswith("#") or not line.strip():
            continue
        cols = line.rstrip("\n").split("\t")
        if len(cols) < 3:
            bad += 1
            continue
        try:
            sc = int(cols[1])
        except Exception:
            bad += 1
            continue
        if not (0 <= sc <= 100) or cols[2] not in ("lite", "mid", "full", "none"):
            bad += 1
            continue
        rows[cols[0].lower()] = (sc, cols[2])
    if bad:
        fails.append("reputation.tsv 有 %d 行格式非法" % bad)
    if len(rows) < 1000:
        fails.append("信誉评分只覆盖 %d 条，样本过少" % len(rows))
    # 一致性：评分 >=70 应至少出现在某档（否则评分与编译脱节）
    lite = set(domains_of("lite", "domains.txt") or [])
    mid = set(domains_of("mid", "domains.txt") or [])
    hi = [d for d, (sc, t) in rows.items() if sc >= 70 and t == "lite"]
    orphan = [d for d in hi if d not in lite and d not in mid]
    if len(orphan) > len(hi) * 0.5:
        fails.append("高分域与产出脱节：%d/%d 条不在 lite/mid" % (len(orphan), len(hi)))
    return fails


def check_shadow():
    """影子期：观察池里还没满 14 天的域，绝不允许进 lite。

    这是"零误拦"的核心机制——新发现的低置信域必须先看够久才能进默认档。
    """
    fails = []
    wp = os.path.join(ROOT, "state", "watch_pool.json")
    watch = _first_col(os.path.join(ROOT, "lists", "cn_ad_watch.txt"))
    if not watch:
        return fails
    if not os.path.exists(wp):
        return ["有观察池但缺 state/watch_pool.json（影子计时器没跑过）"]
    try:
        pool = json.load(open(wp, encoding="utf-8"))
    except Exception:
        return ["state/watch_pool.json 无法解析"]
    lite = set(domains_of("lite", "domains.txt") or [])
    SHADOW_DAYS = 14
    too_young = []
    for d in watch:
        rec = pool.get(d) or {}
        fs = rec.get("first_seen", "")
        if not fs:
            too_young.append(d)
            continue
        try:
            import time as _t
            age = int((_t.mktime(_t.strptime(_t.strftime("%Y-%m-%d"), "%Y-%m-%d"))
                       - _t.mktime(_t.strptime(fs, "%Y-%m-%d"))) // 86400)
        except Exception:
            age = 0
        if age < SHADOW_DAYS:
            too_young.append(d)
    leaked = sorted(set(too_young) & lite)
    if leaked:
        fails.append("影子期内混入 lite %d 条：%s" % (len(leaked), ", ".join(leaked[:5])))
    return fails


def main():
    fails = (check_ledger() + check_precision() + check_cooldown() + check_threat_isolation()
             + check_tags() + check_channel_artifacts() + check_sdk_video()
             + check_golden() + check_service_allow() + check_reputation() + check_shadow())
    allow = load_allow()
    summary = {}

    for tier in TIERS:
        base = domains_of(tier, "domains.txt")
        if base is None:
            fails.append("%s：缺少 domains.txt" % tier)
            continue
        # adguard.txt 额外含 "||*.根域^" 通配行，条数应等于 domains + wildcards
        wc = 0
        try:
            wc = int(json.load(open(os.path.join(SUBS, tier, "meta.json"), encoding="utf-8")).get("wildcards", 0))
        except Exception:
            wc = 0
        counts = {}
        for f in FILES:
            d = domains_of(tier, f)
            if d is None:
                fails.append("%s：缺少 %s" % (tier, f))
                continue
            counts[f] = len(d)
            if len(d) != len(set(d)):
                fails.append("%s/%s 有重复 %d 条" % (tier, f, len(d) - len(set(d))))
            if f == "qx.list":
                # 通配与精确域可能重叠，去重后条数落在 [base, base+wc]
                if not (len(base) <= len(d) <= len(base) + wc):
                    fails.append("%s/%s 条数 %d，应为 %d~%d" % (tier, f, len(d), len(base), len(base) + wc))
                continue
            want = len(base) + (wc if f in ("adguard.txt", "rpz.zone") else 0)
            slack = 2 if f == "rpz.zone" else 0
            if not (want <= len(d) <= want + slack):
                fails.append("%s/%s 条数 %d，应为 %d" % (tier, f, len(d), want))
        if len(base) < 100:
            fails.append("%s：条数过少 %d" % (tier, len(base)))
        ep_all = set()
        epp = os.path.join(ROOT, "lists", "ad_endpoints.txt")
        if os.path.exists(epp):
            for line in open(epp, encoding="utf-8"):
                x = line.split("#", 1)[0].strip().lower()
                if x and "." in x:
                    ep_all.add(x)
        hit = sorted({d for d in set(base) if protected(d, allow) and d not in ep_all})
        if hit:
            fails.append("%s：混入白名单域 %d 条：%s" % (tier, len(hit), ", ".join(hit[:5])))
        bad = [d for d in set(base) if not re.match(r"^[a-z0-9][a-z0-9.\-]*$", d)]
        if bad:
            fails.append("%s：非法域名 %d 条：%s" % (tier, len(bad), ", ".join(bad[:5])))
        mp = os.path.join(SUBS, tier, "meta.json")
        if not os.path.exists(mp):
            fails.append("%s：缺少 meta.json" % tier)
        else:
            meta = json.load(open(mp, encoding="utf-8"))
            if meta.get("count") != len(base):
                fails.append("%s：meta.count=%s 与实际 %d 不符" % (tier, meta.get("count"), len(base)))
            for f in FILES:
                p = os.path.join(SUBS, tier, f)
                if not os.path.exists(p):
                    continue
                real = hashlib.sha256(open(p, "rb").read()).hexdigest()
                if meta.get("files", {}).get(f, {}).get("sha256") != real:
                    fails.append("%s/%s sha256 与 meta 不一致" % (tier, f))
                if os.path.getsize(p) > 40 * 1024 * 1024:
                    fails.append("%s/%s 超过 40MB" % (tier, f))
        summary[tier] = len(base)

    lite = set(domains_of("lite", "domains.txt") or [])
    for d in MUST_BLOCK_LITE:
        if d not in lite:
            fails.append("lite 缺已知广告域：%s" % d)
    for d in MUST_NOT_BLOCK:
        if d in lite:
            fails.append("lite 误收录正常域：%s" % d)

    # 规模突变护栏：与上一轮（history/scale.json）比较
    hist = os.path.join(ROOT, "history", "scale.json")
    prev = {}
    if os.path.exists(hist):
        try:
            prev = json.load(open(hist, encoding="utf-8"))
        except Exception:
            prev = {}
    for tier, n in summary.items():
        old = prev.get(tier)
        if old and n < old * 0.85 and not (tier == "lite" and n <= LITE_CAP):
            fails.append("%s 规模骤降：%d → %d（超过 15%%，疑似上游失效）" % (tier, old, n))
    os.makedirs(os.path.dirname(hist), exist_ok=True)
    json.dump(summary, open(hist, "w", encoding="utf-8"), ensure_ascii=False, indent=1)

    if fails:
        print("FAIL 发布校验 %d 项：" % len(fails))
        for f in fails:
            print("  · " + f)
        return 1
    print("PASS 发布校验：%s｜白名单无冲突｜七格式一致｜meta 校验通过" % summary)
    return 0


if __name__ == "__main__":
    sys.exit(main())
