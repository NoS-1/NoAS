#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""reputation.py —— 域名信誉评分：用多信号合计算出"这个域有多像广告"。

为什么需要它：原来的晋级只看"几个源命中"，太单薄。单一信号容易误判（一个源手抖就把
正常域推进 lite），也容易漏判（一个独有的首方广告子域永远没人给它投票）。
评分把多个互相独立的信号加起来，只有**多个方向同时指向广告**的域才拿高分。

评分维度（各维度互相独立，权重写在 WEIGHTS）：
  · 共识源数：几个独立清单同时收录（tags.tsv 的标签数 + 源数近似）
  · 父域声誉：注册域本身就是广告网络 → 强加分；注册域在良性大盘 → 直接清零
  · 词元结构：子域首标签是 ad/ads/splash/gromore… → 加分
  · 父子关系：挂在已知品牌域下的"广告子域"（首方伪装）→ 加分
  · 分类归属：SDK / 贴片 / 遥测 / 挖矿 → 强加分
  · 机器生成特征：超长随机子域、数字占比高 → 弱加分
  · 白名单冲突：命中 whitelist / service_allow / 黄金集 → 直接清零（一票否决）

产出：
  lists/reputation.tsv   —— domain <TAB> score <TAB> tier <TAB> 理由
  out/reputation.json    —— 全量统计与分布，供 guard / 站点展示

档位建议（给 compile 参考，不强制）：
  score >= 70 → lite 可用（高置信，手机默认档）
  40..69      → mid 可用
  < 40        → 只留在 full / 观察池
"""
import json
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LISTS = os.path.join(ROOT, "lists")
OUT = os.path.join(ROOT, "out")

WEIGHTS = {
    # 实测已在 lite 里 = 已经被"3 源共识 + 端点 + 核心网"这一套验证过，是最硬的证据
    "in_lite": 45,
    "consensus_strong": 25,   # 共识分 >= 4 的额外加权
    "consensus_mid": 12,      # 共识分 2~4
    "parent_ad": 20,          # 注册域是广告网络
    "token": 15,              # 子域词元就是广告
    "firstparty": 10,         # 品牌域下的广告子域
    "category": 25,           # SDK / 贴片 / 遥测 / 挖矿
    "random": 8,              # 机器生成子域
    "probe_ad": 12,           # 探针抓到广告指纹（可选输入）
}

AD_LABELS = {"ad", "ads", "adserver", "adservice", "advert", "advertising", "adclick",
             "adtech", "adx", "banner", "click", "clicks", "track", "tracker", "tracking",
             "beacon", "pixel", "impression", "promo", "sponsor", "sponsored", "splash",
             "gromore", "prebid", "adnxs", "dsp", "ssp", "adview", "admaster"}
SLD_GENERIC = {"com", "net", "org", "cn", "co", "gov", "edu", "io", "me", "tv", "cc"}


def read_first_col(path):
    out = set()
    if not os.path.exists(path):
        return out
    for line in open(path, encoding="utf-8"):
        x = line.split("#", 1)[0].split("\t")[0].strip().lower()
        if x and "." in x:
            out.add(x)
    return out


def read_domains_plain(path):
    out = set()
    if not os.path.exists(path):
        return out
    for line in open(path, encoding="utf-8"):
        x = line.split("#", 1)[0].strip().lower()
        if x and "." in x:
            out.add(x)
    return out


def registrable(d):
    p = [x for x in d.split(".") if x]
    if len(p) < 2:
        return d
    if len(p) >= 3 and p[-1] in ("cn", "uk", "jp", "kr", "au", "br", "in", "ru", "de", "fr") \
            and p[-2] in ("com", "co", "net", "org", "gov", "edu", "ac"):
        return ".".join(p[-3:])
    return ".".join(p[-2:])


RANDOM_RE = re.compile(r"[a-z0-9]{12,}|^[0-9]{4,}$")


def load_tags():
    """tags.tsv → {domain: set(标签)}"""
    out = {}
    p = os.path.join(LISTS, "tags.tsv")
    if not os.path.exists(p):
        return out
    for line in open(p, encoding="utf-8"):
        if line.startswith("#") or not line.strip():
            continue
        cols = line.rstrip("\n").split("\t")
        if len(cols) < 2 or "." not in cols[0]:
            continue
        tags = {t for t in cols[1].split(",") if t}
        # consensus 这个标签名不代表"多源"，用票数近似时要排除它本身
        out[cols[0].lower()] = tags
    return out


def main():
    cat = {}
    for name, key in (("sdk_ads.txt", "sdk"), ("video_ads.txt", "video"),
                      ("telemetry.txt", "telemetry"), ("miner.txt", "miner"),
                      ("affiliate.txt", "affiliate")):
        cat[key] = read_first_col(os.path.join(LISTS, name))

    ad_parents = (read_first_col(os.path.join(LISTS, "core_ad_networks.txt"))
                  | read_first_col(os.path.join(LISTS, "ad_endpoints.txt"))
                  | read_domains_plain(os.path.join(LISTS, "promoted.txt")))
    benign = (read_domains_plain(os.path.join(LISTS, "benign_top.txt"))
              | read_domains_plain(os.path.join(LISTS, "popular_roots.txt"))
              | read_first_col(os.path.join(LISTS, "whitelist.txt"))
              | read_first_col(os.path.join(LISTS, "service_allow.txt"))
              | read_domains_plain(os.path.join(ROOT, "tests", "golden_set.txt")))
    benign_reg = {registrable(d) for d in benign}
    ad_reg = {registrable(d) for d in ad_parents}

    tags = load_tags()

    # 复用编译阶段已经算好的两件事：谁被选进 lite、每条域的跨源共识分。
    # 这样评分与编译口径一致，不会出现"评分说 70 分但编译没要它"的脱节。
    lite_now = read_domains_plain(os.path.join(ROOT, "subs", "lite", "domains.txt"))
    prov = {}
    lp = os.path.join(ROOT, "out", "lite_provenance.json")
    if os.path.exists(lp):
        try:
            prov = {k: float(v) for k, v in json.load(open(lp, encoding="utf-8"))["lite"].items()}
        except Exception:
            prov = {}

    # 评分对象：所有出现在台账 / 分类表 / 晋级表 / 观察池里的域
    targets = set(tags)
    for s in cat.values():
        targets |= s
    targets |= read_domains_plain(os.path.join(LISTS, "promoted.txt"))
    targets |= read_first_col(os.path.join(LISTS, "cn_ad_watch.txt"))
    targets |= read_first_col(os.path.join(LISTS, "cn_ad_endpoints.txt"))
    targets |= lite_now
    targets = {d for d in targets if "." in d}

    rows = []
    dist = {"ge70": 0, "40_69": 0, "lt40": 0}
    vetoed = 0
    for d in sorted(targets):
        reg = registrable(d)
        parts = d.split(".")
        head = parts[0] if len(parts) > 1 else ""
        reasons = []
        score = 0

        # 一票否决：任何白名单/黄金集/良性大盘命中，直接清零，不给翻盘机会
        if d in benign or reg in benign_reg:
            vetoed += 1
            rows.append((d, 0, "none", "白名单/良性/黄金集一票否决"))
            continue

        if d in lite_now:
            score += WEIGHTS["in_lite"]
            reasons.append("已在lite")

        cons = prov.get(d, 0)
        if cons >= 4.0:
            score += WEIGHTS["consensus_strong"]
            reasons.append("共识%.1f" % cons)
        elif cons >= 2.0:
            score += WEIGHTS["consensus_mid"]
            reasons.append("共识%.1f" % cons)

        n_consensus = len(tags.get(d, set()) - {"consensus"})
        if n_consensus >= 2:
            score += 8
            reasons.append("标签%d类" % n_consensus)

        if reg in ad_reg or d in ad_parents:
            score += WEIGHTS["parent_ad"]
            reasons.append("父域为广告网络")

        if head in AD_LABELS:
            score += WEIGHTS["token"]
            reasons.append("词元=%s" % head)

        # 首方伪装：挂在良性品牌域下，但子域是广告词元
        if reg in benign_reg and head in AD_LABELS:
            score += WEIGHTS["firstparty"]
            reasons.append("品牌域下广告子域")

        for key, s in cat.items():
            if d in s:
                score += WEIGHTS["category"]
                reasons.append("分类=%s" % key)
                break

        if RANDOM_RE.search(head) or (head.isdigit() and len(head) >= 3):
            score += WEIGHTS["random"]
            reasons.append("机器生成子域")

        score = min(score, 100)
        tier = "lite" if score >= 70 else ("mid" if score >= 40 else "full")
        if score >= 70:
            dist["ge70"] += 1
        elif score >= 40:
            dist["40_69"] += 1
        else:
            dist["lt40"] += 1
        rows.append((d, score, tier, "; ".join(reasons) or "无信号"))

    os.makedirs(OUT, exist_ok=True)
    with open(os.path.join(LISTS, "reputation.tsv"), "w", encoding="utf-8") as f:
        f.write("# NoAS 域名信誉评分：域名 <TAB> 分数 <TAB> 建议档位 <TAB> 理由\n")
        f.write("# 由 tools/reputation.py 生成，勿手改；score>=70 才够进 lite（手机默认档）\n")
        for d, sc, tier, why in rows:
            f.write("%s\t%d\t%s\t%s\n" % (d, sc, tier, why))

    stats = {"generated": __import__("time").strftime("%Y-%m-%d %H:%M"),
             "total": len(rows), "vetoed": vetoed, "dist": dist,
             "weights": WEIGHTS}
    json.dump(stats, open(os.path.join(OUT, "reputation.json"), "w", encoding="utf-8"),
              ensure_ascii=False, indent=1)
    print("信誉评分：共 %d 条｜一票否决 %d｜≥70 分 %d｜40-69 %d｜<40 %d"
          % (len(rows), vetoed, dist["ge70"], dist["40_69"], dist["lt40"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
