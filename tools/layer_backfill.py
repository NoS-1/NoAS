#!/usr/bin/env python3
"""layer_backfill.py —— 把 L2（路径层）/ L3（uBO）里"落到域名"的广告判定回灌到 L1（DNS 三档）。

为什么要回灌：
  路径层和 uBO 是「更准但覆盖更窄」的层 —— 它们知道 ad.maoyan.com/api/position/detail 是广告位，
  但只能在 MITM / 浏览器里生效。同一个域名在 DNS 层如果能直接拦掉，设备侧就不用 MITM、
  不用装浏览器插件，收益立刻放大一个数量级。反过来，DNS 层漏掉的域名，只要 L2/L3 已经验证过，
  就应该升级成 L1 规则 —— 这正是「融合」。

口径（宁可少灌，绝不误伤）：
  · L2：只取 host 本身带广告语义的（ad / ads / adx / track / splash / cpro / pos / gromore…）。
        像 www.meituan.com、app.bilibili.com、mbasecc.bas.cmbchina.com 这种「业务主机 + 广告接口路径」
        一律不进 —— DNS 拦主机等于把整个 App 打死。
  · L3：只取网络层规则 `||domain^`。元素规则 `site##selector` 是页内广告位，拦站点会误伤正文。
  · L4（GKD，已下线）：规则是界面选择器，DNS 层物理上执行不了。它的遗产是「哪些国内 App 有广告位」，
        这份清单用来做覆盖度审计（哪些 App 在 L1/L2 完全没有对应规则），不直接产生域名。
  · 白名单（whitelist / service_allow / 各档 allow）一票否决。
  · 过泛父域（单段或两段如 qq.com / baidu.com）不进，否则等于拦整片。

用法：
  python3 tools/layer_backfill.py            # 干跑，打印候选与拒绝原因
  python3 tools/layer_backfill.py --write    # 写 lists/layer_backfill.txt
"""
import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LISTS = ROOT / "lists"
SUBS = ROOT / "subs"
STATE = ROOT / "state"
OUT = LISTS / "layer_backfill.txt"

# host 标签命中这些词，才算「主机本身是广告端点」
AD_LABELS = {"ad", "ads", "adx", "adserver", "adservice", "adapi", "adlog", "adstat",
             "adsdk", "splash", "splashad", "gromore", "pangolin", "pangle", "openads",
             "mobads", "union", "track", "tracker", "stat", "stats", "analytics",
             "metrics", "beacon", "click", "cpro", "pos", "eclick", "cbjs", "advert",
             "advertise", "dynamicad", "dsp", "adex"}
# 这些标签出现在业务主机里也不该被当成广告端点（防误伤白名单式放行）
BUSINESS_HINT = {"api", "app", "www", "m", "wap", "client", "mall", "pay", "order", "user"}

DOMAIN_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.\-]{2,253}$")


def lines_of(p):
    if not p.exists():
        return []
    out = []
    for line in p.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.split("#", 1)[0].strip()
        if line:
            out.append(line)
    return out


def read_set(paths):
    s = set()
    for p in paths:
        for line in lines_of(p):
            d = line.lower().strip().lstrip("*.").rstrip("^")
            if DOMAIN_RE.match(d):
                s.add(d)
    return s


def host_is_ad(host):
    """主机名里是否有独立成段的广告语义标签"""
    parts = re.split(r"[.\-_]", host.lower())
    return any(p in AD_LABELS for p in parts)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--write", action="store_true")
    args = ap.parse_args()

    cands = {}   # domain -> [来源...]

    # ① L2 路径层：ad_paths.tsv 的 host 列 + 各档产物里的 MITM 主机
    tsv = LISTS / "ad_paths.tsv"
    for line in lines_of(tsv):
        cols = line.split("\t")
        if len(cols) < 4:
            continue
        host = cols[0].strip().lower()
        if not host or host == "*" or not DOMAIN_RE.match(host):
            continue
        app = cols[3].strip() if len(cols) > 3 else ""
        if not host_is_ad(host):
            continue
        cands.setdefault(host, []).append("L2:" + (app or "路径层"))

    # ② L3 uBO：只取网络层 ||domain^
    for p in sorted((SUBS / "paths" / "ubo").glob("*.txt")):
        for line in lines_of(p):
            m = re.match(r"^\|\|([A-Za-z0-9.\-]+)\^?$", line)
            if m:
                d = m.group(1).lower()
                if DOMAIN_RE.match(d):
                    cands.setdefault(d, []).append("L3:ubo")

    # ③ L4 遗产：只做覆盖度审计（界面选择器没有域名可抽）
    l4_apps = read_set([LISTS / "l4_apps_legacy.txt"])
    l4_note = {"apps": len(l4_apps), "domain_rules": 0,
               "why": "GKD 规则是 UI 选择器（text/id/vid 匹配），不含域名；"
                      "它的价值用 L2 同 App 的广告主机来回灌，而不是直接产生解析规则"}

    white = read_set([LISTS / "whitelist.txt", LISTS / "service_allow.txt",
                      SUBS / "lite" / "allow.txt", SUBS / "mid" / "allow.txt",
                      SUBS / "full" / "allow.txt"])
    benign = read_set([LISTS / "benign_top.txt", LISTS / "popular_roots.txt"])
    dead = read_set([LISTS / "dead.txt"])   # 解析不出地址的域：拦了也没流量，不进 L1
    tiers = {t: read_set([SUBS / t / "domains.txt"]) for t in ("lite", "mid", "full")}

    keep, already, rejected, endpoint_exc = {}, [], {}, {}
    for d, srcs in sorted(cands.items()):
        labels = d.split(".")
        root = ".".join(labels[-2:])
        # 精确命中白名单（域名本身在放行清单）才否决
        if d in white:
            rejected[d] = "精确命中白名单"
            continue
        # 良性/热门根域只在「规则本身就是那个根域」时否决，不连累子域:
        # gdt.qq.com 是腾讯广告、cpro.baidu.com 是百度联盟，qq.com 热门 ≠ 子域不能拦
        if len(labels) <= 2 and (root in benign or root in white):
            rejected[d] = "过泛根域（良性/热门）"
            continue
        if d in dead:
            rejected[d] = "死域（dead.txt）"
            continue
        if d in tiers["full"]:
            already.append(d)
            continue
        keep[d] = srcs
        for i in range(1, len(labels) - 1):
            parent = ".".join(labels[i:])
            if parent in white:
                endpoint_exc[d] = parent + " 在白名单，按端点例外处理（ep 身份免疫白名单）"
                break

    print("候选 %d ｜已在 full %d ｜待回灌 %d ｜拒绝 %d"
          % (len(cands), len(already), len(keep), len(rejected)))
    for d, srcs in sorted(keep.items()):
        print("  + %-38s %s" % (d, ",".join(sorted(set(srcs)))))
    for d, why in sorted(rejected.items()):
        print("  - %-38s %s" % (d, why))

    if args.write:
        # 回灌表是「持久登记」而不是「本轮新增」：某条域一旦以端点例外身份进过 L1，
        # 就必须一直留在表里 —— 否则下一轮编译它会被白名单父域（如 amap.com）再剔一次。
        # 登记集 = 所有通过校验的候选（含本轮已在 full 的）∪ 旧表 —— 不能只登记"新增"，
        # 否则一旦某轮新增为空，表就被写成空，下一轮白名单父域又把它剔掉。
        registered = set(keep) | set(already)
        if OUT.exists():
            for line in lines_of(OUT):
                d = line.lower()
                if DOMAIN_RE.match(d) and d not in dead:
                    registered.add(d)
        keep_report = sorted(keep)
        for d in sorted(registered):
            keep.setdefault(d, ["登记在案"])
        OUT.write_text(
            "# NoAS 跨层回灌（L2 路径层 / L3 uBO → L1 DNS）\n"
            "# 自动生成，勿手改：改规则请动 lists/ad_paths.tsv 与 subs/paths/ubo/*.txt，"
            "再跑 tools/layer_backfill.py --write\n"
            "# 只收「主机本身就是广告端点」的域名；业务主机 + 广告路径一律不进（DNS 拦整站会误伤）\n"
            + "\n".join(sorted(registered)) + "\n", encoding="utf-8")
        STATE.mkdir(exist_ok=True)
        (STATE / "layer_backfill.json").write_text(json.dumps({
            "candidates": len(cands), "added": keep_report, "registered": sorted(registered),
            "already_in_full": sorted(already),
            "rejected": rejected, "endpoint_exceptions": endpoint_exc, "l4": l4_note,
            "sources": {d: sorted(set(s)) for d, s in keep.items()},
        }, ensure_ascii=False, indent=1), encoding="utf-8")
        print("已写入 %s 与 state/layer_backfill.json" % OUT.relative_to(ROOT))
    else:
        print("干跑结束（加 --write 才落文件）")
    return 0


if __name__ == "__main__":
    sys.exit(main())
