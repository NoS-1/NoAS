#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""compile.py —— 把各源归一成"可发布的拦截规则"。

流水线：
  1. 解析（hosts / adblock / 纯域名 / dnsmasq）→ 只留纯域名与通配后缀
  2. 归一：小写、去端口/路径、丢 IP、丢内网、丢单标签域
  3. 白名单硬闸：任何一条命中白名单（含父域/子域关系）一律剔除——这是防"拦死正常网站"的最后一道
  4. 分档：lite（高置信、约数千条，日常默认）／full（全部源并集）
  5. 输出 7 种格式 + meta（版本号由内容指纹决定，规则不变就不产生新提交）

用法：
  python3 tools/compile.py            # 同时产出 lite 与 full
  python3 tools/compile.py --only lite
"""
import argparse
import hashlib
import json
import os
import re
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CACHE = os.path.join(ROOT, "cache")
SUBS = os.path.join(ROOT, "subs")
LISTS = os.path.join(ROOT, "lists")
STATE = os.path.join(CACHE, "sources.json")

DOMAIN_RE = re.compile(r"^[a-z0-9]([a-z0-9\-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]*[a-z0-9])?)+$")
PRIVATE_SUFFIX = ("localhost",)


def parse_hosts(text):
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line or line.startswith("!"):
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        # 只认 0.0.0.0 / 127.0.0.1 指向的域
        if parts[0] not in ("0.0.0.0", "127.0.0.1", "::"):
            continue
        yield parts[1]


def parse_adblock(text):
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("!") or line.startswith("[") or line.startswith("#"):
            continue
        m = re.match(r"^\|\|([^\^/$|]+)\^?$", line)
        if not m:
            m = re.match(r"^\|\|([^\^/$|]+)\^?\$[a-z,]+$", line)
        if m:
            yield m.group(1)


def parse_domains(text):
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line or line.startswith("!"):
            continue
        if re.match(r"^(address=|server=)", line):
            m = re.match(r"^address=/([^/]+)/", line)
            if m:
                yield m.group(1)
            continue
        m = re.match(r"^(?:- +)?(?:DOMAIN-SUFFIX|DOMAIN),(\S+)$", line)
        if m:
            yield m.group(1)
            continue
        yield line.split()[0]


def parse_wildcard(text):
    """兼容两种通配写法：adblock 的 ||*.x^ 和纯文本的 *.x（OISD / HaGeZi）。"""
    for line in text.splitlines():
        line = line.strip()
        m = re.match(r"^\|\|\*\.([^\^/$|]+)\^", line)
        if m:
            yield "W:" + m.group(1)
            continue
        m = re.match(r"^\*\.([a-z0-9][a-z0-9._-]*)$", line, re.I)
        if m:
            yield "W:" + m.group(1)


def norm(d):
    d = d.strip().lower().strip(".")
    # 非 ASCII 域名先转 punycode：列表里混有 Unicode 域，DNS 查询只会是 xn-- 形式
    if any(ord(c) > 127 for c in d):
        try:
            d = d.encode("idna").decode("ascii")
        except Exception:
            return ""
    if d.startswith("||"):
        d = d[2:]
    d = d.rstrip("^")
    if d.startswith("*"):
        d = d.lstrip("*").lstrip(".")
    d = d.split("/")[0].split(":")[0]
    if not d or d.count(".") < 1:
        return ""
    if d.startswith("10.") or d.startswith("192.168.") or d.startswith("172."):
        return ""
    if any(d == s or d.endswith("." + s) for s in PRIVATE_SUFFIX):
        return ""
    if not DOMAIN_RE.match(d):
        return ""
    if len(d) > 253:
        return ""
    return d



def registrable(d):
    parts = d.split(".")
    if len(parts) < 2:
        return d
    cc2 = {"com.cn", "net.cn", "org.cn", "gov.cn", "co.uk", "com.au", "co.jp", "co.kr",
           "com.br", "com.mx", "com.tr", "com.tw", "com.hk", "com.sg", "com.my"}
    if len(parts) >= 3 and ".".join(parts[-2:]) in cc2:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def drop_benign_parent(domains, benign, endpoints):
    """精度优先：属于良性大盘站点的子域默认不拦，只有审计过的端点例外。"""
    keep, dropped = set(), []
    for d in domains:
        if d in endpoints:
            keep.add(d)
            continue
        if registrable(d) in benign or d in benign:
            dropped.append(d)
            continue
        keep.add(d)
    return keep, dropped


def load_list_file(name):
    """读取 lists/<name>，返回域集合（忽略注释）。"""
    out = set()
    p = os.path.join(LISTS, name)
    if os.path.exists(p):
        for line in open(p, encoding="utf-8"):
            d = line.split("#", 1)[0].strip().lower()
            if d and "." in d:
                out.add(d)
    return out


def load_first_col(name):
    """读取 lists/<name> 的首列（tab 分隔的发现产物用）。"""
    out = set()
    p = os.path.join(LISTS, name)
    if os.path.exists(p):
        for line in open(p, encoding="utf-8"):
            line = line.split("#", 1)[0]
            if not line.strip():
                continue
            d = line.split("\t")[0].strip().lower()
            if d and "." in d and not d.startswith("."):
                out.add(d)
    return out


def load_whitelist():
    """白名单三源合一：人工台账 + 回归基线 + 基础服务表。

    service_allow.txt 存的是"登录/支付/推送/地图/验证码"这类一旦拦了整个 App 就废掉的
    第三方基础服务。它们与 whitelist.txt 同等待遇（编译期整体剔除 + 父域保护），
    只是维护视角不同：台账按"事故"记，服务表按"功能"记。
    """
    wl = set()
    for fn, first_col_only in (("whitelist.txt", False), ("service_allow.txt", True)):
        p = os.path.join(LISTS, fn)
        if not os.path.exists(p):
            continue
        for line in open(p, encoding="utf-8"):
            line = line.split("#", 1)[0].strip()
            if not line:
                continue
            if first_col_only or "\t" in line:
                line = line.split("\t")[0].strip()
            if line and "." in line:
                wl.add(line.lower())
    p2 = os.path.join(ROOT, "tests", "benign_baseline.txt")
    if os.path.exists(p2):
        for line in open(p2, encoding="utf-8"):
            line = line.split("#", 1)[0].strip()
            if line:
                wl.add(line.lower())
    return wl


def protected(d, wl):
    """白名单不仅保护精确域，也保护父域：白名单里有 baidu.com 时，x.baidu.com 不能被拦。"""
    parts = d.split(".")
    for i in range(len(parts) - 1):
        if ".".join(parts[i:]) in wl:
            return True
    return False


def sources_by_kind():
    meta = {}
    if os.path.exists(STATE):
        try:
            meta = json.load(open(STATE, encoding="utf-8"))
        except Exception:
            meta = {}
    src = []
    with open(os.path.join(ROOT, "sources.tsv"), encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            p = line.split("\t")
            if len(p) < 4:
                continue
            src.append({"name": p[0], "fmt": p[2], "kind": p[3]})
    return src, meta


def slug(name):
    return "".join(ch if ch.isalnum() or ch in "-_." else "_" for ch in name).lower()


PARSERS = {"hosts": parse_hosts, "adblock": parse_adblock, "domains": parse_domains,
           "dnsmasq": parse_domains, "wildcard": parse_wildcard,
           "domainswild": parse_wildcard, "clash": parse_domains}


# 三档硬上限（2026-11-21 定档）：lite 1 万 / mid 2 万 / full 3 万。
# 只留国内设备真会请求的域 + 国际大广告 SDK，其余长尾一律删 —— 规则不是越多越好，
# 每条都要占额度（KV、Gateway 100×1000、Worker bundle），换不来拦截收益就是负债。
LITE_CAP = 10000
MID_CAP = 40000   # L2 把 mid 搬进 KV 后，体积墙从 3 万条推到 KV 上限，mid 扩到 4 万
FULL_CAP = 30000

HEAVY_HINTS = ("AdGuard", "HaGeZi", "hagezi", "OISD", "oisd", "1Hosts", "KADhosts", "antiAD")
# 小而准、单源也必须进中档的清单：CNAME 落点表（反第一方伪装）与国内 App 去广告清单
FORCE_MID_HINTS = ("CNAME-original", "ACL4SSR")
AD_LABELS = {"ad", "ads", "adserver", "adservice", "advert", "advertising", "adclick",
             "adtech", "banner", "banners", "click", "clicks", "track", "tracker",
             "tracking", "beacon", "pixel", "impression", "promo", "sponsor", "sponsored",
             "doubleclick", "pagead", "prebid", "adnxs", "adform", "adsrv", "dsp", "ssp"}


def load_local(name):
    """仓库根目录的本地覆盖清单（allowlist.txt / blocklist.txt）。"""
    p = os.path.join(ROOT, name)
    out = set()
    if os.path.exists(p):
        for line in open(p, encoding="utf-8"):
            line = line.split("#", 1)[0].strip().lower()
            if line and "." in line:
                out.add(line)
    return out


def collect():
    srcs, meta = sources_by_kind()
    exact, wild = set(), set()
    per_source = {}
    consensus = {}   # 域 → 加权共识分（高质量源权重更高）
    hitn = {}        # 域 → 命中的独立源个数
    for s in srcs:
        fp = os.path.join(CACHE, slug(s["name"]) + ".txt")
        if not os.path.exists(fp):
            continue
        parser = PARSERS.get(s["fmt"], parse_domains)
        n = 0
        try:
            text = open(fp, encoding="utf-8", errors="ignore").read()
        except Exception:
            continue
        seen = set()
        for raw in parser(text):
            if raw.startswith("W:"):
                w = norm(raw[2:])
                if w:
                    wild.add(w)
                continue
            d = norm(raw)
            if d:
                exact.add(d)
                seen.add(d)
                n += 1
        if any(k in s["name"] for k in FORCE_MID_HINTS):
            w = 3.0      # 单源即可过中档门槛，但仍进不了小档（小档要 4.0 + 3 源）
        elif any(k in s["name"] for k in HEAVY_HINTS):
            w = 1.5
        else:
            w = 1.0
        for d in seen:
            consensus[d] = consensus.get(d, 0) + w
            hitn[d] = hitn.get(d, 0) + 1
        per_source[s["name"]] = n
    return exact, wild, per_source, meta, consensus, hitn


def drop_children(exact):
    """父域已覆盖时删子域：只是压缩体积，语义不变（匹配本来就按后缀）。"""
    keep = []
    for d in exact:
        parts = d.split(".")
        covered = any(".".join(parts[i:]) in exact for i in range(1, len(parts) - 1))
        if not covered:
            keep.append(d)
    return set(keep)


def write_formats(domains, wild, outdir, kind, stamp_fixed=None):
    os.makedirs(outdir, exist_ok=True)
    doms = sorted(domains)
    wilds = sorted(wild)
    ts = stamp_fixed or time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime())
    body_hash = hashlib.sha256(("\n".join(doms) + "|" + "\n".join(wilds)).encode()).hexdigest()[:8]
    ver = time.strftime("%Y%m%d") + "-" + body_hash

    files = {}
    head = ["! Title: NoAS 拦截订阅（%s）" % kind,
            "! Description: 免费公开源并集，白名单硬闸过滤后发布；每日自动重建",
            "! Version: %s" % ver,
            "! Last modified: %s" % ts,
            "! Expires: 12 hours",
            "! Homepage: https://github.com/NoS-1/NoAS",
            "! 条数: %d（含通配 %d）" % (len(doms), len(wilds), )]
    files["adguard.txt"] = "\n".join(head + [""] +
                                    ["||%s^" % d for d in doms] +
                                    ["||*.%s^" % w for w in wilds]) + "\n"
    files["domains.txt"] = "\n".join(doms) + "\n"
    files["hosts.txt"] = "\n".join(["# NoAS %s（%d 条）" % (ver, len(doms))] +
                                   ["0.0.0.0 %s" % d for d in doms]) + "\n"
    # dnsmasq 的 # 表示 NULL 地址：同时回 0.0.0.0 与 ::，
    # 否则只有 IPv4 被黑洞、IPv6 客户端会绕过拦截
    files["dnsmasq.conf"] = "\n".join(["# NoAS %s（%d 条）" % (ver, len(doms))] +
                                     ["address=/%s/#" % d for d in doms]) + "\n"
    files["clash.yaml"] = "\n".join(["# NoAS %s rule-provider payload" % ver, "payload:"] +
                                   ["  - DOMAIN-SUFFIX,%s" % d for d in doms]) + "\n"
    files["surge.list"] = "\n".join(["DOMAIN-SUFFIX,%s" % d for d in doms]) + "\n"
    # QuantumultX 过滤器语法（host-suffix 天然覆盖子域，通配条目按后缀下发）
    dom_set = set(doms)
    qx_extra = [w for w in wilds if w not in dom_set]
    files["qx.list"] = "\n".join(["# NoAS %s（%d 条 + 通配 %d）" % (ver, len(doms), len(qx_extra))] +
                                  ["host-suffix, %s, reject" % d for d in doms] +
                                  ["host-suffix, %s, reject" % w for w in qx_extra]) + "\n"
    files["singbox.json"] = json.dumps({"version": 1, "rules": [{"domain_suffix": doms}]},
                                       ensure_ascii=False, indent=1) + "\n"
    # 通配清单（DoH 端按 *.x 匹配任意多级子域；suffix 格式客户端可直接吃根域）
    files["wildcards.txt"] = "\n".join(["# NoAS 通配清单（%s）：*.域 = 该域任意多级子域" % ver] +
                                        ["*.%s" % w for w in wilds]) + "\n"
    # RPZ：BIND / Knot / PowerDNS / Unbound 通用，CNAME . 表示 NXDOMAIN
    files["rpz.zone"] = "\n".join(["# NoAS RPZ（%s）" % ver,
                                   "; $TTL 300"] +
                                  ["%s CNAME ." % d for d in doms] +
                                  ["*.%s CNAME ." % w for w in wilds]) + "\n"
    # 通配域名格式：Blocky / OPNsense / FritzBox / DNSCrypt 系
    files["wildcard.txt"] = "\n".join(["# NoAS 通配（%s）" % ver] +
                                       ["*.%s" % d for d in doms]) + "\n"
    # Unbound 原生配置
    files["unbound.conf"] = "\n".join(["# NoAS Unbound（%s）" % ver] +
                                       ['local-zone: "%s" always_nxdomain' % d for d in doms]) + "\n"
    # 允许清单：把白名单台账下发给客户端，用户侧也能"宁放不误拦"
    ep_set = load_list_file("ad_endpoints.txt")
    allow = load_whitelist()
    allow = sorted(d for d in allow if d not in ep_set)
    files["allow.txt"] = "\n".join(["# NoAS 允许清单（%s）：这些域禁止拦截" % ver] +
                                    [d for d in allow]) + "\n"

    changed = []
    for name, text in files.items():
        p = os.path.join(outdir, name)
        old = None
        if os.path.exists(p):
            try:
                old = open(p, encoding="utf-8").read()
            except Exception:
                old = None
        if old != text:
            with open(p, "w", encoding="utf-8") as f:
                f.write(text)
            changed.append(name)

    meta = {"kind": kind, "version": ver, "count": len(doms), "wildcards": len(wilds),
            "generated_utc": ts, "files": {}}
    for name in sorted(files):
        p = os.path.join(outdir, name)
        meta["files"][name] = {"bytes": os.path.getsize(p),
                               "sha256": hashlib.sha256(open(p, "rb").read()).hexdigest()}
    mp = os.path.join(outdir, "meta.json")
    new_meta = json.dumps(meta, ensure_ascii=False, indent=1) + "\n"
    old_meta = open(mp, encoding="utf-8").read() if os.path.exists(mp) else None
    if old_meta != new_meta:
        open(mp, "w", encoding="utf-8").write(new_meta)
        changed.append("meta.json")
    return ver, changed, meta


INPUT_GLOBS = ("lists", "tests")
FP_PATH = os.path.join(ROOT, "state", "compile_fingerprint.json")


def input_fingerprint():
    """参与编译的所有输入文件的内容指纹：任何一个字节变了，指纹就变。

    用途：没变化时直接跳过重算。CI 里 discover/promote 会改 lists，所以正常情况下
    指纹天天变；但一天跑 8 次日常构建，多数轮次输入是没变的，跳过能省下大头时间。
    """
    h = hashlib.sha256()
    files = []
    for g in INPUT_GLOBS:
        d = os.path.join(ROOT, g)
        if not os.path.isdir(d):
            continue
        for name in sorted(os.listdir(d)):
            fp = os.path.join(d, name)
            if os.path.isfile(fp) and (name.endswith(".txt") or name.endswith(".tsv")):
                files.append(fp)
    files.append(os.path.join(ROOT, "sources.tsv"))
    # 源本体在 cache/（每轮 fetch 重新拉到），lists/ 只是上一次的产物。
    # 只盯 lists 会漏掉"源更新了但还没来得及反映到 lists"的情况，必须把源本身算进指纹。
    cdir = os.path.join(ROOT, "cache")
    if os.path.isdir(cdir):
        for name in sorted(os.listdir(cdir)):
            fp = os.path.join(cdir, name)
            if os.path.isfile(fp) and fp.endswith((".txt", ".json", ".list", ".domains")):
                files.append(fp)
    for fp in files:
        if not os.path.isfile(fp):
            continue
        try:
            st = os.stat(fp)
            h.update(("%s|%d|%d\n" % (os.path.basename(fp), st.st_size, int(st.st_mtime))).encode())
            if st.st_size < 4 * 1024 * 1024:
                h.update(open(fp, "rb").read())
        except Exception:
            pass
    return h.hexdigest()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--only", choices=["lite", "mid", "full"])
    ap.add_argument("--force", action="store_true", help="忽略增量判断，强制全量重算")
    args = ap.parse_args()
    os.makedirs(os.path.join(ROOT, "out"), exist_ok=True)

    fp = input_fingerprint()
    if not args.force and args.only is None:
        prev = {}
        if os.path.exists(FP_PATH):
            try:
                prev = json.load(open(FP_PATH, encoding="utf-8"))
            except Exception:
                prev = {}
        ready = all(os.path.exists(os.path.join(SUBS, t, "domains.txt")) for t in ("lite", "mid", "full"))
        if prev.get("fp") == fp and ready:
            print("编译跳过：输入指纹未变（%s…），直接复用上次产物" % fp[:12])
            return 0

    exact, wild, per_source, _, consensus, hitn = collect()
    wl = load_whitelist()
    # 端点表 = 人工审计的国内广告端点 + 自动发现的高置信首方广告子域（解析链落在广告网络）
    # ep = 端点例外集合：白名单父域下仍然要拦的纯广告端点，免疫白名单剔除。
    # 跨层回灌（L2 路径层 / L3 uBO 已验证的广告主机）按同一语义并入 ep，
    # 这样它们在 DNS 层不只知道"存在"，而且真的会被拦。
    ep = (load_list_file("ad_endpoints.txt") | load_first_col("cn_ad_endpoints.txt")
          | load_list_file("layer_backfill.txt"))
    # 观察池：只靠前缀命中、链上无广告落点，仅进 mid/full，绝不进 lite
    # 观察池两条来源：① 自动发现的低置信首方广告子域；② 用户报的漏拦域（misses.txt）。
    # 两者都只进 mid/full：单条反馈不足以进默认档，但也不该石沉大海。
    watch = load_first_col("cn_ad_watch.txt") | load_first_col("misses.txt")
    blocked_wl = [d for d in exact if protected(d, wl) and d not in ep]
    exact = {d for d in exact if not protected(d, wl) or d in ep}
    wild = {w for w in wild if not protected(w, wl)}
    lallow = load_local("allowlist.txt")
    lblock = load_local("blocklist.txt")
    # 冷却池：被反馈误伤、进入观察期的域，编译期强制豁免（等同白名单级别）
    cooldown = load_list_file("cooldown.txt")
    wl = wl | lallow | cooldown
    exact = drop_children(exact) | ep

    if len(per_source) < 8:
        print("FAIL：可用源只剩 %d 个（下限 8），疑似批量失效，拒绝发布" % len(per_source))
        return 1
    if len(exact) < 500:
        print("FAIL：规则太少（%d），疑似所有源都失效，拒绝发布" % len(exact))
        return 1

    # 三层分档，用"跨源共识"定义可信度（单源可能是误伤，多源同时命中才稳）：
    #   lite = 至少 3 个独立源都拦（日常默认，误拦率最低）
    #   mid  = 至少 2 个源（覆盖更广）
    #   full = 全部（含长尾）
    core = set()
    cp = os.path.join(LISTS, "core_ad_networks.txt")
    if os.path.exists(cp):
        for line in open(cp, encoding="utf-8"):
            line = line.split("#", 1)[0].strip().lower()
            if line and "." in line:
                core.add(line)
    benign = load_list_file("benign_top.txt") | wl
    wild = {w for w in wild if registrable(w) not in benign and w not in benign}
    # 观察池过滤：不碰白名单父子域，也不碰良性大盘父域（除非它已经在端点表里）
    watch = {w for w in watch if w not in benign and w not in ep
             and not protected(w, wl) and registrable(w) not in benign}
    exact, benign_dropped = drop_benign_parent(exact, benign, ep)
    # 分类长尾：挖矿 / 返利跳转 / 系统遥测。只进 full，不进 lite/mid；
    # 同样受白名单、良性大盘、端点表约束，避免误伤。
    miner = load_list_file("miner.txt")
    affiliate = load_list_file("affiliate.txt")
    telemetry = load_list_file("telemetry.txt")
    # 广告 SDK 与长视频贴片：高置信、低误伤，进 mid（不进 lite，避免挤占 1 万名额）
    sdk = load_list_file("sdk_ads.txt")
    video = load_list_file("video_ads.txt")
    dead = load_list_file("dead.txt")
    # 设备实测确认（手机日志里真实发出的广告请求，AI+多信号判定过）：强制进 mid，不参与名额竞争
    dconf = {d for d in load_list_file("device_confirmed.txt")
             if not protected(d, wl) and d not in benign and d not in ep}
    # 影子观察（机器判定但还没经过观察期）：只进 full，三档都不拦，观察期满由 identify.py 转正
    shadow = load_list_file("shadow.txt")
    # 人工审核过的必拦清单（SDK/贴片/端点/威胁）不适用死域闸：
    # 品牌根域常常没有 A 记录（pangle.io 就是这样），但它是真广告实体，删掉等于漏拦。
    sdk_video = {d for d in (sdk | video)
                 if not protected(d, wl) and d not in benign and d not in ep}
    threat_all = miner | affiliate | telemetry
    threat_extra = {d for d in threat_all
                    if not protected(d, wl) and d not in benign and d not in ep}
    # 死域一律剔除：这些域解析探测已确认不存在（NXDOMAIN/无记录），留着只占名额、拦不到任何东西。
    # 硬边界：白名单与审计端点永不剪，避免把正常站误判成死域。
    dropped_dead = {d for d in exact if d in dead and not protected(d, wl) and d not in ep}
    exact = exact - dropped_dead
    # 本地 blocklist：用户显式要求必拦，优先于良性大盘判断（仍让本地 allow 压过）
    exact = drop_children(exact) | ep | (lblock - lallow)
    # 精度优先：lite 只保留"多源共识 + 核心广告网 + 审计端点"，自动晋级只进 mid
    promoted = {d for d in load_list_file("promoted.txt") if d not in wl and d in exact}
    # lite 硬上限 1 万条：强制条目（端点/核心广告网/本地拦截）永远保留；
    # 其次放入强结构晋级条目；剩余名额按共识分、命中源数排序取最高的共识域。
    forced = (core & exact) | ep | (lblock - lallow)
    promoted_keep = promoted - forced
    consensus_pool = {d for d in exact
                      if consensus.get(d, 0) >= 4.0 and hitn.get(d, 0) >= 3} - forced - promoted_keep
    ordered = sorted(consensus_pool,
                     key=lambda d: (-consensus.get(d, 0), -hitn.get(d, 0), d))
    # 安全通配：核心广告网根域 + "注册域恰好是广告结构子域的父域"，绝不碰白名单/良性大盘
    wild_safe = {c for c in core
                 if not protected(c, wl) and c not in benign and c not in ep}
    for d in exact:
        parts = d.split(".")
        if len(parts) >= 3 and any(p in AD_LABELS for p in parts[:-2]):
            r = registrable(d)
            if (r and r in exact and r != d and not protected(r, wl)
                    and r not in benign and r not in ep):
                wild_safe.add(r)
    wild_safe = set(sorted(wild_safe)[:500])

    # 名额要连通配一起算：lite 产物 = 域名行 + 通配行，合计不得越 LITE_CAP
    slots = LITE_CAP - len(forced) - len(wild_safe)
    promoted_keep = set(sorted(promoted_keep)[:max(0, slots)])
    slots -= len(promoted_keep)
    consensus_keep = set(ordered[:max(0, slots)])
    # 威胁分类（挖矿/返利/遥测）严禁出现在 lite/mid：即便上游源带了也强制剔除
    lite = drop_children(forced | promoted_keep | consensus_keep) - threat_all
    # 观察池只进 mid / full：这些是自动发现的"前缀像广告、但链上没有广告落点"的域
    # 档位必须严格包含：lite ⊆ mid ⊆ full。否则用户从 lite 升到 mid 会突然漏拦（体验倒退）。
    # 「国内优先」：这些域是国内设备真的会查的 —— 国内观察池 / 国内发现端点 / 国内根域 /
    # 核心广告网（含 AdMob·AppLovin·Unity 这类国内 App 内嵌的海外 SDK，必须留），
    # 以及审计端点与白名单相关。排序时先国内、再按共识分与命中源数。
    cn = (load_list_file("cn_ad_watch.txt") | load_list_file("cn_ad_endpoints.txt")
          | load_list_file("cn_roots.txt") | ep | core | sdk | video)
    # 「只要国内的」：国内设备不会请求纯海外本地服务/品牌域（timhortons.ca、playstation.net 这类），
    # 它们在海外源里躺了几十万条，占额度换不到任何拦截收益 —— 直接排除，除非它属于必留白名单。
    FOREIGN_CC = {"ca", "au", "uk", "de", "fr", "jp", "kr", "ru", "br", "mx", "in", "id",
                  "th", "vn", "my", "sg", "ph", "tr", "pl", "nl", "se", "no", "dk", "fi",
                  "ch", "at", "be", "es", "it", "pt", "gr", "cz", "ar", "cl", "co", "za",
                  "ae", "il", "nz", "ie", "hu", "ro", "ua"}
    must = ep | core | sdk | video | (lblock - lallow)

    def foreign(d):
        if d in must or d in cn:
            return 0
        return 1 if d.rsplit(".", 1)[-1] in FOREIGN_CC else 0

    def rank(d):
        return (foreign(d), 0 if d in cn else 1, -consensus.get(d, 0), -hitn.get(d, 0), len(d), d)

    mid_raw = drop_children(
        drop_children({d for d in exact if consensus.get(d, 0) >= 2.0} | promoted)
        | ep | watch | sdk_video | (lblock - lallow) | lite) - threat_all
    mid_keep = (lite | ep | sdk_video | promoted | (core & exact) | (lblock - lallow)
                | (dconf - threat_all))
    mid_raw = mid_raw - shadow
    mid_extra = sorted(mid_raw - mid_keep, key=rank)[:max(0, MID_CAP - len(mid_keep))]
    mid = drop_children((mid_keep | set(mid_extra)) - threat_all)

    full_raw = exact | watch | sdk_video | threat_extra | mid | shadow
    # 影子域必须真的留在 full（否则被 rank 截掉，观察期形同虚设）
    full_keep = mid | threat_extra | ep | (core & exact) | shadow
    full_extra = sorted(full_raw - full_keep, key=rank)[:max(0, FULL_CAP - len(full_keep))]
    # 挖矿/恶意域必须留在 full（拦掉才算真防护），归因/统计域三档都不进
    full = (full_keep | set(full_extra)) - threat_all | miner

    prov = {d: round(consensus.get(d, 0), 2) for d in lite}
    json.dump({"lite": prov, "core": sorted(core & lite), "endpoints": sorted(ep & lite)},
              open(os.path.join(ROOT, "out", "lite_provenance.json"), "w", encoding="utf-8"),
              ensure_ascii=False)

    report = {"dead_dropped": len(dropped_dead), "sources": per_source,
              "full": len(full), "lite": len(lite), "mid": len(mid),
              "cn_discovered": len(ep - load_list_file("ad_endpoints.txt")), "cn_watch": len(watch),
              "lite_cap": LITE_CAP, "mid_cap": MID_CAP, "full_cap": FULL_CAP, "lite_pool": len(promoted) + len(consensus_pool),
              "wildcards": len(wild), "whitelist_blocked": len(blocked_wl),
              "ad_endpoints": len(ep), "promoted": len(promoted),
              "device_confirmed": len(dconf), "shadow": len(shadow), "benign_dropped": len(benign_dropped)}
    print("编译完成：full %d ／mid %d ／lite %d 条（通配 %d）｜白名单剔除 %d｜源 %d 个｜国内发现端点 %d＋观察 %d" % (
        len(full), len(mid), len(lite), len(wild | wild_safe), len(blocked_wl), len(per_source),
        len(ep - load_list_file("ad_endpoints.txt")), len(watch)))

    os.makedirs(LISTS, exist_ok=True)
    json.dump(report, open(os.path.join(ROOT, "out_compile.json"), "w", encoding="utf-8"),
              ensure_ascii=False, indent=1)
    os.makedirs(os.path.join(ROOT, "out"), exist_ok=True)

    os.replace(os.path.join(ROOT, "out_compile.json"), os.path.join(ROOT, "out", "compile.json"))

    results = {}
    if args.only in (None, "lite"):
        ver, changed, meta = write_formats(lite, wild_safe, os.path.join(SUBS, "lite"), "lite")
        results["lite"] = {"version": ver, "changed": changed, "count": meta["count"]}
    if args.only in (None, "mid"):
        ver, changed, meta = write_formats(mid, wild_safe, os.path.join(SUBS, "mid"), "mid")
        results["mid"] = {"version": ver, "changed": changed, "count": meta["count"]}
    if args.only in (None, "full"):
        # full 通配上限 3000：通配一条覆盖整棵子树，价值高但也最容易误伤，只留国内可查的前 3000 条
        wild_full = set(sorted([w for w in wild if not foreign(w)],
                               key=lambda d: (0 if d in cn else 1, -consensus.get(d, 0), len(d), d))[:3000])
        ver, changed, meta = write_formats(full, wild_full | wild_safe, os.path.join(SUBS, "full"), "full")
        results["full"] = {"version": ver, "changed": changed, "count": meta["count"]}
    for k, v in results.items():
        print("  %s：%d 条，版本 %s，变更 %d 个文件" % (k, v["count"], v["version"], len(v["changed"])))

    # 名额余量告警：mid/lite 一旦撞上 cap，超出的规则会被**静默**截掉、产物照样是绿的，
    # 等于"覆盖在缩水但没人知道"。余量低于 3% 就在这里喊一声，让 CI 出黄条。
    def _head(used, cap):
        return {"used": used, "cap": cap, "left": cap - used,
                "pct_left": round(max(0, cap - used) / cap * 100, 2)}
    headroom = {"lite": _head(results.get("lite", {}).get("count", len(lite)), LITE_CAP),
                "mid": _head(results.get("mid", {}).get("count", len(mid)), MID_CAP),
                "full": _head(results.get("full", {}).get("count", len(full)), FULL_CAP)}
    report["headroom"] = headroom
    json.dump(headroom, open(os.path.join(ROOT, "out", "cap_headroom.json"), "w", encoding="utf-8"), indent=1)
    for t in ("lite", "mid"):
        h = headroom[t]
        if h["left"] < 0:
            print("::warning title=规则名额溢出::%s 超出 cap %d 条（cap=%d）——超出部分已被截断，规则没进产物" %
                  (t, -h["left"], h["cap"]))
        elif h["pct_left"] < 3:
            print("::warning title=规则名额见底::%s 只剩 %d 条余量（cap=%d，%.2f%%）——再加源就会被静默截断，该扩 cap 或收源了" %
                  (t, h["left"], h["cap"], h["pct_left"]))
    print("名额余量：lite 剩 %d ／mid 剩 %d ／full 剩 %d" %
          (headroom["lite"]["left"], headroom["mid"]["left"], headroom["full"]["left"]))

    try:
        os.makedirs(os.path.join(ROOT, "state"), exist_ok=True)
        json.dump({"fp": fp, "at": time.strftime("%Y-%m-%d %H:%M:%S")},
                  open(FP_PATH, "w", encoding="utf-8"))
    except Exception:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
