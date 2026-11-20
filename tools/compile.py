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


def load_whitelist():
    wl = set()
    p = os.path.join(LISTS, "whitelist.txt")
    if os.path.exists(p):
        for line in open(p, encoding="utf-8"):
            line = line.split("#", 1)[0].strip()
            if line:
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


HEAVY_HINTS = ("AdGuard", "HaGeZi", "hagezi", "OISD", "oisd", "1Hosts", "KADhosts", "antiAD")
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
        w = 1.5 if any(k in s["name"] for k in HEAVY_HINTS) else 1.0
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
    files["dnsmasq.conf"] = "\n".join(["# NoAS %s（%d 条）" % (ver, len(doms))] +
                                     ["address=/%s/0.0.0.0" % d for d in doms]) + "\n"
    files["clash.yaml"] = "\n".join(["# NoAS %s rule-provider payload" % ver, "payload:"] +
                                   ["  - DOMAIN-SUFFIX,%s" % d for d in doms]) + "\n"
    files["surge.list"] = "\n".join(["DOMAIN-SUFFIX,%s" % d for d in doms]) + "\n"
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


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--only", choices=["lite", "mid", "full"])
    args = ap.parse_args()
    os.makedirs(os.path.join(ROOT, "out"), exist_ok=True)

    exact, wild, per_source, _, consensus, hitn = collect()
    wl = load_whitelist()
    ep = load_list_file("ad_endpoints.txt")
    blocked_wl = [d for d in exact if protected(d, wl) and d not in ep]
    exact = {d for d in exact if not protected(d, wl) or d in ep}
    wild = {w for w in wild if not protected(w, wl)}
    lallow = load_local("allowlist.txt")
    lblock = load_local("blocklist.txt")
    wl = wl | lallow
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
    exact, benign_dropped = drop_benign_parent(exact, benign, ep)
    dead = load_list_file("dead.txt")
    dropped_dead = {d for d in exact if d in dead and hitn.get(d, 0) <= 1}
    exact = exact - dropped_dead
    # 本地 blocklist：用户显式要求必拦，优先于良性大盘判断（仍让本地 allow 压过）
    exact = drop_children(exact) | ep | (lblock - lallow)
    # 精度优先：lite 只保留"多源共识 + 核心广告网 + 审计端点"，自动晋级只进 mid
    promoted = {d for d in load_list_file("promoted.txt") if d not in wl and d in exact}
    lite = drop_children({d for d in exact
                          if (consensus.get(d, 0) >= 4.0 and hitn.get(d, 0) >= 3)}
                         | (core & exact)) | ep | (lblock - lallow)
    mid = drop_children({d for d in exact if consensus.get(d, 0) >= 2.0} | promoted) | ep | (lblock - lallow)

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

    prov = {d: round(consensus.get(d, 0), 2) for d in lite}
    json.dump({"lite": prov, "core": sorted(core & lite), "endpoints": sorted(ep & lite)},
              open(os.path.join(ROOT, "out", "lite_provenance.json"), "w", encoding="utf-8"),
              ensure_ascii=False)

    report = {"sources": per_source, "full": len(exact), "lite": len(lite), "mid": len(mid),
              "wildcards": len(wild), "whitelist_blocked": len(blocked_wl),
              "ad_endpoints": len(ep), "promoted": len(promoted), "benign_dropped": len(benign_dropped)}
    print("编译完成：full %d ／mid %d ／lite %d 条（通配 %d）｜白名单剔除 %d｜源 %d 个" % (
        len(exact), len(mid), len(lite), len(wild | wild_safe), len(blocked_wl), len(per_source)))

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
        ver, changed, meta = write_formats(exact, wild | wild_safe, os.path.join(SUBS, "full"), "full")
        results["full"] = {"version": ver, "changed": changed, "count": meta["count"]}
    for k, v in results.items():
        print("  %s：%d 条，版本 %s，变更 %d 个文件" % (k, v["count"], v["version"], len(v["changed"])))
    return 0


if __name__ == "__main__":
    sys.exit(main())
