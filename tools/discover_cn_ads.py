#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""discover_cn_ads.py —— 自动发现国内 App 的「首方广告子域」。

背景：国内 App 的广告接口几乎都挂在自家主域下（`splash.xx.com`、`adx.xx.com`），
上游清单要么漏、要么不敢收（怕拦死整站）。人肉维护永远追不上，所以做成自动发现。

发现链路（每一层都可验证，不靠猜）：
  1. 证书透明度（crt.sh）：拉 root 及其全部真实子域 —— 这是"真实存在过"的子域全集；
  2. 词元判定：把域名切成词元（按 . 和 - ），只有整词命中广告语义词表才算候选，
     天然排掉 download / upload / shadow / adapter / adobe 这类假阳性；
  3. 存活校验：DoH 并发解析，NXDOMAIN 丢弃；
  4. 泛解析识别：先探一个不存在的随机子域，若它也解析成功 -> 该 root 是泛解析，
     整根域的候选全部丢弃（这是"误伤为零"的关键一步）；
  5. 停放页识别：解析链落到 overdue / parking / sedo 之类占位页的丢弃；
  6. 置信分档：
       · 解析链落在已知广告网络落点 -> 高置信，写 lists/cn_ad_endpoints.txt（全档强制拦）
       · 只是词元命中、链上无广告落点 -> 低置信，写 lists/cn_ad_watch.txt（仅 mid/full）

产物：
  lists/cn_ad_endpoints.txt   高置信端点（tab 分隔：域名 / 命中词 / 落点证据）
  lists/cn_ad_watch.txt       低置信观察池
  out/cn_ads.json             本轮统计
"""
import concurrent.futures as cf
import json
import os
import re
import sys
import time
import urllib.parse
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LISTS = os.path.join(ROOT, "lists")
CACHE = os.path.join(ROOT, "cache", "ct")
OUT = os.path.join(ROOT, "out")
UA = "NoAS-discover-cn-ads/1.0 (+https://github.com/NoS-1/NoAS)"

DOH = "https://dns.alidns.com/resolve"
CT = "https://crt.sh/"
CT_WORKERS = 5
DNS_WORKERS = 32
CT_TIMEOUT = 25
DNS_TIMEOUT = 8
# 每轮处理多少根域（crt.sh 慢，分批滚动覆盖，一周内跑完全部）
ROOTS_PER_RUN = int(os.environ.get("NOAS_CT_ROOTS", "45"))

# 广告/追踪词元（整词匹配，避免 substring 假阳性）
AD_TOKENS = {
    "ad", "ads", "adx", "adv", "adver", "advert", "adverts", "advertise", "adserver",
    "adserv", "adservice", "adapi", "adopen", "adsdk", "adnet", "adreq", "adrequest",
    "adlog", "adstat", "admetric", "splash", "splashad", "op", "gdt", "pangle",
    "gromore", "pangolin", "openads", "union", "tanx", "mobads", "cpro", "umeng",
    "track", "tracker", "tracking", "click", "clk", "impression", "beacon", "log",
    "logs", "stat", "stats", "statistics", "metric", "metrics", "analytics", "monitor",
    "promote", "promotion", "market", "mkt", "bdad", "tuia", "tuiguang", "admon",
}
# 强前缀：域名最左标签整词就是这些词 -> 该品牌给自有广告业务单独开的子域，
# 消费端用户不会正常访问，可直接进端点表（全档强制拦）。
STRONG_PREFIX = {
    "ad", "ads", "adx", "adv", "adapi", "adlog", "adsdk", "adserver", "adservice",
    "adopen", "adnet", "adstat", "admetric", "splash", "splashad", "gromore",
    "pangolin", "pangle", "openads", "mobads", "tanx", "cpro", "gdt", "tuia",
}
# 词元前缀形态：ad1 / ads2 / adserver01 / splash3 之类
TOKEN_RE = re.compile(r"^(ad|ads|adx|adserver|adsdk|splash)[0-9]{0,3}$")
# 落点证据：CNAME 链里出现即判高置信
AD_CHAIN_HINTS = (
    "gdtimg", "pangle", "pangolin", "gromore", "snssdk", "bytedance", "volces",
    "kuaishou", "gifshow", "mobads", "cpro", "tanx", "alimama", "umeng",
    "applovin", "ironsource", "mintegral", "inmobi", "unityads", "chartboost",
    "vungle", "adcolony", "tapjoy", "startapp", "supersonic", "doubleclick",
    "googleads", "adnxs", "adform", "adsrvr", "amazon-adsystem", "admaster",
    "talkingdata", "growingio", "sensorsdata", "getui", "igexin", "jpush",
)
PARKING_HINTS = ("overdue", "parking", "sedo", "dnspod", "above.com", "buydomains",
                 "expired", "domainmarket", "hugedomains", "afternic", "godaddy")

# 暴力枚举用的广告前端前缀：覆盖国内主流 SDK / 服务端的命名习惯
BRUTE_PREFIX = [
    "ad", "ads", "adx", "adv", "adserver", "adservice", "adapi", "adopen",
    "splash", "splashad", "gromore", "pangolin", "pangle", "openads",
    "adsdk", "adnet", "adlog", "adstat", "union", "tuia",
]


def brute_candidates(root):
    return [("%s.%s" % (p, root), p) for p in sorted(set(BRUTE_PREFIX))]



def read_roots():
    p = os.path.join(LISTS, "cn_roots.txt")
    out = []
    if not os.path.exists(p):
        return out
    for line in open(p, encoding="utf-8"):
        d = line.split("#", 1)[0].strip().lower()
        if d and "." in d and not d.startswith("."):
            out.append(d)
    return out


def benign_set():
    out = set()
    for p in (os.path.join(LISTS, "whitelist.txt"),
              os.path.join(LISTS, "benign_top.txt"),
              os.path.join(ROOT, "tests", "benign_baseline.txt")):
        if not os.path.exists(p):
            continue
        for line in open(p, encoding="utf-8"):
            d = line.split("#", 1)[0].strip().lower()
            if d and "." in d:
                out.add(d)
    return out


def protected(d, allow):
    parts = d.split(".")
    return any(".".join(parts[i:]) in allow for i in range(len(parts) - 1))


def _get(url, timeout):
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "*/*"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read().decode("utf-8", "ignore")


def _from_passive_dns(root):
    """被动 DNS（hackertarget）：每次返回一批真实解析过的子域，快且稳。"""
    txt = _get("https://api.hackertarget.com/hostsearch/?q=" + root, 15)
    if txt.startswith("error") or txt.startswith("API count exceeded"):
        return []
    out = []
    for line in txt.splitlines():
        host = line.split(",")[0].strip().lower()
        if host.endswith("." + root):
            out.append(host)
    return out


def _from_ct(root):
    """证书透明度（crt.sh）：子域最全，但大域会超时/截断，成功才用。"""
    txt = _get(CT + "?q=" + urllib.parse.quote("%." + root) + "&output=json", CT_TIMEOUT)
    rows = json.loads(txt)          # 截断会抛异常 -> 上层当成失败
    out = []
    for row in rows:
        for field in ("name_value", "common_name"):
            for n in str(row.get(field, "")).split("\n"):
                n = n.strip().lower().lstrip("*").lstrip(".")
                if n.endswith("." + root):
                    out.append(n)
    return out


def subdomains(root):
    """多通道采集 + 本地缓存；任何一个通道失败都不影响另一个。"""
    os.makedirs(CACHE, exist_ok=True)
    cache = os.path.join(CACHE, root + ".json")
    if os.path.exists(cache) and time.time() - os.path.getmtime(cache) < 7 * 86400:
        try:
            return json.load(open(cache, encoding="utf-8"))
        except Exception:
            pass
    names = set()
    for fn in (_from_passive_dns, _from_ct):
        try:
            names.update(fn(root))
        except Exception:
            continue
    names = sorted(n for n in names if n and n != root)[:4000]
    if names:
        try:
            json.dump(names, open(cache, "w", encoding="utf-8"))
        except Exception:
            pass
    return names


def token_hit(host):
    root_tokens_count = host.count(".")
    labels = host.split(".")[:-2] if root_tokens_count >= 2 else []
    # 也覆盖二级 ccTLD（com.cn 这类）：退一步逐段判断
    cands = host.split(".")[:-2] if len(host.split(".")) > 2 else []
    for label in cands:
        for tok in re.split(r"[-_]", label):
            if tok in AD_TOKENS or TOKEN_RE.match(tok):
                return tok
    return None


def strong_prefix(host):
    """最左标签整词等于强前缀词 -> 视为品牌自有广告子域。

    排除带连字符的标签（ad-admin 这类多为广告主后台 / 企业 AD 域控），
    也排除出现在中间标签的情况（如 xxx.ad-cdn.com 不在此列）。
    """
    labels = host.split(".")
    if len(labels) < 3:
        return None
    left = labels[0]
    if "-" in left or "_" in left:
        return None
    return left if left in STRONG_PREFIX else None


def resolve(name):
    url = "%s?name=%s&type=A" % (DOH, name)
    req = urllib.request.Request(url, headers={"User-Agent": UA,
                                               "Accept": "application/dns-json"})
    try:
        with urllib.request.urlopen(req, timeout=DNS_TIMEOUT) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except Exception:
        return False, []
    if data.get("Status") != 0:
        return False, []
    chain = [str(a.get("data", "")).rstrip(".").lower()
             for a in (data.get("Answer") or []) if a.get("type") in (1, 28, 5)]
    return bool(chain), chain


def is_wildcard(root):
    probe = "noas-nx-%d.%s" % (abs(hash(root)) % 999983, root)
    exists, _ = resolve(probe)
    return exists


def main():
    roots = read_roots()
    if not roots:
        print("FAIL：lists/cn_roots.txt 为空")
        return 1
    allow = benign_set()

    # 滚动分批，避免 crt.sh 一次拉太多
    # 游标必须落在会被提交的目录里（cache/ 被 gitignore，放那里 CI 每次都会从头重跑）
    stamp = os.path.join(ROOT, "state", "ct_cursor.txt")
    os.makedirs(os.path.dirname(stamp), exist_ok=True)
    start = 0
    try:
        start = int(open(stamp, encoding="utf-8").read().strip())
    except Exception:
        start = 0
    batch = [roots[(start + i) % len(roots)] for i in range(min(ROOTS_PER_RUN, len(roots)))]
    os.makedirs(CACHE, exist_ok=True)
    with open(stamp, "w", encoding="utf-8") as f:
        f.write(str((start + ROOTS_PER_RUN) % len(roots)))

    # 1 · 证书透明度批量采集
    ct_map = {}
    with cf.ThreadPoolExecutor(max_workers=CT_WORKERS) as pool:
        futs = {pool.submit(subdomains, r): r for r in batch}
        for fut in cf.as_completed(futs):
            r = futs[fut]
            try:
                ct_map[r] = fut.result()
            except Exception:
                ct_map[r] = []

    # 2 · 词元过滤 + 广告前缀暴力枚举（两条通道合并）
    cands = []
    for root, names in ct_map.items():
        for host in names:
            if protected(host, allow):
                continue
            tok = token_hit(host)
            if tok:
                cands.append((host, tok))
    for root in roots:
        for host, tok in brute_candidates(root):
            if not protected(host, allow):
                cands.append((host, tok))
    cands = sorted(set(cands))

    # 3 · 泛解析识别（把"什么都解析得出来"的根域整批丢掉）
    probe_roots = sorted({r for r in roots})
    wild_roots = set()
    with cf.ThreadPoolExecutor(max_workers=DNS_WORKERS) as pool:
        futs = {pool.submit(is_wildcard, r): r for r in probe_roots}
        for fut in cf.as_completed(futs):
            r = futs[fut]
            try:
                if fut.result():
                    wild_roots.add(r)
            except Exception:
                continue
    cands = [(h, t) for h, t in cands if not any(h.endswith("." + r) for r in wild_roots)]

    # 4 · 存活 + 落点判定
    resolved = {}
    with cf.ThreadPoolExecutor(max_workers=DNS_WORKERS) as pool:
        futs = {pool.submit(resolve, h): (h, t) for h, t in cands}
        for fut in cf.as_completed(futs):
            h, t = futs[fut]
            try:
                exists, chain = fut.result()
            except Exception:
                continue
            if exists and chain:
                resolved[h] = {"token": t, "chain": chain}

    strong, watch = [], []
    for h, info in sorted(resolved.items()):
        chain_text = " ".join(info["chain"])
        if any(p in chain_text for p in PARKING_HINTS):
            continue
        hint = next((x for x in AD_CHAIN_HINTS if x in chain_text), None)
        if hint:
            strong.append((h, info["token"], hint))
        elif strong_prefix(h):
            # 词元就是 ad/ads/adx/splash 这类强前缀，且挂在品牌注册域下
            strong.append((h, info["token"], "prefix"))
        else:
            watch.append((h, info["token"]))

    ts = time.strftime("%Y-%m-%d")

    def previous(fn):
        """读上一轮产物：本轮没重新探到的条目保留，避免覆盖写把历史成果冲掉。"""
        out = {}
        p2 = os.path.join(LISTS, fn)
        if not os.path.exists(p2):
            return out
        for line in open(p2, encoding="utf-8"):
            if line.startswith("#") or not line.strip():
                continue
            cols = line.rstrip("\n").split("\t")
            if len(cols) >= 2 and "." in cols[0]:
                out[cols[0]] = cols[1:]
        return out

    probed = set(resolved)          # 本轮实测过的域名
    old_strong = previous("cn_ad_endpoints.txt")
    old_watch = previous("cn_ad_watch.txt")
    s_map = {h: (t, hint) for h, t, hint in strong}
    w_map = {h: t for h, t in watch}
    for h, cols in old_strong.items():
        if h not in probed and h not in s_map:
            s_map[h] = (cols[0] if cols else "", cols[2] if len(cols) > 2 else "prev")
    for h, cols in old_watch.items():
        if h not in probed and h not in w_map and h not in s_map:
            w_map[h] = cols[0] if cols else ""
    # 本轮确认存在的从观察池提升到端点表
    for h in s_map:
        w_map.pop(h, None)

    strong = [(h, t, hint) for h, (t, hint) in sorted(s_map.items())]
    watch = [(h, t) for h, t in sorted(w_map.items())]

    with open(os.path.join(LISTS, "cn_ad_endpoints.txt"), "w", encoding="utf-8") as f:
        f.write("# NoAS 国内 App 首方广告子域（高置信：解析链落在广告网络，或品牌自有广告子域）\n"
                "# 自动发现并累积，构建日期 %s；列：域名 / 命中词 / 证据（落点域名 或 prefix）\n" % ts)
        for h, t, hint in strong:
            f.write("%s\t%s\t%s\n" % (h, t, hint))

    with open(os.path.join(LISTS, "cn_ad_watch.txt"), "w", encoding="utf-8") as f:
        f.write("# NoAS 国内广告子域观察池（低置信：词元命中的中间标签、链上无广告落点）\n"
                "# 仅 mid/full 引入，lite 不用；累积，构建日期 %s\n" % ts)
        for h, t in watch:
            f.write("%s\t%s\n" % (h, t))

    os.makedirs(OUT, exist_ok=True)
    stats = {"generated": ts, "roots_total": len(roots), "roots_batch": batch,
             "wildcard_roots": sorted(wild_roots), "candidates": len(cands),
             "resolved": len(resolved), "strong": len(strong), "watch": len(watch),
             "strong_samples": [h for h, _, _ in strong[:20]]}
    json.dump(stats, open(os.path.join(OUT, "cn_ads.json"), "w", encoding="utf-8"),
              ensure_ascii=False, indent=1)
    print("国内广告子域发现：本轮根域 %d｜候选 %d｜解析成功 %d｜高置信 %d｜观察池 %d｜泛解析根域 %d" % (
        len(batch), len(cands), len(resolved), len(strong), len(watch), len(wild_roots)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
