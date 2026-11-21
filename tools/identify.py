#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""identify.py —— 让 AI 直接判定哪些域是广告，并直接写入对应档位表。

和 ai_classify.py 的区别：ai_classify 只出“建议文件”，等人来看；这里 AI 的裁决就是
最终裁决，直接落进规则表，不需要人工二次确认。

候选来源（都是“真实流量里出现过的域”，不是凭空猜）：
  1) --device <目录|CSV>  手机抓包/DNS 日志里真实发出的请求（含未被拦的），按次数排序
  2) --pool              上游观察池 cn_ad_watch.txt + ai_ads_suggest.txt
  3) --names a,b,c       手工指定（方便抽查）

AI 一次判一批（默认 25 域/次），直接输出每个域的：
  v = ad | tracker | benign | unknown     它认为是什么
  c = 0~100 置信
  t = lite | mid | full | none            它认为该放哪一档
裁决映射（不再打本地分数）：
  t=lite/mid 且 v in (ad,tracker) → lists/device_confirmed.txt（强制进 mid，不挤名额）
  t=full                         → lists/shadow.txt（只进 full，不拦，观察）
  其余（benign/unknown/none）     → state/identify_denied.json（永不再自动加）

硬边界（AI 也不能越过，一票否决，写进代码而不是靠提示词）：
  · 白名单父域、service_allow、telemetry：绝不进任何拦截档
  · 已在规则库里的域：不重复处理
  · 每日调用上限（默认 20 次）与单轮上限（默认 4 次），超了排队到明天

自动兜底：--verify 会在写盘后立刻跑良性回归，FP 一旦 >0 整批回滚。

用法：
  python3 tools/identify.py --pool --dry-run
  python3 tools/identify.py --device ~/logs --verify
  python3 tools/identify.py --revoke some.domain
"""
import argparse
import concurrent.futures as cf
import csv
import datetime
import json
import os
import pathlib
import re
import subprocess
import sys
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parent.parent
LISTS = ROOT / "lists"
STATE = ROOT / "state"
SUBS = ROOT / "subs"

ACC = os.environ.get("CF_ACCOUNT_ID", "226431c8f431ebb75d82dd5dbd5e8d86").strip()  # 账号 ID 非密钥，公开可查
TOK = os.environ.get("CF_API_TOKEN", "").strip()
MODEL = os.environ.get("AI_MODEL", "@cf/meta/llama-3.3-70b-instruct-fp8-fast").strip()
FALLBACK_MODEL = "@cf/meta/llama-3.1-8b-instruct"
BATCH = int(os.environ.get("AI_BATCH", "20"))
RUN_CAP = int(os.environ.get("AI_RUN_CALL_CAP", "4"))
DAY_CAP = int(os.environ.get("AI_DAY_CALL_CAP", "24"))

DCONF = LISTS / "device_confirmed.txt"
SHADOW = LISTS / "shadow.txt"
DENIED = STATE / "identify_denied.json"
REPORT = STATE / "identify.json"
USAGE = STATE / "ai_usage.json"
SHADOW_STATE = STATE / "shadow.json"

DOMAIN_RE = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$")
IPV4_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def today():
    return datetime.date.today().isoformat()


def read_first_col(path):
    out = set()
    if not path.exists():
        return out
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        s = line.split("#")[0].strip().lower()
        if s and DOMAIN_RE.match(s.split("\t")[0].strip()):
            out.add(s.split("\t")[0].strip())
    return out


def load_json(path, default):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return default



def token_hit(domain, tokens):
    """域名各段是否命中词元表（精确段匹配，避免 adsl 这类误命中）"""
    if not tokens:
        return False
    for seg in domain.split("."):
        if seg in tokens:
            return True
    return False


def parent_hit(domain, roots):
    """domain 本身或它的任一父域在 roots 里 → True"""
    d = domain
    while True:
        if d in roots:
            return True
        if "." not in d:
            return False
        d = d.split(".", 1)[1]
        if d.count(".") < 1:
            return d in roots


# ── 候选收集 ────────────────────────────────────────────────────────────────
def from_device(path):
    """从手机日志里取“真实发出的域”。返回 {domain: hits}。"""
    files = []
    p = pathlib.Path(os.path.expanduser(path))
    if p.is_dir():
        files = [f for f in p.rglob("*.csv")]
    elif p.exists():
        files = [p]
    counts = {}
    for f in files:
        try:
            with f.open("r", encoding="utf-8-sig", errors="ignore", newline="") as fh:
                sample = fh.read(2048)
                fh.seek(0)
                delim = "\t" if sample.count("\t") > sample.count(",") else ","
                head = None
                col = None
                for row in csv.reader(fh, delimiter=delim):
                    if head is None:
                        head = [h.strip().lower() for h in row]
                        for i, h in enumerate(head):
                            if h in ("host/查询", "host", "域名", "domain", "query", "主机/查询",
                                     "hostname", "fqdn", "url", "原始消息"):
                                col = i
                                break
                        continue
                    if col is None or col >= len(row):
                        continue
                    v = row[col].strip().lower()
                    if "://" in v:
                        v = v.split("://", 1)[1].split("/", 1)[0]
                    v = v.split(":", 1)[0].strip(".")
                    if not v or IPV4_RE.match(v) or not DOMAIN_RE.match(v):
                        continue
                    counts[v] = counts.get(v, 0) + 1
        except Exception:
            continue
    return counts


def from_pool():
    out = {}
    for name in ("cn_ad_watch.txt", "ai_ads_suggest.txt"):
        for d in read_first_col(LISTS / name):
            out[d] = out.get(d, 0) + 1
    return out


# ── AI 直判 ────────────────────────────────────────────────────────────────
ALI_KEY = (os.environ.get("DASHSCOPE_API_KEY") or os.environ.get("ALIYUN_API_KEY") or "").strip()
ALI_BASE = os.environ.get("ALI_BASE", "https://dashscope.aliyuncs.com/compatible-mode/v1").strip()
ALI_MODEL = os.environ.get("ALI_MODEL", "qwen3.5-turbo").strip()

DS_KEY = (os.environ.get("DEEPSEEK_API_KEY") or os.environ.get("DEEPSEEK_KEY") or "").strip()
DS_BASE = os.environ.get("DEEPSEEK_BASE", "https://api.deepseek.com").strip()
DS_MODEL = os.environ.get("DEEPSEEK_MODEL", "deepseek-chat").strip()

ARK_KEY = (os.environ.get("ARK_API_KEY") or os.environ.get("DOUBAO_API_KEY") or "").strip()
ARK_BASE = os.environ.get("ARK_BASE", "https://ark.cn-beijing.volces.com/api/v3").strip()
ARK_MODEL = os.environ.get("ARK_MODEL", "doubao-seed-1-6-250615").strip()


def ark_call(prompt, max_tokens=2000):
    body = json.dumps({"model": ARK_MODEL, "messages": [{"role": "user", "content": prompt}],
                       "max_tokens": max_tokens, "temperature": 0.1}).encode()
    req = urllib.request.Request(ARK_BASE.rstrip("/") + "/chat/completions", data=body,
                                 headers={"Authorization": "Bearer " + ARK_KEY,
                                          "Content-Type": "application/json"})
    d = json.loads(urllib.request.urlopen(req, timeout=90).read().decode())
    return ((d.get("choices") or [{}])[0].get("message") or {}).get("content", "")


def ds_call(prompt, max_tokens=2000):
    body = json.dumps({"model": DS_MODEL, "messages": [{"role": "user", "content": prompt}],
                       "max_tokens": max_tokens, "temperature": 0.1,
                       "response_format": {"type": "json_object"}}).encode()
    req = urllib.request.Request(DS_BASE.rstrip("/") + "/chat/completions", data=body,
                                 headers={"Authorization": "Bearer " + DS_KEY,
                                          "Content-Type": "application/json"})
    d = json.loads(urllib.request.urlopen(req, timeout=120).read().decode())
    return ((d.get("choices") or [{}])[0].get("message") or {}).get("content", "")


def ali_call(prompt, max_tokens=2000):
    """阿里云百炼（通义千问）OpenAI 兼容端点"""
    body = json.dumps({"model": ALI_MODEL, "messages": [{"role": "user", "content": prompt}],
                       "max_tokens": max_tokens, "temperature": 0.1}).encode()
    req = urllib.request.Request(ALI_BASE.rstrip("/") + "/chat/completions", data=body,
                                 headers={"Authorization": "Bearer " + ALI_KEY,
                                          "Content-Type": "application/json"})
    d = json.loads(urllib.request.urlopen(req, timeout=120).read().decode())
    return ((d.get("choices") or [{}])[0].get("message") or {}).get("content", "")


def ai_call(prompt, model, max_tokens=1200):
    if DS_KEY:
        try:
            return ds_call(prompt, max_tokens)
        except Exception:
            pass
    if ARK_KEY:
        try:
            return ark_call(prompt, max_tokens)
        except Exception:
            pass
    body = json.dumps({"messages": [{"role": "user", "content": prompt}],
                       "max_tokens": max_tokens}).encode()
    req = urllib.request.Request(
        "https://api.cloudflare.com/client/v4/accounts/%s/ai/run/%s" % (ACC, model),
        data=body, headers={"Authorization": "Bearer " + TOK, "Content-Type": "application/json"})
    d = json.loads(urllib.request.urlopen(req, timeout=60).read().decode())
    r = d.get("result") or {}
    if isinstance(r.get("response"), str):
        return r["response"]
    ch = (r.get("choices") or [{}])[0].get("message") or {}
    return ch.get("content") or ""


def parse_verdicts(text, allowed):
    m = re.search(r"\[[\s\S]*\]", text or "")
    if not m:
        return []
    try:
        raw = json.loads(m.group(0))
    except Exception:
        return []
    out = []
    for it in raw:
        if not isinstance(it, dict):
            continue
        d = str(it.get("d", "")).strip().lower()
        if d not in allowed:
            continue
        v = str(it.get("v", "unknown")).lower()
        t = str(it.get("t", "none")).lower()
        if v not in ("ad", "tracker", "benign", "unknown"):
            v = "unknown"
        if t not in ("lite", "mid", "full", "none"):
            t = "none"
        try:
            c = max(0, min(100, int(it.get("c", 0))))
        except Exception:
            c = 0
        out.append({"d": d, "v": v, "c": c, "t": t})
    return out


def judge(domains, hits):
    """把候选分批交给 AI，返回 (verdicts, calls, model_used, err)"""
    verdicts, calls, used_model, err = [], 0, MODEL, ""
    trusted = bool(ARK_KEY)
    if not (ACC and TOK) and not ARK_KEY and not DS_KEY and not ALI_KEY:
        return verdicts, 0, "", "缺少 CF_ACCOUNT_ID / CF_API_TOKEN，AI 直判不可用"
    usage = load_json(USAGE, {})
    day = today()
    used = int(usage.get(day, 0))
    if used >= DAY_CAP:
        return verdicts, 0, "", "今日 AI 调用已达上限 %d/%d" % (used, DAY_CAP)

    for i in range(0, len(domains), BATCH):
        if calls >= RUN_CAP or used + calls >= DAY_CAP:
            break
        chunk = domains[i:i + BATCH]
        lines = []
        for d in chunk:
            l = d
            if d.count(".") >= 3 and re.search(r"\d", d.split(".")[0]):
                l += "   (子域含数字/随机串，可能是动态拼接)"
            lines.append("%s   请求次数=%d" % (l, hits.get(d, 0)))
        prompt = (
            "任务：给下面这些真实设备请求过的域名打标签，决定它要不要进广告拦截规则。\n"
            "输出格式（只输出 JSON 数组，不要任何解释）：\n"
            '[{"d":"域名","v":"ad|tracker|benign|unknown","c":0-100,"t":"lite|mid|full|none"}]\n'
            "字段含义：v=这个域是什么；c=置信度(0-100，整数)；t=放进哪一档。\n"
            "v 与 t 的对应关系（必须一致，不许出现 v=ad 但 t=none 这种矛盾）：\n"
            "- v=ad 或 tracker 且能确证、请求频繁 → t=lite\n"
            "- v=ad 或 tracker 且能确证但不算高频 → t=mid\n"
            "- v=unknown（像广告但没把握） → t=full（只记录不拦）\n"
            "- v=benign（正常业务） → t=none\n"
            "v 的判定口径：\n"
            "ad=广告请求、素材、曝光/点击上报、归因、开屏、激励视频、信息流广告位、联盟 SDK 接口\n"
            "tracker=埋点、行为统计、设备信息采集、A/B 实验上报、第三方统计\n"
            "benign=官网、登录、支付、内容分发、客服、系统更新、公开 CDN 静态资源、应用商店\n"
            "unknown=域名像广告但没有足够证据\n"
            "示例：\n"
            '[{"d":"ads.example-app.cn","v":"ad","c":92,"t":"mid"},'
            '{"d":"track.toutiao.com","v":"tracker","c":88,"t":"lite"},'
            '{"d":"cdn.jsdelivr.net","v":"benign","c":95,"t":"none"},'
            '{"d":"a1b2c3.xn--xyz.com","v":"unknown","c":40,"t":"full"}]\n'
            "待判域名（域名   请求次数）：\n" + "\n".join(lines)
        )
        # 判定源优先级：DeepSeek > 豆包 Ark > CF（70B 优先，8B 兜底）
        if DS_KEY:
            providers = [("deepseek", lambda: ds_call(prompt))]
        elif ALI_KEY:
            providers = [("aliyun", lambda: ali_call(prompt))]
        elif ARK_KEY:
            providers = [("ark", lambda: ark_call(prompt))]
        else:
            providers = [(used_model, lambda m=used_model: ai_call(prompt, m))]
            if used_model != FALLBACK_MODEL:
                providers.append((FALLBACK_MODEL, lambda: ai_call(prompt, FALLBACK_MODEL)))
        got = []
        for pname, fn in providers:
            try:
                raw = fn()
                if os.environ.get("IDENTIFY_DEBUG"):
                    print("[debug] %s -> %s" % (pname, raw[:500]))
                got = parse_verdicts(raw, set(chunk))
                calls += 1
                used_model = pname
                break
            except Exception as e:
                err = "%s: %s" % (pname, type(e).__name__)
                calls += 1
        verdicts.extend(got)
    usage[day] = used + calls
    USAGE.write_text(json.dumps(usage, ensure_ascii=False, indent=1), encoding="utf-8")
    return verdicts, calls, used_model, err


# ── 写入 ────────────────────────────────────────────────────────────────────
def append_block(path, domains, header):
    if not domains:
        return
    old = path.read_text(encoding="utf-8") if path.exists() else ""
    if not old.endswith("\n") and old:
        old += "\n"
    path.write_text(old + header + "\n" + "\n".join(sorted(domains)) + "\n", encoding="utf-8")


def revoke(domain):
    removed = []
    for p in (DCONF, SHADOW):
        if not p.exists():
            continue
        lines = p.read_text(encoding="utf-8").splitlines()
        keep = [l for l in lines if l.split("#")[0].strip().lower() != domain]
        if len(keep) != len(lines):
            p.write_text("\n".join(keep) + "\n", encoding="utf-8")
            removed.append(p.name)
    denied = load_json(DENIED, {})
    denied[domain] = {"v": "benign", "c": 100, "t": "none", "ts": today(), "by": "manual-revoke"}
    DENIED.write_text(json.dumps(denied, ensure_ascii=False, indent=1), encoding="utf-8")
    print("已撤销 %s（%s），并加入永久否决" % (domain, ",".join(removed) or "仅否决"))
    return 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--device", help="手机日志目录或 CSV")
    ap.add_argument("--pool", action="store_true", help="上游观察池")
    ap.add_argument("--names", help="逗号分隔的手工域名")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--verify", action="store_true", help="写盘后跑良性回归，FP>0 自动回滚")
    ap.add_argument("--revoke", help="撤销某域并永久否决")
    ap.add_argument("--export", help="只导出候选清单（含特征），交给主脑模型判定")
    ap.add_argument("--verdicts", help="读取主脑模型的判定 JSON（跳过外部 AI 调用）")
    ap.add_argument("--promote", action="store_true", help="把观察期满的影子域转正进 mid")
    a = ap.parse_args()

    if a.revoke:
        return revoke(a.revoke.strip().lower())

    if a.promote:
        days = int(os.environ.get("SHADOW_DAYS", "3"))
        st = load_json(SHADOW_STATE, {})
        in_shadow = read_first_col(SHADOW)
        ready, kept = [], []
        for d in in_shadow:
            first = (st.get(d) or {}).get("first_seen", today())
            try:
                age = (datetime.date.fromisoformat(today()) - datetime.date.fromisoformat(first)).days
            except Exception:
                age = 0
            (ready if age >= days else kept).append(d)
        if not ready:
            print("影子转正：观察期未满，0 条可转（共 %d 条在观察）" % len(kept))
            return 0
        SHADOW.write_text("# 影子观察（只进 full，不拦）\n" + "\n".join(sorted(kept)) + "\n", encoding="utf-8")
        append_block(DCONF, ready, "# 影子转正 %s（观察满 %d 天）" % (today(), days))
        print("影子转正：%d 条进 mid（%s）｜留在观察 %d 条" % (len(ready), ", ".join(sorted(ready)[:6]), len(kept)))
        return 0

    cand = {}
    if a.device:
        cand.update(from_device(a.device))
    if a.pool:
        for d, n in from_pool().items():
            cand[d] = max(cand.get(d, 0), n)
    if a.names:
        for d in a.names.split(","):
            d = d.strip().lower()
            if DOMAIN_RE.match(d):
                cand[d] = cand.get(d, 0)

    if not cand:
        print("没有候选。用 --device / --pool / --names 指定来源。")
        return 0

    # 硬边界
    wl = read_first_col(LISTS / "whitelist.txt")
    allow = read_first_col(LISTS / "service_allow.txt")
    tele = read_first_col(LISTS / "telemetry.txt")
    # 良性大盘与流行根域：这两张表是"全站主业务域"，AI 就算判成广告也不许进拦截档
    benign = read_first_col(LISTS / "benign_top.txt") | read_first_col(LISTS / "popular_roots.txt")
    exist = set()
    for t in ("lite", "mid", "full"):
        exist |= read_first_col(SUBS / t / "domains.txt")
    exist |= read_first_col(DCONF) | read_first_col(SHADOW)
    denied = load_json(DENIED, {})

    skipped = {"白名单/服务放行/遥测": 0, "已在规则库": 0, "已否决": 0}
    todo = {}
    for d, n in cand.items():
        if (parent_hit(d, wl) or parent_hit(d, allow) or d in tele
                or parent_hit(d, benign)):
            skipped["白名单/服务放行/遥测"] += 1
            continue
        if d in exist:
            skipped["已在规则库"] += 1
            continue
        if d in denied:
            skipped["已否决"] += 1
            continue
        todo[d] = n

    ranked = sorted(todo, key=lambda d: (-todo[d], d))
    print("候选 %d｜硬边界剔除 %s｜待判 %d" % (len(cand), skipped, len(ranked)))

    if a.export:
        ad_tok = {l.split("#")[0].strip().lower() for l in (LISTS / "ad_tokens.txt").read_text(encoding="utf-8").splitlines()}
        biz_tok = {l.split("#")[0].strip().lower() for l in (LISTS / "biz_tokens.txt").read_text(encoding="utf-8").splitlines()}
        known_ad = (read_first_col(LISTS / "core_ad_networks.txt") | read_first_col(LISTS / "sdk_ads.txt")
                    | read_first_col(LISTS / "ad_endpoints.txt") | read_first_col(LISTS / "cn_ad_endpoints.txt"))
        rows = []
        for d in ranked:
            root = ".".join(d.split(".")[-2:])
            rows.append({"d": d, "hits": todo[d], "root": root,
                         "ad_token": token_hit(d, ad_tok), "biz_token": token_hit(d, biz_tok),
                         "known_ad": parent_hit(d, known_ad)})
        pathlib.Path(os.path.expanduser(a.export)).write_text(
            json.dumps(rows, ensure_ascii=False, indent=1), encoding="utf-8")
        print("已导出 %d 个候选 → %s" % (len(rows), a.export))
        return 0

    if a.verdicts:
        raw = json.loads(pathlib.Path(os.path.expanduser(a.verdicts)).read_text(encoding="utf-8"))
        verdicts = [x for x in raw if isinstance(x, dict) and x.get("d") in todo]
        calls, model_used, err = 0, "main-brain", ""
    else:
        verdicts, calls, model_used, err = judge(ranked, todo)
    if err:
        print("AI 提示：%s" % err)

    conf, shadow, deny = [], [], []
    HOT = int(os.environ.get("IDENTIFY_CONF_HITS", "5"))
    ad_tok = {l.split("#")[0].strip().lower() for l in (LISTS / "ad_tokens.txt").read_text(encoding="utf-8").splitlines()}
    biz_tok = {l.split("#")[0].strip().lower() for l in (LISTS / "biz_tokens.txt").read_text(encoding="utf-8").splitlines()}
    known_ad = (read_first_col(LISTS / "core_ad_networks.txt") | read_first_col(LISTS / "sdk_ads.txt")
                | read_first_col(LISTS / "ad_endpoints.txt") | read_first_col(LISTS / "cn_ad_endpoints.txt"))
    for it in verdicts:
        d = it["d"]
        if it["v"] in ("ad", "tracker") and it["t"] in ("lite", "mid"):
            # AI 说该拦 ≠ 就能直接进 mid。三个条件同时成立才升级：
            #   1) 真实高频请求（≥HOT 次）  2) 名字带广告词元且不带业务词元，或根域已知广告网络  3) AI 置信 ≥85
            name_ad = token_hit(d, ad_tok) and not token_hit(d, biz_tok)
            if model_used == "main-brain":
                # 主脑模型逐条审过，不再用词元闸兜底；只要求置信达标 + 有真实请求痕迹
                ok = it["c"] >= 85 and (todo.get(d, 0) >= 3 or parent_hit(d, known_ad))
            elif DS_KEY or ALI_KEY or ARK_KEY or "70b" in (model_used or "").lower():
                # 豆包接口判：可信，但保留词元/已知网络作为结构证据
                ok = (todo.get(d, 0) >= HOT and it["c"] >= 85
                      and (name_ad or parent_hit(d, known_ad)))
            else:
                # 兜底小模型（CF llama）不可直接进 mid：它把业务 API 判成广告的实录太多，
                # 只放行"广告词元 + 已知广告网络 + 高频"三重确证。
                ok = (todo.get(d, 0) >= HOT and it["c"] >= 85 and name_ad
                      and parent_hit(d, known_ad))
            if ok:
                conf.append(d)
            else:
                shadow.append(d)
        elif it["t"] == "full" or it["v"] == "unknown":
            shadow.append(it["d"])
        else:
            deny.append(it)

    if a.dry_run:
        print("AI 直判 %d 个（调用 %d 次，模型 %s）" % (len(verdicts), calls, model_used or "-"))
        for group, name in ((conf, "进 mid（强制）"), (shadow, "仅 full 观察"), ([x["d"] for x in deny], "否决")):
            print("%s %d 条：%s" % (name, len(group), ", ".join(group[:12]) + (" …" if len(group) > 12 else "")))
        return 0

    backup = None
    if a.verify and (conf or shadow):
        backup = {p: p.read_text(encoding="utf-8") if p.exists() else "" for p in (DCONF, SHADOW)}

    stamp = "# AI 直判 %s  model=%s  calls=%d" % (today(), model_used or "-", calls)
    append_block(DCONF, conf, stamp)
    append_block(SHADOW, shadow, stamp)

    sstate = load_json(SHADOW_STATE, {})
    for d in shadow:
        sstate.setdefault(d, {"first_seen": today()})
    for d in deny:
        denied[d["d"]] = dict(d, ts=today(), by="ai")
    SHADOW_STATE.write_text(json.dumps(sstate, ensure_ascii=False, indent=1), encoding="utf-8")
    DENIED.write_text(json.dumps(denied, ensure_ascii=False, indent=1), encoding="utf-8")
    REPORT.write_text(json.dumps({
        "ts": today(), "candidates": len(cand), "judged": len(verdicts), "calls": calls,
        "model": model_used, "confirmed": sorted(conf), "shadow": sorted(shadow),
        "denied": [x["d"] for x in deny], "skipped": skipped, "error": err,
    }, ensure_ascii=False, indent=1), encoding="utf-8")

    print("AI 直判完成：调用 %d 次｜强制进 mid %d｜仅 full %d｜否决 %d"
          % (calls, len(conf), len(shadow), len(deny)))

    if a.verify and backup:
        r = subprocess.run([sys.executable, str(ROOT / "tests" / "benign_fp.py")],
                           capture_output=True, text=True)
        print(r.stdout.strip().splitlines()[-1] if r.stdout.strip() else "")
        if "误伤率 0.0000%" not in r.stdout and "误伤 0" not in r.stdout:
            for p, txt in backup.items():
                p.write_text(txt, encoding="utf-8")
            print("良性回归出现误伤，已整批回滚")
            return 1
        print("良性回归通过，裁决保留")
    return 0


if __name__ == "__main__":
    sys.exit(main())
