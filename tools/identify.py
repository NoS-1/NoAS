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
  v=benign 且 c>=90             → lists/ai_whitelist.txt（精准白名单：编译期放行 + 父域保护）
  t=lite/mid 且 v in (ad,tracker) → lists/device_confirmed.txt（黑名单，强制进拦截）
  t=full 或 v=unknown           → lists/shadow.txt（只记录不拦，观察）
  其余                         → state/identify_denied.json（永不再自动加）

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
import urllib.error
import urllib.request


def _load_local_creds():
    """裸机本地运行时自动加载 ~/.noas/creds.env（不覆盖已有环境变量；CI 无此文件则跳过）。"""
    p = os.path.expanduser("~/.noas/creds.env")
    if not os.path.exists(p):
        return
    for line in open(p, encoding="utf-8"):
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        k, v = k.strip(), v.strip().strip('"').strip("'")
        if k and k not in os.environ:
            os.environ[k] = v


_load_local_creds()

ROOT = pathlib.Path(__file__).resolve().parent.parent
LISTS = ROOT / "lists"
STATE = ROOT / "state"

# ── 判定源休眠（额度用完自动休眠，下次再来）────────────────────────────
AI_COOLDOWN = STATE / "ai_cooldown.json"


def _cool_read():
    try:
        return json.loads(AI_COOLDOWN.read_text(encoding="utf-8"))
    except Exception:
        return {}


def cool_active(name):
    e = (_cool_read().get(name) or {})
    try:
        return datetime.datetime.fromisoformat(str(e.get("until", ""))) > datetime.datetime.now()
    except Exception:
        return False


def cool_remaining(name):
    e = (_cool_read().get(name) or {})
    try:
        d = datetime.datetime.fromisoformat(str(e.get("until", ""))) - datetime.datetime.now()
        return max(0, int(d.total_seconds() // 60))
    except Exception:
        return 0


def cool_mark(name, minutes, reason):
    d = _cool_read()
    until = (datetime.datetime.now() + datetime.timedelta(minutes=minutes)).isoformat(timespec="seconds")
    d[name] = {"until": until, "minutes": minutes, "reason": str(reason)[:140],
               "marked_at": datetime.datetime.now().isoformat(timespec="seconds")}
    try:
        AI_COOLDOWN.parent.mkdir(parents=True, exist_ok=True)
        AI_COOLDOWN.write_text(json.dumps(d, ensure_ascii=False, indent=1), encoding="utf-8")
    except Exception:
        pass
    print("  [休眠] %s：额度/鉴权休止，%d 分钟后自动恢复（下次运行再来）" % (name, minutes),
          file=sys.stderr, flush=True)


def quota_sleep_minutes(err):
    """错误归类：余额/欠费 24h，限流 3h，鉴权 24h，其余不休眠。"""
    t = str(err).lower()
    if any(k in t for k in ("402", "30001", "insufficient", "balance", "quota", "overdue", "exhaust")):
        return 24 * 60
    if "429" in t or "rate limit" in t or "too many" in t:
        return 3 * 60
    if any(k in t for k in ("401", "403", "invalid api", "incorrect api")):
        return 24 * 60
    return 0


SUBS = ROOT / "subs"

ACC = os.environ.get("CF_ACCOUNT_ID", "226431c8f431ebb75d82dd5dbd5e8d86").strip()  # 账号 ID 非密钥，公开可查
TOK = os.environ.get("CF_API_TOKEN", "").strip()
MODEL = os.environ.get("AI_MODEL", "@cf/meta/llama-3.3-70b-instruct-fp8-fast").strip()
FALLBACK_MODEL = "@cf/meta/llama-3.1-8b-instruct"
BATCH = int(os.environ.get("AI_BATCH", "10"))
RUN_CAP = int(os.environ.get("AI_RUN_CALL_CAP", "4"))
DAY_CAP = int(os.environ.get("AI_DAY_CALL_CAP", "24"))

DCONF = LISTS / "device_confirmed.txt"
SHADOW = LISTS / "shadow.txt"
AIWL = LISTS / "ai_whitelist.txt"
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
ZP_KEY = (os.environ.get("ZHIPU_API_KEY") or os.environ.get("GLM_API_KEY") or os.environ.get("BIGMODEL_API_KEY") or "").strip()
ZP_BASE = os.environ.get("ZP_BASE", "https://open.bigmodel.cn/api/paas/v4").strip()
# 用户指定主用 glm-4.7-flash；若它繁忙(1305)/限流/不可用，自动按 ZP_FALLBACK_MODELS 降级并记住可用模型
ZP_MODEL = os.environ.get("ZP_MODEL", "glm-4.7-flash").strip()
ZP_FALLBACKS = [m.strip() for m in
                os.environ.get("ZP_FALLBACK_MODELS", "glm-5.3-flash").split(",") if m.strip()]
ZP_MODELS = [ZP_MODEL] + [m for m in ZP_FALLBACKS if m and m != ZP_MODEL]
_ZP_GOOD = {"model": None}

ALI_KEY = (os.environ.get("DASHSCOPE_API_KEY") or os.environ.get("ALIYUN_API_KEY") or "").strip()
ALI_BASE = os.environ.get("ALI_BASE", "https://dashscope.aliyuncs.com/compatible-mode/v1").strip()
ALI_MODEL = os.environ.get("ALI_MODEL", "qwen3.5-turbo").strip()

DS_KEY = (os.environ.get("DEEPSEEK_API_KEY") or os.environ.get("DEEPSEEK_KEY") or "").strip()
DS_BASE = os.environ.get("DEEPSEEK_BASE", "https://api.deepseek.com").strip()
DS_MODEL = os.environ.get("DEEPSEEK_MODEL", "deepseek-chat").strip()

ARK_KEY = (os.environ.get("ARK_API_KEY") or os.environ.get("DOUBAO_API_KEY") or "").strip()
ARK_BASE = os.environ.get("ARK_BASE", "https://ark.cn-beijing.volces.com/api/v3").strip()
ARK_MODEL = os.environ.get("ARK_MODEL", "doubao-seed-1-6-250615").strip()

SF_KEY = (os.environ.get("SILICONFLOW_API_KEY") or os.environ.get("SF_API_KEY") or "").strip()
SF_BASE = os.environ.get("SF_BASE", "https://api.siliconflow.cn/v1").strip()
# 2026-11 实测 Qwen/Qwen3.5-9B 可用（默认带思考，sf_call 给足预算）；失败按 SF_FALLBACK_MODELS 降级并记忆
SF_MODEL = os.environ.get("SF_MODEL", "Qwen/Qwen3.5-9B").strip()
SF_FALLBACKS = [m.strip() for m in os.environ.get(
    "SF_FALLBACK_MODELS", "Qwen/Qwen3-8B,Qwen/Qwen2.5-7B-Instruct,THUDM/GLM-4-9B-0414").split(",") if m.strip()]
SF_MODELS = [SF_MODEL] + [m for m in SF_FALLBACKS if m and m != SF_MODEL]
_SF_GOOD = {"model": None}
_SF_DEAD = {"dead": False}  # 402 余额不足属账户级，一次判定后本进程不再尝试

# 百度千帆 v2（OpenAI 兼容；Bearer 直接放 bce-v3/ALTAK-... 形式的 API Key）
QF_KEY = (os.environ.get("QIANFAN_API_KEY") or os.environ.get("QIANFAN_AK") or "").strip()
QF_BASE = os.environ.get("QF_BASE", "https://qianfan.baidubce.com/v2").strip()
QF_MODEL = os.environ.get("QF_MODEL", "ernie-light-dt-1.0").strip()  # ERNIE 轻量免费系，实测出文正常
QF_FALLBACKS = [m.strip() for m in os.environ.get(
    "QF_FALLBACK_MODELS", "ernie-5.5-flash-preview,qwen3.5-27b,glm-5.3-flash").split(",") if m.strip()]
QF_MODELS = [QF_MODEL] + [m for m in QF_FALLBACKS if m and m != QF_MODEL]
_QF_GOOD = {"model": None}
_QF_DEAD = {"dead": False}

# GitHub Models（GitHub 官方免费模型网关，走 GH_PAT 鉴权；质量远高于 Workers AI 小模型）
GH_KEY = (os.environ.get("GITHUB_MODELS_TOKEN") or os.environ.get("GH_PAT") or os.environ.get("GITHUB_TOKEN") or "").strip()
GH_BASE = os.environ.get("GH_MODELS_BASE", "https://models.github.ai/inference").strip()
GH_MODEL = os.environ.get("GH_MODEL", "openai/gpt-4o-mini").strip()
GH_FALLBACKS = [m.strip() for m in os.environ.get(
    "GH_FALLBACK_MODELS", "openai/gpt-4.1-mini,openai/gpt-4.1,deepseek/DeepSeek-V3").split(",") if m.strip()]
GH_MODELS = [GH_MODEL] + [m for m in GH_FALLBACKS if m and m != GH_MODEL]
_GH_GOOD = {"model": None}
_GH_DEAD = {"dead": False}

# OpenRouter 免费模型（:free 后缀 = $0 计价，20 RPM / 50 RPD；境外网络下可用，本地不配则跳过）
OR_KEY = (os.environ.get("OPENROUTER_API_KEY") or "").strip()
OR_BASE = os.environ.get("OPENROUTER_BASE", "https://openrouter.ai/api/v1").strip()
OR_MODELS = [m.strip() for m in os.environ.get(
    "OPENROUTER_MODELS",
    "baidu/ernie-5.5-flash-preview:free,nvidia/nemotron-3.5-super-vl:free").split(",") if m.strip()]
_OR_GOOD = {"model": None}
_OR_DEAD = {"dead": False}

# Groq 免费档（30 RPM / 1000 次每天，OpenAI 兼容；低延迟，境外网络下可用）
GR_KEY = (os.environ.get("GROQ_API_KEY") or "").strip()
GR_BASE = os.environ.get("GROQ_BASE", "https://api.groq.com/openai/v1").strip()
GR_MODELS = [m.strip() for m in os.environ.get(
    "GROQ_MODELS", "openai/gpt-oss-120b,qwen/qwen3.8-27b").split(",") if m.strip()]
_GR_GOOD = {"model": None}
_GR_DEAD = {"dead": False}


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


def _zp_once(prompt, model, mt):
    body = json.dumps({"model": model, "messages": [{"role": "user", "content": prompt}],
                       "max_tokens": mt, "temperature": 0.1}).encode()
    req = urllib.request.Request(ZP_BASE.rstrip("/") + "/chat/completions", data=body,
                                 headers={"Authorization": "Bearer " + ZP_KEY,
                                          "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=120) as r:
        d = json.loads(r.read().decode())
    ch = (d.get("choices") or [{}])[0]
    return (ch.get("message") or {}).get("content", "") or ""


def zp_call(prompt, max_tokens=2000):
    """智谱 OpenAI 兼容端点。主模型 glm-4.7-flash；失败/空内容自动降级备用模型。

    glm-5.x 始终开启思考，reasoning 会吃 max_tokens，故对 5.x 强制 ≥6000 预算并在首次空内容时 1.5x 重试；
    4.7-flash 为普通对话模型，按批次给足 JSON 输出预算即可。某个模型一旦成功就被记住，后续批次优先复用，
    避免每批都先在繁忙主模型上等超时。全部模型失败时抛出最后一个异常，交由上层重试。
    """
    order = list(ZP_MODELS)
    if _ZP_GOOD["model"] in order:
        order = [_ZP_GOOD["model"]] + [m for m in order if m != _ZP_GOOD["model"]]
    last_err = None
    for idx, model in enumerate(order):
        think = model.startswith("glm-5")
        mt = max(int(max_tokens), 6000) if think else max(int(max_tokens), 4000)
        try:
            txt = _zp_once(prompt, model, mt)
            if not txt.strip() and think:
                txt = _zp_once(prompt, model, int(mt * 1.5))
            if txt.strip():
                if idx > 0 or model != ZP_MODEL:
                    print("  [zhipu] 实际使用模型 %s（主模型 %s 不可用或已降级）" % (model, ZP_MODEL),
                          file=sys.stderr, flush=True)
                _ZP_GOOD["model"] = model
                return txt
            last_err = "empty content"
        except Exception as e:  # 1305 繁忙 / 429 / 5xx / 超时 / 参数：都尝试下一个模型
            last_err = e
            print("  [zhipu] %s 调用失败，尝试下一模型：%r" % (model, e), file=sys.stderr, flush=True)
    raise RuntimeError("all zhipu models failed: %r" % (last_err,))


def ali_call(prompt, max_tokens=2000):
    """阿里云百炼（通义千问）OpenAI 兼容端点"""
    body = json.dumps({"model": ALI_MODEL, "messages": [{"role": "user", "content": prompt}],
                       "max_tokens": max_tokens, "temperature": 0.1}).encode()
    req = urllib.request.Request(ALI_BASE.rstrip("/") + "/chat/completions", data=body,
                                 headers={"Authorization": "Bearer " + ALI_KEY,
                                          "Content-Type": "application/json"})
    d = json.loads(urllib.request.urlopen(req, timeout=120).read().decode())
    return ((d.get("choices") or [{}])[0].get("message") or {}).get("content", "")


def _sf_once(prompt, model, mt):
    body = json.dumps({"model": model, "messages": [{"role": "user", "content": prompt}],
                       "max_tokens": mt, "temperature": 0.1}).encode()
    req = urllib.request.Request(SF_BASE.rstrip("/") + "/chat/completions", data=body,
                                 headers={"Authorization": "Bearer " + SF_KEY,
                                          "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=120) as r:
        d = json.loads(r.read().decode())
    ch = (d.get("choices") or [{}])[0]
    return ((ch.get("message") or {}).get("content", "") or "")


def sf_call(prompt, max_tokens=2000):
    """硅基流动 OpenAI 兼容端点：模型链降级 + 进程内记忆；思考模型也给足输出预算，空内容扩容重试一次。"""
    order = list(SF_MODELS)
    if _SF_GOOD["model"] in order:
        order = [_SF_GOOD["model"]] + [m for m in order if m != _SF_GOOD["model"]]
    last_err = None
    for idx, model in enumerate(order):
        mt = max(int(max_tokens), 6000)
        try:
            txt = _sf_once(prompt, model, mt)
            if not txt.strip():
                txt = _sf_once(prompt, model, int(mt * 1.5))
            if txt.strip():
                if idx > 0 or model != SF_MODEL:
                    print("  [siliconflow] 实际使用模型 %s（主模型 %s 不可用或已降级）" % (model, SF_MODEL),
                          file=sys.stderr, flush=True)
                _SF_GOOD["model"] = model
                return txt
            last_err = "empty content"
        except urllib.error.HTTPError as e:
            body = ""
            try:
                body = e.read().decode()[:200]
            except Exception:
                pass
            if e.code in (401, 402, 403):
                # 鉴权/计费是账户级问题，换模型无意义，立即上抛交由上层熔断/提示
                if e.code == 402:
                    _SF_DEAD["dead"] = True
                raise RuntimeError("siliconflow %s 账户/鉴权错误 HTTP%s %s" % (model, e.code, body)) from None
            last_err = e
            print("  [siliconflow] %s HTTP%s，尝试下一模型" % (model, e.code), file=sys.stderr, flush=True)
        except Exception as e:  # 5xx/超时/参数：尝试下一模型
            last_err = e
            print("  [siliconflow] %s 调用失败，尝试下一模型：%r" % (model, e), file=sys.stderr, flush=True)
    raise RuntimeError("all siliconflow models failed: %r" % (last_err,))


def _qf_once(prompt, model, mt):
    body = json.dumps({"model": model, "messages": [{"role": "user", "content": prompt}],
                       "max_tokens": mt, "temperature": 0.1}).encode()
    req = urllib.request.Request(QF_BASE.rstrip("/") + "/chat/completions", data=body,
                                 headers={"Authorization": "Bearer " + QF_KEY,
                                          "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=120) as r:
        d = json.loads(r.read().decode())
    ch = (d.get("choices") or [{}])[0]
    return ((ch.get("message") or {}).get("content", "") or "")


def qianfan_call(prompt, max_tokens=2000):
    """百度千帆 v2（OpenAI 兼容）。ERNIE 轻量系为长期免费档，作为主力免费源。
    模型链降级 + 进程内记忆；401/402/403 为账户级错误立即上抛熔断。"""
    order = list(QF_MODELS)
    if _QF_GOOD["model"] in order:
        order = [_QF_GOOD["model"]] + [m for m in order if m != _QF_GOOD["model"]]
    last_err = None
    for idx, model in enumerate(order):
        mt = max(int(max_tokens), 1200)
        try:
            txt = _qf_once(prompt, model, mt)
            if not txt.strip():
                txt = _qf_once(prompt, model, int(mt * 1.5))
            if txt.strip():
                if idx > 0 or model != QF_MODEL:
                    print("  [qianfan] 实际使用模型 %s（主模型 %s 不可用或已降级）" % (model, QF_MODEL),
                          file=sys.stderr, flush=True)
                _QF_GOOD["model"] = model
                return txt
            last_err = "empty content"
        except urllib.error.HTTPError as e:
            body = ""
            try:
                body = e.read().decode()[:200]
            except Exception:
                pass
            if e.code in (401, 402, 403):
                if e.code in (402, 403):
                    _QF_DEAD["dead"] = True
                raise RuntimeError("qianfan %s 账户/鉴权错误 HTTP%s %s" % (model, e.code, body)) from None
            last_err = e
            print("  [qianfan] %s HTTP%s，尝试下一模型" % (model, e.code), file=sys.stderr, flush=True)
        except Exception as e:
            last_err = e
            print("  [qianfan] %s 调用失败，尝试下一模型：%r" % (model, e), file=sys.stderr, flush=True)
    raise RuntimeError("all qianfan models failed: %r" % (last_err,))


def _gh_once(prompt, model, mt):
    body = json.dumps({"model": model, "messages": [{"role": "user", "content": prompt}],
                       "max_tokens": mt, "temperature": 0}).encode()
    req = urllib.request.Request(GH_BASE.rstrip("/") + "/chat/completions", data=body,
                                 headers={"Authorization": "Bearer " + GH_KEY,
                                          "Accept": "application/json",
                                          "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=120) as r:
        d = json.loads(r.read().decode())
    ch = (d.get("choices") or [{}])[0]
    return ((ch.get("message") or {}).get("content", "") or "")


def gh_call(prompt, max_tokens=2000):
    """GitHub Models（OpenAI 兼容）。temperature=0 保证同一域名判定可复现；
    free 计划有每分钟/每日限额，遇 429 抛错交由上层退避或换源。"""
    order = list(GH_MODELS)
    if _GH_GOOD["model"] in order:
        order = [_GH_GOOD["model"]] + [m for m in order if m != _GH_GOOD["model"]]
    last_err = None
    for idx, model in enumerate(order):
        mt = max(int(max_tokens), 1200)
        try:
            txt = _gh_once(prompt, model, mt)
            if txt.strip():
                if idx > 0 or model != GH_MODEL:
                    print("  [github-models] 实际使用 %s（主模型 %s 不可用或已降级）" % (model, GH_MODEL),
                          file=sys.stderr, flush=True)
                _GH_GOOD["model"] = model
                return txt
            last_err = "empty content"
        except urllib.error.HTTPError as e:
            body = ""
            try:
                body = e.read().decode()[:200]
            except Exception:
                pass
            if e.code in (401, 403):
                _GH_DEAD["dead"] = True
                raise RuntimeError("github-models %s 鉴权失败 HTTP%s %s" % (model, e.code, body)) from None
            last_err = e
            print("  [github-models] %s HTTP%s，尝试下一模型" % (model, e.code), file=sys.stderr, flush=True)
        except Exception as e:
            last_err = e
            print("  [github-models] %s 调用失败：%r" % (model, e), file=sys.stderr, flush=True)
    raise RuntimeError("all github models failed: %r" % (last_err,))



def _oai_once(base, key, model, prompt, mt, extra=None):
    body = json.dumps({"model": model, "messages": [{"role": "user", "content": prompt}],
                       "max_tokens": max(1200, int(mt)), "temperature": 0}).encode()
    h = {"Authorization": "Bearer " + key, "Content-Type": "application/json"}
    h.update(extra or {})
    req = urllib.request.Request(base.rstrip("/") + "/chat/completions", data=body, headers=h)
    d = json.loads(urllib.request.urlopen(req, timeout=120).read().decode())
    return (((d.get("choices") or [{}])[0].get("message") or {}).get("content", "") or "")


def _multi_model(provider, models, good, dead, call):
    order = ([good["model"]] + [m for m in models if m != good["model"]]
             if good["model"] in models else list(models))
    last = None
    for model in order:
        try:
            txt = call(model)
            if txt.strip():
                good["model"] = model
                return txt
            last = "empty content"
        except urllib.error.HTTPError as e:
            if e.code in (401, 403):
                dead["dead"] = True
                raise RuntimeError("%s 鉴权失败 HTTP%s" % (provider, e.code)) from None
            last = e
            print("  [%s] %s HTTP%s，换下一模型" % (provider, model, e.code), file=sys.stderr, flush=True)
        except Exception as e:
            last = e
    raise RuntimeError("%s all models failed: %r" % (provider, last))


def openrouter_call(prompt, max_tokens=2000):
    """OpenRouter :free 模型：$0 计价，未充值 50 次/天、20 次/分。"""
    return _multi_model("openrouter", OR_MODELS, _OR_GOOD, _OR_DEAD,
                        lambda m: _oai_once(OR_BASE, OR_KEY, m, prompt, max_tokens,
                                            {"HTTP-Referer": "https://github.com/NoS-1/NoAS",
                                             "X-Title": "NoAS domain judge"}))


def groq_call(prompt, max_tokens=2000):
    """Groq 免费档：30 次/分、1000 次/天（大模型档）。"""
    return _multi_model("groq", GR_MODELS, _GR_GOOD, _GR_DEAD,
                        lambda m: _oai_once(GR_BASE, GR_KEY, m, prompt, max_tokens))

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
    if not (ACC and TOK) and not ARK_KEY and not DS_KEY and not ALI_KEY and not SF_KEY and not QF_KEY and not ZP_KEY:
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
        # 判定源：已配置的国产源按序作为故障转移（各 call 内部还有模型链降级）；全都没有才用 CF
        providers = []
        if GH_KEY and not _GH_DEAD["dead"] and not cool_active("github-models"):
            providers.append(("github-models", lambda: gh_call(prompt)))
        if OR_KEY and not _OR_DEAD["dead"] and not cool_active("openrouter"):
            providers.append(("openrouter", lambda: openrouter_call(prompt)))
        if GR_KEY and not _GR_DEAD["dead"] and not cool_active("groq"):
            providers.append(("groq", lambda: groq_call(prompt)))
        if ZP_KEY:
            providers.append(("zhipu", lambda: zp_call(prompt)))
        if SF_KEY and not _SF_DEAD["dead"]:
            providers.append(("siliconflow", lambda: sf_call(prompt)))
        if QF_KEY and not _QF_DEAD["dead"]:
            providers.append(("qianfan", lambda: qianfan_call(prompt)))
        if ALI_KEY:
            providers.append(("aliyun", lambda: ali_call(prompt)))
        if DS_KEY:
            providers.append(("deepseek", lambda: ds_call(prompt)))
        if ARK_KEY:
            providers.append(("ark", lambda: ark_call(prompt)))
        if not providers:
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
                if not got:
                    raise ValueError("%s 返回不可解析（%d 字节）" % (pname, len(raw)))
                calls += 1
                used_model = pname
                break
            except Exception as e:
                err = "%s: %s" % (pname, type(e).__name__)
                calls += 1
                _m = quota_sleep_minutes(e)
                if _m:
                    cool_mark(pname, _m, e)
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

    conf, shadow, deny, white = [], [], [], []
    HOT = int(os.environ.get("IDENTIFY_CONF_HITS", "5"))
    ad_tok = {l.split("#")[0].strip().lower() for l in (LISTS / "ad_tokens.txt").read_text(encoding="utf-8").splitlines()}
    biz_tok = {l.split("#")[0].strip().lower() for l in (LISTS / "biz_tokens.txt").read_text(encoding="utf-8").splitlines()}
    known_ad = (read_first_col(LISTS / "core_ad_networks.txt") | read_first_col(LISTS / "sdk_ads.txt")
                | read_first_col(LISTS / "ad_endpoints.txt") | read_first_col(LISTS / "cn_ad_endpoints.txt"))
    for it in verdicts:
        d = it["d"]
        if it["v"] == "benign" and it["c"] >= 90:
            # AI 高置信判为正常业务域 → 精准进白名单（编译期放行 + 父域保护）
            white.append(d)
            continue
        if it["v"] in ("ad", "tracker") and it["t"] in ("lite", "mid"):
            # AI 说该拦 ≠ 就能直接进 mid。三个条件同时成立才升级：
            #   1) 真实高频请求（≥HOT 次）  2) 名字带广告词元且不带业务词元，或根域已知广告网络  3) AI 置信 ≥85
            name_ad = token_hit(d, ad_tok) and not token_hit(d, biz_tok)
            if model_used == "main-brain":
                # 主脑模型逐条审过，不再用词元闸兜底；只要求置信达标 + 有真实请求痕迹
                ok = it["c"] >= 85 and (todo.get(d, 0) >= 3 or parent_hit(d, known_ad))
            elif ZP_KEY or QF_KEY or SF_KEY or DS_KEY or ALI_KEY or ARK_KEY or "70b" in (model_used or "").lower():
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
        for group, name in ((conf, "进黑名单（拦截）"), (white, "进白名单（放行）"),
                            (shadow, "仅 full 观察"), ([x["d"] for x in deny], "否决")):
            print("%s %d 条：%s" % (name, len(group), ", ".join(group[:12]) + (" …" if len(group) > 12 else "")))
        return 0

    backup = None
    if a.verify and (conf or shadow or white):
        backup = {p: p.read_text(encoding="utf-8") if p.exists() else "" for p in (DCONF, SHADOW, AIWL)}

    stamp = "# AI 直判 %s  model=%s  calls=%d" % (today(), model_used or "-", calls)
    append_block(DCONF, conf, stamp)
    append_block(SHADOW, shadow, stamp)
    append_block(AIWL, white, stamp)

    sstate = load_json(SHADOW_STATE, {})
    for d in shadow:
        sstate.setdefault(d, {"first_seen": today()})
    for d in deny:
        denied[d["d"]] = dict(d, ts=today(), by="ai")
    SHADOW_STATE.write_text(json.dumps(sstate, ensure_ascii=False, indent=1), encoding="utf-8")
    DENIED.write_text(json.dumps(denied, ensure_ascii=False, indent=1), encoding="utf-8")
    REPORT.write_text(json.dumps({
        "ts": today(), "candidates": len(cand), "judged": len(verdicts), "calls": calls,
        "model": model_used, "confirmed": sorted(conf), "whitelisted": sorted(white),
        "shadow": sorted(shadow), "denied": [x["d"] for x in deny], "skipped": skipped, "error": err,
    }, ensure_ascii=False, indent=1), encoding="utf-8")

    print("AI 直判完成：调用 %d 次｜黑名单 %d｜白名单 %d｜仅 full %d｜否决 %d"
          % (calls, len(conf), len(white), len(shadow), len(deny)))

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
