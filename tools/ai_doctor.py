#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ai_doctor.py —— AI 判定源体检：谁在判、能不能判、还差什么凭据。

判定源（identify.py 已配置源按序故障转移；pwjudge.py 多源轮询分流）：
  1. 主脑模型（会话内逐条判，--verdicts 传入，不需要任何凭据）
  2. 智谱 GLM       ZHIPU_API_KEY        open.bigmodel.cn（glm-4.7-flash 主，模型链降级）
  3. 硅基流动       SILICONFLOW_API_KEY  api.siliconflow.cn/v1（Qwen3.5-9B 主，模型链降级）
  4. 阿里云百炼     DASHSCOPE_API_KEY
  5. DeepSeek       DEEPSEEK_API_KEY
  6. 豆包 Ark       ARK_API_KEY
  7. Cloudflare     CF_API_TOKEN         70B（首选）/ 8B（兜底）

每个源只发一次最小请求验证可用性；失败不影响构建（soft）。
用法：python3 tools/ai_doctor.py
"""
import json
import os
import sys
import urllib.error
import urllib.request


def _load_local_creds():
    """独立运行时自动加载 ~/.noas/creds.env（不覆盖已有环境变量）。"""
    p = os.path.expanduser("~/.noas/creds.env")
    if not os.path.exists(p):
        return
    for line in open(p, encoding="utf-8"):
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        if k.strip() and k.strip() not in os.environ:
            os.environ[k.strip()] = v.strip().strip('"').strip("'")


_load_local_creds()

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MC = "只回两个字：可用"


def _post(url, body, headers, timeout=45):
    req = urllib.request.Request(url, data=json.dumps(body).encode(), headers=headers)
    d = json.loads(urllib.request.urlopen(req, timeout=timeout).read().decode())
    r = d.get("result") or {}
    if isinstance(r.get("response"), str):
        return r["response"]
    return ((d.get("choices") or [{}])[0].get("message") or {}).get("content", "") or str(r)[:40]


def check_deepseek():
    key = (os.environ.get("DEEPSEEK_API_KEY") or os.environ.get("DEEPSEEK_KEY") or "").strip()
    if not key:
        return "missing", "未配置 DEEPSEEK_API_KEY"
    base = os.environ.get("DEEPSEEK_BASE", "https://api.deepseek.com").rstrip("/")
    model = os.environ.get("DEEPSEEK_MODEL", "deepseek-chat")
    try:
        txt = _post(base + "/chat/completions", {"model": model, "max_tokens": 16,
                 "messages": [{"role": "user", "content": MC}]},
                 {"Authorization": "Bearer " + key, "Content-Type": "application/json"})
        return "ok", "%s → %s" % (model, txt.strip()[:20])
    except Exception as e:
        return "fail", "%s: %s" % (type(e).__name__, str(e)[:80])


def check_zhipu():
    key = (os.environ.get("ZHIPU_API_KEY") or os.environ.get("GLM_API_KEY") or os.environ.get("BIGMODEL_API_KEY") or "").strip()
    if not key:
        return "missing", "未配置 ZHIPU_API_KEY（智谱 BigModel）"
    base = os.environ.get("ZP_BASE", "https://open.bigmodel.cn/api/paas/v4").rstrip("/")
    primary = os.environ.get("ZP_MODEL", "glm-4.7-flash")
    fallbacks = [m.strip() for m in os.environ.get("ZP_FALLBACK_MODELS", "glm-5.3-flash").split(",") if m.strip()]
    models = [primary] + [m for m in fallbacks if m != primary]
    last = ""
    for model in models:
        try:
            mt = 3000 if model.startswith("glm-5") else 300
            txt = _post(base + "/chat/completions", {"model": model, "max_tokens": mt,
                     "messages": [{"role": "user", "content": MC}]},
                     {"Authorization": "Bearer " + key, "Content-Type": "application/json"})
            tag = model if model == primary else ("主模型不可用，备用 %s" % model)
            return "ok", "%s → %s" % (tag, (txt or "ok").strip()[:20])
        except Exception as e:
            last = "%s: %s" % (model, str(e)[:80])
    return "fail", last


def check_siliconflow():
    key = (os.environ.get("SILICONFLOW_API_KEY") or os.environ.get("SF_API_KEY") or "").strip()
    if not key:
        return "missing", "未配置 SILICONFLOW_API_KEY（硅基流动）"
    base = os.environ.get("SF_BASE", "https://api.siliconflow.cn/v1").rstrip("/")
    primary = os.environ.get("SF_MODEL", "Qwen/Qwen3.5-9B")
    fallbacks = [m.strip() for m in os.environ.get(
        "SF_FALLBACK_MODELS", "Qwen/Qwen3-8B,Qwen/Qwen2.5-7B-Instruct,THUDM/GLM-4-9B-0414").split(",") if m.strip()]
    models = [primary] + [m for m in fallbacks if m != primary]
    last = ""
    for model in models:
        try:
            txt = _post(base + "/chat/completions", {"model": model, "max_tokens": 600,
                     "messages": [{"role": "user", "content": MC}]},
                     {"Authorization": "Bearer " + key, "Content-Type": "application/json"})
            tag = model if model == primary else ("主模型不可用，备用 %s" % model)
            return "ok", "%s → %s" % (tag, (txt or "ok").strip()[:20])
        except urllib.error.HTTPError as e:
            detail = ""
            try:
                detail = e.read().decode()[:160]
            except Exception:
                pass
            if e.code == 402:
                return "fail", "Key 有效但账户余额不足/未领免费额度或未实名(HTTP402 code30001)；实名并领取免费额度或充值后恢复"
            if e.code in (401, 403):
                return "fail", "鉴权失败 HTTP %s（检查 SILICONFLOW_API_KEY）" % e.code
            last = "%s: HTTP%s %s" % (model, e.code, detail[:80])
        except Exception as e:
            last = "%s: %s" % (model, str(e)[:80])
    return "fail", last


def check_aliyun():
    key = (os.environ.get("DASHSCOPE_API_KEY") or os.environ.get("ALIYUN_API_KEY") or "").strip()
    if not key:
        return "missing", "未配置 DASHSCOPE_API_KEY（阿里云百炼）"
    base = os.environ.get("ALI_BASE", "https://dashscope.aliyuncs.com/compatible-mode/v1").rstrip("/")
    model = os.environ.get("ALI_MODEL", "qwen3.5-turbo")
    try:
        txt = _post(base + "/chat/completions", {"model": model, "max_tokens": 16,
                 "messages": [{"role": "user", "content": MC}]},
                 {"Authorization": "Bearer " + key, "Content-Type": "application/json"})
        return "ok", "%s → %s" % (model, txt.strip()[:20])
    except Exception as e:
        return "fail", "%s: %s" % (type(e).__name__, str(e)[:80])


def check_ark():
    key = (os.environ.get("ARK_API_KEY") or os.environ.get("DOUBAO_API_KEY") or "").strip()
    if not key:
        return "missing", "未配置 ARK_API_KEY"
    base = os.environ.get("ARK_BASE", "https://ark.cn-beijing.volces.com/api/v3").rstrip("/")
    model = os.environ.get("ARK_MODEL", "doubao-seed-1-6-250615")
    try:
        txt = _post(base + "/chat/completions", {"model": model, "max_tokens": 16,
                 "messages": [{"role": "user", "content": MC}]},
                 {"Authorization": "Bearer " + key, "Content-Type": "application/json"})
        return "ok", "%s → %s" % (model, txt.strip()[:20])
    except Exception as e:
        return "fail", "%s: %s" % (type(e).__name__, str(e)[:80])


def check_cf():
    acc = (os.environ.get("CF_ACCOUNT_ID") or "226431c8f431ebb75d82dd5dbd5e8d86").strip()  # 账号 ID 非密钥
    tok = (os.environ.get("CF_API_TOKEN") or "").strip()
    if not (acc and tok):
        return "missing", "缺少 CF_API_TOKEN 密钥"
    model = os.environ.get("AI_MODEL", "@cf/meta/llama-3.3-70b-instruct-fp8-fast")
    try:
        txt = _post("https://api.cloudflare.com/client/v4/accounts/%s/ai/run/%s" % (acc, model),
                    {"messages": [{"role": "user", "content": MC}], "max_tokens": 16},
                    {"Authorization": "Bearer " + tok, "Content-Type": "application/json"})
        return "ok", "%s → %s" % (model, txt.strip()[:20])
    except Exception as e:
        return "fail", "%s: %s" % (type(e).__name__, str(e)[:80])


def main():
    sources = [("主脑模型（会话内逐条判）", "ok", "无需凭据：--verdicts 传入即可，优先级最高"),
               ("智谱 GLM", *check_zhipu()), ("硅基流动", *check_siliconflow()),
               ("阿里云百炼", *check_aliyun()),
               ("DeepSeek", *check_deepseek()),
               ("豆包 Ark", *check_ark()), ("Cloudflare AI", *check_cf())]
    print("%-26s %-8s %s" % ("判定源", "状态", "说明"))
    for name, st, msg in sources:
        print("%-26s %-8s %s" % (name, st, msg))
    usable = [n for n, st, _ in sources if st == "ok"]
    if not usable:
        print("\n结论：没有任何可用判定源，AI 直判会跳过（构建不受影响）")
    else:
        print("\n结论：可用判定源 %s；identify.py 会按优先级自动选第一个" % "、".join(usable))
    missing = [n for n, st, _ in sources if st == "missing"]
    if missing:
        print("缺凭据：%s（补到 /home/user/.noas/creds.env 或仓库 Secrets 即生效）" % "、".join(missing))
    out = os.path.join(ROOT, "state", "ai_doctor.json")
    json.dump({"sources": [{"name": n, "status": s, "note": m} for n, s, m in sources]},
              open(out, "w"), ensure_ascii=False, indent=1)
    return 0


if __name__ == "__main__":
    sys.exit(main())
