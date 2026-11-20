#!/usr/bin/env python3
"""用 Workers AI（免费 1 万 neurons/天）复核观察池，产出“建议”而非“规则”。

原则：
- 只做第二意见，结果写 state/ai_verdicts.json 与 lists/ai_ads_suggest.txt；
- 绝不直接写进 lite/mid 主表，避免模型误判造成误拦；
- 有硬额度：每次运行 ≤8 次调用、每天 ≤30 次，超额直接跳过。
"""
import datetime
import json
import os
import pathlib
import re
import sys
import urllib.error
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parent.parent
ACC = os.environ.get("CF_ACCOUNT_ID", "226431c8f431ebb75d82dd5dbd5e8d86").strip()
TOK = os.environ.get("CF_API_TOKEN", "").strip()
MODEL = os.environ.get("AI_MODEL", "@cf/meta/llama-3.2-3b-instruct").strip()
RUN_CAP = int(os.environ.get("AI_RUN_CALL_CAP", "8"))
DAY_CAP = int(os.environ.get("AI_DAY_CALL_CAP", "30"))
BATCH = 5

POOL = ROOT / "state" / "watch_pool.json"
USAGE = ROOT / "state" / "ai_usage.json"
VERDICTS = ROOT / "state" / "ai_verdicts.json"
SUGGEST = ROOT / "lists" / "ai_ads_suggest.txt"
SUGGEST_MIN_C = int(os.environ.get("AI_SUGGEST_MIN_C", "70"))


def today():
    return datetime.date.today().isoformat()


def load(p, default):
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return default


def ai(prompt, max_tokens=256):
    body = json.dumps({"messages": [{"role": "user", "content": prompt}],
                       "max_tokens": max_tokens}).encode()
    req = urllib.request.Request(
        "https://api.cloudflare.com/client/v4/accounts/%s/ai/run/%s" % (ACC, MODEL),
        data=body, headers={"Authorization": "Bearer " + TOK,
                            "Content-Type": "application/json"})
    d = json.load(urllib.request.urlopen(req, timeout=45))
    r = d.get("result") or {}
    if isinstance(r.get("response"), str):
        return r["response"]
    ch = (r.get("choices") or [{}])[0].get("message") or {}
    return ch.get("content") or ""


def parse(text):
    m = re.search(r"\[[\s\S]*\]", text or "")
    if not m:
        return []
    try:
        return json.loads(m.group(0))
    except Exception:
        return []


def main():
    if not TOK:
        print("AI 复核跳过：未配置 CF_API_TOKEN")
        return 0
    pool = load(POOL, {})
    if not pool:
        print("AI 复核跳过：观察池为空")
        return 0

    usage = load(USAGE, {})
    used_today = usage.get(today(), 0)
    if used_today >= DAY_CAP:
        print("AI 复核跳过：今日已用 %d 次，达自设上限 %d" % (used_today, DAY_CAP))
        return 0

    todo = []
    for dom, meta in pool.items():
        ai_meta = meta.get("ai") or {}
        if ai_meta.get("ts", "") >= datetime.date.today().isoformat():
            continue
        todo.append(dom)
    todo = todo[: RUN_CAP * BATCH]
    if not todo:
        print("AI 复核：没有待判域名")
        return 0

    verdicts = load(VERDICTS, {})
    calls = 0
    for i in range(0, len(todo), BATCH):
        if calls >= RUN_CAP or used_today + calls >= DAY_CAP:
            break
        chunk = todo[i:i + BATCH]
        prompt = (
            "你是 DNS 去广告规则的复核员。判断下列域名是否属于广告/追踪/统计/弹窗类域名。\n"
            "严格只输出 JSON 数组，每项 {\"d\":\"域名\",\"v\":\"ad|tracker|benign|unknown\",\"c\":0-100}。\n"
            "c 为置信度。正常业务（官网、支付、内容分发、登录、客服）必须判 benign。\n"
            "域名：\n" + "\n".join(chunk)
        )
        try:
            raw = ai(prompt)
            calls += 1
        except Exception as e:
            print("AI 调用失败（停止本轮）：%s" % e)
            break
        for item in parse(raw):
            dom = str(item.get("d", "")).strip().lower()
            if dom not in pool:
                continue
            v = str(item.get("v", "unknown")).lower()
            if v not in ("ad", "tracker", "benign", "unknown"):
                v = "unknown"
            try:
                c = int(item.get("c", 0))
            except Exception:
                c = 0
            pool[dom]["ai"] = {"v": v, "c": max(0, min(100, c)), "ts": today()}
            verdicts[dom] = pool[dom]["ai"]

    usage[today()] = used_today + calls
    USAGE.write_text(json.dumps(usage, ensure_ascii=False, indent=1), encoding="utf-8")
    POOL.write_text(json.dumps(pool, ensure_ascii=False, indent=1), encoding="utf-8")
    VERDICTS.write_text(json.dumps(verdicts, ensure_ascii=False, indent=1), encoding="utf-8")

    strong = sorted(d for d, a in verdicts.items()
                    if a.get("v") in ("ad", "tracker") and a.get("c", 0) >= 85)
    SUGGEST.parent.mkdir(parents=True, exist_ok=True)
    SUGGEST.write_text("\n".join(strong) + ("\n" if strong else ""), encoding="utf-8")
    print("AI 复核完成：%d 次调用 / 覆盖 %d 个域 / 高置信建议 %d 条（仅建议，不进主表）"
          % (calls, len(todo), len(strong)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
