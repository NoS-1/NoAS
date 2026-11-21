#!/usr/bin/env python3
"""并行批量判定器：把 --export 导出的候选交给多家 OpenAI 兼容模型多线程判定，
结果写成 identify.py --verdicts 可直接吃的 JSON。

启用哪些源取决于 ~/.noas/creds.env / 环境变量（identify.py 导入时会自动加载本地凭据）：
  智谱 zp_call（ZHIPU_API_KEY）、硅基流动 sf_call（SILICONFLOW_API_KEY）、
  阿里 ali_call（DASHSCOPE_API_KEY）、DeepSeek ds_call（DEEPSEEK_API_KEY）、豆包 ark_call（ARK_API_KEY）。
调度：各批在“可用源”上轮询选起点以分流额度、规避单家 QPS；本批失败/空结果自动顺延下一家；
单源连续失败或命中 429/1305 时进入短时冷却熔断。可用 PW_PROVIDERS=siliconflow,zhipu 限定/排序。

用法：
  python3 tools/pwjudge.py --cand /tmp/all_cand.json --out /tmp/all_verdicts.json --workers 6
  PW_PROVIDERS=siliconflow,zhipu python3 tools/pwjudge.py --cand /tmp/all_cand.json --out /tmp/all_verdicts.json
  python3 tools/identify.py --device <目录> --verdicts /tmp/all_verdicts.json --verify
"""
import argparse
import importlib.util
import json
import os
import pathlib
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

ROOT = pathlib.Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("idf", str(ROOT / "tools" / "identify.py"))
idf = importlib.util.module_from_spec(spec)
spec.loader.exec_module(idf)

PROMPT_HEAD = (
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
    "待判域名（域名   请求次数）：\n"
)


def make_prompt(chunk, hits):
    lines = []
    for d in chunk:
        lines.append("%s   请求次数=%d" % (d, hits.get(d, 0)))
    return PROMPT_HEAD + "\n".join(lines)


# ── 多源池：轮询分流 + 故障转移 + 冷却熔断 ─────────────────────────────────
def _build_providers():
    avail = {
        "github": (getattr(idf, "GH_KEY", ""), getattr(idf, "gh_call", None)),
        "zhipu": (getattr(idf, "ZP_KEY", ""), getattr(idf, "zp_call", None)),
        "siliconflow": (getattr(idf, "SF_KEY", ""), getattr(idf, "sf_call", None)),
        "qianfan": (getattr(idf, "QF_KEY", ""), getattr(idf, "qianfan_call", None)),
        "aliyun": (getattr(idf, "ALI_KEY", ""), getattr(idf, "ali_call", None)),
        "deepseek": (getattr(idf, "DS_KEY", ""), getattr(idf, "ds_call", None)),
        "ark": (getattr(idf, "ARK_KEY", ""), getattr(idf, "ark_call", None)),
        # Cloudflare Workers AI：免费额度、不限流，用 CF_API_TOKEN 走 ai_call（无 DS/ARK 时直连 CF）
        "cf": (getattr(idf, "TOK", ""), (lambda p: idf.ai_call(p, getattr(idf, "MODEL")))),
    }
    order_env = [x.strip() for x in os.environ.get("PW_PROVIDERS", "").split(",") if x.strip()]
    names = order_env or list(avail)
    providers = []
    for name in names:
        if name in avail and avail[name][0] and callable(avail[name][1]):
            providers.append((name, avail[name][1]))
    return providers


PROVIDERS = _build_providers()
_plock = threading.Lock()
_rr = [0]
_cool_until = {}
_streak = {}
_dead = set()


def ordered_providers():
    """返回本轮尝试顺序：在未冷却源中用全局轮询选起点，实现跨批分流；全冷却时放行全部兜底。"""
    now = time.time()
    with _plock:
        live = [(n, f) for n, f in PROVIDERS if n not in _dead]
        active = [(n, f) for n, f in live if _cool_until.get(n, 0.0) <= now]
        if not active:
            active = live  # 仅冷却中的源可放行兜底；已判死（鉴权/计费）源本轮不再尝试
        return active


def mark_ok(name):
    with _plock:
        _streak[name] = 0
        _cool_until.pop(name, None)


def mark_fail(name, err):
    if any(k in err for k in ("401", "402", "403", "30001", "账户/鉴权错误")):
        with _plock:
            if name not in _dead:
                _dead.add(name)
                print("  [pool] %s 鉴权/计费不可恢复，本轮停用该源（%s）" % (name, err[:100]), flush=True)
        return
    rate_limited = ("429" in err or "Rate" in err or "rate" in err or "1305" in err)
    cool = 60.0 if rate_limited else 30.0
    with _plock:
        _streak[name] = _streak.get(name, 0) + 1
        if rate_limited or _streak[name] >= 3:
            _cool_until[name] = time.time() + cool
            print("  [pool] %s 失败/限流，冷却 %.0fs（%s）" % (name, cool, err[:90]), flush=True)


lock = threading.Lock()
done_batches = [0]
total_batches = [0]


def judge_chunk(chunk, hits, retries=3):
    prompt = make_prompt(chunk, hits)
    last_err = "no-provider"
    for i in range(retries):
        provs = ordered_providers()
        if not provs:
            return [], "no-provider"
        for name, fn in provs:
            try:
                raw = fn(prompt)
                got = idf.parse_verdicts(raw, set(chunk))
                if got:
                    mark_ok(name)
                    return got, ""
                last_err = "%s:empty/unparsable" % name
                mark_fail(name, "empty content")
            except Exception as e:
                last_err = "%s:%s:%s" % (name, type(e).__name__, str(e)[:80])
                mark_fail(name, last_err)
        time.sleep(2 + i * 3)
    return [], last_err


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cand", required=True, help="identify.py --export 产出的候选 JSON")
    ap.add_argument("--out", required=True, help="输出 verdicts JSON")
    def_workers = int(os.environ.get("PW_WORKERS", str(max(3, 2 * len(PROVIDERS)))))
    ap.add_argument("--workers", type=int, default=def_workers)
    ap.add_argument("--batch", type=int, default=int(os.environ.get("PW_BATCH", "10")))
    a = ap.parse_args()

    if not PROVIDERS:
        print("没有任何可用 AI 源：请先在 /home/user/.noas/creds.env 配置 "
              "ZHIPU_API_KEY / SILICONFLOW_API_KEY / DASHSCOPE_API_KEY / DEEPSEEK_API_KEY / ARK_API_KEY")
        return 2

    rows = json.loads(pathlib.Path(os.path.expanduser(a.cand)).read_text(encoding="utf-8"))
    hits = {r["d"]: int(r.get("hits", 0)) for r in rows}
    domains = [r["d"] for r in rows]
    chunks = [domains[i:i + a.batch] for i in range(0, len(domains), a.batch)]
    total_batches[0] = len(chunks)
    print("候选 %d｜批数 %d｜并发 %d｜单批 %d 域｜源[%s]"
          % (len(domains), len(chunks), a.workers, a.batch, ",".join(n for n, _ in PROVIDERS)), flush=True)

    verdicts, errors = [], []
    t0 = time.time()
    with ThreadPoolExecutor(max_workers=a.workers) as pool:
        futs = {pool.submit(judge_chunk, c, hits): c for c in chunks}
        for f in as_completed(futs):
            got, err = f.result()
            with lock:
                verdicts.extend(got)
                done_batches[0] += 1
                n = done_batches[0]
                el = time.time() - t0
                eta = el / n * (total_batches[0] - n) if n else 0
                print("[%d/%d] +%d verdict｜累计 %d｜已用 %.0fs｜预计剩余 %.0fs%s"
                      % (n, total_batches[0], len(got), len(verdicts), el, eta,
                         ("  err=" + err) if err else ""), flush=True)
            if err:
                errors.append(err)

    pathlib.Path(os.path.expanduser(a.out)).write_text(
        json.dumps(verdicts, ensure_ascii=False, indent=1), encoding="utf-8")
    print("完成：%d 条裁决 → %s｜失败批 %d" % (len(verdicts), a.out, len(errors)), flush=True)
    if errors:
        print("失败样本：" + " | ".join(errors[:5]), flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
