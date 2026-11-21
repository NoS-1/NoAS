#!/usr/bin/env python3
"""judge_v2.py —— 证据优先的广告域判定器（规则前置 + 双模型投票）

核心思路：不把"这个域名是不是广告"丢给模型拍脑袋，而是先构建可核验的证据面：
  1) 父域是否已在上游广告网络库（CNAME/根域归属）  —— 最强证据
  2) 域名结构词元：广告/追踪词元 vs 业务词元      —— 结构性证据
  3) 真实请求频次                                  —— 行为证据
规则能定的直接定（零幻觉）；只有"证据两难"的分歧样本才上模型，
且必须两个不同模型一致才采信，不一致一律进观察池，绝不误拦。

用法：python3 tools/judge_v2.py --cand /tmp/all_cand.json --out /tmp/v2_verdicts.json
"""
import importlib.util
import json
import pathlib
import sys
import time
from concurrent.futures import ThreadPoolExecutor

ROOT = pathlib.Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("idf", str(ROOT / "tools" / "identify.py"))
idf = importlib.util.module_from_spec(spec)
spec.loader.exec_module(idf)

BIG, SMALL = "@cf/meta/llama-3.3-70b-instruct-fp8-fast", "@cf/meta/llama-3.1-8b-instruct"
PROMPT = (
    "判断下列域名是否为广告/追踪域名。已给出可核验证据，请只依据证据下结论，不要臆测品牌。\n"
    '只输出 JSON 数组：[{"d":"域名","v":"ad|tracker|benign|unknown","c":0-100}]\n'
    "口径：广告/追踪=曝光点击上报、归因、埋点统计、广告素材与联盟SDK；benign=业务API、登录支付、内容分发、系统更新。\n"
    "证据不足时必须输出 unknown，宁可放过不可误拦。\n"
    "待判（域名｜次数｜父域在广告库｜广告词元｜业务词元）：\n"
)


def load_tokens():
    ad = idf.read_first_col(ROOT / "lists/ad_tokens.txt")
    biz = idf.read_first_col(ROOT / "lists/biz_tokens.txt")
    known = (idf.read_first_col(ROOT / "lists/core_ad_networks.txt")
             | idf.read_first_col(ROOT / "lists/sdk_ads.txt")
             | idf.read_first_col(ROOT / "lists/ad_endpoints.txt")
             | idf.read_first_col(ROOT / "lists/cn_ad_endpoints.txt"))
    return ad, biz, known


def evidence(d, hits, ad, biz, known):
    return {
        "d": d, "hits": hits,
        "known": idf.parent_hit(d, known),
        "ad_tok": idf.token_hit(d, ad) and not idf.token_hit(d, biz),
        "biz_tok": idf.token_hit(d, biz),
        "root": ".".join(d.split(".")[-2:]),
    }


def rule_decide(e):
    """规则优先：只处理证据明确的样本，返回 (v,c,by) 或 None"""
    if e["known"]:
        return ("ad", 95, "rule-known-network")
    if e["ad_tok"] and e["hits"] >= 3:
        return ("tracker" if "log" in e["d"] or "stat" in e["d"] else "ad", 88, "rule-ad-token")
    if e["biz_tok"] and not e["ad_tok"] and e["hits"] >= 20:
        return ("benign", 90, "rule-biz-token")
    return None


def ask(model, rows):
    lines = ["%s｜%d｜%s｜%s｜%s" % (r["d"], r["hits"], "是" if r["known"] else "否",
                                   "是" if r["ad_tok"] else "否", "是" if r["biz_tok"] else "否")
             for r in rows]
    return idf.ai_call(PROMPT + "\n".join(lines), model)


def vote(rows, hits):
    """双模型投票：一致才采信"""
    out = []
    for chunk in [rows[i:i + 10] for i in range(0, len(rows), 10)]:
        texts = []
        for m in (BIG, SMALL):
            try:
                texts.append(idf.parse_verdicts(ask(m, chunk), {r["d"] for r in chunk}))
            except Exception:
                texts.append([])
        a = {x["d"]: x for x in texts[0]}
        b = {x["d"]: x for x in texts[1]}
        for r in chunk:
            x, y = a.get(r["d"]), b.get(r["d"])
            if x and y and x["v"] == y["v"] and x["v"] != "unknown":
                out.append({"d": r["d"], "v": x["v"], "c": min(x["c"], y["c"]), "by": "vote2"})
            elif x and y:
                out.append({"d": r["d"], "v": "unknown", "c": 0, "by": "disagree"})
            else:
                out.append({"d": r["d"], "v": "unknown", "c": 0, "by": "no-answer"})
    return out


def main():
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--cand", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--workers", type=int, default=6)
    a = ap.parse_args()

    ad, biz, known = load_tokens()
    cand = json.loads(pathlib.Path(a.cand).read_text(encoding="utf-8"))
    hits = {r["d"]: int(r.get("hits", 0)) for r in cand}
    evs = [evidence(r["d"], hits[r["d"]], ad, biz, known) for r in cand]

    final, pending = [], []
    for e in evs:
        r = rule_decide(e)
        if r:
            final.append({"d": e["d"], "v": r[0], "c": r[1], "by": r[2]})
        else:
            pending.append(e)

    t0 = time.time()
    chunks = [pending[i:i + 60] for i in range(0, len(pending), 60)]
    with ThreadPoolExecutor(max_workers=a.workers) as pool:
        for got in pool.map(lambda c: vote(c, hits), chunks):
            final.extend(got)
    el = time.time() - t0

    by = {}
    for f in final:
        by[f["by"]] = by.get(f["by"], 0) + 1
    vc = {}
    for f in final:
        vc[f["v"]] = vc.get(f["v"], 0) + 1
    print("总 %d｜规则直判 %d｜模型需判 %d" % (len(final), len(final) - len(pending), len(pending)))
    print("判定来源:", by)
    print("结论分布:", vc)
    print("模型耗时 %.0fs｜双模型一致率 %.1f%%" % (
        el, 100.0 * by.get("vote2", 0) / max(1, len(pending))))

    pathlib.Path(a.out).write_text(json.dumps(final, ensure_ascii=False, indent=1), encoding="utf-8")


if __name__ == "__main__":
    sys.exit(main())
