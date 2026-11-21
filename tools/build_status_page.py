#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""build_status_page.py —— 生成 docs/status.html：一张页面看全部通道的当前状态。

读的都是一天内生成的真产物（subs/*/meta.json、state/*.json），没有就标「未知」，
绝不编造数字。生成失败不阻断发布（CI 里走 soft）。
"""
import datetime
import html
import json
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DOCS = os.path.join(ROOT, "docs")


def jload(rel, default=None):
    p = os.path.join(ROOT, rel)
    if not os.path.exists(p):
        return default
    try:
        return json.loads(open(p, encoding="utf-8").read())
    except Exception:
        return default


def row(name, value, note=""):
    return f"<tr><td>{html.escape(name)}</td><td class='v'>{html.escape(str(value))}</td><td class='n'>{html.escape(note)}</td></tr>"


def main():
    tiers = []
    for t in ("lite", "mid", "full"):
        m = jload(f"subs/{t}/meta.json", {}) or {}
        tiers.append(row(f"{t} 档条数", m.get("count", "未知"), f"独立端点 /dns-query/{t}"))
    bm = jload("state/build_manifest.json", {}) or {}
    fp = jload("state/benign_fp.json", {}) or {}
    ga = jload("state/gateway_align.json", {}) or {}
    gv = jload("state/gateway_verify.json", {}) or {}
    bj = jload("state/board.json", {}) or {}

    fp_rows = []
    for k in ("tier1", "tier2", "tier3"):
        if k in fp:
            fp_rows.append(row(f"误伤 {k}", f"样本 {fp[k].get('n')}／误伤 {fp[k].get('fp')}", "真产物逐档判定"))
        else:
            fp_rows.append(row(f"误伤 {k}", "未知", "尚未运行"))

    # gateway_align.json 结构：{t1:{missing,extra}, t2:..., t3:..., status}
    al_txt = ga.get("status", "未知")
    frag = jload("state/gateway_prune.json", {}) or {}
    if isinstance(ga, dict) and all(k in ga for k in ("t1", "t2", "t3")):
        miss = sum(int(ga[k].get("missing", 0) or 0) for k in ("t1", "t2", "t3"))
        extra = sum(int(ga[k].get("extra", 0) or 0) for k in ("t1", "t2", "t3"))
        al_txt = f"{al_txt}（缺 {miss}／多余 {extra}）"
    rows = [
        row("Worker 版本", bm.get("version", "未知"), f"sha {bm.get('sha256', '?')}"),
    ] + tiers + fp_rows + [
        row("Gateway 对齐", al_txt, "按根域比 lite／mid／full"),
        row("Gateway 探活", "通过" if gv.get("ok") is True else gv.get("ok", "未知"),
            str(gv.get("detail", "") or "")[:60]),
    ]

    ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    out = f"""<!doctype html><html lang="zh-CN"><meta charset="utf-8">
<title>NoAS 状态</title>
<style>
:root{{color-scheme:dark}}
body{{margin:0;padding:32px 20px;background:#0c0d10;color:#e6e8ee;
font:15px/1.7 -apple-system,BlinkMacSystemFont,"Segoe UI","PingFang SC","Microsoft YaHei",sans-serif}}
h1{{font-size:22px;margin:0 0 4px}}
.sub{{color:#8b93a7;font-size:13px;margin-bottom:22px}}
table{{width:100%;max-width:760px;border-collapse:collapse;background:#14161b;border-radius:10px;overflow:hidden}}
th,td{{padding:10px 14px;text-align:left;border-bottom:1px solid #23262f;font-size:14px}}
th{{background:#1a1d24;color:#9aa3b8;font-weight:600}}
td.v{{font-variant-numeric:tabular-nums;color:#7ee2a8}}
td.n{{color:#8b93a7;font-size:13px}}
.links{{margin-top:18px;font-size:14px}}
a{{color:#7cb7ff;text-decoration:none;margin-right:14px}}
.foot{{margin-top:26px;color:#5b6274;font-size:12px}}
</style>
<h1>NoAS 运行状态</h1>
<div class="sub">页面生成于 {ts}｜全部数字来自当日构建产物，缺失即显示「未知」</div>
<table><tr><th>项目</th><th>值</th><th>说明</th></tr>
{chr(10).join(rows)}
</table>
<div class="links">
<a href="/precision.html">精度看板</a>
<a href="https://noas-cdn.pages.dev/tier">在线条数 /tier</a>
<a href="/CLIENTS.md">接入配置</a>
<a href="/FAQ.md">常见问题</a>
</div>
<div class="foot">NoAS · 规则产物按 CC BY-SA 4.0 + GPL-3.0 双协议开放｜代码 MIT</div>
"""
    os.makedirs(DOCS, exist_ok=True)
    p = os.path.join(DOCS, "status.html")
    open(p, "w", encoding="utf-8").write(out)
    print("已生成 docs/status.html")


if __name__ == "__main__":
    main()
