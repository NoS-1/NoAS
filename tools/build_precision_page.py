#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""build_precision_page.py —— 生成 docs/precision.html：零误拦闭环的可查页面。

为什么要有这页：规则订阅最怕的不是拦不住，是拦错了还查不出原因。这页把"凭什么说
零误拦"摊开：黄金回归集多大、三档实测误拦率、五道防线各自挡掉多少、评分分布、
观察池里还有多少条在影子期。全部数字从产物里读，不手填。
"""
import json
import os
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DOCS = os.path.join(ROOT, "docs")


def read_json(p, default=None):
    try:
        return json.load(open(os.path.join(ROOT, p), encoding="utf-8"))
    except Exception:
        return default or {}


def count_lines(p, skip_col=False):
    fp = os.path.join(ROOT, p)
    if not os.path.exists(fp):
        return 0
    n = 0
    for line in open(fp, encoding="utf-8"):
        x = line.split("#", 1)[0]
        if not x.strip():
            continue
        d = x.split("\t")[0].strip()
        if skip_col or d:
            n += 1
    return n


def domains(tier):
    fp = os.path.join(ROOT, "subs", tier, "domains.txt")
    if not os.path.exists(fp):
        return 0
    return sum(1 for l in open(fp, encoding="utf-8")
               if l.split("#", 1)[0].strip() and "." in l)


def main():
    golden = read_json("history/golden.json")
    rep = read_json("out/reputation.json")
    comp = read_json("out/compile.json")
    pool = read_json("state/watch_pool.json")

    total_golden = (golden.get("lite") or {}).get("total", 0)
    rows = ""
    for tier, label in (("lite", "lite · 手机默认档"), ("mid", "mid · 平衡档"), ("full", "full · 高召回档")):
        d = golden.get(tier) or {}
        hit = d.get("hit", 0)
        rate = d.get("rate", 0)
        cls = "ok" if hit == 0 else ("warn" if rate < 5 else "")
        args = "零误拦" if hit == 0 else ("低" if rate < 5 else "需关注")
        rows += ("<tr><td>%s</td><td>%d</td><td>%d</td><td><span class=\"pill %s\">%.2f%% %s</span></td></tr>"
                 % (label, domains(tier), hit, cls, rate, args))

    dist = rep.get("dist", {})
    scores = [("≥70 分 · 够格进 lite", dist.get("ge70", 0), "ok"),
              ("40–69 分 · 只进 mid", dist.get("40_69", 0), ""),
              ("<40 分 · 留 full 或观察", dist.get("lt40", 0), "")]
    score_rows = "".join("<tr><td>%s</td><td>%d</td></td><td><span class=\"pill %s\">%s</span></td></tr>"
                         % (a, b, c, "—") for a, b, c in scores)

    young = 0
    wakes = 0
    for d, rec in (pool or {}).items():
        fs = rec.get("first_seen", "")
        try:
            age = int((time.mktime(time.strptime(time.strftime("%Y-%m-%d"), "%Y-%m-%d"))
                       - time.mktime(time.strptime(fs, "%Y-%m-%d"))) // 86400)
        except Exception:
            age = 0
        if age < 14:
            young += 1
        else:
            wakes += 1

    html = """<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>NoAS · 零误拦闭环</title>
<style>
:root{--bg:#0d1117;--card:#161b22;--line:#30363d;--txt:#e6edf3;--dim:#8b949e;--ok:#3fb950;--warn:#d29922}
*{box-sizing:border-box}
body{background:var(--bg);color:var(--txt);font:15px/1.75 -apple-system,"Segoe UI","PingFang SC",sans-serif;margin:0;padding:28px 18px}
.wrap{max-width:880px;margin:0 auto}
h1{font-size:26px;margin:0 0 6px}
h2{font-size:17px;margin:34px 0 10px;padding-bottom:6px;border-bottom:1px solid var(--line)}
.sub{color:var(--dim);font-size:13px;margin-bottom:20px}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px 16px;margin:10px 0}
code{background:#0b0f14;border:1px solid var(--line);border-radius:5px;padding:1px 5px;font-size:13px;word-break:break-all}
table{width:100%;border-collapse:collapse;font-size:13.5px;margin:8px 0}
th,td{border:1px solid var(--line);padding:8px 10px;text-align:left;vertical-align:top}
th{background:#1b212a;color:var(--dim);font-weight:600}
.pill{display:inline-block;font-size:11.5px;padding:1px 7px;border-radius:999px;border:1px solid var(--line);color:var(--dim)}
.pill.ok{color:var(--ok);border-color:#238636}
.pill.warn{color:var(--warn);border-color:#9e6a03}
a{color:#58a6ff;text-decoration:none}
ul{margin:6px 0 0 18px}
li{margin:4px 0}
</style>
</head>
<body>
<div class="wrap">

<h1>零误拦闭环</h1>
<div class="sub">NoAS · 判断"这套规则会不会把你的正常网站拦死"。<br>
原则：<b>拦得准不准可以慢慢提，拦错一次就没有第二次机会</b>——所以误伤优先，宁放不误拦。</div>

<h2>1 · 结论先行</h2>
<table>
<tr><th>档位</th><th>本期规则条数</th><th>黄金集命中（误拦）</th><th>实测误拦率</th></tr>
{{rows}}
</table>
<div class="card">
黄金回归集共 <b>{{tg}}</b> 条正常站点，每轮构建都用它跑一遍：lite 命中必须为 <b>0</b>，出现一条就判红、不发版。
mid/full 是高召回档，只记录误拦率，不阻断。
</div>

<h2>2 · 五道防线</h2>
<table>
<tr><th>防线</th><th>怎么挡</th><th>本期规模</th></tr>
<tr><td>白名单（一票否决）</td><td>人工台账 + 回归基线 + 基础服务表，编译期整体剔除，连父域一起保护</td><td>剔除 {{wlb}} 条</td></tr>
<tr><td>良性母域剔除</td><td>一个平台主体域在正常大盘里，就不拦它下面整片子域</td><td>{{benign}} 条母域</td></tr>
<tr><td>基础服务表</td><td>登录/支付/推送/地图/验证码/崩溃上报，拦了 App 就废</td><td>{{svc}} 条</td></tr>
<tr><td>影子期（观察池）</td><td>低置信域先观察 14 天且复现 2 轮才准晋级，30 天不复现直接退役</td><td>在池 {{watch}} 条</td></tr>
<tr><td>冷却池</td><td>被报过误伤的域永久豁免，即使白名单被误删也不会复发</td><td>{{cool}} 条</td></tr>
</table>

<h2>3 · 域名信誉评分</h2>
<div class="sub">谁够格进 lite 不看"几个清单都收了"，看多信号合起来的分数。</div>
<table>
<tr><th>分数段</th><th>条数</th><th>档位含义</th></tr>
{{score_rows}}
</table>
<div class="card">
共评 <b>{{rtotal}}</b> 条，其中 <b>{{vetoed}}</b> 条因命中白名单/良性大盘/黄金集被<b>一票否决</b>（直接清零，不给翻盘机会）。
评分维度：是否已在 lite 实证、跨源共识分、父域是否广告网络、子域词元、是否品牌域下的首方伪装、是否 SDK/贴片/遥测、是否机器生成子域。
</div>

<h2>4 · 观察池现状</h2>
<table>
<tr><th>状态</th><th>条数</th><th>含义</th></tr>
<tr><td>影子期内（&lt;14 天）</td><td>{{young}}</td><td>只记录不晋级，绝不许进 lite</td></tr>
<tr><td>已满 14 天待复现</td><td>{{wakes}}</td><td>下一轮若再复现就晋级到端点表</td></tr>
</table>

<h2>5 · 为什么这样做</h2>
<div class="card">
<ul>
<li><b>不用"被拦了就认定是广告"来凑指标。</b>黄金集里每一条冲突域都是逐条审读注册域后判定的，
确认是广告才移出黄金集、记进 <code>lists/golden_ads.txt</code>；判不出来的就留在黄金集里持续报警。</li>
<li><b>不同档位用不同标准。</b>lite 是手机默认档，误拦代价最大，所以只收"多源共识 + 审计端点 + 核心广告网"，
并用 1 万条硬上限保证体积可控；mid/full 是高召回档，愿意用一点误拦换覆盖。</li>
<li><b>影子期对应行业做法。</b>企业实践里新情报源要在真实流量上只记录不拦截，观察够久、误报率足够低才允许执行；
这里用"14 天 + 复现 2 轮"的轻量版本，因为静态订阅拿不到用户查询日志。</li>
<li><b>误伤走反馈自动闭环。</b>开 Issue 打 <code>误伤</code> 标签，下一个 4 小时窗口白名单 + 冷却池都会加上，不用等人工。</li>
</ul>
</div>

<h2>6 · 报误拦</h2>
<div class="card">
发现正常网站打不开：<a href="https://github.com/NoS-1/NoAS/issues/new">开一个 Issue</a>，标题写域名，正文说清"哪个网页/哪个功能坏了"，打上 <code>误伤</code> 标签。<br>
自动流程：进白名单台账 → 进冷却池 → 重编译 → 硬校验 → 发布，一般 4 小时内生效。
</div>

<div class="sub" style="margin-top:28px">数据由每轮构建自动重算（tools/build_precision_page.py），不手填。</div>
</div>
</body>
</html>
"""
    data = {
        "rows": rows, "tg": total_golden,
        "wlb": comp.get("whitelist_blocked", 0),
        "benign": count_lines("lists/benign_top.txt"),
        "svc": count_lines("lists/service_allow.txt", True),
        "watch": count_lines("lists/cn_ad_watch.txt", True),
        "cool": count_lines("lists/cooldown.txt", True),
        "score_rows": score_rows,
        "rtotal": rep.get("total", 0), "vetoed": rep.get("vetoed", 0),
        "young": young, "wakes": wakes,
    }
    out = os.path.join(DOCS, "precision.html")
    os.makedirs(DOCS, exist_ok=True)
    for k, v in data.items():
        html = html.replace("{{%s}}" % k, str(v))
    open(out, "w", encoding="utf-8").write(html)
    print("生成 %s：黄金集 %d｜误拦率 %s｜评分 %d 条"
          % (out, total_golden,
             {k: (golden.get(k) or {}).get("rate") for k in ("lite", "mid", "full")},
             rep.get("total", 0)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
