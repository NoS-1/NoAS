#!/usr/bin/env python3
"""gen_channels.py —— 把通道清单渲染成可直接抄的配置文件。

产物（subs/channels/）：
  doh.txt            一行一个 DoH URL，AdGuard Home / sing-box / 浏览器都能直接用
  dot.txt            一行一个 DoT 地址
  aiodns.sh          本机 aiodns 启动脚本（参数全部按官方 README 写，不自造）
  aiodns.special.txt aiodns 的 --special-list：国内域走国内上游
  adguardhome-upstream.yaml  AdGuard Home 的上游片段
  health.json        最近一次健康检查结果（check_channels.py 产出，这里只读）
  README.md          通道怎么选、额度红线、坑

排序规则：health.json 里标 down 的通道自动沉底并注释掉，避免把死通道推荐出去。
"""
import json
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LISTS = ROOT / "lists"
OUTDIR = ROOT / "subs" / "channels"
DOCS = ROOT / "docs" / "subs" / "channels"

PRIORITY_ROLE = ["primary", "backup", "local", "last"]


def load_channels():
    rows = []
    p = LISTS / "dns_channels.tsv"
    for line in p.read_text(encoding="utf-8").splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        cols = line.split("\t")
        if len(cols) < 6:
            continue
        rows.append({"name": cols[0].strip(), "proto": cols[1].strip(),
                     "endpoint": cols[2].strip(), "priority": int(cols[3]),
                     "role": cols[4].strip(), "note": cols[5].strip()})
    rows.sort(key=lambda r: r["priority"])
    return rows


def health_map():
    p = OUTDIR / "health.json"
    if not p.exists():
        return {}, ""
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return {}, ""
    return {k: v for k, v in (data.get("channels") or {}).items()}, data.get("checked_at", "")


def main():
    rows = load_channels()
    health, checked_at = health_map()
    OUTDIR.mkdir(parents=True, exist_ok=True)
    md_lines = []

    def alive(r):
        h = health.get(r["name"]) or {}
        return h.get("status") == "ok"          # unknown/absent 都不算可用，只信实测

    up = [r for r in rows if r["role"] not in ("last", "gateway")]
    gw = [r for r in rows if r["role"] == "gateway"]
    alive_up = [r for r in up if alive(r)]
    dead_up = [r for r in up if not alive(r)]
    # FAIL-SAFE：体检环境不可信（一条都没通）时，绝不能把清单剔空——
    # 宁可推完整清单，也不给用户一个空文件。这是硬规则。
    fallback = False
    if not alive_up:
        alive_up, dead_up, fallback = up, [], True

    # doh.txt
    doh = [r for r in alive_up if r["proto"] in ("doh", "ndoh")]
    verify = {}
    vp = ROOT / "state" / "gateway_verify.json"
    if vp.exists():
        try:
            verify = json.loads(vp.read_text(encoding="utf-8"))
        except Exception:
            verify = {}
    gw_endpoint = gw[0]["endpoint"] if gw else "https://oxyacq0a4t.cloudflare-gateway.com/dns-query"
    gw_status = "已实测：拦广告 / 放正常" if verify.get("ok") else "待验证"
    head = (
        "# NoAS DoH 清单 —— 注意：下面都是「纯解析」通道，不拦截广告。\n"
        "# 要拦截，二选一：\n"
        "#   a) 本地过滤：AGH / sing-box 加载 subs/lite/adguard.txt，上游填下面任意一条（零额度）；\n"
        "#   b) 云端带规则 —— 按设备选档位（服务端只按该档判定，响应头 x-noas-tier 回显实际档）：\n"
        "#      /dns-query/lite   1 万条  低配设备 / 只想零误伤（最小集）\n"
        "#      /dns-query/mid    2 万条  手机默认档（Android 私人 DNS 只能填主机名，靠 UA 自动判为 mid）\n"
        "#      /dns-query/full   3 万条  路由器 / AGH / 桌面\n"
        "#      /dns-query        自动档：按 UA 判定（AGH/sing-box/clash→full，手机/桌面→mid，其余→lite）\n"
        "#      显式覆盖：/dns-query?tier=full，或请求头 x-noas-tier: full（会记住，同 IP 同 UA 最多写一次）\n"
        "#      自查：GET /tier 或 /dns-query?info=1 → 返回当前档与条数\n"
        "#      首选快速通道（已装全三档，首包 382ms）：" + gw_endpoint + "（Gateway，" + gw_status + "）\n"
        "#      Pages 承载（国内可达，10 万/天，90% 熔断）：https://noas-cdn.pages.dev/dns-query/full\n"
        "#      workers.dev 原生域在国内被阻断，仅境外可用，不要再填\n"
        + ("# 注意：本次体检环境异常，以下为完整清单（未经在线验证），请自行试通\n" if fallback else "")
        + "# 顺序即优先级；均为国内直连，无调用额度\n"
    )
    (OUTDIR / "doh.txt").write_text(
        head + "".join("%s\n" % r["endpoint"] for r in doh), encoding="utf-8")

    # dot.txt
    dot = [r for r in alive_up if r["proto"] == "dot"]
    (OUTDIR / "dot.txt").write_text(
        "# NoAS 国内 DoT 上游（853 端口，客户端支持 TLS 时优先用这个，更快）\n"
        + "".join("%s\n" % r["endpoint"] for r in dot), encoding="utf-8")

    # gateway.txt：带规则的自建端点（不与公共通道混排，避免把未验证的当默认）
    (OUTDIR / "gateway.txt").write_text(
        "# NoAS 自建带规则端点（Zero Trust Gateway）\n"
        "# DoH 与 DoT 均带 7 条档位规则；额度按用户数计算，远高于 Worker 的 10 万/天\n"
        "# 标注「已实测」的才可信；未标注的需自行试通（本机代理会伪造响应）\n"
        + "".join("%s%s\n" % (r["endpoint"],
                              "   # 已实测" if (verify.get("ok") or (health.get(r["name"]) or {}).get("status") == "ok") else "   # 待验证")
                  for r in gw), encoding="utf-8")

    # dot-preferred.txt：只留健康检查里最快的那条 DoT，安卓私人 DNS 直接抄
    measured = [(r, (health.get(r["name"]) or {}).get("rtt_ms"))
                for r in dot if (health.get(r["name"]) or {}).get("status") == "ok"]
    measured = [(r, ms) for r, ms in measured if isinstance(ms, int)]
    measured.sort(key=lambda x: x[1])
    best = measured[0] if measured else (dot[0] if dot else None)
    if best:
        r, ms = best if isinstance(best, tuple) else (best, None)
        (OUTDIR / "dot-preferred.txt").write_text(
            "# 安卓「私人 DNS」/ iOS 描述文件 里直接填这一行（只填主机名，端口固定 853）\n"
            "# 依据：本轮 CI 在干净网络实测 RTT 排序，最快者为 %s%s\n"
            "%s\n" % (r["name"], ("（%dms）" % ms if ms else "（本轮无有效实测，按清单顺序取首条）"),
                       r["endpoint"].replace("tls://", "").split(":")[0]), encoding="utf-8")

    # aiodns special-list：国内域走国内上游，境外域仍走默认上游
    special = []
    for f in ("cn_roots.txt",):
        p = LISTS / f
        if not p.exists():
            continue
        for line in p.read_text(encoding="utf-8").splitlines():
            x = line.split("#")[0].split("\t")[0].strip().lower()
            if x and "." in x and "/" not in x:
                special.append(x)
    special = sorted(set(special))
    (OUTDIR / "aiodns.special.txt").write_text(
        "# aiodns --special-list：这些域走国内上游（避免国内站点绕道境外）\n"
        + "".join("%s\n" % d for d in special), encoding="utf-8")

    # aiodns.sh（参数严格照 honwen/aiodns --help，不自造开关）
    # bootstrap 必须走明文 IP：它用来解析 DoH/DoT 的域名，本身不能再依赖加密解析，
    # 也不能用域名（否则鸡生蛋）。阿里/腾讯的 53 端口国内全通。
    boot = "--bootstrap 223.5.5.5 --bootstrap 119.29.29.29"
    sh = f"""#!/usr/bin/env bash
# NoAS · 本机 aiodns 通道（honwen/aiodns，AdGuard dnsproxy 内核）
# 作用：国内域走国内上游直连、开启缓存、拒绝 ANY，境外域走默认上游。
# 注意：aiodns 本身【不做广告拦截】，拦截请用 AdGuard Home 加载 adguard.txt，
#       或在系统 hosts 导入 hosts.txt（0.0.0.0 方案）。
# 安装：docker pull chenhw2/aiodns  或  go install github.com/honwen/aiodns@latest
set -euo pipefail

SPECIAL_LIST="${{SPECIAL_LIST:-https://noas-cdn.pages.dev/subs/channels/aiodns.special.txt}}"
LISTEN="${{LISTEN:-127.0.0.1:5300}}"

exec aiodns \\
  --listen   "$LISTEN" \\
  {" ".join('--upstream tls://%s' % r["endpoint"].split("//")[-1] for r in dot[:2]) if dot else '--upstream tls://dns.alidns.com:853'} \\
  {" ".join('--special-upstream %s' % r["endpoint"] for r in doh[:1]) if doh else '--special-upstream https://dns.alidns.com/dns-query'} \\
  {" ".join('--fallback %s' % r["endpoint"] for r in doh[:2]) if doh else '--fallback https://doh.pub/dns-query'} \\
  {boot} \\
  --special-list "$SPECIAL_LIST" \\
  --timeout 3 \\
  --cache \\
  --refuse-any
"""
    (OUTDIR / "aiodns.sh").write_text(sh, encoding="utf-8")

    # AdGuard Home 上游片段
    yaml = f"""# NoAS · AdGuard Home 上游片段（YAML 键名与 AGH 配置文件一致）
# 用法：编辑 AdGuardHome.yaml 的 dns 段，替换 upstream_dns / bootstrap_dns 后重启
# AGH 免费、无调用额度，是"规则 + 通道"一起用的推荐方案
dns:
  upstream_dns:
{"".join("    - %s\n" % r["endpoint"] for r in doh)}  bootstrap_dns:
    - 223.5.5.5
    - 119.29.29.29
  upstream_dns_file: ""
  fallback_dns:
    - https://noas-doh.199999510.workers.dev/dns-query
"""
    (OUTDIR / "adguardhome-upstream.yaml").write_text(yaml, encoding="utf-8")

    # README
    table = ["| 序号 | 通道 | 协议 | 地址 | 角色 | 状态 | 说明 |",
             "|---|---|---|---|---|---|---|"]
    for i, r in enumerate(rows, 1):
        st = (health.get(r["name"]) or {}).get("status", "未测")
        if st == "ok":
            st = "ok · %sms" % (health[r["name"]].get("rtt_ms") or "-")
        table.append("| %d | `%s` | %s | `%s` | %s | %s | %s |"
                     % (i, r["name"], r["proto"], r["endpoint"], r["role"], st, r["note"]))

    md = f"""# NoAS · DNS 通道（最低够用版）

原则：**主一备一，绝不铺满；额度不超，接近上限就熔断。**

## 通道表

{chr(10).join(table)}

健康检查时间：{checked_at or "尚未运行"}
{"⚠️ 本次体检环境异常（判定为代理劫持/网络不可达），已回退为**完整清单**，未经在线验证。" if fallback else "down 的通道已在 `doh.txt` / `dot.txt` 里自动剔除，不会推荐给客户端。"}

## 三种用法（按精力选一种）

### 1. 只要通道（最省事）
把 `doh.txt` 里的地址逐个填进手机的"私人 DNS / 自定义 DoH"，或路由器 DNS。
只换解析通道，不带任何拦截规则 —— 也最不容易误伤。

### 2. 通道 + 规则（推荐）
AdGuard Home：上游填 `adguardhome-upstream.yaml` 里的地址，过滤器订阅
`https://noas-cdn.pages.dev/subs/lite/adguard.txt`。
AGH 免费无额度，规则和通道都在本地，最稳。

### 3. 通道 + 分流（进阶）
`bash aiodns.sh`，本机 5300 端口起 aiodns：国内域走阿里/腾讯直连，开缓存。
**注意 aiodns 不做拦截**，拦截仍需第 2 步的 AGH 或 hosts。

## 额度红线（这就是"额度不超"）

| 资源 | 免费额度 | 本方案怎么守 |
|---|---|---|
| CF Workers | 10 万请求/天（UTC 0 点重置） | 只做兜底；Worker 内 90% 熔断 + 单 IP 120/分钟 |
| CF KV | 读 10 万 / 写 1000 每天 | 通道计数只用内存，**绝不写 KV** |
| CF D1 | 读 500 万行 / 写 10 万行每天 | 规则不进库，只有单行状态 |
| GitHub raw / Pages | 不限 Actions 分钟；Pages 约 100GB/月 | 订阅分发全走这里，零额度压力 |
| 阿里/腾讯 DoH | 无公开调用上限 | 主通道，日常主力 |

## 已知的坑（踩过就别再踩）

- DoT 必须带 **2 字节长度前缀**（DNS over TCP 帧格式），少这个直接收不到回应。
- Worker 全局作用域不能做异步 I/O，规则只能同步切分，不能解压。
- 本机若挂了代理，所有 853/53 探测会拿到假响应（rcode 4/5 且极快），此时健康检查会判 `env=suspect` 而不是判通道死。
"""
    (OUTDIR / "README.md").write_text(md, encoding="utf-8")

    DOCS.mkdir(parents=True, exist_ok=True)
    for f in ("README.md", "doh.txt", "dot.txt", "dot-preferred.txt", "aiodns.sh",
              "aiodns.special.txt", "adguardhome-upstream.yaml", "health.json"):
        src = OUTDIR / f
        if src.exists():
            (DOCS / f).write_text(src.read_text(encoding="utf-8"), encoding="utf-8")

    print("通道产物：%d 条（可用 %d／已剔除 %d%s）→ %s"
          % (len(rows), len(alive_up), len(dead_up),
             "／体检异常→回退完整清单" if fallback else "", OUTDIR))


if __name__ == "__main__":
    main()
