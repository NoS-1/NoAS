# 客户端接入

三条通道，任选一条（也可同时用）：

| 通道 | 地址 | 特点 |
|---|---|---|
| DoH（Pages，首选） | `https://noas-cdn.pages.dev/dns-query/{lite,mid,full,auto}` | 国内可直连，首包 0.9–1.3s，支持 `?v6=v4only`、`?mode=nxdomain`、`?ecs=off` |
| DoH（Gateway） | `https://oxyacq0a4t.cloudflare-gateway.com/dns-query` | CF 网络层拦截，首包更快（382ms）；不走我们的 Worker 逻辑（没有 CNAME 多跳/TTL 钳制） |
| 本地规则订阅 | `https://noas-cdn.pages.dev/subs/{lite,mid,full}/adguard.txt` | 客户端自己跑规则，零云端依赖 |

`auto` 会按 UA 推断档位：AGH / sing-box / clash / mihomo / openwrt / dnsmasq / unbound / stubby → full；
Android / iOS / macOS / Windows → mid；其余 → lite。

## AdGuard Home

```
上游 DNS: https://noas-cdn.pages.dev/dns-query/mid
（设置 → DNS 设置 → 上游 DNS 服务器，只能填一个 HTTPS 地址时用 mid）
```

AGH 支持多个上游并行，但会把查询分摊到各上游；只填一个才能保证每次都走本服务。

## sing-box / SFA

```json
{ "type": "https", "tag": "noas", "server": "noas-cdn.pages.dev", "server_port": 443,
  "path": "/dns-query/full", "domain_strategy": "prefer_ipv4" }
```

## mihomo / Clash.Meta

```yaml
dns:
  enable: true
  nameserver:
    - https://noas-cdn.pages.dev/dns-query/full
  fallback: []
```

## OpenWrt / 路由器

dnsmasq 本身不支持 DoH。两条路：
1. 装 AdGuard Home 或 sing-box，按上面配置；
2. 用 Gateway 的 DoH，配合 `https-dns-proxy`。

## Windows / macOS

系统层没有通用 DoH 开关（Windows 11 需手动加 DoH 模板，要求域名有 DoT/DNS 记录支持，本项目不提供）。
实际做法：本机跑 AdGuard Home / sing-box，把系统 DNS 指向它。

## Android / iOS

- **Android 系统级 Private DNS 只支持 DoT**，而 DoT 853 在国内被封 → 系统级接入走不通。
  只能装 App（AdGuard / sing-box / mihomo）配 DoH。
- iOS 需要装 DNS 描述文件或 App；系统不原生支持 DoH。

## 群晖 / NAS

无内置 DoH 客户端，用 Docker 跑 AdGuard Home，再按上面配置。

## 一键导入（复制链接就能用）

| 通道 | 粘贴这个 | 适合 |
|---|---|---|
| 订阅 · lite | `https://noas-cdn.pages.dev/subs/lite/adguard.txt` | 老设备/内存紧张，误伤最低 |
| 订阅 · mid | `https://noas-cdn.pages.dev/subs/mid/adguard.txt` | 日常主力（订阅默认选这个） |
| 订阅 · full | `https://noas-cdn.pages.dev/subs/full/adguard.txt` | 覆盖优先，接受长尾误伤 |
| DoH · 自动分档 | `https://noas-cdn.pages.dev/dns-query/auto` | 一个地址搞定，UA 自动判档 |
| DoH · 固定 mid | `https://noas-cdn.pages.dev/dns-query/mid` | 不想让客户端猜 |
| DoH · Gateway | `https://oxyacq0a4t.cloudflare-gateway.com/dns-query` | 想要网络层拦截（含 DoT 853，国内被封） |

> 都是 GET/POST 双支持的 RFC 8484 端点，`content-type: application/dns-message`。
> 解析结果可疑时先跑 `https://noas-cdn.pages.dev/why?d=域名&tier=2`，确认是哪一层判的。
