# NoAS · DNS 通道（最低够用版）

原则：**主一备一，绝不铺满；额度不超，接近上限就熔断。**

## 通道表

| 序号 | 通道 | 协议 | 地址 | 角色 | 状态 | 说明 |
|---|---|---|---|---|---|---|
| 1 | `ali-doh` | ndoh | `https://dns.alidns.com/dns-query` | primary | unknown | 阿里公共 DNS，国内最快，无调用额度 |
| 2 | `tencent-doh` | ndoh | `https://doh.pub/dns-query` | backup | unknown | 腾讯 DNSPod，国内直连，无调用额度 |
| 3 | `ali-dot` | dot | `tls://dns.alidns.com:853` | backup | unknown | 同上加密通道（DoT），客户端支持 TLS 时用 |
| 4 | `tencent-dot` | dot | `tls://dot.pub:853` | backup | unknown | 腾讯 DoT，移动/联通线路稳 |
| 5 | `aiodns-local` | aiodns | `127.0.0.1:5300` | local | absent | 本机 aiodns（honwen/aiodns），做国内分流 + 缓存，零额度 |
| 6 | `gateway-doh` | doh | `https://oxyacq0a4t.cloudflare-gateway.com/dns-query` | gateway | unknown | 自建带规则 DoH（Zero Trust Gateway，7 条档位规则），免费额度远高于 Worker |
| 7 | `gateway-dot` | dot | `tls://oxyacq0a4t.cloudflare-gateway.com:853` | gateway | unknown | 自建带规则 DoT；端点已启用且免 token，需 CI 干净网络验证 |
| 8 | `cf-doh` | doh | `https://noas-doh.199999510.workers.dev/dns-query` | last | unknown | 自建规则层，仅兜底；10 万/天，90% 自动熔断 |

健康检查时间：2026-11-20T23:52:05Z
⚠️ 本次体检环境异常（判定为代理劫持/网络不可达），已回退为**完整清单**，未经在线验证。

## 三种用法（按精力选一种）

### 1. 只要通道（最省事）
把 `doh.txt` 里的地址逐个填进手机的"私人 DNS / 自定义 DoH"，或路由器 DNS。
只换解析通道，不带任何拦截规则 —— 也最不容易误伤。

### 2. 通道 + 规则（推荐）
AdGuard Home：上游填 `adguardhome-upstream.yaml` 里的地址，过滤器订阅
`https://raw.githubusercontent.com/NoS-1/NoAS/main/subs/lite/adguard.txt`。
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
