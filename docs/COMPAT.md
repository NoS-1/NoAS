# 客户端兼容矩阵

| 客户端 | DoH | 只认 GET | 只认 HTTP/2 | ECS | 备注 |
|---|---|---|---|---|---|
| AdGuard Home | ✅ | ✅ | ✅ | 透传 | 推荐；多上游会分摊，建议只填一个 |
| sing-box | ✅ | ✅ | ✅ | 可关 | `type: https` |
| mihomo / Clash.Meta | ✅ | ✅ | ✅ | 可关 | `nameserver` 直接写 https |
| unbound | ✅ | ❌（只 POST） | ✅ | 透传 | 老版本要求 POST |
| dnsmasq | ❌ | — | — | — | 需配 https-dns-proxy |
| stubby | ✅（DoT 为主） | — | — | — | DoT 853 国内被封，实际不可用 |
| Windows 10/11 | 需模板 | — | — | — | 系统不认自定义 DoH 域名 |
| Android Private DNS | ❌（只 DoT） | — | — | — | 国内 853 被封 → 不可用 |
| iOS | 描述文件/App | — | — | — | 无原生 DoH |

## 我们已适配的差异

- **GET 与 POST 都支持**：RFC 8484 两种形态，Pages 内部统一转 POST 给 Worker（避免查询串重编码）。
- **ECS**：客户端自带就透传；没有就按客户端 IP 生成 `/24`；`?ecs=off` 可关闭。
- **AAAA**：默认原样返回；`?v6=v4only` 回空答，让客户端立刻回退 A。
- **拦截响应**：默认 `0.0.0.0` / `::`；`?mode=nxdomain` 可改成 NXDOMAIN。
- **ANY / CHAOS**：直接回 NOTIMP(4)，不走上游（防反射放大）。
