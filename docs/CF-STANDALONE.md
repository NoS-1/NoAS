# CF 侧独立运行与依赖解耦

## 一、结论

CF 侧**运行期只依赖自身内嵌制品**（worker.js 里已编译进 lite+mid 规则），不依赖 GitHub 在线可达。
唯一从仓库读取的是 `state/build_manifest.json`（KB 级构建指纹，每 15 分钟 1 次，可关）。
仓库侧只是"构建 + 推送"的上游，**CF 不回写仓库，仓库不依赖 CF 运行态**。

## 二、必须经过仓库的东西（全部清单）

| # | 项目 | 用途 | 谁读 | 频率 | 缺失后果 | 可关 |
|---|---|---|---|---|---|---|
| 1 | `lists/` + `subs/{lite,mid,full}/domains.txt` | 规则唯一真源 | compile / build_doh / gateway_sync / gateway_prune | 每日 | 规则不再更新（线上照旧跑） | 否 |
| 2 | `state/build_manifest.json` | 判断线上规则是否落后 | Worker `scheduled()` | 每 15 分钟 1 次（KB 级） | `rules_stale=null`（未知，不告警） | 是（清空常量） |
| 2b | `subs/lite/domains.txt` | 热规则（不重部署也能换规则） | Worker `scheduled()` → KV | 仅版本变化时拉（约 140KB） | 继续用内嵌基线 | 是（不绑 KV 即关闭） |

> 2 和 2b 都是**双源**：先拉自建 CDN `https://noas-cdn.pages.dev/...`（Pages，带宽不限、无匿名限流），失败再回落到 GitHub raw。原因是 GitHub 从 2025-05 起把匿名 `raw.githubusercontent.com` 压到约 60 次/小时/IP，单靠它做每 15 分钟轮询会被限流，且 CF 边缘访问 raw 实测不通。
| 3 | `doh/worker.tpl.js` | 代码模板 | build_doh | 改代码时 | 无法重建制品 | 否 |
| 4 | `doh/worker.js` | 部署输入 | deploy_doh | 每轮 | 线上停在旧版 | 可由模板重生成 |
| 5 | `state/gateway_rules.bak.json` | Gateway 规则灾备 | 人工/回滚 | 变更时 | 无备份 | 否 |
| 6 | Pages 静态产物（`site/`） | 分发与展示 | CI | 每轮 | 站点停旧版 | 否 |

除以上 6 项，**没有任何东西需要经过仓库**：AE、Workers Logs、Gateway 列表、Cron、熔断状态全部在 CF 云端自持。

## 三、单向数据流（谁只读谁）

```
上游清单 ──► lists/ ──► subs/lite ─┐
                      subs/mid  ──┼─► doh/worker.js ──► CF Worker（内嵌，运行期零外呼）
                      subs/full ──┘
                      subs/lite ──► CF Gateway 列表（规则镜像）
                      subs/paths / ubo ──► Pages
CF AE / Logs / Cron ──► 只读观测（不进构建判定）
```

每级只读上一级的**文件契约**（路径 + 指纹），不读对方代码、不依赖对方运行状态。

## 四、消除互相依赖的 6 条硬规则

1. **文件契约**：每级产物旁写指纹 JSON（`version` / `sha256` / `counts`），下游校验指纹，不靠猜结构。现有 `state/compile_fingerprint.json`、`state/build_manifest.json`。
2. **禁止反向写**：CF 不写仓库；CI 只 push 产物，不根据线上运行态改判定（线上状态只用于告警）。
3. **失败隔离**：任一环失败都不阻断服务——内嵌规则兜底 + 熔断降级直转 + workflow 各步 `continue-on-error`。
4. **运行期零外呼**：DNS 应答路径不访问 GitHub；只有 cron 每 15 分钟读 1 次 KB 级指纹。
5. **单点开关**：AE 绑定（`DOH_AE_DATASET=off`）、版本哨兵（置空 `MANIFEST_URL`）、Gateway 同步（默认干跑）都能独立关，关掉不影响解析。
6. **幂等**：所有写入脚本先算差异、默认干跑、`--apply` 才写；重跑结果一致。

## 五、CF 侧已有的自治能力

- **规则内嵌**：`doh/worker.js` ≈ 4.7 MB，lite 9903 + mid 210385 + 通配 57 + 端点 59 直接编进模块，冷启动即生效。
- **Cron 自治**（`*/15`，96 次/天，占免费额度 0.1%）：
  - 心跳写 AE（GitHub Actions 挂了也能看出 Worker 活着）；
  - 版本哨兵：读 `build_manifest.json` 比对 `VERSION`，落后则写 `stale` 点并使 `/health.rules_stale=true`；
  - 上游自检：内置最小 A 报文直问上游（绕过自身规则层），成功则自动解除降级，失败写 `upstream-dead`。
- **熔断不再断服**：额度到 90% 或单 IP 超 300/min 时，**跳过规则匹配直接转发**，响应头 `x-noas: degraded`，客户端无感；UTC 换日或 cron 自检成功后自动恢复。
- **上游容错**：阿里 / 腾讯 / 360 三条 DoH，单条 5s 超时即切换。
- **热规则自更新**（KV `RULES`）：cron 读 manifest 发现版本变化时，才拉 `subs/lite/domains.txt` → 条数/金丝雀双校验 → 存 KV；请求 isolate 冷启动读一次 KV，之后全走内存。**不重部署也能换规则**，校验不过就丢弃、继续用内嵌基线。源是 Pages 优先、raw 兜底；解析用一次换行替换 + 计数，避免 Free cron 的 10ms CPU 被上万行 split/join 吃掉。
- **每日自检**（UTC 0 点那一轮）：只读本 isolate 状态，写一条 `diag` 点，内容包括三档条数、热规则条数、当前版本、上游失败数、是否降级。一条日志就能回答"线上到底装的是什么"。
- **上游断线兜底**（Cache API）：放行应答按 qname+qtype 缓存 300s（与拦截 TTL 一致）；三条上游全挂时先回缓存再报错，客户端不至于彻底解析失败。Cache 免费且不计 Worker 请求额度。
- **观测**：AE（绑定缺失静默）+ Workers Logs 1% 采样；pass 只采样 5%，block/cname/cron 全量；AE 写点有 9 万/天硬上限（免费额度 10 万），到顶后静默丢弃，绝不因写日志失败拖慢应答。

## 六、依赖矩阵：哪一环坏了会怎样

| 失败环节 | 线上表现 | 恢复方式 |
|---|---|---|
| GitHub Actions 全挂 | DoH/Gateway 照常服务，规则停在旧版 | 修 CI 或本地手动跑 deploy |
| 上游清单抓取失败 | 沿用上次 `subs/`，不重建 | 下轮重试 |
| compile / build 失败 | 产物不变，线上不受影响 | 修脚本后重跑 |
| deploy 失败 | 线上继续跑旧 worker，`rules_stale=true` | 重跑 `tools/deploy_doh.py` |
| Gateway 同步失败 | Gateway 保留旧列表，规则仍生效 | 重跑 `tools/gateway_sync.py --apply` |
| AE 写入失败 | 仅丢观测，DNS 应答不受影响 | 无需处理 |
| 三条上游全挂 | 返回 502 + `degraded=upstream-down` | 上游恢复后 cron 自动复位 |
| 仓库 raw 不可达 | `rules_stale=null`（未知），不误报 | 网络恢复后自动恢复 |
| Pages 部署异常 | 站点回到 500，规则分发中断；DoH/Gateway 不受影响 | `cdn_deploy.py` 用 wrangler 重发 + 取文验证，不通过即红 |
| 触发 1,000 次/分钟准入 | 部分请求被平台直接拒绝，Worker 内无法自救 | 靠 Gateway 分流 + 本地规则把请求量压下来 |

## 七、明确不做

- 多账户刷额度（违规且互相拖累）
- KV 当请求计数器（1000 写/天会被瞬间打爆）
- D1 存访问日志（500 万行读/天留给配置与状态）
- 把 mid/full 全量塞进 Gateway（列表上限约 100，会直接撞墙）
