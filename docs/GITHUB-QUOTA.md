# GitHub 免费额度的真相与分工（2026-11-21）

## 一句话

**public 仓库的 Actions 分钟数本来就不计费** —— 我们这套仓库是 public，所以「免费额度接近无限」不是靠技巧换来的，而是本来就成立。真正会撞墙的不是分钟数，而是**仓库体积、Artifact 存储、Release 累积**这三件存储类限制。这一轮把它们全部收掉了。

## 官方口径（免费档）

| 项目 | 免费档限制 | 我们的用法 | 状态 |
|---|---|---|---|
| Actions 分钟数（public 仓库） | **不计费**（无月度上限） | 4 轮/天 × 约 90 秒 ≈ 6 分钟/天 | 距上限无穷远 |
| Actions 分钟数（private 仓库） | 2,000 分钟/月 | 不适用（本仓库 public） | — |
| 并发 job | 20（Free） | 1 个 daily job，concurrency 组互斥 | 1/20 |
| 单 job 时长 | 6 小时 | 约 90 秒 | 0.4% |
| 仓库建议体积 | soft 1 GB / 单文件 100 MB | 见下 | 已压缩增量 |
| Actions 缓存 | 10 GB/仓库 | 只用 pip/npm 默认 | < 200 MB |
| Artifact 存储 | 随 retention 计 | 3 档小产物，`retention-days: 7` | 约 10 MB |
| Release 资产 | 单文件 2 GB | 固定 tag `latest` + `--clobber`，永远只有一个 | 不累积 |
| API 配额 | 5,000 请求/小时（PAT） | 构建内约 20 次 | 0.4% |
| GitHub Pages | public 100 GB/月 | **已停用** | 归零 |

## 这一轮改了什么

1. **data 分支停用**。单订阅全格式（`subs/all` × 多种格式）由 CF Pages 承载（`/subs/all/*`），GitHub 不再做分发。省掉每轮 25s 的 git push，也不再往仓库写 MB 级二进制。
2. **GitHub Pages 部署停用**。站点走 CF Pages（`https://noas-cdn.pages.dev`），免费无限流量、国内可达。省掉 configure/upload/deploy 三步约 15s。
3. **入库清单瘦身**。`subs/mid`、`subs/full`（本来就不入库）、`docs/`（3.5 MB）不提交；旧 `subs/mixed`、`subs/paths` 已随 DNS-only 改造物理删除；只留规则源、`subs/lite` 与 `subs/all`（克隆即用）、代码、`state`/`history` 台账。
4. **提交降频到每天一次**。4 轮/天里只有 03:17 那轮落 git，其余三轮产物直接进 CF。历史增长从 ~1 MB/轮降到 ~1 MB/天（降 75%）。
5. **Artifact retention 14 → 7 天**。
6. **Release 只保留一个 `latest` tag**（`--clobber` 覆盖），不会按月累积。
7. **客户端链接全部改 CF**：README、`verify`、`probe`、`gen_channels` 里的 `raw.githubusercontent.com` / `nos-1.github.io` 均已替换为 `noas-cdn.pages.dev`。Worker 的热规则源本来就是 CF 优先，GitHub raw 仅作第二兜底。

## 现在的分工

```
GitHub                         Cloudflare（免费档）
├─ Actions：拉源 → 编译 → 校验  →  Pages：单订阅全格式 + 站点 + DoH 统一入口
├─ 仓库：规则源 + lite + 代码    →  Workers：DoH 判定 / 上游竞速 / KV 热规则
└─ Release：latest 单包（留档）   →  Gateway：60 片云列表（单订阅全量，最快通道）
```

GitHub 只负责「算」，CF 负责「发」。仓库里除了必须的数据（规则源、lite、代码、台账），不再有任何分发产物。

## 还剩的硬限（改不了，但够用）

- CF Workers 免费 **10 万请求/天**（同账户共享）：到 90% 自动降级直转，客户端不断服。
- CF Gateway 免费 **约 10 seats**：按 seat 计 5,000 次/天/seat，与 Worker 额度**互不占用**。
- CF KV 免费 **写 1,000/天**：只在显式声明档位或版本变化时写。
- GitHub 仓库 1 GB 建议线：按现在每天约 1 MB 的增量，跑三年仍在安全区；真要触线时把 `subs/lite` 也迁到 CF（Pages 已经在托管同一份文件）。
