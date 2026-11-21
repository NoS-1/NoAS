# 降级、备份与迁移

## 单点故障：整套服务压在一个 CF 账号

Pages、Worker、Gateway、KV、AE 同账号。若账号被风控/欠费/封禁，全链路同时消失。
这不是“概率低所以不管”，而是必须有手册：

### 5 分钟内恢复（降级到客户端本地规则）

1. 从 GitHub Release 下载最新快照：`gh release download latest -p noas-snapshot.zip`
2. 把 `subs/<档位>/adguard.txt` 直接导入客户端（AdGuard、AGH 本地跑规则）
3. 从此不再依赖云端，代价是没有逐请求判定、CNAME 多跳、ECS 就近、TTL 钳制。

### 换云端（需重写部署层）

Worker 是标准 fetch handler，可迁到 Deno Deploy / Vercel Edge / 自建 Node（`serve/standalone.mjs` 已是自建版本）。
不能迁的是 **Gateway 那套网络层拦截**（CF Zero Trust 专有）—— 只能退回“只做 DoH”。

迁移步骤：
1. 部署 `serve/standalone.mjs` + `doh/worker.js` 到新平台（Dockerfile 已备）
2. 改客户端地址到新域名
3. Gateway 相关的三档列表暂时失效，接受覆盖下降

## 备份

- 规则快照：GitHub Release（`latest` + 最近 5 个 `snap-YYYYMMDD-HHMM`）
- 工作树备份：本地 `NoAS-worktree-backup-*.tar.gz`
- 历史瘦身前的完整历史：tag `pre-slim-20261121`
- 凭据：`/home/user/.noas/creds.env`（600，不入库）
