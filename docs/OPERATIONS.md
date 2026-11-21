# 运维手册 · 凭据与状态怎么看

> 只写位置和入口，不写任何令牌值。凭据本体永远只在 `/home/user/.noas/creds.env`（600）。

## 一、四枚凭据在哪、谁能动

| 名称 | 级别 | 作用 | 在哪看 | 能自动轮换吗 |
|---|---|---|---|---|
| `GH_PAT` | GitHub 个人令牌 | 本机推送、写 Actions secret、备份同步 | [github.com/settings/tokens](https://github.com/settings/tokens) | 否（手工重建） |
| `CF_USER_TOKEN` | CF **user 级**根令牌 | 签发/删除 account token | [dash.cloudflare.com/profile/api-tokens](https://dash.cloudflare.com/profile/api-tokens) | 否（它是根） |
| `CF_API_TOKEN` | CF **account 级**令牌 | 部署 Pages / Worker / D1 | [dash.cloudflare.com/?to=/:account/api-tokens](https://dash.cloudflare.com/?to=/:account/api-tokens) | 是，每 30 天 |
| `GH_APP_*`（未启用） | GitHub App | 推送双保险的备用路 | [github.com/settings/apps](https://github.com/settings/apps) | 每次现签，1 小时失效 |

关键点：account 级令牌在 CF 协议层**无法**派生其它令牌（`sub-token is not allowed to have permissions to manage other tokens`），所以只有 user 级根令牌能驱动轮换。根令牌丢了，轮换链就断，只能回后台重建一枚。

## 二、手机上怎么看状态

- 构建是否正常：[github.com/NoS-1/NoAS/actions](https://github.com/NoS-1/NoAS/actions) —— 每日 4 轮，每轮 30 步全绿即没问题
- 失败告警：[Issues](https://github.com/NoS-1/NoAS/issues) —— 只有 `failure/timed_out/action_required` 才开单，`cancelled` 不再误报；恢复后自动评论并关闭
- 误拦率与规模：[precision.html](https://noas-cdn.pages.dev/precision.html) —— 三档误拦率、规则条数、黄金集通过情况
- 构建明细：[tasks.html](https://noas-cdn.pages.dev/tasks.html) · DNS 延迟：[dns-latency.html](https://noas-cdn.pages.dev/dns-latency.html)
- CF Pages 部署历史：[dash.cloudflare.com/?to=/:account/pages/view/noas-cdn](https://dash.cloudflare.com/?to=/:account/pages/view/noas-cdn)
- CF Worker（DoH）：[dash.cloudflare.com/?to=/:account/workers-and-pages](https://dash.cloudflare.com/?to=/:account/workers-and-pages)

## 三、本机命令

```bash
cd /home/user/NoAS
python3 tools/cf_rotate.py --doctor   # 根令牌故障第一站：四段链路逐段点亮 + 下一步动作
cat /home/user/.noas/creds.env       # 看当前值（600，不入库）
python3 tools/token_check.py         # GitHub PAT + CF 令牌双体检
python3 tools/cf_rotate.py --check    # 轮换链路体检，不动手
python3 tools/cf_rotate.py --backup-only  # 把 creds.env 同步到私有备份仓库
cat state/cf_rotation.json           # 上次轮换时间 / 新旧令牌 id
```

`--doctor` 只读，输出直接写成"去点哪里、跑哪条命令"；`--check` 判断能不能轮换；`--force` 才真轮换；`--keep-old` 保留旧令牌便于回滚。

## 四、轮换节奏

- 触发条件：`state/cf_rotation.json` 里 `last_rotated` 超过 30 天
- 执行环境：必须在有 `creds.env` 的机器上（CI 里没有 `GH_PAT`，内置 `GITHUB_TOKEN` 无权写 secret）
- 流程：签新令牌 → verify → 写 GitHub secret → 回写 `creds.env` → 自动同步私有备份 → 删旧令牌
- 失败回滚：任一步失败即删掉新令牌，旧值不动，两端不会对不上
- 首次自举已完成（`NoAS-Root` 根令牌已建）

## 五、凭据泄露怎么办

1. CF：删掉对应的 user / account 令牌，重跑 `python3 tools/cf_rotate.py --force`（会重新签发并回写 secret）
2. GitHub：撤销 PAT，重建后写回 `creds.env` 的 `GH_PAT`，再跑 `--backup-only`
3. 检查是否已被使用：CF 看令牌 `上次使用` 时间，GitHub 看设置页 `Last used within`
4. 私有备份仓库 `noas-secrets` 里是编码后的同一份内容，泄露处置后记得同步覆盖

## 六、根令牌出问题时的四条路径

先跑 `python3 tools/cf_rotate.py --doctor`，它会把下面四段逐段点亮，缺哪段就直说缺哪段。

| 出问题的环节 | 表现 | 一条命令修好 |
|---|---|---|
| 根令牌失效/被删 | `--doctor` 第一行 ✗ | 后台重建 `NoAS-Root` → 改 `creds.env` 的 `CF_USER_TOKEN` → `cf_rotate.py --force` |
| 现用令牌失效 | Pages/Worker 部署全 4xx，`--doctor` 第二行 ✗ | `cf_rotate.py --force`（用根令牌签新的，自动回写 secret） |
| GitHub secret 缺失或过期 | CI 里 `0 · 凭据健康检查` 红 | `cf_rotate.py --force`（自动写 secret） |
| GH_PAT 失效 | 本地推送 403 | 后台重建 PAT → 改 `creds.env` 的 `GH_PAT` |

最底的一条：**根令牌本身不能自助重建**，它只能由已登录的人在 CF 后台建一次。所以根令牌一旦删掉，必须人工重建；其余三段都能由一行命令自愈。

## 七、持久副本（VM 没了也拿得回来）

- 位置：私有仓库 `NoS-1/noas-secrets`，文件 `creds.b64`（base64 编码，非明文）
- 本机镜像：`/home/user/.noas/backup`（700，凭据经 credential helper 取，命令里不含令牌）
- 何时同步：每次 `--force` 轮换成功后自动同步；也可手动 `--backup-only`
- 还原（新机器上）：

```bash
mkdir -p /home/user/.noas
base64 -d creds.b64 > /home/user/.noas/creds.env
chmod 600 /home/user/.noas/creds.env
cd /home/user/NoAS && python3 tools/cf_rotate.py --doctor
```

- 边界：私有仓库只对本账号可见，但仓库权限不等于加密——账号被盗即副本被盗。建议给 GitHub 账号开 2FA。

## 八、免费额度地图（什么在花、花在哪）

| 资源 | 免费额度（2026-11 官方实测口径） | 本项目用法 | 守门 |
|---|---|---|---|
| Workers 请求 | **10 万次/天**（同账户所有脚本共享，UTC 0 点重置＝北京 08:00）；**准入另限 1,000 次/分钟**；CPU 10ms、内存 128MB、外部 subrequest 50、脚本 64MiB、启动 1s | DoH 判定 `/dns-query` | 到 90%（9 万）转**降级直转**（`x-noas=degraded`），客户端不断服；恢复由 UTC 换日自动完成 |
| Pages | 请求与带宽不限；**部署 500 次/月**、单站 2 万文件、单文件 25MiB | 规则包静态分发，也是 Worker 热规则的主源 | `tools/quota_check.py`，≥350 让构建红 |
| Analytics Engine | 写 **10 万点/天**、读 **1 万查询/天**（不是旧文档写的 1 亿/月） | 只记 DNS 判定（block / cname / pass 抽样 / cron） | 代码内 `AE_DAILY_CAP=90000` 硬上限，超了静默丢日志 |
| Workers Logs | 现口径 20 万事件/天、保留 3 天；**2026-12-01 起改用 Observability 计价：免费 0.5GB/天摄取、保留 7 天** | 只开 1% 采样 | 采样率写死在部署配置里 |
| D1 | 读 500 万行/天、写 10 万行/天、5GB | 只放配置与状态 | 日志一律不进 D1 |
| KV | 读 10 万/天、写 1000/天、1GB | 只放低频状态（热规则 `lite_v1`） | 计数绝不写 KV；写入只在版本变化时 |
| Gateway | Free 定价页有"50 用户"与"实际 10 user limit"两种表述；**DNS 查询按 seat 计：平均 5,000/seat/天（月均 15 万/seat）**；Lists 100 个、每表 1,000 条、List API 600 次/分；规则表达式上限 4,096 字符 | **三档全量（lite 10 片 / mid 20 片 / full 30 片，共 60 片 6 万条）+ 3 条 override** —— 定档后规模装得下，Gateway 通道（首包 382ms／复用 210ms，比 Pages 快一倍）可独立覆盖全档 | `gateway_all.py` 幂等同步 + `gateway_align.py` 回读三档 缺 0/多余 0；列表数 60/100 留 40 片余量 |

分摊顺序（从最省到最贵）：

1. **本地规则**：sing-box / AdGuard Home 直接吃 lite 表 → 0 请求、0 延迟；
2. **CF Gateway DoH**（`https://oxyacq0a4t.cloudflare-gateway.com/dns-query`）：**DNS 查询不计 Worker 请求**，额度按 seat 单独算。已实测拦截生效：doubleclick.net / googleadservices.com 返回 `0.0.0.0`，baidu.com 返回真实 IP。注意别写成 `oxyacq0a4t4`——多一个 4 会拿到「不过滤」的应答，看着通、其实没拦；
3. **Worker 判定**：只有 Gateway 覆盖不到的长尾才走；
4. **国内 DoH 回落**：阿里 / 腾讯 / 360，额度不归我们。

### 分档端点（DoH 客户端「知道自己用哪一档」）

Pages 的 DoH 端点按档位服务，客户端在配置 URL 里写档位即声明：

| 路径 | 条数 | 适用 |
|---|---|---|
| `/dns-query/lite` | 1 万 | 低配设备、只要零误伤最小集 |
| `/dns-query/mid` | 2 万 | 手机默认（Android 私人 DNS 只能填主机名 → 靠 UA 自动判 mid） |
| `/dns-query/full` | 3 万 | 路由器 / AGH / 桌面 |
| `/dns-query` | 自动 | UA 判定：AGH·sing-box·clash·openwrt → full；手机·桌面 → mid；其余 → lite |

显式覆盖：`?tier=full` 或请求头 `x-noas-tier: full` —— 会写入 STATS KV（`t:<ipHash>:<uaHash>`，同 IP 同 UA 只写一次，避免共享出口串档）。
响应头 `x-noas-tier` / `x-noas-tier-count` 回显实际档与条数；`GET /tier` 返回同一份 JSON，客户端可自查。
每次请求只加载自己那一档：lite 196KB / mid 360KB / full 572KB，isolate 内存缓存 10 分钟，命中直接回 0.0.0.0，不跳 Worker。
不达标（条数低于阈值）一律整条退回 Worker 兜底，绝不误拦。

### 规则定档（2026-11-21）

三档硬上限：**lite 10,000 / mid 20,000 / full 30,000**。裁剪口径国内优先：
必留集（国内端点、核心广告网、SDK、贴片、挖矿、被 lite 命中的父域）→ 国内名单/`.cn` → 多源共识分 → 命中源数；
**海外 ccTLD 长尾（`.ca` `.au` `.uk` `.de` `.jp` 等）直接排除**，full 通配也只留 3,000 条。
归因/统计域（adjust、appsflyer、branch、telemetry）三档一律不拦 —— 拦了只误伤 App 上报。
`guard.py` 只看"是否凑齐目标九成"，不再比较历史规模（主动裁剪会跌 90%，那是策略不是故障）。

按官方数字算，这套结构的天花板不是"无限"，而是 **约 15 万次/天**：Gateway 10 seats ≈ 5 万 + Worker 10 万，两者互不占用。再往上就只能靠 L0 本地过滤把请求消掉——这也正是 lite 表要一直维持在 1 万条以内的原因。

通道实测（2026-11-21，国内直连，各 3 轮取中位）：

| 端点 | TCP 建连 | TLS | 首包 | 结论 |
|---|---|---|---|---|
| Gateway DoH `oxyacq0a4t.cloudflare-gateway.com` | 0.09~0.10 s | 0.22~0.25 s | 0.33~0.38 s | **最快**，就近边缘，拦截实测 0.0.0.0 |
| Pages DoH `noas-cdn.pages.dev`（承载自建 Worker） | 0.20~0.21 s | 0.51~1.52 s | 1.03~1.78 s | 落在远端边缘，TLS 抖动大；连接复用后降至几十 ms |
| `noas-doh.199999510.workers.dev` | 超时 6.2 s | — | — | **国内被阻断**，只能走 Pages 承载 |
| `1.1.1.1/dns-query` | TCP 不通 | — | — | 国内不可达 |
| `cloudflare-dns.com/dns-query` | 0.22 s | 握手失败 | — | TCP 通、TLS 被重置，不可用 |
| Gateway DoT `:853` | 建连成功 | 握手后读超时 | — | **853 端口普遍被阻断**，国内不要主用 DoT |

结论：服务端处理时间可忽略（Worker 命中缓存 0ms、未命中上游竞速 5~40ms），**延迟几乎全部来自"国内→CF 最近边缘"的建连**。所以顺序是 ① 本地规则 ② Gateway DoH（就近边缘）③ Pages 承载的全规则档，DoT 仅作境外/可用环境备用。

Pages 这一档做了两级判定：`lite`（9,902 条零误伤集）在 **Pages 边缘直接应答**（`x-noas-path: pages-local`，不跳 Worker），其余域名透传 Worker 走 mid 全量规则。长连接实测（温州，2026-11-21）：边缘拦截 237~336 ms ≈ 单个 RTT，透传 267~834 ms——省掉的那一跳就是 150~500 ms。

再加两层结果缓存：`isolate` 内存 LRU（30 s / 800 条，`x-noas-path: pages-mem`）与 GET 请求的 Cache API（60 s，`pages-cache`）。高频域名第二次起不再跳 Worker，实测稳定在 193~246 ms，抖动从 267~834 ms 收敛成一个 RTT。

**通道侧到此已到物理下限**：服务端处理是 0（缓存命中不建连、广告域边缘直拦），剩下那 ~200 ms 就是温州到 CF 最近边缘的往返。要再快只能换更近的边缘（Gateway 落在香港方向，复用 235 ms），应用层没有别的可压。`lite` 与本域白名单无直接交集，白名单父域下的 16 个纯广告端点仍按端点例外拦掉（`union.baidu.com` 实测被拦）。

关于“多开账户接近无限”：

- 同一账户下所有 Worker **共享**同一份 10 万/天，多建 Worker 不叠加；
- 多账户确实能叠加额度，但代价是双份 secret、双份部署、双份故障面，且属于规避额度，不做；最多留一个灾备账户。

AE 自检：`tools/ae_selfcheck.py`（daily 第 6.9 步），每轮发 1 个真实查询 + 查最近 15 分钟数据点，失败只提示不打红。
