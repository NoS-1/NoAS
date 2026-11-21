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
- 误拦率与规模：[precision.html](https://noas-cdn.pages.dev/precision.html) —— 单订阅误拦率、规则条数、黄金集通过情况
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

### 端点例外（ep）与白名单父域保护

正常业务根域（`amap.com`、`qq.com`、`baidu.com` 等热门大盘）默认受白名单父域保护，其子域不进黑名单；
但纯广告端点以 **端点例外（ep）** 身份进入 `lists/ad_endpoints.txt` / `lists/cn_ad_endpoints.txt`，
与 `union.baidu.com` / `gdt.qq.com` 同语义 —— 即使父域在白名单，该端点照样拦。

> 2026-11 起只做 DNS 层：旧 L2 路径层、L3 uBO 内容层、L4 GKD 与 `layer_backfill.py` 已物理删除，
> 原跨层回灌的 18 个广告主机已并入 `lists/ad_endpoints.txt`。

四处口径必须一致，否则同一份规则在不同校验器里结论不同：`compile.py`、`build_doh.py`（Worker 内嵌）、
`precision.py`（误伤审计）、`tests/worker_check.mjs`（回归）。

排除项：`dead.txt`（解析不出地址，拦了也没流量）、精确命中白名单的域、两段以内的良性/热门根域。
台账里打 `layer-backfill` 标签，与 `cn-endpoint` 区分来源。

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

## 发布后验证（2026-11-21）

部署脚本返回码只说明"API 调用成功"，不代表线上生效。`tools/post_deploy_verify.py`
按客户端视角打真实端点，任何一项不符就让构建红（Alert 自动开 Issue）：

- `/tier` 能读到规则，三档条数与 `subs/*/meta.json` 完全一致
- `/dns-query/{lite,mid,full}` 三个端点都 200
- DoH 实测：拦截域回 `0.0.0.0`、白名单域放行且不是 `0.0.0.0`
- Worker `noas-doh` 与其 bindings 在线
- Gateway 列表片数 10/20/30 + allow + core，规则 ≥ 6

配套：`tools/step_run.py` 的 `required` 模式（重试 3 次 → 仍失败则红），
`soft` 模式只记 `out/deploy_warnings.json` 的统一告警。Gateway 对齐校验已从 soft 升为 required。

## DoH 响应模式与 lite 快路径（2026-11-21）

- `?mode=nxdomain`：拦截时回 NXDOMAIN(3) 而不是 `0.0.0.0`，客户端重试更少；默认仍是 `0.0.0.0`（兼容性更宽）。
- KV `lite_v1` 是 Worker cron 写的 JSON（`{ver,count,compact:"|a|b|c"}`），Pages 侧曾按纯文本行解析，
  把整段 JSON 当成一行 → `size=1` 永不达标 → lite 每次冷启动都回源 195KB。已改为识别 JSON 的 `compact` 字段，
  现在 lite 直接吃 KV，`/tier` 的 `err` 为空。
- Actions 全部按 commit SHA 固定（tag 注释保留版本号），由 dependabot 提 PR 更新。

## 协议层补齐（2026-11-21 第二批）

本轮把 DoH 端点的"协议完备度"补齐，全部有回归覆盖（`tests/dns_features_check.mjs` 18 项）：

| 能力 | 端点/参数 | 作用 | 回归 |
|---|---|---|---|
| EDNS BADVERS | 报文 OPT version>0 | RFC 6891 要求回 ext-rcode 16，否则老客户端会无限重试 | `x-noas: badvers` + 不转上游 |
| ECS 隐私开关 | `?ecs=off` | **真删**报文里的 ECS option（`stripEcs`），不是只回填空值 | 上游报文不含 ECS |
| ECS scope 回填 | 自建 OPT 时 | SCOPE 长度=请求前缀，客户端按同粒度缓存，减少跨网段串味 | — |
| 拦截语义 | `?mode=nxdomain\|refused\|servfail` | 四选一：0.0.0.0 / NXDOMAIN / REFUSED(5) / SERVFAIL(2) | 各自 RCODE |
| JSON 解析视图 | `/resolve?name=&type=&tier=`（或 `/dns-query?name=`） | 字段对齐 Google DoH JSON，脚本可直接用 | 命中/放行两路 |
| 畸形报文 | 任意垃圾字节 | 越界读归 400 `bad-request`，不再伪装成 500 服务端故障 | 500 个随机输入 0 异常 |
| 缓存隔离 | — | 缓存键含 ECS 子网 + DO 位 + SWR 影子键 | 不同子网不共用应答 |

配套治理：`tools/sources_guard.py`（源清单卫生 + 内容形状 + 单源 ±60% 突变，CI 1.5 步 required；
基线在 `state/source_counts.json`，只有全绿才推进基线）、`tools/build_status_page.py`（`docs/status.html`
一张页看全部通道）、`tests/fuzz_check.mjs`、`tests/cache_iso_check.mjs` 已进 6 步回归、
`eslint.config.mjs` + `ruff.toml` + 3.95 步 soft 静态检查、`tools/legacy/` 收纳已退役脚本。

## 免费额度与 CPU 上限（2026-11-21 第三批）

免费版只有三个真天花板，全部**全账号合计**：请求 100,000/天、KV 读 100,000/天（写 1,000/天）、
AE 写点 100,000/天；单次调用 CPU **10ms**（超了直接被限流，不是慢慢变慢）。数字来自
Cloudflare 官方 Limits 页（2026-11 版）。

**水位监控**：`tools/quota_water.py` 走 GraphQL Analytics（免费只读）拉当日用量与 CPU 分位，
写 `state/quota.json`，接在 CI 6.97 步（soft，80% 预警）。实测当天：

| 维度 | 用量 | 上限 | 占比 |
|---|---|---|---|
| 请求 | 507 | 100,000 | 0.5% |
| KV 读 | 366 | 100,000 | 0.4% |
| AE 写点 | 166 | 100,000 | 0.2% |
| CPU p50 / p99 | 2.49ms / **10.91ms** | 10ms | p99 越线 |

**结论**：额度不是瓶颈（连 1% 都没到），**CPU p99 才是**。归因与修复：

- 元凶：`hotHit()` 每次请求都在 195KB 的 `compact` 字符串上做 `includes("|域名|")`，
  未命中也要按 3~6 层逐层扫；CNAME 多跳时一次请求调 4 次 → 单次 163µs × 多次 ≈ 10ms 级。
- 修法：冷启动时 `HOT_SET = new Set(compact.split("|"))`，判定变 O(层数) 的哈希查找；
  同时把 `matchSet`/`allowed` 的 `parts.slice(i).join(".")` 改成原地累加，去掉每次分配。
- 基准：同机 2 万次判定，旧 3262ms → 新 10ms（**326×**）。
- 部署后线上 sha `2af14b30d3039545`，规则集与计数不变（lite 9904 / mid 19959 / full 29990）。
- Pages 侧 `RULES.get` 补 `cacheTtl: 300`：同 PoP 内 5 分钟只真读一次 KV，省 KV 读也降冷启动。

**没做的、以及为什么**：Gateway 前置分流（额度只用了 0.5%，收益为零，且 Gateway 免费版
列表上限 100、已用 62，留给后续新增源更值）；AE 动态降采样（日写点 166，离 10 万差 600 倍）；
observability 1%→0.1%（20 万日志额度，1% 于 10 万请求仅 1000 条）。都不值得动。

## 规则分层：内嵌只留 lite，mid/full 走 KV（2026-11-21 第四批）

1MB 部署上限与"覆盖要涨"直接冲突：三档全内嵌做到 3 万条就 646KB，再涨必撞墙。
所以把规则拆成"保底 + 分档"：

| 层 | 存放 | 内容 | 体积 |
|---|---|---|---|
| 内嵌 | `doh/worker.tpl.js` | lite 9904 + 白名单 137 + 端点 111 + 通配 56 | 454KB（原 646KB） |
| KV `mid_v1` | Workers KV（namespace `1e20a4a1…`） | mid 19959 条 | 351KB |
| KV `full_v1` | 同上 | full 29990 条 | 558KB |

- **写入**：`tools/kv_push.py`，CI 3.7 步（编译之后、构建 Worker 之前），写完回读 count 比对，
  不一致直接红。这样"新代码 + 旧规则"不可能上线。
- **读取**：Worker 冷启动按档读一次（`cacheTtl 300`），isolate 内存缓存。KV 实测日读 420 / 10 万。
- **降级**：KV 不可用时 tier2/3 自动退回内嵌 lite（少拦不误拦，也不 500）。
- **代价**：mid/full 首次请求多一次 KV 往返（边缘缓存命中时 <5ms）；`serve/standalone.mjs` 无 KV，
  只能跑 lite —— 它本来就是离线兜底，定位不变。
- **收益**：体积墙从 3 万条推到"1MB 内 lite 保底 + KV 上限 25MB/键"，mid 未来能上 4 万；
  改规则不再需要重新部署 Worker。

实测验证（线上，`/why`）：`cunealwolvish.com`（mid 独有）tier1 放行、tier2/3 拦截；
`www.qq.com` 三档 `allowlist`；`2345.com` 三档放行。

另：CNAME 深追默认 4 跳 → **3 跳**（`?deep=1` 恢复 4 跳），因为 4 跳把 CPU p99 顶到 13ms。
`tools/quota_water.py` 现在同时覆盖 请求 / KV / AE / **D1**（当日 118 次）与 CPU p50/p99。

## Gateway 列表容量收口（第五批）

Cloudflare Gateway 免费版两个硬限实测：单列表 **1000 条**（API 直接 400 `list size is limited to 1000 items`）、列表总数 **100 个**。
mid 扩到 4 万后若三档全铺会变成 93 个列表（10+40+41），只剩 7 个槽，规则再长一点就爆表。

因此 Gateway 定为「粗拦层」：只铺 lite（10 片）+ mid（40 片）= **50 片 / 5 万条**，加 `noas_allow`、`noas_core` 共 **52 个列表**，留 48 槽；
full 不进 Gateway（full 只在 DoH 精细通道生效），「NoAS 大档拦截」规则置 `enabled=false` 并指向 core 列表，旧 `noas_l3_*` 分片已清理。

配套口径同步：`gateway_all.py` 的 `TIERS` 只有 lite/mid（`NOAS_GATEWAY_FULL=1` 可临时恢复三档）、
`gateway_align.py` 无 l3 列表时跳过 t3 校验、`post_deploy_verify.py` 期望片数改成按 `subs/*/meta.json` 的 `ceil(count/1000)` 推算（不再写死 10/20/30），列表数 >95 才预警。

## CI 编排收口（第六批）

- **断自触发**：产物提交 `build: 每日重建 …` 结尾带跳过标记；`paths-ignore` 追加 `state/**`（只忽略流程自写台账，`lists/ tools/ doh/ sources.tsv` 必须触发，否则手改规则不会重建）。注意：提交消息里出现该跳过字面会让 GitHub 整条跳过本轮，写说明文字时要避开。
- **回归提速的真实瓶颈是 fuzz**：6 项里其余 5 项都在 1.5s 内，`fuzz_check.mjs` 串行 500 例要 81s（每例触发一次上游解析约 160ms）。改成 50 并发抢队列后 1.9s，500 例一条不少。6 项并行保留作兜底。
- **分支保护不能设 required status checks**：CI 用内置令牌直推 main，一旦要求 4/4 检查会直接被拒（`9 · 提交` 重试 5 次后红）。现在只保留"禁强推 + 禁删除"，不设 required checks。
- **编译三档并行不采用**：实测串行 23s / 三进程并行 21s（每个进程都重算全量，只摊到写盘），收益 2s 但会三进程同时写 `out/*.json`，写竞争损坏产物的风险不值。

## 隐私分级与统计退出（第七批）

`logHit` 拆成两级：拦截命中记明文域名（公开黑名单，便于定位漏拦/规则失效），放行只记 `SHA-256(域名|当日盐|内部串)` 前 12 位。盐存 KV `stats_salt:<UTC日期>`（每日 1 次写，额度无压力），无盐时退化为 `h:na`，绝不回落到明文。`?stats=off` 可整请求退出统计。`tests/dns_features_check.mjs` 扩到 23 项，直接断言“同域同盐稳定 / 异域不同 / 放行不含明文 / 拦截保留明文”。
