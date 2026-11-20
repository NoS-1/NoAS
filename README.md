# NoAS

免费、可审计、每天自动重建的**广告 / 追踪 / 威胁域拦截规则**。
不依赖任何云平台、不需要账号或密钥：规则以「订阅」形式发布，GitHub 自己就是文件服务器。

## 直接可用（订阅地址）

| 档位 | 条数 | 说明 | 地址 |
|---|---|---|---|
| lite | 9,903（硬上限 10,000） | 跨 3 源共识 + 广告结构自动晋级，按共识分排序截断；**零误伤最小集**，设备算力很弱时用这档 | `https://raw.githubusercontent.com/NoS-1/NoAS/main/subs/lite/adguard.txt` |
| mid | 210,265 | 跨 2 源共识 + 广告 SDK/贴片专项；**日常默认就用这档**，覆盖与误伤的平衡点 | `https://raw.githubusercontent.com/NoS-1/NoAS/data/subs/mid/adguard.txt` |
| full | ≈53 万（529,385） | 21 源并集，最激进 | `https://raw.githubusercontent.com/NoS-1/NoAS/data/subs/full/adguard.txt` |

> 上面三个数字取自 CI 每日重建后的**线上实际产物**（`main` 分支 lite、`data` 分支 mid/full）。CI 出网能拉到 21 个源，本机受限网络只到 19 个，所以本地复跑会比线上小 20% 左右——这不是丢规则，是源可达性差异。任何时刻以 `precision.html` 上的实时数字为准。

每档都有 7 种格式，把上表地址里的文件名换掉即可：

| 格式 | 客户端 | 文件名 |
|---|---|---|
| AdGuard / uBlock | AdGuard Home、uBlock Origin | `adguard.txt` |
| 纯域名 | mosdns、自写脚本 | `domains.txt` |
| hosts | 路由器、老 App | `hosts.txt` |
| dnsmasq | OpenWrt / dnsmasq | `dnsmasq.conf` |
| Clash | Clash / Mihomo rule-provider（behavior: domain） | `clash.yaml` |
| sing-box | rule_set（format: source），**仅 L1**；内核无 MITM，不能跑 L2 路径改写 | `singbox.json` |
| Surge / Loon | DOMAIN-SUFFIX 列表 | `surge.list` |

四通道，全部是自家免费能力（GitHub + 自建 CF Pages），不挂任何第三方 CDN：

| 通道 | 用法 | 说明 |
|---|---|---|
| raw | 上表地址 | 随仓库提交即时生效 |
| Pages | `https://nos-1.github.io/NoAS/subs/lite/adguard.txt` | 站点镜像，带宽由 GitHub 承担，与 raw 互为备份 |
| **CF Pages** | `https://noas-cdn.pages.dev/subs/mid/adguard.txt` | **国内推荐**：CF 边缘静态分发，免费、带宽不限，**不占 Worker 额度** |
| Release | `https://github.com/NoS-1/NoAS/releases/latest/download/noas-snapshot.zip` | 单包下载（三档 + DoH + 通道产物），长期留档 |

站点首页 `https://nos-1.github.io/NoAS/` 有实时条数、各格式校验值、源健康度与自我成长记录。

## 用了哪些行业级手段

- **CNAME 反隐蔽**：第一方子域 CNAME 到追踪者（`stats.某站.com` → `tracker.com`）是近几年最主要的绕过手段。自建 DoH 会解析应答里的 CNAME 链，链上任何一跳命中黑名单就直接拦掉，并在响应头标记 `x-noas: blocked-cname`。
- **官方 CNAME 清单**：接入 AdGuard 的 CNAME 伪装落地域名清单（约 30 万条）与原始追踪者清单（用于反隐蔽校验）。
- **通配规则匹配**：`*.example.com` 形态的规则在运行时按后缀匹配，不再被丢掉。
- **广告端点例外**：审计过的投放端点穿透白名单父域保护（百度/腾讯/谷歌的广告子域不会被"保护整站"误放）。
- **跨源共识分档**：3 源以上进 lite、2 源进 mid、并集进 full；单源但域名结构即广告的自动晋级进 lite。

## 为什么可信

发布前有一道硬闸，任一项不过就不出包（`tools/guard.py`）：

1. 七个格式条数必须完全一致（渲染漏一条就红）
2. 干扰名单硬过滤：命中 `lists/whitelist.txt`、`lists/service_allow.txt` 或 `tests/benign_baseline.txt` 的域**连同父域**全部剔除
3. 重复 / 非法字符 / 超长域检查
4. `meta.json` 里的 sha256 必须与真实文件一致（改了文件没重算直接红）
5. 抽查：已知广告网络必须拦、已知正常站必须放
6. **规模突变护栏**：比上一轮少 15% 以上直接判红停发（多半是上游集体挂掉，宁可停一天也不发残包）
7. **黄金回归**：`tests/golden_set.txt` 里 2,227 条正常站点，lite 档命中必须为 0，出现一条就判红（实测三档误拦率见 [precision.html](https://nos-1.github.io/NoAS/precision.html)）
8. **基础服务护栏**：`lists/service_allow.txt`（登录/支付/推送/地图/验证码/崩溃上报）三档都不许出现——这条挂了，用户是登不上微信、付不了款，比误拦广告严重得多
9. **影子期**：观察池里的低置信域必须先看够 14 天且复现 2 轮才准晋级，30 天不复现直接退役；没满期的绝不许进 lite（`tools/watch_pool.py`）
10. **信誉评分**：多信号加权打分，≥70 才够格进 lite；命中白名单/良性大盘/黄金集的域直接清零，不给翻盘机会（`tools/reputation.py`）

误伤走自动闭环：Issue 打 `误伤` 标签 → 进白名单台账 + **进冷却池**（以后白名单被误删也不会复发）→ 重编译 → 硬校验 → 发布，4 小时内生效。
每轮校验通过后自动拍 known-good 快照，出问题 `python3 tools/rollback.py` 一键退回上一版可用产物。

## 自己跑（一条命令）

```bash
python3 tools/fetch.py       # 拉 12 个公开源（失败源沿用缓存）
python3 tools/compile.py     # 三档编译 + 白名单硬闸
python3 tools/guard.py       # 发布校验
python3 tools/build_doh.py   # 生成 DoH 产物
node tests/worker_check.mjs  # 真产物回归：lite 全量 + mid 抽样，漏放/误拦必须为 0
```

## 自建 DoH（不需要任何平台）

```bash
python3 tools/build_doh.py
node serve/standalone.mjs          # 监听 0.0.0.0:8053
curl 'http://127.0.0.1:8053/check?q=doubleclick.net&tier=1'   # blocked: true
```

`serve/standalone.mjs` 加载的就是构建产物 `doh/worker.js`，和订阅同源同规则，
一份逻辑两种形态，不会出现「订阅和 DoH 不一致」。

## 自动化

`.github/workflows/daily.yml`：每天 03:17 / 15:17（北京）自我体检 → 拉源 → 编译 → 校验 → 发布 → 回归 → 站点部署，**只用仓库自带的 GITHUB_TOKEN，不读任何外部 secrets**。

- 高频写入走 git push（不吃 API 配额）
- mid/full 发到 `data` 分支，每次强制单 commit —— 历史永不膨胀，jsDelivr 可直接按分支取
- lite 跟代码留在 `main`，克隆即用
- 生成物按内容指纹做幂等：规则没变就不产生新提交
- 公开仓库的 Actions 时长不限，规则更新不设频率上限；写入走 git push，不吃 API 配额
- 安全扫描（CodeQL，公开仓库免费）每周跑一次，只扫自己的流水线脚本

## 已知边界（不吹）

- 「100% 拦截」在 DNS 层不可能做到：同域多租户（如 CDN 上的广告路径）、加密 SNI、DoH 客户端自带解析都能绕过 DNS 拦截。本项目能做到的是**把公开源并集拉满 + 白名单硬闸**，DNS 层能拦的都拦。
- 白名单是保守的：写了 `baidu.com` 就保护所有 `*.baidu.com`；只有人工审计过的广告端点（`lists/ad_endpoints.txt`）能穿透这层保护。
- lite 里除共识条目外，还包含 `lists/promoted.txt` 自动晋级的域名结构即广告条目，规则见 `tools/promote.py`，误伤可直接在台账里加白。
- full 档很激进（含大量长尾域），对极少数站点可能有误伤；介意就用 lite。

## DNS 通道（国内主用 + 自建兜底）

规则解决"拦什么"，通道解决"走哪条路"。默认全走国内公共 DNS，零调用额度：

| 角色 | 通道 | 地址 |
|---|---|---|
| 主 | 阿里 DoH | `https://dns.alidns.com/dns-query` |
| 备 | 腾讯 DoH | `https://doh.pub/dns-query` |
| 备 | 阿里/腾讯 DoT | `tls://dns.alidns.com:853`、`tls://dot.pub:853` |
| 本地 | aiodns | `127.0.0.1:5300`（国内分流 + 缓存，不做拦截） |
| 兜底 | 自建 DoH | `https://noas-doh.199999510.workers.dev/dns-query`（10 万/天，90% 熔断） |

产物在 `subs/channels/`：`doh.txt`、`dot.txt`、`aiodns.sh`、`adguardhome-upstream.yaml`、`aiodns.special.txt`、`health.json`。
每轮构建先体检再生成；体检若判定环境被代理劫持（`env=suspect`），**沿用完整清单，绝不剔空**。

延迟不是拍脑袋定的：`tools/bench_dns.py` 按真实 DNS wire query 实测各家首包与复用耗时，结论和取舍写在 [`dns-latency.html`](https://nos-1.github.io/NoAS/dns-latency.html)。
一句话：延迟大头是每次重做 TLS 握手，所以主用常连的国内 DoH（复用后 9–16ms），自建只兜底。

## 三层叠加（DNS 只是第一层）

单层做不到 100%。完整方案见站点 `docs/stack.html`：

| 层 | 产物 | 作用 |
| --- | --- | --- |
| L1 DNS | `subs/{lite,mid,full}/` | 拦广告/追踪域名，全设备生效 |
| L2 路径 | `subs/paths/{core,full}/noas-path.{sgmodule,plugin,conf}` | MITM 后拦开屏/广告接口（Surge/Loon/QX） |
| L3 内容 | `subs/paths/ubo/noas-ubo.txt` | 浏览器内隐藏广告位、拦广告脚本 |

**国内首方广告子域（自动发现，累积不覆盖）**：`tools/discover_cn_ads.py` 以证书透明度 + 被动 DNS + 广告前缀枚举三条通道收集子域，再用 DoH 逐个解析；先探泛解析（随机子域也解析得出来就整根域丢弃），再按证据分两档：

- **端点表 `lists/cn_ad_endpoints.txt`**：解析链落到已知广告网络（穿山甲/优量汇/阿里妈妈/快手/Mintegral…），或域名最左标签就是 `ad/ads/adx/adapi/adserver/splash/gromore/pangolin…` 这类品牌自有广告前缀（带连字符的广告主后台除外）。全档强制拦；
- **观察池 `lists/cn_ad_watch.txt`**：广告词元出现在中间标签、或 `union/track/stat/log/metrics` 这类歧义前缀。仅 mid/full，lite 不引入。

产物按轮累积：本轮没重新探到的旧条目保留，不会被覆盖写冲掉；根域清单 `lists/cn_roots.txt`（188 个国内 App/品牌注册域）由游标轮换分批覆盖，每周随 Discover 流水线刷新。

路径层源表是 `lists/ad_paths.tsv`，每行带 App 与用途；`core` 只打单主机端点，`full` 才启用通用路径（范围由 MITM 白名单兜住）。

## 运行监控

- `Daily Build`：每日 4 轮重建 + 发布（03/09/15/21 点）
- `Availability Probe`：每 3 小时探测 raw / Pages / Release / 路径层四条通道，失败开 Issue、恢复自动关
- `Discover` / `Maintain`：每周两次（周一、周四）


## 可选加速层：Cloudflare D1

D1 只存**小体量状态**（构建版本、三档条数、通配数、lite 的 sha），不存规则正文也不存查询日志——免费额度按行读取计费，灌日志两天就会被限流（错误码 7500）。
每日构建的 3.58 步会自动建表并 upsert 一行 `build_state`；额度打满或未配 secret 时该步静默跳过，不影响主链。
