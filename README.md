# NoAS

免费、可审计、每天自动重建的**广告 / 追踪 / 威胁域拦截规则**。
不依赖任何云平台、不需要账号或密钥：规则以「订阅」形式发布，GitHub 自己就是文件服务器。

## 直接可用（订阅地址）

| 档位 | 条数 | 说明 | 地址 |
|---|---|---|---|
| lite | ≈28k | 跨 3 源共识 + 广告结构自动晋级 + AdGuard DNS 过滤器，误拦率最低，**日常用这档** | `https://raw.githubusercontent.com/NoS-1/NoAS/main/subs/lite/adguard.txt` |
| mid | ≈162k | 跨 2 源共识，覆盖更广 | `https://raw.githubusercontent.com/NoS-1/NoAS/data/subs/mid/adguard.txt` |
| full | ≈41 万 | 14 源并集，最激进 | `https://raw.githubusercontent.com/NoS-1/NoAS/data/subs/full/adguard.txt` |

每档都有 7 种格式，把上表地址里的文件名换掉即可：

| 格式 | 客户端 | 文件名 |
|---|---|---|
| AdGuard / uBlock | AdGuard Home、uBlock Origin | `adguard.txt` |
| 纯域名 | mosdns、自写脚本 | `domains.txt` |
| hosts | 路由器、老 App | `hosts.txt` |
| dnsmasq | OpenWrt / dnsmasq | `dnsmasq.conf` |
| Clash | Clash / Mihomo rule-provider（behavior: domain） | `clash.yaml` |
| sing-box | rule_set（format: source） | `singbox.json` |
| Surge / Loon | DOMAIN-SUFFIX 列表 | `surge.list` |

三通道，全部是 GitHub 自家，不挂任何第三方 CDN：

| 通道 | 用法 | 说明 |
|---|---|---|
| raw | 上表地址 | 随仓库提交即时生效 |
| Pages | `https://nos-1.github.io/NoAS/subs/lite/adguard.txt` | 站点镜像，带宽由 GitHub 承担，与 raw 互为备份 |
| Release | `https://github.com/NoS-1/NoAS/releases/download/latest/noas-snapshot.zip` | 单包下载（三档 + DoH 产物），长期留档 |

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
2. 干扰名单硬过滤：命中 `tests/benign_baseline.txt` 或 `lists/whitelist.txt` 的域**连同父域**全部剔除
3. 重复 / 非法字符 / 超长域检查
4. `meta.json` 里的 sha256 必须与真实文件一致（改了文件没重算直接红）
5. 抽查：已知广告网络必须拦、已知正常站必须放
6. **规模突变护栏**：比上一轮少 15% 以上直接判红停发（多半是上游集体挂掉，宁可停一天也不发残包）

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

## 四层叠加（DNS 只是第一层）

单层做不到 100%。完整方案见站点 `docs/stack.html`：

| 层 | 产物 | 作用 |
| --- | --- | --- |
| L1 DNS | `subs/{lite,mid,full}/` | 拦广告/追踪域名，全设备生效 |
| L2 路径 | `subs/paths/{core,full}/noas-path.{sgmodule,plugin,conf}` | MITM 后拦开屏/广告接口（Surge/Loon/QX） |
| L3 内容 | `subs/paths/ubo/noas-ubo.txt` | 浏览器内隐藏广告位、拦广告脚本 |
| L4 交互 | 文档指引（GKD） | 安卓无障碍自动点"跳过" |

路径层源表是 `lists/ad_paths.tsv`，每行带 App 与用途；`core` 只打单主机端点，`full` 才启用通用路径（范围由 MITM 白名单兜住）。

## 运行监控

- `Daily Build`：每日 4 轮重建 + 发布（03/09/15/21 点）
- `Availability Probe`：每 3 小时探测 raw / Pages / Release / 路径层四条通道，失败开 Issue、恢复自动关
- `Discover` / `Maintain`：每周两次（周一、周四）
