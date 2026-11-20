# NoAS

免费、可审计、每天自动重建的**广告 / 追踪 / 威胁域拦截规则**。
不依赖任何云平台、不需要账号或密钥：规则以「订阅」形式发布，GitHub 自己就是文件服务器。

## 直接可用（订阅地址）

| 档位 | 条数 | 说明 | 地址 |
|---|---|---|---|
| lite | ≈3.5k | 跨 3 个以上独立源共识，误拦率最低，**日常用这档** | `https://raw.githubusercontent.com/NoS-1/NoAS/main/subs/lite/adguard.txt` |
| mid | ≈29k | 跨 2 个源共识，覆盖更广 | `https://raw.githubusercontent.com/NoS-1/NoAS/data/subs/mid/adguard.txt` |
| full | ≈28 万 | 全部源并集，最激进 | `https://raw.githubusercontent.com/NoS-1/NoAS/data/subs/full/adguard.txt` |

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

国内直连 raw 慢时，把前缀换成 jsDelivr（同一份文件、免费无限带宽）：

```
https://cdn.jsdelivr.net/gh/NoS-1/NoAS@main/subs/lite/adguard.txt
https://cdn.jsdelivr.net/gh/NoS-1/NoAS@data/subs/mid/adguard.txt
```

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

`.github/workflows/daily.yml`：每天 03:17 / 15:17（北京）拉源、编译、校验、发布、回归，**不读任何 secrets**。

- 高频写入走 git push（不吃 API 配额）
- mid/full 发到 `data` 分支，每次强制单 commit —— 历史永不膨胀，jsDelivr 可直接按分支取
- lite 跟代码留在 `main`，克隆即用
- 生成物按内容指纹做幂等：规则没变就不产生新提交

## 已知边界（不吹）

- 「100% 拦截」在 DNS 层不可能做到：同域多租户（如 CDN 上的广告路径）、加密 SNI、DoH 客户端自带解析都能绕过 DNS 拦截。本项目能做到的是**把公开源并集拉满 + 白名单硬闸**，DNS 层能拦的都拦。
- 白名单是保守的：写了 `baidu.com` 就保护所有 `*.baidu.com`。宁可放过也不误伤。
- full 档很激进（含大量长尾域），对极少数站点可能有误伤；介意就用 lite。
