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
- 误拦率与规模：[precision.html](https://nos-1.github.io/NoAS/precision.html) —— 三档误拦率、规则条数、黄金集通过情况
- 构建明细：[tasks.html](https://nos-1.github.io/NoAS/tasks.html) · DNS 延迟：[dns-latency.html](https://nos-1.github.io/NoAS/dns-latency.html)
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

| 资源 | 免费额度 | 本项目用法 | 守门 |
|---|---|---|---|
| Workers 请求 | **10 万次/天**，UTC 0 点重置＝北京 08:00；单次 CPU 上限 10ms | DoH 判定 `/dns-query` | 到 90%（9 万）主动熔断，返回 503 让客户端回落国内 DoH |
| Pages | 请求与带宽不限；**部署 500 次/月** | 规则包静态分发 | `tools/quota_check.py`，≥350 让构建红 |
| Analytics Engine | 写 **1 亿点/月**、读 1000 万点/月 | 只记 DNS 判定（block / cname / pass） | 按万级/天，约用 3% 以内 |
| D1 | 读 500 万行/天、写 10 万行/天 | 只放配置与状态 | 日志一律不进 D1 |
| KV | 读 10 万/天、写 1000/天 | 只放低频状态 | 配额计数绝不写 KV |

分摊顺序（从最省到最贵）：

1. **本地规则**：sing-box / AdGuard Home 直接吃 lite 表 → 0 请求、0 延迟；
2. **Worker 判定**：只有需要云端拦截时才走；
3. **国内 DoH 回落**：阿里 / 腾讯 / 360，额度不归我们；
4. **CF Gateway DoH**（`https://oxyacq0a4t.cloudflare-gateway.com/dns-query`）：与 Worker 额度分开计。已实测拦截生效：doubleclick.net / googleadservices.com 返回 `0.0.0.0`，baidu.com 返回真实 IP。注意别写成 `oxyacq0a4t4`——多一个 4 会拿到「不过滤」的应答，看着通、其实没拦。

关于“多开账户接近无限”：

- 同一账户下所有 Worker **共享**同一份 10 万/天，多建 Worker 不叠加；
- 多账户确实能叠加额度，但代价是双份 secret、双份部署、双份故障面，且属于规避额度，不做；最多留一个灾备账户。

AE 自检：`tools/ae_selfcheck.py`（daily 第 6.9 步），每轮发 1 个真实查询 + 查最近 15 分钟数据点，失败只提示不打红。
