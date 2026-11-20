# 运维手册 · 凭据与状态怎么看

> 只写位置和入口，不写任何令牌值。凭据本体永远只在 `/home/user/.noas/creds.env`（600）。

## 一、四枚凭据在哪、谁能动

| 名称 | 级别 | 作用 | 在哪看 | 能自动轮换吗 |
|---|---|---|---|---|
| `GH_PAT` | GitHub 个人令牌 | 本机推送、写 Actions secret | [github.com/settings/tokens](https://github.com/settings/tokens) | 否（手工重建） |
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

## 三、本机三条命令

```bash
cd /home/user/NoAS
cat /home/user/.noas/creds.env          # 看当前值（600，不入库）
python3 tools/token_check.py            # GitHub PAT + CF 令牌双体检
python3 tools/cf_rotate.py --check      # 轮换链路体检，不动手
cat state/cf_rotation.json              # 上次轮换时间 / 新旧令牌 id
```

`--check` 只读，随时可跑；`--force` 才真轮换；`--keep-old` 保留旧令牌便于回滚。

## 四、轮换节奏

- 触发条件：`state/cf_rotation.json` 里 `last_rotated` 超过 30 天
- 执行环境：必须在有 `creds.env` 的机器上（CI 里没有 `GH_PAT`，内置 `GITHUB_TOKEN` 无权写 secret）
- 流程：签新令牌 → verify → 写 GitHub secret → 回写 `creds.env` → 删旧令牌
- 失败回滚：任一步失败即删掉新令牌，旧值不动，两端不会对不上
- 首次自举已完成（`NoAS-Root` 根令牌已建）

## 五、凭据泄露怎么办

1. CF：删掉对应的 user / account 令牌，重跑 `python3 tools/cf_rotate.py --force`（会重新签发并回写 secret）
2. GitHub：撤销 PAT，重建后写回 `creds.env` 的 `GH_PAT`
3. 检查是否已被使用：CF 看令牌 `上次使用` 时间，GitHub 看设置页 `Last used within`
