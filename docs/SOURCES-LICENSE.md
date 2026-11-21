# 规则源归属与许可证

本项目的规则产物（`subs/*`）是把下列公开规则集编译、裁剪、去重后的**衍生作品**。
每个源的许可证以其项目页面为准；本仓库不对上游条款做任何豁免或再授权。

| 源 | 用途 | 许可证（以项目页为准） | 归属 |
|---|---|---|---|
| AdGuard DNS filter | 主线域名源 | GPL-3.0 | © AdGuard Software Ltd |
| HaGeZi Pro / Pro++ | 通配与高覆盖 | CC BY-SA 4.0 | © HaGeZi |
| OISD（small/big） | 广告+追踪并集 | 见项目页（OISD 声明免费使用） | © OISD |
| EasyList | 从 adblock 语法提取域名 | GPL-3.0 / CC BY-SA | © EasyList authors |
| anti-AD | 中文区高命中 | 见项目页 | © anti-AD contributors |
| aiodns / 国内 DNS 通道 | 通道体检，不产生规则 | — | © 各作者 |

## 我们的处理方式

1. 只做**格式转换 + 集合运算**（并、交、差、按父域裁通配），不改写单条规则语义。
2. 产物按**最严格条款**开放：CC BY-SA 4.0 + GPL-3.0 双协议。任何下游使用 `subs/*` 都必须保留本节归属。
3. 代码部分（`tools/`、`doh/`、`pages/`、`tests/`）为 MIT。
4. 若某个上游条款不允许再分发，请提 Issue，我们会把该源移出构建链（`sources.tsv` 里删一行即可）。

## 引用方式

```
规则数据来自 AdGuard DNS filter / HaGeZi / OISD / EasyList / anti-AD，
经 NoAS 编译（https://github.com/NoS-1/NoAS），按 CC BY-SA 4.0 + GPL-3.0 提供。
```
