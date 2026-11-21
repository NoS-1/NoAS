# FAQ

**Q：开了之后地图定位偏、打车定位到别的城市？**
ECS 会把 `/24` 子网带给上游，多数情况正常；若出现定位异常，试 `?ecs=off` 对比。
注意：不带 ECS 时上游按出口 IP 选节点，也可能偏移，这不是本项目能决定的。

**Q：支付/银行 App 打不开、验证码收不到？**
先 `/why?d=<域名>` 查是否命中。若命中又确认是业务域，开 Issue 附域名，我们加白名单或做端点例外。

**Q：为什么条数比别的清单少？**
三档只留国内相关，海外长尾被 `FOREIGN_CC` 排除；lite 硬上限 1 万，按共识分排序截断。

**Q：0.0.0.0 和 NXDOMAIN 有什么区别？**
`0.0.0.0` 让客户端拿到一个不可达地址；NXDOMAIN 直接说“域名不存在”，重试更少。
某些客户端对 `0.0.0.0` 会回退 IPv6 或反复重试，这时用 `?mode=nxdomain`。

**Q：IPv6 怎么办？**
默认原样返回；设备 IPv6 有问题时用 `?v6=v4only` 让它立刻回退 A。

**Q：能保证 100% 拦截吗？**
不能。同域多租户、加密 SNI、客户端自带解析都能绕过 DNS 层。我们做的是把公开源并集拉满 + 白名单硬闸。

**Q：能保证不误伤吗？**
不能保证“全量零误伤”，但我们有量化口径：4444 条业务主域样本上三档实测 0 误伤（见 `state/benign_fp.json`），
且 lite 档在 CI 里是硬门禁，误伤不为 0 直接拦发布。

**Q：为什么手机系统级 Private DNS 填不了？**
Android 只支持 DoT，而 853 端口国内被封。只能装 App 用 DoH。

## 客户端把 0.0.0.0 当成"域名解析成功"怎么办

用 `?mode=nxdomain`（回 NXDOMAIN，确定性"不存在"）、`?mode=refused`（RCODE 5，明确策略拒绝）、
`?mode=servfail`（RCODE 2，让少数把 NXDOMAIN 永久负缓存的老解析器重试）。四种模式同一端点，按客户端脾气选。

## 想看某条解析的 JSON 结果

`GET https://noas-cdn.pages.dev/resolve?name=www.qq.com&type=A&tier=2`（Worker 直连时 `/dns-query?name=` 同义），
返回 `{Status,AD,blocked,Answer:[{name,type,TTL,data}]}`，字段与 Google DoH JSON 对齐，脚本里直接用。

## 我不想让 DNS 知道我大概在哪个区

加 `?ecs=off`。注意这不只是"不回填 ECS"：**报文里客户端自带的那段 ECS 也会被剥掉**（`stripEcs`），
代价是上游 CDN 只能按出口 IP 就近，可能拿到远一点的节点。想要隐私就接受这点延迟。
