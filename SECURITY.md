# 安全策略

## 报告问题
私人邮箱或 GitHub Security Advisory（仓库 Security 标签页 → Report a vulnerability）。
请勿用公开 Issue 提交可利用细节（绕过规则、伪造 ECS、DoS 手法等）。

## 处理时限
- 确认收到：72 小时内
- 初步评估：7 天内
- 修复或缓解：30 天内（严重问题会先降级/回滚已发布版本）

## 范围
- `doh/worker.tpl.js`（DoH 判定与上游处理）
- `pages/`（Pages Functions 与 `/why`、`/tier`）
- `.github/workflows/`（构建与部署流水线，含 secret 使用）
- `tools/`（构建、部署、Gateway 同步脚本）

不在范围：客户端自身的 DNS 配置、上游 DoH 供应商的服务可用性、第三方规则源的内容准确性。

## 已知设计取舍
- 不校验 DNSSEC（Worker 每请求 CPU 10ms，只透传 DO 位）
- 不实现 DoT 853（国内封禁）
- 上游 DoH 走 GET 形态，报文在查询串里（RFC 8484 允许）
