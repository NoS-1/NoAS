#!/usr/bin/env bash
# NoAS · 本机 aiodns 通道（honwen/aiodns，AdGuard dnsproxy 内核）
# 作用：国内域走国内上游直连、开启缓存、拒绝 ANY，境外域走默认上游。
# 延迟调优（实测依据见 docs/dns-latency.html）：
#   --timeout 1   上游卡住时 1 秒就切下一个，别让一次抖动拖到 3 秒
#   --http3       DoH 走 QUIC，少一个握手往返；上游不支持时自动降级 HTTP/2，不会失败
#   两个 DoT 上游常驻长连接，复用后实测 9~16ms
# 注意：aiodns 本身【不做广告拦截】，拦截请用 AdGuard Home 加载 adguard.txt，
#       或在系统 hosts 导入 hosts.txt（0.0.0.0 方案）。
# 安装：docker pull chenhw2/aiodns  或  go install github.com/honwen/aiodns@latest
set -euo pipefail

SPECIAL_LIST="${SPECIAL_LIST:-https://raw.githubusercontent.com/NoS-1/NoAS/main/subs/channels/aiodns.special.txt}"
LISTEN="${LISTEN:-127.0.0.1:5300}"

exec aiodns \
  --listen   "$LISTEN" \
  --upstream tls://dns.alidns.com:853 --upstream tls://dot.pub:853 \
  --special-upstream https://dns.alidns.com/dns-query \
  --fallback https://dns.alidns.com/dns-query --fallback https://doh.pub/dns-query \
  --bootstrap 223.5.5.5 --bootstrap 119.29.29.29 \
  --special-list "$SPECIAL_LIST" \
  --timeout 1 \
  --http3 \
  --cache \
  --refuse-any
