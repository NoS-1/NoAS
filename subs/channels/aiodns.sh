#!/usr/bin/env bash
# NoAS · 本机 aiodns 通道（honwen/aiodns，AdGuard dnsproxy 内核）
# 作用：国内域走国内上游直连、开启缓存、拒绝 ANY，境外域走默认上游。
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
  --timeout 3 \
  --cache \
  --refuse-any
