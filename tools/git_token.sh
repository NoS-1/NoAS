#!/usr/bin/env bash
# git_token.sh —— 统一取推送凭据：优先 GitHub App（现签 1 小时），否则回退 PAT。
#
# 双保险的意义：App 令牌短期、可自动轮换；PAT 是兜底。哪一路缺失都不阻塞，
# 任何异常都静默降级，绝不因为凭据问题让推送失败在别处。
#
# 用法：TOKEN=$(bash tools/git_token.sh)
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CREDS="/home/user/.noas/creds.env"

# 1) App 优先
if [ -n "${GH_APP_ID:-}" ] && [ -n "${GH_APP_PRIVATE_KEY:-}" ] || [ -f /home/user/.noas/app.pem ]; then
  APP_TOKEN="$(python3 "$HERE/gh_app_token.py" 2>/dev/null || true)"
  if [ -n "$APP_TOKEN" ]; then
    echo "$APP_TOKEN"
    exit 0
  fi
fi

# 2) 回退 PAT
PAT="$(sed -n 's/^GH_PAT=//p' "$CREDS" 2>/dev/null | head -1)"
if [ -n "$PAT" ]; then
  echo "$PAT"
  exit 0
fi

# 3) 最后回退内置 GITHUB_TOKEN（CI 场景）
[ -n "${GITHUB_TOKEN:-}" ] && echo "$GITHUB_TOKEN"
exit 0
