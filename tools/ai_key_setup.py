#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ai_key_setup.py —— 一条命令把判定源 key 写进本机凭据文件（600 权限）。

用法：
  python3 tools/ai_key_setup.py --provider aliyun   --key sk-xxxx
  python3 tools/ai_key_setup.py --provider deepseek --key sk-xxxx
  python3 tools/ai_key_setup.py --provider ark      --key xxxx
  python3 tools/ai_key_setup.py --list              # 看当前已配哪些

写入位置：/home/user/.noas/creds.env（与 CF/GH 凭据同文件，600，不入库）
写完后跑 tools/ai_doctor.py 验证；CI 侧需在仓库 Secrets 同名添加才会生效。
"""
import argparse
import os
import pathlib
import sys

CREDS = pathlib.Path(os.path.expanduser("~/.noas/creds.env"))
KEYS = {"aliyun": "DASHSCOPE_API_KEY", "deepseek": "DEEPSEEK_API_KEY", "ark": "ARK_API_KEY"}


def read_lines():
    if not CREDS.exists():
        CREDS.parent.mkdir(parents=True, exist_ok=True)
        CREDS.write_text("", encoding="utf-8")
        CREDS.chmod(0o600)
    return CREDS.read_text(encoding="utf-8").splitlines()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--provider", choices=list(KEYS))
    ap.add_argument("--key")
    ap.add_argument("--list", action="store_true")
    a = ap.parse_args()

    lines = read_lines()
    if a.list or not (a.provider and a.key):
        print("%-12s %-24s %s" % ("provider", "env 变量", "状态"))
        for p, var in KEYS.items():
            hit = any(l.startswith(var + "=") and len(l.split("=", 1)[1].strip()) > 8 for l in lines)
            print("%-12s %-24s %s" % (p, var, "已配置" if hit else "未配置"))
        return 0

    var = KEYS[a.provider]
    key = a.key.strip()
    if len(key) < 8:
        print("key 太短，疑似粘贴错误")
        return 2
    keep = [l for l in lines if not l.startswith(var + "=")]
    keep.append("%s=%s" % (var, key))
    CREDS.write_text("\n".join(keep) + "\n", encoding="utf-8")
    CREDS.chmod(0o600)
    print("已写入 %s → %s（权限 %o）" % (var, CREDS, CREDS.stat().st_mode & 0o777))
    print("本地已生效。CI 生效需在仓库 Settings → Secrets 添加同名 %s。" % var)
    return 0


if __name__ == "__main__":
    sys.exit(main())
