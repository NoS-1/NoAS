"""发布后端到端验证：部署"成功"不等于线上"生效"。

只查部署脚本的返回码是不够的：CDN 可能还挂着旧版本、Worker 可能新版本没切、
Gateway 可能少了几片（规则顺序一错就整档失效）。这里直接按客户端视角打真实端点，
再回读 CF 侧对象数，任何一项不符就退出码 1（CI 走 required 模式 → 红 → Alert 开 Issue）。

检查项：
  1. Pages /tier 可读，且三档条数与仓库 subs/*/meta.json 一致
  2. Pages 三档端点 /dns-query/{lite,mid,full} 都 200
  3. DoH 实测：拦截域回 0.0.0.0、白名单域放行且不是 0.0.0.0
  4. Worker 脚本与其 bindings 在线（CF API）
  5. Gateway 列表片数 = 60（10+20+30）+ allow + core，规则 6 条
"""
import json
import os
import pathlib
import struct
import sys

import requests

BASE = "https://noas-cdn.pages.dev"
UA = {"user-agent": "Mozilla/5.0 NoAS-postcheck", "accept": "application/dns-message"}
TIMEOUT = 20


def dns_query(name, qtype=1):
    body = b"".join(bytes([len(l)]) + l for l in name.encode().split(b".") + [b""])
    msg = struct.pack(">HHHHHH", 0x4321, 0x0100, 1, 0, 0, 0) + body + struct.pack(">HH", qtype, 1)
    r = requests.post(f"{BASE}/dns-query", data=msg,
                      headers={**UA, "content-type": "application/dns-message"}, timeout=TIMEOUT)
    if r.status_code != 200:
        return {"status": r.status_code, "rdata": None, "x": None}
    b = r.content
    an = struct.unpack(">H", b[6:8])[0]
    off = 12
    while off < len(b) and b[off]:
        off += b[off] + 1
    off += 5
    rdata = None
    if an:
        if (b[off] & 0xc0) == 0xc0:
            off += 2
        rdlen = struct.unpack(">H", b[off + 8:off + 10])[0] if len(b) >= off + 10 else 0
        p = off + 10
        rdata = ".".join(str(x) for x in b[p:p + 4]) if qtype == 1 and rdlen == 4 else "?"
    return {"status": r.status_code, "rdata": rdata, "x": r.headers.get("x-noas")}


def cf_get(path):
    tok = os.environ.get("CF_API_TOKEN") or os.environ.get("CF_TOKEN") or ""
    acc = os.environ.get("CF_ACCOUNT_ID", "226431c8f431ebb75d82dd5dbd5e8d86").strip()
    r = requests.get(f"https://api.cloudflare.com/client/v4/accounts/{acc}/{path}",
                     headers={"Authorization": f"Bearer {tok}", "user-agent": "NoAS-postcheck"},
                     timeout=TIMEOUT)
    return r


def main():
    fails, notes = [], []

    # 1) /tier 与三档条数
    try:
        t = requests.get(f"{BASE}/tier", headers=UA, timeout=TIMEOUT).json()
        if not t.get("set_loaded"):
            fails.append(f"/tier 规则未加载：{t.get('err')}")
        # /tier 只报当前档；条数用固定三档端点逐个核
        for tier in ("lite", "mid", "full"):
            m = pathlib.Path(f"subs/{tier}/meta.json")
            want = json.loads(m.read_text(encoding="utf-8")).get("count") if m.exists() else None
            r = requests.get(f"{BASE}/dns-query/{tier}?info=1", headers=UA, timeout=TIMEOUT)
            if r.status_code != 200:
                fails.append(f"{tier} 端点 {r.status_code}")
                continue
            got = r.json().get("count")
            if want and got != want:
                fails.append(f"{tier} 线上 {got} ≠ 仓库 {want}")
            else:
                notes.append(f"{tier}={got}")
    except Exception as e:
        fails.append(f"/tier 不可用：{e}")

    # 3) DoH 实测
    try:
        blocked = dns_query("adsrvr.org")
        if blocked.get("rdata") != "0.0.0.0":
            fails.append(f"adsrvr.org 未拦截（rdata={blocked.get('rdata')} x={blocked.get('x')}）")
        allow = dns_query("www.qq.com")
        if allow.get("status") != 200 or allow.get("rdata") in (None, "0.0.0.0"):
            fails.append(f"www.qq.com 被误伤（rdata={allow.get('rdata')} x={allow.get('x')}）")
        notes.append(f"blocked={blocked.get('x')} allow={allow.get('x')}")
    except Exception as e:
        fails.append(f"DoH 实测异常：{e}")

    # 4) Worker 在线（CF API 只在有令牌时查，本地/无密场景跳过）
    if os.environ.get("CF_API_TOKEN") or os.environ.get("CF_TOKEN"):
        try:
            r = cf_get("workers/scripts/noas-doh/settings")
            if r.status_code != 200:
                fails.append(f"Worker settings {r.status_code}")
            else:
                notes.append("worker=online")
        except Exception as e:
            fails.append(f"Worker 查询异常：{e}")

        # 5) Gateway 片数与规则数
        try:
            lists = cf_get("gateway/lists?per_page=100").json().get("result", [])
            names = [l.get("name", "") for l in lists]
            cnt = {"l1": sum(n.startswith("noas_l1_") for n in names),
                   "l2": sum(n.startswith("noas_l2_") for n in names),
                   "l3": sum(n.startswith("noas_l3_") for n in names)}
            if cnt != {"l1": 10, "l2": 20, "l3": 30}:
                fails.append(f"Gateway 片数 {cnt} ≠ 10/20/30")
            if "noas_allow" not in names or "noas_core" not in names:
                fails.append("Gateway 缺 allow/core 列表")
            rules = cf_get("gateway/rules").json().get("result", [])
            if len(rules) < 6:
                fails.append(f"Gateway 规则 {len(rules)} < 6")
            notes.append(f"lists={len(names)} rules={len(rules)}")
        except Exception as e:
            fails.append(f"Gateway 查询异常：{e}")

    print(json.dumps({"ok": not fails, "notes": notes, "fails": fails}, ensure_ascii=False, indent=1))
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
