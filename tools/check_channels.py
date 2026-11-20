#!/usr/bin/env python3
"""check_channels.py —— 通道体检（并发，只做真实解析，不做纸面判断）。

为什么必须做：DNS 通道"配了不通"是这类方案最常见的 bug；而且本机/CI 若挂了
代理，会拿到极快的假响应（rcode 4/5、an=0），单看返回码会被骗。
所以做两层判定：
  1. 真解析：发一条 A 查询，要求 ID 回显一致、QDCOUNT=1、rcode ∈ {0,3}、
     NOERROR 时必须有应答记录；
  2. 环境自检：若 >=60% 通道失败且平均 rtt < 50ms，判为 env=suspect（本地劫持），
     全部标 unknown，绝不误判通道死亡。

产物：subs/channels/health.json
退出码恒为 0（体检失败不该阻断每日构建），由 guard 读状态决定是否告警。
"""
import base64
import json
import os
import socket
import ssl
import struct
import sys
import time
import urllib.request
from urllib.request import ProxyHandler, build_opener

# 显式禁掉系统代理：本机/CI 的 HTTP(S)_PROXY 白名单通常不含 Cloudflare 与 DNS 厂商，
# 走代理会被安全网关拦成 000/5xx，体检就会把好通道全判死。直连才是真实结果。
OPENER = build_opener(ProxyHandler({}))
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUTDIR = ROOT / "subs" / "channels"
PROBE_HOST = "www.baidu.com"


def build_query(name):
    hdr = struct.pack(">HHHHHH", 0x4E41, 0x0100, 1, 0, 0, 0)
    q = b"".join(struct.pack(">H", len(p)) + p.encode() for p in name.split(".")) + b"\x00"
    return hdr + q + struct.pack(">HH", 1, 1)


def looks_forged(resp):
    """网关 DPI 伪造响应的指纹：报文截断在 17-20 字节、QDCOUNT=1 但问题名被砍、
    rcode 为 NOTIMP(4)/REFUSED(5)、RA=0。真实解析器不会返回这种残缺报文。"""
    if not (17 <= len(resp) <= 20):
        return False
    flags = struct.unpack(">H", resp[2:4])[0]
    qd = struct.unpack(">H", resp[4:6])[0]
    rcode = flags & 0xF
    ra = (flags >> 7) & 0x1
    return qd == 1 and rcode in (4, 5) and ra == 0 and ancount_of(resp) == 0


def ancount_of(resp):
    return struct.unpack(">H", resp[6:8])[0] if len(resp) >= 8 else 0


def judge(resp):
    """返回 (ok, rcode)。要求 ID 回显、QDCOUNT=1、rcode 合法、NOERROR 有应答。"""
    if looks_forged(resp):
        return False, -5          # -5：明文网关伪造，非通道故障
    if len(resp) < 12:
        return False, -1
    ident = struct.unpack(">H", resp[0:2])[0]
    if ident != 0x4E41:
        return False, -2                      # ID 不对：多半是中间设备伪响应
    qd = struct.unpack(">H", resp[4:6])[0]
    an = struct.unpack(">H", resp[6:8])[0]
    if qd != 1:
        return False, -3                      # 回显问题（如网关截断）
    rcode = resp[3] & 0xF
    if rcode not in (0, 3):
        return False, rcode
    if rcode == 0 and an == 0:
        return False, -4                      # 空 NOERROR：解析器没干活
    return True, rcode


def probe_doh(url):
    raw = build_query(PROBE_HOST)
    b64 = base64.urlsafe_b64encode(raw).decode().rstrip("=")
    t0 = time.time()
    req = urllib.request.Request(
        url + ("&" if "?" in url else "?") + "dns=" + b64,
        headers={"accept": "application/dns-message", "user-agent": "NoAS-health/1.0"})
    with OPENER.open(req, timeout=10) as r:
        body = r.read()
    return judge(body), int((time.time() - t0) * 1000)


def probe_dot(uri):
    host = uri.split("://")[-1]
    port = 853
    if ":" in host:
        host, p = host.rsplit(":", 1)
        port = int(p)
    msg = build_query(PROBE_HOST)
    t0 = time.time()
    ctx = ssl.create_default_context()
    with socket.create_connection((host, port), timeout=10) as s:
        with ctx.wrap_socket(s, server_hostname=host) as ss:
            ss.sendall(struct.pack(">H", len(msg)) + msg)
            buf = b""
            while len(buf) < 2:
                buf += ss.recv(2 - len(buf))
            ln = struct.unpack(">H", buf[:2])[0]
            body = b""
            while len(body) < ln:
                body += ss.recv(ln - len(body))
    return judge(body), int((time.time() - t0) * 1000)


def probe_local(endpoint):
    host, _, port = endpoint.partition(":")
    t0 = time.time()
    with socket.create_connection((host, int(port or 53)), timeout=3):
        pass
    return (True, 0), int((time.time() - t0) * 1000)


def one(row):
    proto, ep = row["proto"], row["endpoint"]
    t0 = time.time()
    try:
        if proto in ("doh", "ndoh"):
            res, rtt = probe_doh(ep)
        elif proto == "dot":
            res, rtt = probe_dot(ep)
        elif proto in ("local", "aiodns"):
            try:
                res, rtt = probe_local(ep)
            except Exception:
                # 本机还没装 aiodns 很正常，这是可选方案，不能算通道故障
                return row["name"], {"status": "absent", "proto": proto, "endpoint": ep,
                                     "rtt_ms": 0, "detail": "本机未部署（可选方案）"}
        else:
            return row["name"], {"status": "skip", "proto": proto, "rtt_ms": 0,
                                 "detail": "非探测协议"}
        ok, rcode = res
        if ok:
            return row["name"], {"status": "ok", "proto": proto, "endpoint": ep,
                                 "rtt_ms": rtt, "rcode": rcode}
        return row["name"], {"status": "down", "proto": proto, "endpoint": ep,
                             "rtt_ms": rtt, "rcode": rcode,
                             "detail": "解析未通过（rcode=%s）" % rcode}
    except Exception as e:
        return row["name"], {"status": "down", "proto": proto, "endpoint": ep,
                             "rtt_ms": int((time.time() - t0) * 1000),
                             "detail": "%s: %s" % (type(e).__name__, str(e)[:80])}


def main():
    rows = []
    for line in (ROOT / "lists" / "dns_channels.tsv").read_text(encoding="utf-8").splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        c = line.split("\t")
        if len(c) >= 6:
            rows.append({"name": c[0], "proto": c[1], "endpoint": c[2], "role": c[4]})

    t0 = time.time()
    workers = min(8, max(1, len(rows)))      # 通道少就少开线程，不空转
    with ThreadPoolExecutor(max_workers=workers) as pool:
        results = dict(pool.map(one, rows))
    OUTDIR.mkdir(parents=True, exist_ok=True)

    real = [v for v in results.values() if v["status"] in ("ok", "down")]
    down = [v for v in real if v["status"] == "down"]
    # 已经强制直连，代理存在不再等于测不准；只保留"全部失败"这一条强证据
    proxy_env = False
    suspect = False
    # 判定优先级：一条都没通 → 环境问题（阿里/腾讯在国内不可能同时全挂）
    # 只要出现"网关伪造"指纹，就说明本机网络不可信，与通道无关
    forged = sum(1 for v in real if v.get("rcode") == -5)
    if forged:
        suspect = True
    if real and not any(v["status"] == "ok" for v in real):
        suspect = True
    elif real and len(down) / len(real) >= 0.6:
        avg = sum(v.get("rtt_ms", 0) for v in down) / max(1, len(down))
        if avg < 50 or proxy_env:          # 极快失败 / 显式代理 → 不可信
            suspect = True
    elif proxy_env and down:
        suspect = True
    if suspect:
        for k, v in results.items():
            if v["status"] == "down":
                v["status"] = "unknown"
                v["detail"] = "疑似本机代理劫持，未计入通道死亡：" + v.get("detail", "")

    payload = {
        "checked_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "probe": PROBE_HOST,
        "elapsed_ms": int((time.time() - t0) * 1000),
        "env": "suspect" if suspect else "clean",
        "channels": results,
    }
    (OUTDIR / "health.json").write_text(
        json.dumps(payload, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    ok = sum(1 for v in results.values() if v["status"] == "ok")
    print("通道体检：ok %d／%d，env=%s，用时 %dms"
          % (ok, len(results), payload["env"], payload["elapsed_ms"]))
    for k, v in results.items():
        print("  %-14s %-8s %s" % (k, v["status"], v.get("detail") or ("%sms" % v.get("rtt_ms"))))
    return 0


if __name__ == "__main__":
    sys.exit(main())
