#!/usr/bin/env python3
"""Gateway 双向实测：必须“拦广告 + 放正常”，只测通不通没有意义。

为什么单独一个脚本：
- 本机 probe 走代理，代理会伪造/失败，导致 gateway 在 health.json 里长期 unknown；
- Gateway 端点直连可通（不走代理），所以这里强制 no_proxy，自己断言。
结果写 state/gateway_verify.json，供 gen_channels 标注「已实测」。
"""
import json
import os
import pathlib
import struct
import sys
import urllib.error
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parent.parent
HOST = os.environ.get("GATEWAY_HOST", "oxyacq0a4t.cloudflare-gateway.com").strip()
OUT = ROOT / "state" / "gateway_verify.json"
BLOCK_PROBE = ["doubleclick.net", "googleadservices.com"]
PASS_PROBE = ["baidu.com"]


def _no_proxy():
    for k in ("http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY", "all_proxy", "ALL_PROXY"):
        os.environ.pop(k, None)
    os.environ["no_proxy"] = "*"
    os.environ["NO_PROXY"] = "*"


def dns_query(name, qtype=1):
    b = struct.pack(">HHHHHH", 0x5A5A, 0x0100, 1, 0, 0, 0)
    for lab in name.split("."):
        b += bytes([len(lab)]) + lab.encode()
    return b + b"\x00" + struct.pack(">HH", qtype, 1)


def _skip(dv, p):
    while True:
        ln = dv[p]
        if ln == 0:
            return p + 1
        if ln & 0xC0 == 0xC0:
            return p + 2
        p += ln + 1


def answers(raw):
    dv = memoryview(raw)
    qd, an = struct.unpack(">HH", raw[4:8])
    off = 12
    for _ in range(qd):
        off = _skip(dv, off) + 4
    out = []
    for _ in range(an):
        off = _skip(dv, off)
        t, _cl, _ttl, rl = struct.unpack(">HHIH", raw[off:off + 10])
        off += 10
        if t == 1:
            out.append(".".join(str(x) for x in raw[off:off + 4]))
        off += rl
    return out


def ask(name):
    req = urllib.request.Request(
        "https://%s/dns-query" % HOST, data=dns_query(name),
        headers={"content-type": "application/dns-message",
                 "accept": "application/dns-message"})
    raw = urllib.request.urlopen(req, timeout=15).read()
    return answers(raw), (raw[3] & 0xF)


def main():
    _no_proxy()
    detail = {}
    ok = True
    try:
        for d in BLOCK_PROBE:
            ips, rcode = ask(d)
            hit = "0.0.0.0" in ips
            detail[d] = {"rcode": rcode, "answer": ips[:4], "blocked": hit}
            ok = ok and hit
        for d in PASS_PROBE:
            ips, rcode = ask(d)
            passed = bool(ips) and "0.0.0.0" not in ips
            detail[d] = {"rcode": rcode, "answer": ips[:4], "passed": passed}
            ok = ok and passed
    except Exception as e:
        ok = False
        detail["error"] = str(e)[:200]

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps({"host": HOST, "ok": ok, "detail": detail},
                              ensure_ascii=False, indent=1), encoding="utf-8")
    print("Gateway 双向实测：%s（%s）" % ("通过" if ok else "失败", HOST))
    for k, v in detail.items():
        if isinstance(v, dict):
            print("  %s → %s" % (k, v))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
