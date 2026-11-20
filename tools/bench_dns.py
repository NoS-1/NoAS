#!/usr/bin/env python3
"""DoH / DoT 端点延迟基准测试。

只做测量，不做判断：每个端点跑 N 次，报 min / median / 失败数。
工程上"最低延迟"= 最小 RTT，而不是平均——平均值会被偶发抖动拉偏。

用法：
    python3 tools/bench_dns.py                # 默认全部端点
    python3 tools/bench_dns.py --rounds 7
    python3 tools/bench_dns.py --only doh     # 只测 DoH
"""
import argparse, json, socket, ssl, statistics, struct, time
import urllib.request, urllib.error

# 构造一个最小的 A 查询（example.com）
def _name_bytes(name):
    out = b""
    for part in name.split("."):
        out += bytes([len(part)]) + part.encode()
    return out + b"\x00"


def dns_query(name="example.com", qtype=1):
    hdr = struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
    return hdr + _name_bytes(name) + struct.pack(">HH", qtype, 1)


DOH = [
    ("阿里 DoH", "https://dns.alidns.com/dns-query"),
    ("腾讯 DoH", "https://doh.pub/dns-query"),
    ("360 DoH", "https://doh.360.cn/dns-query"),
    ("中科大 DoH", "https://doh.ustc.edu.cn/dns-query"),
    ("CF 公共 DoH", "https://cloudflare-dns.com/dns-query"),
    ("自建 Worker DoH", "https://noas-doh.199999510.workers.dev/dns-query"),
]

DOT = [
    ("阿里 DoT", ("223.5.5.5", 853), None),
    ("腾讯 DoT", ("120.53.53.53", 853), None),
    ("腾讯 DoT2", ("dot.pub", 853), None),
    ("CF DoT", ("1.1.1.1", 853), None),
    ("自建 Gateway DoT", ("oxyacq0a4t.cloudflare-gateway.com", 853), None),
]


def timeit(fn):
    t0 = time.perf_counter()
    try:
        fn()
        return (time.perf_counter() - t0) * 1000
    except Exception:
        return None


def probe_doh(url, timeout=6):
    body = dns_query()
    req = urllib.request.Request(
        url, data=body,
        headers={"Content-Type": "application/dns-message", "Accept": "application/dns-message"},
        method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as r:
        r.read(16)          # 读一点就够，重点是首字节延迟


def probe_dot(host, port, timeout=6):
    sock = socket.create_connection((host, port), timeout=timeout)
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with ctx.wrap_socket(sock, server_hostname=host) as s:
        q = dns_query()
        s.sendall(struct.pack(">H", len(q)) + q)
        head = s.recv(2)
        if len(head) < 2:
            raise IOError("no response")


def bench(label, fn, rounds):
    vals, fails = [], 0
    for _ in range(rounds):
        ms = timeit(fn)
        if ms is None:
            fails += 1
        else:
            vals.append(ms)
    if not vals:
        return label, None, None, rounds
    return label, min(vals), statistics.median(vals), fails


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rounds", type=int, default=5)
    ap.add_argument("--only", choices=["doh", "dot", "all"], default="all")
    args = ap.parse_args()

    print("## DoH（HTTPS POST，含 TLS 握手）")
    if args.only in ("doh", "all"):
        print("%-20s %8s %8s %6s" % ("端点", "min(ms)", "median", "失败"))
        for label, url in DOH:
            r = bench(label, lambda u=url: probe_doh(u), args.rounds)
            print("%-20s %8s %8s %6s" % (r[0], "%.0f" % r[1] if r[1] else "-",
                                         "%.0f" % r[2] if r[2] else "-", r[3]))

    print("\n## DoT（TCP+TLS 853）")
    if args.only in ("dot", "all"):
        print("%-20s %8s %8s %6s" % ("端点", "min(ms)", "median", "失败"))
        for label, addr, _ in DOT:
            r = bench(label, lambda a=addr: probe_dot(*a), args.rounds)
            print("%-20s %8s %8s %6s" % (r[0], "%.0f" % r[1] if r[1] else "-",
                                         "%.0f" % r[2] if r[2] else "-", r[3]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
