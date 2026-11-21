"""大样本误伤率（FP）统计：用真产物 worker.js 对 benign_5000 全量跑三档。

判定口径：一个"业务主域"被任一档判为拦截，就是一次误伤（FP）。
lite 档硬门禁 FP=0；mid/full 先记录真实数字，用于逐月对比。
"""
import json
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
SAMPLE = ROOT / "tests/benign_5000.txt"
OUT = ROOT / "state/benign_fp.json"


def load():
    d = []
    for line in SAMPLE.read_text(encoding="utf-8").splitlines():
        s = line.strip()
        if s and not s.startswith("#"):
            d.append(s)
    return d


def run_tier(domains, tier):
    """一次 node 进程跑完一档，避免 1.3 万次进程启动。"""
    js = """
const mod = await import('file://ROOTP/doh/worker.js');
const h = mod.default.fetch;
const ctx = { waitUntil() {} };
// mid/full 已移到 KV：这里从 subs 读出来当 KV 替身，否则 tier2/3 会退化成 lite，
// 误伤统计就失真了（会"看起来更安全"，其实测的不是同一份规则）。
import fs from 'fs';
const NL = String.fromCharCode(10);
const readTier = (t) => { const p = 'ROOTP/subs/' + t + '/domains.txt'; if (!fs.existsSync(p)) return null;
  const ds = [...new Set(fs.readFileSync(p, 'utf8').split(NL).map((l) => l.split('#')[0].trim())
    .filter((l) => l && !l.startsWith('!')).map((l) => l.toLowerCase()).filter((l) => l.includes('.')))];
  return { ver: 'local', count: ds.length, compact: '|' + ds.join('|') + '|' }; };
const env = { RULES: { async get(k) { return k === 'mid_v1' ? readTier('mid') : k === 'full_v1' ? readTier('full') : null; }, async put() {} } };
const tier = TIERP;
let out = [];
for (const d of require_domains) {
  const r = await h(new Request('https://x.dev/check?q=' + d + '&tier=' + tier), env, ctx);
  const j = await r.json();
  if (j.blocked) out.push(d);
}
console.log(JSON.stringify(out));
"""\
    .replace("require_domains", json.dumps(domains)) \
    .replace("ROOTP", str(ROOT)) \
    .replace("TIERP", str(tier))
    p = subprocess.run(["node", "--input-type=module", "-e", js], input="", capture_output=True,
                       text=True, cwd=str(ROOT), env={"PATH": "/usr/bin:/bin:/usr/local/bin"},
                       timeout=600)
    if p.returncode != 0:
        print(p.stderr[:1200], file=sys.stderr)
        return None
    return json.loads(p.stdout.strip().splitlines()[-1])


def main():
    domains = load()
    if not domains:
        print("样本为空", file=sys.stderr)
        return 1
    res = {}
    for t in (1, 2, 3):
        hits = run_tier(domains, t)
        if hits is None:
            return 1
        res[t] = {"n": len(domains), "fp": len(hits), "rate": round(len(hits) / len(domains), 6),
                  "domains": hits[:200]}
        print(f"tier{t}: 样本 {len(domains)}  FP {len(hits)}  误伤率 {len(hits)/len(domains):.4%}")
        if hits:
            print("   命中示例:", ", ".join(hits[:12]))
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps({"sample": str(SAMPLE.relative_to(ROOT)), **{f"tier{k}": v for k, v in res.items()}},
                              ensure_ascii=False, indent=1), encoding="utf-8")
    ok = res[1]["fp"] == 0
    print("lite 硬门禁:", "PASS" if ok else "FAIL（lite 出现误伤，必须修规则）")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
