// 本地/CI 用的 KV 替身：mid/full 现在不内嵌，必须从 subs 读出来当 KV，
// 否则 tier2/3 会静默退化成 lite，回归就测不到真正的 mid/full 行为。
import fs from 'fs';
import path from 'path';

const ROOT = path.resolve(import.meta.dirname, '..');

function load(tier) {
  const p = path.join(ROOT, 'subs', tier, 'domains.txt');
  if (!fs.existsSync(p)) return null;
  const ds = [...new Set(fs.readFileSync(p, 'utf8').split('\n')
    .map((l) => l.split('#')[0].trim())
    .filter((l) => l && !l.startsWith('!'))
    .map((l) => (l.startsWith('||') ? l.slice(2).replace(/\^$/, '') : l).toLowerCase())
    .filter((l) => l.includes('.')))];
  return { ver: 'local', tier, count: ds.length, compact: '|' + ds.join('|') + '|' };
}

export function makeEnv() {
  const mid = load('mid');
  const full = load('full');
  return {
    RULES: {
      async get(k) {
        if (k === 'mid_v1') return mid;
        if (k === 'full_v1') return full;
        return null;
      },
      async put() { return; },
    },
  };
}
