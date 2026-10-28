// Reports gzipped size of the cold-load bundle (everything index.html pulls in eagerly)
// against the foundation's perf bar (§2.10(b): under ~300 KB gzipped).
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, resolve, dirname } from 'node:path';
import { gzipSync } from 'node:zlib';
import { fileURLToPath } from 'node:url';

const dist = resolve(dirname(fileURLToPath(import.meta.url)), '../dist');
const html = readFileSync(join(dist, 'index.html'), 'utf8');
const eager = new Set(
  [...html.matchAll(/(?:src|href)="\/?(assets\/[^"]+)"/g)]
    .map((m) => m[1])
    .filter((p) => !/rel="modulepreload"/.test(p)),
);
// modulepreload links are also fetched on cold load
for (const m of html.matchAll(/<link rel="modulepreload"[^>]*href="\/?(assets\/[^"]+)"/g)) eager.add(m[1]);

const rows = [];
let total = 0;
let totalRaw = 0;
const walk = (dir) => {
  for (const f of readdirSync(dir)) {
    const p = join(dir, f);
    if (statSync(p).isDirectory()) walk(p);
    else if (/\.(js|css)$/.test(f)) {
      const raw = readFileSync(p);
      const gz = gzipSync(raw, { level: 9 }).length;
      const rel = p.slice(dist.length + 1);
      const isEager = eager.has(rel);
      rows.push([rel, raw.length, gz, isEager]);
      if (isEager) {
        total += gz;
        totalRaw += raw.length;
      }
    }
  }
};
walk(join(dist, 'assets'));
rows.sort((a, b) => b[2] - a[2]);
const kb = (n) => (n / 1024).toFixed(1).padStart(7) + ' KB';
for (const [rel, raw, gz, e] of rows) console.log(`${e ? 'eager' : 'lazy '}  ${kb(raw)}  ${kb(gz)} gz  ${rel}`);
console.log(`\ncold load: ${kb(totalRaw)} raw, ${kb(total)} gzipped  (bar: < 300 KB gzipped) ${total < 300 * 1024 ? 'PASS' : 'FAIL'}`);
