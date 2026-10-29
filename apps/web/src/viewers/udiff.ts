// Line-based Myers diff → unified patch text, for "Export patch" in the Diff viewer.
// Capped: beyond MAX_LINES the patch degrades to whole-file replace so the UI never stalls.

export const MAX_LINES = 20_000;

type Op = { t: ' ' | '-' | '+'; line: string };

function myers(a: string[], b: string[]): Op[] {
  const n = a.length;
  const m = b.length;
  const max = n + m;
  const v = new Int32Array(2 * max + 2);
  const trace: Int32Array[] = [];
  const off = max + 1;
  let found = false;
  for (let d = 0; d <= max && !found; d++) {
    trace.push(v.slice());
    for (let k = -d; k <= d; k += 2) {
      let x: number;
      if (k === -d || (k !== d && v[off + k - 1]! < v[off + k + 1]!)) x = v[off + k + 1]!;
      else x = v[off + k - 1]! + 1;
      let y = x - k;
      while (x < n && y < m && a[x] === b[y]) {
        x++;
        y++;
      }
      v[off + k] = x;
      if (x >= n && y >= m) {
        found = true;
        break;
      }
    }
  }
  // Backtrack.
  const ops: Op[] = [];
  let x = n;
  let y = m;
  for (let d = trace.length - 1; d >= 0; d--) {
    const vv = trace[d]!;
    const k = x - y;
    let prevK: number;
    if (k === -d || (k !== d && vv[off + k - 1]! < vv[off + k + 1]!)) prevK = k + 1;
    else prevK = k - 1;
    const prevX = vv[off + prevK]!;
    const prevY = prevX - prevK;
    while (x > prevX && y > prevY) {
      ops.push({ t: ' ', line: a[x - 1]! });
      x--;
      y--;
    }
    if (d > 0) {
      if (x === prevX) {
        ops.push({ t: '+', line: b[y - 1]! });
        y--;
      } else {
        ops.push({ t: '-', line: a[x - 1]! });
        x--;
      }
    }
  }
  return ops.reverse();
}

export function unifiedDiff(aText: string, bText: string, aName = 'a', bName = 'b', context = 3): string {
  const a = aText.split('\n');
  const b = bText.split('\n');
  let ops: Op[];
  if (a.length + b.length > MAX_LINES) {
    ops = [...a.map((line) => ({ t: '-', line }) as Op), ...b.map((line) => ({ t: '+', line }) as Op)];
  } else {
    ops = myers(a, b);
  }
  if (!ops.some((o) => o.t !== ' ')) return '';

  const out: string[] = [`--- ${aName}`, `+++ ${bName}`];
  let i = 0;
  let aLine = 1;
  let bLine = 1;
  while (i < ops.length) {
    // Skip unchanged until the next change (keeping `context` lines before it).
    let j = i;
    while (j < ops.length && ops[j]!.t === ' ') j++;
    if (j >= ops.length) break;
    const start = Math.max(i, j - context);
    for (let k = i; k < start; k++) {
      aLine++;
      bLine++;
    }
    // Extend the hunk while changes stay within 2*context of each other.
    let end = j;
    let last = j;
    while (end < ops.length) {
      if (ops[end]!.t !== ' ') last = end;
      else if (end - last > 2 * context) break;
      end++;
    }
    end = Math.min(ops.length, last + context + 1);
    const hunk = ops.slice(start, end);
    const aCount = hunk.filter((o) => o.t !== '+').length;
    const bCount = hunk.filter((o) => o.t !== '-').length;
    out.push(`@@ -${aLine},${aCount} +${bLine},${bCount} @@`);
    for (const o of hunk) {
      out.push(o.t + o.line);
      if (o.t !== '+') aLine++;
      if (o.t !== '-') bLine++;
    }
    i = end;
  }
  return out.join('\n') + '\n';
}
