// Fuzzy matching for the command palette (§2.7): case-insensitive subsequence match scored with
// contiguity and word-start bonuses, returning the matched indices so the UI can emphasise them.
// Dynamic programming over (query char × text char); inputs are short (tool names, descriptions,
// URLs), so the O(n·m) table is cheap.

export interface FuzzyMatch {
  score: number;
  /** Indices into the original text, ascending. */
  indices: number[];
}

const SEPARATORS = new Set([' ', '.', '_', '-', '/', ':', '?', '&', '=', '(', ')', ',']);

function isWordStart(text: string, i: number): boolean {
  if (i === 0) return true;
  const prev = text[i - 1]!;
  if (SEPARATORS.has(prev)) return true;
  const cur = text[i]!;
  // camelCase boundary
  return cur !== cur.toLowerCase() && prev === prev.toLowerCase() && prev !== prev.toUpperCase();
}

// fzf-like weights: a match is worth 16; word starts add 8 (doubled for the first query char);
// a char that continues a run adds 8; a gap costs 3 to open and 2 per further skipped char.
const MATCH = 16;
const CONTIGUOUS = 8;
const WORD_START = 8;
const EXACT_PREFIX = 16;
const GAP_OPEN = 3;
const GAP_EXTEND = 2;
const LEAD_PENALTY = 0.1;

/**
 * Match `query` against `text`. Returns null when `query` is not a subsequence of `text`.
 * An empty query matches everything with score 0 and no indices.
 */
export function fuzzyMatch(query: string, text: string): FuzzyMatch | null {
  const q = query.toLowerCase();
  const t = text.toLowerCase();
  const n = q.length;
  const m = t.length;
  if (n === 0) return { score: 0, indices: [] };
  if (n > m) return null;

  // Quick reject: must be a subsequence at all.
  let k = 0;
  for (let j = 0; j < m && k < n; j++) if (t[j] === q[k]) k++;
  if (k < n) return null;

  // best[i][j]: best score matching q[0..i] with q[i] matched at t[j]; -Infinity when impossible.
  const NEG = -Infinity;
  const best: number[][] = Array.from({ length: n }, () => new Array<number>(m).fill(NEG));
  const from: number[][] = Array.from({ length: n }, () => new Array<number>(m).fill(-1));

  for (let j = 0; j < m; j++) {
    if (t[j] !== q[0]) continue;
    best[0]![j] = MATCH + (isWordStart(text, j) ? WORD_START * 2 : 0) - j * LEAD_PENALTY;
  }
  for (let i = 1; i < n; i++) {
    const qi = q[i]!;
    // Best non-contiguous predecessor p < j-1, with the gap cost folded in: the cost of a gap from
    // p to j is GAP_OPEN + GAP_EXTEND·(j-p-2), so track max over p of best[i-1][p] + GAP_EXTEND·p.
    let runMax = NEG;
    let runIdx = -1;
    for (let j = 1; j < m; j++) {
      const p = j - 2;
      if (p >= 0 && best[i - 1]![p]! > NEG && best[i - 1]![p]! + GAP_EXTEND * p > runMax) {
        runMax = best[i - 1]![p]! + GAP_EXTEND * p;
        runIdx = p;
      }
      if (t[j] !== qi) continue;
      const wordStart = isWordStart(text, j) ? WORD_START : 0;
      let candidate = NEG;
      let src = -1;
      const contiguous = best[i - 1]![j - 1]!;
      if (contiguous > NEG) {
        candidate = contiguous + MATCH + CONTIGUOUS + wordStart;
        src = j - 1;
      }
      if (runMax > NEG) {
        const gap = runMax - GAP_EXTEND * (j - 2) - GAP_OPEN + MATCH + wordStart;
        if (gap > candidate) {
          candidate = gap;
          src = runIdx;
        }
      }
      best[i]![j] = candidate;
      from[i]![j] = src;
    }
  }

  let end = -1;
  let score = NEG;
  for (let j = 0; j < m; j++) {
    if (best[n - 1]![j]! > score) {
      score = best[n - 1]![j]!;
      end = j;
    }
  }
  if (end < 0) return null;

  const indices = new Array<number>(n);
  let j = end;
  for (let i = n - 1; i >= 0; i--) {
    indices[i] = j;
    j = from[i]![j]!;
  }
  if (t.startsWith(q)) score += EXACT_PREFIX;
  return { score, indices };
}

export interface Ranked<T> {
  item: T;
  score: number;
  /** Matched indices per searched field, in the order the fields were given. */
  matches: (number[] | null)[];
}

/**
 * Rank `items` by the best fuzzy score across `fields` (earlier fields weigh more: the first
 * field counts double). Items that match no field are dropped. Stable for equal scores.
 */
export function fuzzyRank<T>(items: readonly T[], query: string, fields: (item: T) => string[]): Ranked<T>[] {
  const q = query.trim();
  const out: Ranked<T>[] = [];
  items.forEach((item, order) => {
    const texts = fields(item);
    if (!q) {
      out.push({ item, score: -order, matches: texts.map(() => null) });
      return;
    }
    let score = -Infinity;
    const matches: (number[] | null)[] = [];
    texts.forEach((text, fi) => {
      const m = fuzzyMatch(q, text);
      matches.push(m ? m.indices : null);
      if (m) {
        const weighted = fi === 0 ? m.score * 2 : m.score;
        if (weighted > score) score = weighted;
      }
    });
    if (score > -Infinity) out.push({ item, score, matches });
  });
  if (q) out.sort((a, b) => b.score - a.score);
  return out;
}

/** Split `text` into [plain, matched, plain, …] segments for rendering emphasis. */
export function segments(text: string, indices: number[] | null | undefined): { text: string; hit: boolean }[] {
  if (!indices || indices.length === 0) return [{ text, hit: false }];
  const set = new Set(indices);
  const out: { text: string; hit: boolean }[] = [];
  let cur = '';
  let curHit = set.has(0);
  for (let i = 0; i < text.length; i++) {
    const hit = set.has(i);
    if (hit !== curHit) {
      if (cur) out.push({ text: cur, hit: curHit });
      cur = '';
      curHit = hit;
    }
    cur += text[i];
  }
  if (cur) out.push({ text: cur, hit: curHit });
  return out;
}
