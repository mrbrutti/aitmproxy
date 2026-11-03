// The pure matchers of `scan-live.mjs` (plan Task 3.11, gap 56; Task 3.12 C moved them here): the
// live proof itself needs ports and a core, so its matchers are pinned where vitest runs,
// `src/panels/scanner/tester.scan-live-matchers.test.ts`, which loads this module by file URL and
// holds the 48 literals the script's `--selfcheck` used to carry. Nothing here touches the disk, the
// network or the DOM: every export is a function of its arguments or a constant.
const j = JSON.stringify;

/** JobState's terminal states (crates/aitm-scan-model/src/job.rs). */
export const TERMINAL = new Set(['done', 'cancelled', 'failed']);

/** `287 of 2,000` (the W2 row and KPI) or `418/2000` (the older row) -> `{ sent, budget }`; null otherwise. */
export function parseProbesText(text) {
  if (typeof text !== 'string') return null;
  const m = text.match(/(\d[\d,]*)\s*(?:\/|of)\s*(\d[\d,]*)/);
  return m ? { sent: ungroup(m[1]), budget: ungroup(m[2]) } : null;
}
/** The witness-comparable word of a rendered state cell, lowercased: `Auditing` -> `auditing`, legacy `running · crawling` -> `crawling`. */
export function phaseWord(words) {
  if (typeof words !== 'string' || words.trim() === '') return null;
  return (words.includes('·') ? words.split('·').pop() : words).trim().toLowerCase();
}
/** The lowercased word when it is a terminal JobState (`Done` -> `done`), else null. */
export function terminalWord(words) {
  const w = phaseWord(words);
  return w !== null && TERMINAL.has(w) ? w : null;
}
export const CANCEL_WORDS = /cancelling|cancelled/i;
export const CANCELLED_WORD = /^cancelled$/i;
/** The row's auditing text (helpers.ts `rowText`): `50 % · 3,236 of 6,468` with U+00A0 before `%`. */
export const ROW_PROGRESS_AUDITING = /^(\d+)\u00a0% · ([\d,]+) of ([\d,]+)$/;
/** The KPI Progress numeral (`percentText`): `50 %` with U+00A0. */
export const PERCENT_TEXT = /^(\d+)\u00a0%$/;
/** D4's cancelled sentence with its three numbers captured. */
export const CANCELLED_SENTENCE = /^Cancelled after (\d+:\d{2}(?::\d{2})?); ([\d,]+) of ([\d,]+) checks? had run\. What it found stays\.$/;
/** D9's check-error attention line. */
export const ATTENTION_ERRORS = /^([\d,]+) checks? could not run$/;
export const STOPPED_ERRORS_SENTENCE = 'Stopped early: too many errors from the target.';
export const RAW_ERRORS_LINE = 'stopped_reason: errors';

const GROUPED = new Intl.NumberFormat('en-US', { maximumFractionDigits: 0 });
/** `6,468` (helpers.ts `grouped`). */
export const grouped = (n) => GROUPED.format(Math.trunc(n));
/** `6,468` -> 6468. */
export const ungroup = (text) => Number(String(text).replace(/,/g, ''));
/** `m:ss` / `h:mm:ss` (helpers.ts `fmtElapsed`). */
export function fmtElapsed(ms) {
  const total = Number.isFinite(ms) && ms > 0 ? Math.floor(ms / 1000) : 0;
  const sec = total % 60;
  const min = Math.floor(total / 60) % 60;
  const h = Math.floor(total / 3600);
  const two = (n) => String(n).padStart(2, '0');
  return h > 0 ? `${h}:${two(min)}:${two(sec)}` : `${min}:${two(sec)}`;
}
/** `1:55` -> 115 seconds. */
export const elapsedSeconds = (text) => String(text).split(':').reduce((acc, part) => acc * 60 + Number(part), 0);

/**
 * The lines of a JSONL audit log that record `scan.cancel` for `job`: `command` is `scan.cancel`
 * and `args` (the bounded args summary, `aitm_ca::audit::entry_to_jsonl`) names the job. A line
 * that is not JSON is judged on its text.
 */
export function cancelLinesFor(text, job) {
  const hits = [];
  for (const line of String(text ?? '').split('\n')) {
    if (line.trim() === '') continue;
    let command = null;
    let args = null;
    try {
      const o = JSON.parse(line);
      command = typeof o.command === 'string' ? o.command : null;
      args = typeof o.args === 'string' ? o.args : j(o.args ?? null);
    } catch {
      command = line.includes('scan.cancel') ? 'scan.cancel' : null;
      args = line;
    }
    if (command === 'scan.cancel' && args.includes(job)) hits.push(line);
  }
  return hits;
}
/** The first `audit_log:` line under the top-level `mcp:` and `ca:` keys of a rendered config (null when a block has none). */
export function auditLogLines(configText) {
  let block = null;
  const found = { mcp: null, ca: null };
  for (const line of String(configText).split('\n')) {
    if (line.length && !line.startsWith(' ')) block = line.replace(/:\s*$/, '');
    else if ((block === 'mcp' || block === 'ca') && /^\s+audit_log:\s/.test(line) && found[block] === null) found[block] = line;
  }
  return found;
}
/** The path an `  audit_log: "<path>"` line names (JSON-quoted or bare); null when none. */
export function auditLogPath(line) {
  if (typeof line !== 'string') return null;
  const v = line.replace(/^\s*audit_log:\s*/, '').trim();
  if (v.startsWith('"')) {
    try {
      return JSON.parse(v);
    } catch {
      return null;
    }
  }
  return v === '' ? null : v;
}
/** Whether `path` lies inside `dir` (a path-segment prefix, so `/tmp/run2` is not inside `/tmp/run`). */
export const insideDir = (path, dir) => typeof path === 'string' && (path === dir || path.startsWith(dir.endsWith('/') ? dir : `${dir}/`));
/**
 * AC58 (c)'s "the only `errors` token inside the card": the count of the word `errors` in the card's
 * text once D4's sentence (`too many errors from the target`) and the crawl-trouble clause
 * (`hit 2 errors`) are set aside; exactly 1 means the data-face line is the only raw token.
 */
export function strayErrorsTokens(cardText) {
  const stripped = String(cardText).split(STOPPED_ERRORS_SENTENCE).join(' ').replace(/hit [\d,]+ errors?/g, ' ');
  return (stripped.match(/\berrors\b/g) ?? []).length;
}
/** Whether two `{ file: { size, sha256 } }` maps agree on every file. */
export const sameDigests = (a, b) => {
  const names = new Set([...Object.keys(a), ...Object.keys(b)]);
  return [...names].every((n) => a[n]?.size === b[n]?.size && a[n]?.sha256 === b[n]?.sha256);
};
/** A POSIX single-quoted word. */
export const shellQuote = (text) => `'${String(text).replace(/'/g, `'\\''`)}'`;

// --- Task 3.12 C ------------------------------------------------------------------------------
/** The operator URL with its bridge token hidden: `…/#t=<redacted>&expect=operator`. The only form the script prints. */
export const redactOperatorUrl = (url) => String(url).replace(/#t=[^&]*/, '#t=<redacted>');
/**
 * The ports of every `<key>: 127.0.0.1:<port>` line of a rendered config, unique and ascending: the
 * `listen` proxy and the `browser.proxy_addr` port (which `startAitm` does not return). Scope list
 * entries (`- "127.0.0.1:<port>"`) are not read: the dead host is one of them by design.
 */
export function listenPortsIn(configText) {
  const ports = new Set();
  for (const m of String(configText ?? '').matchAll(/^\s*[a-z_]+:\s*127\.0\.0\.1:(\d+)\s*$/gm)) ports.add(Number(m[1]));
  return [...ports].sort((a, b) => a - b);
}
/** The names in `named` whose port equals `port` (the dead port's clashes; empty when it is distinct). */
export function portClashes(port, named) {
  return Object.entries(named)
    .filter(([, p]) => p === port)
    .map(([name]) => name);
}
