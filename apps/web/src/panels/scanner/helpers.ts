// Pure helpers for the v2 Scan surface (D-T8.4): no Solid, no bus, no DOM — every function here is
// a total function of its arguments so the views, the live model and the launch path share one
// answer. The fixed operator texts of D-T8.6 (errors, pre-flight notes, the D11 L4 hint) and the
// Jobs view's end-state sentences (D4: `stopped_reason`, crawl trouble) live here too, so a text is
// written once and asserted once; the end-state words copy the mac Kit's `ScanEndText` byte for byte.
//
// Nothing here enforces anything: the core is the enforcement (`panels/l4/model.ts:141`). The scope
// predicates below only let the UI explain, ahead of the round trip, why a launch would be refused.

import type { L4ScopeEntryWire } from '~/panels/l4/model';
import { scopeCoversInterface } from '~/panels/l4/model';

import type {
  CheckCounters,
  CheckMeta,
  CheckSelection,
  Confidence,
  CrawlCounters,
  CrawlErrorKind,
  IssueStatus,
  IssueSummary,
  JobState,
  JobStatus,
  JobSummary,
  Lane,
  Phase,
  ScanErrorCode,
  ScanProfile,
  Severity,
  SiteNode,
  StoppedReason,
} from './model';
import { SEVERITY_ORDER } from './model';

/* ------------------------------------------------------------------ wire-keyed records */

/**
 * A record keyed by a wire string (a job id, a profile name, an issue id) must never answer from
 * `Object.prototype`: `drafts['constructor']` is a function, not a draft. Every keyed read of such a
 * record goes through here, and the record itself starts as `emptyRecord()` so a reactive read of
 * an absent key is tracked instead of landing on the prototype.
 */
export function own<T>(record: Record<string, T>, key: string): T | undefined {
  // The read comes first so a Solid store tracks the key even while it is absent.
  const value = record[key];
  return Object.hasOwn(record, key) ? value : undefined;
}

/** A record with no prototype at all, for `createStore` roots keyed by wire strings. */
export function emptyRecord<T>(): Record<string, T> {
  return Object.create(null) as Record<string, T>;
}

/* ------------------------------------------------------------------ job state */

const TERMINAL: readonly JobState[] = ['done', 'cancelled', 'failed'];

/** `done | cancelled | failed`: the job will never change again. */
export function isTerminal(state: JobState): boolean {
  return TERMINAL.includes(state);
}

/** `queued | running | cancelling`: the job is still moving, so it is polled (D-T8.3). */
export function isLive(state: JobState): boolean {
  return !isTerminal(state);
}

/**
 * Whether an incoming status is older than the one held (D-T8.3 "Monotonic"). A terminal reply is
 * always accepted — a finished job's elapsed time can legitimately be lower than a late running
 * read's. Counters therefore never step backwards in the UI (W-5).
 */
export function isStale(held: JobStatus, incoming: JobStatus): boolean {
  return incoming.elapsed_ms < held.elapsed_ms && !isTerminal(incoming.state);
}

/** `0:42`, `12:03`, `1:02:03` — elapsed wall time, never a date. */
export function fmtElapsed(ms: number): string {
  const total = Number.isFinite(ms) && ms > 0 ? Math.floor(ms / 1000) : 0;
  const s = total % 60;
  const m = Math.floor(total / 60) % 60;
  const h = Math.floor(total / 3600);
  const two = (n: number) => String(n).padStart(2, '0');
  return h > 0 ? `${h}:${two(m)}:${two(s)}` : `${m}:${two(s)}`;
}

/** The state-token tone for a job state (D-T8.7): cancelled is neutral, only `failed` is danger. */
export function jobTone(state: JobState): 'neutral' | 'success' | 'danger' {
  if (state === 'done') return 'success';
  if (state === 'failed') return 'danger';
  return 'neutral';
}

/**
 * The re-read rule (Jobs view D2): a listed job owes a `scan.status` read while nothing is stored
 * for it, or when the list calls it terminal while the stored status is still live (the one-beat
 * gap in which a finished job would otherwise keep its last running read for ever).
 */
export function needsStatusRead(summary: Pick<JobSummary, 'state'>, stored: JobStatus | null): boolean {
  return stored === null || (isTerminal(summary.state) && !isTerminal(stored.state));
}

/** The shared counters of a status, in the list row's shape. */
function summaryOf(s: JobStatus): JobSummary {
  return {
    job: s.job,
    state: s.state,
    phase: s.phase,
    elapsed_ms: s.elapsed_ms,
    probes: s.probes,
    points: s.points,
    issues: s.issues,
  };
}

/**
 * One truth per job (Jobs view D2): the shared counters come from, in order, a terminal status
 * (final, every field present); else a terminal list row (the list turned terminal while the
 * stored status is still live); else whichever of the two has the higher `elapsed_ms`, the status
 * on a tie. The detail-only fields stay on the status the caller holds.
 */
export function mergeJob(summary: JobSummary, status: JobStatus | null): JobSummary {
  if (status === null) return summary;
  if (isTerminal(status.state)) return summaryOf(status);
  if (isTerminal(summary.state)) return summary;
  return status.elapsed_ms >= summary.elapsed_ms ? summaryOf(status) : summary;
}

const GROUPED = new Intl.NumberFormat('en-US', { maximumFractionDigits: 0 });

/** `6,468`: a count with the en-US thousands comma whatever the browser locale (D4, D11). */
export function grouped(n: number): string {
  return GROUPED.format(Number.isFinite(n) ? Math.trunc(n) : 0);
}

/** `1 check` / `6,468 checks`: the one singular rule of the end-state sentences. */
function plural(n: number, noun: string): string {
  return `${grouped(n)} ${noun}${n === 1 ? '' : 's'}`;
}

const STATE_WORDS: Record<JobState, string> = {
  queued: 'Queued',
  running: 'Running',
  cancelling: 'Cancelling',
  done: 'Done',
  cancelled: 'Cancelled',
  failed: 'Failed',
};

const PHASE_WORDS: Record<Phase, string> = {
  queued: 'Queued',
  crawling: 'Crawling',
  passive: 'Passive',
  auditing: 'Auditing',
  reporting: 'Reporting',
  done: 'Done',
};

/** The glossary word: the phase while running (`Auditing`), else the state (`Done`, `Cancelling`). */
export function stateWords(s: Pick<JobSummary, 'state' | 'phase'>): string {
  return s.state === 'running' ? PHASE_WORDS[s.phase] : STATE_WORDS[s.state];
}

/* ------------------------------------------------------------------ fixed texts */

/**
 * The stopped-reason sentence of the Jobs view (D4); `null` for a reason the state sentence already
 * says (`cancelled` on a cancelled job) or the error text already shows (`failed` with an error).
 * The decoder maps a token it does not know to `null`, so the last arm is reached only if one gets
 * past it; it still says something rather than printing the raw token (glossary rule).
 */
export function stoppedReasonText(
  reason: StoppedReason,
  state: JobState,
  probesBudget: number,
  error: string | null,
): string | null {
  switch (reason) {
    case 'budget':
      return `Stopped early: the probe budget of ${grouped(probesBudget)} was spent. Raise it in the profile to go further.`;
    case 'time':
      return 'Stopped early: the time budget ran out.';
    case 'cancelled':
      return state === 'cancelled' ? null : 'Stopped early: the job was cancelled.';
    case 'session_lost':
      return 'Stopped early: the session was lost and the profile says stop when that happens.';
    case 'errors':
      return 'Stopped early: too many errors from the target.';
    case 'policy':
      return 'Stopped early: the agent policy changed to paused or read-only.';
    case 'guard_refused':
      return 'Stopped early: the L4 guard refused a target mid-run.';
    case 'failed':
      return error !== null && error !== '' ? null : 'Stopped early: an error ended the job.';
    default:
      return 'Stopped early for a reason this app does not know.';
  }
}

/** `stopped_reason: errors`: the raw token, for the data-face line only. */
export function rawReasonLine(reason: StoppedReason): string {
  return `stopped_reason: ${reason}`;
}

/**
 * The one sentence for a terminal job (D4); `null` while the job is live. `checks` are the stored
 * status's counters and are `null` until a terminal status has landed: during the one-beat gap in
 * which the list says terminal and the stored status is still live, a live read's numbers must not
 * be quoted, so the caller passes `null` and the sentence waits for the final ones.
 */
export function endSentence(j: JobSummary | JobStatus, checks: CheckCounters | null): string | null {
  if (checks === null || !isTerminal(j.state)) return null;
  const elapsed = fmtElapsed(j.elapsed_ms);
  switch (j.state) {
    case 'done':
      return `Done in ${elapsed} · ${plural(j.points.found, 'point')} · ${plural(checks.scheduled, 'check')}.`;
    case 'cancelled':
      return `Cancelled after ${elapsed}; ${grouped(checks.done)} of ${plural(checks.scheduled, 'check')} had run. What it found stays.`;
    case 'failed':
      return `Failed after ${elapsed}.`;
    default:
      return null;
  }
}

/** `The crawl fetched 1 page and hit 1 error`; `null` when the crawl hit none (D4). */
export function crawlTroubleText(crawl: CrawlCounters): string | null {
  if (crawl.errors <= 0) return null;
  return `The crawl fetched ${plural(crawl.pages, 'page')} and hit ${plural(crawl.errors, 'error')}`;
}

/** The words for a `crawl.last_error` token; `transport`, `other` and an unknown token all read as a failed connection. */
export function crawlErrorWords(kind: CrawlErrorKind | string): string {
  switch (kind) {
    case 'connect_refused':
      return 'the target refused the connection';
    case 'tls':
      return 'TLS handshake failed';
    case 'timeout':
      return 'the target did not answer in time';
    case 'h2_not_negotiated':
      return 'the target does not speak HTTP/2';
    default:
      return 'the connection failed';
  }
}

/** `crawl.last_error: connect_refused`: the raw token, for the data-face line only. */
export function rawCrawlErrorLine(kind: CrawlErrorKind | string): string {
  return `crawl.last_error: ${kind}`;
}

/** Why active scanning is off for an agent session; the core enforces it, the panel explains it. */
export const AGENT_NOTE =
  'Agent session: the core refuses active scans unless scanner.allow_agent_active is set; intrusive is operator-only';

/** The D11 sentence, printed verbatim under the L4 target list and in the pre-flight reason. */
export const L4_HINT =
  'The L4 stream lane needs an L4 scope entry with interface: "*", direction: outbound, the target CIDR and port range, and the Inject capability.';

/** Printed under the launch buttons when the draft will trigger the `_confirm` handshake. */
export const CONFIRM_NOTE = 'The core will ask for confirmation.';

/* ------------------------------------------------------------------ profile names */

/**
 * The engine's rule for a saved profile name: `^[a-z0-9][a-z0-9._-]{0,63}$`, lowercase only. Anything
 * else is refused with `invalid_profile`, so the editor dims `Save` ahead of the round trip. A
 * built-in name is refused too, but that is a list lookup the editor does itself.
 */
const PROFILE_NAME = /^[a-z0-9][a-z0-9._-]{0,63}$/;

export function isValidProfileName(name: string): boolean {
  return PROFILE_NAME.test(name);
}

/** The one sentence shown under the name field while the typed name fails the rule. */
export const PROFILE_NAME_HINT =
  'lowercase letters, digits, . _ - ; 1-64 characters, starting with a letter or digit';

/**
 * Every `scan:` error code as the editor's result block and the toast print it (D-T8.6, W-3). An
 * unknown code (`null`) prints the core's message verbatim — the UI never invents a reason.
 */
export function scanErrorText(code: ScanErrorCode | null, detail: string): string {
  switch (code) {
    case 'out_of_scope':
      return `Out of scope: ${detail}`;
    case 'refused_agent':
      return `${AGENT_NOTE}: ${detail}`;
    case 'refused_l4':
      return `L4 refused: ${detail} (l4.enabled, scanner.allow_agent_l4_fuzz, l4.allow_agent_inject)`;
    case 'lane_unavailable':
      return `No requested lane is available on this build: ${detail}`;
    case 'busy':
      return `Busy: ${detail} (max_jobs or an origin already being scanned)`;
    case 'invalid_profile':
      return `Invalid profile: ${detail}`;
    case 'unknown_check':
      return `Unknown check: ${detail}`;
    case 'confirm_required':
      return 'Confirmation required';
    case 'not_found':
      return `Not found: ${detail}`;
    case null:
      return detail;
  }
}

/* ------------------------------------------------------------------ issues: grouping, filtering */

/** Rows under severity headers, worst first; a severity with no rows gets no header (D-T8.9). */
export function groupBySeverity<T extends { severity: Severity }>(
  rows: readonly T[],
): { severity: Severity; rows: T[] }[] {
  const out: { severity: Severity; rows: T[] }[] = [];
  for (const severity of SEVERITY_ORDER) {
    const group = rows.filter((r) => r.severity === severity);
    if (group.length > 0) out.push({ severity, rows: group });
  }
  return out;
}

/** The Issues view's client-side filter; an empty set means "every value" (D-T8.9). */
export interface IssueFilter {
  confidence: ReadonlySet<Confidence>;
  lanes: ReadonlySet<Lane>;
  classes: ReadonlySet<string>;
  statuses: ReadonlySet<IssueStatus>;
  text: string;
}

export const EMPTY_FILTER: IssueFilter = {
  confidence: new Set<Confidence>(),
  lanes: new Set<Lane>(),
  classes: new Set<string>(),
  statuses: new Set<IssueStatus>(),
  text: '',
};

/** Filters the loaded pages in place of a refetch: instant, and the server's counts stay the truth. */
export function filterIssues(rows: readonly IssueSummary[], f: IssueFilter): IssueSummary[] {
  const needle = f.text.trim().toLowerCase();
  return rows.filter((r) => {
    if (f.confidence.size > 0 && !f.confidence.has(r.confidence)) return false;
    if (f.lanes.size > 0 && !f.lanes.has(r.lane)) return false;
    if (f.classes.size > 0 && !f.classes.has(r.class)) return false;
    if (f.statuses.size > 0 && !f.statuses.has(r.status)) return false;
    if (needle === '') return true;
    const hay = `${r.name}\n${r.location.path_template}\n${r.location.name}`.toLowerCase();
    return hay.includes(needle);
  });
}

/* ------------------------------------------------------------------ hosts and scope */

const DEFAULT_PORTS: Record<string, number> = { http: 80, https: 443, ws: 80, wss: 443 };

/** `host` when the port is the scheme default, else `host:port` — the site map's grouping key. */
export function hostKey(n: Pick<SiteNode, 'scheme' | 'host' | 'port'>): string {
  return DEFAULT_PORTS[n.scheme.toLowerCase()] === n.port ? n.host : `${n.host}:${n.port}`;
}

/** Site-map nodes grouped by `host[:port]`, hosts in first-seen order (D-T8.8). */
export function nodesByHost(nodes: readonly SiteNode[]): { host: string; nodes: SiteNode[] }[] {
  const out: { host: string; nodes: SiteNode[] }[] = [];
  const index = new Map<string, { host: string; nodes: SiteNode[] }>();
  for (const node of nodes) {
    const host = hostKey(node);
    let group = index.get(host);
    if (!group) {
      group = { host, nodes: [] };
      index.set(host, group);
      out.push(group);
    }
    group.nodes.push(node);
  }
  return out;
}

/** The host and the *explicit* port of an origin; `null` when it is not a URL at all. */
export function originHost(origin: string): { host: string; port: number | null } | null {
  let url: URL;
  try {
    url = new URL(origin);
  } catch {
    return null;
  }
  if (url.hostname === '') return null;
  return { host: url.hostname.toLowerCase(), port: url.port === '' ? null : Number(url.port) };
}

/**
 * Whether an origin is covered by a scope entry: an exact host, an exact `host:port`, or a
 * `*.suffix` wildcard (the v1 LaunchForm rule). An origin that is not a URL is never in scope.
 */
export function hostInScope(origin: string, scope: readonly { host: string }[]): boolean {
  const parsed = originHost(origin);
  if (!parsed) return false;
  const { host, port } = parsed;
  return scope.some((e) => {
    const entry = e.host.toLowerCase();
    if (entry === host) return true;
    if (port !== null && entry === `${host}:${port}`) return true;
    if (entry.startsWith('*.')) {
      const suffix = entry.slice(2);
      return suffix !== '' && (host === suffix || host.endsWith(`.${suffix}`));
    }
    return false;
  });
}

/* ------------------------------------------------------------------ L4 scope coverage */

function parseIpv4(ip: string): number | null {
  const parts = ip.split('.');
  if (parts.length !== 4) return null;
  let n = 0;
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) return null;
    const octet = Number(part);
    if (octet > 255) return null;
    n = (n * 256 + octet) >>> 0;
  }
  return n;
}

function parseCidr(cidr: string): { base: number; mask: number } | null {
  const slash = cidr.indexOf('/');
  if (slash < 0) return null;
  const base = parseIpv4(cidr.slice(0, slash));
  const lenText = cidr.slice(slash + 1);
  if (base === null || !/^\d{1,2}$/.test(lenText)) return null;
  const len = Number(lenText);
  if (len > 32) return null;
  const mask = len === 0 ? 0 : (0xffffffff << (32 - len)) >>> 0;
  return { base, mask };
}

function parsePorts(ports: string): { lo: number; hi: number } | null {
  const text = ports.trim();
  const range = /^(\d{1,5})-(\d{1,5})$/.exec(text);
  if (range) {
    const lo = Number(range[1]);
    const hi = Number(range[2]);
    return lo <= hi && hi <= 65535 ? { lo, hi } : null;
  }
  if (!/^\d{1,5}$/.test(text)) return null;
  const only = Number(text);
  return only <= 65535 ? { lo: only, hi: only } : null;
}

/**
 * Whether one L4 scope entry authorises injecting at `ip:port` (W-9): IPv4 CIDR, port range,
 * `capability: inject`, `direction: outbound`, and an interface the wildcard target matches
 * (D9.5). `null` means *unknown* — an IPv6 address or an entry this UI cannot parse — and an
 * unknown never disables a control; only the core refuses.
 */
export function l4EntryCovers(
  entry: L4ScopeEntryWire,
  ip: string,
  port: number,
): boolean | null {
  const addr = parseIpv4(ip);
  if (addr === null) return null;
  const net = parseCidr(entry.cidr);
  if (net === null) return null;
  const range = parsePorts(entry.ports);
  if (range === null) return null;
  if (entry.capability !== 'inject') return false;
  if (entry.direction !== 'outbound') return false;
  if (!scopeCoversInterface(entry, '*')) return false;
  const inNet = ((addr & net.mask) >>> 0) === ((net.base & net.mask) >>> 0);
  return inNet && port >= range.lo && port <= range.hi;
}

/** Any entry covering wins; all-false is false; otherwise unknown (`null`), which never disables. */
export function l4Covered(
  entries: readonly L4ScopeEntryWire[],
  ip: string,
  port: number,
): boolean | null {
  let unknown = false;
  for (const entry of entries) {
    const covered = l4EntryCovers(entry, ip, port);
    if (covered === true) return true;
    if (covered === null) unknown = true;
  }
  return unknown ? null : false;
}

/* ------------------------------------------------------------------ profile predicates */

/** Whether the draft runs a packet or stream L4 lane (both are `Sensitive` and confirm-gated). */
export function profileHasL4(p: ScanProfile): boolean {
  return p.lanes.includes('l4_packet') || p.lanes.includes('l4_stream');
}

/** When to print `CONFIRM_NOTE`: an L4 lane or `intensity: intrusive` (D-T8.6). */
export function needsConfirmNote(p: ScanProfile): boolean {
  return profileHasL4(p) || p.intensity === 'intrusive';
}

/* ------------------------------------------------------------------ check selection algebra */

/** What a check-tree row toggles: one check, a class row, or a lane row (`<lane>:*`). */
export type CheckTarget = { id: string } | { class: string } | { lane: Lane };

function selectorOf(target: CheckTarget): string {
  if ('id' in target) return target.id;
  if ('class' in target) return target.class;
  return `${target.lane}:*`;
}

function selectorMatches(selector: string, meta: Pick<CheckMeta, 'id' | 'class' | 'lanes'>): boolean {
  if (selector === meta.id || selector === meta.class) return true;
  if (selector.endsWith(':*')) {
    const lane = selector.slice(0, -2);
    return (meta.lanes as readonly string[]).includes(lane);
  }
  return false;
}

function coveredIds(selector: string, checks: readonly CheckMeta[]): string[] {
  return checks.filter((c) => selectorMatches(selector, c)).map((c) => c.id);
}

/**
 * Writes one tree toggle into `include`/`exclude` using the `id | class | lane:*` grammar.
 *
 * The tree edits `include` while it is non-empty (the operator has opted into a subset), otherwise
 * it edits `exclude` (Architect's call, D-T8.5). A class or lane selector *replaces* the single ids
 * it covers; turning one id back on under a broader selector rewrites that selector as the other
 * ids it covered, so the grammar stays a faithful description of what is on. A selector matching no
 * known check is never dropped — `unknownSelectors` surfaces it instead.
 */
export function applyCheckToggle(
  sel: CheckSelection,
  target: CheckTarget,
  on: boolean,
  checks: readonly CheckMeta[],
): CheckSelection {
  const editingInclude = sel.include.length > 0;
  const list = editingInclude ? sel.include : sel.exclude;
  const selector = selectorOf(target);
  // In `include`, present means on; in `exclude`, present means off.
  const wantPresent = editingInclude ? on : !on;
  const ids = new Set(coveredIds(selector, checks));
  const next: string[] = [];

  if (wantPresent) {
    for (const s of list) {
      const sIds = coveredIds(s, checks);
      const subsumed = sIds.length > 0 && sIds.every((id) => ids.has(id));
      if (!subsumed && !next.includes(s)) next.push(s);
    }
    if (!next.includes(selector)) next.push(selector);
  } else {
    for (const s of list) {
      if (s === selector) continue;
      const sIds = coveredIds(s, checks);
      if (sIds.length > 0 && sIds.every((id) => ids.has(id))) continue;
      if (sIds.some((id) => ids.has(id))) {
        for (const id of sIds) if (!ids.has(id) && !next.includes(id)) next.push(id);
        continue;
      }
      if (!next.includes(s)) next.push(s);
    }
  }

  return editingInclude
    ? { include: next, exclude: [...sel.exclude] }
    : { include: [...sel.include], exclude: next };
}

/** A check runs when `include` is empty or matches it, and no `exclude` selector matches it. */
export function checkIsOn(
  sel: CheckSelection,
  meta: Pick<CheckMeta, 'id' | 'class' | 'lanes'>,
): boolean {
  const included =
    sel.include.length === 0 || sel.include.some((s) => selectorMatches(s, meta));
  return included && !sel.exclude.some((s) => selectorMatches(s, meta));
}

/** The selectors in a selection that match no known check (the tree highlights them; D-T8.6). */
export function unknownSelectors(sel: CheckSelection, checks: readonly CheckMeta[]): string[] {
  const out: string[] = [];
  for (const s of [...sel.include, ...sel.exclude]) {
    if (out.includes(s)) continue;
    if (!checks.some((c) => selectorMatches(s, c))) out.push(s);
  }
  return out;
}
