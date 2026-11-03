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
  BySeverity,
  Canary,
  CheckCounters,
  CheckErrorSample,
  CheckMeta,
  CheckSelection,
  Clamped,
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
  SkippedLane,
  SkippedPoints,
  StartedBy,
  StoppedReason,
} from './model';
import { boundedStr, LANES, SEVERITY_ORDER, STAMP_MAX } from './model';

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
  return s.state === 'running' ? phaseWord(s.phase) : stateWord(s.state);
}

/** The phase's glossary word; a token this build does not know reads as it came (the Kit's `.other`). */
function phaseWord(phase: Phase): string {
  return PHASE_WORDS[phase] ?? String(phase);
}

/** The state's glossary word; a token this build does not know reads as it came. */
function stateWord(state: JobState): string {
  return STATE_WORDS[state] ?? String(state);
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

/**
 * The attention block's crawl line: `crawlTroubleText`, joined by an em dash with the last error's
 * words when the engine set `crawl.last_error` (`The crawl fetched 0 pages and hit 1 error — the
 * target refused the connection`); `null` when the crawl hit no errors (the Kit's `crawlTroubleLine`).
 */
export function crawlTroubleLine(crawl: CrawlCounters): string | null {
  const trouble = crawlTroubleText(crawl);
  if (trouble === null) return null;
  return crawl.last_error === null ? trouble : `${trouble} — ${crawlErrorWords(crawl.last_error)}`;
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

/* ------------------------------------------------------------------ Jobs view W2: the Kit's words (D18 W2, D21) */

// Every type and function from here to the agent note copies its counterpart in the mac Kit
// (`apps/mac/Sources/AitmproxyKit/Panels/ScanSurface.swift`: `ScanJobFacts`, `ScanJobProgress`,
// `ScanEndText`, `ScanFormat`, `ScanJobsLink`) rule for rule and word for word; the parity pin
// P15–P23 and plan Task 3.5's table hold the literals. Nothing here is re-derived: the web and the
// TUI render one set of forms.

/** The web's `ScanJobFacts`: the shared counters merged by `mergeJob`, and the status as held (`null` until it lands). */
export interface JobFacts {
  summary: JobSummary;
  status: JobStatus | null;
}

/** `JobFacts` from a list row and the stored status: the summary is `mergeJob(summary, status)`. */
export function jobFacts(summary: JobSummary, status: JobStatus | null): JobFacts {
  return { summary: mergeJob(summary, status), status };
}

/** The card's tone (`ScanJobTone`): the app maps it to a token pair once. */
export type Tone = 'progress' | 'pending' | 'success' | 'danger' | 'neutral';

/** A finding-line part's role (`ScanFindingLine.Role`): the view inks `figure`, `checkId` and `agent` differently. */
export type PartRole = 'plain' | 'figure' | 'checkId' | 'agent';

/** One piece of the finding line or the now tag (`ScanFindingLine.Part`); joined, the parts are the text. */
export interface Part {
  text: string;
  role: PartRole;
}

/** `ScanJobProgress.Ring`: nothing to draw, unmeasurable, the fraction, or a terminal job's final fraction. */
export type Ring = 'none' | 'indeterminate' | { determinate: number } | { finished: number | null };

/** `ScanPace`: the pace a running audit keeps, from two bus counters over the elapsed time. */
export interface Pace {
  /** `ceil((scheduled - done) / checksPerSecond)`. */
  secondsToGo: number;
  /** `done / (elapsedMs / 1000)`. */
  checksPerSecond: number;
}

/**
 * `ScanJobProgress`: what the row's ring, the card's lane and the KPI strip show, from the merged
 * facts by one total rule (D8).
 */
export interface JobProgress {
  ring: Ring;
  /** The determinate value, 0…1; `null` otherwise (a finished ring included). */
  fraction: number | null;
  /** `50 %` (U+00A0 before the sign), floored; `null` when `fraction` is. */
  percentText: string | null;
  /** The card's progress line; `''` for a terminal job (the card shows the end sentence, D9). */
  phaseLine: string;
  /** `Now: xss-reflected and 3 more`; `null` when nothing runs. The parity spelling (P22). */
  nowLine: string | null;
  /** `3,236 of 6,468 checks (derived from the engine's counters)` or `Progress is not known yet`. */
  helpText: string;
  /** `3,232 checks to go` while running in auditing or reporting with something left; `null` otherwise. */
  checksToGoText: string | null;
  /** `now · xss-reflected and 3 more`: the lane's spelling, `nowTagParts` joined; `null` with it. */
  nowTag: string | null;
  /** `now · ` (plain), the first running id (`checkId`), ` and 3 more` (plain); `null` when nothing runs (D21). */
  nowTagParts: Part[] | null;
  /** `at this pace, about 1:04 to go`; only while running in auditing with a derivable pace. */
  estimateText: string | null;
  /** `Derived from the counters: 3,236 checks done in 1:04, about 51 checks per second, 3,232 to go.` */
  estimateHelp: string | null;
  /** The table's Progress cell (D10, D21): `—`, `50 % · 3,236 of 6,468`, the crawl line, a phase word, `3,236 of 6,468`. */
  rowText: string;
}

/** `ScanFindingLine`: the line under the card's heading, in parts, with a terminal job's reason above it. */
export interface FindingLine {
  reason: string | null;
  parts: Part[];
  text: string;
  agentOriginated: boolean;
}

/** `ScanLedgerGroup`: one group of the issue ledger, its marks capped at `LEDGER_MARK_CAP`. */
export interface LedgerGroup {
  severity: Severity;
  count: number;
  marks: number;
  /** `4 low`. */
  word: string;
}

/** One severity word with its ink (`severityWordParts`). */
export interface SeverityPart {
  severity: Severity;
  word: string;
}

/** `ScanPointSkipWords`: one skipped-points row of the Crawl well. */
export interface PointSkipWords {
  count: number;
  words: string;
  /** `722 skipped as repetitive`. */
  text: string;
}

/** `ScanWellCell.Ink`: the data ink, the tertiary ink for a zero severity count, or a severity's ink. */
export type WellInk = 'value' | 'muted' | { severity: Severity };

export interface WellCell {
  text: string;
  ink: WellInk;
}

/** `ScanWellRow`: a key and one cell per value; `text` is the cells joined by `WELL_CELL_SEPARATOR`. */
export interface WellRow {
  key: string;
  cells: WellCell[];
  text: string;
}

/** `ScanWellRows`: the two wells' rows, in the wells' order. */
export interface WellRows {
  crawl: WellRow[];
  issues: WellRow[];
}

/** `ScanAttentionLine`: a count sentence and the samples behind its disclosure. */
export interface AttentionLine {
  text: string;
  samples: CheckErrorSample[];
}

/* ---- fixed words (ScanFormat; D10, D11, D17) */

/** The table's header labels, sentence case, in column order. */
export const TABLE_HEADERS: readonly string[] = [
  'State',
  'Profile',
  'Target',
  'Progress',
  'Probes',
  'Points',
  'Issues',
  'Elapsed',
];
/** The KPI strip's labels, in cell order. */
export const KPI_LABELS: readonly string[] = ['Progress', 'Checks', 'Probes', 'Points audited', 'Issues'];
export const GAUGE_LABEL = 'probe budget';
export const LANE_CRAWL_LABEL = 'crawl';
export const LANE_AUDIT_LABEL = 'audit';
/** What a cell shows for a value the bus has not said. */
export const MISSING_VALUE = '—';
export const AGENT_DOT_HELP = 'started by an agent';
export const WELL_CRAWL_TITLE = 'Crawl and points';
export const WELL_CRAWL_SUBTITLE = 'what the job found to test';
export const WELL_ISSUES_TITLE = 'Issues';
export const WELL_ISSUES_SUBTITLE = 'by severity and confidence';
/** The most marks one ledger group draws; the word carries the true count. */
export const LEDGER_MARK_CAP = 12;
/** The one allowed `Stop` in a Jobs string (AC32): the card's Cancel Scan and the row's hover Cancel read it. */
export const CANCEL_SCAN_HELP = 'Stop this job; the issues and site map it found stay (⌥⌘.)';
export const SCAN_AGAIN_HELP_GENERIC = "Start a new job with this job's profile and target";
export const SHOW_ISSUES_HELP = 'Open the Issues tab filtered to this job';
export const SHOW_SITE_MAP_HELP = 'Open the Site map tab for this job';
/** D13's refusal line under the card's title row: this prefix, then the refusal's text. */
export const SCAN_AGAIN_ERROR_PREFIX = 'Unable to scan again: ';
/** The primary verb's title while the merged state is cancelling: disabled, not a verb. */
export const CANCELLING_TITLE = 'Cancelling…';
/** The Jobs tab's empty state (the Kit's `scanNoJobsText`). */
export const NO_JOBS_TEXT = 'No jobs yet — pick a profile and Start Scan.';
/** Between a well row's cells: `0 · 1 · 0`. */
export const WELL_CELL_SEPARATOR = ' · ';
/** Between the severity words: `1 high, 3 low`. */
const SEVERITY_WORD_SEPARATOR = ', ';
/** The most characters of a `started_by.client_label` the finding line shows. */
const STARTED_BY_LABEL_MAX = 40;

/** The keys of the card's two wells (`ScanFormat.WellKey`), one constant each. */
export const WELL_KEY = {
  pagesFetched: 'Pages fetched',
  pagesWaiting: 'Pages waiting',
  depth: 'Depth',
  formsSubmitted: 'Forms submitted',
  formsNotSubmitted: 'Forms not submitted',
  crawlErrors: 'Crawl errors',
  pointsFound: 'Points found',
  waitingForAudit: 'Waiting for audit',
  audited: 'Audited',
  lanes: 'Lanes',
  laneSkipped: 'Lane skipped',
  probesByLane: 'Probes by lane',
  session: 'Session',
  l4Cases: 'L4 cases',
  l4Crashes: 'L4 crashes',
  l4LivenessFailures: 'L4 liveness failures',
  l4RetiredElements: 'L4 retired elements',
  criticalHighMedium: 'Critical · High · Medium',
  low: 'Low',
  info: 'Info',
  certainFirmTentative: 'Certain · Firm · Tentative',
  probeErrors: 'Probe errors · timeouts · rate waits',
  checks: 'Checks scheduled · done · errors · skipped',
} as const;

/** Every well key, in the wells' order (`WellKey.all`, 23 of them). */
export const WELL_KEYS: readonly string[] = Object.values(WELL_KEY);

const WAITING_LINE = 'Waiting for the engine to start this job.';
const PASSIVE_LINE = 'Passive checks over captured traffic';
/** The Progress cell's passive form: the row has no room for the card's line. */
const PASSIVE_ROW_LINE = 'Passive checks';
const SCHEDULING_LINE = 'Scheduling checks';
const REPORTING_LINE = 'Writing results';
const UNKNOWN_HELP = 'Progress is not known yet';
const DERIVED_SUFFIX = " (derived from the engine's counters)";

/* ---- small words */

/** `1 hour` / `2 hours`: the singular rule without grouping (`elapsedWords`). */
function pluralPlain(n: number, noun: string): string {
  return `${n} ${noun}${n === 1 ? '' : 's'}`;
}

const LANE_WORDS: Record<Lane, string> = {
  http: 'HTTP',
  ws: 'WebSocket',
  l4_packet: 'L4 packet',
  l4_stream: 'L4 stream',
};

/** `HTTP` / `WebSocket` / `L4 packet` / `L4 stream`; a lane this build does not know reads as it came. */
function laneWord(lane: Lane): string {
  return LANE_WORDS[lane] ?? String(lane);
}

/** HTTP 0, WebSocket 1, L4 packet 2, L4 stream 3, anything newer 4 (`ScanLane.displayOrder`). */
function laneDisplayOrder(lane: Lane): number {
  const index = (LANES as readonly string[]).indexOf(lane);
  return index === -1 ? LANES.length : index;
}

/** `yes` / `no`, for the session flags. */
export function yesNo(value: boolean): string {
  return value ? 'yes' : 'no';
}

/** `ok` when a canary flow guards the session, `off` when there is none: the Session row's third cell. */
export function canaryWord(canary: Canary): string {
  return canary.kind === 'flow' ? 'ok' : 'off';
}

/** `Clamped budget.probes 50000 → 20000`: a `scan.start` / `scan.status` clamp notice (the raw numbers, as the Kit). */
export function clampedText(c: Clamped): string {
  return `Clamped ${c.field} ${c.requested} → ${c.applied}`;
}

/** `Skipped ws: lane not available on this build`: a `lanes.skipped` notice. */
export function skippedLaneText(s: SkippedLane): string {
  return `Skipped ${s.lane}: ${s.reason}`;
}

/** `WebSocket: lane not available on this build`: the Crawl well's `Lane skipped` row. */
export function skippedLaneWords(s: SkippedLane): string {
  return `${laneWord(s.lane)}: ${s.reason}`;
}

/** The sum of the five tallies (the Kit's `BySeverity.total`). */
function totalOf(by: BySeverity): number {
  return by.critical + by.high + by.medium + by.low + by.info;
}

/** The non-zero tallies, critical → info. */
function severityCounts(by: BySeverity): [Severity, number][] {
  const out: [Severity, number][] = [];
  for (const severity of SEVERITY_ORDER) {
    const count = by[severity];
    if (count > 0) out.push([severity, count]);
  }
  return out;
}

/* ---- hosts and the profile (ScanFormat.hostOf / hostList / profileName) */

/**
 * `host[:port]` of an origin, lower-cased, the userinfo dropped; the origin itself when it is not
 * an http(s) URL (the Kit's `hostOf`, over `ScanForm.authority`).
 */
function hostOf(origin: string): string {
  const sep = origin.indexOf('://');
  if (sep === -1) return origin;
  const scheme = origin.slice(0, sep).toLowerCase();
  if (scheme !== 'http' && scheme !== 'https') return origin;
  const rest = origin.slice(sep + 3);
  const end = rest.search(/[/\\?#]/);
  const component = end === -1 ? rest : rest.slice(0, end);
  const at = component.lastIndexOf('@');
  const host = at === -1 ? component : component.slice(at + 1);
  return host === '' ? origin : host.toLowerCase();
}

/** The hosts of the status's targets; empty until a status lands. */
function hostList(f: JobFacts): string[] {
  return f.status === null ? [] : f.status.targets.map(hostOf);
}

/** `host[:port]` of every origin, joined with `, `; `null` when there are none. */
function hostsJoined(origins: readonly string[]): string | null {
  return origins.length === 0 ? null : origins.map(hostOf).join(', ');
}

/** The status's profile name; `null` when there is no status or it carries none. */
function profileName(f: JobFacts): string | null {
  const name = f.status?.profile_name ?? '';
  return name === '' ? null : name;
}

/** `standard`; `—` until the status lands or when it carries no name. */
export function profileText(f: JobFacts): string {
  return profileName(f) ?? MISSING_VALUE;
}

/** `127.0.0.1:8117` / `a.test, b.test:8080`; `—` until the status lands. */
export function hostsText(f: JobFacts): string {
  return hostsJoined(f.status?.targets ?? []) ?? MISSING_VALUE;
}

/** The card's heading: the hosts, `a.test and 2 more` from three on; `—` until known. */
export function jobHeading(f: JobFacts): string {
  const hosts = hostList(f);
  const first = hosts[0];
  if (first === undefined) return MISSING_VALUE;
  return hosts.length >= 3 ? `${first} and ${hosts.length - 1} more` : hosts.join(', ');
}

/** The full host list for the heading's help when three or more are cut; `null` otherwise. */
export function jobHeadingHelp(f: JobFacts): string | null {
  const hosts = hostList(f);
  return hosts.length >= 3 ? hosts.join(', ') : null;
}

/* ---- the derived progress model (ScanJobProgress; D8 and its amendment) */

/**
 * `done / total` when `total > 0`, clamped at 1 so a core reporting `done` past `scheduled` never
 * overshoots the ring, the lane or `percentText`; `null` otherwise.
 */
function fractionOf(done: number, total: number): number | null {
  if (!(total > 0)) return null;
  return Math.min(1, done / total);
}

/** `50 %` (U+00A0 before the sign), floored: the one spelling `percentText` and the auditing `rowText` share. */
function percent(fraction: number): string {
  return `${Math.floor(fraction * 100)} %`;
}

/** `3,236 of 6,468 checks`. */
function checksLine(checks: CheckCounters): string {
  return `${grouped(checks.done)} of ${plural(checks.scheduled, 'check')}`;
}

/** `3,236 of 6,468`: the row's form, no unit. */
function checksOfText(checks: CheckCounters): string {
  return `${grouped(checks.done)} of ${grouped(checks.scheduled)}`;
}

/** `xss-reflected` / `xss-reflected and 3 more`. */
function nowIds(running: readonly string[], first: string): string {
  return running.length > 1 ? `${first} and ${running.length - 1} more` : first;
}

/**
 * `checks.done` over the elapsed time (D8 amendment); `null` when no rate can be derived:
 * `elapsedMs <= 0`, `done <= 0`, `scheduled <= 0`, `done >= scheduled`, or when the seconds to go
 * would not fit under the decoder's 2^53 ms ceiling.
 */
export function paceEstimate(done: number, scheduled: number, elapsedMs: number): Pace | null {
  if (!(elapsedMs > 0) || !(done > 0) || !(scheduled > 0) || !(done < scheduled)) return null;
  const checksPerSecond = done / (elapsedMs / 1000);
  const seconds = (scheduled - done) / checksPerSecond;
  if (!(seconds <= Number.MAX_SAFE_INTEGER / 1000)) return null;
  return { secondsToGo: Math.ceil(seconds), checksPerSecond };
}

/** `3,232 checks to go` / `1 check to go`; `null` when nothing is scheduled or nothing is left. */
export function checksToGo(done: number, scheduled: number): string | null {
  if (!(scheduled > 0) || !(done < scheduled)) return null;
  return `${plural(scheduled - done, 'check')} to go`;
}

/** `at this pace, about 1:04 to go`. */
export function estimateText(pace: Pace): string {
  return `at this pace, about ${fmtElapsed(pace.secondsToGo * 1000)} to go`;
}

/**
 * `Derived from the counters: 3,236 checks done in 1:04, about 51 checks per second, 3,232 to go.`;
 * the rate is rounded (`about 1 check per second`), or `fewer than 1 check per second` at 0.
 */
export function estimateHelp(done: number, elapsedMs: number, pace: Pace, toGo: number): string {
  const rate = Math.round(pace.checksPerSecond);
  const rateWords = rate === 0 ? 'fewer than 1 check per second' : `about ${plural(rate, 'check')} per second`;
  const lead = `Derived from the counters: ${plural(done, 'check')} done in ${fmtElapsed(elapsedMs)}`;
  return `${lead}, ${rateWords}, ${grouped(toGo)} to go.`;
}

/**
 * The progress model (`ScanJobProgress.init`): one total rule over the merged facts (D8, its
 * amendment, D21's `rowText` and `nowTagParts`; P15–P22). The engine sends counters, never a
 * percentage; every value here says so in its help.
 */
export function jobProgress(f: JobFacts): JobProgress {
  const summary = f.summary;
  const status = f.status;
  const checks = status?.checks ?? null;
  const crawl = status?.crawl ?? null;
  const running = checks?.running ?? [];

  const first = running[0];
  const nowLine = first === undefined ? null : `Now: ${nowIds(running, first)}`;
  let nowTagParts: Part[] | null = null;
  if (first !== undefined) {
    nowTagParts = [
      { text: 'now · ', role: 'plain' },
      { text: first, role: 'checkId' },
    ];
    if (running.length > 1) nowTagParts.push({ text: ` and ${running.length - 1} more`, role: 'plain' });
  }
  const nowTag = nowTagParts === null ? null : nowTagParts.map((p) => p.text).join('');

  const checksFraction = checks === null ? null : fractionOf(checks.done, checks.scheduled);
  const pagesFraction = crawl === null ? null : fractionOf(crawl.pages, crawl.pages + crawl.queued);
  const checksHelp = checks !== null && checksFraction !== null ? checksLine(checks) : null;
  const pagesHelp =
    crawl !== null && pagesFraction !== null
      ? `${grouped(crawl.pages)} of ${plural(crawl.pages + crawl.queued, 'page')}`
      : null;

  let ring: Ring = 'indeterminate';
  let line = '';
  let row: string = MISSING_VALUE;
  let help: string | null = null;
  let toGo: string | null = null;
  let pace: Pace | null = null;

  switch (summary.state) {
    case 'queued':
      line = WAITING_LINE;
      break;
    case 'running':
    case 'cancelling':
      if (checks === null || crawl === null) {
        line = phaseWord(summary.phase);
        break;
      }
      switch (summary.phase) {
        case 'crawling':
          if (pagesFraction !== null) ring = { determinate: pagesFraction };
          line = `${plural(crawl.pages, 'page')}, ${grouped(crawl.queued)} queued`;
          row = line;
          help = pagesHelp;
          break;
        case 'passive':
          line = PASSIVE_LINE;
          row = PASSIVE_ROW_LINE;
          break;
        case 'auditing':
          if (checksFraction !== null) {
            ring = { determinate: checksFraction };
            line = checksLine(checks);
            row = `${percent(checksFraction)} · ${checksOfText(checks)}`;
          } else {
            line = SCHEDULING_LINE;
            row = SCHEDULING_LINE;
          }
          help = checksHelp;
          if (summary.state === 'running') {
            toGo = checksToGo(checks.done, checks.scheduled);
            pace = paceEstimate(checks.done, checks.scheduled, summary.elapsed_ms);
          }
          break;
        case 'reporting':
          ring = { determinate: 1 };
          line = REPORTING_LINE;
          row = REPORTING_LINE;
          help = checksHelp;
          if (summary.state === 'running') toGo = checksToGo(checks.done, checks.scheduled);
          break;
        default:
          line = phaseWord(summary.phase);
          row = line;
      }
      break;
    case 'done':
    case 'cancelled':
    case 'failed':
      ring = { finished: checksFraction ?? pagesFraction };
      if (checks !== null) row = checksOfText(checks);
      help = checksFraction !== null ? checksHelp : pagesHelp;
      break;
    default:
      ring = 'none';
      line = stateWord(summary.state);
  }

  const determinate = typeof ring === 'object' && 'determinate' in ring ? ring.determinate : null;
  let estimate: string | null = null;
  let estimateDetail: string | null = null;
  if (pace !== null && checks !== null) {
    estimate = estimateText(pace);
    estimateDetail = estimateHelp(checks.done, summary.elapsed_ms, pace, checks.scheduled - checks.done);
  }
  return {
    ring,
    fraction: determinate,
    percentText: determinate === null ? null : percent(determinate),
    phaseLine: line,
    nowLine,
    helpText: help === null ? UNKNOWN_HELP : `${help}${DERIVED_SUFFIX}`,
    checksToGoText: toGo,
    nowTag,
    nowTagParts,
    estimateText: estimate,
    estimateHelp: estimateDetail,
    rowText: row,
  };
}

/* ---- the end state's lines (ScanEndText; D9, D21) */

/**
 * The stopped-reason sentence for a terminal job whose status has landed and carries a
 * `stopped_reason`; `null` otherwise, and `stoppedReasonText`'s own nulls stand (`cancelled` on a
 * cancelled job, `failed` with an error). The row's sub-line and the card's finding line both read it.
 */
export function reasonLine(f: JobFacts): string | null {
  const { summary, status } = f;
  if (!isTerminal(summary.state) || status === null || status.stopped_reason === null) return null;
  return stoppedReasonText(status.stopped_reason, summary.state, summary.probes.budget, status.error);
}

/**
 * A finished row's second line (D10, D21): `reasonLine`, else the first non-empty line of
 * `status.error`; `null` for a live job, before the status lands, and when neither exists.
 */
export function rowSubLine(f: JobFacts): string | null {
  const { summary, status } = f;
  if (!isTerminal(summary.state) || status === null) return null;
  const sentence = reasonLine(f);
  if (sentence !== null) return sentence;
  if (status.error === null) return null;
  const firstLine = status.error.split(/\r\n|\n|\r/).find((l) => l !== '') ?? '';
  return firstLine === '' ? null : firstLine;
}

/**
 * The attention lines (D9), in this order and only when non-zero: `<n> checks could not run` with
 * the error samples, `<n> checks were skipped` with the skip samples, the crawl trouble line with
 * none. Empty until a status has landed; rendered in every state.
 */
export function attention(f: JobFacts): AttentionLine[] {
  const status = f.status;
  if (status === null) return [];
  const lines: AttentionLine[] = [];
  const checks = status.checks;
  if (checks.errors > 0) {
    lines.push({ text: `${plural(checks.errors, 'check')} could not run`, samples: checks.error_samples });
  }
  if (checks.skipped > 0) {
    const verb = checks.skipped === 1 ? 'was' : 'were';
    lines.push({ text: `${plural(checks.skipped, 'check')} ${verb} skipped`, samples: checks.skipped_samples });
  }
  const trouble = crawlTroubleLine(status.crawl);
  if (trouble !== null) lines.push({ text: trouble, samples: [] });
  return lines;
}

/** One sample row under an attention line's disclosure: the check id and the detail, `xss-reflected · connection refused`. */
export function sampleRowText(sample: CheckErrorSample): string {
  return `${sample.check} · ${sample.detail}`;
}

/**
 * The **Notices** list: the launch's notices (the `scan.start` result's `clamped` and
 * `lanes.skipped`) first, then the status's clamp rows and skipped lanes the notices did not
 * already spell out.
 */
export function notices(st: JobStatus, launchNotices: readonly string[]): string[] {
  const lines = [...launchNotices];
  for (const line of [...st.clamped.map(clampedText), ...st.lanes.skipped.map(skippedLaneText)]) {
    if (!lines.includes(line)) lines.push(line);
  }
  return lines;
}

/* ---- the row's cells (ScanFormat; D10) */

/**
 * `[(high, "1 high"), (low, "3 low")]`, critical → info, zero counts omitted: the ledger's groups as
 * words (one word rule, D21).
 */
export function severityWordParts(by: BySeverity): SeverityPart[] {
  return ledgerGroups(by).map((g) => ({ severity: g.severity, word: g.word }));
}

/** `4 low` / `1 high, 3 low`; `no issues yet` for a live job with none, `no issues` otherwise. */
export function severityWords(by: BySeverity, running: boolean): string {
  const parts = severityWordParts(by);
  if (parts.length === 0) return running ? 'no issues yet' : 'no issues';
  return parts.map((p) => p.word).join(SEVERITY_WORD_SEPARATOR);
}

/** `4 jobs · 1 running` / `1 job` / `3 jobs`: the table's caption. */
export function jobsCaption(total: number, running: number): string {
  const jobs = plural(total, 'job');
  return running > 0 ? `${jobs} · ${grouped(running)} running` : jobs;
}

/** `jobsCaption` over the table's rows: every row counts; a row is running when its merged state is `running` (not queued, not cancelling). */
export function jobsCaptionFor(rows: JobFacts[]): string {
  return jobsCaption(rows.length, rows.filter((f) => f.summary.state === 'running').length);
}

/* ---- the card's heading and finding line (ScanFormat; D11) */

/** Whether an MCP or agent frontend started the job. */
export function agentOriginated(by: StartedBy): boolean {
  return by.frontend === 'mcp' || by.frontend === 'agent';
}

/**
 * Who started the job: `this app` when the cleaned label is this surface's own (`ownLabel`; the mac
 * passes `aitm-mac`, the web has none, gap 48), `the CLI`, `an agent`, an operator client's label
 * (control and format scalars stripped, cut to 40 characters), else `the operator`.
 */
export function startedByWords(by: StartedBy, ownLabel: string | null = null): string {
  const label = by.client_label === null ? '' : boundedStr(by.client_label, STARTED_BY_LABEL_MAX);
  if (ownLabel !== null && label === ownLabel) return 'this app';
  if (by.frontend === 'cli') return 'the CLI';
  if (agentOriginated(by)) return 'an agent';
  if (by.frontend === 'operator' && label !== '') return label;
  return 'the operator';
}

/** One `Intl.DateTimeFormat` per time zone: building one is the costly part, and the card asks on every beat. */
const CLOCK_FORMATS = new Map<string, Intl.DateTimeFormat>();

function clockFormat(timeZone: string): Intl.DateTimeFormat {
  let format = CLOCK_FORMATS.get(timeZone);
  if (format === undefined) {
    format = new Intl.DateTimeFormat('en-GB', { hour: '2-digit', minute: '2-digit', hourCycle: 'h23', timeZone });
    CLOCK_FORMATS.set(timeZone, format);
  }
  return format;
}

/** `HH:mm`, 24-hour, of an epoch-millisecond stamp in the given zone; `00:00` for a stamp no date holds (`STAMP_MAX`). */
export function clock(ms: number, timeZone: string): string {
  if (!Number.isFinite(ms) || Math.abs(ms) > STAMP_MAX) return '00:00';
  return clockFormat(timeZone).format(new Date(ms));
}

const plain = (text: string): Part => ({ text, role: 'plain' });
const figure = (n: number): Part => ({ text: grouped(n), role: 'figure' });
const checkIdPart = (id: string): Part => ({ text: id, role: 'checkId' });

function issuesSoFarParts(by: BySeverity): Part[] {
  const counts = severityCounts(by);
  const only = counts[0];
  if (only === undefined) return [plain('no issues so far')];
  if (counts.length === 1) {
    const [severity, count] = only;
    return [figure(count), plain(` ${severity} issue${count === 1 ? '' : 's'} so far`)];
  }
  const parts = [figure(totalOf(by)), plain(' issues so far: ')];
  counts.forEach(([severity, count], index) => {
    if (index > 0) parts.push(plain(', '));
    parts.push(figure(count), plain(` ${severity}`));
  });
  return parts;
}

/** `no issues so far` / `4 low issues so far` / `1 high issue so far` / `5 issues so far: 1 high, 4 low`. */
export function issuesSoFar(by: BySeverity): string {
  return issuesSoFarParts(by)
    .map((p) => p.text)
    .join('');
}

function nowClauseParts(running: readonly string[]): Part[] | null {
  const first = running[0];
  if (first === undefined) return null;
  const more = running.length - 1;
  if (more === 0) return [checkIdPart(first), plain(' running now')];
  return [checkIdPart(first), plain(` and ${more} more check${more === 1 ? '' : 's'} running now`)];
}

/** `xss-reflected running now` / `xss-reflected and 3 more checks running now`; `null` when nothing runs. */
export function nowClause(running: readonly string[]): string | null {
  const parts = nowClauseParts(running);
  return parts === null ? null : parts.map((p) => p.text).join('');
}

/**
 * The finding line (D11). Live: `<issues so far> · <now clause> · <profile> · started <h:mm> by
 * <who>`; terminal: `<profile> · started <h:mm> by <who> · finished <h:mm>` with the stopped-reason
 * sentence as `reason`. The clauses the status carries wait for it: before it lands a live line is
 * the issues clause alone and a terminal line is empty. A status without `started_at` reads
 * `started by <who>`. `ownLabel` is this surface's own client label (none on the web).
 */
export function findingLine(f: JobFacts, timeZone: string, ownLabel: string | null = null): FindingLine {
  const { summary, status } = f;
  const terminal = isTerminal(summary.state);
  const clauses: Part[][] = [];
  let agent = false;
  if (!terminal) clauses.push(issuesSoFarParts(summary.issues.by_severity));
  if (status !== null) {
    if (!terminal) {
      const now = nowClauseParts(status.checks.running);
      if (now !== null) clauses.push(now);
    }
    clauses.push([plain(profileText(f))]);
    agent = agentOriginated(status.started_by);
    const when = status.started_at > 0 ? ` ${clock(status.started_at, timeZone)}` : '';
    clauses.push([
      plain(`started${when} by `),
      { text: startedByWords(status.started_by, ownLabel), role: agent ? 'agent' : 'plain' },
    ]);
    if (terminal && status.finished_at !== null && status.finished_at > 0) {
      clauses.push([plain(`finished ${clock(status.finished_at, timeZone)}`)]);
    }
  }
  const parts: Part[] = [];
  clauses.forEach((clause, index) => {
    if (index > 0) parts.push(plain(' · '));
    parts.push(...clause);
  });
  return {
    reason: reasonLine(f),
    parts,
    text: parts.map((p) => p.text).join(''),
    agentOriginated: agent,
  };
}

/* ---- tone, ledger, gauge, lane and KPI words (ScanFormat; D11) */

/**
 * Queued and running → `progress`; cancelling → `pending`; done → `success`; failed → `danger`;
 * cancelled and an unknown state → `neutral`.
 */
export function tone(f: JobFacts): Tone {
  switch (f.summary.state) {
    case 'queued':
    case 'running':
      return 'progress';
    case 'cancelling':
      return 'pending';
    case 'done':
      return 'success';
    case 'failed':
      return 'danger';
    default:
      return 'neutral';
  }
}

/** One group per non-zero severity, critical → info, `marks = min(count, 12)`, `word = "4 low"`. */
export function ledgerGroups(by: BySeverity): LedgerGroup[] {
  return severityCounts(by).map(([severity, count]) => ({
    severity,
    count,
    marks: Math.min(count, LEDGER_MARK_CAP),
    word: `${grouped(count)} ${severity}`,
  }));
}

/** The gauge turns amber past 80 % of a known budget. */
export function budgetWarning(sent: number, budget: number): boolean {
  return budget > 0 && sent > 0.8 * budget;
}

/** `287 of 2,000`; `287 probes` when the budget is unknown (`0`). */
export function probeBudgetText(sent: number, budget: number): string {
  return budget > 0 ? `${grouped(sent)} of ${grouped(budget)}` : plural(sent, 'probe');
}

/** `Probe budget, 287 of 2,000`: the gauge's one accessibility label (D11 §4, D14). */
export function gaugeAccessibilityLabel(sent: number, budget: number): string {
  return `Probe budget, ${probeBudgetText(sent, budget)}`;
}

/** `287 of 2,000 probes sent (the probe budget, not progress)`; `287 probes sent (…)` without a budget. */
export function probesTileHelp(sent: number, budget: number): string {
  const count = budget > 0 ? `${grouped(sent)} of ${grouped(budget)} probes` : plural(sent, 'probe');
  return `${count} sent (the probe budget, not progress)`;
}

/** `4 issues: 1 high, 3 low` / `no issues`: the ledger's and the Issues KPI cell's help. */
export function issuesTileHelp(by: BySeverity): string {
  const parts = severityWordParts(by);
  if (parts.length === 0) return 'no issues';
  return `${plural(totalOf(by), 'issue')}: ${parts.map((p) => p.word).join(SEVERITY_WORD_SEPARATOR)}`;
}

/** `of 6,468`: the unit after a KPI or cell numeral. */
export function ofText(n: number): string {
  return `of ${grouped(n)}`;
}

/** `3,236 checks done`: the audit segment's lower label. */
export function laneChecksDone(done: number): string {
  return `${plural(done, 'check')} done`;
}

/** `46 pages` / `1 page`: the crawl segment's lower label. */
export function lanePages(pages: number): string {
  return plural(pages, 'page');
}

/** `started 11:32`: the scale row's first entry. */
export function scaleStarted(clockText: string): string {
  return `started ${clockText}`;
}

/** `elapsed 1:04`: the scale row's second entry. */
export function scaleElapsed(ms: number): string {
  return `elapsed ${fmtElapsed(ms)}`;
}

/* ---- the wells' rows (ScanFormat; D11, D21) */

/**
 * The Crawl well's skipped-points rows, one per reason, zeros included: `722 skipped as
 * repetitive`, `6 skipped by rule`, `0 skipped at the per-request cap`.
 */
export function pointSkipWords(skipped: SkippedPoints): PointSkipWords[] {
  const row = (count: number, words: string): PointSkipWords => ({ count, words, text: `${grouped(count)} ${words}` });
  return [
    row(skipped.frequent, 'skipped as repetitive'),
    row(skipped.ignored, 'skipped by rule'),
    row(skipped.limit, 'skipped at the per-request cap'),
  ];
}

const valueCell = (text: string): WellCell => ({ text, ink: 'value' });

function wellRow(key: string, cells: WellCell[]): WellRow {
  return { key, cells, text: cells.map((c) => c.text).join(WELL_CELL_SEPARATOR) };
}

function oneCellRow(key: string, text: string): WellRow {
  return wellRow(key, [valueCell(text)]);
}

/** A grouped number, or the missing mark before the status lands. */
function numberOrMissing(value: number | undefined): string {
  return value === undefined ? MISSING_VALUE : grouped(value);
}

/** Several counts, one cell each, every one grouped. */
function countCells(values: readonly number[]): WellCell[] {
  return values.map((v) => valueCell(grouped(v)));
}

/** One severity tally: its severity's ink when > 0, muted when 0 (D11). */
function severityCell(severity: Severity, count: number): WellCell {
  return { text: grouped(count), ink: count > 0 ? { severity } : 'muted' };
}

/** `HTTP 240` · `WebSocket 47`, one cell per lane in display order then wire name; one `—` when the bus listed none. */
function probesByLaneCells(byLane: Partial<Record<Lane, number>>): WellCell[] {
  const lanes = (Object.keys(byLane) as Lane[]).filter((lane) => byLane[lane] !== undefined);
  if (lanes.length === 0) return [valueCell(MISSING_VALUE)];
  lanes.sort((a, b) => laneDisplayOrder(a) - laneDisplayOrder(b) || (a < b ? -1 : a > b ? 1 : 0));
  return lanes.map((lane) => valueCell(`${laneWord(lane)} ${grouped(byLane[lane] ?? 0)}`));
}

function crawlRows(f: JobFacts): WellRow[] {
  const { summary, status } = f;
  const crawl = status?.crawl;
  const rows: WellRow[] = [
    oneCellRow(WELL_KEY.pagesFetched, numberOrMissing(crawl?.pages)),
    oneCellRow(WELL_KEY.pagesWaiting, numberOrMissing(crawl?.queued)),
    oneCellRow(WELL_KEY.depth, numberOrMissing(crawl?.depth)),
    oneCellRow(WELL_KEY.formsSubmitted, numberOrMissing(crawl?.forms_submitted)),
    oneCellRow(WELL_KEY.formsNotSubmitted, numberOrMissing(crawl?.forms_skipped)),
  ];
  if (crawl !== undefined && crawl.errors > 0) rows.push(oneCellRow(WELL_KEY.crawlErrors, grouped(crawl.errors)));
  rows.push(
    oneCellRow(WELL_KEY.pointsFound, grouped(summary.points.found)),
    oneCellRow(WELL_KEY.waitingForAudit, grouped(summary.points.queued)),
    oneCellRow(WELL_KEY.audited, grouped(summary.points.audited)),
  );
  for (const skip of pointSkipWords(summary.points.skipped)) rows.push(oneCellRow(skip.words, grouped(skip.count)));
  const run = status?.lanes.run ?? [];
  rows.push(oneCellRow(WELL_KEY.lanes, run.length === 0 ? MISSING_VALUE : run.map(laneWord).join(', ')));
  for (const skipped of status?.lanes.skipped ?? []) rows.push(oneCellRow(WELL_KEY.laneSkipped, skippedLaneWords(skipped)));
  rows.push(wellRow(WELL_KEY.probesByLane, probesByLaneCells(summary.probes.by_lane)));
  const session = status?.session ?? null;
  if (session !== null) {
    rows.push(
      wellRow(
        WELL_KEY.session,
        [yesNo(session.reused), yesNo(session.lost), canaryWord(session.canary), yesNo(session.browser_partial)].map(valueCell),
      ),
    );
  }
  const l4 = status?.l4 ?? null;
  if (l4 !== null) {
    rows.push(
      oneCellRow(WELL_KEY.l4Cases, grouped(l4.cases)),
      oneCellRow(WELL_KEY.l4Crashes, grouped(l4.crashes)),
      oneCellRow(WELL_KEY.l4LivenessFailures, grouped(l4.liveness_failures)),
      oneCellRow(WELL_KEY.l4RetiredElements, grouped(l4.retired_elements)),
    );
  }
  return rows;
}

function issueRows(f: JobFacts): WellRow[] {
  const { summary, status } = f;
  const by = summary.issues.by_severity;
  const confidence = summary.issues.by_confidence;
  const checks = status?.checks;
  return [
    wellRow(WELL_KEY.criticalHighMedium, [
      severityCell('critical', by.critical),
      severityCell('high', by.high),
      severityCell('medium', by.medium),
    ]),
    wellRow(WELL_KEY.low, [severityCell('low', by.low)]),
    wellRow(WELL_KEY.info, [severityCell('info', by.info)]),
    wellRow(WELL_KEY.certainFirmTentative, countCells([confidence.certain, confidence.firm, confidence.tentative])),
    wellRow(WELL_KEY.probeErrors, countCells([summary.probes.errors, summary.probes.timeouts, summary.probes.rate_waits])),
    wellRow(
      WELL_KEY.checks,
      checks === undefined
        ? [valueCell(MISSING_VALUE)]
        : countCells([checks.scheduled, checks.done, checks.errors, checks.skipped]),
    ),
  ];
}

/**
 * The two wells' rows in D11's order (D21), every key a `WELL_KEY` or a skip-words key, every
 * number grouped, `—` for a status-only value until the status lands. Crawl and points: the crawl
 * counters, Crawl errors (only when > 0), the point counters, the three skipped-points rows,
 * Lanes, one `Lane skipped` row per skipped lane, Probes by lane, Session (only with one), the
 * four L4 rows (only with `l4`). Issues: the severity tallies (`severity` ink above zero, `muted`
 * at zero), the confidence tally, the probe trouble tally, and the four check counts.
 */
export function wellRows(f: JobFacts): WellRows {
  return { crawl: crawlRows(f), issues: issueRows(f) };
}

/* ---- accessibility (ScanFormat; D14) */

/** `1 minute 4 seconds` / `42 seconds` / `1 hour 2 minutes 3 seconds`; zero components left out, `0 seconds` for nothing. */
export function elapsedWords(ms: number): string {
  const total = Number.isFinite(ms) && ms > 0 ? Math.floor(ms / 1000) : 0;
  const hours = Math.floor(total / 3600);
  const minutes = Math.floor((total % 3600) / 60);
  const seconds = total % 60;
  const parts: string[] = [];
  if (hours > 0) parts.push(pluralPlain(hours, 'hour'));
  if (minutes > 0) parts.push(pluralPlain(minutes, 'minute'));
  if (seconds > 0 || parts.length === 0) parts.push(pluralPlain(seconds, 'second'));
  return parts.join(' ');
}

/** `50 percent` for a determinate progress (the lane's accessibility value); `null` otherwise. */
export function progressAccessibilityValue(p: JobProgress): string | null {
  return p.percentText === null ? null : p.percentText.replace(' %', ' percent');
}

/**
 * The row as one sentence: `Auditing, standard, 127.0.0.1:8117, 50 percent, 3,236 of 6,468
 * checks, 4 issues: 4 low, 1 minute 4 seconds.` The percent and the progress line only when the
 * progress is determinate; the profile and hosts only once the status has said them.
 */
export function jobAccessibilityLabel(f: JobFacts): string {
  const summary = f.summary;
  const progress = jobProgress(f);
  const parts = [stateWords(summary)];
  const name = profileName(f);
  if (name !== null) parts.push(name);
  const hosts = hostsJoined(f.status?.targets ?? []);
  if (hosts !== null) parts.push(hosts);
  const value = progressAccessibilityValue(progress);
  if (value !== null) parts.push(value, progress.phaseLine);
  const by = summary.issues.by_severity;
  parts.push(totalOf(by) > 0 ? issuesTileHelp(by) : severityWords(by, !isTerminal(summary.state)));
  parts.push(elapsedWords(summary.elapsed_ms));
  return `${parts.join(', ')}.`;
}

/* ---- Scan Again and the banner (ScanSurfaceModel.scanAgainHelp, ScanJobsLink.bannerText; D13, D15) */

/**
 * The Scan Again verb's help: `Start a new job with profile standard against 127.0.0.1:8117`
 * (every host, joined with `, `). Without a profile name the generic help stands; without targets
 * the `against` clause is left off.
 */
export function scanAgainHelp(st: JobStatus): string {
  if (st.profile_name === '') return SCAN_AGAIN_HELP_GENERIC;
  const base = `Start a new job with profile ${st.profile_name}`;
  const hosts = hostsJoined(st.targets);
  return hosts === null ? base : `${base} against ${hosts}`;
}

/**
 * D15's banner while the bus is not open: `Bus disconnected · showing values from 0:42 ago ·
 * reconnecting…`; the age clause is left off while no list has landed (`null`). The web tells an
 * open socket from a closed one and nothing more, so the Kit's one `reconnecting` row is its whole
 * table (gap 5).
 */
export function linkBannerText(valuesAgeMs: number | null): string {
  const parts = ['Bus disconnected'];
  if (valuesAgeMs !== null) parts.push(`showing values from ${fmtElapsed(valuesAgeMs)} ago`);
  parts.push('reconnecting…');
  return parts.join(' · ');
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
