// The scanner v2 wire types and their parsers (spec D-T8.4).
//
// Every type here mirrors a Rust type in `crates/aitm-scan-model/src/` field for field: snake_case
// keys, `number` for integers, `T | null` for an `Option`. The Rust model is the authority; the
// fixture pack (`crates/aitm-scan-model/fixtures/`) is one example of each shape.
//
// Parsing rules, applied by every `parse*` below:
//   - the input is `unknown` and may be anything a drifted or hostile core sent; a parser never
//     throws and never returns a half-built object. It returns `T | null`.
//   - `null` when a required discriminant is missing or unknown: the job id, an id, `state`,
//     `phase`, `kind`, or any required enum token.
//   - lists are capped at `MAX_LIST` so one payload cannot allocate without bound, and a row that
//     does not parse is dropped rather than taking its whole page down. The one exception is
//     `parseScanProfile`, which is strict (see there): a draft is sent back to the core on save, so
//     silently dropping a value the operator cannot see would delete their configuration.
//   - absent counters default to `0`, absent lists to `[]`, absent optionals to `null`.

import { SEVERITIES, isSeverity } from '~/panels/findings/model';
import type { Severity } from '~/panels/findings/model';

export type { Severity } from '~/panels/findings/model';

/* ------------------------------------------------------------------ vocabulary (vocab.rs) */

export const JOB_STATES = ['queued', 'running', 'cancelling', 'done', 'cancelled', 'failed'] as const;
export type JobState = (typeof JOB_STATES)[number];

export const PHASES = ['queued', 'crawling', 'passive', 'auditing', 'reporting', 'done'] as const;
export type Phase = (typeof PHASES)[number];

export const STOPPED_REASONS = [
  'budget',
  'time',
  'cancelled',
  'session_lost',
  'errors',
  'policy',
  'guard_refused',
  'failed',
] as const;
export type StoppedReason = (typeof STOPPED_REASONS)[number];

export const LANES = ['http', 'ws', 'l4_packet', 'l4_stream'] as const;
export type Lane = (typeof LANES)[number];

export const INTENSITIES = ['passive', 'light', 'medium', 'intrusive'] as const;
export type Intensity = (typeof INTENSITIES)[number];

export const SPEEDS = ['fast', 'normal', 'thorough'] as const;
export type Speed = (typeof SPEEDS)[number];

export const ACCURACIES = ['fewer_false_negatives', 'normal', 'fewer_false_positives'] as const;
export type Accuracy = (typeof ACCURACIES)[number];

/** The 20 insertion kinds of spec D2, in the engine's order; also the default `audit.kinds`. */
export const INSERTION_KINDS = [
  'query',
  'body_param',
  'json_value',
  'xml_value',
  'xml_attr',
  'multipart_value',
  'multipart_filename',
  'header',
  'cookie',
  'path_segment',
  'path_filename',
  'param_name_query',
  'param_name_body',
  'entire_body',
  'ws_json_value',
  'ws_text',
  'ws_form_param',
  'ws_binary',
  'ws_handshake_header',
  'l4_field',
] as const;
export type InsertionKind = (typeof INSERTION_KINDS)[number];

export const POINT_TRAITS = ['url', 'filename', 'number', 'email', 'base64', 'json', 'id', 'session', 'structured'] as const;
export type PointTrait = (typeof POINT_TRAITS)[number];

export const CONFIDENCES = ['tentative', 'firm', 'certain'] as const;
export type Confidence = (typeof CONFIDENCES)[number];

export const ISSUE_STATUSES = ['open', 'confirmed', 'false_positive'] as const;
export type IssueStatus = (typeof ISSUE_STATUSES)[number];

export const TECHNIQUES = [
  'reflected',
  'error',
  'boolean',
  'timing',
  'handshake',
  'malformed',
  'observe',
  'passive',
] as const;
export type Technique = (typeof TECHNIQUES)[number];

export const CHECK_COSTS = ['light', 'medium', 'heavy'] as const;
export type CheckCost = (typeof CHECK_COSTS)[number];

/** Where a check came from: compiled in, a script from the shipped catalogue, an operator's script. */
export type CheckOrigin =
  | { kind: 'native' }
  | { kind: 'bundled'; path: string }
  | { kind: 'custom'; path: string };

export const SCAN_ERROR_CODES = [
  'not_found',
  'busy',
  'out_of_scope',
  'refused_agent',
  'refused_l4',
  'lane_unavailable',
  'invalid_profile',
  'unknown_check',
  'confirm_required',
] as const;
export type ScanErrorCode = (typeof SCAN_ERROR_CODES)[number];

export const JOB_EVENTS = [
  'started',
  'phase',
  'progress',
  'issue',
  'finished',
  'cancelled',
  'failed',
] as const;
export type JobEvent = (typeof JOB_EVENTS)[number];

export const L4_TRANSPORTS = ['tcp', 'udp'] as const;
export type L4Transport = (typeof L4_TRANSPORTS)[number];

export const CRAWL_STRATEGIES = ['fast', 'normal', 'thorough'] as const;
export type CrawlStrategy = (typeof CRAWL_STRATEGIES)[number];

/** Why an all-failing client crawl failed (`CrawlCounters.last_error`, job.rs `CrawlErrorKind`). */
export const CRAWL_ERROR_KINDS = ['h2_not_negotiated', 'connect_refused', 'tls', 'timeout', 'transport', 'other'] as const;
export type CrawlErrorKind = (typeof CRAWL_ERROR_KINDS)[number];

export const USE_BROWSER = ['auto', 'always', 'never'] as const;
export type UseBrowser = (typeof USE_BROWSER)[number];

export const SESSION_MODES = ['observed', 'none'] as const;
export type SessionMode = (typeof SESSION_MODES)[number];

export const ON_LOST = ['stop', 'continue'] as const;
export type OnLost = (typeof ON_LOST)[number];

export const HTTP_VERSION_POLICIES = ['auto', 'h1', 'h2', 'h2c'] as const;
export type HttpVersionPolicy = (typeof HTTP_VERSION_POLICIES)[number];

export const RECORD_PROBES = ['issues_only', 'all'] as const;
export type RecordProbes = (typeof RECORD_PROBES)[number];

/** Severity order for grouped lists and the stacked bar: worst first. */
export const SEVERITY_ORDER = SEVERITIES;

/** The push method every job line arrives on (`results.rs: JOB_NOTIFICATION_METHOD`). */
export const JOB_NOTIFICATION_METHOD = 'notifications/aitm/job';

/** The `kind` a scan job's push line carries (`results.rs: JOB_KIND_SCAN`). */
const JOB_KIND_SCAN = 'scan';

/** The page size the Issues view asks `scan.issues` for. */
export const ISSUES_LIMIT = 1024;

/** The page size the Site map view asks `scan.sitemap` for. */
export const SITEMAP_LIMIT = 1024;

/* ------------------------------------------------------------------ counters (job.rs) */

export interface BySeverity {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
}

export interface ByConfidence {
  certain: number;
  firm: number;
  tentative: number;
}

export interface ProbeCounters {
  sent: number;
  budget: number;
  errors: number;
  timeouts: number;
  rate_waits: number;
  by_lane: Partial<Record<Lane, number>>;
}

export interface CrawlCounters {
  pages: number;
  queued: number;
  depth: number;
  forms_submitted: number;
  /** Crawl errors, a failed browser crawl among them (the client crawl then stands in). Absent → 0. */
  errors: number;
  /** Forms the crawler saw but did not submit (`submit_forms: false`, or a form it would not fill). Absent → 0. */
  forms_skipped: number;
  /** Why every request of the crawl failed, when it did. Absent or an unknown token → `null`. */
  last_error: CrawlErrorKind | null;
}

export interface SkippedPoints {
  ignored: number;
  frequent: number;
  limit: number;
}

export interface PointCounters {
  found: number;
  queued: number;
  audited: number;
  skipped: SkippedPoints;
}

/** One sampled check `error` (or skip): which check, the first point it hit, and its detail. */
export interface CheckErrorSample {
  check: string;
  point: string;
  detail: string;
}

export interface CheckCounters {
  scheduled: number;
  done: number;
  running: string[];
  /** Checks that ended in an `error` verdict. Absent → 0. */
  errors: number;
  /** The engine keeps the first few distinct `(check, detail)` pairs. Absent → `[]`. */
  error_samples: CheckErrorSample[];
  /** Checks skipped (a lane that hosts nothing, a point the check does not fit). Absent → 0. */
  skipped: number;
  /** Samples of the skips, apart from the errors so a skip never reads as a failure. Absent → `[]`. */
  skipped_samples: CheckErrorSample[];
}

export interface IssueCounters {
  total: number;
  by_severity: BySeverity;
  by_confidence: ByConfidence;
}

export interface L4Counters {
  cases: number;
  crashes: number;
  liveness_failures: number;
  retired_elements: number;
}

/** The auth-lost canary: either none (detection off) or a flow to replay. */
export type Canary =
  | { kind: 'none' }
  | { kind: 'flow'; method: string; path: string; expected_status: number | null };

export interface SessionStatus {
  reused: boolean;
  lost: boolean;
  canary: Canary;
  browser_partial: boolean;
}

export interface SkippedLane {
  lane: Lane;
  reason: string;
}

export interface LaneReport {
  requested: Lane[];
  run: Lane[];
  skipped: SkippedLane[];
}

export interface Clamped {
  field: string;
  requested: number;
  applied: number;
}

export interface StartedBy {
  frontend: string;
  client_label: string | null;
}

export interface JobStatus {
  job: string;
  state: JobState;
  phase: Phase;
  profile_name: string;
  targets: string[];
  started_by: StartedBy;
  started_at: number;
  finished_at: number | null;
  elapsed_ms: number;
  stopped_reason: StoppedReason | null;
  probes: ProbeCounters;
  crawl: CrawlCounters;
  points: PointCounters;
  checks: CheckCounters;
  issues: IssueCounters;
  l4: L4Counters | null;
  session: SessionStatus | null;
  lanes: LaneReport;
  clamped: Clamped[];
  error: string | null;
}

export interface JobSummary {
  job: string;
  state: JobState;
  phase: Phase;
  elapsed_ms: number;
  probes: ProbeCounters;
  points: PointCounters;
  issues: IssueCounters;
}

/* ------------------------------------------------------------------ verb results (results.rs) */

export interface StartResult {
  job: string;
  status: JobStatus;
  clamped: Clamped[];
  lanes: LaneReport;
  /** Only for a profile with an L4 lane; the key is absent otherwise. */
  dry_run?: boolean | undefined;
}

export interface ListResult {
  jobs: JobSummary[];
}

/* ------------------------------------------------------------------ issues (issue.rs, check.rs) */

export interface IssueTarget {
  scheme: string;
  host: string;
  port: number;
}

export interface L4Location {
  ip: string;
  port: number;
  proto: L4Transport;
  grammar: string | null;
  field_path: string | null;
  mutation: string | null;
}

export interface IssueLocation {
  method: string | null;
  path: string;
  path_template: string;
  kind: InsertionKind;
  name: string;
  field_path: string | null;
  ws_path: string | null;
  l4: L4Location | null;
}

export interface Timing {
  requested_s: number[];
  observed_ms: number[];
  baseline_ms: number[];
  slope: number;
  r: number;
}

export interface Diff {
  baseline_len: number;
  true_len: number;
  false_len: number;
}

/** How the L4 oracle classified the target's reaction (`check.rs: L4Oracle`). */
export type L4Oracle =
  | { kind: 'protocol_error' }
  | { kind: 'reset' }
  | { kind: 'icmp'; type: number; code: number }
  | { kind: 'silence' }
  | { kind: 'liveness_failed' }
  | { kind: 'latency_outlier' };

export interface L4Evidence {
  sent_hex: string;
  seed_id: string;
  rng_seed: number;
  mutation_chain: string[];
  prior_messages: number;
  oracle: L4Oracle;
  liveness_before: boolean;
  liveness_after: boolean;
  /** `[k, n]`: the case reproduced k times out of n attempts. */
  reproduced: [number, number];
  scope_entry: string;
}

export interface Evidence {
  payload: string | null;
  matched: string | null;
  probe_flows: string[];
  baseline_flow: string | null;
  timing: Timing | null;
  diff: Diff | null;
  l4: L4Evidence | null;
}

export interface IssueSummary {
  id: string;
  /** The job that first found the issue. */
  job: string;
  /** Every job that found or re-found it, the first finder included. Absent on the wire → `[]`. */
  jobs: string[];
  check_id: string;
  class: string;
  name: string;
  severity: Severity;
  confidence: Confidence;
  status: IssueStatus;
  lane: Lane;
  target: IssueTarget;
  location: IssueLocation;
  first_seen: number;
  last_seen: number;
  occurrences: number;
  poc_ref: string | null;
  finding_id: string | null;
}

export interface Issue extends IssueSummary {
  evidence: Evidence;
  description: string;
  remediation: string | null;
  note: string | null;
}

export interface IssuesResult {
  issues: IssueSummary[];
  next_cursor: string | null;
  by_severity: BySeverity;
}

/* ------------------------------------------------------------------ site map (point.rs) */

export interface ParamRef {
  kind: InsertionKind;
  name: string;
}

export interface SiteNode {
  id: string;
  method: string;
  scheme: string;
  host: string;
  port: number;
  path_template: string;
  flows: string[];
  params: ParamRef[];
  auth: boolean;
  points: number;
  audited: boolean;
}

export interface InsertionPoint {
  id: string;
  lane: Lane;
  kind: InsertionKind;
  name: string;
  path: string | null;
  /** Already redacted by the engine; rendered verbatim, `<redacted>` included. */
  example: string | null;
  flow: string | null;
  site_node: string | null;
  traits: PointTrait[];
  frequency: number;
  method: string | null;
  url: string | null;
}

export interface SitemapResult {
  nodes: SiteNode[];
  points: InsertionPoint[];
  next_cursor: string | null;
}

/* ------------------------------------------------------------------ checks (check.rs) */

export interface CheckMeta {
  id: string;
  name: string;
  class: string;
  lanes: Lane[];
  kinds: InsertionKind[];
  intensity: Intensity;
  cost: CheckCost;
  technique: Technique;
  severity: Severity;
  confidence_max: Confidence;
  needs_baseline: boolean;
  wants_traits: PointTrait[] | null;
  targets_session: boolean;
  cwe: number | null;
  description: string;
  remediation: string | null;
  origin: CheckOrigin;
}

export interface ChecksResult {
  checks: CheckMeta[];
}

/* ------------------------------------------------------------------ profiles (profile.rs) */

export interface ProfileSummary {
  lanes: Lane[];
  intensity: Intensity;
  speed: Speed;
}

export interface ProfileListEntry {
  name: string;
  builtin: boolean;
  summary: ProfileSummary;
}

export interface ProfileListResult {
  profiles: ProfileListEntry[];
}

export interface L4TargetSpec {
  ip: string;
  port: number;
  proto: L4Transport;
  grammar: string | null;
}

export interface ProfileTarget {
  origins: string[];
  l4: L4TargetSpec[];
}

export interface CheckSelection {
  include: string[];
  exclude: string[];
}

export interface CrawlOptions {
  strategy: CrawlStrategy;
  max_depth: number;
  max_pages: number;
  submit_forms: boolean;
  click_handlers: boolean;
  robots: boolean;
  sitemap: boolean;
  use_browser: UseBrowser;
}

export interface IgnoreRule {
  kind: InsertionKind | null;
  name_regex: string | null;
  /** `trait` on the wire; Rust calls the field `point_trait` because it cannot use the keyword. */
  trait: PointTrait | null;
}

export interface AuditOptions {
  kinds: InsertionKind[];
  ignore: IgnoreRule[];
  max_points_per_request: number;
  frequent_point_threshold: number;
}

export interface SessionOptions {
  mode: SessionMode;
  from_flow: string | null;
  on_lost: OnLost;
}

export interface PerHostErrors {
  consecutive: number;
  ratio: number;
}

export interface Budget {
  probes: number;
  time_s: number;
  max_issues: number;
  check_timeout_s: number;
  per_host_errors: PerHostErrors;
}

export interface HttpOptions {
  version: HttpVersionPolicy;
  record_probes: RecordProbes;
}

export interface WsOptions {
  reply_window_ms: number;
  max_frame_bytes: number;
}

/** A seed message the L4 lane mutates from: exactly one of the three forms. */
export type L4Seed = { flow: string } | { hex: string } | { base64: string };

export interface L4Options {
  cases: number;
  reproduce_count: number;
  liveness_every: number;
  consecutive_timeouts: number;
  max_bytes_per_s: number;
  seeds: L4Seed[];
  dry_run: boolean;
}

export interface ScanProfile {
  name: string;
  target: ProfileTarget;
  lanes: Lane[];
  intensity: Intensity;
  speed: Speed;
  accuracy: Accuracy;
  checks: CheckSelection;
  crawl: CrawlOptions;
  audit: AuditOptions;
  session: SessionOptions;
  budget: Budget;
  http: HttpOptions;
  ws: WsOptions;
  l4: L4Options;
}

export interface ProfileSaveResult {
  saved: string;
  path: string;
}

export interface ProfileDeleteResult {
  deleted: boolean;
}

/* ------------------------------------------------------------------ session (session.rs) */

/**
 * The session the scanner would reuse, as **names only**. Spec D7's anti-goal: no result carries
 * session material, so this type deliberately has no value field of any kind.
 */
export interface SessionProfile {
  origin: string;
  cookies: string[];
  headers: string[];
  source_flow: string | null;
  observed_at: number;
  canary: Canary;
}

/* ------------------------------------------------------------------ push line (results.rs) */

export interface JobNotification {
  job: string;
  kind: string;
  event: JobEvent;
  seq: number;
  ts_ms: number;
  status: JobSummary;
  /** Present on an `issue` line only. */
  issue?: IssueSummary | undefined;
}

/* ------------------------------------------------------------------ parsing primitives */

/** The engine's own page ceiling; also the bound on anything we allocate from one payload. */
const MAX_LIST = 1024;

/**
 * Hostile-core bounds for the Jobs view (spec D1 amendment, web AC1b; the Kit's `ScanWire` caps and
 * the TUI's `bound_status`). A status is drawn one row per sample, so every string it carries is
 * cleaned and cut at decode and every sampled list is cut to the engine's own cap of 8.
 */
/** The cap on an error text, a sample field, a skipped reason, a running check id. */
export const STR_MAX = 400;
/** The cap on a profile name, a client label, a clamped field. */
export const TOKEN_MAX = 64;
/** The cap on one target origin (the Kit's `ScanWire.targetMax`); the list holds `MAX_SAMPLES`. */
export const TARGET_MAX = 200;
/** The engine's cap on `error_samples`, `skipped_samples` and `checks.running`; held against `lanes.skipped`, `clamped` and `targets` too. */
export const MAX_SAMPLES = 8;
/** The largest millisecond stamp a `Date` can hold (±8.64e15; the wire's stamps are epoch ms, so only the positive side). */
const STAMP_MAX = 8.64e15;

/** Control, format, line and paragraph separator scalars: none of them belongs in a row. */
const UNPRINTABLE = /[\p{Cc}\p{Cf}\u2028\u2029]/gu;

/**
 * `v` as a string with `UNPRINTABLE` scalars dropped and cut to `max` code points (not UTF-16
 * units, so an astral scalar is never split); `''` for a non-string. The strings of a status that a
 * Jobs row prints go through here, never `str`.
 */
function boundedStr(v: unknown, max: number): string {
  if (typeof v !== 'string') return '';
  const clean = v.replace(UNPRINTABLE, '');
  let end = 0;
  let n = 0;
  for (const ch of clean) {
    if (n === max) break;
    end += ch.length;
    n += 1;
  }
  return end === clean.length ? clean : clean.slice(0, end);
}

/** `boundedStr`, keeping an absent or non-string value as `null`. */
function boundedOptStr(v: unknown, max: number): string | null {
  return typeof v === 'string' ? boundedStr(v, max) : null;
}

/** The first `MAX_SAMPLES` strings of a list, each bounded to `max`; a non-string item is dropped. */
function boundedStrList(v: unknown, max: number): string[] {
  return rows(v, (x) => (typeof x === 'string' ? boundedStr(x, max) : null), MAX_SAMPLES);
}

type Dict = Record<string, unknown>;

/** A plain object, or `null`. An array is not an object here: it means a drifted contract. */
function dict(raw: unknown): Dict | null {
  return typeof raw === 'object' && raw !== null && !Array.isArray(raw) ? (raw as Dict) : null;
}

/** A required non-empty string, or `null`. Used for every id a view would otherwise render blank. */
function reqStr(v: unknown): string | null {
  return typeof v === 'string' && v !== '' ? v : null;
}

function str(v: unknown): string {
  return typeof v === 'string' ? v : '';
}

/**
 * The one key a Solid store will not hold: `setStore(path, '__proto__', …)` logs "Refusing to
 * traverse unsafe key" and writes nothing, so a row keyed by it would be polled forever and never
 * shown. Every id and id reference on this wire goes through `idStr`/`optId`/`idList`; an unsafe
 * id is `null` (the enclosing row is dropped), an unsafe reference reads as absent.
 */
const UNSAFE_ID = '__proto__';

/** A required id: a non-empty string that a store can key on, or `null`. */
function idStr(v: unknown): string | null {
  const s = reqStr(v);
  return s === null || s === UNSAFE_ID ? null : s;
}

/** An optional id reference (a flow, a site node): absent, or a string a store can key on. */
function optId(v: unknown): string | null {
  const s = optStr(v);
  return s === null || s === UNSAFE_ID ? null : s;
}

/** A list of id references with the unsafe key filtered out. */
function idList(v: unknown): string[] {
  return strList(v).filter((x) => x !== UNSAFE_ID);
}

function optStr(v: unknown): string | null {
  return typeof v === 'string' ? v : null;
}

/**
 * A finite, non-negative number, or `fallback`. Every integer on this wire is a counter, a size, a
 * timestamp or a budget: `NaN`/`Infinity` would render as garbage and a negative one would step a
 * counter below zero, so both are rejected (the signed timing statistics use `signed`).
 */
function num(v: unknown, fallback = 0): number {
  return typeof v === 'number' && Number.isFinite(v) && v >= 0 ? v : fallback;
}

function optNum(v: unknown): number | null {
  return typeof v === 'number' && Number.isFinite(v) && v >= 0 ? v : null;
}

/**
 * A millisecond stamp the Jobs view puts through `clock`: an integer in `0 … STAMP_MAX`, or `0`
 * (the card's "unknown", read as `started —`). `num` alone would pass a finite `1e300`, which no
 * `Date` holds and the clock would print as `00:00`.
 */
function stamp(v: unknown): number {
  return typeof v === 'number' && Number.isInteger(v) && v >= 0 && v <= STAMP_MAX ? v : 0;
}

/** `stamp` for an optional one: a stamp `stamp` would reject, like an absent value, is `null` (not known). */
function optStamp(v: unknown): number | null {
  return typeof v === 'number' && stamp(v) === v ? v : null;
}

/** A finite number of either sign: a regression slope or a correlation coefficient. */
function signed(v: unknown): number {
  return typeof v === 'number' && Number.isFinite(v) ? v : 0;
}

function bool(v: unknown, fallback = false): boolean {
  return typeof v === 'boolean' ? v : fallback;
}

/** A known token, or `null` for an absent, unknown or non-string one. */
function token<T extends string>(tokens: readonly T[], v: unknown): T | null {
  return typeof v === 'string' && (tokens as readonly string[]).includes(v) ? (v as T) : null;
}

function strList(v: unknown): string[] {
  return Array.isArray(v)
    ? v.slice(0, MAX_LIST).filter((x): x is string => typeof x === 'string')
    : [];
}

function numList(v: unknown): number[] {
  return Array.isArray(v)
    ? v.slice(0, MAX_LIST).filter((x): x is number => typeof x === 'number' && Number.isFinite(x))
    : [];
}

/** Map a list, dropping what does not parse (a bad row must not lose its whole page). */
function rows<T>(v: unknown, parse: (raw: unknown) => T | null, cap = MAX_LIST): T[] {
  if (!Array.isArray(v)) return [];
  const out: T[] = [];
  for (const item of v.slice(0, cap)) {
    const parsed = parse(item);
    if (parsed !== null) out.push(parsed);
  }
  return out;
}

/**
 * `rows`, keeping the first row of each id only. A listbox walks ids, so a page that repeats one
 * (a core bug, a cursor overlap) would otherwise trap ArrowDown on the repeated row.
 */
function uniqueRows<T>(v: unknown, parse: (raw: unknown) => T | null, key: (row: T) => string, cap = MAX_LIST): T[] {
  const seen = new Set<string>();
  return rows(v, parse, cap).filter((row) => {
    const k = key(row);
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  });
}

/** Map a list of tokens, dropping unknown ones. For read-only report types only. */
function tokenList<T extends string>(tokens: readonly T[], v: unknown): T[] {
  return rows(v, (x) => token(tokens, x));
}

/**
 * Strict list for profile drafts: absent gives `fallback`, a non-array or any unparsable row gives
 * `null`. A draft is sent back whole on save, so a value we cannot represent must surface as an
 * error, never be silently dropped from the operator's configuration.
 */
function strictRows<T>(v: unknown, parse: (raw: unknown) => T | null, fallback: T[]): T[] | null {
  if (v === undefined || v === null) return fallback;
  if (!Array.isArray(v)) return null;
  const out: T[] = [];
  for (const item of v.slice(0, MAX_LIST)) {
    const parsed = parse(item);
    if (parsed === null) return null;
    out.push(parsed);
  }
  return out;
}

/** Strict enum for profile drafts: absent takes the default, present-but-unknown is an error. */
function strictToken<T extends string>(tokens: readonly T[], v: unknown, fallback: T): T | null {
  if (v === undefined || v === null) return fallback;
  return token(tokens, v);
}

/* ------------------------------------------------------------------ counter parsers */

function bySeverity(v: unknown): BySeverity {
  const o = dict(v) ?? {};
  return {
    critical: num(o.critical),
    high: num(o.high),
    medium: num(o.medium),
    low: num(o.low),
    info: num(o.info),
  };
}

function byConfidence(v: unknown): ByConfidence {
  const o = dict(v) ?? {};
  return { certain: num(o.certain), firm: num(o.firm), tentative: num(o.tentative) };
}

function probeCounters(v: unknown): ProbeCounters {
  const o = dict(v) ?? {};
  const by_lane: Partial<Record<Lane, number>> = {};
  const raw = dict(o.by_lane);
  if (raw) {
    for (const [key, value] of Object.entries(raw)) {
      const lane = token(LANES, key);
      if (lane !== null && typeof value === 'number' && Number.isFinite(value)) {
        by_lane[lane] = value;
      }
    }
  }
  return {
    sent: num(o.sent),
    budget: num(o.budget),
    errors: num(o.errors),
    timeouts: num(o.timeouts),
    rate_waits: num(o.rate_waits),
    by_lane,
  };
}

function crawlCounters(v: unknown): CrawlCounters {
  const o = dict(v) ?? {};
  return {
    pages: num(o.pages),
    queued: num(o.queued),
    depth: num(o.depth),
    forms_submitted: num(o.forms_submitted),
    errors: num(o.errors),
    forms_skipped: num(o.forms_skipped),
    last_error: token(CRAWL_ERROR_KINDS, o.last_error),
  };
}

function pointCounters(v: unknown): PointCounters {
  const o = dict(v) ?? {};
  const s = dict(o.skipped) ?? {};
  return {
    found: num(o.found),
    queued: num(o.queued),
    audited: num(o.audited),
    skipped: { ignored: num(s.ignored), frequent: num(s.frequent), limit: num(s.limit) },
  };
}

/** A sample is `#[serde(default)]` on the engine: a missing key reads `''`; a non-object is dropped. */
function checkErrorSample(v: unknown): CheckErrorSample | null {
  const o = dict(v);
  if (!o) return null;
  return {
    check: boundedStr(o.check, STR_MAX),
    point: boundedStr(o.point, STR_MAX),
    detail: boundedStr(o.detail, STR_MAX),
  };
}

function checkCounters(v: unknown): CheckCounters {
  const o = dict(v) ?? {};
  return {
    scheduled: num(o.scheduled),
    done: num(o.done),
    running: boundedStrList(o.running, STR_MAX),
    errors: num(o.errors),
    error_samples: rows(o.error_samples, checkErrorSample, MAX_SAMPLES),
    skipped: num(o.skipped),
    skipped_samples: rows(o.skipped_samples, checkErrorSample, MAX_SAMPLES),
  };
}

function issueCounters(v: unknown): IssueCounters {
  const o = dict(v) ?? {};
  return {
    total: num(o.total),
    by_severity: bySeverity(o.by_severity),
    by_confidence: byConfidence(o.by_confidence),
  };
}

function l4Counters(v: unknown): L4Counters | null {
  const o = dict(v);
  if (!o) return null;
  return {
    cases: num(o.cases),
    crashes: num(o.crashes),
    liveness_failures: num(o.liveness_failures),
    retired_elements: num(o.retired_elements),
  };
}

/** An unrecognisable canary is `none`: auth-lost detection off is the safe reading. */
function canary(v: unknown): Canary {
  const o = dict(v);
  if (!o || o.kind !== 'flow') return { kind: 'none' };
  const method = optStr(o.method);
  const path = optStr(o.path);
  if (method === null || path === null) return { kind: 'none' };
  return { kind: 'flow', method, path, expected_status: optNum(o.expected_status) };
}

function sessionStatus(v: unknown): SessionStatus | null {
  const o = dict(v);
  if (!o) return null;
  return {
    reused: bool(o.reused),
    lost: bool(o.lost),
    canary: canary(o.canary),
    browser_partial: bool(o.browser_partial),
  };
}

function skippedLane(v: unknown): SkippedLane | null {
  const o = dict(v);
  if (!o) return null;
  const lane = token(LANES, o.lane);
  if (lane === null) return null;
  return { lane, reason: boundedStr(o.reason, STR_MAX) };
}

function laneReport(v: unknown): LaneReport {
  const o = dict(v) ?? {};
  return {
    requested: tokenList(LANES, o.requested),
    run: tokenList(LANES, o.run),
    skipped: rows(o.skipped, skippedLane, MAX_SAMPLES),
  };
}

function clamped(v: unknown): Clamped | null {
  const o = dict(v);
  if (!o) return null;
  // Bounded first: a field that is nothing but unprintable scalars would render blank, so it is
  // dropped like a missing one.
  const field = reqStr(boundedStr(o.field, TOKEN_MAX));
  if (field === null) return null;
  return { field, requested: num(o.requested), applied: num(o.applied) };
}

function startedBy(v: unknown): StartedBy {
  const o = dict(v) ?? {};
  return { frontend: str(o.frontend), client_label: boundedOptStr(o.client_label, TOKEN_MAX) };
}

/* ------------------------------------------------------------------ job parsers */

/** `scan.status` and `scan.cancel`. */
export function parseJobStatus(raw: unknown): JobStatus | null {
  const o = dict(raw);
  if (!o) return null;
  const job = idStr(o.job);
  const state = token(JOB_STATES, o.state);
  const phase = token(PHASES, o.phase);
  if (job === null || state === null || phase === null) return null;
  return {
    job,
    state,
    phase,
    profile_name: boundedStr(o.profile_name, TOKEN_MAX),
    targets: boundedStrList(o.targets, TARGET_MAX),
    started_by: startedBy(o.started_by),
    started_at: stamp(o.started_at),
    finished_at: optStamp(o.finished_at),
    elapsed_ms: num(o.elapsed_ms),
    stopped_reason: token(STOPPED_REASONS, o.stopped_reason),
    probes: probeCounters(o.probes),
    crawl: crawlCounters(o.crawl),
    points: pointCounters(o.points),
    checks: checkCounters(o.checks),
    issues: issueCounters(o.issues),
    l4: l4Counters(o.l4),
    session: sessionStatus(o.session),
    lanes: laneReport(o.lanes),
    clamped: rows(o.clamped, clamped, MAX_SAMPLES),
    error: boundedOptStr(o.error, STR_MAX),
  };
}

/** The trimmed job view carried by `scan.list` rows and every push line. */
export function parseJobSummary(raw: unknown): JobSummary | null {
  const o = dict(raw);
  if (!o) return null;
  const job = idStr(o.job);
  const state = token(JOB_STATES, o.state);
  const phase = token(PHASES, o.phase);
  if (job === null || state === null || phase === null) return null;
  return {
    job,
    state,
    phase,
    elapsed_ms: num(o.elapsed_ms),
    probes: probeCounters(o.probes),
    points: pointCounters(o.points),
    issues: issueCounters(o.issues),
  };
}

/** `scan.start` and `scan.map`. */
export function parseStartResult(raw: unknown): StartResult | null {
  const o = dict(raw);
  if (!o) return null;
  const job = idStr(o.job);
  const status = parseJobStatus(o.status);
  if (job === null || status === null) return null;
  return {
    job,
    status,
    clamped: rows(o.clamped, clamped, MAX_SAMPLES),
    lanes: laneReport(o.lanes),
    // The key is absent for a profile with no L4 lane, and absent is not `false`.
    ...(typeof o.dry_run === 'boolean' ? { dry_run: o.dry_run } : {}),
  };
}

/** `scan.list`. */
export function parseListResult(raw: unknown): ListResult | null {
  const o = dict(raw);
  if (!o) return null;
  return { jobs: uniqueRows(o.jobs, parseJobSummary, (j) => j.job) };
}

/* ------------------------------------------------------------------ issue parsers */

function issueTarget(v: unknown): IssueTarget | null {
  const o = dict(v);
  if (!o) return null;
  const host = reqStr(o.host);
  if (host === null) return null;
  return { scheme: str(o.scheme), host, port: num(o.port) };
}

function l4Location(v: unknown): L4Location | null {
  const o = dict(v);
  if (!o) return null;
  const ip = reqStr(o.ip);
  const proto = token(L4_TRANSPORTS, o.proto);
  if (ip === null || proto === null) return null;
  return {
    ip,
    port: num(o.port),
    proto,
    grammar: optStr(o.grammar),
    field_path: optStr(o.field_path),
    mutation: optStr(o.mutation),
  };
}

function issueLocation(v: unknown): IssueLocation | null {
  const o = dict(v);
  if (!o) return null;
  const kind = token(INSERTION_KINDS, o.kind);
  if (kind === null) return null;
  return {
    method: optStr(o.method),
    path: str(o.path),
    path_template: str(o.path_template),
    kind,
    name: str(o.name),
    field_path: optStr(o.field_path),
    ws_path: optStr(o.ws_path),
    l4: l4Location(o.l4),
  };
}

function timing(v: unknown): Timing | null {
  const o = dict(v);
  if (!o) return null;
  return {
    requested_s: numList(o.requested_s),
    observed_ms: numList(o.observed_ms),
    baseline_ms: numList(o.baseline_ms),
    slope: signed(o.slope),
    r: signed(o.r),
  };
}

function diff(v: unknown): Diff | null {
  const o = dict(v);
  if (!o) return null;
  return { baseline_len: num(o.baseline_len), true_len: num(o.true_len), false_len: num(o.false_len) };
}

function l4Oracle(v: unknown): L4Oracle | null {
  const o = dict(v);
  if (!o) return null;
  switch (o.kind) {
    case 'protocol_error':
    case 'reset':
    case 'silence':
    case 'liveness_failed':
    case 'latency_outlier':
      return { kind: o.kind };
    case 'icmp':
      return { kind: 'icmp', type: num(o.type), code: num(o.code) };
    default:
      return null;
  }
}

function l4Evidence(v: unknown): L4Evidence | null {
  const o = dict(v);
  if (!o) return null;
  const oracle = l4Oracle(o.oracle);
  if (oracle === null) return null;
  const pair = numList(o.reproduced);
  return {
    sent_hex: str(o.sent_hex),
    seed_id: str(o.seed_id),
    rng_seed: num(o.rng_seed),
    mutation_chain: strList(o.mutation_chain),
    prior_messages: num(o.prior_messages),
    oracle,
    liveness_before: bool(o.liveness_before),
    liveness_after: bool(o.liveness_after),
    reproduced: [pair[0] ?? 0, pair[1] ?? 0],
    scope_entry: str(o.scope_entry),
  };
}

/** Absent evidence is empty evidence: an issue is worth showing even with nothing attached. */
function evidence(v: unknown): Evidence {
  const o = dict(v) ?? {};
  return {
    payload: optStr(o.payload),
    matched: optStr(o.matched),
    probe_flows: strList(o.probe_flows),
    baseline_flow: optId(o.baseline_flow),
    timing: timing(o.timing),
    diff: diff(o.diff),
    l4: l4Evidence(o.l4),
  };
}

/** The fields an `Issue` and an `IssueSummary` share; `null` when any required one is bad. */
function issueCore(raw: unknown): IssueSummary | null {
  const o = dict(raw);
  if (!o) return null;
  const id = idStr(o.id);
  const job = idStr(o.job);
  const severity = isSeverity(o.severity) ? o.severity : null;
  const confidence = token(CONFIDENCES, o.confidence);
  const status = token(ISSUE_STATUSES, o.status);
  const lane = token(LANES, o.lane);
  const target = issueTarget(o.target);
  const location = issueLocation(o.location);
  if (
    id === null ||
    job === null ||
    severity === null ||
    confidence === null ||
    status === null ||
    lane === null ||
    target === null ||
    location === null
  ) {
    return null;
  }
  return {
    id,
    job,
    jobs: idList(o.jobs),
    check_id: str(o.check_id),
    class: str(o.class),
    name: str(o.name),
    severity,
    confidence,
    status,
    lane,
    target,
    location,
    first_seen: num(o.first_seen),
    last_seen: num(o.last_seen),
    occurrences: num(o.occurrences),
    poc_ref: optStr(o.poc_ref),
    finding_id: optStr(o.finding_id),
  };
}

/** One row of `scan.issues`, and the `issue` of a push line. */
export function parseIssueSummary(raw: unknown): IssueSummary | null {
  return issueCore(raw);
}

/** `scan.issue` and `scan.issue.update`. */
export function parseIssue(raw: unknown): Issue | null {
  const core = issueCore(raw);
  if (core === null) return null;
  const o = dict(raw) ?? {};
  return {
    ...core,
    evidence: evidence(o.evidence),
    description: str(o.description),
    remediation: optStr(o.remediation),
    note: optStr(o.note),
  };
}

/** `scan.issues`. */
export function parseIssuesResult(raw: unknown): IssuesResult | null {
  const o = dict(raw);
  if (!o) return null;
  return {
    issues: uniqueRows(o.issues, parseIssueSummary, (i) => i.id, ISSUES_LIMIT),
    next_cursor: optStr(o.next_cursor),
    by_severity: bySeverity(o.by_severity),
  };
}

/* ------------------------------------------------------------------ site map parsers */

function paramRef(v: unknown): ParamRef | null {
  const o = dict(v);
  if (!o) return null;
  const kind = token(INSERTION_KINDS, o.kind);
  if (kind === null) return null;
  return { kind, name: str(o.name) };
}

/** One node of `scan.sitemap`. */
export function parseSiteNode(raw: unknown): SiteNode | null {
  const o = dict(raw);
  if (!o) return null;
  const id = idStr(o.id);
  const path_template = optStr(o.path_template);
  if (id === null || path_template === null) return null;
  return {
    id,
    method: str(o.method),
    scheme: str(o.scheme),
    host: str(o.host),
    port: num(o.port),
    path_template,
    flows: idList(o.flows),
    params: rows(o.params, paramRef),
    auth: bool(o.auth),
    points: num(o.points),
    audited: bool(o.audited),
  };
}

/** One insertion point of `scan.sitemap`. */
export function parseInsertionPoint(raw: unknown): InsertionPoint | null {
  const o = dict(raw);
  if (!o) return null;
  const id = idStr(o.id);
  const lane = token(LANES, o.lane);
  const kind = token(INSERTION_KINDS, o.kind);
  if (id === null || lane === null || kind === null) return null;
  return {
    id,
    lane,
    kind,
    name: str(o.name),
    path: optStr(o.path),
    example: optStr(o.example),
    flow: optId(o.flow),
    site_node: optId(o.site_node),
    traits: tokenList(POINT_TRAITS, o.traits),
    frequency: num(o.frequency),
    method: optStr(o.method),
    url: optStr(o.url),
  };
}

/** `scan.sitemap`. */
export function parseSitemapResult(raw: unknown): SitemapResult | null {
  const o = dict(raw);
  if (!o) return null;
  return {
    nodes: rows(o.nodes, parseSiteNode, SITEMAP_LIMIT),
    points: rows(o.points, parseInsertionPoint, SITEMAP_LIMIT),
    next_cursor: optStr(o.next_cursor),
  };
}

/* ------------------------------------------------------------------ check parsers */

function checkOrigin(v: unknown): CheckOrigin | null {
  const o = dict(v);
  if (!o) return null;
  if (o.kind === 'native') return { kind: 'native' };
  if (o.kind === 'bundled' || o.kind === 'custom') {
    const path = optStr(o.path);
    if (path === null) return null;
    return { kind: o.kind, path };
  }
  return null;
}

/** One check of `scan.checks`. */
export function parseCheckMeta(raw: unknown): CheckMeta | null {
  const o = dict(raw);
  if (!o) return null;
  const id = idStr(o.id);
  const intensity = token(INTENSITIES, o.intensity);
  const cost = token(CHECK_COSTS, o.cost);
  const technique = token(TECHNIQUES, o.technique);
  const severity = isSeverity(o.severity) ? o.severity : null;
  const confidence_max = token(CONFIDENCES, o.confidence_max);
  const origin = checkOrigin(o.origin);
  if (
    id === null ||
    intensity === null ||
    cost === null ||
    technique === null ||
    severity === null ||
    confidence_max === null ||
    origin === null
  ) {
    return null;
  }
  return {
    id,
    name: str(o.name),
    class: str(o.class),
    lanes: tokenList(LANES, o.lanes),
    kinds: tokenList(INSERTION_KINDS, o.kinds),
    intensity,
    cost,
    technique,
    severity,
    confidence_max,
    needs_baseline: bool(o.needs_baseline),
    wants_traits: Array.isArray(o.wants_traits) ? tokenList(POINT_TRAITS, o.wants_traits) : null,
    targets_session: bool(o.targets_session),
    cwe: optNum(o.cwe),
    description: str(o.description),
    remediation: optStr(o.remediation),
    origin,
  };
}

/** `scan.checks`. */
export function parseChecksResult(raw: unknown): ChecksResult | null {
  const o = dict(raw);
  if (!o) return null;
  return { checks: rows(o.checks, parseCheckMeta) };
}

/* ------------------------------------------------------------------ profile parsers */

function profileListEntry(v: unknown): ProfileListEntry | null {
  const o = dict(v);
  if (!o) return null;
  const name = idStr(o.name);
  const s = dict(o.summary);
  if (name === null || s === null) return null;
  const intensity = token(INTENSITIES, s.intensity);
  const speed = token(SPEEDS, s.speed);
  if (intensity === null || speed === null) return null;
  return {
    name,
    builtin: bool(o.builtin),
    summary: { lanes: tokenList(LANES, s.lanes), intensity, speed },
  };
}

/** `scan.profile.list`. */
export function parseProfileList(raw: unknown): ProfileListResult | null {
  const o = dict(raw);
  if (!o) return null;
  return { profiles: uniqueRows(o.profiles, profileListEntry, (p) => p.name) };
}

function l4TargetSpec(v: unknown): L4TargetSpec | null {
  const o = dict(v);
  if (!o) return null;
  const ip = reqStr(o.ip);
  const proto = strictToken(L4_TRANSPORTS, o.proto, 'tcp');
  if (ip === null || proto === null) return null;
  return { ip, port: num(o.port), proto, grammar: optStr(o.grammar) };
}

function ignoreRule(v: unknown): IgnoreRule | null {
  const o = dict(v);
  if (!o) return null;
  const kind = o.kind === undefined || o.kind === null ? null : token(INSERTION_KINDS, o.kind);
  if (o.kind !== undefined && o.kind !== null && kind === null) return null;
  const pointTrait = o.trait === undefined || o.trait === null ? null : token(POINT_TRAITS, o.trait);
  if (o.trait !== undefined && o.trait !== null && pointTrait === null) return null;
  return { kind, name_regex: optStr(o.name_regex), trait: pointTrait };
}

function l4Seed(v: unknown): L4Seed | null {
  const o = dict(v);
  if (!o) return null;
  const flow = optId(o.flow);
  const hex = optStr(o.hex);
  const base64 = optStr(o.base64);
  const given = [flow, hex, base64].filter((x) => x !== null);
  // Exactly one of the three, as `L4SeedRaw::try_from` requires.
  if (given.length !== 1) return null;
  if (flow !== null) return { flow };
  if (hex !== null) return { hex };
  return { base64: base64 as string };
}

/**
 * `scan.profile.get`, and any draft the editor round-trips.
 *
 * Unknown keys are dropped and a missing block takes the engine's default (`profile.rs`'s `Default`
 * impls), so a draft always comes back whole and can be sent to `scan.profile.save` as it stands.
 * Unlike the report parsers this one is strict about tokens: a value we cannot represent fails the
 * parse instead of vanishing from the operator's profile on the next save.
 */
export function parseScanProfile(raw: unknown): ScanProfile | null {
  const o = dict(raw);
  if (!o) return null;

  const lanes = strictRows<Lane>(o.lanes, (x) => token(LANES, x), ['http']);
  const intensity = strictToken(INTENSITIES, o.intensity, 'medium');
  const speed = strictToken(SPEEDS, o.speed, 'normal');
  const accuracy = strictToken(ACCURACIES, o.accuracy, 'normal');
  if (lanes === null || intensity === null || speed === null || accuracy === null) return null;

  const t = dict(o.target) ?? {};
  const l4Targets = strictRows(t.l4, l4TargetSpec, []);
  if (l4Targets === null) return null;

  const c = dict(o.checks) ?? {};
  const cr = dict(o.crawl) ?? {};
  const strategy = strictToken(CRAWL_STRATEGIES, cr.strategy, 'normal');
  const use_browser = strictToken(USE_BROWSER, cr.use_browser, 'auto');
  if (strategy === null || use_browser === null) return null;

  const a = dict(o.audit) ?? {};
  const kinds = strictRows(a.kinds, (x) => token(INSERTION_KINDS, x), [...INSERTION_KINDS]);
  const ignore = strictRows(a.ignore, ignoreRule, [{ kind: null, name_regex: null, trait: 'session' }]);
  if (kinds === null || ignore === null) return null;

  const s = dict(o.session) ?? {};
  const mode = strictToken(SESSION_MODES, s.mode, 'observed');
  const on_lost = strictToken(ON_LOST, s.on_lost, 'stop');
  if (mode === null || on_lost === null) return null;

  const b = dict(o.budget) ?? {};
  const phe = dict(b.per_host_errors) ?? {};

  const h = dict(o.http) ?? {};
  const version = strictToken(HTTP_VERSION_POLICIES, h.version, 'auto');
  const record_probes = strictToken(RECORD_PROBES, h.record_probes, 'issues_only');
  if (version === null || record_probes === null) return null;

  const w = dict(o.ws) ?? {};

  const l = dict(o.l4) ?? {};
  const seeds = strictRows(l.seeds, l4Seed, []);
  if (seeds === null) return null;

  return {
    name: str(o.name),
    target: { origins: strList(t.origins), l4: l4Targets },
    lanes,
    intensity,
    speed,
    accuracy,
    checks: { include: strList(c.include), exclude: strList(c.exclude) },
    crawl: {
      strategy,
      max_depth: num(cr.max_depth, 3),
      max_pages: num(cr.max_pages, 200),
      submit_forms: bool(cr.submit_forms, true),
      click_handlers: bool(cr.click_handlers, true),
      robots: bool(cr.robots, true),
      sitemap: bool(cr.sitemap, true),
      use_browser,
    },
    audit: {
      kinds,
      ignore,
      max_points_per_request: num(a.max_points_per_request, 64),
      frequent_point_threshold: num(a.frequent_point_threshold, 8),
    },
    session: { mode, from_flow: optId(s.from_flow), on_lost },
    budget: {
      probes: num(b.probes, 2000),
      time_s: num(b.time_s, 600),
      max_issues: num(b.max_issues, 1024),
      check_timeout_s: num(b.check_timeout_s, 60),
      per_host_errors: { consecutive: num(phe.consecutive, 10), ratio: num(phe.ratio, 0.5) },
    },
    http: { version, record_probes },
    ws: { reply_window_ms: num(w.reply_window_ms, 1500), max_frame_bytes: num(w.max_frame_bytes, 1048576) },
    l4: {
      cases: num(l.cases, 500),
      reproduce_count: num(l.reproduce_count, 3),
      liveness_every: num(l.liveness_every, 25),
      consecutive_timeouts: num(l.consecutive_timeouts, 20),
      max_bytes_per_s: num(l.max_bytes_per_s, 65536),
      seeds,
      dry_run: bool(l.dry_run),
    },
  };
}

/** `scan.profile.save`: the saved name and where the core wrote it. */
export function parseProfileSaveResult(raw: unknown): ProfileSaveResult | null {
  const o = dict(raw);
  if (!o) return null;
  const saved = idStr(o.saved);
  const path = reqStr(o.path);
  if (saved === null || path === null) return null;
  return { saved, path };
}

/** `scan.profile.delete`: whether anything was deleted. */
export function parseProfileDeleteResult(raw: unknown): ProfileDeleteResult | null {
  const o = dict(raw);
  if (!o || typeof o.deleted !== 'boolean') return null;
  return { deleted: o.deleted };
}

/** `scan.session.preview`. Names only: the wire carries no session value (D7). */
export function parseSessionProfile(raw: unknown): SessionProfile | null {
  const o = dict(raw);
  if (!o) return null;
  const origin = reqStr(o.origin);
  if (origin === null) return null;
  return {
    origin,
    cookies: strList(o.cookies),
    headers: strList(o.headers),
    source_flow: optId(o.source_flow),
    observed_at: num(o.observed_at),
    canary: canary(o.canary),
  };
}

/* ------------------------------------------------------------------ push line */

/** A `notifications/aitm/job` line. `null` for any job kind other than a scan. */
export function parseJobNotification(raw: unknown): JobNotification | null {
  const o = dict(raw);
  if (!o) return null;
  if (o.kind !== JOB_KIND_SCAN) return null;
  const job = idStr(o.job);
  const event = token(JOB_EVENTS, o.event);
  const status = parseJobSummary(o.status);
  if (job === null || event === null || status === null) return null;
  const issue = parseIssueSummary(o.issue);
  return {
    job,
    kind: JOB_KIND_SCAN,
    event,
    seq: num(o.seq),
    ts_ms: num(o.ts_ms),
    status,
    ...(issue !== null ? { issue } : {}),
  };
}

/* ------------------------------------------------------------------ errors */

/**
 * Split a core error string into its `ScanErrorCode` and detail, mirroring
 * `ScanErrorCode::parse_message` (`scan: <code>: <detail>`).
 *
 * A bridge may prefix the tool name (`scan.start: scan: busy: max_jobs`), so when the message does
 * not start with `scan: ` but contains it, parsing starts there. Anything else — an unknown code
 * included — comes back as `{ code: null, detail: <the whole message> }` so the operator still sees
 * what the core actually said.
 */
export function parseScanError(message: string): { code: ScanErrorCode | null; detail: string } {
  const start = message.startsWith('scan: ') ? 0 : message.indexOf('scan: ');
  if (start === -1) return { code: null, detail: message };
  const rest = message.slice(start + 'scan: '.length);
  const split = rest.indexOf(': ');
  if (split === -1) return { code: null, detail: message };
  const code = token(SCAN_ERROR_CODES, rest.slice(0, split));
  if (code === null) return { code: null, detail: message };
  return { code, detail: rest.slice(split + 2) };
}
