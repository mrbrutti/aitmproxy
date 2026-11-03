// The pure helpers of the v2 Scan surface: formatting, the fixed texts of D-T8.6/D-T8.7, the
// grouping and filtering the Issues view does client-side, the scope predicates the pre-flight
// uses, and the check-selection algebra the check tree writes.
//
// Fixtures (`crates/aitm-scan-model/fixtures/`) are read for *shapes* only, exactly as the fixture
// pack's README demands: nothing here is evidence that a scan found, reported or reproduced
// anything. T8's acceptance is the live run, never this suite.

import { describe, expect, it, vi } from 'vitest';

import type { L4ScopeEntryWire } from '~/panels/l4/model';

import {
  AGENT_DOT_HELP,
  AGENT_NOTE,
  CANCELLING_TITLE,
  CANCEL_SCAN_HELP,
  CONFIRM_NOTE,
  EMPTY_FILTER,
  GAUGE_LABEL,
  KPI_LABELS,
  L4_HINT,
  LANE_AUDIT_LABEL,
  LANE_CRAWL_LABEL,
  LEDGER_MARK_CAP,
  MISSING_VALUE,
  NO_JOBS_TEXT,
  PROFILE_NAME_HINT,
  SCAN_AGAIN_ERROR_PREFIX,
  SCAN_AGAIN_HELP_GENERIC,
  SHOW_ISSUES_HELP,
  SHOW_SITE_MAP_HELP,
  TABLE_HEADERS,
  WELL_CELL_SEPARATOR,
  WELL_CRAWL_SUBTITLE,
  WELL_CRAWL_TITLE,
  WELL_ISSUES_SUBTITLE,
  WELL_ISSUES_TITLE,
  WELL_KEY,
  WELL_KEYS,
  agentOriginated,
  applyCheckToggle,
  attention,
  budgetWarning,
  canaryWord,
  checkIsOn,
  checksToGo,
  clampedText,
  clock,
  crawlErrorWords,
  crawlTroubleLine,
  crawlTroubleText,
  elapsedWords,
  endSentence,
  estimateHelp,
  estimateText,
  filterIssues,
  findingLine,
  fmtElapsed,
  gaugeAccessibilityLabel,
  groupBySeverity,
  grouped,
  hostInScope,
  hostKey,
  hostsText,
  isLive,
  isStale,
  issuesSoFar,
  issuesTileHelp,
  jobAccessibilityLabel,
  jobFacts,
  jobHeading,
  jobHeadingHelp,
  jobProgress,
  jobsCaption,
  jobsCaptionFor,
  laneChecksDone,
  lanePages,
  ledgerGroups,
  linkBannerText,
  own,
  emptyRecord,
  isTerminal,
  isValidProfileName,
  jobTone,
  l4Covered,
  l4EntryCovers,
  mergeJob,
  needsConfirmNote,
  needsStatusRead,
  nodesByHost,
  notices,
  nowClause,
  ofText,
  originHost,
  paceEstimate,
  pointSkipWords,
  probeBudgetText,
  probesTileHelp,
  profileHasL4,
  profileText,
  progressAccessibilityValue,
  rawCrawlErrorLine,
  rawReasonLine,
  reasonLine,
  rowSubLine,
  sampleRowText,
  scaleElapsed,
  scaleStarted,
  scanAgainHelp,
  scanErrorText,
  severityWordParts,
  severityWords,
  skippedLaneText,
  skippedLaneWords,
  startedByWords,
  stateWords,
  stoppedReasonText,
  tone,
  unknownSelectors,
  wellRows,
  yesNo,
} from './helpers';
import type { JobFacts, Part, Tone } from './helpers';
import type {
  BySeverity,
  CheckSelection,
  CrawlCounters,
  JobState,
  JobStatus,
  JobSummary,
  Phase,
  StoppedReason,
} from './model';
import {
  parseChecksResult,
  parseIssuesResult,
  parseJobStatus,
  parseScanProfile,
  parseSitemapResult,
} from './model';

import { fixture } from './testkit';

const status = () => parseJobStatus(fixture('scan.status.json'))!;
const issueRows = () => parseIssuesResult(fixture('scan.issues.json'))!.issues;
const checks = () => parseChecksResult(fixture('scan.checks.json'))!.checks;
const profile = () => parseScanProfile(fixture('scan.profile.get.json'))!;

/** The fixture status (running · auditing, 0:42) with the case's fields over it. */
const statusWith = (over: Partial<JobStatus>): JobStatus => ({ ...status(), ...over });

/** A `scan.list` row cut from the fixture status, with the case's fields over it. */
const summaryWith = (over: Partial<JobSummary>): JobSummary => {
  const s = status();
  return {
    job: s.job,
    state: s.state,
    phase: s.phase,
    elapsed_ms: s.elapsed_ms,
    probes: s.probes,
    points: s.points,
    issues: s.issues,
    ...over,
  };
};

const crawlWith = (over: Partial<CrawlCounters>): CrawlCounters => ({ ...status().crawl, ...over });

const entry = (over: Partial<L4ScopeEntryWire> = {}): L4ScopeEntryWire => ({
  id: 'e',
  cidr: '127.0.0.0/8',
  ports: '0-65535',
  interface: '*',
  direction: 'outbound',
  capability: 'inject',
  inject_rate: { pps: 100, burst: 100 },
  ...over,
});

describe('job state predicates', () => {
  it('splits live from terminal states', () => {
    expect(isTerminal('done')).toBe(true);
    expect(isTerminal('cancelled')).toBe(true);
    expect(isTerminal('failed')).toBe(true);
    expect(isTerminal('queued')).toBe(false);
    expect(isTerminal('running')).toBe(false);
    expect(isTerminal('cancelling')).toBe(false);
    expect(isLive('running')).toBe(true);
    expect(isLive('cancelling')).toBe(true);
    expect(isLive('done')).toBe(false);
  });

  it('maps a state to a state-token tone', () => {
    expect(jobTone('done')).toBe('success');
    expect(jobTone('failed')).toBe('danger');
    expect(jobTone('running')).toBe('neutral');
    expect(jobTone('cancelled')).toBe('neutral');
  });

  it('prints the glossary word: the phase while running, else the state (P23)', () => {
    expect(stateWords({ state: 'running', phase: 'auditing' })).toBe('Auditing');
    expect(stateWords({ state: 'running', phase: 'crawling' })).toBe('Crawling');
    expect(stateWords({ state: 'done', phase: 'done' })).toBe('Done');
    expect(stateWords({ state: 'cancelling', phase: 'auditing' })).toBe('Cancelling');
    expect(stateWords({ state: 'queued', phase: 'queued' })).toBe('Queued');
    expect(stateWords({ state: 'cancelled', phase: 'auditing' })).toBe('Cancelled');
    expect(stateWords({ state: 'failed', phase: 'auditing' })).toBe('Failed');
  });
});

describe('needsStatusRead (D2 re-read rule, AC3)', () => {
  it('owes a read while nothing is stored or the list went terminal ahead of the stored status', () => {
    const running = statusWith({ state: 'running' });
    const done = statusWith({ state: 'done', phase: 'done' });
    const cancelled = statusWith({ state: 'cancelled', phase: 'auditing' });
    expect(needsStatusRead({ state: 'running' }, null)).toBe(true);
    expect(needsStatusRead({ state: 'done' }, running)).toBe(true);
    expect(needsStatusRead({ state: 'running' }, running)).toBe(false);
    expect(needsStatusRead({ state: 'done' }, done)).toBe(false);
    expect(needsStatusRead({ state: 'cancelled' }, cancelled)).toBe(false);
  });
});

describe('mergeJob (D2: one truth per job, AC4)', () => {
  it('a terminal list row beats a stored status still running', () => {
    const merged = mergeJob(
      summaryWith({ state: 'done', phase: 'done', elapsed_ms: 69_000 }),
      statusWith({ state: 'running', elapsed_ms: 65_000 }),
    );
    expect(merged.state).toBe('done');
    expect(merged.elapsed_ms).toBe(69_000);
  });

  it('with both live, the higher elapsed_ms wins (the status on a tie)', () => {
    const live = mergeJob(
      summaryWith({ state: 'running', elapsed_ms: 65_000 }),
      statusWith({ state: 'running', elapsed_ms: 66_000 }),
    );
    expect(live.elapsed_ms).toBe(66_000);
    const later = mergeJob(
      summaryWith({ state: 'running', elapsed_ms: 67_000 }),
      statusWith({ state: 'running', elapsed_ms: 66_000 }),
    );
    expect(later.elapsed_ms).toBe(67_000);
    const tie = mergeJob(
      summaryWith({ state: 'running', phase: 'crawling', elapsed_ms: 66_000 }),
      statusWith({ state: 'running', phase: 'auditing', elapsed_ms: 66_000 }),
    );
    expect(tie.phase).toBe('auditing');
  });

  it('a terminal status wins over a later live list row; no status leaves the row as is', () => {
    const merged = mergeJob(
      summaryWith({ state: 'running', elapsed_ms: 70_000 }),
      statusWith({ state: 'cancelled', elapsed_ms: 69_500 }),
    );
    expect(merged.state).toBe('cancelled');
    expect(merged.elapsed_ms).toBe(69_500);
    const row = summaryWith({ state: 'running', elapsed_ms: 70_000 });
    expect(mergeJob(row, null)).toEqual(row);
  });
});

describe('fmtElapsed', () => {
  it('prints m:ss under an hour and h:mm:ss above', () => {
    expect(fmtElapsed(42000)).toBe('0:42');
    expect(fmtElapsed(723000)).toBe('12:03');
    expect(fmtElapsed(3723000)).toBe('1:02:03');
    expect(fmtElapsed(0)).toBe('0:00');
  });
});

describe('isStale (W-5: counters never step backwards)', () => {
  it('drops a reply older than the held one and keeps a terminal reply', () => {
    const held = status();
    expect(held.elapsed_ms).toBe(42000);
    expect(isStale(held, { ...held, elapsed_ms: 41000 })).toBe(true);
    expect(isStale(held, { ...held, elapsed_ms: 41000, state: 'done' })).toBe(false);
    expect(isStale(held, { ...held, elapsed_ms: 42000 })).toBe(false);
    expect(isStale(held, { ...held, elapsed_ms: 43000 })).toBe(false);
  });
});

describe('stoppedReasonText (Jobs view D4; P4-P8)', () => {
  it('prints the eight reasons as D4 sentences, grouping the budget', () => {
    expect(stoppedReasonText('budget', 'done', 2000, null)).toBe(
      'Stopped early: the probe budget of 2,000 was spent. Raise it in the profile to go further.',
    );
    expect(stoppedReasonText('time', 'done', 2000, null)).toBe('Stopped early: the time budget ran out.');
    expect(stoppedReasonText('cancelled', 'done', 2000, null)).toBe('Stopped early: the job was cancelled.');
    expect(stoppedReasonText('session_lost', 'done', 2000, null)).toBe(
      'Stopped early: the session was lost and the profile says stop when that happens.',
    );
    expect(stoppedReasonText('errors', 'done', 2000, null)).toBe('Stopped early: too many errors from the target.');
    expect(stoppedReasonText('policy', 'done', 2000, null)).toBe(
      'Stopped early: the agent policy changed to paused or read-only.',
    );
    expect(stoppedReasonText('guard_refused', 'done', 2000, null)).toBe(
      'Stopped early: the L4 guard refused a target mid-run.',
    );
    expect(stoppedReasonText('failed', 'failed', 2000, null)).toBe('Stopped early: an error ended the job.');
    expect(stoppedReasonText('failed', 'failed', 2000, '')).toBe('Stopped early: an error ended the job.');
  });

  it('is null when the state sentence or the error already says it (P6, P7)', () => {
    expect(stoppedReasonText('cancelled', 'cancelled', 2000, null)).toBeNull();
    expect(stoppedReasonText('failed', 'failed', 2000, 'boom')).toBeNull();
  });

  it('names an unknown token as a reason this app does not know (P8)', () => {
    // The decoder maps an unknown token to null, so this branch is reached only by a cast.
    expect(stoppedReasonText('paused' as StoppedReason, 'done', 2000, null)).toBe(
      'Stopped early for a reason this app does not know.',
    );
  });

  it('prints the raw token for the data-face line (P9)', () => {
    expect(rawReasonLine('errors')).toBe('stopped_reason: errors');
    expect(rawReasonLine('guard_refused')).toBe('stopped_reason: guard_refused');
    expect(rawCrawlErrorLine('connect_refused')).toBe('crawl.last_error: connect_refused');
  });
});

describe('endSentence (Jobs view D4; P1-P3)', () => {
  const checks = (done: number, scheduled: number) => ({ ...status().checks, done, scheduled });

  it('Done in <elapsed> · <points> · <checks>.', () => {
    const s = statusWith({ state: 'done', phase: 'done', elapsed_ms: 69_000 });
    s.points = { ...s.points, found: 1020 };
    expect(endSentence(s, checks(6468, 6468))).toBe('Done in 1:09 · 1,020 points · 6,468 checks.');
  });

  it('Cancelled after <elapsed>; <done> of <scheduled> checks had run. What it found stays.', () => {
    const s = statusWith({ state: 'cancelled', elapsed_ms: 115_000 });
    expect(endSentence(s, checks(3236, 6468))).toBe(
      'Cancelled after 1:55; 3,236 of 6,468 checks had run. What it found stays.',
    );
  });

  it('Failed after <elapsed>.', () => {
    expect(endSentence(statusWith({ state: 'failed', elapsed_ms: 12_000 }), checks(3, 240))).toBe(
      'Failed after 0:12.',
    );
  });

  it('singulars: 1 point, 1 check', () => {
    const s = statusWith({ state: 'done', phase: 'done', elapsed_ms: 1_000 });
    s.points = { ...s.points, found: 1 };
    expect(endSentence(s, checks(1, 1))).toBe('Done in 0:01 · 1 point · 1 check.');
  });

  it('is null while the job is live and until a terminal status has landed', () => {
    expect(endSentence(statusWith({ state: 'running' }), checks(180, 240))).toBeNull();
    expect(endSentence(summaryWith({ state: 'cancelling' }), checks(180, 240))).toBeNull();
    expect(endSentence(summaryWith({ state: 'done', phase: 'done', elapsed_ms: 69_000 }), null)).toBeNull();
  });
});

describe('crawlTroubleText / crawlErrorWords (Jobs view D4; P10-P14)', () => {
  it('counts the pages and the errors with singulars; null with no error', () => {
    expect(crawlTroubleText(crawlWith({ pages: 1, errors: 1 }))).toBe('The crawl fetched 1 page and hit 1 error');
    expect(crawlTroubleText(crawlWith({ pages: 46, errors: 2 }))).toBe('The crawl fetched 46 pages and hit 2 errors');
    expect(crawlTroubleText(crawlWith({ pages: 0, errors: 1 }))).toBe('The crawl fetched 0 pages and hit 1 error');
    expect(crawlTroubleText(crawlWith({ pages: 37, errors: 0 }))).toBeNull();
  });

  it('words every last_error token; transport, other and an unknown token read as a failed connection', () => {
    expect(crawlErrorWords('connect_refused')).toBe('the target refused the connection');
    expect(crawlErrorWords('tls')).toBe('TLS handshake failed');
    expect(crawlErrorWords('timeout')).toBe('the target did not answer in time');
    expect(crawlErrorWords('h2_not_negotiated')).toBe('the target does not speak HTTP/2');
    expect(crawlErrorWords('transport')).toBe('the connection failed');
    expect(crawlErrorWords('other')).toBe('the connection failed');
    expect(crawlErrorWords('x')).toBe('the connection failed');
  });
});

describe('grouped (the en-US thousands comma of D4 and D11)', () => {
  it('groups every three digits and leaves small numbers alone', () => {
    expect(grouped(6468)).toBe('6,468');
    expect(grouped(1020)).toBe('1,020');
    expect(grouped(1234567)).toBe('1,234,567');
    expect(grouped(0)).toBe('0');
    expect(grouped(999)).toBe('999');
  });
});

describe('scanErrorText (D-T8.6, W-3)', () => {
  it('prints every code and passes an unknown code through verbatim', () => {
    expect(scanErrorText('out_of_scope', 'host x')).toBe('Out of scope: host x');
    expect(scanErrorText('refused_agent', 'd')).toMatch(
      /^Agent session: the core refuses active scans unless scanner\.allow_agent_active is set; intrusive is operator-only/,
    );
    expect(scanErrorText('refused_l4', 'no permit')).toBe(
      'L4 refused: no permit (l4.enabled, scanner.allow_agent_l4_fuzz, l4.allow_agent_inject)',
    );
    expect(scanErrorText('lane_unavailable', 'ws')).toBe(
      'No requested lane is available on this build: ws',
    );
    expect(scanErrorText('busy', 'max_jobs')).toBe(
      'Busy: max_jobs (max_jobs or an origin already being scanned)',
    );
    expect(scanErrorText('invalid_profile', 'budget.probes')).toBe(
      'Invalid profile: budget.probes',
    );
    expect(scanErrorText('unknown_check', 'nope')).toBe('Unknown check: nope');
    expect(scanErrorText('confirm_required', 'token')).toBe('Confirmation required');
    expect(scanErrorText('not_found', 'scan-1')).toBe('Not found: scan-1');
    expect(scanErrorText(null, 'raw')).toBe('raw');
  });
});

describe('fixed texts', () => {
  it('L4_HINT is the D11 sentence verbatim', () => {
    expect(L4_HINT).toBe(
      'The L4 stream lane needs an L4 scope entry with interface: "*", direction: outbound, the target CIDR and port range, and the Inject capability.',
    );
    expect(L4_HINT).toContain('interface: "*"');
  });

  it('CONFIRM_NOTE and AGENT_NOTE are the D-T8.6 sentences', () => {
    expect(CONFIRM_NOTE).toBe('The core will ask for confirmation.');
    expect(AGENT_NOTE).toBe(
      'Agent session: the core refuses active scans unless scanner.allow_agent_active is set; intrusive is operator-only',
    );
  });
});

describe('isValidProfileName (the engine’s saved-profile name rule)', () => {
  it('accepts lowercase names of 1-64 chars from [a-z0-9._-] starting with a letter or digit', () => {
    expect(isValidProfileName('my-api')).toBe(true);
    expect(isValidProfileName('a')).toBe(true);
    expect(isValidProfileName('x.y_z-1')).toBe(true);
    expect(isValidProfileName('a'.repeat(64))).toBe(true);
  });

  it('refuses empty, uppercase, a leading separator, 65 chars, and a space', () => {
    expect(isValidProfileName('')).toBe(false);
    expect(isValidProfileName('My-API')).toBe(false);
    expect(isValidProfileName('-x')).toBe(false);
    expect(isValidProfileName('a'.repeat(65))).toBe(false);
    expect(isValidProfileName('has space')).toBe(false);
  });

  it('PROFILE_NAME_HINT is the one sentence the editor shows', () => {
    expect(PROFILE_NAME_HINT).toBe(
      'lowercase letters, digits, . _ - ; 1-64 characters, starting with a letter or digit',
    );
  });
});

describe('groupBySeverity', () => {
  it('groups critical -> info and omits empty groups', () => {
    expect(groupBySeverity(issueRows()).map((g) => [g.severity, g.rows.length])).toEqual([
      ['high', 1],
      ['medium', 1],
    ]);
    expect(groupBySeverity([])).toEqual([]);
  });
});

describe('filterIssues', () => {
  it('an empty filter keeps every row', () => {
    expect(filterIssues(issueRows(), EMPTY_FILTER)).toHaveLength(2);
  });

  it('filters on the free text across name, path_template and point name', () => {
    const byText = filterIssues(issueRows(), { ...EMPTY_FILTER, text: 'redirect' });
    expect(byText).toHaveLength(1);
    expect(byText[0]!.id).toBe('issue-4c3b2a19');
    expect(filterIssues(issueRows(), { ...EMPTY_FILTER, text: '/SEARCH' })).toHaveLength(1);
    expect(filterIssues(issueRows(), { ...EMPTY_FILTER, text: 'next' })).toHaveLength(1);
    expect(filterIssues(issueRows(), { ...EMPTY_FILTER, text: 'nothing here' })).toHaveLength(0);
  });

  it('filters on confidence, lane, class and status', () => {
    expect(
      filterIssues(issueRows(), { ...EMPTY_FILTER, confidence: new Set(['certain']) }),
    ).toHaveLength(1);
    expect(filterIssues(issueRows(), { ...EMPTY_FILTER, lanes: new Set(['http']) })).toHaveLength(2);
    expect(filterIssues(issueRows(), { ...EMPTY_FILTER, lanes: new Set(['ws']) })).toHaveLength(0);
    expect(
      filterIssues(issueRows(), { ...EMPTY_FILTER, classes: new Set(['open-redirect']) }),
    ).toHaveLength(1);
    expect(
      filterIssues(issueRows(), { ...EMPTY_FILTER, statuses: new Set(['false_positive']) }),
    ).toHaveLength(0);
  });
});

describe('site map hosts', () => {
  it('prints host:port unless the port is the scheme default', () => {
    expect(hostKey({ scheme: 'http', host: '127.0.0.1', port: 8080 })).toBe('127.0.0.1:8080');
    expect(hostKey({ scheme: 'http', host: 'shop.test', port: 80 })).toBe('shop.test');
    expect(hostKey({ scheme: 'https', host: 'shop.test', port: 443 })).toBe('shop.test');
    expect(hostKey({ scheme: 'https', host: 'shop.test', port: 80 })).toBe('shop.test:80');
  });

  it('groups the fixture nodes by host', () => {
    const nodes = parseSitemapResult(fixture('scan.sitemap.json'))!.nodes;
    const groups = nodesByHost(nodes);
    expect(groups[0]!.host).toBe('127.0.0.1:8080');
    expect(groups[0]!.nodes).toHaveLength(1);
    expect(groups).toHaveLength(1);
  });
});

describe('originHost / hostInScope', () => {
  it('reads the host and the explicit port out of an origin', () => {
    expect(originHost('http://127.0.0.1:8080')).toEqual({ host: '127.0.0.1', port: 8080 });
    expect(originHost('https://api.shop.test')).toEqual({ host: 'api.shop.test', port: null });
    expect(originHost('nonsense')).toBeNull();
  });

  it('matches an exact host, host:port or a *.suffix entry', () => {
    expect(hostInScope('http://127.0.0.1:8080', [{ host: '127.0.0.1' }])).toBe(true);
    expect(hostInScope('http://127.0.0.1:8080', [{ host: '127.0.0.1:8080' }])).toBe(true);
    expect(hostInScope('http://127.0.0.1:8080', [{ host: '127.0.0.1:9' }])).toBe(false);
    expect(hostInScope('https://api.shop.test', [{ host: '*.shop.test' }])).toBe(true);
    expect(hostInScope('https://api.shop.test', [{ host: '*.other.test' }])).toBe(false);
    expect(hostInScope('nonsense', [{ host: '*' }])).toBe(false);
    expect(hostInScope('http://127.0.0.1:8080', [])).toBe(false);
  });
});

describe('l4EntryCovers / l4Covered (W-9)', () => {
  it('covers only an outbound inject entry on a wildcard interface', () => {
    expect(l4EntryCovers(entry(), '127.0.0.1', 9)).toBe(true);
    expect(l4EntryCovers(entry({ capability: 'capture' }), '127.0.0.1', 9)).toBe(false);
    expect(l4EntryCovers(entry({ direction: 'inbound' }), '127.0.0.1', 9)).toBe(false);
    expect(l4EntryCovers(entry({ interface: 'lo0' }), '127.0.0.1', 9)).toBe(false);
    expect(l4EntryCovers(entry({ ports: '80-80' }), '127.0.0.1', 9)).toBe(false);
    expect(l4EntryCovers(entry({ ports: '9' }), '127.0.0.1', 9)).toBe(true);
    expect(l4EntryCovers(entry({ cidr: '10.0.0.0/8' }), '127.0.0.1', 9)).toBe(false);
  });

  it('answers unknown for an address or a CIDR it cannot judge', () => {
    expect(l4EntryCovers(entry(), '::1', 9)).toBeNull();
    expect(l4EntryCovers(entry({ cidr: 'garbage' }), '127.0.0.1', 9)).toBeNull();
  });

  it('folds entries: any true wins, all false is false, otherwise unknown', () => {
    expect(l4Covered([], '127.0.0.1', 9)).toBe(false);
    expect(l4Covered([entry()], '127.0.0.1', 9)).toBe(true);
    expect(l4Covered([entry({ capability: 'capture' })], '127.0.0.1', 9)).toBe(false);
    expect(l4Covered([entry({ cidr: 'garbage' }), entry()], '127.0.0.1', 9)).toBe(true);
    expect(l4Covered([entry({ cidr: 'garbage' })], '127.0.0.1', 9)).toBeNull();
    expect(l4Covered([entry()], '::1', 9)).toBeNull();
  });
});

describe('profileHasL4 / needsConfirmNote', () => {
  it('notes a confirmation for an L4 lane or an intrusive intensity', () => {
    const p = profile();
    expect(profileHasL4(p)).toBe(false);
    expect(needsConfirmNote(p)).toBe(false);
    expect(profileHasL4({ ...p, lanes: ['http', 'l4_stream'] })).toBe(true);
    expect(needsConfirmNote({ ...p, lanes: ['http', 'l4_stream'] })).toBe(true);
    expect(needsConfirmNote({ ...p, intensity: 'intrusive' })).toBe(true);
    expect(needsConfirmNote({ ...p, intensity: 'medium' })).toBe(false);
  });
});

describe('applyCheckToggle / checkIsOn (the check-tree algebra)', () => {
  const empty: CheckSelection = { include: [], exclude: [] };

  it('writes exclude while include is empty', () => {
    const one = applyCheckToggle(empty, { id: 'http.sqli-error' }, false, checks());
    expect(one).toEqual({ include: [], exclude: ['http.sqli-error'] });
    expect(checkIsOn(one, checks()[1]!)).toBe(false);
    expect(checkIsOn(one, checks()[0]!)).toBe(true);

    const two = applyCheckToggle(one, { class: 'sqli-error' }, false, checks());
    expect(two).toEqual({ include: [], exclude: ['sqli-error'] });
    expect(checkIsOn(two, checks()[1]!)).toBe(false);

    const lane = applyCheckToggle(empty, { lane: 'http' }, false, checks());
    expect(lane.exclude).toEqual(['http:*']);
    expect(checkIsOn(lane, checks()[0]!)).toBe(false);
    expect(checkIsOn(lane, checks()[2]!)).toBe(false);
  });

  it('edits include once include is non-empty', () => {
    const sel = applyCheckToggle(
      { include: ['http.reflected-xss'], exclude: [] },
      { id: 'http.sqli-error' },
      true,
      checks(),
    );
    expect(sel.include).toEqual(['http.reflected-xss', 'http.sqli-error']);
    expect(checkIsOn(sel, checks()[1]!)).toBe(true);
    expect(checkIsOn(sel, checks()[2]!)).toBe(false);
  });

  it('rewrites an excluded lane as its other ids when one id is turned back on', () => {
    const lane = applyCheckToggle(empty, { lane: 'http' }, false, checks());
    const back = applyCheckToggle(lane, { id: 'http.sqli-error' }, true, checks());
    expect(back).toEqual({
      include: [],
      exclude: ['http.reflected-xss', 'http.custom-marker'],
    });
    expect(checkIsOn(back, checks()[1]!)).toBe(true);
    expect(checkIsOn(back, checks()[0]!)).toBe(false);
  });

  it('an empty include means every check, a lane selector matches its lane', () => {
    expect(checkIsOn({ include: [], exclude: [] }, checks()[0]!)).toBe(true);
    expect(checkIsOn({ include: ['http:*'], exclude: [] }, checks()[0]!)).toBe(true);
    expect(checkIsOn({ include: ['ws:*'], exclude: [] }, checks()[0]!)).toBe(false);
    expect(
      checkIsOn({ include: ['http:*'], exclude: ['http.reflected-xss'] }, checks()[0]!),
    ).toBe(false);
  });
});

describe('unknownSelectors', () => {
  it('names only the selectors no check matches', () => {
    expect(unknownSelectors({ include: ['nope'], exclude: ['sqli-error'] }, checks())).toEqual([
      'nope',
    ]);
    expect(
      unknownSelectors({ include: ['http:*', 'http.custom-marker'], exclude: [] }, checks()),
    ).toEqual([]);
    expect(unknownSelectors({ include: ['l4_stream:*'], exclude: ['x.y'] }, checks())).toEqual([
      'l4_stream:*',
      'x.y',
    ]);
  });
});

describe('own / emptyRecord (A5: wire-keyed records never read Object.prototype)', () => {
  it('own answers only an own property, never a prototype one', () => {
    const r: Record<string, number> = { a: 1 };
    expect(own(r, 'a')).toBe(1);
    expect(own(r, 'b')).toBeUndefined();
    expect(own(r, 'constructor')).toBeUndefined();
    expect(own(r, 'hasOwnProperty')).toBeUndefined();
    expect(own(r, '__proto__')).toBeUndefined();
  });

  it('emptyRecord has no prototype, so a wire key like "constructor" starts undefined', () => {
    const r = emptyRecord<number>();
    expect(Object.getPrototypeOf(r)).toBeNull();
    expect(r['constructor']).toBeUndefined();
    r['constructor'] = 2;
    expect(own(r, 'constructor')).toBe(2);
  });
});

/* ------------------------------------------------------------------ Jobs view W2: the Kit's words (D18 W2, D21, AC36) */

// Every literal below is copied from `apps/mac/Tests/AitmproxyKitTests/ScanSurfaceTests.swift`
// (plan Task 3.5's table; the parity pin P15–P23 verbatim). The mac Kit is the reference; the web
// re-derives nothing. The comp's job: `standard` on 127.0.0.1:8117, 3,236 of 6,468 checks, four
// running ids, 4 low issues, started 11:32 Lisbon by this web UI (`client_label: null`).

const FOUR_IDS = ['xss-reflected', 'sqli-error', 'open-redirect', 'ssrf'];
const LISBON = 'Europe/Lisbon';
/** 2026-07-01T10:32:00Z: `11:32` in Lisbon (WEST, UTC+1), so the zone is exercised, not assumed. */
const STARTED_AT_1132 = 1_782_901_920_000;
/** One minute later: `11:33`. */
const FINISHED_AT_1133 = 1_782_901_980_000;

const tally = (over: Partial<BySeverity> = {}): BySeverity => ({
  critical: 0,
  high: 0,
  medium: 0,
  low: 0,
  info: 0,
  ...over,
});

/** The `scan.list` row a status implies: the shared counters, nothing else. */
const rowOf = (s: JobStatus): JobSummary => ({
  job: s.job,
  state: s.state,
  phase: s.phase,
  elapsed_ms: s.elapsed_ms,
  probes: s.probes,
  points: s.points,
  issues: s.issues,
});

/**
 * The Kit's `progressFacts`: the fixture status re-stated with a state, a phase, an elapsed time
 * and the case's fields, under a list row that agrees on all three.
 */
function facts(state: JobState, phase: Phase, over: Partial<JobStatus> = {}, elapsed_ms = 64_000): JobFacts {
  const st = statusWith({ state, phase, elapsed_ms, ...over });
  return jobFacts(rowOf(st), st);
}

/** A list row the status has not landed for. */
function unread(state: JobState, phase: Phase): JobFacts {
  return jobFacts(rowOf(statusWith({ state, phase, elapsed_ms: 64_000 })), null);
}

const checksOf = (done: number, scheduled: number, running: string[] = []) => ({
  ...status().checks,
  done,
  scheduled,
  running,
});

const issuesOf = (by: Partial<BySeverity>) => {
  const by_severity = tally(by);
  const total = by_severity.critical + by_severity.high + by_severity.medium + by_severity.low + by_severity.info;
  return { ...status().issues, total, by_severity };
};

/** The comp's job: one target on 8117, started at 11:32 Lisbon, by this web UI (no client label). */
const COMP_JOB: Partial<JobStatus> = {
  targets: ['http://127.0.0.1:8117'],
  started_at: STARTED_AT_1132,
  started_by: { frontend: 'operator', client_label: null },
};

/** The AC32 sweep: 7 states (an unknown one cast in) × 6 phases, plus one unread row: 43 facts. */
function ac32Sweep(): JobFacts[] {
  const out: JobFacts[] = [];
  const states = ['queued', 'running', 'cancelling', 'done', 'cancelled', 'failed', 'paused' as JobState] as const;
  const phases: Phase[] = ['queued', 'crawling', 'passive', 'auditing', 'reporting', 'done'];
  for (const state of states) {
    for (const phase of phases) {
      out.push(
        facts(state, phase, {
          ...COMP_JOB,
          checks: { ...checksOf(3236, 6468, FOUR_IDS), errors: 7, skipped: 3 },
          crawl: { ...status().crawl, errors: 1 },
          issues: issuesOf({ high: 1, low: 4 }),
          error: 'boom',
        }),
      );
    }
  }
  out.push(unread('running', 'auditing'));
  return out;
}

describe('jobFacts (D18 W2: the web ScanJobFacts)', () => {
  it('holds the merged summary and the status as given', () => {
    const st = statusWith({ state: 'running', elapsed_ms: 66_000 });
    const f = jobFacts(summaryWith({ state: 'running', elapsed_ms: 65_000 }), st);
    expect(f.summary.elapsed_ms).toBe(66_000);
    expect(f.status).toBe(st);
    const none = jobFacts(summaryWith({ state: 'running' }), null);
    expect(none.status).toBeNull();
    expect(none.summary.state).toBe('running');
  });
});

describe('jobProgress (D8 and its amendment; P15–P22)', () => {
  it('P15: auditing, 3,236 of 6,468 checks', () => {
    const p = jobProgress(facts('running', 'auditing', { checks: checksOf(3236, 6468, FOUR_IDS) }));
    expect(p.fraction).not.toBeNull();
    expect(Math.abs(p.fraction! - 0.5003)).toBeLessThan(0.0001);
    expect(typeof p.ring === 'object' && 'determinate' in p.ring).toBe(true);
    expect(p.percentText).toBe('50 %');
    expect(p.phaseLine).toBe('3,236 of 6,468 checks');
    expect(p.helpText).toBe("3,236 of 6,468 checks (derived from the engine's counters)");
    // P22: four ids.
    expect(p.nowLine).toBe('Now: xss-reflected and 3 more');
    expect(p.nowTag).toBe('now · xss-reflected and 3 more');
    expect(p.checksToGoText).toBe('3,232 checks to go');
    expect(p.estimateText).toBe('at this pace, about 1:04 to go');
    expect(p.estimateHelp).toBe(
      'Derived from the counters: 3,236 checks done in 1:04, about 51 checks per second, 3,232 to go.',
    );
    // The percent floors: 6,467 of 6,468 is still 99 %, never 100 % before done == scheduled.
    expect(jobProgress(facts('running', 'auditing', { checks: checksOf(6467, 6468) })).percentText).toBe('99 %');
    expect(jobProgress(facts('running', 'auditing', { checks: checksOf(6468, 6468) })).percentText).toBe('100 %');
  });

  it('P16: crawling, 46 pages and 12 queued', () => {
    const p = jobProgress(facts('running', 'crawling', { crawl: crawlWith({ pages: 46, queued: 12 }) }));
    expect(Math.abs(p.fraction! - 0.7931)).toBeLessThan(0.0001);
    expect(p.percentText).toBe('79 %');
    expect(p.phaseLine).toBe('46 pages, 12 queued');
    expect(p.helpText).toBe("46 of 58 pages (derived from the engine's counters)");
    const onePage = jobProgress(facts('running', 'crawling', { crawl: crawlWith({ pages: 1, queued: 0 }) }));
    expect(onePage.phaseLine).toBe('1 page, 0 queued');
    expect(onePage.fraction).toBe(1);
    const noPages = jobProgress(facts('running', 'crawling', { crawl: crawlWith({ pages: 0, queued: 0 }) }));
    expect(noPages.ring).toBe('indeterminate');
    expect(noPages.fraction).toBeNull();
    expect(noPages.phaseLine).toBe('0 pages, 0 queued');
    expect(noPages.helpText).toBe('Progress is not known yet');
  });

  it('P17: passive', () => {
    const p = jobProgress(facts('running', 'passive'));
    expect(p.ring).toBe('indeterminate');
    expect(p.fraction).toBeNull();
    expect(p.percentText).toBeNull();
    expect(p.phaseLine).toBe('Passive checks over captured traffic');
    expect(p.helpText).toBe('Progress is not known yet');
  });

  it('P18: reporting', () => {
    const p = jobProgress(facts('running', 'reporting', { checks: checksOf(6468, 6468) }));
    expect(p.ring).toEqual({ determinate: 1 });
    expect(p.fraction).toBe(1);
    expect(p.percentText).toBe('100 %');
    expect(p.phaseLine).toBe('Writing results');
    expect(p.helpText).toBe("6,468 of 6,468 checks (derived from the engine's counters)");
  });

  it('P19: queued, whatever the phase and the counters', () => {
    const p = jobProgress(facts('queued', 'queued', { checks: checksOf(10, 20) }));
    expect(p.ring).toBe('indeterminate');
    expect(p.fraction).toBeNull();
    expect(p.percentText).toBeNull();
    expect(p.phaseLine).toBe('Waiting for the engine to start this job.');
    expect(p.helpText).toBe('Progress is not known yet');
    const noStatus = jobProgress(unread('queued', 'queued'));
    expect(noStatus.ring).toBe('indeterminate');
    expect(noStatus.phaseLine).toBe('Waiting for the engine to start this job.');
    expect(noStatus.nowLine).toBeNull();
  });

  it('P20: auditing with nothing scheduled yet', () => {
    const p = jobProgress(facts('running', 'auditing', { checks: checksOf(0, 0) }));
    expect(p.ring).toBe('indeterminate');
    expect(p.fraction).toBeNull();
    expect(p.percentText).toBeNull();
    expect(p.phaseLine).toBe('Scheduling checks');
    expect(p.helpText).toBe('Progress is not known yet');
  });

  it('P21: cancelled keeps the final fraction in a finished ring, with no percent', () => {
    const p = jobProgress(facts('cancelled', 'done', { checks: checksOf(3236, 6468) }, 115_000));
    expect(typeof p.ring === 'object' && 'finished' in p.ring).toBe(true);
    const finished = (p.ring as { finished: number | null }).finished;
    expect(Math.abs(finished! - 0.5003)).toBeLessThan(0.0001);
    expect(p.fraction).toBeNull();
    expect(p.percentText).toBeNull();
    expect(p.phaseLine).toBe('');
    expect(p.helpText).toBe("3,236 of 6,468 checks (derived from the engine's counters)");
    // A finished job whose checks never scheduled falls back to the crawl; one with neither has no fraction.
    const failedCrawl = jobProgress(
      facts('failed', 'done', { checks: checksOf(0, 0), crawl: crawlWith({ pages: 3, queued: 1 }) }, 12_000),
    );
    expect(Math.abs((failedCrawl.ring as { finished: number | null }).finished! - 0.75)).toBeLessThan(0.0001);
    expect(failedCrawl.helpText).toBe("3 of 4 pages (derived from the engine's counters)");
    const failedEmpty = jobProgress(
      facts('failed', 'done', { checks: checksOf(0, 0), crawl: crawlWith({ pages: 0, queued: 0 }) }, 12_000),
    );
    expect(failedEmpty.ring).toEqual({ finished: null });
    expect(failedEmpty.fraction).toBeNull();
    expect(failedEmpty.phaseLine).toBe('');
    expect(failedEmpty.helpText).toBe('Progress is not known yet');
    const doneNoStatus = jobProgress(unread('done', 'done'));
    expect(doneNoStatus.ring).toEqual({ finished: null });
    expect(doneNoStatus.phaseLine).toBe('');
  });

  it('cancelling runs the rule for its phase; P22 for one id', () => {
    const p = jobProgress(facts('cancelling', 'auditing', { checks: checksOf(3236, 6468, ['xss-reflected']) }));
    expect(Math.abs(p.fraction! - 0.5003)).toBeLessThan(0.0001);
    expect(p.percentText).toBe('50 %');
    expect(p.phaseLine).toBe('3,236 of 6,468 checks');
    expect(p.nowLine).toBe('Now: xss-reflected');
    expect(p.nowTag).toBe('now · xss-reflected');
  });

  it('running without a status yet: indeterminate, the phase word', () => {
    const p = jobProgress(unread('running', 'auditing'));
    expect(p.ring).toBe('indeterminate');
    expect(p.fraction).toBeNull();
    expect(p.percentText).toBeNull();
    expect(p.phaseLine).toBe('Auditing');
    expect(p.helpText).toBe('Progress is not known yet');
    expect(p.nowLine).toBeNull();
    expect(p.nowTag).toBeNull();
    expect(jobProgress(unread('running', 'crawling')).phaseLine).toBe('Crawling');
  });

  it('P22: no id in flight, two ids', () => {
    const idle = jobProgress(facts('running', 'auditing', { checks: checksOf(3236, 6468, []) }));
    expect(idle.nowLine).toBeNull();
    expect(idle.nowTag).toBeNull();
    const two = jobProgress(facts('running', 'auditing', { checks: checksOf(1, 2, ['a', 'b']) }));
    expect(two.nowLine).toBe('Now: a and 1 more');
    expect(two.nowTag).toBe('now · a and 1 more');
  });

  it('an unknown state has no ring and reads the state as it came', () => {
    const p = jobProgress(facts('paused' as JobState, 'auditing'));
    expect(p.ring).toBe('none');
    expect(p.fraction).toBeNull();
    expect(p.percentText).toBeNull();
    expect(p.phaseLine).toBe('paused');
    expect(p.helpText).toBe('Progress is not known yet');
  });

  it('rowText: the twelve AC54 forms', () => {
    const row = (f: JobFacts) => jobProgress(f).rowText;
    expect(row(facts('running', 'auditing', { checks: checksOf(3236, 6468, FOUR_IDS) }))).toBe('50 % · 3,236 of 6,468');
    expect(row(facts('running', 'crawling', { crawl: crawlWith({ pages: 46, queued: 12 }) }))).toBe('46 pages, 12 queued');
    expect(row(facts('running', 'passive'))).toBe('Passive checks');
    expect(row(facts('running', 'auditing', { checks: checksOf(0, 0) }))).toBe('Scheduling checks');
    expect(row(facts('running', 'reporting', { checks: checksOf(6468, 6468) }))).toBe('Writing results');
    expect(row(facts('queued', 'queued'))).toBe('—');
    expect(row(facts('done', 'done', { checks: checksOf(6468, 6468) }))).toBe('6,468 of 6,468');
    expect(row(facts('cancelled', 'done', { checks: checksOf(3236, 6468) }))).toBe('3,236 of 6,468');
    expect(row(facts('done', 'done', { checks: checksOf(0, 0) }))).toBe('0 of 0');
    expect(row(facts('cancelling', 'auditing', { checks: checksOf(3236, 6468) }))).toBe('50 % · 3,236 of 6,468');
    expect(row(unread('done', 'done'))).toBe('—');
    expect(row(unread('running', 'auditing'))).toBe('—');
    // The floor, the clamp and a zero schedule.
    expect(row(facts('running', 'auditing', { checks: checksOf(3233, 6468) }))).toBe('49 % · 3,233 of 6,468');
    expect(row(facts('running', 'auditing', { checks: checksOf(7000, 6468) }))).toBe('100 % · 7,000 of 6,468');
    expect(row(facts('done', 'done', { checks: checksOf(7000, 6468) }))).toBe('7,000 of 6,468');
    expect(row(facts('running', 'auditing', { checks: checksOf(5, 0) }))).toBe('Scheduling checks');
    expect(row(facts('failed', 'done', { checks: checksOf(5, 0) }))).toBe('5 of 0');
    expect(row(facts('cancelling', 'crawling', { crawl: crawlWith({ pages: 46, queued: 12 }) }))).toBe('46 pages, 12 queued');
  });

  it('rowText over the sweep: — unread, queued and unknown; the live form by phase; the checks when terminal', () => {
    const liveByPhase: Record<string, string> = {
      queued: 'Queued',
      crawling: '37 pages, 0 queued',
      passive: 'Passive checks',
      auditing: '50 % · 3,236 of 6,468',
      reporting: 'Writing results',
      done: 'Done',
    };
    let seen = 0;
    for (const f of ac32Sweep()) {
      const s = f.summary.state as string;
      let expected: string;
      if (f.status === null || s === 'queued' || s === 'paused') expected = '—';
      else if (s === 'running' || s === 'cancelling') expected = liveByPhase[f.summary.phase]!;
      else expected = '3,236 of 6,468';
      expect(jobProgress(f).rowText, `${s} / ${f.summary.phase}`).toBe(expected);
      seen += 1;
    }
    expect(seen).toBe(43);
  });

  it('nowTagParts (AC56): now · , the first id as checkId, and n more', () => {
    const four = jobProgress(facts('running', 'auditing', { checks: checksOf(3236, 6468, FOUR_IDS) }));
    expect(four.nowTagParts).toEqual<Part[]>([
      { text: 'now · ', role: 'plain' },
      { text: 'xss-reflected', role: 'checkId' },
      { text: ' and 3 more', role: 'plain' },
    ]);
    const one = jobProgress(facts('running', 'auditing', { checks: checksOf(3236, 6468, ['xss-reflected']) }));
    expect(one.nowTagParts).toEqual<Part[]>([
      { text: 'now · ', role: 'plain' },
      { text: 'xss-reflected', role: 'checkId' },
    ]);
    const two = jobProgress(facts('running', 'auditing', { checks: checksOf(3236, 6468, ['a', 'b']) }));
    expect(two.nowTagParts!.map((p) => p.text)).toEqual(['now · ', 'a', ' and 1 more']);
    const none = jobProgress(facts('running', 'auditing', { checks: checksOf(3236, 6468, []) }));
    expect(none.nowTagParts).toBeNull();
    expect(none.nowTag).toBeNull();
    for (const f of ac32Sweep()) {
      const p = jobProgress(f);
      const joined = p.nowTagParts === null ? null : p.nowTagParts.map((x) => x.text).join('');
      expect(joined, `${f.summary.state} / ${f.summary.phase}`).toBe(p.nowTag);
    }
    const reporting = jobProgress(facts('running', 'reporting', { checks: checksOf(6468, 6468, ['xss-reflected']) }));
    expect(reporting.nowTagParts!.map((p) => p.text)).toEqual(['now · ', 'xss-reflected']);
    expect(reporting.phaseLine).toBe('Writing results');
  });

  it('checksToGoText and the estimate live only on a running audit', () => {
    const scheduling = jobProgress(facts('running', 'auditing', { checks: checksOf(0, 0) }));
    expect(scheduling.estimateText).toBeNull();
    expect(scheduling.estimateHelp).toBeNull();
    expect(scheduling.checksToGoText).toBeNull();
    const complete = jobProgress(facts('running', 'auditing', { checks: checksOf(6468, 6468) }));
    expect(complete.estimateText).toBeNull();
    expect(complete.checksToGoText).toBeNull();
    const crawling = jobProgress(
      facts('running', 'crawling', { checks: checksOf(3236, 6468), crawl: crawlWith({ pages: 46, queued: 12 }) }),
    );
    expect(crawling.estimateText).toBeNull();
    expect(crawling.checksToGoText).toBeNull();
    expect(jobProgress(facts('running', 'passive', { checks: checksOf(3236, 6468) })).estimateText).toBeNull();
    expect(jobProgress(facts('queued', 'queued', { checks: checksOf(3236, 6468) })).checksToGoText).toBeNull();
    const cancelling = jobProgress(facts('cancelling', 'auditing', { checks: checksOf(3236, 6468) }));
    expect(cancelling.estimateText).toBeNull();
    expect(cancelling.estimateHelp).toBeNull();
    expect(cancelling.checksToGoText).toBeNull();
    const cancelled = jobProgress(facts('cancelled', 'done', { checks: checksOf(3236, 6468) }, 115_000));
    expect(cancelled.estimateText).toBeNull();
    expect(cancelled.checksToGoText).toBeNull();
    expect(jobProgress(unread('running', 'auditing')).estimateText).toBeNull();
    const reportingDone = jobProgress(facts('running', 'reporting', { checks: checksOf(6468, 6468) }));
    expect(reportingDone.estimateText).toBeNull();
    expect(reportingDone.checksToGoText).toBeNull();
    const reportingShort = jobProgress(facts('running', 'reporting', { checks: checksOf(6467, 6468) }));
    expect(reportingShort.estimateText).toBeNull();
    expect(reportingShort.checksToGoText).toBe('1 check to go');
  });
});

describe('paceEstimate / checksToGo / estimateText / estimateHelp (D8 amendment, AC44)', () => {
  it('derives the pace from two counters over the elapsed time', () => {
    expect(paceEstimate(3236, 6468, 64_000)).toEqual({ secondsToGo: 64, checksPerSecond: 50.5625 });
    const fast = paceEstimate(500_000, 600_000, 100_000)!;
    expect(fast.checksPerSecond).toBe(5000);
    expect(fast.secondsToGo).toBe(20);
    expect(estimateText(fast)).toBe('at this pace, about 0:20 to go');
    expect(estimateHelp(500_000, 100_000, fast, 100_000)).toBe(
      'Derived from the counters: 500,000 checks done in 1:40, about 5,000 checks per second, 100,000 to go.',
    );
  });

  it('is null when no rate can be derived', () => {
    expect(paceEstimate(0, 6468, 10_000)).toBeNull();
    expect(paceEstimate(3236, 6468, 0)).toBeNull();
    expect(paceEstimate(6468, 6468, 90_000)).toBeNull();
    expect(paceEstimate(3236, 0, 64_000)).toBeNull();
    expect(paceEstimate(7000, 6468, 64_000)).toBeNull();
    expect(paceEstimate(3236, 6468, -5)).toBeNull();
    // The seconds to go past the decoder's ceiling (2^53 ms): no estimate rather than nonsense.
    expect(paceEstimate(1, Number.MAX_SAFE_INTEGER, 1_000_000_000)).toBeNull();
  });

  it('words the rate: about 1 check per second, fewer than 1 check per second', () => {
    const one = paceEstimate(10, 20, 10_000)!;
    expect(one.checksPerSecond).toBe(1);
    expect(one.secondsToGo).toBe(10);
    expect(estimateText(one)).toBe('at this pace, about 0:10 to go');
    expect(estimateHelp(10, 10_000, one, 10)).toBe(
      'Derived from the counters: 10 checks done in 0:10, about 1 check per second, 10 to go.',
    );
    const slow = paceEstimate(1, 100, 10_000)!;
    expect(Math.abs(slow.checksPerSecond - 0.1)).toBeLessThan(0.001);
    expect(slow.secondsToGo).toBe(990);
    expect(estimateText(slow)).toBe('at this pace, about 16:30 to go');
    expect(estimateHelp(1, 10_000, slow, 99)).toBe(
      'Derived from the counters: 1 check done in 0:10, fewer than 1 check per second, 99 to go.',
    );
    expect(estimateHelp(1, 64_000, paceEstimate(1, 6468, 64_000)!, 6467)).toBe(
      'Derived from the counters: 1 check done in 1:04, fewer than 1 check per second, 6,467 to go.',
    );
    expect(paceEstimate(2, 5, 1_000)!.secondsToGo).toBe(2);
    expect(estimateText(paceEstimate(1, 3601, 1_000)!)).toBe('at this pace, about 1:00:00 to go');
  });

  it('checksToGo: grouped, singular, absent when nothing is scheduled or nothing is left', () => {
    expect(checksToGo(3236, 6468)).toBe('3,232 checks to go');
    expect(checksToGo(6467, 6468)).toBe('1 check to go');
    expect(checksToGo(6468, 6468)).toBeNull();
    expect(checksToGo(0, 0)).toBeNull();
    expect(checksToGo(0, 6468)).toBe('6,468 checks to go');
    expect(checksToGo(7000, 6468)).toBeNull();
  });
});

describe('the states table: stateWords + tone per state (P23, AC45)', () => {
  it('reads the glossary word and the tone for every state', () => {
    const table: [JobState, Phase, string, Tone][] = [
      ['queued', 'queued', 'Queued', 'progress'],
      ['running', 'crawling', 'Crawling', 'progress'],
      ['running', 'auditing', 'Auditing', 'progress'],
      ['cancelling', 'auditing', 'Cancelling', 'pending'],
      ['done', 'done', 'Done', 'success'],
      ['cancelled', 'done', 'Cancelled', 'neutral'],
      ['failed', 'done', 'Failed', 'danger'],
    ];
    for (const [state, phase, word, expectedTone] of table) {
      const f = facts(state, phase);
      expect(stateWords(f.summary), `${state}/${phase}`).toBe(word);
      expect(tone(f), `${state}/${phase}`).toBe(expectedTone);
    }
    expect(stateWords(facts('running', 'passive').summary)).toBe('Passive');
    expect(stateWords(unread('running', 'crawling').summary)).toBe('Crawling');
    expect(tone(facts('paused' as JobState, 'auditing'))).toBe('neutral');
    expect(stateWords(facts('paused' as JobState, 'auditing').summary)).toBe('paused');
  });
});

describe('profileText / hostsText / jobHeading / jobHeadingHelp (D10, D11)', () => {
  it('reads the profile and the hosts, — until the status lands', () => {
    const f = facts('running', 'auditing', COMP_JOB);
    expect(profileText(f)).toBe('standard');
    expect(profileText(unread('running', 'auditing'))).toBe('—');
    expect(profileText(facts('running', 'auditing', { profile_name: '' }))).toBe('—');
    expect(hostsText(f)).toBe('127.0.0.1:8117');
    expect(hostsText(unread('running', 'auditing'))).toBe('—');
    expect(hostsText(facts('running', 'auditing', { targets: ['https://a.test', 'http://b.test:8080/x'] }))).toBe(
      'a.test, b.test:8080',
    );
    expect(hostsText(facts('running', 'auditing', { targets: ['HTTP://User@A.Test/', 'nonsense'] }))).toBe(
      'a.test, nonsense',
    );
  });

  it('heads the card with the hosts, cut to and n more from three on', () => {
    expect(jobHeading(facts('running', 'auditing', COMP_JOB))).toBe('127.0.0.1:8117');
    expect(jobHeadingHelp(facts('running', 'auditing', COMP_JOB))).toBeNull();
    const two = facts('running', 'auditing', { targets: ['http://a.test', 'http://b.test'] });
    expect(jobHeading(two)).toBe('a.test, b.test');
    expect(jobHeadingHelp(two)).toBeNull();
    const three = facts('running', 'auditing', { targets: ['http://a.test', 'http://b.test', 'https://c.test:8443'] });
    expect(jobHeading(three)).toBe('a.test and 2 more');
    expect(jobHeadingHelp(three)).toBe('a.test, b.test, c.test:8443');
    expect(jobHeading(facts('running', 'auditing', { targets: [] }))).toBe('—');
    expect(jobHeading(unread('running', 'auditing'))).toBe('—');
  });
});

describe('startedByWords / agentOriginated / clock (D11; gap 48)', () => {
  it('names who started the job, with this app only for the surface own label', () => {
    expect(startedByWords({ frontend: 'operator', client_label: null })).toBe('the operator');
    expect(startedByWords({ frontend: 'operator', client_label: '' })).toBe('the operator');
    expect(startedByWords({ frontend: '', client_label: null })).toBe('the operator');
    expect(startedByWords({ frontend: 'cli', client_label: null })).toBe('the CLI');
    expect(startedByWords({ frontend: 'mcp', client_label: null })).toBe('an agent');
    expect(startedByWords({ frontend: 'agent', client_label: 'x' })).toBe('an agent');
    expect(startedByWords({ frontend: 'operator', client_label: 'aitm-tui' })).toBe('aitm-tui');
    // The web has no own label: a mac-started job reads its label, never `this app`.
    expect(startedByWords({ frontend: 'operator', client_label: 'aitm-mac' })).toBe('aitm-mac');
    expect(startedByWords({ frontend: 'operator', client_label: 'aitm-mac' }, 'aitm-mac')).toBe('this app');
    expect(startedByWords({ frontend: 'operator', client_label: 'aitm-tui' }, 'aitm-mac')).toBe('aitm-tui');
    expect(startedByWords({ frontend: 'operator', client_label: 'web\u0000-ui\u202E' })).toBe('web-ui');
    expect(startedByWords({ frontend: 'operator', client_label: 'a'.repeat(50) })).toBe('a'.repeat(40));
    expect(startedByWords({ frontend: 'operator', client_label: `${'a'.repeat(50)}\u0007` })).toBe('a'.repeat(40));
  });

  it('agentOriginated is the mcp and agent frontends', () => {
    expect(agentOriginated({ frontend: 'mcp', client_label: null })).toBe(true);
    expect(agentOriginated({ frontend: 'agent', client_label: null })).toBe(true);
    expect(agentOriginated({ frontend: 'cli', client_label: null })).toBe(false);
    expect(agentOriginated({ frontend: 'operator', client_label: 'aitm-mac' })).toBe(false);
  });

  it('clock is 24-hour HH:mm in the given zone', () => {
    expect(clock(STARTED_AT_1132, LISBON)).toBe('11:32');
    expect(clock(STARTED_AT_1132, 'UTC')).toBe('10:32');
    expect(clock(1_768_467_900_000, LISBON)).toBe('09:05');
    expect(clock(1_768_467_900_000 + 14 * 3_600_000, LISBON)).toBe('23:05');
    expect(scaleStarted('11:32')).toBe('started 11:32');
    expect(scaleElapsed(64_000)).toBe('elapsed 1:04');
  });

  it('clock builds one Intl.DateTimeFormat per zone and reuses it (gap 79)', () => {
    const spy = vi.spyOn(Intl, 'DateTimeFormat');
    try {
      // A zone no earlier test touched, so the cache cannot already hold it.
      expect(clock(STARTED_AT_1132, 'Pacific/Auckland')).toBe('22:32');
      expect(clock(STARTED_AT_1132 + 60_000, 'Pacific/Auckland')).toBe('22:33');
      expect(spy).toHaveBeenCalledTimes(1);
      expect(clock(STARTED_AT_1132, 'America/New_York')).toBe('06:32');
      expect(spy).toHaveBeenCalledTimes(2);
    } finally {
      spy.mockRestore();
    }
  });
});

describe('issuesSoFar / nowClause / findingLine (D11, AC36)', () => {
  it('the clauses on their own', () => {
    expect(issuesSoFar(tally({ high: 1, low: 4 }))).toBe('5 issues so far: 1 high, 4 low');
    expect(issuesSoFar(tally({ high: 1 }))).toBe('1 high issue so far');
    expect(issuesSoFar(tally({ low: 4 }))).toBe('4 low issues so far');
    expect(issuesSoFar(tally())).toBe('no issues so far');
    expect(nowClause([])).toBeNull();
    expect(nowClause(['xss-reflected'])).toBe('xss-reflected running now');
    expect(nowClause(FOUR_IDS)).toBe('xss-reflected and 3 more checks running now');
    expect(nowClause(['a', 'b'])).toBe('a and 1 more check running now');
  });

  it('live, web-started: issues · now · profile · started by the operator', () => {
    const live = facts('running', 'auditing', {
      ...COMP_JOB,
      checks: checksOf(3236, 6468, FOUR_IDS),
      issues: issuesOf({ low: 4 }),
    });
    const line = findingLine(live, LISBON);
    expect(line.text).toBe(
      '4 low issues so far · xss-reflected and 3 more checks running now · standard · started 11:32 by the operator',
    );
    expect(line.reason).toBeNull();
    expect(line.agentOriginated).toBe(false);
    expect(line.parts.map((p) => p.text).join('')).toBe(line.text);
    expect(line.parts).toContainEqual<Part>({ text: '4', role: 'figure' });
    expect(line.parts).toContainEqual<Part>({ text: 'xss-reflected', role: 'checkId' });
    expect(line.parts.some((p) => p.role === 'agent')).toBe(false);
  });

  it('by an agent: the mcp frontend, with an agent part', () => {
    const agent = facts('running', 'auditing', {
      ...COMP_JOB,
      checks: checksOf(3236, 6468, FOUR_IDS),
      issues: issuesOf({ low: 4 }),
      started_by: { frontend: 'mcp', client_label: 'claude-desktop' },
    });
    const line = findingLine(agent, LISBON);
    expect(line.text.endsWith(' · started 11:32 by an agent')).toBe(true);
    expect(line.agentOriginated).toBe(true);
    expect(line.parts).toContainEqual<Part>({ text: 'an agent', role: 'agent' });
  });

  it('by the CLI, one id, no issues; nothing running omits the clause; a mac-started job reads aitm-mac', () => {
    const cli = facts('running', 'auditing', {
      ...COMP_JOB,
      checks: checksOf(10, 6468, ['xss-reflected']),
      issues: issuesOf({}),
      started_by: { frontend: 'cli', client_label: null },
    });
    expect(findingLine(cli, LISBON).text).toBe(
      'no issues so far · xss-reflected running now · standard · started 11:32 by the CLI',
    );
    const idle = facts('queued', 'queued', { ...COMP_JOB, checks: checksOf(0, 0), issues: issuesOf({}) });
    expect(findingLine(idle, LISBON).text).toBe('no issues so far · standard · started 11:32 by the operator');
    const mac = facts('running', 'auditing', {
      ...COMP_JOB,
      started_by: { frontend: 'operator', client_label: 'aitm-mac' },
    });
    expect(findingLine(mac, LISBON).text.endsWith(' by aitm-mac')).toBe(true);
    const tui = facts('running', 'auditing', {
      ...COMP_JOB,
      started_by: { frontend: 'operator', client_label: 'aitm-tui' },
    });
    expect(findingLine(tui, LISBON).text.endsWith(' by aitm-tui')).toBe(true);
  });

  it('terminal: the reason above, then profile · started · finished', () => {
    const stopped = facts('done', 'done', {
      ...COMP_JOB,
      checks: checksOf(240, 240),
      issues: issuesOf({ low: 4 }),
      stopped_reason: 'errors',
      finished_at: FINISHED_AT_1133,
    });
    const line = findingLine(stopped, LISBON);
    expect(line.reason).toBe('Stopped early: too many errors from the target.');
    expect(line.text).toBe('standard · started 11:32 by the operator · finished 11:33');
    expect(line.agentOriginated).toBe(false);
    expect(line.parts.map((p) => p.text).join('')).toBe(line.text);
    const plainDone = facts('done', 'done', { ...COMP_JOB, finished_at: FINISHED_AT_1133 });
    expect(findingLine(plainDone, LISBON).reason).toBeNull();
    const noFinish = facts('failed', 'done', { ...COMP_JOB, error: 'boom' });
    expect(findingLine(noFinish, LISBON).text).toBe('standard · started 11:32 by the operator');
    const cancelled = facts('cancelled', 'done', { ...COMP_JOB, stopped_reason: 'cancelled' });
    expect(findingLine(cancelled, LISBON).reason).toBeNull();
    const noStart = facts('running', 'auditing', {
      ...COMP_JOB,
      started_at: 0,
      checks: checksOf(1, 2, []),
      issues: issuesOf({}),
    });
    expect(findingLine(noStart, LISBON).text).toBe('no issues so far · standard · started by the operator');
  });

  it('no status yet: only what the list row says', () => {
    expect(findingLine(unread('running', 'auditing'), LISBON).text).toBe('3 issues so far: 1 high, 1 medium, 1 low');
    expect(findingLine(unread('done', 'done'), LISBON)).toEqual({ reason: null, parts: [], text: '', agentOriginated: false });
  });

  it('reason is reasonLine over the sweep', () => {
    for (const f of ac32Sweep()) {
      expect(findingLine(f, LISBON).reason, `${f.summary.state} / ${f.summary.phase}`).toBe(reasonLine(f));
    }
  });
});

describe('ledgerGroups / severityWordParts / severityWords (D11, D21; AC45, AC53)', () => {
  it('one group per non-zero severity, critical → info, marks capped at 12', () => {
    expect(ledgerGroups(tally({ low: 4 }))).toEqual([{ severity: 'low', count: 4, marks: 4, word: '4 low' }]);
    expect(ledgerGroups(tally({ high: 1, low: 4 })).map((g) => g.severity)).toEqual(['high', 'low']);
    expect(ledgerGroups(tally({ high: 1, low: 4 })).map((g) => g.word)).toEqual(['1 high', '4 low']);
    const many = ledgerGroups(tally({ low: 30 }));
    expect(many).toHaveLength(1);
    expect(many[0]!.marks).toBe(12);
    expect(many[0]!.count).toBe(30);
    expect(many[0]!.word).toBe('30 low');
    expect(ledgerGroups(tally())).toEqual([]);
    expect(ledgerGroups(tally({ critical: 1, high: 2, medium: 3, low: 4, info: 5 })).map((g) => g.severity)).toEqual([
      'critical',
      'high',
      'medium',
      'low',
      'info',
    ]);
    expect(LEDGER_MARK_CAP).toBe(12);
  });

  it('severityWordParts is the ledger mapped to (severity, word)', () => {
    const three = tally({ critical: 2, medium: 1, info: 5 });
    const parts = severityWordParts(three);
    expect(parts.map((p) => p.word)).toEqual(['2 critical', '1 medium', '5 info']);
    expect(parts.map((p) => p.severity)).toEqual(['critical', 'medium', 'info']);
    for (const by of [three, tally({ high: 1, low: 3 }), tally({ low: 30 }), tally()]) {
      expect(severityWordParts(by).map((p) => p.word)).toEqual(ledgerGroups(by).map((g) => g.word));
      expect(severityWordParts(by).map((p) => p.severity)).toEqual(ledgerGroups(by).map((g) => g.severity));
    }
    expect(severityWordParts(tally({ low: 1200 })).map((p) => p.word)).toEqual(['1,200 low']);
    expect(severityWordParts(tally())).toEqual([]);
  });

  it('severityWords joins the parts; no issues yet while live, no issues otherwise', () => {
    expect(severityWords(tally({ low: 4 }), true)).toBe('4 low');
    expect(severityWords(tally({ high: 1, low: 3 }), false)).toBe('1 high, 3 low');
    expect(severityWords(tally(), true)).toBe('no issues yet');
    expect(severityWords(tally(), false)).toBe('no issues');
    expect(severityWords(tally({ critical: 2, medium: 1, info: 5 }), true)).toBe('2 critical, 1 medium, 5 info');
  });
});

describe('budgetWarning / probeBudgetText / gaugeAccessibilityLabel / probesTileHelp / issuesTileHelp (AC45)', () => {
  it('the gauge turns amber past 80 % of a known budget', () => {
    expect(budgetWarning(1601, 2000)).toBe(true);
    expect(budgetWarning(1600, 2000)).toBe(false);
    expect(budgetWarning(5, 0)).toBe(false);
  });

  it('the probe words', () => {
    expect(probeBudgetText(287, 2000)).toBe('287 of 2,000');
    expect(probeBudgetText(287, 0)).toBe('287 probes');
    expect(probeBudgetText(1, 0)).toBe('1 probe');
    expect(gaugeAccessibilityLabel(287, 2000)).toBe('Probe budget, 287 of 2,000');
    expect(gaugeAccessibilityLabel(287, 0)).toBe('Probe budget, 287 probes');
    expect(probesTileHelp(287, 2000)).toBe('287 of 2,000 probes sent (the probe budget, not progress)');
    expect(probesTileHelp(287, 0)).toBe('287 probes sent (the probe budget, not progress)');
  });

  it('the issues help', () => {
    expect(issuesTileHelp(tally({ high: 1, low: 3 }))).toBe('4 issues: 1 high, 3 low');
    expect(issuesTileHelp(tally({ low: 4 }))).toBe('4 issues: 4 low');
    expect(issuesTileHelp(tally({ high: 1 }))).toBe('1 issue: 1 high');
    expect(issuesTileHelp(tally())).toBe('no issues');
    expect(issuesTileHelp(tally({ critical: 2, medium: 1, info: 5 }))).toBe('8 issues: 2 critical, 1 medium, 5 info');
  });
});

describe('ofText / laneChecksDone / lanePages / scaleStarted / scaleElapsed (D11)', () => {
  it('the lane and KPI unit words', () => {
    expect(ofText(6468)).toBe('of 6,468');
    expect(laneChecksDone(3236)).toBe('3,236 checks done');
    expect(laneChecksDone(1)).toBe('1 check done');
    expect(lanePages(46)).toBe('46 pages');
    expect(lanePages(1)).toBe('1 page');
    expect(scaleStarted('11:32')).toBe('started 11:32');
    expect(scaleElapsed(64_000)).toBe('elapsed 1:04');
  });
});

describe('pointSkipWords / wellRows (D11, D21; AC51, AC52)', () => {
  it('pointSkipWords: frequent, ignored, limit in that order, zeros included', () => {
    const words = pointSkipWords({ ignored: 6, frequent: 722, limit: 0 });
    expect(words).toEqual([
      { count: 722, words: 'skipped as repetitive', text: '722 skipped as repetitive' },
      { count: 6, words: 'skipped by rule', text: '6 skipped by rule' },
      { count: 0, words: 'skipped at the per-request cap', text: '0 skipped at the per-request cap' },
    ]);
    expect(pointSkipWords({ ignored: 1200, frequent: 0, limit: 3 }).map((w) => w.text)).toEqual([
      '0 skipped as repetitive',
      '1,200 skipped by rule',
      '3 skipped at the per-request cap',
    ]);
  });

  /** AC51's running auditing job. */
  const ac51 = (): JobFacts =>
    facts('running', 'auditing', {
      points: { found: 1020, queued: 923, audited: 97, skipped: { frequent: 722, ignored: 6, limit: 0 } },
      probes: { ...status().probes, by_lane: { ws: 47, http: 240 }, errors: 0, timeouts: 3, rate_waits: 1 },
      issues: { total: 5, by_severity: tally({ high: 1, low: 4 }), by_confidence: { certain: 1, firm: 2, tentative: 2 } },
      crawl: { pages: 46, queued: 12, depth: 3, forms_submitted: 5, forms_skipped: 2, errors: 1, last_error: null },
      lanes: {
        requested: ['http', 'ws', 'l4_stream'],
        run: ['http', 'ws'],
        skipped: [{ lane: 'l4_stream', reason: 'no L4 scope entry' }],
      },
      l4: { cases: 1024, crashes: 0, liveness_failures: 2, retired_elements: 7 },
      checks: { ...status().checks, scheduled: 6468, done: 3236, errors: 7, skipped: 3 },
    });

  it('AC51: the crawl rows in D11 order, one cell per value, every cell in its ink', () => {
    const rows = wellRows(ac51());
    expect(rows.crawl.map((r) => `${r.key} = ${r.text}`)).toEqual([
      'Pages fetched = 46',
      'Pages waiting = 12',
      'Depth = 3',
      'Forms submitted = 5',
      'Forms not submitted = 2',
      'Crawl errors = 1',
      'Points found = 1,020',
      'Waiting for audit = 923',
      'Audited = 97',
      'skipped as repetitive = 722',
      'skipped by rule = 6',
      'skipped at the per-request cap = 0',
      'Lanes = HTTP, WebSocket',
      'Lane skipped = L4 stream: no L4 scope entry',
      'Probes by lane = HTTP 240 · WebSocket 47',
      'Session = yes · no · ok · no',
      'L4 cases = 1,024',
      'L4 crashes = 0',
      'L4 liveness failures = 2',
      'L4 retired elements = 7',
    ]);
    expect(rows.crawl.every((r) => r.cells.every((c) => c.ink === 'value'))).toBe(true);
    const probesRow = rows.crawl.find((r) => r.key === WELL_KEY.probesByLane)!;
    expect(probesRow.cells.map((c) => c.text)).toEqual(['HTTP 240', 'WebSocket 47']);
    expect(rows.crawl.find((r) => r.key === WELL_KEY.session)!.cells.map((c) => c.text)).toEqual(['yes', 'no', 'ok', 'no']);
    expect(rows.crawl.find((r) => r.key === WELL_KEY.lanes)!.cells).toHaveLength(1);
    expect(WELL_CELL_SEPARATOR).toBe(' · ');
  });

  it('AC51: the issue rows with their inks', () => {
    const rows = wellRows(ac51());
    expect(rows.issues.map((r) => `${r.key} = ${r.text}`)).toEqual([
      'Critical · High · Medium = 0 · 1 · 0',
      'Low = 4',
      'Info = 0',
      'Certain · Firm · Tentative = 1 · 2 · 2',
      'Probe errors · timeouts · rate waits = 0 · 3 · 1',
      'Checks scheduled · done · errors · skipped = 6,468 · 3,236 · 7 · 3',
    ]);
    expect(rows.issues[0]!.cells.map((c) => c.ink)).toEqual(['muted', { severity: 'high' }, 'muted']);
    expect(rows.issues[1]!.cells.map((c) => c.ink)).toEqual([{ severity: 'low' }]);
    expect(rows.issues[2]!.cells.map((c) => c.ink)).toEqual(['muted']);
    expect(rows.issues[3]!.cells.map((c) => c.ink)).toEqual(['value', 'value', 'value']);
    expect(rows.issues[4]!.cells.map((c) => c.ink)).toEqual(['value', 'value', 'value']);
    expect(rows.issues[5]!.cells.map((c) => c.ink)).toEqual(['value', 'value', 'value', 'value']);
    expect(rows.issues[5]!.cells.map((c) => c.text)).toEqual(['6,468', '3,236', '7', '3']);
  });

  it('AC51: no status yet: the status-only values read —, the conditional rows are absent', () => {
    const rows = wellRows(jobFacts(ac51().summary, null));
    expect(rows.crawl.map((r) => `${r.key} = ${r.text}`)).toEqual([
      'Pages fetched = —',
      'Pages waiting = —',
      'Depth = —',
      'Forms submitted = —',
      'Forms not submitted = —',
      'Points found = 1,020',
      'Waiting for audit = 923',
      'Audited = 97',
      'skipped as repetitive = 722',
      'skipped by rule = 6',
      'skipped at the per-request cap = 0',
      'Lanes = —',
      'Probes by lane = HTTP 240 · WebSocket 47',
    ]);
    expect(rows.issues.map((r) => r.text)).toEqual(['0 · 1 · 0', '4', '0', '1 · 2 · 2', '0 · 3 · 1', '—']);
    expect(rows.issues[5]!.cells).toEqual([{ text: '—', ink: 'value' }]);
  });

  it('the fixture as it is, and the edges: every severity inked, a seven-figure count grouped, no lanes', () => {
    const fixture = wellRows(facts('running', 'auditing'));
    const keys = fixture.crawl.map((r) => r.key);
    expect(keys).not.toContain(WELL_KEY.crawlErrors);
    expect(keys).not.toContain(WELL_KEY.l4Cases);
    expect(fixture.crawl.find((r) => r.key === WELL_KEY.laneSkipped)!.text).toBe('WebSocket: lane not available on this build');
    expect(fixture.crawl.find((r) => r.key === WELL_KEY.lanes)!.text).toBe('HTTP');
    expect(fixture.crawl.find((r) => r.key === WELL_KEY.probesByLane)!.text).toBe('HTTP 418');

    const edges = wellRows(
      facts('running', 'auditing', {
        points: { ...status().points, found: 1_234_567 },
        probes: { ...status().probes, by_lane: { ws: 47, http: 240, l4_packet: 9, l4_stream: 2 } },
        issues: issuesOf({ critical: 2, high: 1, medium: 1, low: 3, info: 4 }),
        lanes: { requested: [], run: [], skipped: [] },
      }),
    );
    expect(edges.crawl.find((r) => r.key === WELL_KEY.probesByLane)!.text).toBe(
      'HTTP 240 · WebSocket 47 · L4 packet 9 · L4 stream 2',
    );
    expect(edges.crawl.find((r) => r.key === WELL_KEY.lanes)!.text).toBe('—');
    expect(edges.crawl.map((r) => r.key)).not.toContain(WELL_KEY.laneSkipped);
    expect(edges.crawl.find((r) => r.key === WELL_KEY.pointsFound)!.text).toBe('1,234,567');
    expect(edges.issues[0]!.cells.map((c) => c.ink)).toEqual([
      { severity: 'critical' },
      { severity: 'high' },
      { severity: 'medium' },
    ]);
    expect(edges.issues[0]!.text).toBe('2 · 1 · 1');
    expect(edges.issues[1]!.cells).toEqual([{ text: '3', ink: { severity: 'low' } }]);
    expect(edges.issues[2]!.cells).toEqual([{ text: '4', ink: { severity: 'info' } }]);

    const noLanes = facts('running', 'auditing', { probes: { ...status().probes, by_lane: {} } });
    expect(wellRows(noLanes).crawl.find((r) => r.key === WELL_KEY.probesByLane)!.cells).toEqual([{ text: '—', ink: 'value' }]);

    const skipKeys = pointSkipWords({ ignored: 0, frequent: 0, limit: 0 }).map((w) => w.words);
    const issueKeys = [
      WELL_KEY.criticalHighMedium,
      WELL_KEY.low,
      WELL_KEY.info,
      WELL_KEY.certainFirmTentative,
      WELL_KEY.probeErrors,
      WELL_KEY.checks,
    ];
    for (const f of [ac51(), noLanes, jobFacts(ac51().summary, null)]) {
      const wells = wellRows(f);
      expect(wells.crawl.map((r) => r.key).filter((k) => !WELL_KEYS.includes(k))).toEqual(skipKeys);
      expect(wells.issues.map((r) => r.key)).toEqual(issueKeys);
      expect(wells.crawl.every((r) => r.cells.length > 0 && r.text !== '')).toBe(true);
      expect(wells.issues.every((r) => r.cells.length > 0 && r.text !== '')).toBe(true);
    }
  });

  it('the wells vocabulary: canary, yes/no, lane words', () => {
    expect(canaryWord({ kind: 'flow', method: 'GET', path: '/account', expected_status: 200 })).toBe('ok');
    expect(canaryWord({ kind: 'none' })).toBe('off');
    expect(yesNo(true)).toBe('yes');
    expect(yesNo(false)).toBe('no');
    expect(skippedLaneWords({ lane: 'ws', reason: 'lane not available on this build' })).toBe(
      'WebSocket: lane not available on this build',
    );
    expect(skippedLaneWords({ lane: 'l4_stream', reason: 'no L4 scope entry' })).toBe('L4 stream: no L4 scope entry');
  });
});

describe('reasonLine / rowSubLine (D21, AC55)', () => {
  const p4 = 'Stopped early: the probe budget of 2,000 was spent. Raise it in the profile to go further.';

  it('the stopped-reason sentence for a terminal job whose status carries one', () => {
    const errors = facts('done', 'done', { stopped_reason: 'errors' });
    expect(reasonLine(errors)).toBe('Stopped early: too many errors from the target.');
    expect(rowSubLine(errors)).toBe('Stopped early: too many errors from the target.');
    const budget = facts('done', 'done', { stopped_reason: 'budget', probes: { ...status().probes, budget: 2000 } });
    expect(reasonLine(budget)).toBe(p4);
    expect(rowSubLine(budget)).toBe(p4);
  });

  it('else the first non-empty line of the error; null when neither', () => {
    const failedWithError = facts('failed', 'done', { stopped_reason: 'failed', error: 'boom\nsecond' });
    expect(reasonLine(failedWithError)).toBeNull();
    expect(rowSubLine(failedWithError)).toBe('boom');
    const leadingNewline = facts('failed', 'done', { error: '\nboom' });
    expect(reasonLine(leadingNewline)).toBeNull();
    expect(rowSubLine(leadingNewline)).toBe('boom');
    const emptyError = facts('failed', 'done', { error: '' });
    expect(reasonLine(emptyError)).toBeNull();
    expect(rowSubLine(emptyError)).toBeNull();
    const cancelled = facts('cancelled', 'done', { stopped_reason: 'cancelled' });
    expect(reasonLine(cancelled)).toBeNull();
    expect(rowSubLine(cancelled)).toBeNull();
    const live = facts('running', 'auditing', { stopped_reason: 'errors' });
    expect(reasonLine(live)).toBeNull();
    expect(rowSubLine(live)).toBeNull();
    expect(reasonLine(unread('done', 'done'))).toBeNull();
    expect(rowSubLine(unread('done', 'done'))).toBeNull();
    const reasonAndError = facts('done', 'done', { stopped_reason: 'errors', error: 'boom' });
    expect(rowSubLine(reasonAndError)).toBe('Stopped early: too many errors from the target.');
    const failedNoError = facts('failed', 'done', { stopped_reason: 'failed', error: null });
    expect(reasonLine(failedNoError)).toBe('Stopped early: an error ended the job.');
    expect(rowSubLine(failedNoError)).toBe('Stopped early: an error ended the job.');
  });

  it('over the sweep: boom for exactly the terminal rows whose status landed', () => {
    for (const f of ac32Sweep()) {
      const expected = isTerminal(f.summary.state) && f.status !== null ? 'boom' : null;
      expect(rowSubLine(f), `${f.summary.state} / ${f.summary.phase}`).toBe(expected);
      expect(reasonLine(f)).toBeNull();
    }
  });
});

describe('attention / notices / crawlTroubleLine (D9, AC15)', () => {
  const sample = { check: 'http.sqli-error', point: 'GET /search?q', detail: 'Connection refused (os error 61)' };
  const secondSample = { check: 'http.ssrf', point: 'POST /hook', detail: 'no lane' };

  it('counts only what is non-zero, in the order could-not-run, skipped, crawl trouble', () => {
    expect(attention(facts('done', 'done', {}, 69_000))).toEqual([]);
    expect(attention(unread('done', 'done'))).toEqual([]);
    const errors = facts('running', 'auditing', { checks: { ...status().checks, errors: 7, error_samples: [sample] } });
    expect(attention(errors)).toEqual([{ text: '7 checks could not run', samples: [sample] }]);
    expect(attention(facts('done', 'done', { checks: { ...status().checks, errors: 1 } }))).toEqual([
      { text: '1 check could not run', samples: [] },
    ]);
    const skipped = facts('done', 'done', {
      checks: { ...status().checks, skipped: 3, skipped_samples: [sample, secondSample] },
    });
    expect(attention(skipped)).toEqual([{ text: '3 checks were skipped', samples: [sample, secondSample] }]);
    expect(attention(facts('done', 'done', { checks: { ...status().checks, skipped: 1 } })).map((l) => l.text)).toEqual([
      '1 check was skipped',
    ]);
    const refused = facts('done', 'done', { crawl: crawlWith({ pages: 0, errors: 1, last_error: 'connect_refused' }) });
    expect(attention(refused)).toEqual([
      { text: 'The crawl fetched 0 pages and hit 1 error — the target refused the connection', samples: [] },
    ]);
    const onePage = facts('done', 'done', { crawl: crawlWith({ pages: 1, errors: 1 }) });
    expect(attention(onePage)).toEqual([{ text: 'The crawl fetched 1 page and hit 1 error', samples: [] }]);
    const everything = facts('done', 'done', {
      checks: { ...status().checks, errors: 1200, error_samples: [sample], skipped: 3, skipped_samples: [secondSample] },
      crawl: crawlWith({ pages: 46, errors: 2 }),
    });
    expect(attention(everything)).toEqual([
      { text: '1,200 checks could not run', samples: [sample] },
      { text: '3 checks were skipped', samples: [secondSample] },
      { text: 'The crawl fetched 46 pages and hit 2 errors', samples: [] },
    ]);
  });

  it('crawlTroubleLine joins the words with an em dash when last_error is set', () => {
    expect(crawlTroubleLine(crawlWith({ pages: 0, errors: 1, last_error: 'connect_refused' }))).toBe(
      'The crawl fetched 0 pages and hit 1 error — the target refused the connection',
    );
    expect(crawlTroubleLine(crawlWith({ pages: 1, errors: 1, last_error: null }))).toBe(
      'The crawl fetched 1 page and hit 1 error',
    );
    expect(crawlTroubleLine(crawlWith({ pages: 37, errors: 0, last_error: 'tls' }))).toBeNull();
  });

  it('notices: the launch notices first, then the status clamps and skipped lanes it did not already say', () => {
    const st = statusWith({
      clamped: [
        { field: 'budget.probes', requested: 50000, applied: 20000 },
        { field: 'budget.time_s', requested: 7200, applied: 3600 },
      ],
    });
    const launchNotices = ['Clamped budget.probes 50000 → 20000', 'Skipped ws: lane not available on this build'];
    expect(notices(st, launchNotices)).toEqual([
      'Clamped budget.probes 50000 → 20000',
      'Skipped ws: lane not available on this build',
      'Clamped budget.time_s 7200 → 3600',
    ]);
    expect(notices(st, [])).toEqual([
      'Clamped budget.probes 50000 → 20000',
      'Clamped budget.time_s 7200 → 3600',
      'Skipped ws: lane not available on this build',
    ]);
    const quiet = statusWith({ lanes: { ...status().lanes, skipped: [] } });
    expect(notices(quiet, [])).toEqual([]);
    expect(notices(quiet, ['Clamped budget.probes 50000 → 20000'])).toEqual(['Clamped budget.probes 50000 → 20000']);
    expect(clampedText({ field: 'budget.probes', requested: 50000, applied: 20000 })).toBe(
      'Clamped budget.probes 50000 → 20000',
    );
    expect(skippedLaneText({ lane: 'ws', reason: 'lane not available on this build' })).toBe(
      'Skipped ws: lane not available on this build',
    );
  });
});

describe('jobsCaption / elapsedWords (D10, D14)', () => {
  it('counts the jobs and the running ones', () => {
    expect(jobsCaption(4, 1)).toBe('4 jobs · 1 running');
    expect(jobsCaption(1, 0)).toBe('1 job');
    expect(jobsCaption(3, 0)).toBe('3 jobs');
    expect(jobsCaption(2, 2)).toBe('2 jobs · 2 running');
  });

  it('jobsCaptionFor counts the rows and the `running` ones only; queued and cancelling are not running (gap 79)', () => {
    expect(jobsCaptionFor([])).toBe('0 jobs');
    expect(jobsCaptionFor([facts('running', 'auditing')])).toBe('1 job · 1 running');
    expect(jobsCaptionFor([facts('running', 'auditing'), facts('queued', 'queued'), facts('cancelling', 'auditing'), facts('done', 'done')])).toBe(
      '4 jobs · 1 running',
    );
    expect(jobsCaptionFor([facts('done', 'done'), facts('cancelled', 'done'), facts('failed', 'done')])).toBe('3 jobs');
    expect(jobsCaptionFor([unread('running', 'crawling'), facts('running', 'crawling')])).toBe('2 jobs · 2 running');
  });

  it('sampleRowText is the check id and the detail joined with ` · ` (gap 79)', () => {
    expect(sampleRowText({ check: 'xss-reflected', point: 'GET /login', detail: 'connection refused' })).toBe('xss-reflected · connection refused');
    expect(sampleRowText({ check: 'sqli-error', point: '', detail: '' })).toBe('sqli-error · ');
  });

  it('spells the elapsed time in words, zero components left out', () => {
    expect(elapsedWords(64_000)).toBe('1 minute 4 seconds');
    expect(elapsedWords(42_000)).toBe('42 seconds');
    expect(elapsedWords(3_723_000)).toBe('1 hour 2 minutes 3 seconds');
    expect(elapsedWords(0)).toBe('0 seconds');
    expect(elapsedWords(999)).toBe('0 seconds');
    expect(elapsedWords(1_000)).toBe('1 second');
    expect(elapsedWords(60_000)).toBe('1 minute');
    expect(elapsedWords(3_600_000)).toBe('1 hour');
    expect(elapsedWords(7_205_000)).toBe('2 hours 5 seconds');
    expect(elapsedWords(-5_000)).toBe('0 seconds');
  });
});

describe('progressAccessibilityValue / jobAccessibilityLabel (D14)', () => {
  it('reads the row as one sentence', () => {
    const auditing = facts('running', 'auditing', { ...COMP_JOB, checks: checksOf(3236, 6468), issues: issuesOf({ low: 4 }) });
    expect(jobAccessibilityLabel(auditing)).toBe(
      'Auditing, standard, 127.0.0.1:8117, 50 percent, 3,236 of 6,468 checks, 4 issues: 4 low, 1 minute 4 seconds.',
    );
    const passive = facts('running', 'passive', { ...COMP_JOB, issues: issuesOf({}) }, 42_000);
    expect(jobAccessibilityLabel(passive)).toBe('Passive, standard, 127.0.0.1:8117, no issues yet, 42 seconds.');
    const queued = facts('queued', 'queued', { ...COMP_JOB, issues: issuesOf({}) }, 0);
    expect(jobAccessibilityLabel(queued)).toBe('Queued, standard, 127.0.0.1:8117, no issues yet, 0 seconds.');
    const crawling = facts(
      'running',
      'crawling',
      { ...COMP_JOB, crawl: crawlWith({ pages: 46, queued: 12 }), issues: issuesOf({}) },
      9_000,
    );
    expect(jobAccessibilityLabel(crawling)).toBe(
      'Crawling, standard, 127.0.0.1:8117, 79 percent, 46 pages, 12 queued, no issues yet, 9 seconds.',
    );
    const done = facts('done', 'done', { ...COMP_JOB, checks: checksOf(6468, 6468), issues: issuesOf({}) }, 69_000);
    expect(jobAccessibilityLabel(done)).toBe('Done, standard, 127.0.0.1:8117, no issues, 1 minute 9 seconds.');
    const twoHosts = facts(
      'cancelled',
      'done',
      { checks: checksOf(3236, 6468), targets: ['http://a.test', 'http://b.test'], issues: issuesOf({ high: 1, low: 3 }) },
      3_723_000,
    );
    expect(jobAccessibilityLabel(twoHosts)).toBe(
      'Cancelled, standard, a.test, b.test, 4 issues: 1 high, 3 low, 1 hour 2 minutes 3 seconds.',
    );
    expect(progressAccessibilityValue(jobProgress(auditing))).toBe('50 percent');
    expect(progressAccessibilityValue(jobProgress(crawling))).toBe('79 percent');
    expect(progressAccessibilityValue(jobProgress(passive))).toBeNull();
    expect(progressAccessibilityValue(jobProgress(done))).toBeNull();
  });
});

describe('scanAgainHelp (D13)', () => {
  it('names the profile and the hosts', () => {
    expect(scanAgainHelp(statusWith(COMP_JOB))).toBe('Start a new job with profile standard against 127.0.0.1:8117');
    expect(scanAgainHelp(statusWith({ ...COMP_JOB, targets: ['http://a.test', 'http://b.test:8080'] }))).toBe(
      'Start a new job with profile standard against a.test, b.test:8080',
    );
    expect(scanAgainHelp(statusWith({ ...COMP_JOB, targets: [] }))).toBe('Start a new job with profile standard');
    expect(scanAgainHelp(statusWith({ ...COMP_JOB, profile_name: '' }))).toBe(SCAN_AGAIN_HELP_GENERIC);
  });
});

describe('linkBannerText (D15, AC38)', () => {
  it('reads the reconnecting banner with the age clause when a list has landed', () => {
    expect(linkBannerText(42_000)).toBe('Bus disconnected · showing values from 0:42 ago · reconnecting…');
    expect(linkBannerText(0)).toBe('Bus disconnected · showing values from 0:00 ago · reconnecting…');
    expect(linkBannerText(3_723_000)).toBe('Bus disconnected · showing values from 1:02:03 ago · reconnecting…');
    expect(linkBannerText(null)).toBe('Bus disconnected · reconnecting…');
  });
});

describe('the Jobs view constants (D10, D11, D17; each the Kit literal)', () => {
  it('fixed words', () => {
    expect(TABLE_HEADERS).toEqual(['State', 'Profile', 'Target', 'Progress', 'Probes', 'Points', 'Issues', 'Elapsed']);
    expect(KPI_LABELS).toEqual(['Progress', 'Checks', 'Probes', 'Points audited', 'Issues']);
    expect(GAUGE_LABEL).toBe('probe budget');
    expect(LANE_CRAWL_LABEL).toBe('crawl');
    expect(LANE_AUDIT_LABEL).toBe('audit');
    expect(MISSING_VALUE).toBe('—');
    expect(AGENT_DOT_HELP).toBe('started by an agent');
    expect(WELL_CRAWL_TITLE).toBe('Crawl and points');
    expect(WELL_CRAWL_SUBTITLE).toBe('what the job found to test');
    expect(WELL_ISSUES_TITLE).toBe('Issues');
    expect(WELL_ISSUES_SUBTITLE).toBe('by severity and confidence');
    expect(WELL_CELL_SEPARATOR).toBe(' · ');
    expect(CANCEL_SCAN_HELP).toBe('Stop this job; the issues and site map it found stay (⌥⌘.)');
    expect(SCAN_AGAIN_HELP_GENERIC).toBe("Start a new job with this job's profile and target");
    expect(SHOW_ISSUES_HELP).toBe('Open the Issues tab filtered to this job');
    expect(SHOW_SITE_MAP_HELP).toBe('Open the Site map tab for this job');
    expect(SCAN_AGAIN_ERROR_PREFIX).toBe('Unable to scan again: ');
    expect(CANCELLING_TITLE).toBe('Cancelling…');
    expect(NO_JOBS_TEXT).toBe('No jobs yet — pick a profile and Start Scan.');
  });

  it('WELL_KEYS: the 23 keys of WellKey.all, in order, distinct', () => {
    expect(WELL_KEYS).toEqual([
      'Pages fetched',
      'Pages waiting',
      'Depth',
      'Forms submitted',
      'Forms not submitted',
      'Crawl errors',
      'Points found',
      'Waiting for audit',
      'Audited',
      'Lanes',
      'Lane skipped',
      'Probes by lane',
      'Session',
      'L4 cases',
      'L4 crashes',
      'L4 liveness failures',
      'L4 retired elements',
      'Critical · High · Medium',
      'Low',
      'Info',
      'Certain · Firm · Tentative',
      'Probe errors · timeouts · rate waits',
      'Checks scheduled · done · errors · skipped',
    ]);
    expect(new Set(WELL_KEYS).size).toBe(23);
    expect(Object.values(WELL_KEY)).toEqual(WELL_KEYS);
  });
});

describe('jobs words avoid the banned terms (AC32)', () => {
  it('none of stop, abort, finding, task as a whole word, bar the two named allowances', () => {
    const banned = /\b(stop|abort|finding|task)\b/i;
    let strings: string[] = [
      ...TABLE_HEADERS,
      ...KPI_LABELS,
      ...WELL_KEYS,
      GAUGE_LABEL,
      LANE_CRAWL_LABEL,
      LANE_AUDIT_LABEL,
      MISSING_VALUE,
      AGENT_DOT_HELP,
      WELL_CRAWL_TITLE,
      WELL_CRAWL_SUBTITLE,
      WELL_ISSUES_TITLE,
      WELL_ISSUES_SUBTITLE,
      SCAN_AGAIN_HELP_GENERIC,
      SHOW_ISSUES_HELP,
      SHOW_SITE_MAP_HELP,
      CANCELLING_TITLE,
      SCAN_AGAIN_ERROR_PREFIX,
      NO_JOBS_TEXT,
      CANCEL_SCAN_HELP,
      jobsCaption(4, 1),
      probesTileHelp(287, 2000),
      probeBudgetText(287, 0),
      gaugeAccessibilityLabel(287, 2000),
      issuesTileHelp(tally({ high: 1, low: 3 })),
      ofText(6468),
      laneChecksDone(3236),
      lanePages(46),
      scaleStarted('11:32'),
      scaleElapsed(64_000),
      elapsedWords(3_723_000),
      severityWords(tally(), true),
      severityWords(tally(), false),
      issuesSoFar(tally()),
      canaryWord({ kind: 'none' }),
      canaryWord({ kind: 'flow', method: 'GET', path: '/account', expected_status: 200 }),
      skippedLaneWords({ lane: 'ws', reason: 'lane not available on this build' }),
      clampedText({ field: 'budget.probes', requested: 50000, applied: 20000 }),
      skippedLaneText({ lane: 'ws', reason: 'lane not available on this build' }),
      yesNo(true),
      yesNo(false),
      linkBannerText(42_000),
      linkBannerText(null),
      scanAgainHelp(statusWith(COMP_JOB)),
      ...pointSkipWords({ ignored: 6, frequent: 722, limit: 0 }).map((w) => w.text),
    ];
    const reasons: StoppedReason[] = [
      'budget',
      'time',
      'cancelled',
      'session_lost',
      'errors',
      'policy',
      'guard_refused',
      'failed',
      'paused' as StoppedReason,
    ];
    for (const reason of reasons) {
      strings.push(stoppedReasonText(reason, 'done', 2000, null) ?? '');
      strings.push(rawReasonLine(reason));
    }
    for (const kind of ['connect_refused', 'tls', 'timeout', 'h2_not_negotiated', 'transport', 'other', 'x']) {
      strings.push(crawlErrorWords(kind), rawCrawlErrorLine(kind));
    }
    for (const f of ac32Sweep()) {
      const p = jobProgress(f);
      const running = !isTerminal(f.summary.state);
      strings = strings.concat([
        stateWords(f.summary),
        profileText(f),
        hostsText(f),
        p.rowText,
        jobHeading(f),
        jobHeadingHelp(f) ?? '',
        jobAccessibilityLabel(f),
        severityWords(f.summary.issues.by_severity, running),
        endSentence(f.summary, f.status === null ? null : f.status.checks) ?? '',
        p.phaseLine,
        p.helpText,
        p.nowLine ?? '',
        p.nowTag ?? '',
        p.checksToGoText ?? '',
        p.estimateText ?? '',
        p.estimateHelp ?? '',
        progressAccessibilityValue(p) ?? '',
        reasonLine(f) ?? '',
        rowSubLine(f) ?? '',
      ]);
      const line = findingLine(f, LISBON);
      strings = strings.concat([line.text, line.reason ?? ''], line.parts.map((x) => x.text));
      strings = strings.concat(attention(f).map((l) => l.text));
      if (f.status !== null) strings = strings.concat(notices(f.status, []));
      const wells = wellRows(f);
      for (const r of [...wells.crawl, ...wells.issues]) strings.push(r.key, r.text);
    }
    expect(strings.filter((s) => s === '').length).toBeLessThan(strings.length / 4);

    // The two allowances, excepted by name; each must still be in the sweep and still trip the matcher.
    const sessionLost = stoppedReasonText('session_lost', 'done', 0, null)!;
    expect(sessionLost).toBe('Stopped early: the session was lost and the profile says stop when that happens.');
    const allowed = [CANCEL_SCAN_HELP, sessionLost];
    for (const text of allowed) {
      expect(text.startsWith('Stop')).toBe(true);
      expect(strings).toContain(text);
      expect(banned.test(text)).toBe(true);
    }
    const offenders = strings.filter((s) => !allowed.includes(s) && banned.test(s));
    expect(offenders).toEqual([]);
    // The matcher's own edges.
    expect(banned.test('Stopped early: the time budget ran out.')).toBe(false);
    expect(banned.test('multitasking')).toBe(false);
    expect(banned.test('Findings so far')).toBe(false);
    expect(banned.test('one finding, two')).toBe(true);
    expect(banned.test('ABORT now')).toBe(true);
    expect(banned.test('a task')).toBe(true);
  });
});
