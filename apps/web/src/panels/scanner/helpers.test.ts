// The pure helpers of the v2 Scan surface: formatting, the fixed texts of D-T8.6/D-T8.7, the
// grouping and filtering the Issues view does client-side, the scope predicates the pre-flight
// uses, and the check-selection algebra the check tree writes.
//
// Fixtures (`crates/aitm-scan-model/fixtures/`) are read for *shapes* only, exactly as the fixture
// pack's README demands: nothing here is evidence that a scan found, reported or reproduced
// anything. T8's acceptance is the live run, never this suite.

import { describe, expect, it } from 'vitest';

import type { L4ScopeEntryWire } from '~/panels/l4/model';

import {
  AGENT_NOTE,
  CONFIRM_NOTE,
  EMPTY_FILTER,
  L4_HINT,
  PROFILE_NAME_HINT,
  applyCheckToggle,
  checkIsOn,
  crawlErrorWords,
  crawlTroubleText,
  endSentence,
  filterIssues,
  fmtElapsed,
  groupBySeverity,
  grouped,
  hostInScope,
  hostKey,
  isLive,
  isStale,
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
  originHost,
  profileHasL4,
  rawCrawlErrorLine,
  rawReasonLine,
  scanErrorText,
  stateWords,
  stoppedReasonText,
  unknownSelectors,
} from './helpers';
import type { CheckSelection, CrawlCounters, JobStatus, JobSummary, StoppedReason } from './model';
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
