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
  filterIssues,
  fmtElapsed,
  groupBySeverity,
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
  needsConfirmNote,
  nodesByHost,
  originHost,
  profileHasL4,
  scanErrorText,
  stateWords,
  stoppedReasonText,
  unknownSelectors,
} from './helpers';
import type { CheckSelection } from './model';
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

  it('prints the words of a live state and a terminal state alone', () => {
    expect(stateWords({ state: 'running', phase: 'auditing' })).toBe('running · auditing');
    expect(stateWords({ state: 'queued', phase: 'queued' })).toBe('queued');
    expect(stateWords({ state: 'done', phase: 'done' })).toBe('done');
    expect(stateWords({ state: 'failed', phase: 'auditing' })).toBe('failed');
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

describe('stoppedReasonText (D-T8.7)', () => {
  it('prints the eight reasons', () => {
    expect(stoppedReasonText('budget')).toBe('stopped: probe budget reached');
    expect(stoppedReasonText('time')).toBe('stopped: time budget reached');
    expect(stoppedReasonText('cancelled')).toBe('cancelled by operator');
    expect(stoppedReasonText('session_lost')).toBe('stopped: session lost');
    expect(stoppedReasonText('errors')).toBe('stopped: too many errors');
    expect(stoppedReasonText('policy')).toBe('stopped: agent policy changed');
    expect(stoppedReasonText('guard_refused')).toBe('stopped: guard refused');
    expect(stoppedReasonText('failed')).toBe('failed');
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
