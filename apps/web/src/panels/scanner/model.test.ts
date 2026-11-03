// Every parser in `model.ts` against the scanner v2 fixture pack
// (`crates/aitm-scan-model/fixtures/`), plus the garbage cases that must yield `null`.
//
// The fixture pack is a *shape* contract, not evidence: its README is explicit that a green parse
// here proves the wire shapes are internally consistent and nothing more. No assertion in this file
// says the scanner found, reported or reproduced anything; acceptance for T8 is the live run
// (`scripts/scan-live.mjs`), never this suite.

import { describe, expect, it } from 'vitest';

import {
  MAX_SAMPLES,
  SCAN_ERROR_CODES,
  STR_MAX,
  TARGET_MAX,
  TOKEN_MAX,
  parseCheckMeta,
  parseChecksResult,
  parseInsertionPoint,
  parseIssue,
  parseIssueSummary,
  parseIssuesResult,
  parseJobNotification,
  parseJobStatus,
  parseJobSummary,
  parseListResult,
  parseProfileDeleteResult,
  parseProfileList,
  parseProfileSaveResult,
  parseScanError,
  parseScanProfile,
  parseSessionProfile,
  parseSiteNode,
  parseSitemapResult,
  parseStartResult,
} from './model';
import { fixture } from './testkit';

describe('parseJobStatus', () => {
  it('reads scan.status.json field for field', () => {
    const status = parseJobStatus(fixture('scan.status.json'));
    expect(status).not.toBeNull();
    expect(status!.job).toBe('scan-1a2b3c4d');
    expect(status!.state).toBe('running');
    expect(status!.phase).toBe('auditing');
    expect(status!.probes.sent).toBe(418);
    expect(status!.probes.by_lane.http).toBe(418);
    expect(status!.session!.canary).toEqual({
      kind: 'flow',
      method: 'GET',
      path: '/account',
      expected_status: 200,
    });
    expect(status!.lanes.skipped[0]!.reason).toBe('lane not available on this build');
    expect(status!.lanes.skipped[0]!.lane).toBe('ws');
    expect(status!.stopped_reason).toBeNull();
    expect(status!.l4).toBeNull();
    // The fixture predates `crawl.errors`: absent on the wire reads as 0, never undefined.
    expect(status!.crawl.errors).toBe(0);
  });

  it('reads crawl.errors when the wire carries it (a failed browser crawl counts here)', () => {
    const raw = fixture('scan.status.json') as Record<string, unknown>;
    const crawl = raw.crawl as Record<string, unknown>;
    const status = parseJobStatus({ ...raw, crawl: { ...crawl, errors: 2 } });
    expect(status!.crawl.errors).toBe(2);
    expect(status!.crawl.pages).toBe(37);
  });

  it('crawl.forms_skipped is 0 when absent and read when present (engine contract A8)', () => {
    const raw = fixture('scan.status.json') as Record<string, unknown>;
    const crawl = raw.crawl as Record<string, unknown>;
    expect(parseJobStatus(raw)!.crawl.forms_skipped).toBe(0);
    expect(parseJobStatus({ ...raw, crawl: { ...crawl, forms_skipped: 3 } })!.crawl.forms_skipped).toBe(3);
  });

  it('a negative counter on the wire reads as 0, never as a negative number', () => {
    const raw = fixture('scan.status.json') as Record<string, unknown>;
    const probes = raw.probes as Record<string, unknown>;
    const status = parseJobStatus({ ...raw, probes: { ...probes, sent: -5 }, finished_at: -1 });
    expect(status!.probes.sent).toBe(0);
    expect(status!.finished_at).toBeNull();
    expect(status!.probes.budget).toBe(2000);
  });

  it('reads scan.cancel.json as a cancelling job', () => {
    const status = parseJobStatus(fixture('scan.cancel.json'));
    expect(status!.state).toBe('cancelling');
    expect(status!.stopped_reason).toBe('cancelled');
  });

  // Spec AC33 (D18 W1), the web copy of AC1 and AC2: the check-error and crawl-error fields the
  // Jobs view's sentences read, with 0 / [] / null defaults so an older core still parses.
  it('reads check errors, samples, skips and the crawl last_error', () => {
    const raw = fixture('scan.status.json') as Record<string, unknown>;
    const checks = {
      scheduled: 4,
      done: 3,
      running: [],
      errors: 7,
      error_samples: [{ check: 'http.xss', point: 'p1', detail: 'Connection refused (os error 61)' }],
      skipped: 3,
      skipped_samples: [{ check: 'fake.point', point: 'p2', detail: 'the lane hosts nothing' }],
    };
    const crawl = {
      pages: 1,
      queued: 0,
      depth: 0,
      forms_submitted: 0,
      errors: 1,
      forms_skipped: 2,
      last_error: 'connect_refused',
    };
    const status = parseJobStatus({ ...raw, checks, crawl })!;
    expect(status.checks.errors).toBe(7);
    expect(status.checks.error_samples.length).toBe(1);
    expect(status.checks.error_samples[0]).toEqual({
      check: 'http.xss',
      point: 'p1',
      detail: 'Connection refused (os error 61)',
    });
    expect(status.checks.error_samples[0]!.detail).toBe('Connection refused (os error 61)');
    expect(status.checks.skipped).toBe(3);
    expect(status.checks.skipped_samples.length).toBe(1);
    expect(status.checks.skipped_samples[0]!.check).toBe('fake.point');
    expect(status.crawl.errors).toBe(1);
    expect(status.crawl.forms_skipped).toBe(2);
    expect(status.crawl.last_error).toBe('connect_refused');

    // An unknown token is null, not a string the view would print as-is.
    expect(parseJobStatus({ ...raw, crawl: { ...crawl, last_error: 'weird' } })!.crawl.last_error).toBeNull();

    // The fixture pack predates these keys: 0, [], 0, [], null.
    const old = parseJobStatus(raw)!;
    expect(old.checks.errors).toBe(0);
    expect(old.checks.error_samples).toEqual([]);
    expect(old.checks.skipped).toBe(0);
    expect(old.checks.skipped_samples).toEqual([]);
    expect(old.crawl.last_error).toBeNull();

    // A sample missing a key reads it as '' (the engine's `#[serde(default)]`); a non-object
    // sample is dropped, not kept as a half-built row.
    const sparse = parseJobStatus({
      ...raw,
      checks: { ...checks, error_samples: [{ check: 'http.xss' }, 'junk', null, 7] },
    })!;
    expect(sparse.checks.error_samples).toEqual([{ check: 'http.xss', point: '', detail: '' }]);
  });

  it('bounds every Jobs string and sample list', () => {
    // Task 3.1b (gap 74, web AC1b): the Kit's `ScanWire` bounds, mirrored. A control or format
    // scalar and a line/paragraph separator never reach a row; a text is cut to its cap in code
    // points; a sampled list is cut to the engine's own cap of 8.
    const raw = fixture('scan.status.json') as Record<string, unknown>;
    const detail = `${'a'.repeat(300)}\u0000${'b'.repeat(300)}\t${'c'.repeat(200)}\u2028${'d'.repeat(197)}`;
    expect(detail.length).toBe(1000);
    const sample = (i: number) => ({ check: `check-${i}`, point: `p${i}`, detail: `d${i}` });
    const nine = (f: (i: number) => unknown) => Array.from({ length: 9 }, (_, i) => f(i));
    const status = parseJobStatus({
      ...raw,
      profile_name: 'p'.repeat(100),
      started_by: { frontend: 'operator', client_label: 'x'.repeat(100) },
      checks: {
        scheduled: 4,
        done: 3,
        running: nine((i) => `http.check-${i}`),
        errors: 9,
        error_samples: [{ check: 'http.xss', point: 'p1', detail }, ...nine(sample).slice(1)],
        skipped: 9,
        skipped_samples: nine(sample),
      },
      lanes: {
        requested: ['http', 'ws'],
        run: ['http'],
        skipped: nine((i) => ({ lane: 'ws', reason: `r${i}\u202E${'z'.repeat(500)}` })),
      },
      clamped: nine((i) => ({ field: `budget.f${i}.${'q'.repeat(100)}`, requested: 9, applied: 1 })),
      error: `${'e'.repeat(500)}\n${'f'.repeat(500)}`,
    })!;

    // 1,000 chars with a NUL, a tab and U+2028 inside: exactly 400 clean chars, the first 400 kept.
    const bounded = status.checks.error_samples[0]!.detail;
    expect(bounded).toBe('a'.repeat(300) + 'b'.repeat(100));
    expect(bounded.length).toBe(400);
    expect(bounded).not.toMatch(/[\u0000\t\u2028]/);
    expect(MAX_SAMPLES).toBe(8);
    expect(STR_MAX).toBe(400);
    expect(TOKEN_MAX).toBe(64);

    // Nine samples, nine running ids, nine skipped lanes, nine clamps: eight each, the first eight.
    expect(status.checks.error_samples.length).toBe(8);
    expect(status.checks.error_samples[7]).toEqual({ check: 'check-7', point: 'p7', detail: 'd7' });
    expect(status.checks.skipped_samples.length).toBe(8);
    expect(status.checks.running.length).toBe(8);
    expect(status.checks.running[7]).toBe('http.check-7');
    expect(status.lanes.skipped.length).toBe(8);
    expect(status.clamped.length).toBe(8);

    // Tokens cut to 64; details to 400; `error` keeps its first 400 clean chars with the newline gone.
    expect(status.started_by.client_label).toBe('x'.repeat(64));
    expect(status.profile_name).toBe('p'.repeat(64));
    expect(status.clamped[0]!.field).toBe(`budget.f0.${'q'.repeat(54)}`);
    expect(status.lanes.skipped[0]!.reason).toBe(`r0${'z'.repeat(398)}`);
    expect(status.error).toBe('e'.repeat(400));

    // Code points, not UTF-16 units: 401 astral scalars cut to 400 (800 units), none split in half.
    const astral = parseJobStatus({
      ...raw,
      checks: { scheduled: 1, done: 0, running: [], error_samples: [{ check: '😀'.repeat(401) }] },
    })!;
    expect([...astral.checks.error_samples[0]!.check].length).toBe(400);
    expect(astral.checks.error_samples[0]!.check).toBe('😀'.repeat(400));

    // The fixture is under every cap and carries no such scalar: it reads as before.
    const same = parseJobStatus(raw)!;
    expect(same.profile_name).toBe('standard');
    expect(same.started_by.client_label).toBe('web-ui');
    expect(same.checks.running).toEqual(['http.reflected-xss', 'http.sqli-error']);
    expect(same.lanes.skipped).toEqual([{ lane: 'ws', reason: 'lane not available on this build' }]);
    expect(same.clamped).toEqual([]);
    expect(same.error).toBeNull();
  });

  it('bounds targets to 200 chars and 8 entries and rejects a stamp no date holds', () => {
    // Task 3.1c (gap 78, web AC1b): the Kit's `ScanWire.targetMax` (200) and `listMax` (8) on
    // `targets`, which Task 3.1b left on `strList`; and a millisecond stamp that is not an integer
    // in `0 … 8.64e15` (what `Date` holds) reads 0, the card's "unknown", so `clock` never prints
    // `00:00` for garbage.
    const raw = fixture('scan.status.json') as Record<string, unknown>;
    const host = `${'a'.repeat(5000)}\u202E${'b'.repeat(4999)}`;
    expect(host.length).toBe(10_000);
    expect(TARGET_MAX).toBe(200);

    // 10,000 chars with a bidi override: the first 200 clean chars (`http://` and 193 of the host).
    const one = parseJobStatus({ ...raw, targets: [`http://${host}:8117`] })!;
    expect(one.targets).toEqual([`http://${'a'.repeat(193)}`]);
    expect(one.targets[0]!.length).toBe(200);
    expect(one.targets[0]).not.toMatch(/\u202E/);
    // Nine targets: the first eight; a non-string entry is dropped.
    const nine = parseJobStatus({ ...raw, targets: Array.from({ length: 9 }, (_, i) => `http://a${i}.test`) })!;
    expect(nine.targets).toHaveLength(8);
    expect(nine.targets[7]).toBe('http://a7.test');
    const mixed = parseJobStatus({ ...raw, targets: ['http://a.test', 7, null, 'http://b.test'] })!;
    expect(mixed.targets).toEqual(['http://a.test', 'http://b.test']);

    // `started_at`: out of range, negative, non-finite, fractional, a string or absent → 0; in range kept whole.
    for (const bad of [1e300, 8.64e15 + 1, -5, Number.NaN, Number.POSITIVE_INFINITY, 1.5, '1782901920000', null, undefined]) {
      expect(parseJobStatus({ ...raw, started_at: bad })!.started_at, String(bad)).toBe(0);
    }
    expect(parseJobStatus({ ...raw, started_at: 1_782_901_920_000 })!.started_at).toBe(1_782_901_920_000);
    expect(parseJobStatus({ ...raw, started_at: 8.64e15 })!.started_at).toBe(8.64e15);
    expect(parseJobStatus({ ...raw, started_at: 0 })!.started_at).toBe(0);
    // `finished_at` is optional: `null`, absent, out of range or negative all read `null` (not known); in range kept whole.
    expect(parseJobStatus({ ...raw, finished_at: null })!.finished_at).toBeNull();
    expect(parseJobStatus({ ...raw, finished_at: 1e300 })!.finished_at).toBeNull();
    expect(parseJobStatus({ ...raw, finished_at: 8.64e15 + 1 })!.finished_at).toBeNull();
    expect(parseJobStatus({ ...raw, finished_at: -1 })!.finished_at).toBeNull();
    expect(parseJobStatus({ ...raw, finished_at: 0 })!.finished_at).toBe(0);
    expect(parseJobStatus({ ...raw, finished_at: 1_782_901_984_000 })!.finished_at).toBe(1_782_901_984_000);

    // The fixture's targets are under the cap and its stamps in range: they read as before.
    const same = parseJobStatus(raw)!;
    expect(same.targets).toEqual(raw.targets);
    expect(same.started_at).toBe(1_761_900_000_000);
    expect(same.finished_at).toBeNull();
  });
});

describe('parseJobSummary', () => {
  it('reads one scan.list.json entry', () => {
    const jobs = (fixture('scan.list.json') as { jobs: unknown[] }).jobs;
    const summary = parseJobSummary(jobs[0]);
    expect(summary!.job).toBe('scan-1a2b3c4d');
    expect(summary!.state).toBe('running');
    expect(summary!.phase).toBe('auditing');
    expect(summary!.elapsed_ms).toBe(42000);
    expect(summary!.points.skipped.ignored).toBe(5);
    expect(summary!.issues.by_severity.high).toBe(1);
  });
});

describe('parseStartResult', () => {
  it('reads scan.start.json with its clamp log and no dry_run key', () => {
    const start = parseStartResult(fixture('scan.start.json'));
    expect(start!.job).toBe('scan-1a2b3c4d');
    expect(start!.status.state).toBe('queued');
    expect(start!.clamped[0]!.field).toBe('budget.probes');
    expect(start!.clamped[0]!.requested).toBe(50000);
    expect(start!.clamped[0]!.applied).toBe(20000);
    expect(start!.lanes.skipped[0]!.lane).toBe('ws');
    expect(start!.dry_run).toBeUndefined();
  });

  it('reads scan.map.json, which is the same StartResult shape', () => {
    const map = parseStartResult(fixture('scan.map.json'));
    expect(map!.status.phase).toBe('crawling');
    expect(map!.clamped).toEqual([]);
    expect(map!.lanes.run).toEqual(['http']);
  });
});

describe('parseListResult', () => {
  it('reads both jobs of scan.list.json', () => {
    const list = parseListResult(fixture('scan.list.json'));
    expect(list!.jobs.length).toBe(2);
    expect(list!.jobs[1]!.state).toBe('done');
  });
});

describe('parseIssuesResult', () => {
  it('reads scan.issues.json with its page tally', () => {
    const page = parseIssuesResult(fixture('scan.issues.json'));
    expect(page!.by_severity.medium).toBe(1);
    expect(page!.by_severity.high).toBe(1);
    expect(page!.issues.length).toBe(2);
    expect(page!.issues[1]!.poc_ref).toBeNull();
    expect(page!.next_cursor).toBeNull();
  });
});

describe('parseIssueSummary', () => {
  it('reads one scan.issues.json row', () => {
    const rows = (fixture('scan.issues.json') as { issues: unknown[] }).issues;
    const summary = parseIssueSummary(rows[0]);
    expect(summary!.id).toBe('issue-9f8e7d6c');
    expect(summary!.severity).toBe('high');
    expect(summary!.confidence).toBe('certain');
    expect(summary!.status).toBe('open');
    expect(summary!.lane).toBe('http');
    expect(summary!.target).toEqual({ scheme: 'http', host: '127.0.0.1', port: 8080 });
    expect(summary!.location.path_template).toBe('/search');
    expect(summary!.occurrences).toBe(1);
  });
});

describe('parseIssue', () => {
  it('reads scan.issue.json with its evidence', () => {
    const issue = parseIssue(fixture('scan.issue.json'));
    expect(issue!.id).toBe('issue-9f8e7d6c');
    expect(issue!.evidence.probe_flows.length).toBe(2);
    expect(issue!.evidence.baseline_flow).toBe('16fd2706-8baf-433b-82eb-8c7fada847da');
    expect(issue!.evidence.payload).toBe('<script>aitm-canary()</script>');
    expect(issue!.location.kind).toBe('query');
    expect(issue!.location.name).toBe('q');
    expect(issue!.poc_ref).toBe('poc-3b1c');
    expect(issue!.finding_id).toBe('finding-7a21');
    expect(issue!.note).toBeNull();
  });

  it('reads scan.issue.update.json as a triaged issue', () => {
    const issue = parseIssue(fixture('scan.issue.update.json'));
    expect(issue!.status).toBe('false_positive');
    expect(issue!.note).toBe('intended behaviour');
  });

  it('issue.jobs: every finder of the issue; absent on the wire reads as [] (engine contract A8)', () => {
    const raw = fixture('scan.issue.json') as Record<string, unknown>;
    expect(parseIssue(raw)!.jobs).toEqual([]);
    expect(parseIssueSummary(raw)!.jobs).toEqual([]);
    const refound = parseIssue({ ...raw, jobs: ['scan-1a2b3c4d', 'scan-55667788'] })!;
    expect(refound.jobs).toEqual(['scan-1a2b3c4d', 'scan-55667788']);
    expect(refound.job).toBe('scan-1a2b3c4d');
  });
});

describe('parseSitemapResult', () => {
  it('reads scan.sitemap.json nodes, points and cursor', () => {
    const map = parseSitemapResult(fixture('scan.sitemap.json'));
    expect(map!.next_cursor).toBe('node-2');
    expect(map!.nodes[0]!.path_template).toBe('/account/{id}');
    expect(map!.nodes[0]!.auth).toBe(true);
    expect(map!.nodes[0]!.params).toEqual([{ kind: 'query', name: 'tab' }]);
    expect(map!.points[1]!.example).toBe('<redacted>');
    expect(map!.points[0]!.traits).toEqual(['json']);
    expect(map!.points[0]!.frequency).toBe(3);
  });
});

describe('parseSiteNode and parseInsertionPoint', () => {
  it('read one node and one point of scan.sitemap.json', () => {
    const raw = fixture('scan.sitemap.json') as { nodes: unknown[]; points: unknown[] };
    const node = parseSiteNode(raw.nodes[0]);
    expect(node!.id).toBe('node-1');
    expect(node!.method).toBe('GET');
    expect(node!.port).toBe(8080);
    expect(node!.points).toBe(2);
    expect(node!.audited).toBe(true);
    expect(node!.flows).toEqual(['550e8400-e29b-41d4-a716-446655440000']);

    const point = parseInsertionPoint(raw.points[0]);
    expect(point!.id).toBe('point-json-1');
    expect(point!.lane).toBe('http');
    expect(point!.kind).toBe('json_value');
    expect(point!.name).toBe('city');
    expect(point!.path).toBe('profile.address.city');
    expect(point!.site_node).toBe('node-1');
    expect(point!.method).toBe('POST');
  });
});

describe('parseChecksResult and parseCheckMeta', () => {
  it('reads scan.checks.json including each origin', () => {
    const checks = parseChecksResult(fixture('scan.checks.json'));
    expect(checks!.checks.length).toBe(3);
    expect(checks!.checks[0]!.origin).toEqual({ kind: 'native' });
    expect(checks!.checks[1]!.origin).toEqual({
      kind: 'bundled',
      path: 'scripts/bundled/active/sqli.rhai',
    });
    expect(checks!.checks[2]!.origin).toEqual({
      kind: 'custom',
      path: '~/.aitmproxy/scripts/marker.rhai',
    });
    expect(checks!.checks[2]!.cwe).toBe(200);
  });

  it('reads one check of scan.checks.json', () => {
    const raw = (fixture('scan.checks.json') as { checks: unknown[] }).checks;
    const meta = parseCheckMeta(raw[1]);
    expect(meta!.id).toBe('http.sqli-error');
    expect(meta!.class).toBe('sqli-error');
    expect(meta!.lanes).toEqual(['http']);
    expect(meta!.kinds).toEqual(['query', 'body_param', 'cookie', 'json_value']);
    expect(meta!.intensity).toBe('medium');
    expect(meta!.cost).toBe('light');
    expect(meta!.technique).toBe('error');
    expect(meta!.severity).toBe('high');
    expect(meta!.confidence_max).toBe('firm');
    expect(meta!.needs_baseline).toBe(true);
    expect(meta!.wants_traits).toBeNull();
  });
});

describe('parseProfileList', () => {
  it('reads the seven built-ins of scan.profile.list.json', () => {
    const list = parseProfileList(fixture('scan.profile.list.json'));
    expect(list!.profiles.map((p) => p.name)).toEqual([
      'passive-only',
      'map-only',
      'light-http',
      'standard',
      'thorough',
      'l4-stream-safe',
      'l4-full',
    ]);
    expect(list!.profiles[3]!.builtin).toBe(true);
    expect(list!.profiles[3]!.summary).toEqual({
      lanes: ['http', 'ws'],
      intensity: 'medium',
      speed: 'normal',
    });
  });
});

describe('parseScanProfile', () => {
  it('reads scan.profile.get.json whole', () => {
    const profile = parseScanProfile(fixture('scan.profile.get.json'));
    expect(profile!.name).toBe('standard');
    expect(profile!.lanes).toEqual(['http', 'ws']);
    expect(profile!.audit.kinds.length).toBe(20);
    expect(profile!.audit.kinds[0]).toBe('query');
    expect(profile!.audit.kinds[19]).toBe('l4_field');
    expect(profile!.audit.ignore[0]!.trait).toBe('session');
    expect(profile!.audit.ignore[0]!.kind).toBeNull();
    expect(profile!.budget.per_host_errors.ratio).toBe(0.5);
    expect(profile!.l4.dry_run).toBe(false);
    expect(profile!.crawl.use_browser).toBe('auto');
    expect(profile!.http.record_probes).toBe('issues_only');
  });

  it('fills every missing block with its default so a draft round-trips whole', () => {
    const profile = parseScanProfile({ name: 'x' });
    expect(profile!.name).toBe('x');
    expect(profile!.budget.probes).toBe(2000);
    expect(profile!.budget.time_s).toBe(600);
    expect(profile!.budget.per_host_errors.consecutive).toBe(10);
    expect(profile!.intensity).toBe('medium');
    expect(profile!.lanes).toEqual(['http']);
    expect(profile!.crawl.max_pages).toBe(200);
    expect(profile!.audit.kinds.length).toBe(20);
    expect(profile!.audit.ignore).toEqual([{ kind: null, name_regex: null, trait: 'session' }]);
    expect(profile!.ws.max_frame_bytes).toBe(1048576);
    expect(profile!.l4.cases).toBe(500);
    expect(profile!.target).toEqual({ origins: [], l4: [] });
  });

  it('drops unknown keys and refuses an unknown enum token', () => {
    const profile = parseScanProfile({ name: 'x', speed: 'fast', nonsense: 42 });
    expect(profile!.speed).toBe('fast');
    expect(Object.keys(profile!)).not.toContain('nonsense');
    expect(parseScanProfile({ name: 'x', speed: 'warp' })).toBeNull();
    expect(parseScanProfile({ name: 'x', lanes: ['http', 'carrier-pigeon'] })).toBeNull();
  });
});

describe('parseSessionProfile', () => {
  it('reads scan.session.preview.json as names only', () => {
    const session = parseSessionProfile(fixture('scan.session.preview.json'));
    expect(session!.origin).toBe('http://127.0.0.1:8080');
    expect(session!.cookies).toEqual(['sid']);
    expect(session!.headers).toEqual(['authorization']);
    expect(session!.source_flow).toBe('550e8400-e29b-41d4-a716-446655440000');
    expect(session!.canary).toEqual({
      kind: 'flow',
      method: 'GET',
      path: '/account',
      expected_status: 200,
    });
    // D7's anti-goal: no result carries session material. The model has no value field at all.
    expect(Object.keys(session!).filter((k) => /value/i.test(k))).toEqual([]);
  });

  it('refuses a payload that is not a session profile', () => {
    expect(parseSessionProfile(fixture('scan.profile.save.json'))).toBeNull();
  });
});

describe('parseJobNotification', () => {
  const pushes: ReadonlyArray<readonly [string, number, string]> = [
    ['job.started.json', 1, 'started'],
    ['job.phase.json', 2, 'phase'],
    ['job.progress.json', 3, 'progress'],
    ['job.issue.json', 4, 'issue'],
    ['job.finished.json', 5, 'finished'],
    ['job.cancelled.json', 6, 'cancelled'],
    ['job.failed.json', 7, 'failed'],
  ];

  for (const [file, seq, event] of pushes) {
    it(`reads ${file} as seq ${seq} event ${event}`, () => {
      const push = parseJobNotification(fixture(file));
      expect(push).not.toBeNull();
      expect(push!.job).toBe('scan-1a2b3c4d');
      expect(push!.seq).toBe(seq);
      expect(push!.event).toBe(event);
      expect(push!.status.job).toBe('scan-1a2b3c4d');
    });
  }

  it('carries the issue summary on an issue line', () => {
    const push = parseJobNotification(fixture('job.issue.json'));
    expect(push!.issue?.id).toBe('issue-9f8e7d6c');
    expect(push!.issue?.severity).toBe('high');
  });

  it('has no issue key on a line that is not an issue line', () => {
    expect(parseJobNotification(fixture('job.progress.json'))!.issue).toBeUndefined();
  });

  it('ignores a job line of another kind', () => {
    const raw = fixture('job.started.json') as Record<string, unknown>;
    expect(parseJobNotification({ ...raw, kind: 'flow' })).toBeNull();
  });
});

describe('garbage payloads', () => {
  it('yield null rather than a half-built object', () => {
    expect(parseJobStatus(null)).toBeNull();
    expect(parseJobStatus('x')).toBeNull();
    expect(parseJobStatus({ job: 1 })).toBeNull();
    expect(parseJobStatus({ job: 'j', state: 'exploded' })).toBeNull();
    expect(parseIssue([])).toBeNull();
    expect(parseStartResult({})).toBeNull();
    expect(parseJobSummary(undefined)).toBeNull();
    expect(parseListResult('x')).toBeNull();
    expect(parseIssuesResult(7)).toBeNull();
    expect(parseSitemapResult(null)).toBeNull();
    expect(parseChecksResult([])).toBeNull();
    expect(parseProfileList(null)).toBeNull();
    expect(parseScanProfile([])).toBeNull();
    expect(parseSessionProfile({ origin: 5 })).toBeNull();
    expect(parseJobNotification({ job: 'scan-1', kind: 'scan', event: 'exploded' })).toBeNull();
    expect(parseCheckMeta({ id: 'x' })).toBeNull();
    expect(parseSiteNode({ id: 'node-1' })).toBeNull();
    expect(parseInsertionPoint({ id: 'p', lane: 'smoke-signal' })).toBeNull();
  });

  it('drop unparsable rows instead of failing the whole page', () => {
    const page = parseIssuesResult({
      issues: [{ id: 'nope' }, (fixture('scan.issues.json') as { issues: unknown[] }).issues[0]],
      next_cursor: null,
      by_severity: {},
    });
    expect(page!.issues.length).toBe(1);
    expect(page!.issues[0]!.id).toBe('issue-9f8e7d6c');
    expect(page!.by_severity.high).toBe(0);
  });
});

describe('unsafe and duplicate ids', () => {
  // A Solid store refuses to traverse `__proto__` (`Refusing to traverse unsafe key`), so a row keyed
  // by that id would be accepted here and then silently never held: the parsers refuse it instead.
  it('parseJobStatus is null for a job id of __proto__', () => {
    const raw = fixture('scan.status.json') as Record<string, unknown>;
    expect(parseJobStatus({ ...raw, job: '__proto__' })).toBeNull();
    expect(parseJobSummary({ ...raw, job: '__proto__' })).toBeNull();
  });

  it('an issues page drops the __proto__ row and keeps the others', () => {
    const issues = (fixture('scan.issues.json') as { issues: Record<string, unknown>[] }).issues;
    const page = parseIssuesResult({
      issues: [{ ...issues[0]!, id: '__proto__' }, issues[1]],
      next_cursor: null,
      by_severity: {},
    });
    expect(page!.issues.map((i) => i.id)).toEqual(['issue-4c3b2a19']);
  });

  it('parseProfileList drops a __proto__ entry', () => {
    const profiles = (fixture('scan.profile.list.json') as { profiles: Record<string, unknown>[] }).profiles;
    const list = parseProfileList({ profiles: [{ ...profiles[0]!, name: '__proto__' }, profiles[3]] });
    expect(list!.profiles.map((p) => p.name)).toEqual(['standard']);
  });

  it('a sitemap drops a __proto__ node or point id and blanks a __proto__ ref', () => {
    const map = fixture('scan.sitemap.json') as { nodes: Record<string, unknown>[]; points: Record<string, unknown>[] };
    const parsed = parseSitemapResult({
      nodes: [{ ...map.nodes[0]!, id: '__proto__' }, { ...map.nodes[0]!, flows: ['__proto__', 'flow-1'] }],
      points: [{ ...map.points[0]!, id: '__proto__' }, { ...map.points[1]!, site_node: '__proto__', flow: '__proto__' }],
      next_cursor: null,
    });
    expect(parsed!.nodes.map((n) => n.id)).toEqual(['node-1']);
    expect(parsed!.nodes[0]!.flows).toEqual(['flow-1']);
    expect(parsed!.points.map((p) => p.id)).toEqual(['point-cookie-1']);
    expect(parsed!.points[0]!.site_node).toBeNull();
    expect(parsed!.points[0]!.flow).toBeNull();
  });

  it('a duplicate id on a page keeps the first occurrence only', () => {
    const issues = (fixture('scan.issues.json') as { issues: Record<string, unknown>[] }).issues;
    const page = parseIssuesResult({
      issues: [issues[0], { ...issues[1]!, id: 'issue-9f8e7d6c', name: 'second' }, issues[1]],
      next_cursor: null,
      by_severity: {},
    });
    expect(page!.issues.map((i) => i.id)).toEqual(['issue-9f8e7d6c', 'issue-4c3b2a19']);
    expect(page!.issues[0]!.name).not.toBe('second');

    const jobs = (fixture('scan.list.json') as { jobs: Record<string, unknown>[] }).jobs;
    const list = parseListResult({ jobs: [jobs[0], jobs[0], jobs[1]] });
    expect(list!.jobs.map((j) => j.job)).toEqual(['scan-1a2b3c4d', 'scan-55667788']);

    const profiles = (fixture('scan.profile.list.json') as { profiles: Record<string, unknown>[] }).profiles;
    const plist = parseProfileList({ profiles: [profiles[3], profiles[3], profiles[0]] });
    expect(plist!.profiles.map((p) => p.name)).toEqual(['standard', 'passive-only']);
  });
});

describe('parseScanError', () => {
  it('splits a scan error message into its code and detail', () => {
    expect(parseScanError('scan: out_of_scope: host x')).toEqual({
      code: 'out_of_scope',
      detail: 'host x',
    });
  });

  it('parses from an embedded "scan: " when a bridge prefixes the tool name', () => {
    expect(parseScanError('scan.start: scan: busy: max_jobs')).toEqual({
      code: 'busy',
      detail: 'max_jobs',
    });
  });

  it('keeps the raw text when the code is unknown', () => {
    expect(parseScanError('scan: bogus: y')).toEqual({ code: null, detail: 'scan: bogus: y' });
  });

  it('keeps the raw text when the message is not a scan error at all', () => {
    expect(parseScanError('boom')).toEqual({ code: null, detail: 'boom' });
    expect(parseScanError('scan: out_of_scope')).toEqual({
      code: null,
      detail: 'scan: out_of_scope',
    });
  });

  it('maps all nine codes to themselves', () => {
    expect(SCAN_ERROR_CODES.length).toBe(9);
    for (const code of SCAN_ERROR_CODES) {
      expect(parseScanError(`scan: ${code}: detail`)).toEqual({ code, detail: 'detail' });
    }
  });
});

describe('parseProfileSaveResult / parseProfileDeleteResult', () => {
  it('reads scan.profile.save.json and scan.profile.delete.json', () => {
    const saved = parseProfileSaveResult(fixture('scan.profile.save.json'));
    expect(saved!.saved).toBe('my-api');
    expect(saved!.path).toBe('/Users/operator/.aitmproxy/findings/scan/profiles/my-api.yaml');
    expect(parseProfileDeleteResult(fixture('scan.profile.delete.json'))!.deleted).toBe(true);
  });

  it('garbage is null', () => {
    expect(parseProfileSaveResult(null)).toBeNull();
    expect(parseProfileSaveResult({ nope: 1 })).toBeNull();
    expect(parseProfileSaveResult({ saved: 'x' })).toBeNull();
    expect(parseProfileDeleteResult('x')).toBeNull();
    expect(parseProfileDeleteResult({ deleted: 'yes' })).toBeNull();
  });
});
