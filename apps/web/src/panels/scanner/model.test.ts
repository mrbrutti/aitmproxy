// Every parser in `model.ts` against the scanner v2 fixture pack
// (`crates/aitm-scan-model/fixtures/`), plus the garbage cases that must yield `null`.
//
// The fixture pack is a *shape* contract, not evidence: its README is explicit that a green parse
// here proves the wire shapes are internally consistent and nothing more. No assertion in this file
// says the scanner found, reported or reproduced anything; acceptance for T8 is the live run
// (`scripts/scan-live.mjs`), never this suite.

import { describe, expect, it } from 'vitest';

import {
  SCAN_ERROR_CODES,
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
