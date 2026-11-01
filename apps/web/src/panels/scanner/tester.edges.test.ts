// Stage-5 Tester additions (whole-branch T8): edge cases a UI over an untrusted bus must survive.
// Parsers, pure helpers, the live job model and the store are fed the shapes a drifted, hostile or
// merely buggy bus can send — a string where an object is due, counters out of range, pages over
// the engine's ceiling, push lines with no sequence — and every assertion is a literal.
//
// The fixtures under `crates/aitm-scan-model/fixtures/` are wire *shapes*, never evidence
// (fixtures/README.md): nothing here says a scan ran. Acceptance for T8 is `scripts/scan-live.mjs`.
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { createRoot } from 'solid-js';
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import type { L4ScopeEntryWire } from '~/panels/l4/model';

import { fmtElapsed, hostInScope, isStale, l4Covered, l4EntryCovers } from './helpers';
import { createLiveModel, type LiveModel } from './live';
import {
  JOB_NOTIFICATION_METHOD,
  parseCheckMeta,
  parseIssuesResult,
  parseJobNotification,
  parseJobStatus,
  parseProfileList,
  parseScanError,
  parseSitemapResult,
  parseStartResult,
  type JobStatus,
} from './model';
import { scanStore, type ScanStore } from './store';
import { stubApp } from './testkit';

const here = dirname(fileURLToPath(import.meta.url));
const FIXTURES = resolve(here, '../../../../../crates/aitm-scan-model/fixtures');
type Raw = Record<string, unknown>;
const fixture = (name: string): unknown => JSON.parse(readFileSync(resolve(FIXTURES, name), 'utf8'));
const raw = (name: string): Raw => fixture(name) as Raw;
const sub = (o: Raw, key: string): Raw => o[key] as Raw;

const JOB = 'scan-1a2b3c4d';
const OTHER = 'scan-55667788';

/** `n` distinct issue rows cloned from the fixture's first row (`issue-000001` …). */
function issueRows(n: number): Raw[] {
  const base = (raw('scan.issues.json').issues as Raw[])[0]!;
  return Array.from({ length: n }, (_, i) => ({ ...base, id: `issue-${String(i + 1).padStart(6, '0')}` }));
}

/* ------------------------------------------------------------------ parsers */

describe('tester: parseJobStatus against a hostile reply', () => {
  it('a string, an array and an unknown state token are null, never a half-built status', () => {
    expect(parseJobStatus('running')).toBeNull();
    expect(parseJobStatus([])).toBeNull();
    expect(parseJobStatus([raw('scan.status.json')])).toBeNull();
    expect(parseJobStatus({ ...raw('scan.status.json'), state: 'exploded' })).toBeNull();
    expect(parseJobStatus({ ...raw('scan.status.json'), phase: 'exploding' })).toBeNull();
    expect(parseJobStatus({ ...raw('scan.status.json'), job: '' })).toBeNull();
  });

  it('a non-finite or non-numeric counter reads as 0, and a negative elapsed renders as 0:00', () => {
    const s = raw('scan.status.json');
    const probes = sub(s, 'probes');
    const parsed = parseJobStatus({
      ...s,
      elapsed_ms: -1,
      probes: { ...probes, sent: 'many', budget: Number.NaN, errors: Number.POSITIVE_INFINITY },
    });
    expect(parsed).not.toBeNull();
    expect(parsed!.state).toBe('running');
    expect(parsed!.probes.sent).toBe(0);
    expect(parsed!.probes.budget).toBe(0);
    expect(parsed!.probes.errors).toBe(0);
    expect(parsed!.elapsed_ms).toBe(-1);
    expect(fmtElapsed(parsed!.elapsed_ms)).toBe('0:00');
  });

  it('counters by lane keep only known lanes with finite numbers', () => {
    const s = raw('scan.status.json');
    const probes = sub(s, 'probes');
    const parsed = parseJobStatus({ ...s, probes: { ...probes, by_lane: { http: 7, carrier: 1, ws: 'x' } } });
    expect(parsed!.probes.by_lane).toEqual({ http: 7 });
  });
});

describe('tester: page ceilings', () => {
  it('an issues page of 1025 rows is cut at 1024, keeping the first 1024 in order', () => {
    const page = parseIssuesResult({ issues: issueRows(1025), next_cursor: null, by_severity: {} });
    expect(page!.issues.length).toBe(1024);
    expect(page!.issues[0]!.id).toBe('issue-000001');
    expect(page!.issues[1023]!.id).toBe('issue-001024');
  });

  it('a site map of 1025 nodes and 1025 points is cut at 1024 each', () => {
    const map = raw('scan.sitemap.json');
    const node = (map.nodes as Raw[])[0]!;
    const point = (map.points as Raw[])[0]!;
    const parsed = parseSitemapResult({
      nodes: Array.from({ length: 1025 }, (_, i) => ({ ...node, id: `node-${i + 1}` })),
      points: Array.from({ length: 1025 }, (_, i) => ({ ...point, id: `point-${i + 1}` })),
      next_cursor: null,
    });
    expect(parsed!.nodes.length).toBe(1024);
    expect(parsed!.points.length).toBe(1024);
    expect(parsed!.nodes[1023]!.id).toBe('node-1024');
  });
});

describe('tester: parseStartResult with a hostile clamp log', () => {
  it('drops every clamped entry that is not an object with a field name', () => {
    const start = raw('scan.start.json');
    const parsed = parseStartResult({
      ...start,
      clamped: [42, null, 'budget.probes', [], { requested: 1, applied: 1 }, { field: 'budget.time_s', requested: 9000, applied: 600 }],
    });
    expect(parsed!.clamped).toEqual([{ field: 'budget.time_s', requested: 9000, applied: 600 }]);
  });

  it('a clamped or lanes value of the wrong type reads as empty, not as a crash', () => {
    const start = raw('scan.start.json');
    const parsed = parseStartResult({ ...start, clamped: 'nope', lanes: 7 });
    expect(parsed!.clamped).toEqual([]);
    expect(parsed!.lanes).toEqual({ requested: [], run: [], skipped: [] });
  });
});

describe('tester: parseJobNotification with a drifted line', () => {
  it('a line with no seq reads as seq 0 and a non-numeric seq too', () => {
    const line = raw('job.progress.json');
    delete line.seq;
    expect(parseJobNotification(line)!.seq).toBe(0);
    expect(parseJobNotification({ ...raw('job.progress.json'), seq: 'x' })!.seq).toBe(0);
  });

  it('a line of another kind, or no kind, is not a scan line', () => {
    const line = raw('job.progress.json');
    expect(parseJobNotification({ ...line, kind: 'flow' })).toBeNull();
    delete line.kind;
    expect(parseJobNotification(line)).toBeNull();
  });

  it('an issue line whose issue does not parse is still a trigger, without the issue', () => {
    const parsed = parseJobNotification({ ...raw('job.issue.json'), issue: { id: 'nope' } });
    expect(parsed!.event).toBe('issue');
    expect(parsed!.issue).toBeUndefined();
  });
});

describe('tester: unknown lane tokens in catalogue and list replies', () => {
  it('a profile list entry keeps known lanes and drops the unknown one; an unknown intensity drops the entry', () => {
    const list = raw('scan.profile.list.json');
    const entries = list.profiles as Raw[];
    const standard = entries[3]!;
    const parsed = parseProfileList({
      profiles: [
        { ...standard, summary: { ...sub(standard, 'summary'), lanes: ['http', 'carrier-pigeon'] } },
        { ...standard, name: 'odd', summary: { ...sub(standard, 'summary'), intensity: 'nuclear' } },
      ],
    });
    expect(parsed!.profiles.length).toBe(1);
    expect(parsed!.profiles[0]!.summary.lanes).toEqual(['http']);
  });

  it('a check listing an unknown lane keeps only the known one', () => {
    const check = (raw('scan.checks.json').checks as Raw[])[1]!;
    const parsed = parseCheckMeta({ ...check, lanes: ['smoke-signal', 'http'] });
    expect(parsed!.lanes).toEqual(['http']);
  });
});

describe('tester: parseScanError on degenerate messages', () => {
  it('an empty string is an unknown error with an empty detail', () => {
    expect(parseScanError('')).toEqual({ code: null, detail: '' });
  });

  it('a bare prefix, a code with no detail separator, and a code with an empty detail', () => {
    expect(parseScanError('scan: ')).toEqual({ code: null, detail: 'scan: ' });
    expect(parseScanError('scan: busy')).toEqual({ code: null, detail: 'scan: busy' });
    expect(parseScanError('scan: busy: ')).toEqual({ code: 'busy', detail: '' });
  });

  it('a message with no colon, or colons without the space, is kept verbatim', () => {
    expect(parseScanError('bus closed')).toEqual({ code: null, detail: 'bus closed' });
    expect(parseScanError('scan:busy:max_jobs')).toEqual({ code: null, detail: 'scan:busy:max_jobs' });
  });
});

/* ------------------------------------------------------------------ helpers */

describe('tester: fmtElapsed on values a counter should never hold', () => {
  it('prints 0:00 for NaN, negative and infinite input', () => {
    expect(fmtElapsed(Number.NaN)).toBe('0:00');
    expect(fmtElapsed(-1)).toBe('0:00');
    expect(fmtElapsed(-60000)).toBe('0:00');
    expect(fmtElapsed(Number.POSITIVE_INFINITY)).toBe('0:00');
  });

  it('floors to the second and rolls over at the minute and the hour', () => {
    expect(fmtElapsed(999)).toBe('0:00');
    expect(fmtElapsed(59999)).toBe('0:59');
    expect(fmtElapsed(60000)).toBe('1:00');
    expect(fmtElapsed(3600000)).toBe('1:00:00');
    expect(fmtElapsed(86399000)).toBe('23:59:59');
  });
});

describe('tester: isStale with a negative elapsed', () => {
  it('a negative running reply is stale; a negative terminal reply is accepted', () => {
    const held = parseJobStatus(fixture('scan.status.json'))!;
    const back: JobStatus = { ...held, elapsed_ms: -1 };
    expect(isStale(held, back)).toBe(true);
    expect(isStale(held, { ...back, state: 'done' })).toBe(false);
  });
});

describe('tester: l4EntryCovers on malformed scope entries', () => {
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

  it('a /33 prefix, a CIDR without a slash and a non-IPv4 target are unknown (null)', () => {
    expect(l4EntryCovers(entry({ cidr: '127.0.0.0/33' }), '127.0.0.1', 9)).toBeNull();
    expect(l4EntryCovers(entry({ cidr: '127.0.0.1' }), '127.0.0.1', 9)).toBeNull();
    expect(l4EntryCovers(entry({ cidr: '256.0.0.0/8' }), '127.0.0.1', 9)).toBeNull();
    expect(l4EntryCovers(entry(), '256.0.0.1', 9)).toBeNull();
    expect(l4EntryCovers(entry(), '', 9)).toBeNull();
    expect(l4EntryCovers(entry(), 'localhost', 9)).toBeNull();
  });

  it('an inverted, oversized or empty port range is unknown (null)', () => {
    expect(l4EntryCovers(entry({ ports: '80-70' }), '127.0.0.1', 75)).toBeNull();
    expect(l4EntryCovers(entry({ ports: '70000' }), '127.0.0.1', 9)).toBeNull();
    expect(l4EntryCovers(entry({ ports: '0-70000' }), '127.0.0.1', 9)).toBeNull();
    expect(l4EntryCovers(entry({ ports: '' }), '127.0.0.1', 9)).toBeNull();
    expect(l4EntryCovers(entry({ ports: 'any' }), '127.0.0.1', 9)).toBeNull();
  });

  it('a /0 covers every IPv4 and a /32 covers exactly one address', () => {
    expect(l4EntryCovers(entry({ cidr: '0.0.0.0/0' }), '203.0.113.9', 443)).toBe(true);
    expect(l4EntryCovers(entry({ cidr: '127.0.0.1/32' }), '127.0.0.1', 9)).toBe(true);
    expect(l4EntryCovers(entry({ cidr: '127.0.0.1/32' }), '127.0.0.2', 9)).toBe(false);
  });

  it('unknown never disables: a malformed entry beside a covering one is covered, alone it is unknown', () => {
    expect(l4Covered([entry({ ports: '80-70' }), entry()], '127.0.0.1', 9)).toBe(true);
    expect(l4Covered([entry({ ports: '80-70' })], '127.0.0.1', 9)).toBeNull();
    expect(l4Covered([entry({ ports: '80-70' }), entry({ capability: 'capture' })], '127.0.0.1', 9)).toBeNull();
  });
});

describe('tester: hostInScope on degenerate scope entries', () => {
  it('a bare wildcard, an empty suffix and an empty host never match', () => {
    expect(hostInScope('http://127.0.0.1:8080', [{ host: '*' }])).toBe(false);
    expect(hostInScope('http://127.0.0.1:8080', [{ host: '*.' }])).toBe(false);
    expect(hostInScope('http://127.0.0.1:8080', [{ host: '' }])).toBe(false);
  });

  it('matches case-insensitively and does not let a suffix match mid-label', () => {
    expect(hostInScope('HTTP://API.Shop.Test', [{ host: '*.shop.test' }])).toBe(true);
    expect(hostInScope('http://evilshop.test', [{ host: '*.shop.test' }])).toBe(false);
    expect(hostInScope('http://shop.test.evil', [{ host: '*.shop.test' }])).toBe(false);
  });
});

/* ------------------------------------------------------------------ live model */

describe('tester: live model against a hostile bus', () => {
  const tick = (ms: number) => vi.advanceTimersByTimeAsync(ms);
  let close: (() => void) | null = null;

  function harness(opts: Parameters<typeof stubApp>[0] = {}) {
    const stub = stubApp(opts);
    let model!: LiveModel;
    const disposeRoot = createRoot((d) => {
      model = createLiveModel(stub.app, () => true);
      return d;
    });
    close = () => {
      model.dispose();
      disposeRoot();
    };
    return { ...stub, m: model };
  }

  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    close?.();
    close = null;
    vi.useRealTimers();
  });

  it('a scan.status reply that is a string, an array or an unknown state leaves the held status alone', async () => {
    const h = harness();
    await h.m.refreshStatus(JOB);
    expect(h.m.status(JOB)!.probes.sent).toBe(418);

    for (const reply of ['running', [], [raw('scan.status.json')], { ...raw('scan.status.json'), state: 'exploded' }]) {
      h.reply('scan.status', reply);
      await h.m.refreshStatus(JOB);
      expect(h.m.status(JOB)!.probes.sent).toBe(418);
      expect(h.m.status(JOB)!.state).toBe('running');
    }
    expect(h.count('scan.status')).toBe(5);
    expect(h.m.jobsError()).toBeNull();
  });

  it('a push line with no seq triggers one read; a second seq-less line is dropped as a replay', async () => {
    const h = harness();
    const line = raw('job.progress.json');
    delete line.seq;

    h.emit(JOB_NOTIFICATION_METHOD, line);
    await tick(300);
    expect(h.count('scan.status')).toBe(1);

    h.emit(JOB_NOTIFICATION_METHOD, line);
    await tick(300);
    expect(h.count('scan.status')).toBe(1);

    // A numbered line after it is new and read.
    h.emit(JOB_NOTIFICATION_METHOD, { ...raw('job.progress.json'), seq: 1 });
    await tick(300);
    expect(h.count('scan.status')).toBe(2);
  });

  it('coalescing is per job: two jobs pushing inside one 250 ms window are two reads (W-4)', async () => {
    const h = harness();
    const line = raw('job.progress.json');
    h.emit(JOB_NOTIFICATION_METHOD, line);
    h.emit(JOB_NOTIFICATION_METHOD, { ...line, job: OTHER, status: { ...sub(line, 'status'), job: OTHER } });
    h.emit(JOB_NOTIFICATION_METHOD, { ...line, seq: 4 });
    await tick(300);
    expect(h.count('scan.status')).toBe(2);
    expect(h.argsOf('scan.status').map((a) => a.job)).toEqual([JOB, OTHER]);
  });

  it('an issues page of 1025 rows is held as 1024', async () => {
    const h = harness();
    h.reply('scan.issues', { issues: issueRows(1025), next_cursor: null, by_severity: { high: 1025 } });
    await h.m.refreshIssues(JOB);
    expect(h.m.issues(JOB).rows.length).toBe(1024);
    expect(h.m.issues(JOB).rows[1023]!.id).toBe('issue-001024');
    expect(h.m.issues(JOB).bySeverity.high).toBe(1025);
    expect(h.m.issues(JOB).error).toBeNull();
  });

  it('a scan.list reply that is a string or an array is a shape error and keeps the held jobs', async () => {
    const h = harness();
    await h.m.refreshJobs();
    expect(h.m.jobs().length).toBe(2);
    h.reply('scan.list', 'jobs');
    await h.m.refreshJobs();
    expect(h.m.jobs().length).toBe(2);
    expect(h.m.jobsError()).toBe('scan.list answered with an unexpected shape');
    h.reply('scan.list', []);
    await h.m.refreshJobs();
    expect(h.m.jobs().length).toBe(2);
    expect(h.m.jobsError()).toBe('scan.list answered with an unexpected shape');
  });
});

/* ------------------------------------------------------------------ store */

describe('tester: store against a hostile profile.delete reply', () => {
  const built: ScanStore[] = [];
  const tick = (ms = 0) => vi.advanceTimersByTimeAsync(ms);

  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    for (const s of built.splice(0)) s.dispose();
    vi.useRealTimers();
  });

  it('a delete reply of the wrong shape is reported, and deleted:false is false without an error', async () => {
    const stub = stubApp();
    const s = scanStore(stub.app);
    built.push(s);
    await tick();

    stub.reply('scan.profile.delete', { nope: 1 });
    expect(await s.deleteProfile('my-api')).toBe(false);
    expect(s.lastError()).toBe('scan.profile.delete answered with an unexpected shape');
    expect(stub.notice).toHaveBeenCalledWith('scan.profile.delete answered with an unexpected shape', 'error');

    stub.reply('scan.profile.delete', { deleted: false });
    expect(await s.deleteProfile('my-api')).toBe(false);
    expect(s.lastError()).toBeNull();
  });
});
