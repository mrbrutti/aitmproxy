// The DEVELOPMENT-ONLY fixtures bus's `scan.*` verbs (D-T8.11) and its simulated job.
//
// What this file proves: the mock answers the fifteen D3 verbs in the shapes `panels/scanner/model`
// parses, and its fake job moves through the phases with monotonic counters, coalesced push lines,
// a two-step cancel and the `needs_confirmation` envelope. What it does NOT prove: anything about
// the scanner. No request leaves the process here; the "job" is a chain of timers and the issues it
// reports are literals. As `crates/aitm-scan-model/fixtures/README.md` says of the pack, a green run
// against a shape is never evidence — neither this suite nor a `?bus=mock` session is acceptance
// for T8. That is the live run against a real core (`scripts/scan-live.mjs`).

import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { isNeedsConfirm, type NeedsConfirm } from '~/panels/l4/model';
import {
  parseChecksResult,
  parseIssue,
  parseIssuesResult,
  parseJobNotification,
  parseJobStatus,
  parseListResult,
  parseProfileList,
  parseScanProfile,
  parseSessionProfile,
  parseSitemapResult,
  parseStartResult,
  type JobNotification,
  type ScanProfile,
} from '~/panels/scanner/model';
import { createMockBus } from './mock';

const here = dirname(fileURLToPath(import.meta.url));
const FIXTURES = resolve(here, '../../../../crates/aitm-scan-model/fixtures');
const fixture = (name: string): unknown => JSON.parse(readFileSync(resolve(FIXTURES, name), 'utf8'));

/** The fifteen D3 verbs the Scan surface calls. */
const SCAN_VERBS = [
  'scan.start',
  'scan.map',
  'scan.status',
  'scan.list',
  'scan.cancel',
  'scan.issues',
  'scan.issue',
  'scan.issue.update',
  'scan.sitemap',
  'scan.checks',
  'scan.profile.list',
  'scan.profile.get',
  'scan.profile.save',
  'scan.profile.delete',
  'scan.session.preview',
];

/** A host of the mock's own scope (`SCOPE_HOSTS`), so a launch is not refused. */
const ORIGIN = 'https://api.shop-staging.test';

let bus: ReturnType<typeof createMockBus>;
let lines: { method: string; params: unknown }[];
let stop: () => void;
let profile: ScanProfile;

beforeEach(() => {
  vi.useFakeTimers();
  bus = createMockBus({ initial: 0, rate: 0, agentActive: false });
  lines = [];
  stop = bus.onNotification((method, params) => {
    lines.push({ method, params });
  });
  const base = parseScanProfile(fixture('scan.profile.get.json'));
  if (base === null) throw new Error('scan.profile.get.json no longer parses');
  profile = { ...base, target: { ...base.target, origins: [ORIGIN] } };
});

afterEach(() => {
  stop();
  bus.close();
  vi.useRealTimers();
});

/**
 * The mock answers after a simulated loopback round trip (< 20 ms), so under fake timers every call
 * has to be driven. The promise gets its handler before the clock moves, so a refusal never becomes
 * an unhandled rejection.
 */
async function call<T = unknown>(tool: string, args: Record<string, unknown> = {}): Promise<T> {
  const settled = bus.call<T>(tool, args).then(
    (v) => ({ ok: true as const, v }),
    (e: unknown) => ({ ok: false as const, e }),
  );
  await vi.advanceTimersByTimeAsync(20);
  const r = await settled;
  if (!r.ok) throw r.e;
  return r.v;
}

const jobLines = (): JobNotification[] =>
  lines
    .filter((l) => l.method === 'notifications/aitm/job')
    .map((l) => {
      const n = parseJobNotification(l.params);
      if (n === null) throw new Error(`a job line did not parse: ${JSON.stringify(l.params)}`);
      return n;
    });

async function startJob(p: ScanProfile = profile): Promise<string> {
  const r = parseStartResult(await call('scan.start', { profile: p }));
  if (r === null) throw new Error('scan.start did not answer a StartResult');
  return r.job;
}

describe('the mock scan verbs', () => {
  it('tools_list_has_every_verb', async () => {
    const names = (await bus.tools()).map((t) => t.name);
    for (const verb of SCAN_VERBS) expect(names).toContain(verb);
    const start = (await bus.tools()).find((t) => t.name === 'scan.start');
    expect(start?.description).toBeTruthy();
    expect(Object.keys(start?.inputSchema.properties ?? {})).toContain('profile');
  });

  it('start_returns_a_job', async () => {
    const r = parseStartResult(await call('scan.start', { profile }));
    expect(r).not.toBeNull();
    expect(r!.job).toMatch(/^scan-[0-9a-f]{8}$/);
    expect(r!.status.state).toBe('queued');
    expect(r!.status.phase).toBe('queued');
    expect(r!.status.targets).toEqual([ORIGIN]);
    expect(r!.status.profile_name).toBe('standard');
    expect(r!.status.started_by).toEqual({ frontend: 'operator', client_label: 'web-ui' });
    expect(r!.lanes).toEqual({ requested: ['http', 'ws'], run: ['http'], skipped: [{ lane: 'ws', reason: 'lane not available on this build' }] });
    expect(r!.clamped).toEqual([]);
    // No L4 lane, so the key is absent (not `false`).
    expect(r!.dry_run).toBeUndefined();
  });

  it('clamps_a_probe_budget_over_the_ceiling', async () => {
    const greedy: ScanProfile = { ...profile, budget: { ...profile.budget, probes: 50000 } };
    const r = parseStartResult(await call('scan.start', { profile: greedy }));
    expect(r!.clamped).toEqual([{ field: 'budget.probes', requested: 50000, applied: 20000 }]);
    expect(r!.status.probes.budget).toBe(20000);
  });

  it('job_runs_to_done_monotonically', async () => {
    const job = await startJob();
    const phases: string[] = [];
    let sent = -1;
    let state = '';
    for (let i = 0; i <= 20; i++) {
      const s = parseJobStatus(await call('scan.status', { job }));
      expect(s).not.toBeNull();
      expect(s!.job).toBe(job);
      expect(s!.probes.sent).toBeGreaterThanOrEqual(sent);
      sent = s!.probes.sent;
      state = s!.state;
      if (phases[phases.length - 1] !== s!.phase) phases.push(s!.phase);
      await vi.advanceTimersByTimeAsync(500);
    }
    expect(phases).toEqual(['queued', 'crawling', 'passive', 'auditing', 'reporting', 'done']);
    expect(state).toBe('done');
    expect(sent).toBeGreaterThan(0);
    const final = parseJobStatus(await call('scan.status', { job }))!;
    expect(final.state).toBe('done');
    expect(final.finished_at).not.toBeNull();
    expect(final.stopped_reason).toBeNull();
    expect(final.probes.sent).toBeLessThanOrEqual(final.probes.budget);
  });

  it('push_is_coalesced', async () => {
    const job = await startJob();
    await vi.advanceTimersByTimeAsync(10_000);
    const ns = jobLines();
    expect(ns.length).toBeGreaterThan(4);
    expect(ns.every((n) => n.job === job && n.kind === 'scan')).toBe(true);
    const seqs = ns.map((n) => n.seq);
    expect(seqs.every((s, i) => i === 0 || s > seqs[i - 1]!)).toBe(true);
    expect(ns[0]!.event).toBe('started');
    expect(ns[ns.length - 1]!.event).toBe('finished');
    expect(ns.map((n) => n.event)).toContain('phase');
    expect(ns.map((n) => n.event)).toContain('issue');
    // At most four `progress` lines per second per job (D3): half-open 1000 ms windows.
    const progress = ns.filter((n) => n.event === 'progress').map((n) => n.ts_ms);
    expect(progress.length).toBeGreaterThan(4);
    for (const t0 of progress) expect(progress.filter((t) => t >= t0 && t < t0 + 1000).length).toBeLessThanOrEqual(4);
  });

  it('issues_appear', async () => {
    const job = await startJob();
    await vi.advanceTimersByTimeAsync(7000);
    const r = parseIssuesResult(await call('scan.issues', { job }));
    expect(r).not.toBeNull();
    expect(r!.issues.length).toBe(2);
    expect(r!.next_cursor).toBeNull();
    expect(r!.by_severity).toEqual({ critical: 0, high: 1, medium: 1, low: 0, info: 0 });
    expect(r!.issues.every((i) => i.job === job)).toBe(true);
    const detail = parseIssue(await call('scan.issue', { id: r!.issues[0]!.id }));
    expect(detail).not.toBeNull();
    expect(detail!.id).toBe(r!.issues[0]!.id);
    expect(detail!.evidence.probe_flows.length).toBeGreaterThan(0);
    expect(detail!.status).toBe('open');
    expect(detail!.note).toBeNull();
    const updated = parseIssue(await call('scan.issue.update', { id: detail!.id, status: 'false_positive', note: 'intended behaviour' }));
    expect(updated!.status).toBe('false_positive');
    expect(updated!.note).toBe('intended behaviour');
    expect(parseIssue(await call('scan.issue', { id: detail!.id }))!.status).toBe('false_positive');
  });

  it('cancel_is_two_step', async () => {
    const job = await startJob();
    await vi.advanceTimersByTimeAsync(3500);
    const c = parseJobStatus(await call('scan.cancel', { job }));
    expect(c).not.toBeNull();
    expect(c!.state).toBe('cancelling');
    await vi.advanceTimersByTimeAsync(500);
    const s = parseJobStatus(await call('scan.status', { job }));
    expect(s!.state).toBe('cancelled');
    expect(s!.stopped_reason).toBe('cancelled');
    const sent = s!.probes.sent;
    // A cancelled job stops: no further counters, no `finished`, a `cancelled` line last.
    await vi.advanceTimersByTimeAsync(8000);
    expect(parseJobStatus(await call('scan.status', { job }))!.probes.sent).toBe(sent);
    const ns = jobLines();
    expect(ns[ns.length - 1]!.event).toBe('cancelled');
    expect(ns.map((n) => n.event)).not.toContain('finished');
  });

  it('needs_confirmation_for_intrusive', async () => {
    const intrusive: ScanProfile = { ...profile, intensity: 'intrusive' };
    const first = await call('scan.start', { profile: intrusive });
    expect(isNeedsConfirm(first)).toBe(true);
    const env = first as NeedsConfirm;
    expect(env.prompt).toBe(`This scan sends malformed traffic to ${ORIGIN} and may disrupt the target. Continue?`);
    const r = parseStartResult(await call('scan.start', { profile: intrusive, _confirm: env.confirm_token }));
    expect(r).not.toBeNull();
    expect(r!.job).toMatch(/^scan-[0-9a-f]{8}$/);
  });

  it('needs_confirmation_for_an_l4_lane', async () => {
    const l4: ScanProfile = {
      ...profile,
      lanes: ['l4_stream'],
      target: { origins: [], l4: [{ ip: '127.0.0.1', port: 9, proto: 'udp', grammar: null }] },
    };
    const first = await call('scan.start', { profile: l4 });
    expect(isNeedsConfirm(first)).toBe(true);
    const env = first as NeedsConfirm;
    expect(env.prompt).toBe('This scan sends malformed traffic to 127.0.0.1:9 and may disrupt the target. Continue?');
    const r = parseStartResult(await call('scan.start', { profile: l4, _confirm: env.confirm_token }));
    // `dry_run` is present only for a profile with an L4 lane (D3).
    expect(r!.dry_run).toBe(false);
    expect(r!.lanes.requested).toEqual(['l4_stream']);
  });

  it('out_of_scope_error_string', async () => {
    const evil: ScanProfile = { ...profile, target: { ...profile.target, origins: ['https://evil.test'] } };
    await expect(call('scan.start', { profile: evil })).rejects.toThrow(/^scan: out_of_scope: /);
    await expect(call('scan.map', { profile: evil })).rejects.toThrow(/^scan: out_of_scope: /);
    await expect(call('scan.status', { job: 'scan-deadbeef' })).rejects.toThrow(/^scan: not_found: /);
  });

  it('map_forces_the_passive_http_lane', async () => {
    const r = parseStartResult(await call('scan.map', { profile }));
    expect(r).not.toBeNull();
    expect(r!.lanes.requested).toEqual(['http']);
    expect(r!.status.job).toBe(r!.job);
  });

  it('list_shows_the_job_newest_first', async () => {
    const first = await startJob();
    const second = await startJob();
    const l = parseListResult(await call('scan.list'));
    expect(l).not.toBeNull();
    expect(l!.jobs.map((j) => j.job)).toEqual([second, first]);
    expect(l!.jobs[0]!.state).toBe('queued');
  });

  it('sitemap_and_checks_answer_the_fixture_shape', async () => {
    const job = await startJob();
    await vi.advanceTimersByTimeAsync(3000);
    const m = parseSitemapResult(await call('scan.sitemap', { job }));
    expect(m).not.toBeNull();
    expect(m!.nodes.length).toBe(2);
    expect(m!.points.length).toBe(3);
    expect(m!.next_cursor).toBeNull();
    expect(m!.nodes[0]!.path_template).toBe('/account/{id}');
    // A cookie example is never a value (D7).
    expect(m!.points.find((p) => p.kind === 'cookie')!.example).toBe('<redacted>');
    const c = parseChecksResult(await call('scan.checks'));
    expect(c!.checks.map((x) => x.id)).toEqual(['http.reflected-xss', 'http.sqli-error', 'http.custom-marker']);
    expect(c!.checks[1]!.origin).toEqual({ kind: 'bundled', path: 'scripts/bundled/active/sqli.rhai' });
  });

  it('profile_verbs_round_trip', async () => {
    const list = parseProfileList(await call('scan.profile.list'));
    expect(list!.profiles.map((p) => p.name)).toEqual(['passive-only', 'map-only', 'light-http', 'standard', 'thorough', 'l4-stream-safe', 'l4-full']);
    expect(list!.profiles.every((p) => p.builtin)).toBe(true);
    const got = parseScanProfile(await call('scan.profile.get', { name: 'l4-stream-safe' }));
    expect(got).not.toBeNull();
    expect(got!.name).toBe('l4-stream-safe');
    expect(got!.lanes).toEqual(['l4_stream']);
    expect(got!.budget.probes).toBe(2000);
    const mine: ScanProfile = { ...profile, name: 'my-api' };
    const saved = (await call('scan.profile.save', { profile: mine })) as { saved: string; path: string };
    expect(saved.saved).toBe('my-api');
    expect(saved.path).toMatch(/my-api\.yaml$/);
    expect(parseProfileList(await call('scan.profile.list'))!.profiles.find((p) => p.name === 'my-api')).toEqual({
      name: 'my-api',
      builtin: false,
      summary: { lanes: ['http', 'ws'], intensity: 'medium', speed: 'normal' },
    });
    expect(parseScanProfile(await call('scan.profile.get', { name: 'my-api' }))!.target.origins).toEqual([ORIGIN]);
    expect(await call('scan.profile.delete', { name: 'my-api' })).toEqual({ deleted: true });
    expect(parseProfileList(await call('scan.profile.list'))!.profiles.some((p) => p.name === 'my-api')).toBe(false);
    await expect(call('scan.profile.save', { profile: { ...profile, name: 'standard' } })).rejects.toThrow(/^scan: invalid_profile: /);
    await expect(call('scan.profile.get', { name: 'nope' })).rejects.toThrow(/^scan: not_found: /);
  });

  it('session_preview_is_names_only', async () => {
    const s = parseSessionProfile(await call('scan.session.preview', { target: ORIGIN }));
    expect(s).not.toBeNull();
    expect(s!.origin).toBe(ORIGIN);
    expect(s!.cookies).toEqual(['sid']);
    expect(s!.headers).toEqual(['authorization']);
    expect(JSON.stringify(s)).not.toMatch(/value/i);
  });
});
