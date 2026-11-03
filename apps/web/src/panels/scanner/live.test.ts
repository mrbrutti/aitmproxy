// T8 Task 8 (D-T8.3 "Live update model" / "Monotonic", umbrella D3 "push is a trigger, poll is
// truth"): the live job model reads every number back from the core. A push line only schedules a
// read, a reply that would move a counter backwards is dropped whole, the poll runs while a job is
// live and stops when none is, and nothing touches the bus while it is not `open`.
//
// The fixtures under `crates/aitm-scan-model/fixtures/` are wire *shapes*, never evidence: a green
// run here says the model holds the contract, not that any scan ever ran (fixtures/README.md).
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { createRoot } from 'solid-js';
import { fixture, stubApp } from './testkit';
import { createLiveModel, type LiveModel } from './live';
import { JOB_NOTIFICATION_METHOD, parseIssue } from './model';

type Raw = Record<string, unknown>;
/** A fixture as a mutable bag, for the "same reply with one field changed" cases. */
const raw = (name: string): Raw => fixture(name) as Raw;
const sub = (o: Raw, key: string): Raw => o[key] as Raw;

const JOB = 'scan-1a2b3c4d';
const OTHER = 'scan-55667788';
const tick = (ms: number) => vi.advanceTimersByTimeAsync(ms);
/**
 * A `scan.status` answer for the job asked about: the fixture is JOB's running status; OTHER is the
 * list fixture's finished job. (The bare fixture names JOB whatever the argument, which would leave
 * OTHER with nothing held and so re-read on every list under W1's rule.)
 */
const statusFor = (args: Record<string, unknown>): Raw =>
  args['job'] === OTHER
    ? { ...raw('scan.status.json'), job: OTHER, state: 'done', phase: 'done' }
    : raw('scan.status.json');

let close: (() => void) | null = null;

/** The model under its own root, as `scanStore` (Task 9) will build it. */
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

describe('createLiveModel: push is a trigger', () => {
  it('push_never_writes_counters: a line never writes a counter, it only schedules a read', async () => {
    const h = harness();
    await h.m.refreshJobs();
    await h.m.refreshStatus(JOB);
    expect(h.m.status(JOB)!.probes.sent).toBe(418);
    const before = h.count('scan.status');

    // The core has moved on, but only the read may say so.
    const next = raw('scan.status.json');
    h.reply('scan.status', { ...next, probes: { ...sub(next, 'probes'), sent: 500 }, elapsed_ms: 43000 });
    h.emit(JOB_NOTIFICATION_METHOD, raw('job.progress.json'));

    expect(h.m.status(JOB)!.probes.sent).toBe(418);
    expect(h.count('scan.status')).toBe(before);

    await tick(300);
    expect(h.m.status(JOB)!.probes.sent).toBe(500);
    expect(h.count('scan.status')).toBe(before + 1);
  });

  it('trigger_coalesces_250ms: five lines in 100 ms are one read', async () => {
    const h = harness();
    await h.m.refreshStatus(JOB);
    const before = h.count('scan.status');
    const line = raw('job.progress.json');
    for (let seq = 10; seq <= 14; seq++) {
      h.emit(JOB_NOTIFICATION_METHOD, { ...line, seq });
      await tick(20);
    }
    await tick(300);
    expect(h.count('scan.status')).toBe(before + 1);
  });

  it('issue_line_reads_issues_once', async () => {
    const h = harness();
    h.emit(JOB_NOTIFICATION_METHOD, { ...raw('job.issue.json'), seq: 20 });
    await tick(600);
    expect(h.count('scan.issues')).toBe(1);
    expect(h.argsOf('scan.issues')[0]).toEqual({ job: JOB, limit: 1024 });
  });

  it('old_seq_dropped: a line at or below the last seq for that job is ignored', async () => {
    const h = harness();
    h.emit(JOB_NOTIFICATION_METHOD, raw('job.issue.json')); // seq 4
    await tick(600);
    const status = h.count('scan.status');
    const issues = h.count('scan.issues');

    h.emit(JOB_NOTIFICATION_METHOD, raw('job.progress.json')); // seq 3
    await tick(600);
    expect(h.count('scan.status')).toBe(status);
    expect(h.count('scan.issues')).toBe(issues);
  });

  it('ignores a line that is not a scan job notification', async () => {
    const h = harness();
    h.emit(JOB_NOTIFICATION_METHOD, { ...raw('job.progress.json'), kind: 'flow' });
    h.emit('notifications/aitm/flow', raw('job.progress.json'));
    await tick(600);
    expect(h.count('scan.status')).toBe(0);
  });
});

describe('createLiveModel: poll is truth', () => {
  it('stale_reply_ignored: a reply that steps a counter backwards is dropped whole', async () => {
    const h = harness();
    await h.m.refreshStatus(JOB);
    expect(h.m.status(JOB)!.probes.sent).toBe(418);
    expect(h.m.status(JOB)!.elapsed_ms).toBe(42000);

    const s = raw('scan.status.json');
    h.reply('scan.status', { ...s, elapsed_ms: 41000, probes: { ...sub(s, 'probes'), sent: 300 } });
    await h.m.refreshStatus(JOB);
    expect(h.m.status(JOB)!.probes.sent).toBe(418);
    expect(h.m.status(JOB)!.elapsed_ms).toBe(42000);

    // A terminal reply is always accepted, late or not.
    h.reply('scan.status', { ...s, elapsed_ms: 41000, state: 'done', probes: { ...sub(s, 'probes'), sent: 300 } });
    await h.m.refreshStatus(JOB);
    expect(h.m.status(JOB)!.state).toBe('done');
    expect(h.m.status(JOB)!.probes.sent).toBe(300);
  });

  it('polls_while_live: 1 Hz status and 5 s list while a job is live, and stops when none is', async () => {
    const h = harness();
    h.reply('scan.status', statusFor);
    expect(h.m.liveCount()).toBeNull();
    await h.m.refreshJobs();
    expect(h.m.liveCount()).toBe(1);
    expect(h.m.jobs().length).toBe(2);
    expect(h.m.jobsLoaded()).toBe(true);
    // The first list seeds one read per job it named (W1's re-read rule: nothing was held yet).
    expect(h.argsOf('scan.status').map((a) => a['job'])).toEqual([JOB, OTHER]);
    const seeded = h.count('scan.status');

    await tick(5000);
    expect(h.count('scan.status') - seeded).toBeGreaterThanOrEqual(5);
    expect(h.count('scan.status') - seeded).toBeLessThanOrEqual(6);
    expect(h.count('scan.list')).toBe(2);
    // Only the live job is polled.
    expect(h.argsOf('scan.status').slice(seeded).every((a) => a['job'] === JOB)).toBe(true);

    const list = raw('scan.list.json');
    const jobs = list['jobs'] as Raw[];
    h.reply('scan.list', { jobs: [{ ...jobs[0]!, state: 'done', phase: 'done' }, jobs[1]!] });
    const s = raw('scan.status.json');
    h.reply('scan.status', { ...s, state: 'done', elapsed_ms: 50000 });
    await tick(5000);
    const settled = { status: h.count('scan.status'), list: h.count('scan.list') };
    expect(h.m.liveCount()).toBe(0);

    await tick(5000);
    expect(h.count('scan.status')).toBe(settled.status);
    expect(h.count('scan.list')).toBe(settled.list);
  });

  it('nothing_while_not_open: a bus that is not open is never called, and a re-open resyncs', async () => {
    const h = harness();
    h.reply('scan.status', statusFor);
    await h.m.refreshJobs();
    // One read per listed job (W1's re-read rule), then nothing more while the bus is away.
    const seeded = h.count('scan.status');
    expect(seeded).toBe(2);
    h.setBusState('reconnecting');
    const before = h.calls.length;

    await tick(6000);
    expect(h.calls.length).toBe(before);
    await h.m.refreshStatus(JOB);
    await h.m.refreshIssues(JOB);
    await h.m.refreshSitemap(JOB);
    await h.m.refreshJobs();
    expect(h.calls.length).toBe(before);

    h.setBusState('open');
    await tick(50);
    expect(h.count('scan.list')).toBe(2);
    expect(h.count('scan.status')).toBe(seeded + 2);
    expect(h.argsOf('scan.status').slice(seeded).map((a) => a['job'])).toEqual([JOB, OTHER]);
  });

  it('issues_heartbeat: the mounted Issues view re-reads every 5 s while its job is live', async () => {
    const h = harness();
    await h.m.refreshJobs();
    const before = h.count('scan.issues');

    h.m.setIssuesMounted(JOB, true);
    await tick(5000);
    expect(h.count('scan.issues')).toBe(before + 1);
    await tick(5000);
    expect(h.count('scan.issues')).toBe(before + 2);

    h.m.setIssuesMounted(JOB, false);
    await tick(5000);
    expect(h.count('scan.issues')).toBe(before + 2);
  });
});

describe('createLiveModel: pages', () => {
  it('issues_paging: the cursor is sent back and rows append', async () => {
    const h = harness();
    const page = raw('scan.issues.json');
    const rows = page['issues'] as Raw[];
    const bySeverity = page['by_severity'];
    h.reply('scan.issues', (args) =>
      args['cursor']
        ? { issues: [rows[1]!], next_cursor: null, by_severity: bySeverity }
        : { issues: [rows[0]!], next_cursor: 'c1', by_severity: bySeverity },
    );

    await h.m.refreshIssues(JOB);
    expect(h.m.issues(JOB).rows.length).toBe(1);
    expect(h.m.issues(JOB).nextCursor).toBe('c1');
    expect(h.m.issues(JOB).bySeverity.medium).toBe(1);
    expect(h.m.issues(JOB).loading).toBe(false);
    expect(h.m.issues(JOB).error).toBeNull();

    await h.m.loadMoreIssues(JOB);
    expect(h.m.issues(JOB).rows.length).toBe(2);
    expect(h.m.issues(JOB).rows.map((r) => r.id)).toEqual(['issue-9f8e7d6c', 'issue-4c3b2a19']);
    expect(h.m.issues(JOB).nextCursor).toBeNull();
    expect(h.argsOf('scan.issues')[0]).toEqual({ job: JOB, limit: 1024 });
    expect(h.argsOf('scan.issues')[1]).toEqual({ job: JOB, limit: 1024, cursor: 'c1' });

    // No cursor left: nothing more is asked for.
    await h.m.loadMoreIssues(JOB);
    expect(h.count('scan.issues')).toBe(2);
  });

  it('all_jobs_omits_job', async () => {
    const h = harness();
    await h.m.refreshIssues(null);
    expect(h.argsOf('scan.issues')[0]).toEqual({ limit: 1024 });
    expect(h.m.issues(null).rows.length).toBe(2);
    // The "all jobs" page is its own page, not the selected job's.
    expect(h.m.issues(JOB).rows.length).toBe(0);
  });

  it('sitemap_paging', async () => {
    const h = harness();
    const page = raw('scan.sitemap.json');
    const nodes = page['nodes'] as Raw[];
    h.reply('scan.sitemap', (args) =>
      args['cursor'] ? { nodes: [{ ...nodes[0]!, id: 'node-2' }], points: [], next_cursor: null } : page,
    );

    await h.m.refreshSitemap(JOB);
    expect(h.m.sitemap(JOB).nextCursor).toBe('node-2');
    expect(h.m.sitemap(JOB).nodes.length).toBe(1);
    expect(h.m.sitemap(JOB).points.length).toBe(2);
    expect(h.argsOf('scan.sitemap')[0]).toEqual({ job: JOB, limit: 1024 });

    await h.m.loadMoreSitemap(JOB);
    expect(h.m.sitemap(JOB).nodes.map((n) => n.id)).toEqual(['node-1', 'node-2']);
    expect(h.m.sitemap(JOB).nextCursor).toBeNull();
    expect(h.argsOf('scan.sitemap')[1]).toEqual({ job: JOB, limit: 1024, cursor: 'node-2' });
  });

  it('replaceIssueRow swaps the loaded row in place', async () => {
    const h = harness();
    await h.m.refreshIssues(JOB);
    expect(h.m.issues(JOB).rows[0]!.status).toBe('open');
    h.m.replaceIssueRow(parseIssue(fixture('scan.issue.update.json'))!);
    expect(h.m.issues(JOB).rows[0]!.status).toBe('false_positive');
    expect(h.m.issues(JOB).rows.length).toBe(2);
  });
});

describe('createLiveModel: failures', () => {
  it('cancel_returns_cancelling', async () => {
    const h = harness();
    const result = await h.m.cancel(JOB);
    expect(result.ok).toBe(true);
    if (result.ok) expect(result.status.state).toBe('cancelling');
    expect(h.m.status(JOB)!.state).toBe('cancelling');
    expect(h.argsOf('scan.cancel')[0]).toEqual({ job: JOB });
  });

  it('cancel answers the refusal text instead of throwing when the verb refuses (A1)', async () => {
    const h = harness();
    h.fail('scan.cancel', 'scan: not_found: scan-1a2b3c4d');
    await expect(h.m.cancel(JOB)).resolves.toEqual({ ok: false, message: 'scan: not_found: scan-1a2b3c4d' });
    expect(h.m.status(JOB)).toBeNull();

    h.reply('scan.cancel', { nope: 1 });
    await expect(h.m.cancel(JOB)).resolves.toEqual({
      ok: false,
      message: 'scan.cancel answered with an unexpected shape',
    });
  });

  it('statusError holds the raw core text of a failed status read and clears on the next good one (A4)', async () => {
    const h = harness();
    await h.m.refreshStatus(JOB);
    expect(h.m.status(JOB)!.probes.sent).toBe(418);
    expect(h.m.statusError(JOB)).toBeNull();

    h.fail('scan.status', 'scan: not_found: scan-1a2b3c4d');
    await h.m.refreshStatus(JOB);
    expect(h.m.statusError(JOB)).toBe('scan: not_found: scan-1a2b3c4d');
    expect(h.m.status(JOB)!.probes.sent).toBe(418);

    h.reply('scan.status', { nope: 1 });
    await h.m.refreshStatus(JOB);
    expect(h.m.statusError(JOB)).toBe('scan.status answered with an unexpected shape');

    h.reply('scan.status', fixture('scan.status.json'));
    await h.m.refreshStatus(JOB);
    expect(h.m.statusError(JOB)).toBeNull();
    expect(h.m.statusError(OTHER)).toBeNull();
  });

  it('a job named like an Object.prototype key is not found on the prototype (A5)', async () => {
    const h = harness();
    expect(h.m.status('constructor')).toBeNull();
    expect(h.m.statusError('constructor')).toBeNull();
    expect(h.m.issues('constructor').rows).toEqual([]);
    expect(h.m.sitemap('constructor').nodes).toEqual([]);
    expect(h.m.issues('hasOwnProperty').loading).toBe(false);

    h.reply('scan.status', { ...raw('scan.status.json'), job: 'constructor' });
    await h.m.refreshStatus('constructor');
    expect(h.m.status('constructor')!.job).toBe('constructor');
  });

  it('bad_shape_is_an_error: a status reply of the wrong shape changes nothing', async () => {
    const h = harness();
    await h.m.refreshStatus(JOB);
    h.reply('scan.status', { nope: 1 });
    await h.m.refreshStatus(JOB);
    expect(h.m.status(JOB)!.probes.sent).toBe(418);
    expect(h.m.jobsError()).toBeNull();
  });

  it('a page reply of the wrong shape sets that page error, and a rejection its message', async () => {
    const h = harness();
    // A page the parser cannot read at all (the lenient parsers keep a partial object).
    h.reply('scan.issues', 'not a page');
    await h.m.refreshIssues(JOB);
    expect(h.m.issues(JOB).error).toBe('scan.issues answered with an unexpected shape');
    expect(h.m.issues(JOB).loading).toBe(false);

    h.fail('scan.sitemap', 'bus closed');
    await h.m.refreshSitemap(JOB);
    expect(h.m.sitemap(JOB).error).toBe('bus closed');
    expect(h.m.sitemap(JOB).loading).toBe(false);

    h.fail('scan.list', 'bus closed');
    await h.m.refreshJobs();
    expect(h.m.jobsError()).toBe('bus closed');
    expect(h.m.jobsLoaded()).toBe(true);
    expect(h.m.liveCount()).toBeNull();
  });
});

// Jobs view W1 (D18, AC34): the web's C1/C2 shape of the re-read rule. Without a push line the
// 1 Hz poll stops the moment the list turns terminal, which would leave the held status at its
// last running read for ever; so a list reply that calls a job terminal while the held status is
// still live costs exactly one `scan.status` read (`needsStatusRead`), de-duplicated while a read
// for that job is already in flight.
describe('createLiveModel: the re-read rule (W1)', () => {
  const listOf = (...jobs: Raw[]): Raw => ({ jobs });
  const jobRow = (patch: Raw = {}): Raw => ({ ...(raw('scan.list.json')['jobs'] as Raw[])[0]!, ...patch });

  it('terminal_list_rereads_a_running_status: list done over a held running status is one read', async () => {
    const h = harness();
    await h.m.refreshStatus(JOB);
    expect(h.m.status(JOB)!.state).toBe('running');

    h.reply('scan.list', listOf(jobRow({ state: 'done', phase: 'done' })));
    const before = h.count('scan.status');
    await h.m.refreshJobs();
    expect(h.count('scan.status')).toBe(before + 1);
    expect(h.argsOf('scan.status').at(-1)).toEqual({ job: JOB });

    // The held status is already terminal: the list has nothing new to say, so no read follows.
    h.reply('scan.status', { ...raw('scan.status.json'), state: 'done', elapsed_ms: 50000 });
    await h.m.refreshStatus(JOB);
    expect(h.m.status(JOB)!.state).toBe('done');
    const settled = h.count('scan.status');
    await h.m.refreshJobs();
    expect(h.count('scan.status')).toBe(settled);
  });

  it('a listed job with no held status is read once, and a live job with a live held status is not', async () => {
    const h = harness();
    h.reply('scan.list', listOf(jobRow()));
    await h.m.refreshJobs();
    expect(h.argsOf('scan.status')).toEqual([{ job: JOB }]);
    await tick(0);
    expect(h.m.status(JOB)!.state).toBe('running');

    await h.m.refreshJobs();
    expect(h.count('scan.status')).toBe(1);
  });

  it('inflight_dedupe: two list replies before the status answers cost one read', async () => {
    const h = harness();
    await h.m.refreshStatus(JOB);
    let release!: (value: unknown) => void;
    h.reply('scan.status', () => new Promise<unknown>((r) => (release = r)));
    h.reply('scan.list', listOf(jobRow({ state: 'done', phase: 'done' })));
    const before = h.count('scan.status');

    await h.m.refreshJobs();
    await h.m.refreshJobs();
    expect(h.count('scan.status')).toBe(before + 1);

    // The answer lands, the slot frees, and the held status is now terminal: a third list says nothing.
    release({ ...raw('scan.status.json'), state: 'done', elapsed_ms: 50000 });
    await tick(0);
    expect(h.m.status(JOB)!.state).toBe('done');
    await h.m.refreshJobs();
    expect(h.count('scan.status')).toBe(before + 1);
  });
});
