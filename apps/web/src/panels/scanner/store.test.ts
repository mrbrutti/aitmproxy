// T8 Task 9 (D-T8.1, D-T8.2, D-T8.3, D-T8.5, D-T8.6, D-T8.8, D-T8.9): the panel-independent scan
// store. What these tests pin down is mostly *what leaves this UI*: a launch carries `{ profile }`
// and nothing else, a save carries the whole profile, an update omits an absent `note`, a session
// preview asks for names and is rendered as names. The rest is selection and cache bookkeeping.
//
// The fixtures under `crates/aitm-scan-model/fixtures/` are wire *shapes*, never evidence: a green
// run here says the store holds the contract, not that any scan ever ran (fixtures/README.md).
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { AppStore } from '~/state/app';
import type { PocRun } from '~/bus/types';
import { findingsState } from '~/panels/findings/state';
import { fixture, stubApp } from './testkit';
import { parseScanProfile, type JobStatus, type ScanProfile } from './model';
import { scanStore, type ScanStore } from './store';

const JOB = 'scan-1a2b3c4d';
const ISSUE = 'issue-9f8e7d6c';
const tick = (ms = 0) => vi.advanceTimersByTimeAsync(ms);

/** The `standard` built-in, parsed fresh per test so a mutation cannot leak. */
const standard = (): ScanProfile => parseScanProfile(fixture('scan.profile.get.json'))!;

/** The status fixture as a finished `standard` job against the comp's target (D13, AC37). */
const finished = (over: Partial<JobStatus> = {}): unknown => ({
  ...(fixture('scan.status.json') as Record<string, unknown>),
  state: 'done',
  phase: 'done',
  finished_at: 1761900064000,
  targets: ['http://127.0.0.1:8117'],
  ...over,
});

const poc = (id: string, pocPath: string): PocRun => ({
  id,
  title: id,
  severity: 'medium',
  target: 'http://127.0.0.1:8080',
  passed: true,
  at: 1761900000000,
  origin: 'human',
  poc_path: pocPath,
  yaml: '',
  finding_capture: '',
  screenshot_path: null,
  evaluated: [],
});

const built: ScanStore[] = [];

/** A stub app plus its store (`s`), disposed after the test. */
function harness(opts: Parameters<typeof stubApp>[0] = {}) {
  const stub = stubApp(opts);
  const s = scanStore(stub.app);
  built.push(s);
  return { ...stub, s };
}

beforeEach(() => {
  vi.useFakeTimers();
});

afterEach(() => {
  for (const s of built.splice(0)) s.dispose();
  vi.useRealTimers();
});

describe('scanStore: feature detection and identity', () => {
  it('offered_three_way: v2 wins over legacy, legacy over nothing', () => {
    expect(harness({ tools: ['scan.start', 'scan.discover'] }).s.offered()).toBe('v2');
    expect(harness({ tools: ['scan.discover'] }).s.offered()).toBe('legacy');
    expect(harness({ tools: [] }).s.offered()).toBe('none');
  });

  it('store_survives_across_calls: one store per app store', () => {
    const h = harness();
    expect(scanStore(h.app)).toBe(h.s);
    expect(scanStore(h.app)).toBe(scanStore(h.app));
  });

  it('l4Offered, agent and busOpen read the live app', () => {
    const h = harness({ role: 'agent' });
    expect(h.s.l4Offered()).toBe(true);
    expect(h.s.agent()).toBe(true);
    expect(h.s.busOpen()).toBe(true);
    h.setBusState('reconnecting');
    expect(h.s.busOpen()).toBe(false);
    h.setTools(['scan.start']);
    expect(h.s.l4Offered()).toBe(false);
  });

  it('a partial app (no bus, no tools) builds a store instead of throwing', () => {
    // The shipped v1 `panels/scan/Scan.test.tsx` stub has no `bus` at all; the Sidebar builds the
    // store for its count regardless of which stub mounted the tree.
    const partial = { proxy: { tools: [], scope: [], findings: [] } } as unknown as AppStore;
    const s = scanStore(partial);
    built.push(s);
    expect(s.offered()).toBe('none');
    expect(s.busOpen()).toBe(false);
    expect(s.agent()).toBe(false);
    expect(s.liveCount()).toBeNull();
  });
});

describe('scanStore: profiles (D-T8.5)', () => {
  it('save_sends_whole_profile: the draft goes out whole and the list reloads (W-12)', async () => {
    const h = harness();
    await tick();
    const mine: ScanProfile = { ...standard(), name: 'my-api' };
    h.s.setDraft('my-api', mine);
    expect(h.s.draft('my-api')!.dirty).toBe(true);

    expect(await h.s.saveProfile(h.s.draft('my-api')!.profile)).toBe(true);

    expect(h.argsOf('scan.profile.save')[0]).toEqual({ profile: { ...standard(), name: 'my-api' } });
    expect(h.count('scan.profile.list')).toBe(2);
    expect(h.s.draft('my-api')!.dirty).toBe(false);
    expect(h.s.lastError()).toBeNull();
  });

  it('delete_sends_name: the delete carries the name and drops the draft', async () => {
    const h = harness();
    await tick();
    h.s.setDraft('my-api', { ...standard(), name: 'my-api' });

    expect(await h.s.deleteProfile('my-api')).toBe(true);

    expect(h.argsOf('scan.profile.delete')[0]).toEqual({ name: 'my-api' });
    expect(h.s.draft('my-api')).toBeNull();
    expect(h.count('scan.profile.list')).toBe(2);
  });

  it('a save reply of the wrong shape is an error, not a silent success', async () => {
    const h = harness();
    await tick();
    h.reply('scan.profile.save', { nope: 1 });
    h.s.setDraft('my-api', { ...standard(), name: 'my-api' });

    expect(await h.s.saveProfile(h.s.draft('my-api')!.profile)).toBe(false);

    expect(h.s.lastError()).toEqual({
      source: 'save',
      code: null,
      text: 'scan.profile.save answered with an unexpected shape',
    });
    expect(h.notice).toHaveBeenCalledWith('scan.profile.save answered with an unexpected shape', 'error');
    expect(h.s.draft('my-api')!.dirty).toBe(true);
  });

  it('a refused save surfaces the core text and keeps the draft', async () => {
    const h = harness();
    await tick();
    h.fail('scan.profile.save', 'scan: invalid_profile: standard is a built-in profile');
    h.s.setDraft('standard', standard());

    expect(await h.s.saveProfile(standard())).toBe(false);

    expect(h.s.lastError()!.text).toBe('Invalid profile: standard is a built-in profile');
    expect(h.s.lastError()!.code).toBe('invalid_profile');
    expect(h.s.lastError()!.source).toBe('save');
    expect(h.s.errorFor(['save'])()!.text).toBe('Invalid profile: standard is a built-in profile');
    expect(h.s.draft('standard')).not.toBeNull();
  });

  it('loadProfiles fills the list and loadProfile is a no-op while a draft exists', async () => {
    const h = harness();
    await tick();
    expect(h.s.profilesLoaded()).toBe(true);
    expect(h.s.profiles().map((p) => p.name)).toEqual([
      'passive-only',
      'map-only',
      'light-http',
      'standard',
      'thorough',
      'l4-stream-safe',
      'l4-full',
    ]);

    await h.s.loadProfile('standard');
    expect(h.argsOf('scan.profile.get')[0]).toEqual({ name: 'standard' });
    expect(h.s.draft('standard')!.profile.name).toBe('standard');
    expect(h.s.draft('standard')!.dirty).toBe(false);

    await h.s.loadProfile('standard');
    expect(h.count('scan.profile.get')).toBe(1);

    h.s.discardDraft('standard');
    expect(h.s.draft('standard')).toBeNull();
    await h.s.loadProfile('standard');
    expect(h.count('scan.profile.get')).toBe(2);
  });

  it('profileError is keyed per name: a failed read lands on that profile only and clears on the next good one', async () => {
    const h = harness();
    await tick();
    h.fail('scan.profile.get', 'scan: not_found: thorough');
    await h.s.loadProfile('thorough');
    expect(h.s.profileError('thorough')).toBe('Not found: thorough');
    expect(h.s.profileError('standard')).toBeNull();
    expect(h.s.draft('thorough')).toBeNull();
    // The toast still goes out through the shared error channel.
    expect(h.s.lastError()).toEqual({ source: 'profile', code: 'not_found', text: 'Not found: thorough' });

    h.reply('scan.profile.get', { ...standard(), name: 'thorough' });
    await h.s.loadProfile('thorough');
    expect(h.s.profileError('thorough')).toBeNull();
    expect(h.s.draft('thorough')!.profile.name).toBe('thorough');

    // A profile named like an Object.prototype key reads its own slot, never the prototype (A5).
    expect(h.s.profileError('constructor')).toBeNull();
    expect(h.s.profileError('__proto__')).toBeNull();
  });

  it('profilesLoadedAt is the time of the last good list read, untouched by a failed one', async () => {
    const T = Date.UTC(2026, 9, 31, 14, 3, 22);
    vi.setSystemTime(T);
    const h = harness();
    expect(h.s.profilesLoadedAt()).toBeNull();
    await h.s.loadProfiles();
    expect(h.s.profilesLoadedAt()).toBe(T);
    vi.setSystemTime(T + 60_000);
    h.fail('scan.profile.list', 'bus closed');
    await h.s.loadProfiles();
    expect(h.s.profilesError()).toBe('bus closed');
    expect(h.s.profilesLoadedAt()).toBe(T);
  });

  it('a draft equal to the loaded profile is not dirty', async () => {
    const h = harness();
    await h.s.loadProfile('standard');
    h.s.setDraft('standard', standard());
    expect(h.s.draft('standard')!.dirty).toBe(false);
    h.s.setDraft('standard', { ...standard(), intensity: 'intrusive' });
    expect(h.s.draft('standard')!.dirty).toBe(true);
  });

  it('preview_names_only: the preview asks for a target and comes back as names (W-13)', async () => {
    const h = harness();
    const session = await h.s.previewSession('http://127.0.0.1:8080');
    expect(session!.cookies).toEqual(['sid']);
    expect(session!.headers).toEqual(['authorization']);
    expect(h.argsOf('scan.session.preview')[0]).toEqual({ target: 'http://127.0.0.1:8080' });
  });

  it('loadChecks and loadL4Scope fill the catalogue and the L4 scope', async () => {
    const h = harness();
    await h.s.loadChecks();
    expect(h.s.checksLoaded()).toBe(true);
    expect(h.s.checks().map((c) => c.id)).toEqual(['http.reflected-xss', 'http.sqli-error', 'http.custom-marker']);

    expect(h.s.l4Entries()).toBeNull();
    h.reply('l4.scope.list', [
      { id: 'e1', cidr: '127.0.0.0/8', ports: '0-65535', interface: '*', direction: 'outbound', capability: 'inject', inject_rate: { pps: 100, burst: 100 } },
      { id: 'bad' },
    ]);
    await h.s.loadL4Scope();
    expect(h.s.l4Entries()).toEqual([
      { id: 'e1', cidr: '127.0.0.0/8', ports: '0-65535', interface: '*', direction: 'outbound', capability: 'inject', inject_rate: { pps: 100, burst: 100 } },
    ]);
  });

  it('ensureProfiles joins the read in flight, is a no-op once loaded, and loadProfiles still re-reads (A3)', async () => {
    const h = harness();
    // The store's own bootstrap already asked once; two concurrent ensures ride that read.
    const a = h.s.ensureProfiles();
    const b = h.s.ensureProfiles();
    expect(h.count('scan.profile.list')).toBe(1);
    await Promise.all([a, b]);
    expect(h.s.profilesLoaded()).toBe(true);

    await h.s.ensureProfiles();
    expect(h.count('scan.profile.list')).toBe(1);

    await h.s.loadProfiles();
    expect(h.count('scan.profile.list')).toBe(2);
  });

  it('ensureChecks, ensureL4Scope and ensureJobs memoise the same way (A3)', async () => {
    const h = harness();
    await Promise.all([h.s.ensureChecks(), h.s.ensureChecks()]);
    expect(h.count('scan.checks')).toBe(1);
    await h.s.ensureChecks();
    expect(h.count('scan.checks')).toBe(1);
    await h.s.loadChecks();
    expect(h.count('scan.checks')).toBe(2);

    await Promise.all([h.s.ensureL4Scope(), h.s.ensureL4Scope()]);
    expect(h.count('l4.scope.list')).toBe(1);
    await h.s.ensureL4Scope();
    expect(h.count('l4.scope.list')).toBe(1);

    // The bootstrap read the list once; ensureJobs rides it and never asks again once loaded.
    await Promise.all([h.s.ensureJobs(), h.s.ensureJobs()]);
    expect(h.count('scan.list')).toBe(1);
    await h.s.ensureJobs();
    expect(h.count('scan.list')).toBe(1);
    await h.s.refreshJobs();
    expect(h.count('scan.list')).toBe(2);
  });

  it('a profile named like an Object.prototype key loads instead of reading the prototype (A5)', async () => {
    const h = harness();
    await tick();
    expect(h.s.draft('constructor')).toBeNull();
    expect(h.s.issueDetail('constructor')).toBeNull();
    expect(h.s.issueDetailError('constructor')).toBeNull();

    h.reply('scan.profile.get', { ...standard(), name: 'constructor' });
    await h.s.loadProfile('constructor');

    expect(h.count('scan.profile.get')).toBe(1);
    expect(h.argsOf('scan.profile.get')[0]).toEqual({ name: 'constructor' });
    expect(h.s.draft('constructor')!.profile.name).toBe('constructor');
    expect(h.s.draft('constructor')!.dirty).toBe(false);
    expect(h.s.lastError()).toBeNull();
  });
});

describe('scanStore: launch (D-T8.6)', () => {
  it('launch_sends_profile_only: nothing but the profile leaves the UI (W-12)', async () => {
    const h = harness();
    const profile = standard();
    await h.s.launch(profile, 'start');
    expect(h.argsOf('scan.start')[0]).toEqual({ profile });
    expect(Object.keys(h.argsOf('scan.start')[0]!)).toEqual(['profile']);
    expect(h.s.busy()).toBe(false);
  });

  it('after_start_selects_and_switches: the started job becomes the selection', async () => {
    const h = harness();
    await tick();
    expect(h.s.tab()).toBe('profiles');
    // Parked on another job, so the new selection can only come from the start result.
    h.s.setSelectedJob('scan-55667788');
    const outcome = await h.s.launch(standard(), 'start');
    expect(outcome.kind).toBe('started');
    expect(h.s.selectedJob()).toBe(JOB);
    expect(h.s.tab()).toBe('jobs');
    expect(h.s.startNotice()!.clamped[0]!.applied).toBe(20000);
    expect(h.notice).toHaveBeenCalledWith('scan-1a2b3c4d started');
    h.s.dismissStartNotice();
    expect(h.s.startNotice()).toBeNull();
  });

  it('confirm_flow: the dialog is the core prompt, cancel sends nothing, confirm carries the token (W-9)', async () => {
    const h = harness({ replies: { 'scan.start': { status: 'needs_confirmation', prompt: 'P', confirm_token: 't1' } } });
    const profile = standard();

    await h.s.launch(profile, 'start');
    expect(h.s.pendingConfirm()!.prompt).toBe('P');
    expect(h.s.pendingConfirm()!.token).toBe('t1');

    h.s.cancelConfirm();
    expect(h.s.pendingConfirm()).toBeNull();
    expect(h.count('scan.start')).toBe(1);

    await h.s.launch(profile, 'start');
    h.reply('scan.start', fixture('scan.start.json'));
    const outcome = await h.s.confirmLaunch();

    expect(outcome.kind).toBe('started');
    expect(h.argsOf('scan.start')[2]).toEqual({ profile, _confirm: 't1' });
    expect(h.s.pendingConfirm()).toBeNull();
  });

  it('refused_agent_text: a guard refusal is explained, never softened (W-15)', async () => {
    const h = harness({ role: 'agent' });
    h.fail('scan.start', 'scan: refused_agent: agent session');

    const outcome = await h.s.launch(standard(), 'start');

    expect(outcome.kind).toBe('refused');
    expect(h.s.lastError()!.text.startsWith('Agent session: the core refuses active scans')).toBe(true);
    expect(h.s.lastError()!.code).toBe('refused_agent');
    expect(h.s.lastError()!.source).toBe('launch');
    expect(h.s.agent()).toBe(true);
    expect(h.notice).toHaveBeenCalledWith(h.s.lastError()!.text, 'error');
    // The convenience filter: a launch error is visible to the editor, not to the issues view.
    expect(h.s.errorFor(['launch', 'save'])()).toBe(h.s.lastError());
    expect(h.s.errorFor(['issue'])()).toBeNull();
  });

  it('a malformed start reply is reported instead of inventing a job', async () => {
    const h = harness({ replies: { 'scan.start': {} } });
    const outcome = await h.s.launch(standard(), 'start');
    expect(outcome.kind).toBe('malformed');
    expect(h.s.lastError()).toEqual({
      source: 'launch',
      code: null,
      text: 'scan.start answered with an unexpected shape',
    });
    expect(h.notice).toHaveBeenCalledWith('scan.start answered with an unexpected shape', 'error');
    // Nothing was invented from the reply: no after-start notice, no switch to the Jobs view.
    expect(h.s.startNotice()).toBeNull();
    expect(h.s.tab()).toBe('profiles');
  });

  it('confirmLaunch with nothing pending sends nothing', async () => {
    const h = harness();
    const outcome = await h.s.confirmLaunch();
    expect(outcome).toEqual({ kind: 'malformed', message: 'no confirmation is pending' });
    expect(h.count('scan.start')).toBe(0);
  });

  it('a not_found refusal re-reads the list and the profiles', async () => {
    const h = harness();
    await tick();
    const lists = h.count('scan.list');
    const profiles = h.count('scan.profile.list');
    h.fail('scan.map', 'scan: not_found: profile gone');

    await h.s.launch(standard(), 'map');

    expect(h.s.lastError()).toEqual({ source: 'launch', code: 'not_found', text: 'Not found: profile gone' });
    expect(h.count('scan.list')).toBe(lists + 1);
    expect(h.count('scan.profile.list')).toBe(profiles + 1);
  });

  it('a stale confirm token shows "Confirmation required" and re-runs the handshake (A7, D-T8.6)', async () => {
    const h = harness();
    let prompts = 0;
    h.reply('scan.start', (args) => {
      if (typeof args._confirm === 'string') return Promise.reject(new Error('scan: confirm_required: stale'));
      prompts += 1;
      return { status: 'needs_confirmation', prompt: `P${prompts}`, confirm_token: `t${prompts}` };
    });

    await h.s.launch(standard(), 'start');
    expect(h.s.pendingConfirm()!.prompt).toBe('P1');

    const outcome = await h.s.confirmLaunch();

    expect(outcome.kind).toBe('confirm');
    expect(h.s.lastError()!.text).toBe('Confirmation required');
    expect(h.s.lastError()!.code).toBe('confirm_required');
    expect(h.notice).toHaveBeenCalledWith('Confirmation required', 'error');
    expect(h.count('scan.start')).toBe(3);
    expect(h.argsOf('scan.start')[1]!._confirm).toBe('t1');
    expect(h.s.pendingConfirm()!.prompt).toBe('P2');
    expect(h.s.pendingConfirm()!.token).toBe('t2');
  });
});

describe('scanStore: Scan Again (Jobs view D13, AC37)', () => {
  it('scan_again_sends_profile_name_and_overrides: the held status names the profile and the origins', async () => {
    const h = harness();
    await tick();
    h.reply('scan.status', finished());
    await h.s.refreshStatus(JOB);
    expect(h.s.status(JOB)!.state).toBe('done');
    h.reply('scan.start', { status: 'needs_confirmation', prompt: 'P', confirm_token: 't1' });

    const first = await h.s.scanAgain(JOB);

    expect(first.kind).toBe('confirm');
    expect(h.argsOf('scan.start')[0]).toEqual({
      profile_name: 'standard',
      overrides: { target: { origins: ['http://127.0.0.1:8117'] } },
    });
    expect(Object.keys(h.argsOf('scan.start')[0]!)).toEqual(['profile_name', 'overrides']);
    const pending = h.s.pendingConfirm()!;
    expect(pending.prompt).toBe('P');
    expect(pending.token).toBe('t1');
    expect(pending.source.kind).toBe('again');
    if (pending.source.kind !== 'again') throw new Error('expected an again source');
    expect(pending.source.args).toEqual({
      profile_name: 'standard',
      overrides: { target: { origins: ['http://127.0.0.1:8117'] } },
    });

    h.reply('scan.start', fixture('scan.start.json'));
    const outcome = await h.s.confirmLaunch();

    expect(outcome.kind).toBe('started');
    expect(h.argsOf('scan.start')[1]).toEqual({
      profile_name: 'standard',
      overrides: { target: { origins: ['http://127.0.0.1:8117'] } },
      _confirm: 't1',
    });
    expect(h.count('scan.start')).toBe(2);
    expect(h.s.pendingConfirm()).toBeNull();
    expect(h.s.selectedJob()).toBe(JOB);
    expect(h.s.tab()).toBe('jobs');
    expect(h.s.lastError()).toBeNull();
  });

  it('a direct start result runs through the same after-start path as Start Scan', async () => {
    const h = harness();
    await tick();
    h.reply('scan.status', finished());
    await h.s.refreshStatus(JOB);
    h.s.setSelectedJob('scan-55667788');

    const outcome = await h.s.scanAgain(JOB);

    expect(outcome.kind).toBe('started');
    expect(h.count('scan.start')).toBe(1);
    expect(h.s.selectedJob()).toBe(JOB);
    expect(h.notice).toHaveBeenCalledWith('scan-1a2b3c4d started');
  });

  it('refuses without a held terminal status: "Select a finished job." through report, nothing sent', async () => {
    const h = harness();
    await tick();
    // Nothing held yet for this job.
    let outcome = await h.s.scanAgain(JOB);
    expect(outcome.kind).toBe('refused');
    expect(h.s.lastError()).toEqual({ source: 'launch', code: null, text: 'Select a finished job.' });
    expect(h.notice).toHaveBeenCalledWith('Select a finished job.', 'error');

    // Held, but still running (the fixture's state).
    await h.s.refreshStatus(JOB);
    expect(h.s.status(JOB)!.state).toBe('running');
    outcome = await h.s.scanAgain(JOB);
    expect(outcome.kind).toBe('refused');
    if (outcome.kind !== 'refused') throw new Error('expected refused');
    expect(outcome.message).toBe('Select a finished job.');
    expect(h.count('scan.start')).toBe(0);
    expect(h.s.pendingConfirm()).toBeNull();
  });

  it('a core refusal of Scan Again is reported under launch, never softened', async () => {
    const h = harness();
    await tick();
    h.reply('scan.status', finished({ profile_name: '' }));
    await h.s.refreshStatus(JOB);
    h.fail('scan.start', 'scan: invalid_profile: no profile named');

    const outcome = await h.s.scanAgain(JOB);

    expect(outcome.kind).toBe('refused');
    expect(h.argsOf('scan.start')[0]).toEqual({ profile_name: '', overrides: { target: { origins: ['http://127.0.0.1:8117'] } } });
    expect(h.s.lastError()).toEqual({ source: 'launch', code: 'invalid_profile', text: 'Invalid profile: no profile named' });
    expect(h.s.busy()).toBe(false);
  });

  it('a stale Scan Again token re-runs the Scan Again handshake, not a profile launch', async () => {
    const h = harness();
    await tick();
    h.reply('scan.status', finished());
    await h.s.refreshStatus(JOB);
    let prompts = 0;
    h.reply('scan.start', (args) => {
      if (typeof args._confirm === 'string') return Promise.reject(new Error('scan: confirm_required: stale'));
      prompts += 1;
      return { status: 'needs_confirmation', prompt: `P${prompts}`, confirm_token: `t${prompts}` };
    });

    await h.s.scanAgain(JOB);
    const outcome = await h.s.confirmLaunch();

    expect(outcome.kind).toBe('confirm');
    expect(h.s.lastError()!.code).toBe('confirm_required');
    expect(h.count('scan.start')).toBe(3);
    for (const args of h.argsOf('scan.start')) {
      expect(args.profile_name).toBe('standard');
      expect(args.profile).toBeUndefined();
    }
    expect(h.s.pendingConfirm()!.source.kind).toBe('again');
    expect(h.s.pendingConfirm()!.token).toBe('t2');
  });

  it('a Start Scan confirmation carries a profile source', async () => {
    const h = harness({ replies: { 'scan.map': { status: 'needs_confirmation', prompt: 'P', confirm_token: 't1' } } });
    const profile = standard();
    await h.s.launch(profile, 'map');
    const pending = h.s.pendingConfirm()!;
    expect(pending.source.kind).toBe('profile');
    if (pending.source.kind !== 'profile') throw new Error('expected a profile source');
    expect(pending.source.mode).toBe('map');
    expect(pending.source.profile).toEqual(profile);
  });
});

describe('scanStore: jobs and issues (D-T8.2, D-T8.9)', () => {
  it('selected_job_defaults_to_newest: the first listed job is the selection', async () => {
    const h = harness();
    await h.s.refreshJobs();
    expect(h.s.selectedJob()).toBe(JOB);
    h.s.setSelectedJob('scan-55667788');
    expect(h.s.selectedJob()).toBe('scan-55667788');
    // A job that vanished from the list falls back to the newest one.
    h.s.setSelectedJob('scan-deadbeef');
    expect(h.s.selectedJob()).toBe(JOB);
  });

  it('issues_scope: "All jobs" scopes the Issues page to every job', async () => {
    const h = harness();
    await h.s.refreshJobs();
    expect(h.s.allJobs()).toBe(false);
    expect(h.s.issuesScope()).toBe(JOB);
    h.s.setAllJobs(true);
    expect(h.s.issuesScope()).toBeNull();
  });

  it('a cancel the core refused is reported through the same text as every other verb (A1)', async () => {
    const h = harness();
    h.fail('scan.cancel', 'scan: not_found: scan-1a2b3c4d');
    const result = await h.s.cancel(JOB);
    expect(result.ok).toBe(false);
    expect(h.s.lastError()!.text.startsWith('Not found:')).toBe(true);
    expect(h.s.lastError()).toEqual({ source: 'cancel', code: 'not_found', text: 'Not found: scan-1a2b3c4d' });
    expect(h.notice).toHaveBeenCalledWith('Not found: scan-1a2b3c4d', 'error');

    h.reply('scan.cancel', { nope: 1 });
    await h.s.cancel(JOB);
    expect(h.s.lastError()!.text).toBe('scan.cancel answered with an unexpected shape');
  });

  it('cancel that the core accepted reports the two-step state', async () => {
    const h = harness();
    h.reply('scan.cancel', fixture('scan.cancel.json'));
    const result = await h.s.cancel(JOB);
    expect(result.ok).toBe(true);
    if (result.ok) expect(result.status.state).toBe('cancelling');
    expect(h.s.lastError()).toBeNull();
  });

  it('update_issue_replaces_row: the detail and the loaded row both move', async () => {
    const h = harness();
    await h.s.refreshIssues(JOB);
    await h.s.loadIssue(ISSUE);
    expect(h.s.issueDetail(ISSUE)!.status).toBe('open');
    expect(h.argsOf('scan.issue')[0]).toEqual({ id: ISSUE });

    h.reply('scan.issue.update', fixture('scan.issue.update.json'));
    const updated = await h.s.updateIssue(ISSUE, 'false_positive', 'intended behaviour');

    expect(updated!.status).toBe('false_positive');
    expect(h.argsOf('scan.issue.update')[0]).toEqual({ id: ISSUE, status: 'false_positive', note: 'intended behaviour' });
    expect(h.s.issueDetail(ISSUE)!.status).toBe('false_positive');
    expect(h.s.issues(JOB).rows[0]!.status).toBe('false_positive');

    await h.s.updateIssue(ISSUE, 'false_positive');
    expect(Object.keys(h.argsOf('scan.issue.update')[1]!)).toEqual(['id', 'status']);
  });

  it('a failed issue read lands on that id, not on the page', async () => {
    const h = harness();
    h.fail('scan.issue', 'bus closed');
    await h.s.loadIssue(ISSUE);
    expect(h.s.issueDetail(ISSUE)).toBeNull();
    expect(h.s.issueDetailError(ISSUE)).toBe('bus closed');
    expect(h.s.lastError()).toBeNull();
  });

  it('the filter and the per-view selections are store state', () => {
    const h = harness();
    expect(h.s.filter().text).toBe('');
    h.s.setFilter({ ...h.s.filter(), text: 'redirect' });
    expect(h.s.filter().text).toBe('redirect');
    h.s.setSelectedIssue(ISSUE);
    expect(h.s.selectedIssue()).toBe(ISSUE);
    h.s.setSelectedNode('node-1');
    expect(h.s.selectedNode()).toBe('node-1');
    h.s.setTab('sitemap');
    expect(h.s.tab()).toBe('sitemap');
    h.s.setSelectedProfile('standard');
    expect(h.s.selectedProfile()).toBe('standard');
  });
});

describe('scanStore: crossing into the rest of the app (D-T8.8, D-T8.9)', () => {
  it('open_flow: the flow is selected and loaded, and a missing one says so', async () => {
    const h = harness();
    h.loadDetail.mockResolvedValueOnce({ id: 'f1' });

    await h.s.openFlow('f1');
    expect(h.select).toHaveBeenCalledWith('f1');
    expect(h.loadDetail).toHaveBeenCalledWith('f1');
    expect(h.notice).not.toHaveBeenCalled();

    await h.s.openFlow('f1');
    expect(h.notice).toHaveBeenCalledWith('flow f1 is not in the store', 'error');
  });

  it('open_poc_matches_three_ways: id, path and bare name all reach Findings', async () => {
    const h = harness({ findings: [poc('poc-3b1c', '/x/a.yaml'), poc('r2', '/x/poc-77.yaml')] });

    await h.s.openPoc('poc-3b1c');
    expect(h.setSidebar).toHaveBeenCalledWith({ kind: 'findings' });
    expect(findingsState(h.app).selectedId()).toBe('poc-3b1c');

    findingsState(h.app).setSelectedId(null);
    await h.s.openPoc('/x/a.yaml');
    expect(findingsState(h.app).selectedId()).toBe('poc-3b1c');

    await h.s.openPoc('poc-77');
    expect(findingsState(h.app).selectedId()).toBe('r2');
    expect(h.refreshSide).not.toHaveBeenCalled();
  });

  it('open_poc: a miss re-reads the side lists once and then says so', async () => {
    const h = harness({ findings: [poc('poc-3b1c', '/x/a.yaml')] });

    await h.s.openPoc('missing');

    expect(h.refreshSide).toHaveBeenCalledTimes(1);
    expect(h.notice).toHaveBeenCalledWith('PoC missing is not in the Findings list', 'error');
    expect(h.setSidebar).not.toHaveBeenCalled();
  });
});

describe('scanStore: the clock (Jobs view D6 amendment, D16, AC38)', () => {
  it('now_ms_ticks_once_a_second_and_stops_on_dispose: the store owns the one timer the banner age reads', async () => {
    const T = Date.UTC(2026, 9, 31, 14, 3, 22);
    vi.setSystemTime(T);
    const h = harness();
    expect(h.s.nowMs()).toBe(T);
    await tick(1_000);
    expect(h.s.nowMs()).toBe(T + 1_000);
    await tick(1_000);
    expect(h.s.nowMs()).toBe(T + 2_000);
    // Nothing between the ticks moves it: the clock is the interval's, not every read's.
    vi.setSystemTime(T + 2_500);
    expect(h.s.nowMs()).toBe(T + 2_000);

    h.s.dispose();
    await tick(3_000);
    expect(h.s.nowMs()).toBe(T + 2_000);
  });
});
