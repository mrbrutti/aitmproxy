// T8 Task 9 (D-T8.1, D-T8.2, D-T8.3, D-T8.5, D-T8.6, D-T8.8, D-T8.9): the panel-independent scan
// store. What these tests pin down is mostly *what leaves this UI*: a launch carries `{ profile }`
// and nothing else, a save carries the whole profile, an update omits an absent `note`, a session
// preview asks for names and is rendered as names. The rest is selection and cache bookkeeping.
//
// The fixtures under `crates/aitm-scan-model/fixtures/` are wire *shapes*, never evidence: a green
// run here says the store holds the contract, not that any scan ever ran (fixtures/README.md).
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import type { AppStore } from '~/state/app';
import type { PocRun } from '~/bus/mock';
import { findingsState } from '~/panels/findings/state';
import { stubApp } from './testkit';
import { parseScanProfile, type ScanProfile } from './model';
import { scanStore, type ScanStore } from './store';

const here = dirname(fileURLToPath(import.meta.url));
const fixture = (name: string): unknown =>
  JSON.parse(readFileSync(resolve(here, '../../../../../crates/aitm-scan-model/fixtures', name), 'utf8'));

const JOB = 'scan-1a2b3c4d';
const ISSUE = 'issue-9f8e7d6c';
const tick = (ms = 0) => vi.advanceTimersByTimeAsync(ms);

/** The `standard` built-in, parsed fresh per test so a mutation cannot leak. */
const standard = (): ScanProfile => parseScanProfile(fixture('scan.profile.get.json'))!;

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

    expect(h.s.lastError()).toBe('scan.profile.save answered with an unexpected shape');
    expect(h.notice).toHaveBeenCalledWith('scan.profile.save answered with an unexpected shape', 'error');
    expect(h.s.draft('my-api')!.dirty).toBe(true);
  });

  it('a refused save surfaces the core text and keeps the draft', async () => {
    const h = harness();
    await tick();
    h.fail('scan.profile.save', 'scan: invalid_profile: standard is a built-in profile');
    h.s.setDraft('standard', standard());

    expect(await h.s.saveProfile(standard())).toBe(false);

    expect(h.s.lastError()).toBe('Invalid profile: standard is a built-in profile');
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
    expect(h.s.lastError()!.startsWith('Agent session: the core refuses active scans')).toBe(true);
    expect(h.s.agent()).toBe(true);
    expect(h.notice).toHaveBeenCalledWith(h.s.lastError(), 'error');
  });

  it('a malformed start reply is reported instead of inventing a job', async () => {
    const h = harness({ replies: { 'scan.start': {} } });
    const outcome = await h.s.launch(standard(), 'start');
    expect(outcome.kind).toBe('malformed');
    expect(h.s.lastError()).toBe('scan.start answered with an unexpected shape');
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

    expect(h.s.lastError()).toBe('Not found: profile gone');
    expect(h.count('scan.list')).toBe(lists + 1);
    expect(h.count('scan.profile.list')).toBe(profiles + 1);
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

  it('a cancel the core refused is reported, not swallowed', async () => {
    const h = harness();
    h.reply('scan.cancel', { nope: 1 });
    expect(await h.s.cancel(JOB)).toBeNull();
    expect(h.s.lastError()).toBe(`Cancel failed for ${JOB}`);
    expect(h.notice).toHaveBeenCalledWith(`Cancel failed for ${JOB}`, 'error');
  });

  it('cancel that the core accepted reports the two-step state', async () => {
    const h = harness();
    h.reply('scan.cancel', fixture('scan.cancel.json'));
    expect((await h.s.cancel(JOB))!.state).toBe('cancelling');
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
