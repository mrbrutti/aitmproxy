// The v2 Scan surface's store: everything the panel shows and does, held per `AppStore` so it
// outlives the panel (the lower region swaps to the inspector constantly) and so the Sidebar can
// read the live job count before the panel is ever opened. It is `findings/state.ts`'s
// `WeakMap` + `createRoot` pattern with a body: the live job model (`live.ts`) wrapped in
// selection, profile drafts, the launch handshake and the two crossings into the rest of the app
// (a flow, a PoC).
//
// Three rules it exists to keep:
//
//   1. **What you see is what runs** (D-T8.5, W-12): `scan.start` / `scan.map` carry `{ profile }`
//      and `scan.profile.save` carries the whole profile. There is no name/overrides merge here.
//   2. **The core is the guard** (D-T8.6, W-15): a refusal is classified for its text and shown,
//      never softened and never second-guessed. Nothing in this file decides whether a scan may
//      run; `preflight` (launch.ts) only explains a dimmed button.
//   3. **Push is a trigger, poll is truth** (D-T8.3): every counter comes from `live.ts`, which
//      reads it back from the core. This file adds no counter of its own.

import { createEffect, createMemo, createRoot, createSignal, untrack, type Accessor } from 'solid-js';
import { createStore, produce } from 'solid-js/store';
import type { AppStore } from '~/state/app';
import { findingsState } from '~/panels/findings/state';
import type { L4ScopeEntryWire } from '~/panels/l4/model';

import { EMPTY_FILTER, scanErrorText, type IssueFilter } from './helpers';
import {
  beginLaunch,
  confirmLaunch as confirmLaunchCall,
  type Call,
  type LaunchMode,
  type LaunchOutcome,
} from './launch';
import { createLiveModel, type LiveModel } from './live';
import {
  parseChecksResult,
  parseIssue,
  parseProfileList,
  parseScanError,
  parseScanProfile,
  parseSessionProfile,
  type CheckMeta,
  type Issue,
  type IssueStatus,
  type ProfileListEntry,
  type JobStatus,
  type ScanProfile,
  type SessionProfile,
  type StartResult,
} from './model';

/** Which scan engine this core offers (D-T8.1): the v2 family, the v1 `scan.discover`, or neither. */
export type Offered = 'v2' | 'legacy' | 'none';

/** The four views of the surface, in tab-strip order. */
export type Tab = 'profiles' | 'jobs' | 'sitemap' | 'issues';

/** An editor draft: the profile as edited, and whether it differs from the one last loaded. */
export interface ProfileDraft {
  profile: ScanProfile;
  dirty: boolean;
}

/** The core's confirmation prompt, held with exactly what is needed to re-issue the launch. */
export interface PendingConfirm {
  prompt: string;
  token: string;
  mode: LaunchMode;
  profile: ScanProfile;
}

export interface ScanStore extends LiveModel {
  offered: Accessor<Offered>;
  l4Offered: Accessor<boolean>;
  agent: Accessor<boolean>;
  busOpen: Accessor<boolean>;

  tab: Accessor<Tab>;
  setTab(t: Tab): void;
  selectedJob: Accessor<string | null>;
  setSelectedJob(j: string | null): void;
  allJobs: Accessor<boolean>;
  setAllJobs(v: boolean): void;
  /** The job the Issues view reads: `null` is the "All jobs" page. */
  issuesScope: Accessor<string | null>;

  profiles: Accessor<ProfileListEntry[]>;
  profilesLoaded: Accessor<boolean>;
  profilesError: Accessor<string | null>;
  selectedProfile: Accessor<string | null>;
  setSelectedProfile(name: string | null): void;
  draft(name: string): ProfileDraft | null;
  setDraft(name: string, profile: ScanProfile): void;
  discardDraft(name: string): void;

  checks: Accessor<CheckMeta[]>;
  checksLoaded: Accessor<boolean>;
  checksError: Accessor<string | null>;
  /** The live L4 scope, or `null` while it has not been read — `null` never disables anything. */
  l4Entries: Accessor<L4ScopeEntryWire[] | null>;

  selectedNode: Accessor<string | null>;
  setSelectedNode(id: string | null): void;
  selectedIssue: Accessor<string | null>;
  setSelectedIssue(id: string | null): void;
  filter: Accessor<IssueFilter>;
  setFilter(f: IssueFilter): void;
  issueDetail(id: string): Issue | null;
  issueDetailError(id: string): string | null;

  busy: Accessor<boolean>;
  lastError: Accessor<string | null>;
  startNotice: Accessor<StartResult | null>;
  dismissStartNotice(): void;
  pendingConfirm: Accessor<PendingConfirm | null>;

  loadProfiles(): Promise<void>;
  loadProfile(name: string): Promise<void>;
  saveProfile(profile: ScanProfile): Promise<boolean>;
  deleteProfile(name: string): Promise<boolean>;
  loadChecks(): Promise<void>;
  loadL4Scope(): Promise<void>;
  previewSession(origin: string): Promise<SessionProfile | null>;
  launch(profile: ScanProfile, mode: LaunchMode): Promise<LaunchOutcome>;
  confirmLaunch(): Promise<LaunchOutcome>;
  cancelConfirm(): void;
  loadIssue(id: string): Promise<void>;
  updateIssue(id: string, status: IssueStatus, note?: string): Promise<Issue | null>;
  openFlow(id: string): Promise<void>;
  openPoc(ref: string): Promise<void>;
}

const errorText = (e: unknown): string => (e instanceof Error ? e.message : String(e));
const shapeError = (verb: string): string => `${verb} answered with an unexpected shape`;

/** Order-insensitive structural equality over JSON values — the dirty test for a draft. */
function sameJson(a: unknown, b: unknown): boolean {
  if (a === b) return true;
  if (typeof a !== 'object' || typeof b !== 'object' || a === null || b === null) return false;
  if (Array.isArray(a) !== Array.isArray(b)) return false;
  if (Array.isArray(a) && Array.isArray(b)) {
    return a.length === b.length && a.every((x, i) => sameJson(x, b[i]));
  }
  const ao = a as Record<string, unknown>;
  const bo = b as Record<string, unknown>;
  const keys = Object.keys(ao);
  if (keys.length !== Object.keys(bo).length) return false;
  return keys.every((k) => Object.prototype.hasOwnProperty.call(bo, k) && sameJson(ao[k], bo[k]));
}

const DIRECTIONS = ['inbound', 'outbound'] as const;
const CAPABILITIES = ['capture', 'inject', 'intercept'] as const;

/**
 * `l4.scope.list` has no parser in `model.ts` (it is the L4 panel's contract), so it is read
 * defensively here exactly as `panels/l4/store.ts` reads it: anything that is not a usable entry is
 * dropped rather than trusted, because `l4Covered` dims a control from it.
 */
function parseL4Entries(raw: unknown): L4ScopeEntryWire[] | null {
  if (!Array.isArray(raw)) return null;
  const out: L4ScopeEntryWire[] = [];
  for (const v of raw.slice(0, 1024)) {
    if (typeof v !== 'object' || v === null) continue;
    const o = v as Record<string, unknown>;
    const str = (x: unknown): string | null => (typeof x === 'string' && x !== '' ? x : null);
    const id = str(o.id);
    const cidr = str(o.cidr);
    const ports = str(o.ports);
    const iface = typeof o.interface === 'string' ? o.interface : null;
    const direction = DIRECTIONS.find((d) => d === o.direction);
    const capability = CAPABILITIES.find((c) => c === o.capability);
    if (id === null || cidr === null || ports === null || iface === null) continue;
    if (direction === undefined || capability === undefined) continue;
    const rate = typeof o.inject_rate === 'object' && o.inject_rate !== null ? (o.inject_rate as Record<string, unknown>) : {};
    out.push({
      id,
      cidr,
      ports,
      interface: iface,
      direction,
      capability,
      inject_rate: {
        pps: typeof rate.pps === 'number' ? rate.pps : 0,
        burst: typeof rate.burst === 'number' ? rate.burst : 0,
      },
    });
  }
  return out;
}

/** `scan.profile.save` / `scan.profile.delete` are the two replies `model.ts` has no parser for. */
function savedName(raw: unknown): string | null {
  if (typeof raw !== 'object' || raw === null) return null;
  const o = raw as Record<string, unknown>;
  return typeof o.saved === 'string' && typeof o.path === 'string' ? o.saved : null;
}

function deletedFlag(raw: unknown): boolean | null {
  if (typeof raw !== 'object' || raw === null) return null;
  const o = raw as Record<string, unknown>;
  return typeof o.deleted === 'boolean' ? o.deleted : null;
}

const stores = new WeakMap<AppStore, ScanStore>();

/** The store for this app store, built once and reused (the panel mounts and unmounts under it). */
export function scanStore(app: AppStore): ScanStore {
  let s = stores.get(app);
  if (!s) {
    s = createRoot((disposeRoot) => build(app, disposeRoot));
    stores.set(app, s);
  }
  return s;
}

function build(app: AppStore, disposeRoot: () => void): ScanStore {
  // A partial app (the v1 `panels/scan/Scan.test.tsx` stub, a bare mount) has no bus and no tools:
  // every read of it is optional, so building the store can never throw.
  const tools = (): string[] => (app.proxy?.tools ?? []).map((t) => t.name);
  const has = (name: string): boolean => tools().includes(name);
  const offered = createMemo<Offered>(() => (has('scan.start') ? 'v2' : has('scan.discover') ? 'legacy' : 'none'));
  const l4Offered = createMemo(() => has('l4.scope.list'));
  const busOpen = (): boolean => app.bus?.state?.() === 'open';
  const agent = (): boolean => app.bus?.role?.() === 'agent';
  /** Every read below is skipped unless the bus is open and this core runs the v2 engine (W-16). */
  const ready = (): boolean => busOpen() && offered() === 'v2';

  const live = createLiveModel(app, () => offered() === 'v2');

  const [tab, setTabSignal] = createSignal<Tab>('profiles');
  const [picked, setPicked] = createSignal<string | null>(null);
  const [allJobs, setAllJobsSignal] = createSignal(false);
  const [profiles, setProfiles] = createSignal<ProfileListEntry[]>([]);
  const [profilesLoaded, setProfilesLoaded] = createSignal(false);
  const [profilesError, setProfilesError] = createSignal<string | null>(null);
  const [selectedProfile, setSelectedProfileSignal] = createSignal<string | null>(null);
  const [checks, setChecks] = createSignal<CheckMeta[]>([]);
  const [checksLoaded, setChecksLoaded] = createSignal(false);
  const [checksError, setChecksError] = createSignal<string | null>(null);
  const [l4Entries, setL4Entries] = createSignal<L4ScopeEntryWire[] | null>(null);
  const [selectedNode, setSelectedNodeSignal] = createSignal<string | null>(null);
  const [selectedIssue, setSelectedIssueSignal] = createSignal<string | null>(null);
  const [filter, setFilterSignal] = createSignal<IssueFilter>(EMPTY_FILTER);
  const [busyCount, setBusyCount] = createSignal(0);
  const [lastError, setLastError] = createSignal<string | null>(null);
  const [startNotice, setStartNotice] = createSignal<StartResult | null>(null);
  const [pendingConfirm, setPendingConfirm] = createSignal<PendingConfirm | null>(null);

  const [drafts, setDrafts] = createStore<Record<string, ProfileDraft>>({});
  const [details, setDetails] = createStore<Record<string, Issue>>({});
  const [detailErrors, setDetailErrors] = createStore<Record<string, string>>({});
  /** The profile each draft is measured against: what `scan.profile.get` (or a save) last gave. */
  const loaded = new Map<string, ScanProfile>();

  /**
   * The selection follows the list: nothing selected, or a job that is gone, falls back to the
   * newest job. A job just started is kept while the list is still empty (the list read is in
   * flight), so the after-start selection is never lost.
   */
  const selectedJob = (): string | null => {
    const cur = picked();
    const list = live.jobs();
    if (cur !== null && (list.length === 0 || list.some((j) => j.job === cur))) return cur;
    return list[0]?.job ?? null;
  };
  const issuesScope = (): string | null => (allJobs() ? null : selectedJob());

  /** A refusal is reported, never softened: the code picks the text, an unknown code stays raw. */
  function report(message: string): string {
    const { code, detail } = parseScanError(message);
    const text = scanErrorText(code, detail);
    setLastError(text);
    app.notice(text, 'error');
    return text;
  }

  async function guarded<T>(fn: () => Promise<T>): Promise<T> {
    setBusyCount((n) => n + 1);
    try {
      return await fn();
    } finally {
      setBusyCount((n) => n - 1);
    }
  }

  /* ---------------------------------------------------------------- profiles */

  async function loadProfiles(): Promise<void> {
    if (!ready()) return;
    try {
      const parsed = parseProfileList(await app.call<unknown>('scan.profile.list'));
      setProfilesLoaded(true);
      if (!parsed) {
        setProfilesError(shapeError('scan.profile.list'));
        return;
      }
      setProfiles(parsed.profiles);
      setProfilesError(null);
    } catch (e) {
      setProfilesLoaded(true);
      setProfilesError(errorText(e));
    }
  }

  function putDraft(name: string, profile: ScanProfile, dirty: boolean): void {
    setDrafts(name, { profile, dirty });
  }

  /** A no-op while a draft exists: a read must never overwrite what the operator is editing. */
  async function loadProfile(name: string): Promise<void> {
    if (!ready() || drafts[name]) return;
    try {
      const parsed = parseScanProfile(await app.call<unknown>('scan.profile.get', { name }));
      if (!parsed) {
        report(shapeError('scan.profile.get'));
        return;
      }
      loaded.set(name, parsed);
      putDraft(name, parsed, false);
    } catch (e) {
      report(errorText(e));
    }
  }

  function setDraft(name: string, profile: ScanProfile): void {
    const base = loaded.get(name);
    putDraft(name, profile, base === undefined || !sameJson(base, profile));
  }

  function discardDraft(name: string): void {
    setDrafts(produce((d: Record<string, ProfileDraft>) => void delete d[name]));
  }

  /** The whole profile, inline: the core stores exactly what the editor showed (W-12). */
  async function saveProfile(profile: ScanProfile): Promise<boolean> {
    return guarded(async () => {
      try {
        const saved = savedName(await app.call<unknown>('scan.profile.save', { profile }));
        if (saved === null) {
          report(shapeError('scan.profile.save'));
          return false;
        }
        loaded.set(profile.name, profile);
        if (drafts[profile.name]) setDrafts(profile.name, 'dirty', false);
        setLastError(null);
        await loadProfiles();
        return true;
      } catch (e) {
        report(errorText(e));
        return false;
      }
    });
  }

  async function deleteProfile(name: string): Promise<boolean> {
    return guarded(async () => {
      try {
        const deleted = deletedFlag(await app.call<unknown>('scan.profile.delete', { name }));
        if (deleted === null) {
          report(shapeError('scan.profile.delete'));
          return false;
        }
        loaded.delete(name);
        discardDraft(name);
        if (untrack(selectedProfile) === name) setSelectedProfileSignal(null);
        setLastError(null);
        // The reload is the truth about what is left, whichever way the core answered.
        await loadProfiles();
        return deleted;
      } catch (e) {
        report(errorText(e));
        return false;
      }
    });
  }

  async function loadChecks(): Promise<void> {
    if (!ready()) return;
    try {
      const parsed = parseChecksResult(await app.call<unknown>('scan.checks'));
      setChecksLoaded(true);
      if (!parsed) {
        setChecksError(shapeError('scan.checks'));
        return;
      }
      setChecks(parsed.checks);
      setChecksError(null);
    } catch (e) {
      setChecksLoaded(true);
      setChecksError(errorText(e));
    }
  }

  /** Unknown coverage stays `null`: it dims nothing (`preflight`), it only explains. */
  async function loadL4Scope(): Promise<void> {
    if (!ready() || !l4Offered()) return;
    try {
      setL4Entries(parseL4Entries(await app.call<unknown>('l4.scope.list')));
    } catch {
      setL4Entries(null);
    }
  }

  /** Names only (D7/W-13): the reply carries no session value and this store holds none. */
  async function previewSession(origin: string): Promise<SessionProfile | null> {
    return guarded(async () => {
      try {
        const parsed = parseSessionProfile(await app.call<unknown>('scan.session.preview', { target: origin }));
        if (!parsed) {
          report(shapeError('scan.session.preview'));
          return null;
        }
        return parsed;
      } catch (e) {
        report(errorText(e));
        return null;
      }
    });
  }

  /* ---------------------------------------------------------------- launch */

  async function afterStart(result: StartResult): Promise<void> {
    app.notice(`${result.job} started`);
    setStartNotice(result);
    setLastError(null);
    await live.refreshJobs();
    setPicked(result.job);
    setTabSignal('jobs');
  }

  async function handle(outcome: LaunchOutcome, mode: LaunchMode, profile: ScanProfile): Promise<LaunchOutcome> {
    switch (outcome.kind) {
      case 'confirm':
        setPendingConfirm({ prompt: outcome.prompt, token: outcome.token, mode, profile });
        return outcome;
      case 'started':
        await afterStart(outcome.result);
        return outcome;
      case 'refused': {
        report(outcome.message);
        // The world moved under us: re-read what the refusal says is gone.
        if (outcome.code === 'not_found') {
          await live.refreshJobs();
          await loadProfiles();
        }
        return outcome;
      }
      case 'malformed':
        setLastError(outcome.message);
        app.notice(outcome.message, 'error');
        return outcome;
    }
  }

  const call: Call = <T,>(tool: string, params?: Record<string, unknown>): Promise<T> => app.call<T>(tool, params);

  async function launch(profile: ScanProfile, mode: LaunchMode): Promise<LaunchOutcome> {
    return guarded(async () => handle(await beginLaunch(call, mode, profile), mode, profile));
  }

  /**
   * The second phase of the core's handshake. A stale or reused token comes back as
   * `confirm_required`: the token is worthless, so the handshake starts over and the operator sees
   * the core's fresh prompt — nothing is sent confirmed in between.
   */
  async function confirmLaunch(): Promise<LaunchOutcome> {
    const pending = untrack(pendingConfirm);
    if (!pending) return { kind: 'malformed', message: 'no confirmation is pending' };
    setPendingConfirm(null);
    return guarded(async () => {
      const outcome = await confirmLaunchCall(call, pending.mode, pending.profile, pending.token);
      if (outcome.kind === 'refused' && outcome.code === 'confirm_required') {
        return handle(await beginLaunch(call, pending.mode, pending.profile), pending.mode, pending.profile);
      }
      return handle(outcome, pending.mode, pending.profile);
    });
  }

  function cancelConfirm(): void {
    setPendingConfirm(null);
  }

  /** A refusal answers `null` rather than throwing (`live.ts`); the operator is told it failed. */
  async function cancel(job: string): Promise<JobStatus | null> {
    const next = await live.cancel(job);
    if (!next) {
      const text = `Cancel failed for ${job}`;
      setLastError(text);
      app.notice(text, 'error');
    }
    return next;
  }

  /* ---------------------------------------------------------------- issues */

  async function loadIssue(id: string): Promise<void> {
    if (!ready()) return;
    try {
      const parsed = parseIssue(await app.call<unknown>('scan.issue', { id }));
      if (!parsed) {
        setDetailErrors(id, shapeError('scan.issue'));
        return;
      }
      setDetails(id, parsed);
      setDetailErrors(id, '');
    } catch (e) {
      setDetailErrors(id, errorText(e));
    }
  }

  async function updateIssue(id: string, status: IssueStatus, note?: string): Promise<Issue | null> {
    return guarded(async () => {
      try {
        const parsed = parseIssue(
          await app.call<unknown>('scan.issue.update', { id, status, ...(note !== undefined ? { note } : {}) }),
        );
        if (!parsed) {
          report(shapeError('scan.issue.update'));
          return null;
        }
        setDetails(id, parsed);
        setDetailErrors(id, '');
        live.replaceIssueRow(parsed);
        setLastError(null);
        return parsed;
      } catch (e) {
        report(errorText(e));
        return null;
      }
    });
  }

  /* ---------------------------------------------------------------- crossings */

  /** D-T8.8: an issue's flow is the app's own flow selection, not a copy of it. */
  async function openFlow(id: string): Promise<void> {
    app.select(id);
    const detail = await app.loadDetail(id);
    if (detail === null) app.notice(`flow ${id} is not in the store`, 'error');
  }

  /** D-T8.9: `poc_ref` is matched against the Findings list by id, by path, or by bare name. */
  function findPoc(ref: string): { id: string } | null {
    const runs = app.proxy?.findings ?? [];
    return runs.find((r) => r.id === ref || r.poc_path === ref || r.poc_path.endsWith(`/${ref}.yaml`)) ?? null;
  }

  async function openPoc(ref: string): Promise<void> {
    let run = findPoc(ref);
    if (!run) {
      // The run may have landed since the last side-list read; ask once, then give up honestly.
      await app.refreshSide();
      run = findPoc(ref);
    }
    if (!run) {
      app.notice(`PoC ${ref} is not in the Findings list`, 'error');
      return;
    }
    findingsState(app).setSelectedId(run.id);
    app.setSidebar({ kind: 'findings' });
  }

  /* ---------------------------------------------------------------- first read */

  // The first time this core is both open and v2, read what the surface needs before it is opened:
  // the job list (the Sidebar's live count) and the profile list. A later reconnect re-reads the
  // profiles; the job resync on reconnect is the live model's (`live.ts`).
  let firstReady = true;
  createEffect(() => {
    if (!ready()) return;
    untrack(() => {
      void loadProfiles();
      if (firstReady) void live.refreshJobs();
      firstReady = false;
    });
  });

  let disposed = false;
  function dispose(): void {
    if (disposed) return;
    disposed = true;
    live.dispose();
    stores.delete(app);
    disposeRoot();
  }

  return {
    ...live,
    cancel,
    dispose,

    offered,
    l4Offered,
    agent,
    busOpen,

    tab,
    setTab: (t: Tab) => setTabSignal(t),
    selectedJob,
    setSelectedJob: (j: string | null) => setPicked(j),
    allJobs,
    setAllJobs: (v: boolean) => setAllJobsSignal(v),
    issuesScope,

    profiles,
    profilesLoaded,
    profilesError,
    selectedProfile,
    setSelectedProfile: (name: string | null) => setSelectedProfileSignal(name),
    draft: (name: string) => drafts[name] ?? null,
    setDraft,
    discardDraft,

    checks,
    checksLoaded,
    checksError,
    l4Entries,

    selectedNode,
    setSelectedNode: (id: string | null) => setSelectedNodeSignal(id),
    selectedIssue,
    setSelectedIssue: (id: string | null) => setSelectedIssueSignal(id),
    filter,
    setFilter: (f: IssueFilter) => setFilterSignal(f),
    issueDetail: (id: string) => details[id] ?? null,
    issueDetailError: (id: string) => detailErrors[id] || null,

    busy: () => busyCount() > 0,
    lastError,
    startNotice,
    dismissStartNotice: () => setStartNotice(null),
    pendingConfirm,

    loadProfiles,
    loadProfile,
    saveProfile,
    deleteProfile,
    loadChecks,
    loadL4Scope,
    previewSession,
    launch,
    confirmLaunch,
    cancelConfirm,
    loadIssue,
    updateIssue,
    openFlow,
    openPoc,
  };
}
