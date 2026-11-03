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
//      The one exception is Scan Again (Jobs view D13): a finished job's status is re-run as
//      `scan.start { profile_name, overrides: { target: { origins } } }`, built by `launch.ts`.
//   2. **The core is the guard** (D-T8.6, W-15): a refusal is classified for its text and shown,
//      never softened and never second-guessed. Nothing in this file decides whether a scan may
//      run; `preflight` (launch.ts) only explains a dimmed button.
//   3. **Push is a trigger, poll is truth** (D-T8.3): every counter comes from `live.ts`, which
//      reads it back from the core. This file adds no counter of its own.

import { batch, createEffect, createMemo, createRoot, createSignal, untrack, type Accessor } from 'solid-js';
import { createStore, produce } from 'solid-js/store';
import type { AppStore } from '~/state/app';
import { findingsState } from '~/panels/findings/state';
import type { L4ScopeEntryWire } from '~/panels/l4/model';

import { EMPTY_FILTER, emptyRecord, isTerminal, own, scanErrorText, type IssueFilter } from './helpers';
import {
  beginLaunch,
  beginScanAgain,
  confirmLaunch as confirmLaunchCall,
  confirmScanAgain,
  scanAgainArgs,
  type Call,
  type LaunchMode,
  type LaunchOutcome,
  type ScanAgainArgs,
} from './launch';
import { createLiveModel, type CancelResult, type LiveModel } from './live';
import {
  parseChecksResult,
  parseIssue,
  parseProfileDeleteResult,
  parseProfileList,
  parseProfileSaveResult,
  parseScanError,
  parseScanProfile,
  parseSessionProfile,
  type CheckMeta,
  type Issue,
  type IssueStatus,
  type ProfileListEntry,
  type ScanErrorCode,
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

/** Which operation an error came from, so a view shows only the errors of the controls it owns. */
export type ScanErrorSource = 'launch' | 'save' | 'delete' | 'preview' | 'cancel' | 'issue' | 'profile';

/**
 * The last failure the operator must see (D-T8.6): where it came from, the `scan:` code the core
 * gave (`null` for a transport error or a shape complaint) and the text `scanErrorText` renders
 * for it. Views branch on `code`/`source`, never on the text.
 */
export interface ScanError {
  source: ScanErrorSource;
  code: ScanErrorCode | null;
  text: string;
}

/**
 * Where a launch came from, held so the confirmed call re-sends the identical arguments: the
 * editor's whole profile under `scan.start` / `scan.map`, or Scan Again's name + origins (D13).
 */
export type PendingConfirmSource =
  | { kind: 'profile'; profile: ScanProfile; mode: LaunchMode }
  | { kind: 'again'; args: ScanAgainArgs };

/** The core's confirmation prompt, held with exactly what is needed to re-issue the launch. */
export interface PendingConfirm {
  prompt: string;
  token: string;
  source: PendingConfirmSource;
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
  /** When `scan.profile.list` last answered without an error (the "last good" of D-T8.10); `null` before it did. */
  profilesLoadedAt: Accessor<number | null>;
  /**
   * Why the last `scan.profile.get` of `name` gave nothing — the rendered text of that refusal —
   * or `null` while the last read of that profile answered. Keyed per name, so one profile's
   * failure never shows under another's editor.
   */
  profileError(name: string): string | null;
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
  lastError: Accessor<ScanError | null>;
  /** `lastError()` when its `source` is one of `sources`, else `null`. */
  errorFor(sources: readonly ScanErrorSource[]): Accessor<ScanError | null>;
  startNotice: Accessor<StartResult | null>;
  dismissStartNotice(): void;
  pendingConfirm: Accessor<PendingConfirm | null>;

  /** `load*` always reads (Retry); `ensure*` joins a read in flight and is a no-op once loaded. */
  loadProfiles(): Promise<void>;
  ensureProfiles(): Promise<void>;
  loadProfile(name: string): Promise<void>;
  saveProfile(profile: ScanProfile): Promise<boolean>;
  deleteProfile(name: string): Promise<boolean>;
  loadChecks(): Promise<void>;
  ensureChecks(): Promise<void>;
  loadL4Scope(): Promise<void>;
  ensureL4Scope(): Promise<void>;
  ensureJobs(): Promise<void>;
  previewSession(origin: string): Promise<SessionProfile | null>;
  launch(profile: ScanProfile, mode: LaunchMode): Promise<LaunchOutcome>;
  /**
   * Scan Again (D13): `scan.start { profile_name, overrides: { target: { origins } } }` from the
   * held status of `job`. Refused here, through `report('launch', …)`, only when no terminal
   * status is held (`Select a finished job.`); everything else is the core's to refuse.
   */
  scanAgain(job: string): Promise<LaunchOutcome>;
  confirmLaunch(): Promise<LaunchOutcome>;
  cancelConfirm(): void;
  cancel(job: string): Promise<CancelResult>;
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
 * `l4.scope.list` is the L4 panel's contract and has no parser anywhere (`panels/l4` trusts the
 * wire shape), so this is the one place it is parsed: anything that is not a usable entry is
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

/**
 * One read, shared: a caller that only needs the data *present* calls `ensure`, which joins the
 * read in flight and does nothing once `loaded()` is true; `load` always reads (Retry, a reconnect)
 * and is what `ensure` joins. Three mounts in the same tick cost one verb (A3).
 */
function sharedLoad(loaded: () => boolean, read: () => Promise<void>): { load(): Promise<void>; ensure(): Promise<void> } {
  let inflight: Promise<void> | null = null;
  const load = (): Promise<void> => {
    const p = read().finally(() => {
      if (inflight === p) inflight = null;
    });
    inflight = p;
    return p;
  };
  const ensure = (): Promise<void> => (loaded() ? Promise.resolve() : (inflight ?? load()));
  return { load, ensure };
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
  const [profilesLoadedAt, setProfilesLoadedAt] = createSignal<number | null>(null);
  const [selectedProfile, setSelectedProfileSignal] = createSignal<string | null>(null);
  const [checks, setChecks] = createSignal<CheckMeta[]>([]);
  const [checksLoaded, setChecksLoaded] = createSignal(false);
  const [checksError, setChecksError] = createSignal<string | null>(null);
  const [l4Entries, setL4Entries] = createSignal<L4ScopeEntryWire[] | null>(null);
  const [selectedNode, setSelectedNodeSignal] = createSignal<string | null>(null);
  const [selectedIssue, setSelectedIssueSignal] = createSignal<string | null>(null);
  const [filter, setFilterSignal] = createSignal<IssueFilter>(EMPTY_FILTER);
  const [busyCount, setBusyCount] = createSignal(0);
  const [lastError, setLastError] = createSignal<ScanError | null>(null);
  const [startNotice, setStartNotice] = createSignal<StartResult | null>(null);
  const [pendingConfirm, setPendingConfirm] = createSignal<PendingConfirm | null>(null);

  // Keyed by wire strings (profile names, issue ids), so: no prototype, every read via `own` (A5).
  const [drafts, setDrafts] = createStore<Record<string, ProfileDraft>>(emptyRecord());
  /** `''` once a read of that name answered: a cleared slot, read back as `null`. */
  const [profileErrors, setProfileErrors] = createStore<Record<string, string>>(emptyRecord());
  const [details, setDetails] = createStore<Record<string, Issue>>(emptyRecord());
  const [detailErrors, setDetailErrors] = createStore<Record<string, string>>(emptyRecord());
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

  /**
   * A refusal is reported, never softened: the code picks the text, an unknown code stays raw, and
   * the parsed code travels with it so a view can act on `out_of_scope` without reading the text.
   */
  function report(source: ScanErrorSource, message: string): ScanError {
    const { code, detail } = parseScanError(message);
    const error: ScanError = { source, code, text: scanErrorText(code, detail) };
    setLastError(error);
    app.notice(error.text, 'error');
    return error;
  }

  const errorFor =
    (sources: readonly ScanErrorSource[]): Accessor<ScanError | null> =>
    () => {
      const e = lastError();
      return e !== null && sources.includes(e.source) ? e : null;
    };

  async function guarded<T>(fn: () => Promise<T>): Promise<T> {
    setBusyCount((n) => n + 1);
    try {
      return await fn();
    } finally {
      setBusyCount((n) => n - 1);
    }
  }

  /* ---------------------------------------------------------------- profiles */

  const { load: loadProfiles, ensure: ensureProfiles } = sharedLoad(profilesLoaded, async () => {
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
      setProfilesLoadedAt(Date.now());
    } catch (e) {
      setProfilesLoaded(true);
      setProfilesError(errorText(e));
    }
  });

  function putDraft(name: string, profile: ScanProfile, dirty: boolean): void {
    setDrafts(name, { profile, dirty });
  }

  /**
   * A no-op while a draft exists: a read must never overwrite what the operator is editing. A
   * failure is reported once (the toast) and kept under its own name (`profileError`) until a
   * read of that same name answers.
   */
  async function loadProfile(name: string): Promise<void> {
    if (!ready() || own(drafts, name)) return;
    try {
      const parsed = parseScanProfile(await app.call<unknown>('scan.profile.get', { name }));
      if (!parsed) {
        setProfileErrors(name, report('profile', shapeError('scan.profile.get')).text);
        return;
      }
      loaded.set(name, parsed);
      batch(() => {
        putDraft(name, parsed, false);
        setProfileErrors(name, '');
      });
    } catch (e) {
      setProfileErrors(name, report('profile', errorText(e)).text);
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
        const saved = parseProfileSaveResult(await app.call<unknown>('scan.profile.save', { profile }));
        if (saved === null) {
          report('save', shapeError('scan.profile.save'));
          return false;
        }
        loaded.set(profile.name, profile);
        if (own(drafts, profile.name)) setDrafts(profile.name, 'dirty', false);
        setLastError(null);
        await loadProfiles();
        return true;
      } catch (e) {
        report('save', errorText(e));
        return false;
      }
    });
  }

  async function deleteProfile(name: string): Promise<boolean> {
    return guarded(async () => {
      try {
        const deleted = parseProfileDeleteResult(await app.call<unknown>('scan.profile.delete', { name }));
        if (deleted === null) {
          report('delete', shapeError('scan.profile.delete'));
          return false;
        }
        loaded.delete(name);
        discardDraft(name);
        if (untrack(selectedProfile) === name) setSelectedProfileSignal(null);
        setLastError(null);
        // The reload is the truth about what is left, whichever way the core answered.
        await loadProfiles();
        return deleted.deleted;
      } catch (e) {
        report('delete', errorText(e));
        return false;
      }
    });
  }

  const { load: loadChecks, ensure: ensureChecks } = sharedLoad(checksLoaded, async () => {
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
  });

  /** Unknown coverage stays `null`: it dims nothing (`preflight`), it only explains. */
  const { load: loadL4Scope, ensure: ensureL4Scope } = sharedLoad(
    () => l4Entries() !== null,
    async () => {
      if (!ready() || !l4Offered()) return;
      try {
        setL4Entries(parseL4Entries(await app.call<unknown>('l4.scope.list')));
      } catch {
        setL4Entries(null);
      }
    },
  );

  const { load: refreshJobs, ensure: ensureJobs } = sharedLoad(live.jobsLoaded, live.refreshJobs);

  /** Names only (D7/W-13): the reply carries no session value and this store holds none. */
  async function previewSession(origin: string): Promise<SessionProfile | null> {
    return guarded(async () => {
      try {
        const parsed = parseSessionProfile(await app.call<unknown>('scan.session.preview', { target: origin }));
        if (!parsed) {
          report('preview', shapeError('scan.session.preview'));
          return null;
        }
        return parsed;
      } catch (e) {
        report('preview', errorText(e));
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

  async function handle(outcome: LaunchOutcome, source: PendingConfirmSource): Promise<LaunchOutcome> {
    switch (outcome.kind) {
      case 'confirm':
        setPendingConfirm({ prompt: outcome.prompt, token: outcome.token, source });
        return outcome;
      case 'started':
        await afterStart(outcome.result);
        return outcome;
      case 'refused': {
        report('launch', outcome.message);
        // The world moved under us: re-read what the refusal says is gone.
        if (outcome.code === 'not_found') {
          await refreshJobs();
          await loadProfiles();
        }
        return outcome;
      }
      case 'malformed':
        report('launch', outcome.message);
        return outcome;
    }
  }

  const call: Call = <T,>(tool: string, params?: Record<string, unknown>): Promise<T> => app.call<T>(tool, params);

  /** The first call of either launch, from its source. */
  const begin = (source: PendingConfirmSource): Promise<LaunchOutcome> =>
    source.kind === 'again' ? beginScanAgain(call, source.args) : beginLaunch(call, source.mode, source.profile);

  /** The confirming call: the same arguments `begin` sent, plus the token. */
  const confirm = (source: PendingConfirmSource, token: string): Promise<LaunchOutcome> =>
    source.kind === 'again'
      ? confirmScanAgain(call, source.args, token)
      : confirmLaunchCall(call, source.mode, source.profile, token);

  async function launch(profile: ScanProfile, mode: LaunchMode): Promise<LaunchOutcome> {
    const source: PendingConfirmSource = { kind: 'profile', profile, mode };
    return guarded(async () => handle(await begin(source), source));
  }

  /**
   * Scan Again's one local gate is the Kit's: a status must be held and terminal. The refusal
   * takes the same path as a core refusal (`report('launch', …)`), so the toast and `lastError`
   * read `Select a finished job.`; nothing is sent. Scope, the tool and the L4 hint are the view's
   * courtesy (`title`) and the core's guard, never second-guessed here.
   */
  async function scanAgain(job: string): Promise<LaunchOutcome> {
    const held = live.status(job);
    if (held === null || !isTerminal(held.state)) {
      const message = 'Select a finished job.';
      report('launch', message);
      return { kind: 'refused', code: null, detail: message, message };
    }
    const source: PendingConfirmSource = { kind: 'again', args: scanAgainArgs(held) };
    return guarded(async () => handle(await begin(source), source));
  }

  /**
   * The second phase of the core's handshake. A stale or reused token comes back as
   * `confirm_required`: the refusal is shown as D-T8.6's "Confirmation required", the worthless
   * token is dropped, and the handshake starts over so the operator sees the core's fresh prompt —
   * nothing is sent confirmed in between.
   */
  async function confirmLaunch(): Promise<LaunchOutcome> {
    const pending = untrack(pendingConfirm);
    if (!pending) return { kind: 'malformed', message: 'no confirmation is pending' };
    setPendingConfirm(null);
    return guarded(async () => {
      const outcome = await confirm(pending.source, pending.token);
      if (outcome.kind === 'refused' && outcome.code === 'confirm_required') {
        report('launch', outcome.message);
        return handle(await begin(pending.source), pending.source);
      }
      return handle(outcome, pending.source);
    });
  }

  function cancelConfirm(): void {
    setPendingConfirm(null);
  }

  /**
   * A refusal answers `{ ok: false }` rather than throwing (`live.ts`), and is reported through the
   * same path as every other verb, so `scan: not_found: x` reads "Not found: x" here too.
   */
  async function cancel(job: string): Promise<CancelResult> {
    const result = await live.cancel(job);
    if (!result.ok) report('cancel', result.message);
    return result;
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
          report('issue', shapeError('scan.issue.update'));
          return null;
        }
        setDetails(id, parsed);
        setDetailErrors(id, '');
        live.replaceIssueRow(parsed);
        setLastError(null);
        return parsed;
      } catch (e) {
        report('issue', errorText(e));
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
  // profiles; the job resync on reconnect is the live model's (`live.ts`). Both go through the
  // shared loads, so a view mounting in the same tick joins these reads instead of repeating them.
  let firstReady = true;
  createEffect(() => {
    if (!ready()) return;
    untrack(() => {
      void loadProfiles();
      if (firstReady) void ensureJobs();
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
    refreshJobs,
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
    profilesLoadedAt,
    profileError: (name: string) => own(profileErrors, name) || null,
    selectedProfile,
    setSelectedProfile: (name: string | null) => setSelectedProfileSignal(name),
    draft: (name: string) => own(drafts, name) ?? null,
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
    issueDetail: (id: string) => own(details, id) ?? null,
    issueDetailError: (id: string) => own(detailErrors, id) || null,

    busy: () => busyCount() > 0,
    lastError,
    errorFor,
    startNotice,
    dismissStartNotice: () => setStartNotice(null),
    pendingConfirm,

    loadProfiles,
    ensureProfiles,
    loadProfile,
    saveProfile,
    deleteProfile,
    loadChecks,
    ensureChecks,
    loadL4Scope,
    ensureL4Scope,
    ensureJobs,
    previewSession,
    launch,
    scanAgain,
    confirmLaunch,
    cancelConfirm,
    loadIssue,
    updateIssue,
    openFlow,
    openPoc,
  };
}
