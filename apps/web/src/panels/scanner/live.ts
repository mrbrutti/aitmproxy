// The live job model of the v2 Scan surface (D-T8.3 "Live update model" and "Monotonic", umbrella
// D3 "Progress push"): **push is a trigger, poll is truth**, the rule the flow store already runs
// on (`state/app.ts:498-520`).
//
// A `notifications/aitm/job` line is never written into the store — not its `status` summary, not
// its `issue` payload. It only schedules a read of `scan.status` (coalesced per job), and for the
// events that change the shape of the world (`started`, `issue`, the three terminal ones) the
// matching list/page read. Everything the UI renders therefore came back from a verb the core
// answered. A reply that would move `elapsed_ms` backwards while the job is still running is
// dropped whole (`isStale`), so counters never step back (D5). While any job is live the model
// polls at 1 Hz for status and 5 s for the list (a job started by the TUI, the mac app or an agent
// has no push for this client), and stops once every job is terminal. Nothing here touches the bus
// unless it is `open` and the v2 engine is offered (W-16): a call into a reconnecting bus can wait
// on it indefinitely.
//
// The model owns no panel state: `store.ts` (Task 9) wraps it and adds selection, drafts and the
// launch path. It is built inside the caller's `createRoot` and freed with `dispose()`.

import { batch, createEffect, createSignal, untrack, type Accessor } from 'solid-js';
import { createStore } from 'solid-js/store';
import type { AppStore } from '~/state/app';
import type { BusState } from '~/bus/types';
import { emptyRecord, isLive, isStale, own } from './helpers';
import {
  ISSUES_LIMIT,
  JOB_NOTIFICATION_METHOD,
  SITEMAP_LIMIT,
  parseIssuesResult,
  parseJobNotification,
  parseJobStatus,
  parseListResult,
  parseSitemapResult,
  type BySeverity,
  type InsertionPoint,
  type Issue,
  type IssueSummary,
  type JobStatus,
  type JobSummary,
  type SiteNode,
} from './model';

/** One in-flight status read per job per this window: a push storm costs one read (D3 ≤ 4/s). */
export const STATUS_COALESCE_MS = 250;
/** The same, for the `issue` line's page re-read. */
export const ISSUES_COALESCE_MS = 500;
/** Poll cadence for a live job's `scan.status` (Architect's call: at or under the push ceiling). */
export const STATUS_POLL_MS = 1000;
/** Poll cadence for `scan.list`, so a job this client never saw started still appears. */
export const LIST_POLL_MS = 5000;
/** Heartbeat for the mounted Issues view while its job is live. */
export const ISSUES_HEARTBEAT_MS = 5000;

export interface IssuesPage {
  rows: IssueSummary[];
  bySeverity: BySeverity;
  nextCursor: string | null;
  loading: boolean;
  error: string | null;
  loadedAt: number | null;
}

export interface SitemapPage {
  nodes: SiteNode[];
  points: InsertionPoint[];
  nextCursor: string | null;
  loading: boolean;
  error: string | null;
  loadedAt: number | null;
}

const NO_SEVERITIES: BySeverity = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };

/** The page a view renders before its first read answered (never mutated). */
export const EMPTY_ISSUES: IssuesPage = {
  rows: [],
  bySeverity: NO_SEVERITIES,
  nextCursor: null,
  loading: false,
  error: null,
  loadedAt: null,
};

export const EMPTY_SITEMAP: SitemapPage = {
  nodes: [],
  points: [],
  nextCursor: null,
  loading: false,
  error: null,
  loadedAt: null,
};

/**
 * What `cancel` answers: the core's `cancelling` status, or why it did not cancel — the core's
 * refusal text verbatim (`scan: not_found: …`), or the shape complaint. Never a rejection.
 */
export type CancelResult = { ok: true; status: JobStatus } | { ok: false; message: string };

export interface LiveModel {
  jobs: Accessor<JobSummary[]>;
  jobsLoaded: Accessor<boolean>;
  jobsError: Accessor<string | null>;
  /** The last status the core gave for `job`, or `null` before the first read answered. */
  status: (job: string) => JobStatus | null;
  /**
   * Why the last `scan.status` read of `job` gave nothing: the core's refusal text verbatim, or
   * the shape complaint. `null` while the last read answered (the held status is then current).
   */
  statusError: (job: string) => string | null;
  /** `null` until the first `scan.list` answered, then how many jobs are non-terminal. */
  liveCount: Accessor<number | null>;
  /** `null` is the "All jobs" page, which is its own page. */
  issues: (job: string | null) => IssuesPage;
  sitemap: (job: string) => SitemapPage;
  refreshJobs(): Promise<void>;
  refreshStatus(job: string): Promise<void>;
  refreshIssues(job: string | null): Promise<void>;
  loadMoreIssues(job: string | null): Promise<void>;
  refreshSitemap(job: string): Promise<void>;
  loadMoreSitemap(job: string): Promise<void>;
  cancel(job: string): Promise<CancelResult>;
  /** The Issues view tells the model which page to heartbeat while its job is live. */
  setIssuesMounted(job: string | null, mounted: boolean): void;
  /** After `scan.issue.update`: the detail replaces its row wherever that row is loaded. */
  replaceIssueRow(issue: Issue): void;
  dispose(): void;
}

/** The "All jobs" page's key: no job id can collide with it. */
const ALL_JOBS = '\u0000all-jobs';

const errorText = (e: unknown): string => (e instanceof Error ? e.message : String(e));
const shapeError = (verb: string): string => `${verb} answered with an unexpected shape`;

export function createLiveModel(app: AppStore, offered: Accessor<boolean>): LiveModel {
  // A partial app (a bare-stub mount of the panel) has no bus: it is simply never read.
  const busState = (): BusState => app.bus?.state() ?? 'closed';
  /** Every read is gated on this; when it is false the call is skipped, not queued. */
  const ready = (): boolean => busState() === 'open' && offered();

  const [jobs, setJobs] = createSignal<JobSummary[]>([]);
  const [jobsLoaded, setJobsLoaded] = createSignal(false);
  const [jobsError, setJobsError] = createSignal<string | null>(null);
  const [liveCount, setLiveCount] = createSignal<number | null>(null);
  // Keyed by wire strings (job ids), so: no prototype, and every read through `own` (A5).
  const [statuses, setStatuses] = createStore<Record<string, JobStatus>>(emptyRecord());
  const [statusErrors, setStatusErrors] = createStore<Record<string, string | null>>(emptyRecord());
  const [issuePages, setIssuePages] = createStore<Record<string, IssuesPage>>(emptyRecord());
  const [sitemapPages, setSitemapPages] = createStore<Record<string, SitemapPage>>(emptyRecord());

  const lastSeq = new Map<string, number>();
  const statusTriggers = new Map<string, ReturnType<typeof setTimeout>>();
  const issueTriggers = new Map<string, ReturnType<typeof setTimeout>>();
  let statusPoll: ReturnType<typeof setInterval> | null = null;
  let listPoll: ReturnType<typeof setInterval> | null = null;
  let issuesPoll: ReturnType<typeof setInterval> | null = null;
  /** `undefined` = the Issues view is not mounted; `null` = it is mounted on "All jobs". */
  let issuesMounted: string | null | undefined = undefined;
  let issuesPollFor: string | null | undefined = undefined;
  let disposed = false;

  const issuesKey = (job: string | null): string => job ?? ALL_JOBS;
  const issuesPage = (job: string | null): IssuesPage => own(issuePages, issuesKey(job)) ?? EMPTY_ISSUES;
  const sitemapPage = (job: string): SitemapPage => own(sitemapPages, job) ?? EMPTY_SITEMAP;

  function patchIssues(key: string, patch: Partial<IssuesPage>): void {
    setIssuePages(key, (prev: IssuesPage | undefined) => ({ ...(prev ?? EMPTY_ISSUES), ...patch }));
  }

  function patchSitemap(job: string, patch: Partial<SitemapPage>): void {
    setSitemapPages(job, (prev: SitemapPage | undefined) => ({ ...(prev ?? EMPTY_SITEMAP), ...patch }));
  }

  /* ---------------------------------------------------------------- reads */

  async function refreshJobs(): Promise<void> {
    if (disposed || !ready()) return;
    try {
      const parsed = parseListResult(await app.call<unknown>('scan.list'));
      if (disposed) return;
      if (!parsed) {
        batch(() => {
          setJobsLoaded(true);
          setJobsError(shapeError('scan.list'));
        });
        return;
      }
      batch(() => {
        setJobs(parsed.jobs);
        setJobsLoaded(true);
        setJobsError(null);
        setLiveCount(parsed.jobs.filter((j) => isLive(j.state)).length);
      });
    } catch (e) {
      batch(() => {
        setJobsLoaded(true);
        setJobsError(errorText(e));
      });
    }
    syncPolls();
  }

  /**
   * Monotonic (D-T8.3): a running job's reply that is older than what we hold is dropped whole —
   * not merged — because two reads in flight at once can land out of order. A terminal reply is the
   * last word and is always taken.
   */
  function applyStatus(next: JobStatus): void {
    const held = own(statuses, next.job);
    if (held && isStale(held, next)) return;
    setStatuses(next.job, next);
  }

  /**
   * A failed read never touches the held status (a drifted or empty reply says nothing about the
   * job), but it is not dropped either: `statusError(job)` carries the core's text until a read
   * answers again, so a row can say why its counters stopped moving.
   */
  async function refreshStatus(job: string): Promise<void> {
    if (disposed || !ready()) return;
    try {
      const next = parseJobStatus(await app.call<unknown>('scan.status', { job }));
      if (disposed) return;
      if (!next) {
        setStatusErrors(job, shapeError('scan.status'));
        return;
      }
      batch(() => {
        applyStatus(next);
        setStatusErrors(job, null);
      });
    } catch (e) {
      if (!disposed) setStatusErrors(job, errorText(e));
    }
  }

  async function readIssues(job: string | null, cursor: string | null): Promise<void> {
    if (disposed || !ready()) return;
    const key = issuesKey(job);
    patchIssues(key, { loading: true });
    try {
      const raw = await app.call<unknown>('scan.issues', {
        ...(job !== null ? { job } : {}),
        limit: ISSUES_LIMIT,
        ...(cursor !== null ? { cursor } : {}),
      });
      if (disposed) return;
      const parsed = parseIssuesResult(raw);
      if (!parsed) {
        patchIssues(key, { loading: false, error: shapeError('scan.issues') });
        return;
      }
      const held = own(issuePages, key);
      patchIssues(key, {
        rows: cursor !== null && held ? [...held.rows, ...parsed.issues] : parsed.issues,
        bySeverity: parsed.by_severity,
        nextCursor: parsed.next_cursor,
        loading: false,
        error: null,
        loadedAt: Date.now(),
      });
    } catch (e) {
      if (!disposed) patchIssues(key, { loading: false, error: errorText(e) });
    }
  }

  const refreshIssues = (job: string | null): Promise<void> => readIssues(job, null);

  async function loadMoreIssues(job: string | null): Promise<void> {
    const cursor = issuesPage(job).nextCursor;
    if (cursor === null) return;
    await readIssues(job, cursor);
  }

  async function readSitemap(job: string, cursor: string | null): Promise<void> {
    if (disposed || !ready()) return;
    patchSitemap(job, { loading: true });
    try {
      const raw = await app.call<unknown>('scan.sitemap', {
        job,
        limit: SITEMAP_LIMIT,
        ...(cursor !== null ? { cursor } : {}),
      });
      if (disposed) return;
      const parsed = parseSitemapResult(raw);
      if (!parsed) {
        patchSitemap(job, { loading: false, error: shapeError('scan.sitemap') });
        return;
      }
      const held = own(sitemapPages, job);
      patchSitemap(job, {
        nodes: cursor !== null && held ? [...held.nodes, ...parsed.nodes] : parsed.nodes,
        points: cursor !== null && held ? [...held.points, ...parsed.points] : parsed.points,
        nextCursor: parsed.next_cursor,
        loading: false,
        error: null,
        loadedAt: Date.now(),
      });
    } catch (e) {
      if (!disposed) patchSitemap(job, { loading: false, error: errorText(e) });
    }
  }

  const refreshSitemap = (job: string): Promise<void> => readSitemap(job, null);

  async function loadMoreSitemap(job: string): Promise<void> {
    const cursor = sitemapPage(job).nextCursor;
    if (cursor === null) return;
    await readSitemap(job, cursor);
  }

  /**
   * Two-step by contract: the reply is `cancelling`, the job turns `cancelled` later and the poll
   * reads that. Total: a refusal answers `{ ok: false, message }` with the core's text rather than
   * rejecting, so a row's Cancel button cannot leave an unhandled rejection behind and the caller
   * can show *why* (`scan: not_found: …` is not "cancel failed").
   */
  async function cancel(job: string): Promise<CancelResult> {
    if (disposed || !ready()) return { ok: false, message: 'the bus is not open on a v2 core' };
    try {
      const next = parseJobStatus(await app.call<unknown>('scan.cancel', { job }));
      if (!next) return { ok: false, message: shapeError('scan.cancel') };
      applyStatus(next);
      return { ok: true, status: next };
    } catch (e) {
      return { ok: false, message: errorText(e) };
    }
  }

  function replaceIssueRow(issue: Issue): void {
    for (const key of Object.keys(issuePages)) {
      const page = own(issuePages, key);
      if (!page || !page.rows.some((r) => r.id === issue.id)) continue;
      setIssuePages(key, 'rows', (rows: IssueSummary[]) => rows.map((r) => (r.id === issue.id ? issue : r)));
    }
  }

  /* ---------------------------------------------------------------- push: a trigger only */

  /** A trailing throttle: the first line arms the window, later lines ride it (no re-arm). */
  function triggerStatus(job: string): void {
    if (disposed || statusTriggers.has(job)) return;
    statusTriggers.set(
      job,
      setTimeout(() => {
        statusTriggers.delete(job);
        void refreshStatus(job);
      }, STATUS_COALESCE_MS),
    );
  }

  function triggerIssues(job: string): void {
    if (disposed || issueTriggers.has(job)) return;
    issueTriggers.set(
      job,
      setTimeout(() => {
        issueTriggers.delete(job);
        void refreshIssues(job);
      }, ISSUES_COALESCE_MS),
    );
  }

  const unsubscribe =
    app.bus?.onNotification((method, params) => {
      if (disposed || method !== JOB_NOTIFICATION_METHOD) return;
      // Anything that is not a scan job line (another kind, a drifted payload) is not ours.
      const line = parseJobNotification(params);
      if (!line) return;
      const seen = lastSeq.get(line.job);
      if (seen !== undefined && line.seq <= seen) return;
      lastSeq.set(line.job, line.seq);
      triggerStatus(line.job);
      if (line.event === 'started') void refreshJobs();
      if (line.event === 'issue') triggerIssues(line.job);
      if (line.event === 'finished' || line.event === 'cancelled' || line.event === 'failed') {
        void refreshJobs();
        triggerIssues(line.job);
      }
    }) ?? (() => {});

  /* ---------------------------------------------------------------- poll: the truth */

  function anyLive(): boolean {
    return jobs().some((j) => isLive(j.state));
  }

  function issuesJobLive(): boolean {
    if (issuesMounted === undefined) return false;
    const mounted = issuesMounted;
    return mounted === null ? anyLive() : jobs().some((j) => j.job === mounted && isLive(j.state));
  }

  function syncPolls(): void {
    if (disposed) return;
    const want = ready() && anyLive();
    if (want && statusPoll === null) {
      statusPoll = setInterval(() => {
        for (const j of jobs()) if (isLive(j.state)) void refreshStatus(j.job);
      }, STATUS_POLL_MS);
      listPoll = setInterval(() => void refreshJobs(), LIST_POLL_MS);
    } else if (!want && statusPoll !== null) {
      clearInterval(statusPoll);
      statusPoll = null;
      if (listPoll !== null) clearInterval(listPoll);
      listPoll = null;
    }
    syncIssuesPoll();
  }

  function syncIssuesPoll(): void {
    if (disposed) return;
    const want = ready() && issuesJobLive();
    if (want && (issuesPoll === null || issuesPollFor !== issuesMounted)) {
      if (issuesPoll !== null) clearInterval(issuesPoll);
      const job = issuesMounted ?? null;
      issuesPollFor = issuesMounted;
      issuesPoll = setInterval(() => void refreshIssues(job), ISSUES_HEARTBEAT_MS);
    } else if (!want && issuesPoll !== null) {
      clearInterval(issuesPoll);
      issuesPoll = null;
      issuesPollFor = undefined;
    }
  }

  function setIssuesMounted(job: string | null, mounted: boolean): void {
    if (mounted) issuesMounted = job;
    else if (issuesMounted === job) issuesMounted = undefined;
    syncIssuesPoll();
  }

  /** Every (re)connection is a new stream (`app.ts:721`): re-read the list and every job. */
  async function resync(): Promise<void> {
    await refreshJobs();
    for (const j of untrack(jobs)) await refreshStatus(j.job);
  }

  // The state at creation is not a transition, so a store built on an already-open bus does not
  // resync on its first run; a later `open` after any other state does.
  let previous: BusState = untrack(busState);
  createEffect(() => {
    const state = busState();
    const on = offered();
    untrack(() => {
      const was = previous;
      previous = state;
      if (state === 'open' && was !== 'open' && on) void resync();
      syncPolls();
    });
  });

  function dispose(): void {
    disposed = true;
    unsubscribe();
    for (const t of statusTriggers.values()) clearTimeout(t);
    statusTriggers.clear();
    for (const t of issueTriggers.values()) clearTimeout(t);
    issueTriggers.clear();
    if (statusPoll !== null) clearInterval(statusPoll);
    if (listPoll !== null) clearInterval(listPoll);
    if (issuesPoll !== null) clearInterval(issuesPoll);
    statusPoll = null;
    listPoll = null;
    issuesPoll = null;
  }

  return {
    jobs,
    jobsLoaded,
    jobsError,
    status: (job: string) => own(statuses, job) ?? null,
    statusError: (job: string) => own(statusErrors, job) ?? null,
    liveCount,
    issues: issuesPage,
    sitemap: sitemapPage,
    refreshJobs,
    refreshStatus,
    refreshIssues,
    loadMoreIssues,
    refreshSitemap,
    loadMoreSitemap,
    cancel,
    setIssuesMounted,
    replaceIssueRow,
    dispose,
  };
}
