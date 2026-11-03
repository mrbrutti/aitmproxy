// The single path from the Scan surface to a running scan (D-T8.5, D-T8.6).
//
// Two rules this module exists to keep:
//
//   1. **What you see is what runs.** `scan.start` / `scan.map` carry `{ profile }` — the draft,
//      whole and inline — and nothing else. The editor never sends `profile_name`, `target` or
//      `overrides`, so there are no partial-merge semantics to get wrong and an unsaved tweak runs
//      exactly as it reads in the editor. The one other sender is Scan Again (Jobs view D13): a
//      finished job's status names its profile and targets, so it re-runs as
//      `scan.start { profile_name, overrides: { target: { origins } } }` — the engine resolves the
//      name and merges the override; the status carries no profile body to send whole.
//   2. **The core is the guard.** The confirm handshake is `beginGuarded`/`confirmGuarded` from
//      `panels/l4/inject.ts`: this module surfaces what the core returns (a `needs_confirmation`
//      prompt verbatim, a refusal classified but never softened, or the start result) and
//      fabricates nothing. `preflight` below is a *courtesy* that explains a dimmed button; it is
//      not policy, it never widens anything, and an unknown (`null`) answer never disables a
//      control — only the core refuses (`panels/l4/model.ts:141`).

import { beginGuarded, confirmGuarded, type GuardedOutcome } from '~/panels/l4/inject';
import type { L4ScopeEntryWire } from '~/panels/l4/model';

import {
  AGENT_NOTE,
  CONFIRM_NOTE,
  L4_HINT,
  hostInScope,
  l4Covered,
  needsConfirmNote,
  originHost,
  profileHasL4,
} from './helpers';
import type { JobStatus, ScanErrorCode, ScanProfile, StartResult } from './model';
import { parseScanError, parseStartResult } from './model';

export type Call = <T = unknown>(tool: string, params?: Record<string, unknown>) => Promise<T>;

/** `Start` runs the full scan, `Map only` crawls and reports insertion points without auditing. */
export type LaunchMode = 'start' | 'map';

export const LAUNCH_VERB: Record<LaunchMode, 'scan.start' | 'scan.map'> = {
  start: 'scan.start',
  map: 'scan.map',
};

export type LaunchOutcome =
  /** The core asked for confirmation first: show the dialog, then `confirmLaunch` with the token. */
  | { kind: 'confirm'; prompt: string; token: string }
  /** The job exists on the core. */
  | { kind: 'started'; result: StartResult }
  /** A `scan:` refusal — `code`/`detail` for the text, `message` kept raw for the unknown case. */
  | { kind: 'refused'; code: ScanErrorCode | null; detail: string; message: string }
  /** A reply that is not a `StartResult`; the UI says so rather than inventing a job. */
  | { kind: 'malformed'; message: string };

function classify(verb: string, outcome: GuardedOutcome): LaunchOutcome {
  switch (outcome.kind) {
    case 'confirm':
      return { kind: 'confirm', prompt: outcome.prompt, token: outcome.token };
    case 'done': {
      const result = parseStartResult(outcome.result);
      return result
        ? { kind: 'started', result }
        : { kind: 'malformed', message: `${verb} answered with an unexpected shape` };
    }
    case 'refused': {
      const { code, detail } = parseScanError(outcome.message);
      return { kind: 'refused', code, detail, message: outcome.message };
    }
  }
}

/** First phase: run the launch verb without `_confirm` and classify what comes back. */
export async function beginLaunch(call: Call, mode: LaunchMode, profile: ScanProfile): Promise<LaunchOutcome> {
  const verb = LAUNCH_VERB[mode];
  return classify(verb, await beginGuarded(call, verb, { profile }));
}

/** Second phase: re-issue the identical launch carrying the reserved `_confirm` token. */
export async function confirmLaunch(
  call: Call,
  mode: LaunchMode,
  profile: ScanProfile,
  token: string,
): Promise<LaunchOutcome> {
  const verb = LAUNCH_VERB[mode];
  return classify(verb, await confirmGuarded(call, verb, { profile }, token));
}

/* ------------------------------------------------------------------ Scan Again (Jobs view D13) */

/** What Scan Again sends: the job's profile by name, run again against the job's own origins. */
export interface ScanAgainArgs {
  profile_name: string;
  overrides: { target: { origins: string[] } };
}

/**
 * `scan.start { profile_name, overrides: { target: { origins } } }` from a job's status. The
 * name goes out verbatim (an empty one is the engine's `invalid_profile` to refuse, not ours to
 * guess at) and `origins: []` is what a pure-L4 job sends (plan gap 32). Whether the job is
 * finished is the caller's gate (`store.scanAgain`), as it is the Kit's.
 */
export function scanAgainArgs(st: JobStatus): ScanAgainArgs {
  return { profile_name: st.profile_name, overrides: { target: { origins: [...st.targets] } } };
}

/** First phase of Scan Again: `scan.start` without `_confirm`, classified like any launch. */
export async function beginScanAgain(call: Call, args: ScanAgainArgs): Promise<LaunchOutcome> {
  return classify('scan.start', await beginGuarded(call, 'scan.start', { ...args }));
}

/** Second phase: the identical arguments carrying the reserved `_confirm` token. */
export async function confirmScanAgain(call: Call, args: ScanAgainArgs, token: string): Promise<LaunchOutcome> {
  return classify('scan.start', await confirmGuarded(call, 'scan.start', { ...args }, token));
}

/* ------------------------------------------------------------------ pre-flight (courtesy only) */

export interface PreflightCtx {
  /** The operator's HTTP scope (`app.proxy.scope`). */
  scope: readonly { host: string }[];
  /** Whether this core offers the L4 layer at all (`l4.scope.list` in the tool list). */
  l4Offered: boolean;
  /** The live L4 scope, or `null` when it has not been read — `null` never disables anything. */
  l4Entries: readonly L4ScopeEntryWire[] | null;
  busOpen: boolean;
  role: 'operator' | 'agent' | null;
}

export type Preflight = { ok: true; note: string | null } | { ok: false; reason: string };

/**
 * Why `Start` / `Map only` are dimmed, in the order D-T8.6 lists. Every reason is something the
 * operator can act on; nothing here decides policy, and an agent session is *never* disabled here
 * (the core refuses it, and `AGENT_NOTE` explains why it may).
 */
export function preflight(profile: ScanProfile, ctx: PreflightCtx): Preflight {
  if (!ctx.busOpen) return { ok: false, reason: 'the bus is not open' };

  const origins = profile.target.origins;
  const l4Targets = profile.target.l4;
  if (origins.length === 0 && l4Targets.length === 0) {
    return { ok: false, reason: 'add an origin or an L4 target' };
  }

  for (const origin of origins) {
    if (!hostInScope(origin, ctx.scope)) {
      const host = originHost(origin)?.host ?? origin;
      return { ok: false, reason: `out of scope: add ${host} to Scope` };
    }
  }

  if (profileHasL4(profile)) {
    if (!ctx.l4Offered) return { ok: false, reason: 'the L4 layer is not enabled on this core' };
    const entries = ctx.l4Entries;
    if (entries !== null) {
      for (const t of l4Targets) {
        // `null` is *unknown* (IPv6, an entry this UI cannot parse) and must not disable.
        if (l4Covered(entries, t.ip, t.port) === false) {
          return {
            ok: false,
            reason: `no L4 scope entry with Inject covers ${t.ip}:${t.port}. ${L4_HINT}`,
          };
        }
      }
    }
  }

  const notes: string[] = [];
  if (needsConfirmNote(profile)) notes.push(CONFIRM_NOTE);
  if (ctx.role === 'agent') notes.push(AGENT_NOTE);
  return { ok: true, note: notes.length ? notes.join(' ') : null };
}
