// The system-proxy pill word and menu state, as pure functions of `proxy.status.system_proxy`
// (spec D6 fields, D12 word table, D15 web; plan C9), and the merge the poll applies over the last
// full status. `app.ts` parses on poll and the toolbar renders; nothing here touches the bus.

import type { BusRole, SystemProxyState, SystemProxyStatus } from '~/bus/types';

const STATES: readonly SystemProxyState[] = ['off', 'points_at_us', 'other', 'unsupported', 'needs_privilege', 'unknown'];

function asState(v: unknown): SystemProxyState {
  return typeof v === 'string' && (STATES as readonly string[]).includes(v) ? (v as SystemProxyState) : 'unknown';
}

function optText(v: unknown): string | null {
  return typeof v === 'string' ? v : null;
}

/**
 * Read the `system_proxy` sub-object of `proxy.status` (or a full `proxy.system.*` result).
 * `null` when it is absent or not an object; a state string we do not know becomes `unknown`.
 */
export function parseSystemProxy(v: unknown): SystemProxyStatus | null {
  if (typeof v !== 'object' || v === null || Array.isArray(v)) return null;
  const o = v as Record<string, unknown>;
  const state = asState(o.state);
  return {
    state,
    host: optText(o.host),
    port: typeof o.port === 'number' && Number.isFinite(o.port) ? o.port : null,
    managed_by_us: o.managed_by_us === true,
    setting: o.setting === true,
    supported: typeof o.supported === 'boolean' ? o.supported : state !== 'unsupported',
    detail: typeof o.detail === 'string' ? o.detail : '',
    guidance: optText(o.guidance),
    remedy: optText(o.remedy),
  };
}

/**
 * The D12 pill word appended after the listening address, or `null` when the table says
 * "nothing" (`unsupported`, `unknown`, no status). `inFlight` is this client's own pending
 * set/unset; `setting` is another client's — both read `· sys-proxy setting…`.
 */
export function pillWord(s: SystemProxyStatus | null, inFlight: boolean): string | null {
  if (inFlight || s?.setting) return '· sys-proxy setting…';
  if (!s) return null;
  switch (s.state) {
    case 'points_at_us':
      return '· sys-proxy → us';
    case 'other':
      // The D12 row is `→ h:p`; an `other` without a complete endpoint has no row, so no word.
      return s.host !== null && s.port !== null ? `· sys-proxy → ${s.host}:${s.port}` : null;
    case 'off':
      return '· sys-proxy off';
    case 'needs_privilege':
      return '· sys-proxy needs admin';
    case 'unsupported':
    case 'unknown':
      return null;
  }
}

/**
 * The 2 s poll's compact object over the last status (spec D15, amended 2026-11-01): every field is
 * the new object's, except that `guidance` and `remedy` are kept from `prev` when `next` carries
 * none — the compact sub-object never does, and the full `proxy.system.status` read that set them
 * must survive until the next menu open or a set/unset reply replaces it. A `null` next stays null.
 */
export function mergeSystemProxy(prev: SystemProxyStatus | null, next: SystemProxyStatus | null): SystemProxyStatus | null {
  if (next === null) return null;
  return {
    ...next,
    guidance: next.guidance ?? prev?.guidance ?? null,
    remedy: next.remedy ?? prev?.remedy ?? null,
  };
}

export interface SystemProxyMenuState {
  /** The "Set as system proxy" checkbox: checked when the system proxy points at this core. */
  checked: boolean;
  disabled: boolean;
  /** Why the item is disabled, when there is a reason to show. */
  title: string | undefined;
  /** Offer "Copy env line" (the `guidance` line is present). */
  showCopyEnv: boolean;
}

/**
 * The D15 menu: the checkbox is disabled with a title while a change is in flight, when the
 * mechanism is unsupported, or when this connection is not the operator; it is also disabled
 * (no title) when there is nothing it could do — `needs_privilege`, `unknown`, or no status yet.
 */
export function menuState(s: SystemProxyStatus | null, inFlight: boolean, role: BusRole | null): SystemProxyMenuState {
  const checked = s?.state === 'points_at_us';
  const showCopyEnv = typeof s?.guidance === 'string' && s.guidance.length > 0;
  let title: string | undefined;
  let disabled = false;
  if (inFlight || s?.setting) {
    disabled = true;
    title = 'setting system proxy…';
  } else if (s !== null && !s.supported) {
    disabled = true;
    title = 'system proxy not available here';
  } else if (role !== 'operator') {
    disabled = true;
    title = 'connect with the operator token to change the system proxy';
  } else if (s === null || s.state === 'unknown' || s.state === 'needs_privilege') {
    disabled = true;
    title = s?.remedy ?? undefined;
  }
  return { checked, disabled, title, showCopyEnv };
}
