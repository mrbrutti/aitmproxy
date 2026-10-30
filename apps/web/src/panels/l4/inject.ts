// Guarded inject (ui-ext §3.4, L4OPS-AC10): the wire is reached ONLY through `l4.inject`, and the
// operator action triggers the M4 confirm-over-the-wire handshake. There is no UI side channel to
// the wire — this module is the single path, and it never fabricates a confirmation: it surfaces
// exactly what the core returns (a `needs_confirmation` prompt, a guard refusal verbatim, or the
// sent result). The dimming/disabling the surface shows is a courtesy; the guard is the enforcement.

import { isNeedsConfirm, type PacketSpec } from './model';

export interface InjectArgs {
  spec: PacketSpec;
  dst: string;
  interface: string;
  port?: number | undefined;
  count?: number | undefined;
}

export type InjectOutcome =
  /** The core asked for operator confirmation first (§2.4): show the dialog, then `confirm`. */
  | { kind: 'confirm'; prompt: string; token: string }
  /** The inject reached the wire. */
  | { kind: 'sent'; flowId: string; sent: number }
  /** A guard refusal (out-of-scope / rate / denylist / oversize / count) or any error — verbatim. */
  | { kind: 'refused'; message: string };

type Call = <T = unknown>(tool: string, params?: Record<string, unknown>) => Promise<T>;

// ---- generic confirm-over-the-wire (inject + intercept forward/drop share it) --------------------

export type GuardedOutcome =
  | { kind: 'confirm'; prompt: string; token: string }
  | { kind: 'done'; result: unknown }
  | { kind: 'refused'; message: string };

/** First phase for any confirm-gated verb: run it, and classify the result. */
export async function beginGuarded(call: Call, tool: string, params: Record<string, unknown>): Promise<GuardedOutcome> {
  try {
    const result = await call(tool, params);
    if (isNeedsConfirm(result)) return { kind: 'confirm', prompt: result.prompt, token: result.confirm_token };
    return { kind: 'done', result };
  } catch (e) {
    return { kind: 'refused', message: (e as Error).message };
  }
}

/** Second phase: re-issue carrying the reserved `_confirm` token. */
export async function confirmGuarded(call: Call, tool: string, params: Record<string, unknown>, token: string): Promise<GuardedOutcome> {
  try {
    const result = await call(tool, { ...params, _confirm: token });
    if (isNeedsConfirm(result)) return { kind: 'refused', message: 'confirmation was not accepted (stale or reused token)' };
    return { kind: 'done', result };
  } catch (e) {
    return { kind: 'refused', message: (e as Error).message };
  }
}

/** The parameters `l4.inject` takes; `_confirm` is added on the second (confirming) call only. */
function wire(args: InjectArgs): Record<string, unknown> {
  const w: Record<string, unknown> = { spec: args.spec, dst: args.dst, interface: args.interface };
  if (args.port != null) w.port = args.port;
  if (args.count != null) w.count = args.count;
  return w;
}

function asSent(result: unknown): InjectOutcome | null {
  if (result && typeof result === 'object' && 'sent' in result) {
    const r = result as { flow_id?: unknown; sent?: unknown };
    return { kind: 'sent', flowId: typeof r.flow_id === 'string' ? r.flow_id : '', sent: typeof r.sent === 'number' ? r.sent : 0 };
  }
  return null;
}

/**
 * First phase: send `l4.inject` without `_confirm`. The operator role gets back a
 * `needs_confirmation` envelope (→ `confirm`); a non-operator / already-confirmed path may return
 * the sent result directly; a guard refusal throws and is surfaced verbatim (never a dialog).
 */
export async function beginInject(call: Call, args: InjectArgs): Promise<InjectOutcome> {
  try {
    const result = await call('l4.inject', wire(args));
    if (isNeedsConfirm(result)) return { kind: 'confirm', prompt: result.prompt, token: result.confirm_token };
    const sent = asSent(result);
    if (sent) return sent;
    return { kind: 'refused', message: 'l4.inject returned an unexpected result' };
  } catch (e) {
    return { kind: 'refused', message: (e as Error).message };
  }
}

/** Second phase: re-issue the identical call carrying the reserved `_confirm` token. */
export async function confirmInject(call: Call, args: InjectArgs, token: string): Promise<InjectOutcome> {
  try {
    const result = await call('l4.inject', { ...wire(args), _confirm: token });
    const sent = asSent(result);
    if (sent) return sent;
    if (isNeedsConfirm(result)) return { kind: 'refused', message: 'confirmation was not accepted (stale or reused token)' };
    return { kind: 'refused', message: 'l4.inject returned an unexpected result' };
  } catch (e) {
    return { kind: 'refused', message: (e as Error).message };
  }
}
