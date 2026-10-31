// The Activity flood rule (push spec D7): which audit lines are this UI watching itself. A domain
// rule with no view in it, used by the store's intake (`state/app.ts`); the Activity panel's view
// logic (filters, labels, args summaries) is `panels/agent/activity.ts`.

import type { AgentNotification, BusRole } from '~/bus/types';

/**
 * The reads the UI issues on timers or in bulk refreshes (push spec D7, as amended after review
 * round 2). Every call is audited and echoed back to us, so a successful one of these from this
 * connection is the UI watching itself. `flow.get` is not here: it is the inspector's whole-flow read
 * on a click, not a timer. `l4.flow.get` is: the L4 store re-reads every session with it on its
 * 1.5 s poll (`state/context.tsx`, `panels/l4/store.ts`), and it returns a summary (kind, bind,
 * per-packet lengths and layers), never payload bytes. `flow.detail` is here only in the poll's
 * shape (`isPollDetail`).
 */
export const UI_BACKGROUND_READS: ReadonlySet<string> = new Set([
  'flow.list',
  'flow.detail',
  'proxy.status',
  'agent.status',
  'agent.activity',
  'scope.list',
  'poc.list',
  'l4.flow.list',
  'l4.flow.get',
  'l4.scope.list',
  'l4.capture.status',
  'l4.agent.status',
  'l4.intercept.status',
  'l4.intercept.list',
  'browser.tabs',
  'browser.screenshot',
]);

/**
 * The poll reads a row as `flow.detail {id, body:'none'}` (`state/app.ts` fetchRows); the inspector's
 * click reads the same flow with bodies (`{id}`), a content read the operator asked for. Only the
 * poll's exact shape is a background read. `args` is what `toAgentEntry` left: the wire's JSON text
 * parsed to an object, or the text itself when it did not parse, which is never the poll's shape.
 */
const isPollDetail = (args: unknown): boolean => !!args && typeof args === 'object' && !Array.isArray(args) && (args as { body?: unknown }).body === 'none';

/** The audit `origin` the server records for calls made under this connection's role; unknown matches nothing. */
export function ownOriginOf(role: BusRole | null): 'operator' | 'mcp' | null {
  if (role === 'operator') return 'operator';
  if (role === 'agent') return 'mcp';
  return null;
}

/**
 * The flood rule (push spec D7): a line is dropped iff it succeeded, names a background read, and
 * is ours — unlabelled and from our own origin. The bridge labels no connection (every line made
 * over `/bus` has `client_label: null`), and a label is the caller's self-declared
 * `initialize.clientInfo.name`, which an agent could set to `aitm-web` to hide its reads from the
 * operator: a labelled line is therefore never ours, whatever it says. Everything else stays: every
 * action, every error, every labelled client, other frontends' reads. What this cannot tell apart
 * is a second `/bus` client under the same token and role (accepted; the server would have to stamp
 * a connection id on audit lines). `args` decides `flow.detail` alone: the poll's `{id, body:'none'}`
 * is noise, the inspector's `{id}` (bodies included) is the operator's read and stays.
 */
export function isUiPollNoise(
  e: Pick<AgentNotification, 'origin' | 'command' | 'result' | 'clientLabel' | 'args'>,
  own: { origin: AgentNotification['origin'] | null },
): boolean {
  if (e.result !== 'ok') return false;
  if (!UI_BACKGROUND_READS.has(e.command)) return false;
  if (e.command === 'flow.detail' && !isPollDetail(e.args)) return false;
  return e.clientLabel == null && own.origin !== null && e.origin === own.origin;
}
