// The Activity flood rule (push spec D7): which audit lines are this UI watching itself. A domain
// rule with no view in it, used by the store's intake (`state/app.ts`); the Activity panel's view
// logic (filters, labels, args summaries) is `panels/agent/activity.ts`.

import type { AgentNotification, BusRole } from '~/bus/types';

/**
 * The reads the UI issues on timers or in bulk refreshes (push spec D7). Every call is audited and
 * echoed back to us, so a successful one of these from this connection is the UI watching itself.
 */
export const UI_BACKGROUND_READS: ReadonlySet<string> = new Set([
  'flow.list',
  'flow.get',
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
 * a connection id on audit lines).
 */
export function isUiPollNoise(
  e: Pick<AgentNotification, 'origin' | 'command' | 'result' | 'clientLabel'>,
  own: { origin: AgentNotification['origin'] | null },
): boolean {
  if (e.result !== 'ok') return false;
  if (!UI_BACKGROUND_READS.has(e.command)) return false;
  return e.clientLabel == null && own.origin !== null && e.origin === own.origin;
}
