// The bus's confirm handshake as every operator surface sees it (bus spec D4, `crates/aitm-mcp/src/server.rs`):
// a confirm-gated verb called from an operator connection answers first with this non-error envelope
// and runs nothing; the identical call re-sent with `_confirm: confirm_token` runs it. A second such
// envelope in reply to the confirming call means the token was not accepted.

import { isRecord } from '~/lib/isRecord';

export interface NeedsConfirm {
  status: 'needs_confirmation';
  prompt: string;
  confirm_token: string;
}

export const isNeedsConfirm = (v: unknown): v is NeedsConfirm =>
  isRecord(v) && v.status === 'needs_confirmation' && typeof v.prompt === 'string' && typeof v.confirm_token === 'string';

/** The error shown when the confirming call is answered with another `needs_confirmation`. */
export const STALE_CONFIRM_MESSAGE = 'confirmation was not accepted (stale or reused token)';
