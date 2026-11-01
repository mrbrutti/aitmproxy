// CA trust as the web UI sees it (system-proxy spec §D17.12): the parsed `ca.status` reply, the
// pill word of the D17.6 table, the scope argument of D17.1 and the cancelled message of D17.4.
// Pure, so the words are unit-tested; `state/app.ts` only wires the reads.

import { isRecord } from '~/lib/isRecord';

export interface CATrustStatus {
  /** A store reports `trusted: yes`. */
  trusted: boolean;
  /** Which store trusts the CA (`user` before `system` when both do); null when none does. */
  scope: 'user' | 'system' | null;
  /** `ca.status.platform`: macos | linux-debian | linux-fedora | windows | unsupported. */
  platform: string;
  /** `fingerprint_sha256`, colon-separated uppercase hex; null without a certificate. */
  fingerprint: string | null;
}

/**
 * The status a `ca.status` reply amounts to, or null when it is not that shape or no store
 * reports a reading (`stores` empty — no certificate yet — or every store `trusted: unknown`, an
 * older core or a failed evaluation). "Unread" never renders as "not trusted" (D17.5).
 */
export function parseCATrust(v: unknown): CATrustStatus | null {
  if (!isRecord(v) || typeof v.platform !== 'string') return null;
  const stores = v.stores;
  if (!isRecord(stores)) return null;
  const trustOf = (name: string): string | null => {
    const entry = stores[name];
    return isRecord(entry) && typeof entry.trusted === 'string' ? entry.trusted : null;
  };
  const readings = Object.keys(stores)
    .map(trustOf)
    .filter((t): t is string => t === 'yes' || t === 'no');
  if (readings.length === 0) return null;
  const scope = trustOf('user') === 'yes' ? 'user' : trustOf('system') === 'yes' ? 'system' : null;
  return {
    trusted: readings.includes('yes'),
    scope,
    platform: v.platform,
    fingerprint: typeof v.fingerprint_sha256 === 'string' ? v.fingerprint_sha256 : null,
  };
}

/** The pill word (D17.6): in flight wins; no reading renders nothing. */
export function caPillWord(s: CATrustStatus | null, inFlight: boolean): string | null {
  if (inFlight) return '· CA trusting…';
  if (!s) return null;
  return s.trusted ? '· CA trusted' : '· CA untrusted';
}

/** `ca.install` / `ca.uninstall` arguments (D17.1): the user store on macOS and Windows, the platform's only store elsewhere. */
export function caInstallArgs(s: CATrustStatus | null): Record<string, unknown> {
  return s && (s.platform === 'macos' || s.platform === 'windows') ? { scope: 'user' } : {};
}

/** The two calls that change the OS trust store: the palette holds the in-flight word around them and re-reads `ca.status` after (D17.5, D17.12). */
export const isCATrustTool = (name: string): boolean => name === 'ca.install' || name === 'ca.uninstall';

/** The core's reply when the operator dismissed the OS authentication dialog (D17.4), for either verb. */
export function isCACancelled(message: string): boolean {
  return /^ca\.(install|uninstall) cancelled/.test(message);
}
