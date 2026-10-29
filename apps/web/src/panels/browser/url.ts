// URL field semantics and the local navigation history. There are no bus commands for
// back/forward/reload (F14), so the view remembers the URLs it navigated to and re-navigates.
import { createSignal, type Accessor } from 'solid-js';

// `host:8080` is not a scheme: only `scheme://` or the schemeless page kinds count.
const HAS_SCHEME = /^(?:[a-z][a-z0-9+.-]*:\/\/|(?:about|data|blob|file|javascript):)/i;
const LOOPBACK = /^(localhost|127(?:\.\d{1,3}){3}|\[::1\]|0\.0\.0\.0)(?::\d+)?(?:[/?#]|$)/i;

/**
 * What the operator typed → what we navigate to. Adds `https://` when there is no scheme
 * (plain `http://` for localhost and loopback addresses — local targets rarely speak TLS),
 * keeps `about:` pages and anything already carrying a scheme. Empty input → null.
 */
export function normalizeUrl(input: string): string | null {
  const s = input.trim();
  if (!s) return null;
  if (LOOPBACK.test(s)) return `http://${s}`;
  if (HAS_SCHEME.test(s)) return s;
  return `https://${s}`;
}

/** The host for a tab title when the page has none. */
export function hostOf(url: string): string {
  if (!url) return '';
  if (url.startsWith('about:')) return url;
  try {
    return new URL(url).host || url;
  } catch {
    return url;
  }
}

export interface UrlHistory {
  current: Accessor<string | null>;
  canBack: Accessor<boolean>;
  canForward: Accessor<boolean>;
  /** Record a navigation; drops the forward stack. A repeat of the current URL is a no-op. */
  push(url: string): void;
  /** Step and return the URL to re-navigate to, or null at the edge. */
  back(): string | null;
  forward(): string | null;
  /** Visible for tests. */
  entries: Accessor<readonly string[]>;
}

export function createHistory(): UrlHistory {
  const [entries, setEntries] = createSignal<readonly string[]>([]);
  const [index, setIndex] = createSignal(-1);
  const current = () => entries()[index()] ?? null;
  return {
    current,
    entries,
    canBack: () => index() > 0,
    canForward: () => index() < entries().length - 1,
    push(url) {
      if (current() === url) return;
      const kept = entries().slice(0, index() + 1);
      setEntries([...kept, url]);
      setIndex(kept.length);
    },
    back() {
      if (index() <= 0) return null;
      setIndex(index() - 1);
      return current();
    },
    forward() {
      if (index() >= entries().length - 1) return null;
      setIndex(index() + 1);
      return current();
    },
  };
}
