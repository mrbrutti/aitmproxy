import type { BusClient } from './types';
import { createMockBus } from './mock';
import { createWsBus } from './ws';

export type { BusClient } from './types';
export * from './types';

/**
 * Picks the bus for this page load. `?bus=mock` / `?bus=live` force one; otherwise a production
 * build (served by `aitm web`) is live and `vite dev` runs on fixtures. The bridge token comes
 * from the `#t=` fragment `aitm web` prints in its start-up URL and is kept in sessionStorage.
 */
export function createBus(): BusClient {
  const params = new URLSearchParams(location.search);
  const forced = params.get('bus');
  const live = forced === 'live' || (forced !== 'mock' && !import.meta.env.DEV);
  if (!live) {
    const rate = Number(params.get('rate') ?? '4');
    const initial = Number(params.get('initial') ?? '40');
    return createMockBus({ rate: Number.isFinite(rate) ? rate : 4, initial: Number.isFinite(initial) ? initial : 40 });
  }
  const hash = new URLSearchParams(location.hash.replace(/^#/, ''));
  let token = hash.get('t');
  if (token) {
    sessionStorage.setItem('aitm.bus.token', token);
    history.replaceState(null, '', location.pathname + location.search);
  } else token = sessionStorage.getItem('aitm.bus.token');
  const proto = location.protocol === 'https:' ? 'wss' : 'ws';
  return createWsBus({ url: `${proto}://${location.host}/bus`, token });
}
