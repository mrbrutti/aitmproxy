import type { BusClient } from './types';
import { asRole } from './types';
import { createWsBus } from './ws';

export type { BusClient } from './types';
export * from './types';

/**
 * The bus for this page load: always the WebSocket bridge at `/bus` on this origin. `aitm web`
 * serves the UI and `/bus` together; in development `vite dev` proxies `/bus` to a running
 * `aitm web` (`vite.config.ts`, `AITM_WEB`) and the operator opens `http://127.0.0.1:5173/#t=<token>`
 * with the token `aitm web` prints. The bridge token comes from the `#t=` fragment and is kept in
 * sessionStorage. `?bus=` is no longer read: there is no other bus.
 */
export function createBus(): BusClient {
  const hash = new URLSearchParams(location.hash.replace(/^#/, ''));
  let token = hash.get('t');
  // The `expect` fragment (Decision B) rides the same launch URL as the token; keep it beside the
  // token in sessionStorage and strip it from the address bar exactly as the token is stripped.
  let expect = asRole(hash.get('expect'));
  if (token) {
    sessionStorage.setItem('aitm.bus.token', token);
    if (expect) sessionStorage.setItem('aitm.bus.expect', expect);
    else sessionStorage.removeItem('aitm.bus.expect');
    history.replaceState(null, '', location.pathname + location.search);
  } else {
    token = sessionStorage.getItem('aitm.bus.token');
    expect = asRole(sessionStorage.getItem('aitm.bus.expect'));
  }
  const proto = location.protocol === 'https:' ? 'wss' : 'ws';
  return createWsBus({ url: `${proto}://${location.host}/bus`, token, expect });
}
