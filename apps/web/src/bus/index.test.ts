// `createBus()` is the one place the UI picks its bus. There is exactly one: the WebSocket bridge
// at `/bus` on this origin. The mock bus and its `?bus=mock` switch were removed on 2026-10-31
// (spec 2026-10-31-remove-fake-data-ui-modes, D1 web); this pins that a page opened with the old
// query still gets the real bus, and that the launch-URL fragment is read and stripped as before.
//
// `createWsBus` opens no socket until `connect()` is called, so every case here builds a bus, reads
// its fields and closes it without a server. Under vitest's jsdom the page is `http://localhost:3000/`,
// so the host the WS bus derives from `ws://${location.host}/bus` is `localhost:3000`; the deleted
// mock reported `address: 'fixtures'` and never honoured `#expect=`, which is why both are pinned.
import { afterEach, describe, expect, it } from 'vitest';
import type { BusClient } from './types';
import { createBus } from './index';

/** The bridge host the WS bus reports: the page's own host, never an invented endpoint name. */
const BRIDGE = 'localhost:3000';

let open: BusClient[] = [];
const build = () => {
  const bus = createBus();
  open.push(bus);
  return bus;
};

afterEach(() => {
  for (const b of open) b.close();
  open = [];
  sessionStorage.clear();
  history.replaceState(null, '', '/');
});

describe('createBus', () => {
  it('ignores ?bus=mock and always builds the WebSocket bus', () => {
    history.replaceState(null, '', '/?bus=mock&rate=1#t=abc&expect=operator');
    const bus = build();
    expect(location.host).toBe(BRIDGE); // the jsdom page this file assumes
    expect(bus.address).toBe(BRIDGE); // the WS bus's host; the mock said 'fixtures'
    expect(bus.state()).toBe('idle'); // built, not connected: nothing was opened on our behalf
    expect(bus.expectRole).toBe('operator'); // the WS bus honours `#expect=`; the mock never did
    expect(sessionStorage.getItem('aitm.bus.token')).toBe('abc');
    expect(sessionStorage.getItem('aitm.bus.expect')).toBe('operator');
    expect(location.hash).toBe('');
  });

  it('leaves the old mock parameters in the query untouched: only the fragment is consumed', () => {
    history.replaceState(null, '', '/?bus=mock&rate=1&initial=40#t=abc');
    build();
    // The fragment is stripped; the query is exactly as it was — nothing read it and nothing rewrote it.
    expect(location.search).toBe('?bus=mock&rate=1&initial=40');
    expect(location.hash).toBe('');
  });

  it('builds the same WebSocket bus for ?bus=live and for no query at all', () => {
    history.replaceState(null, '', '/?bus=live#t=abc');
    const live = build();
    history.replaceState(null, '', '/#t=abc');
    const plain = build();
    expect(live.address).toBe(BRIDGE);
    expect(plain.address).toBe(BRIDGE);
  });

  it('with no token anywhere it still builds the WebSocket bus and writes nothing to sessionStorage', () => {
    history.replaceState(null, '', '/');
    const bus = build();
    expect(bus.address).toBe(BRIDGE);
    expect(bus.state()).toBe('idle');
    expect(bus.expectRole).toBeNull();
    expect(sessionStorage.length).toBe(0);
    expect(location.hash).toBe('');
  });

  it('a reload reads the token and the expectation back from sessionStorage', () => {
    sessionStorage.setItem('aitm.bus.token', 'kept');
    sessionStorage.setItem('aitm.bus.expect', 'operator');
    history.replaceState(null, '', '/');
    const bus = build();
    expect(bus.expectRole).toBe('operator');
    expect(sessionStorage.getItem('aitm.bus.token')).toBe('kept'); // untouched
  });

  it('a fresh token without #expect= clears a stale expectation', () => {
    sessionStorage.setItem('aitm.bus.expect', 'operator');
    history.replaceState(null, '', '/#t=new');
    const bus = build();
    expect(bus.expectRole).toBeNull();
    expect(sessionStorage.getItem('aitm.bus.token')).toBe('new');
    expect(sessionStorage.getItem('aitm.bus.expect')).toBeNull();
  });

  it('an unknown #expect= value is not stored and sets no expectation', () => {
    history.replaceState(null, '', '/#t=abc&expect=root');
    const bus = build();
    expect(bus.expectRole).toBeNull();
    expect(sessionStorage.getItem('aitm.bus.expect')).toBeNull();
    expect(sessionStorage.getItem('aitm.bus.token')).toBe('abc');
  });

  it('a fragment without t= (an empty hash, or an expectation alone) leaves sessionStorage alone', () => {
    history.replaceState(null, '', '/#');
    build();
    expect(sessionStorage.length).toBe(0);

    history.replaceState(null, '', '/#expect=operator'); // an expectation without a token is nothing to keep
    const bus = build();
    expect(bus.expectRole).toBeNull();
    expect(sessionStorage.length).toBe(0);
  });

  it('survives a malformed percent-encoding and an oversized token without throwing', () => {
    history.replaceState(null, '', '/#t=%E0%A4%A&expect=operator'); // a truncated UTF-8 sequence
    expect(() => build()).not.toThrow();
    // The literal `URLSearchParams` yields: `%E0%A4` is a truncated 3-byte sequence, so one U+FFFD;
    // `%A` has a single hex digit, so it stays as typed. Stored as decoded, neither re-encoded nor dropped.
    expect(sessionStorage.getItem('aitm.bus.token')).toBe('\uFFFD%A');
    sessionStorage.clear();

    const huge = 'x'.repeat(64 * 1024);
    history.replaceState(null, '', `/#t=${huge}`);
    const bus = build();
    expect(bus.address).toBe(BRIDGE);
    expect(sessionStorage.getItem('aitm.bus.token')).toBe(huge); // stored verbatim, not truncated
    expect(location.hash).toBe('');
  });
});
