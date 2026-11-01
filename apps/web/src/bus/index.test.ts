// `createBus()` is the one place the UI picks its bus. There is exactly one: the WebSocket bridge
// at `/bus` on this origin. The mock bus and its `?bus=mock` switch were removed on 2026-10-31
// (spec 2026-10-31-remove-fake-data-ui-modes, D1 web); this pins that a page opened with the old
// query still gets the real bus, and that the launch-URL fragment is read and stripped as before.
import { afterEach, describe, expect, it } from 'vitest';
import { createBus } from './index';

afterEach(() => {
  sessionStorage.clear();
  history.replaceState(null, '', '/');
});

describe('createBus', () => {
  it('ignores ?bus=mock and always builds the WebSocket bus', () => {
    history.replaceState(null, '', '/?bus=mock&rate=1#t=abc&expect=operator');
    const bus = createBus();
    expect(bus.address).not.toBe('fixtures');
    expect(sessionStorage.getItem('aitm.bus.token')).toBe('abc');
    expect(sessionStorage.getItem('aitm.bus.expect')).toBe('operator');
    expect(location.hash).toBe('');
    bus.close();
  });
});
