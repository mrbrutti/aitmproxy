// Pure logic for the system-proxy pill and menu (spec D6 compact fields, D12 word table, D15 web;
// plan Task 20 / C9). No bus, no store: `app.ts` only wires these.

import { describe, expect, it } from 'vitest';
import type { SystemProxyStatus } from '~/bus/types';
import { menuState, parseSystemProxy, pillWord } from './systemProxy';

const base: SystemProxyStatus = {
  state: 'off',
  host: null,
  port: null,
  managed_by_us: false,
  setting: false,
  supported: true,
  detail: 'HTTP and HTTPS off',
};
const off = base;
const pointsAtUs: SystemProxyStatus = {
  ...base,
  state: 'points_at_us',
  managed_by_us: true,
  detail: 'HTTP and HTTPS → 127.0.0.1:8080 (this core)',
};
const other: SystemProxyStatus = {
  ...base,
  state: 'other',
  host: '127.0.0.1',
  port: 9090,
  detail: 'HTTP and HTTPS → 127.0.0.1:9090 (not this core)',
};
const needsPrivilege: SystemProxyStatus = { ...base, state: 'needs_privilege', detail: 'needs an administrator' };
const unsupported: SystemProxyStatus = {
  ...base,
  state: 'unsupported',
  supported: false,
  detail: 'no system proxy mechanism here',
};
const unknown: SystemProxyStatus = { ...base, state: 'unknown', detail: 'read failed' };

describe('parseSystemProxy', () => {
  it('reads the compact proxy.status sub-object field for field', () => {
    const s = parseSystemProxy({
      state: 'other',
      host: '127.0.0.1',
      port: 9090,
      managed_by_us: false,
      setting: false,
      supported: true,
      detail: 'x',
    });
    expect(s).not.toBeNull();
    expect(s?.state).toBe('other');
    expect(s?.host).toBe('127.0.0.1');
    expect(s?.port).toBe(9090);
    expect(s?.managed_by_us).toBe(false);
    expect(s?.setting).toBe(false);
    expect(s?.supported).toBe(true);
    expect(s?.detail).toBe('x');
  });

  it('is null when the sub-object is absent or not an object', () => {
    expect(parseSystemProxy(undefined)).toBeNull();
    expect(parseSystemProxy(null)).toBeNull();
    expect(parseSystemProxy('points_at_us')).toBeNull();
    expect(parseSystemProxy(42)).toBeNull();
    expect(parseSystemProxy([])).toBeNull();
  });

  it('maps a state string it does not know to unknown', () => {
    const s = parseSystemProxy({ state: 'teleported', detail: 'd' });
    expect(s?.state).toBe('unknown');
    expect(s?.detail).toBe('d');
  });

  it('keeps guidance and remedy from the full status, null when absent', () => {
    const full = parseSystemProxy({
      state: 'unsupported',
      host: null,
      port: null,
      managed_by_us: false,
      setting: false,
      supported: false,
      detail: 'd',
      guidance: 'export HTTPS_PROXY=http://127.0.0.1:8080',
      remedy: null,
    });
    expect(full?.guidance).toBe('export HTTPS_PROXY=http://127.0.0.1:8080');
    expect(full?.remedy).toBeNull();
    const compact = parseSystemProxy({ state: 'off', detail: 'd' });
    expect(compact?.guidance).toBeNull();
    expect(compact?.remedy).toBeNull();
  });

  it('drops host/port that are not a string/number', () => {
    const s = parseSystemProxy({ state: 'other', host: 7, port: '9090', detail: 'd' });
    expect(s?.host).toBeNull();
    expect(s?.port).toBeNull();
  });
});

describe('pillWord (D12 pill-word column)', () => {
  it('names the other endpoint', () => {
    expect(pillWord(other, false)).toBe('· sys-proxy → 127.0.0.1:9090');
  });
  it('says us when the system proxy points at this core', () => {
    expect(pillWord(pointsAtUs, false)).toBe('· sys-proxy → us');
    expect(pillWord({ ...pointsAtUs, managed_by_us: false }, false)).toBe('· sys-proxy → us');
  });
  it('says off', () => {
    expect(pillWord(off, false)).toBe('· sys-proxy off');
  });
  it('says needs admin', () => {
    expect(pillWord(needsPrivilege, false)).toBe('· sys-proxy needs admin');
  });
  it('shows nothing for unsupported, unknown and no status', () => {
    expect(pillWord(unsupported, false)).toBeNull();
    expect(pillWord(unknown, false)).toBeNull();
    expect(pillWord(null, false)).toBeNull();
  });
  it('shows setting… while a change is in flight, ours or another client’s', () => {
    expect(pillWord(off, true)).toBe('· sys-proxy setting…');
    expect(pillWord({ ...other, setting: true }, false)).toBe('· sys-proxy setting…');
    expect(pillWord(null, true)).toBe('· sys-proxy setting…');
  });
});

describe('menuState (D15 menu button)', () => {
  it('is checked when the system proxy points at us', () => {
    const m = menuState(pointsAtUs, false, 'operator');
    expect(m.checked).toBe(true);
    expect(m.disabled).toBe(false);
    expect(m.title).toBeUndefined();
    expect(m.showCopyEnv).toBe(false);
  });
  it('is unchecked and enabled for off and other on an operator connection', () => {
    expect(menuState(off, false, 'operator')).toEqual({ checked: false, disabled: false, title: undefined, showCopyEnv: false });
    expect(menuState(other, false, 'operator').checked).toBe(false);
    expect(menuState(other, false, 'operator').disabled).toBe(false);
  });
  it('is disabled with the in-flight title while setting', () => {
    const m = menuState(off, true, 'operator');
    expect(m.disabled).toBe(true);
    expect(m.title).toBe('setting system proxy…');
    expect(menuState({ ...off, setting: true }, false, 'operator').title).toBe('setting system proxy…');
  });
  it('is disabled with the unsupported title when the mechanism is none', () => {
    const m = menuState(unsupported, false, 'operator');
    expect(m.disabled).toBe(true);
    expect(m.title).toBe('system proxy not available here');
  });
  it('is disabled for a non-operator connection, with the operator-token title', () => {
    const agent = menuState(off, false, 'agent');
    expect(agent.disabled).toBe(true);
    expect(agent.title).toBe('connect with the operator token to change the system proxy');
    const unknownRole = menuState(off, false, null);
    expect(unknownRole.disabled).toBe(true);
    expect(unknownRole.title).toBe('connect with the operator token to change the system proxy');
  });
  it('is disabled for needs_privilege, unknown and no status', () => {
    expect(menuState(needsPrivilege, false, 'operator').disabled).toBe(true);
    expect(menuState(unknown, false, 'operator').disabled).toBe(true);
    expect(menuState(null, false, 'operator').disabled).toBe(true);
    expect(menuState(null, false, 'operator').checked).toBe(false);
  });
  it('offers Copy env line only when guidance is present', () => {
    expect(menuState({ ...unsupported, guidance: 'export HTTPS_PROXY=http://127.0.0.1:8080' }, false, 'operator').showCopyEnv).toBe(true);
    expect(menuState({ ...unsupported, guidance: null }, false, 'operator').showCopyEnv).toBe(false);
    expect(menuState({ ...unsupported, guidance: '' }, false, 'operator').showCopyEnv).toBe(false);
    expect(menuState(unsupported, false, 'operator').showCopyEnv).toBe(false);
  });
});
