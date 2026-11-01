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

// ---- tester additions (stage 5): degenerate inputs, the fallback fields, and the menu's precedence ----

describe('parseSystemProxy — degenerate fields (tester)', () => {
  it('drops a non-finite port and a non-object detail; a string "true" is not a boolean', () => {
    const s = parseSystemProxy({ state: 'other', host: '10.0.0.1', port: Number.NaN, managed_by_us: 'true', setting: 'yes', detail: 42 });
    expect(s).toEqual({
      state: 'other',
      host: '10.0.0.1',
      port: null,
      managed_by_us: false,
      setting: false,
      supported: true,
      detail: '',
      guidance: null,
      remedy: null,
    });
    expect(parseSystemProxy({ state: 'other', port: Number.POSITIVE_INFINITY })?.port).toBeNull();
    expect(parseSystemProxy({ state: 'other', port: -1 })?.port).toBe(-1); // passed through: the core owns the range
  });

  it('derives `supported` from the state only when the field is absent', () => {
    expect(parseSystemProxy({ state: 'unsupported' })?.supported).toBe(false);
    expect(parseSystemProxy({ state: 'other' })?.supported).toBe(true);
    expect(parseSystemProxy({ state: 'unknown' })?.supported).toBe(true);
    // Explicit wins over the derivation, in both directions.
    expect(parseSystemProxy({ state: 'off', supported: false })?.supported).toBe(false);
    expect(parseSystemProxy({ state: 'unsupported', supported: true })?.supported).toBe(true);
  });

  it('an empty object is a status with state unknown, not null', () => {
    expect(parseSystemProxy({})).toEqual({
      state: 'unknown',
      host: null,
      port: null,
      managed_by_us: false,
      setting: false,
      supported: true,
      detail: '',
      guidance: null,
      remedy: null,
    });
  });

  it('never returns a word for a status that is not a plain object (a function, a Date are not statuses)', () => {
    expect(parseSystemProxy(() => 1)).toBeNull();
    // A Date is an object: it parses to a status with state unknown and no detail; the pill then shows nothing.
    const fromDate = parseSystemProxy(new Date(0));
    expect(fromDate?.state).toBe('unknown');
    expect(fromDate?.detail).toBe('');
    expect(pillWord(fromDate, false)).toBeNull();
  });
});

describe('pillWord — the `other` row without an endpoint (tester)', () => {
  it('falls back to ? for a missing host or port rather than inventing one', () => {
    expect(pillWord({ ...other, host: null, port: null }, false)).toBe('· sys-proxy → ?:?');
    expect(pillWord({ ...other, port: null }, false)).toBe('· sys-proxy → 127.0.0.1:?');
    expect(pillWord({ ...other, host: null }, false)).toBe('· sys-proxy → ?:9090');
  });

  it('is either null or a D12 word for every state — never an empty string', () => {
    const states = ['off', 'points_at_us', 'other', 'unsupported', 'needs_privilege', 'unknown'] as const;
    for (const state of states) {
      const w = pillWord({ ...base, state }, false);
      expect(w === null || w.startsWith('· sys-proxy ')).toBe(true);
    }
    // Only the three "nothing" cases are null; the table has four words plus setting….
    expect(states.filter((state) => pillWord({ ...base, state }, false) === null)).toEqual(['unsupported', 'unknown']);
  });

  it('setting… wins over every state, including the ones that otherwise show nothing', () => {
    for (const s of [off, pointsAtUs, other, needsPrivilege, unsupported, unknown]) {
      expect(pillWord(s, true)).toBe('· sys-proxy setting…');
      expect(pillWord({ ...s, setting: true }, false)).toBe('· sys-proxy setting…');
    }
  });
});

describe('menuState — needs_privilege title and the precedence of the three titles (tester)', () => {
  it('needs_privilege: disabled, unchecked, the title is the remedy sentence when the core sent one', () => {
    const remedy = 'The system proxy needs an administrator; run the core as one.';
    const m = menuState({ ...needsPrivilege, remedy }, false, 'operator');
    expect(m).toEqual({ checked: false, disabled: true, title: remedy, showCopyEnv: false });
    expect(menuState(needsPrivilege, false, 'operator').title).toBeUndefined();
  });

  it('in flight beats unsupported beats non-operator beats nothing-to-do', () => {
    // in flight > unsupported
    expect(menuState(unsupported, true, 'operator').title).toBe('setting system proxy…');
    // unsupported > non-operator
    expect(menuState(unsupported, false, 'agent').title).toBe('system proxy not available here');
    // non-operator > needs_privilege / unknown / null
    expect(menuState({ ...needsPrivilege, remedy: 'r' }, false, 'agent').title).toBe('connect with the operator token to change the system proxy');
    expect(menuState(null, false, 'agent').title).toBe('connect with the operator token to change the system proxy');
    // `supported: false` with any other state is the unsupported title too
    expect(menuState({ ...off, supported: false }, false, 'operator').title).toBe('system proxy not available here');
  });

  it('checked follows the state regardless of who is connected or what is in flight', () => {
    expect(menuState(pointsAtUs, true, 'operator').checked).toBe(true);
    expect(menuState(pointsAtUs, false, 'agent').checked).toBe(true);
    expect(menuState({ ...pointsAtUs, supported: false }, false, 'operator').checked).toBe(true);
    expect(menuState(other, false, 'operator').checked).toBe(false);
  });

  it('showCopyEnv needs a non-empty guidance string, whatever the state', () => {
    expect(menuState({ ...off, guidance: 'export HTTP_PROXY=http://127.0.0.1:8080' }, false, 'agent').showCopyEnv).toBe(true);
    expect(menuState(off, false, 'operator').showCopyEnv).toBe(false); // the compact status has no guidance key at all
  });
});
