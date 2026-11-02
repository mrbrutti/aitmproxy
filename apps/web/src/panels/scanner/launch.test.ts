// The guarded launch path (D-T8.5, D-T8.6): `scan.start` / `scan.map` carry the draft profile
// WHOLE and nothing else, the `needs_confirmation` handshake is surfaced (never fabricated), a
// refusal is classified by `parseScanError`, and the pre-flight explains why a launch button is
// dimmed — a courtesy only: the core's guard is the enforcement.
//
// Fixtures (`crates/aitm-scan-model/fixtures/`) are read for *shapes* only, as the fixture pack's
// README demands: nothing here is evidence that any scan ran, found or reproduced anything.

import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it, vi } from 'vitest';

import type { L4ScopeEntryWire } from '~/panels/l4/model';

import { AGENT_NOTE, CONFIRM_NOTE, L4_HINT } from './helpers';
import { beginLaunch, confirmLaunch, preflight, type PreflightCtx } from './launch';
import type { ScanProfile } from './model';
import { parseScanProfile } from './model';

const here = dirname(fileURLToPath(import.meta.url));
const FIXTURES = resolve(here, '../../../../../crates/aitm-scan-model/fixtures');

const fixture = (name: string): unknown => JSON.parse(readFileSync(resolve(FIXTURES, name), 'utf8'));

/** The `standard` built-in, with the one origin the pre-flight cases talk about. */
const profileOf = (over: Partial<ScanProfile> = {}): ScanProfile => {
  const base = parseScanProfile(fixture('scan.profile.get.json'))!;
  return {
    ...base,
    target: { ...base.target, origins: ['http://127.0.0.1:8080'] },
    ...over,
  };
};

/** The core's real wire prompt for a confirm-gated scan (D-T8.6: printed verbatim). */
const PROMPT =
  'This scan sends malformed traffic to 127.0.0.1:9 and may disrupt the target. Continue?';

const ctx = (over: Partial<PreflightCtx> = {}): PreflightCtx => ({
  scope: [{ host: '127.0.0.1' }],
  l4Offered: false,
  l4Entries: null,
  busOpen: true,
  role: 'operator',
  ...over,
});

const l4Profile = (over: Partial<ScanProfile> = {}): ScanProfile => {
  const base = profileOf();
  return {
    ...base,
    lanes: ['l4_stream'],
    target: { ...base.target, l4: [{ ip: '127.0.0.1', port: 9, proto: 'udp', grammar: null }] },
    ...over,
  };
};

const injectEntry: L4ScopeEntryWire = {
  id: 'e',
  cidr: '127.0.0.0/8',
  ports: '0-65535',
  interface: '*',
  direction: 'outbound',
  capability: 'inject',
  inject_rate: { pps: 100, burst: 100 },
};

describe('launch_sends_the_profile_whole', () => {
  it('surfaces the core prompt and sends { profile } and nothing else (W-12)', async () => {
    const profile = profileOf();
    const call = vi.fn().mockResolvedValue({ status: 'needs_confirmation', prompt: PROMPT, confirm_token: 'tok-1' });

    const outcome = await beginLaunch(call, 'start', profile);

    expect(outcome).toEqual({ kind: 'confirm', prompt: PROMPT, token: 'tok-1' });
    expect(call.mock.calls[0]).toEqual(['scan.start', { profile }]);
    // No `profile_name`, `target`, `overrides` — and no `_confirm` on the first call.
    expect(Object.keys(call.mock.calls[0]![1] as Record<string, unknown>)).toEqual(['profile']);
  });

  it('re-issues the map verb with the reserved _confirm token', async () => {
    const profile = profileOf();
    const call = vi.fn().mockResolvedValue(fixture('scan.start.json'));

    const outcome = await confirmLaunch(call, 'map', profile, 'tok-1');

    expect(call.mock.calls[0]).toEqual(['scan.map', { profile, _confirm: 'tok-1' }]);
    expect(outcome.kind).toBe('started');
  });

  it('parses a direct start result (no confirmation asked)', async () => {
    const call = vi.fn().mockResolvedValue(fixture('scan.start.json'));

    const outcome = await beginLaunch(call, 'start', profileOf());

    expect(outcome.kind).toBe('started');
    if (outcome.kind !== 'started') throw new Error('expected started');
    expect(outcome.result.job).toBe('scan-1a2b3c4d');
    expect(outcome.result.clamped[0]!.applied).toBe(20000);
  });

  it('reports a reply it cannot parse as malformed instead of inventing a job', async () => {
    const call = vi.fn().mockResolvedValue({});

    const outcome = await beginLaunch(call, 'start', profileOf());

    expect(outcome.kind).toBe('malformed');
    if (outcome.kind !== 'malformed') throw new Error('expected malformed');
    expect(outcome.message).toBe('scan.start answered with an unexpected shape');
  });
});

describe('launch_classifies_a_refusal', () => {
  it('splits a scan: error into its code and detail, keeping the raw message', async () => {
    const call = vi.fn().mockRejectedValue(new Error('scan: refused_agent: agent session'));

    const outcome = await beginLaunch(call, 'start', profileOf());

    expect(outcome).toEqual({
      kind: 'refused',
      code: 'refused_agent',
      detail: 'agent session',
      message: 'scan: refused_agent: agent session',
    });
  });

  it('keeps an unrecognised message verbatim with a null code', async () => {
    const call = vi.fn().mockRejectedValue(new Error('nope'));

    const outcome = await beginLaunch(call, 'start', profileOf());

    expect(outcome.kind).toBe('refused');
    if (outcome.kind !== 'refused') throw new Error('expected refused');
    expect(outcome.code).toBeNull();
    expect(outcome.detail).toBe('nope');
    expect(outcome.message).toBe('nope');
  });

  it('classifies a refusal on the confirming call too', async () => {
    const call = vi.fn().mockRejectedValue(new Error('scan: busy: max_jobs'));

    const outcome = await confirmLaunch(call, 'start', profileOf(), 'tok-1');

    expect(outcome).toEqual({
      kind: 'refused',
      code: 'busy',
      detail: 'max_jobs',
      message: 'scan: busy: max_jobs',
    });
  });
});

describe('preflight_explains_a_dimmed_button', () => {
  it('passes an in-scope HTTP draft with no note', () => {
    expect(preflight(profileOf(), ctx())).toEqual({ ok: true, note: null });
  });

  it('refuses before the bus is open', () => {
    expect(preflight(profileOf(), ctx({ busOpen: false }))).toEqual({
      ok: false,
      reason: 'the bus is not open',
    });
  });

  it('asks for a target when the draft has neither an origin nor an L4 target', () => {
    const empty = profileOf({ target: { origins: [], l4: [] } });
    expect(preflight(empty, ctx())).toEqual({ ok: false, reason: 'add an origin or an L4 target' });
  });

  it('names the host to add when an origin is out of scope', () => {
    expect(preflight(profileOf(), ctx({ scope: [] }))).toEqual({
      ok: false,
      reason: 'out of scope: add 127.0.0.1 to Scope',
    });
  });

  it('refuses an L4 lane when the core does not offer the L4 layer', () => {
    expect(preflight(l4Profile(), ctx({ l4Offered: false }))).toEqual({
      ok: false,
      reason: 'the L4 layer is not enabled on this core',
    });
  });

  it('prints the D11 hint when no Inject scope entry covers the L4 target', () => {
    const result = preflight(l4Profile(), ctx({ l4Offered: true, l4Entries: [] }));

    expect(result.ok).toBe(false);
    if (result.ok) throw new Error('expected a refusal');
    expect(result.reason.startsWith('no L4 scope entry with Inject covers 127.0.0.1:9')).toBe(true);
    expect(result.reason).toContain('interface: "*"');
    expect(result.reason).toContain(L4_HINT);
  });

  it('passes a covered L4 target and notes the confirmation handshake', () => {
    expect(preflight(l4Profile(), ctx({ l4Offered: true, l4Entries: [injectEntry] }))).toEqual({
      ok: true,
      note: CONFIRM_NOTE,
    });
  });

  it('never disables on unknown coverage (no live l4.scope.list)', () => {
    const result = preflight(l4Profile(), ctx({ l4Offered: true, l4Entries: null }));
    expect(result.ok).toBe(true);
  });

  it('keeps the controls enabled for an agent session and explains the core policy', () => {
    const result = preflight(profileOf({ intensity: 'intrusive' }), ctx({ role: 'agent' }));

    expect(result.ok).toBe(true);
    if (!result.ok) throw new Error('expected ok');
    expect(result.note).toContain(CONFIRM_NOTE);
    expect(result.note).toContain(AGENT_NOTE);
  });
});
