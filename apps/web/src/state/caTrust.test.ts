// CA trust in the web UI (system-proxy spec §D17.12, SP-AC36): the pure readers of `ca.status`
// and the words they render, then the store's wiring of them.

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { BusClient } from '~/bus/types';
import { createAppStore } from './app';
import { memoryBus, tick } from './bridgeBus.testkit';
import { caInstallArgs, caPillWord, isCACancelled, isCATrustTool, parseCATrust, type CATrustStatus } from './caTrust';

/** `ca.status` as the core answers it on a Mac with the CA in the login keychain and trusted. */
const MAC_TRUSTED = {
  exists: true,
  dir: '/Users/op/Library/Application Support/aitmproxy',
  path: '/Users/op/Library/Application Support/aitmproxy/ca.crt',
  platform: 'macos',
  fingerprint_sha256: 'AB:CD',
  fingerprint_sha1: '12:34',
  stores: { user: { installed: 'present', trusted: 'yes', location: 'x' } },
  detail: [],
};

/** The same Mac before `security verify-cert` could say anything: every store `trusted: unknown`. */
const MAC_ALL_UNKNOWN = {
  ...MAC_TRUSTED,
  stores: { user: { installed: 'present', trusted: 'unknown', location: 'x' }, system: { installed: 'absent', trusted: 'unknown', location: 'y' } },
};

const trusted: CATrustStatus = { trusted: true, scope: 'user', platform: 'macos', fingerprint: 'AB:CD' };
const notTrusted: CATrustStatus = { trusted: false, scope: null, platform: 'macos', fingerprint: 'AB:CD' };
const linux: CATrustStatus = { trusted: false, scope: null, platform: 'linux-debian', fingerprint: 'AB:CD' };

describe('parseCATrust', () => {
  it('reads a trusted user store into the status', () => {
    expect(parseCATrust({ exists: true, platform: 'macos', fingerprint_sha256: 'AB:CD', stores: { user: { installed: 'present', trusted: 'yes', location: 'x' } } })).toEqual({
      trusted: true,
      scope: 'user',
      platform: 'macos',
      fingerprint: 'AB:CD',
    });
  });

  it('is null when every store is unknown (an older core, or the evaluation tool failed)', () => {
    expect(parseCATrust({ exists: true, platform: 'macos', fingerprint_sha256: 'AB:CD', stores: { user: { installed: 'present', trusted: 'unknown', location: 'x' }, system: { installed: 'absent', trusted: 'unknown', location: 'y' } } })).toBeNull();
  });

  it('reads "no" everywhere as not trusted, with no scope', () => {
    expect(parseCATrust({ exists: true, platform: 'macos', fingerprint_sha256: 'AB:CD', stores: { user: { installed: 'absent', trusted: 'no', location: 'x' }, system: { installed: 'absent', trusted: 'no', location: 'y' } } })).toEqual(notTrusted);
  });

  it('names the System keychain when only that store trusts the CA', () => {
    expect(parseCATrust({ exists: true, platform: 'macos', fingerprint_sha256: null, stores: { user: { installed: 'absent', trusted: 'no', location: 'x' }, system: { installed: 'present', trusted: 'yes', location: 'y' } } })).toEqual({
      trusted: true,
      scope: 'system',
      platform: 'macos',
      fingerprint: null,
    });
  });

  it('is null for anything that is not the ca.status shape', () => {
    expect(parseCATrust(null)).toBeNull();
    expect(parseCATrust('trusted')).toBeNull();
    expect(parseCATrust({ exists: false, platform: 'macos', fingerprint_sha256: null, stores: {} })).toBeNull();
    // the fixture bus's older shape: store values are bare strings and there is no platform
    expect(parseCATrust({ installed: 'yes', trusted: 'yes', stores: { system: 'no', user: 'yes' } })).toBeNull();
  });
});

describe('caPillWord', () => {
  it('renders the four words of the D17.6 table and nothing else', () => {
    expect(caPillWord(trusted, false)).toBe('· CA trusted');
    expect(caPillWord(notTrusted, false)).toBe('· CA untrusted');
    expect(caPillWord(trusted, true)).toBe('· CA trusting…');
    expect(caPillWord(notTrusted, true)).toBe('· CA trusting…');
    expect(caPillWord(null, true)).toBe('· CA trusting…');
    expect(caPillWord(null, false)).toBeNull();
    expect(caPillWord(parseCATrust(MAC_ALL_UNKNOWN), false)).toBeNull();
  });
});

describe('caInstallArgs', () => {
  it('asks for the user scope on macOS and Windows and nothing elsewhere (D17.1)', () => {
    expect(caInstallArgs(notTrusted)).toEqual({ scope: 'user' });
    expect(caInstallArgs({ ...notTrusted, platform: 'windows' })).toEqual({ scope: 'user' });
    expect(caInstallArgs(linux)).toEqual({});
    expect(caInstallArgs(null)).toEqual({});
  });
});

describe('isCACancelled', () => {
  it('recognises the core’s cancelled message for both verbs and nothing else', () => {
    expect(isCACancelled('ca.install cancelled: the macOS authentication dialog was dismissed; the CA is not trusted')).toBe(true);
    expect(isCACancelled('ca.uninstall cancelled: the macOS authentication dialog was dismissed; the CA is still trusted')).toBe(true);
    expect(isCACancelled('ca.install refused: ca.install is refused from an agent frontend')).toBe(false);
    expect(isCACancelled('ca.status cancelled')).toBe(false);
    expect(isCACancelled('the ca.install cancelled message, quoted')).toBe(false);
    expect(isCACancelled('')).toBe(false);
  });
});

describe('isCATrustTool', () => {
  it('names exactly the two calls that change the OS trust store', () => {
    expect(isCATrustTool('ca.install')).toBe(true);
    expect(isCATrustTool('ca.uninstall')).toBe(true);
    expect(isCATrustTool('ca.status')).toBe(false);
    expect(isCATrustTool('ca.export')).toBe(false);
    expect(isCATrustTool('')).toBe(false);
  });
});

// ---- store wiring --------------------------------------------------------------------------

/** The in-memory bus with `ca.status` answering the core's real shape, optionally without the tool at all. */
function caBus(reply: () => unknown, opts: { withTool?: boolean } = {}): BusClient & { reads: () => number } {
  const mem = memoryBus(opts.withTool === false ? {} : { extraTools: ['ca.status'] });
  let reads = 0;
  return {
    ...mem,
    reads: () => reads,
    async call<T>(tool: string, args: Record<string, unknown> = {}): Promise<T> {
      if (tool === 'ca.status') {
        reads++;
        return reply() as T;
      }
      return mem.call<T>(tool, args);
    },
  };
}

let open: BusClient[] = [];
const start = (bus: BusClient) => {
  open.push(bus);
  return createAppStore(bus);
};

beforeEach(() => {
  vi.useFakeTimers();
});
afterEach(() => {
  for (const b of open) b.close();
  open = [];
  vi.useRealTimers();
});

describe('app store — CA trust', () => {
  it('reads ca.status once after the tool catalogue and keeps the parsed status', async () => {
    const bus = caBus(() => MAC_TRUSTED);
    const app = start(bus);
    expect(app.ca).toBeNull();
    expect(app.caInstalling).toBe(false);

    await tick(200);

    expect(bus.reads()).toBe(1);
    expect(app.ca).toEqual(trusted);
  });

  it('never asks a bus without ca.status, and refreshCA() is then a no-op', async () => {
    const bus = caBus(() => MAC_TRUSTED, { withTool: false });
    const app = start(bus);
    await tick(200);
    await expect(app.refreshCA()).resolves.toBe(false);
    expect(bus.reads()).toBe(0);
    expect(app.ca).toBeNull();
  });

  it('refreshCA() re-reads and follows the store (the word comes from the read-back, D17.5)', async () => {
    let reply: unknown = { ...MAC_TRUSTED, stores: { user: { installed: 'absent', trusted: 'no', location: 'x' } } };
    const bus = caBus(() => reply);
    const app = start(bus);
    await tick(200);
    expect(app.ca).toEqual(notTrusted);

    reply = MAC_TRUSTED;
    await expect(app.refreshCA()).resolves.toBe(true);
    expect(bus.reads()).toBe(2);
    expect(app.ca).toEqual(trusted);

    reply = { ...MAC_TRUSTED, stores: { user: { installed: 'present', trusted: 'unknown', location: 'x' } } };
    await expect(app.refreshCA()).resolves.toBe(true);
    expect(app.ca).toBeNull();
  });

  it('keeps the last reading when the re-read fails, and says so', async () => {
    let fail = false;
    const bus = caBus(() => {
      if (fail) throw new Error('ca.status: bus closed (1006)');
      return MAC_TRUSTED;
    });
    const app = start(bus);
    await tick(200);
    fail = true;
    await expect(app.refreshCA()).resolves.toBe(false);
    expect(app.ca).toEqual(trusted);
  });

  it('exposes the in-flight flag the palette sets around ca.install / ca.uninstall', async () => {
    const app = start(caBus(() => MAC_TRUSTED));
    await tick(200);
    app.setCAInstalling(true);
    expect(app.caInstalling).toBe(true);
    app.setCAInstalling(false);
    expect(app.caInstalling).toBe(false);
  });
});
