import { describe, expect, it } from 'vitest';
import { countSeen, fmtBackoff, fmtRateLimit, matchesScope, outOfScopeHosts, validateHost } from './scope';

describe('validateHost', () => {
  it('accepts the three forms and normalises case and whitespace', () => {
    expect(validateHost('api.shop-staging.test')).toEqual({ ok: true, host: 'api.shop-staging.test' });
    expect(validateHost('  API.Shop-Staging.TEST ')).toEqual({ ok: true, host: 'api.shop-staging.test' });
    expect(validateHost('localhost')).toEqual({ ok: true, host: 'localhost' });
    expect(validateHost('10.0.0.5')).toEqual({ ok: true, host: '10.0.0.5' });
    expect(validateHost('api.example.test:8443')).toEqual({ ok: true, host: 'api.example.test:8443' });
    expect(validateHost('*.shop-staging.test')).toEqual({ ok: true, host: '*.shop-staging.test' });
  });

  it('rejects URLs, paths, spaces, bad ports and stray wildcards', () => {
    expect(validateHost('')).toMatchObject({ ok: false });
    expect(validateHost('https://api.example.test')).toMatchObject({ ok: false, error: expect.stringContaining('not a URL') });
    expect(validateHost('api.example.test/login')).toMatchObject({ ok: false, error: expect.stringContaining('no path') });
    expect(validateHost('api example.test')).toMatchObject({ ok: false, error: 'Hosts contain no spaces.' });
    expect(validateHost('api.example.test:99999')).toMatchObject({ ok: false, error: 'Port must be 1–65535.' });
    expect(validateHost('api.example.test:')).toMatchObject({ ok: false });
    expect(validateHost('api.*.test')).toMatchObject({ ok: false, error: expect.stringContaining('wildcard goes first') });
    expect(validateHost('*.test')).toMatchObject({ ok: false, error: expect.stringContaining('domain after it') });
    expect(validateHost('*.example.test:443')).toMatchObject({ ok: false });
    expect(validateHost('-bad.example.test')).toMatchObject({ ok: false });
    expect(validateHost('user@example.test')).toMatchObject({ ok: false });
  });
});

describe('matchesScope / countSeen', () => {
  it('matches exact hosts regardless of the authority port, host:port exactly, wildcards by suffix', () => {
    expect(matchesScope('api.example.test', 'api.example.test')).toBe(true);
    expect(matchesScope('api.example.test:8443', 'api.example.test')).toBe(true);
    expect(matchesScope('api.example.test:8443', 'api.example.test:8443')).toBe(true);
    expect(matchesScope('api.example.test', 'api.example.test:8443')).toBe(false);
    expect(matchesScope('api.example.test', '*.example.test')).toBe(true);
    expect(matchesScope('a.b.example.test', '*.example.test')).toBe(true);
    expect(matchesScope('example.test', '*.example.test')).toBe(false);
    expect(matchesScope('notexample.test', '*.example.test')).toBe(false);
    expect(matchesScope('API.Example.TEST', 'api.example.test')).toBe(true);
  });

  it('counts wildcard matches across authorities', () => {
    const seen = ['api.shop-staging.test', 'cdn.shop-staging.test', 'cdn.shop-staging.test', 'auth.other.test', 'shop-staging.test'];
    expect(countSeen(seen, '*.shop-staging.test')).toBe(3);
    expect(countSeen(seen, 'cdn.shop-staging.test')).toBe(2);
    expect(countSeen(seen, 'nothing.test')).toBe(0);
  });
});

describe('outOfScopeHosts', () => {
  it('keeps only hosts no entry covers, in the given order', () => {
    const domains = [
      { host: 'api.shop-staging.test', count: 40 },
      { host: 'telemetry.vendor.test', count: 12 },
      { host: 'cdn.shop-staging.test', count: 9 },
      { host: 'auth.other.test:8443', count: 2 },
    ];
    const scope = [{ host: '*.shop-staging.test' }, { host: 'auth.other.test:8443' }];
    expect(outOfScopeHosts(domains, scope)).toEqual([{ host: 'telemetry.vendor.test', count: 12 }]);
    expect(outOfScopeHosts(domains, [])).toEqual(domains);
  });
});

describe('rate limit / back-off readouts', () => {
  it('formats what the core sends and returns null for absent config', () => {
    expect(fmtRateLimit({ rps: 10, burst: 20 })).toBe('10 rps · burst 20');
    expect(fmtRateLimit({ rps: 5 })).toBe('5 rps');
    expect(fmtRateLimit(3)).toBe('3 rps');
    expect(fmtRateLimit(undefined)).toBeNull();
    expect(fmtRateLimit({})).toBeNull();
    expect(fmtBackoff({ base_ms: 500, max_ms: 8000 })).toBe('500 ms → 8.00 s');
    expect(fmtBackoff({ base_ms: 250 })).toBe('250 ms');
    expect(fmtBackoff(null)).toBeNull();
  });
});
