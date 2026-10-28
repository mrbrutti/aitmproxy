import { describe, expect, it } from 'vitest';
import { createHistory, hostOf, normalizeUrl } from './url';

describe('normalizeUrl', () => {
  it('adds https:// when the scheme is missing', () => {
    expect(normalizeUrl('shop-staging.test/login')).toBe('https://shop-staging.test/login');
    expect(normalizeUrl('  api.example.com  ')).toBe('https://api.example.com');
  });
  it('keeps about:blank and anything with a scheme', () => {
    expect(normalizeUrl('about:blank')).toBe('about:blank');
    expect(normalizeUrl('http://shop-staging.test/')).toBe('http://shop-staging.test/');
    expect(normalizeUrl('https://a.test/?q=1')).toBe('https://a.test/?q=1');
    expect(normalizeUrl('data:text/html,<b>x</b>')).toBe('data:text/html,<b>x</b>');
  });
  it('uses plain http for localhost and loopback addresses', () => {
    expect(normalizeUrl('localhost:3000/admin')).toBe('http://localhost:3000/admin');
    expect(normalizeUrl('127.0.0.1:8080')).toBe('http://127.0.0.1:8080');
    expect(normalizeUrl('localhost.test')).toBe('https://localhost.test');
  });
  it('returns null for empty input', () => {
    expect(normalizeUrl('')).toBeNull();
    expect(normalizeUrl('   ')).toBeNull();
  });
});

describe('hostOf', () => {
  it('extracts the host, falls back to the input', () => {
    expect(hostOf('https://shop-staging.test/a/b')).toBe('shop-staging.test');
    expect(hostOf('about:blank')).toBe('about:blank');
    expect(hostOf('')).toBe('');
    expect(hostOf('not a url')).toBe('not a url');
  });
});

describe('createHistory', () => {
  it('steps back and forward over navigated URLs and drops the forward stack on push', () => {
    const h = createHistory();
    expect(h.current()).toBeNull();
    expect(h.back()).toBeNull();
    h.push('https://a.test/');
    h.push('https://b.test/');
    h.push('https://c.test/');
    expect(h.canBack()).toBe(true);
    expect(h.canForward()).toBe(false);
    expect(h.back()).toBe('https://b.test/');
    expect(h.back()).toBe('https://a.test/');
    expect(h.back()).toBeNull();
    expect(h.canBack()).toBe(false);
    expect(h.forward()).toBe('https://b.test/');
    h.push('https://d.test/');
    expect(h.entries()).toEqual(['https://a.test/', 'https://b.test/', 'https://d.test/']);
    expect(h.canForward()).toBe(false);
    expect(h.forward()).toBeNull();
  });
  it('ignores a push of the current URL (reload)', () => {
    const h = createHistory();
    h.push('https://a.test/');
    h.push('https://a.test/');
    expect(h.entries()).toEqual(['https://a.test/']);
  });
});
