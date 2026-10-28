import { describe, expect, it } from 'vitest';
import { parseCookieHeader, parseSetCookie, requestCookies, responseCookies } from './cookies';

describe('cookies', () => {
  it('parses a cookie header into pairs', () => {
    expect(parseCookieHeader('session=s%3A9f1c3b; _ga=GA1.2.1; bare')).toEqual([
      { name: 'session', value: 's%3A9f1c3b' },
      { name: '_ga', value: 'GA1.2.1' },
      { name: 'bare', value: '' },
    ]);
  });
  it('parses set-cookie with attributes', () => {
    expect(parseSetCookie('session=s%3A9f1c3b; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=3600')).toEqual({
      name: 'session',
      value: 's%3A9f1c3b',
      attributes: [
        { name: 'Path', value: '/' },
        { name: 'HttpOnly', value: null },
        { name: 'Secure', value: null },
        { name: 'SameSite', value: 'Lax' },
        { name: 'Max-Age', value: '3600' },
      ],
    });
  });
  it('keeps "=" inside values', () => {
    expect(parseSetCookie('t=a=b=c; Path=/').value).toBe('a=b=c');
  });
  it('collects across headers, case-insensitively', () => {
    const req = requestCookies([
      { name: 'Cookie', value: 'a=1' },
      { name: 'accept', value: '*/*' },
      { name: 'cookie', value: 'b=2; c=3' },
    ]);
    expect(req.map((c) => c.name)).toEqual(['a', 'b', 'c']);
    const res = responseCookies([
      { name: 'Set-Cookie', value: 'a=1; Secure' },
      { name: 'set-cookie', value: 'b=2' },
    ]);
    expect(res).toHaveLength(2);
    expect(res[0]!.attributes).toEqual([{ name: 'Secure', value: null }]);
  });
});
