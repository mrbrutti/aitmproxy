// Cookie / Set-Cookie header parsing for the Cookies and Set-Cookie tabs.

import type { Header } from '~/model/flow';

export interface Cookie {
  name: string;
  value: string;
}

export interface CookieAttribute {
  name: string;
  value: string | null;
}

export interface SetCookie extends Cookie {
  attributes: CookieAttribute[];
}

/** `a=1; b=2` → pairs. Values keep their encoding (the table shows them as sent). */
export function parseCookieHeader(value: string): Cookie[] {
  return value
    .split(';')
    .map((p) => p.trim())
    .filter(Boolean)
    .map((p) => {
      const i = p.indexOf('=');
      return i < 0 ? { name: p, value: '' } : { name: p.slice(0, i).trim(), value: p.slice(i + 1).trim() };
    });
}

/** `session=abc; Path=/; HttpOnly; Secure; SameSite=Lax` → cookie + attribute list. */
export function parseSetCookie(value: string): SetCookie {
  const [first = '', ...rest] = value.split(';');
  const i = first.indexOf('=');
  const name = i < 0 ? first.trim() : first.slice(0, i).trim();
  const val = i < 0 ? '' : first.slice(i + 1).trim();
  const attributes = rest
    .map((p) => p.trim())
    .filter(Boolean)
    .map((p) => {
      const j = p.indexOf('=');
      return j < 0 ? { name: p, value: null } : { name: p.slice(0, j).trim(), value: p.slice(j + 1).trim() };
    });
  return { name, value: val, attributes };
}

/** Every cookie across all `cookie` headers of a request. */
export function requestCookies(headers: Header[]): Cookie[] {
  return headers.filter((h) => h.name.toLowerCase() === 'cookie').flatMap((h) => parseCookieHeader(h.value));
}

/** Every `set-cookie` header of a response, parsed. */
export function responseCookies(headers: Header[]): SetCookie[] {
  return headers.filter((h) => h.name.toLowerCase() === 'set-cookie').map((h) => parseSetCookie(h.value));
}
