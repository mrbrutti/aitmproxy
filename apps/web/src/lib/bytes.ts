// Byte helpers for binary bodies: base64 ⇄ Uint8Array and UTF-8 decoding. Bodies arrive as
// `Body.base64` when they are not text (§3.3 hex / image viewers).

const B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
const LOOKUP = new Uint8Array(128);
for (let i = 0; i < B64.length; i++) LOOKUP[B64.charCodeAt(i)] = i;
LOOKUP['-'.charCodeAt(0)] = 62; // url-safe variants
LOOKUP['_'.charCodeAt(0)] = 63;

export function base64ToBytes(b64: string): Uint8Array {
  const clean = b64.replace(/[^A-Za-z0-9+/\-_]/g, '');
  const len = clean.length;
  const pad = len % 4;
  const outLen = Math.floor((len * 3) / 4) - (pad === 0 ? 0 : 0);
  const out = new Uint8Array(outLen);
  let o = 0;
  let buf = 0;
  let bits = 0;
  for (let i = 0; i < len; i++) {
    const c = clean.charCodeAt(i);
    buf = (buf << 6) | (LOOKUP[c] ?? 0);
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      if (o < outLen) out[o++] = (buf >> bits) & 0xff;
    }
  }
  return o === outLen ? out : out.subarray(0, o);
}

export function bytesToBase64(bytes: Uint8Array): string {
  let s = '';
  for (let i = 0; i < bytes.length; i += 3) {
    const a = bytes[i]!;
    const b = i + 1 < bytes.length ? bytes[i + 1]! : 0;
    const c = i + 2 < bytes.length ? bytes[i + 2]! : 0;
    const n = (a << 16) | (b << 8) | c;
    s += B64[(n >> 18) & 63]! + B64[(n >> 12) & 63]!;
    s += i + 1 < bytes.length ? B64[(n >> 6) & 63]! : '=';
    s += i + 2 < bytes.length ? B64[n & 63]! : '=';
  }
  return s;
}

const decoder = new TextDecoder('utf-8', { fatal: false });
const strictDecoder = new TextDecoder('utf-8', { fatal: true });
const encoder = new TextEncoder();

export function utf8Decode(bytes: Uint8Array): string {
  return decoder.decode(bytes);
}

/** Null when the bytes are not valid UTF-8 (so the caller falls back to hex). */
export function utf8DecodeStrict(bytes: Uint8Array): string | null {
  try {
    return strictDecoder.decode(bytes);
  } catch {
    return null;
  }
}

export function utf8Encode(text: string): Uint8Array {
  return encoder.encode(text);
}

export function utf8Length(text: string): number {
  return encoder.encode(text).length;
}

/** Heuristic: a body is binary when the first 512 bytes contain NUL or > 10% control chars. */
export function looksBinary(bytes: Uint8Array): boolean {
  const n = Math.min(bytes.length, 512);
  if (n === 0) return false;
  let control = 0;
  for (let i = 0; i < n; i++) {
    const b = bytes[i]!;
    if (b === 0) return true;
    if (b < 7 || (b > 13 && b < 32)) control++;
  }
  return control / n > 0.1;
}
