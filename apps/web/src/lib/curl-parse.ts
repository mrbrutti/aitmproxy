// Import cURL (§2.7 Compose: "paste auto-parses"). The inverse of lib/curl.ts: a POSIX-ish shell
// tokenizer (single/double quotes, `$'…'` ANSI-C quoting, backslash escapes, `\`-newline
// continuations) followed by curl's option grammar for the flags a browser or lib/curl.ts emits.

import type { Header } from '~/model/flow';

export interface ParsedCurl {
  method: string;
  url: string;
  headers: Header[];
  /** null when the command sends no body. */
  body: string | null;
  /** Flags the parser understood but cannot express in a compose (kept for the UI's notice). */
  ignored: string[];
}

export class CurlParseError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'CurlParseError';
  }
}

const ANSI: Record<string, string> = { n: '\n', t: '\t', r: '\r', a: '\x07', b: '\b', f: '\f', v: '\v', e: '\x1b', '\\': '\\', "'": "'", '"': '"' };

/** Split a shell command line into words. Exported for tests. */
export function tokenize(input: string): string[] {
  const words: string[] = [];
  let cur = '';
  let has = false;
  let i = 0;
  const s = input;
  const push = () => {
    if (has) words.push(cur);
    cur = '';
    has = false;
  };
  while (i < s.length) {
    const c = s[i]!;
    if (c === '\\') {
      const next = s[i + 1];
      if (next === '\n' || next === undefined) {
        i += 2;
        continue; // line continuation
      }
      if (next === '\r' && s[i + 2] === '\n') {
        i += 3;
        continue;
      }
      cur += next;
      has = true;
      i += 2;
      continue;
    }
    if (c === ' ' || c === '\t' || c === '\n' || c === '\r') {
      push();
      i++;
      continue;
    }
    if (c === "'") {
      const end = s.indexOf("'", i + 1);
      if (end < 0) throw new CurlParseError('Unterminated single quote');
      cur += s.slice(i + 1, end);
      has = true;
      i = end + 1;
      continue;
    }
    if (c === '$' && s[i + 1] === "'") {
      i += 2;
      let out = '';
      let closed = false;
      while (i < s.length) {
        const ch = s[i]!;
        if (ch === "'") {
          closed = true;
          i++;
          break;
        }
        if (ch === '\\') {
          const e = s[i + 1] ?? '';
          if (e === 'x') {
            const hex = /^[0-9a-fA-F]{1,2}/.exec(s.slice(i + 2))?.[0] ?? '';
            if (hex) {
              out += String.fromCharCode(parseInt(hex, 16));
              i += 2 + hex.length;
              continue;
            }
          }
          if (e === 'u') {
            const hex = /^[0-9a-fA-F]{1,4}/.exec(s.slice(i + 2))?.[0] ?? '';
            if (hex) {
              out += String.fromCharCode(parseInt(hex, 16));
              i += 2 + hex.length;
              continue;
            }
          }
          if (/^[0-7]$/.test(e)) {
            const oct = /^[0-7]{1,3}/.exec(s.slice(i + 1))?.[0] ?? '0';
            out += String.fromCharCode(parseInt(oct, 8));
            i += 1 + oct.length;
            continue;
          }
          out += ANSI[e] ?? e;
          i += 2;
          continue;
        }
        out += ch;
        i++;
      }
      if (!closed) throw new CurlParseError("Unterminated $'…' quote");
      cur += out;
      has = true;
      continue;
    }
    if (c === '"') {
      i++;
      let closed = false;
      while (i < s.length) {
        const ch = s[i]!;
        if (ch === '"') {
          closed = true;
          i++;
          break;
        }
        if (ch === '\\') {
          const e = s[i + 1];
          if (e === '\n') {
            i += 2;
            continue;
          }
          if (e === '"' || e === '\\' || e === '$' || e === '`') {
            cur += e;
            i += 2;
            continue;
          }
          cur += ch;
          i++;
          continue;
        }
        cur += ch;
        i++;
      }
      if (!closed) throw new CurlParseError('Unterminated double quote');
      has = true;
      continue;
    }
    cur += c;
    has = true;
    i++;
  }
  push();
  return words;
}

const DATA_FLAGS = new Set(['-d', '--data', '--data-raw', '--data-binary', '--data-ascii']);
const URLENCODE_FLAGS = new Set(['--data-urlencode', '--data-urlencoded']);
const HEADER_FLAGS = new Set(['-H', '--header']);
// Flags that take a value we do not model; consume the value so it is not mistaken for the URL.
const VALUED_IGNORED = new Set([
  '-o', '--output', '-w', '--write-out', '--max-time', '-m', '--connect-timeout', '--retry', '-x', '--proxy',
  '--cacert', '--cert', '--key', '--resolve', '--interface', '--limit-rate', '-c', '--cookie-jar', '-D', '--dump-header',
  '-T', '--upload-file', '-F', '--form', '--form-string', '--url-query', '-K', '--config', '--proto', '--ciphers',
  '--tls-max', '--tlsv1.2', '--unix-socket', '--abstract-unix-socket', '--http1.1', '--http2', '--http3', '--http2-prior-knowledge',
]);
const NO_VALUE_IGNORED = new Set([
  '-s', '--silent', '-S', '--show-error', '-v', '--verbose', '-k', '--insecure', '-L', '--location', '-i', '--include',
  '--compressed', '-f', '--fail', '-#', '--progress-bar', '--http1.1', '--http2', '--http3', '--http2-prior-knowledge',
  '--tlsv1.2', '--tlsv1.3', '-4', '--ipv4', '-6', '--ipv6', '-N', '--no-buffer', '--globoff', '-g', '--no-progress-meter',
]);

function urlEncodePair(v: string): string {
  // --data-urlencode forms: `content`, `=content`, `name=content`, `@file`, `name@file`.
  if (v.startsWith('=')) return encodeURIComponent(v.slice(1));
  const eq = v.indexOf('=');
  if (eq >= 0) return `${v.slice(0, eq)}=${encodeURIComponent(v.slice(eq + 1))}`;
  return encodeURIComponent(v);
}

/** Parse a cURL command. Throws CurlParseError when it is not one or has no URL. */
export function parseCurl(input: string): ParsedCurl {
  const words = tokenize(input.trim());
  if (words.length === 0) throw new CurlParseError('Empty command');
  let start = 0;
  // Tolerate a leading `$ ` prompt or env assignments before `curl`.
  while (start < words.length && words[start] !== 'curl' && !/^curl(\.exe)?$/.test(words[start]!)) {
    if (words[start] === '$' || /^[A-Za-z_][A-Za-z0-9_]*=/.test(words[start]!)) start++;
    else break;
  }
  if (!/^curl(\.exe)?$/.test(words[start] ?? '')) throw new CurlParseError('Not a curl command');

  let method: string | null = null;
  let url: string | null = null;
  const headers: Header[] = [];
  const data: string[] = [];
  const ignored: string[] = [];
  let head = false;
  let get = false;
  let json = false;
  let basic: string | null = null;
  const extraHeaders: Header[] = [];

  const take = (i: number, flag: string): string => {
    const v = words[i + 1];
    if (v === undefined) throw new CurlParseError(`${flag} needs a value`);
    return v;
  };

  for (let i = start + 1; i < words.length; i++) {
    let w = words[i]!;
    let inline: string | null = null;
    // --flag=value
    if (w.startsWith('--') && w.includes('=')) {
      const eq = w.indexOf('=');
      inline = w.slice(eq + 1);
      w = w.slice(0, eq);
    }
    // Bundled short flags that take a value with no space: -XPOST, -HFoo, -d{...}
    if (/^-[XHdAeubo]./.test(w) && !w.startsWith('--')) {
      inline = w.slice(2);
      w = w.slice(0, 2);
    }
    const value = (): string => {
      if (inline != null) return inline;
      const v = take(i, w);
      i++;
      return v;
    };

    if (w === '-X' || w === '--request') method = value().toUpperCase();
    else if (HEADER_FLAGS.has(w)) {
      const h = value();
      const colon = h.indexOf(':');
      if (colon < 0) {
        // `-H 'Name;'` removes a default header; nothing for us to do.
        continue;
      }
      headers.push({ name: h.slice(0, colon).trim(), value: h.slice(colon + 1).trim() });
    } else if (DATA_FLAGS.has(w)) {
      const d = value();
      data.push(w === '--data-binary' || w === '--data-raw' ? d : d.replace(/\r?\n/g, '')); // -d strips newlines like curl
    } else if (URLENCODE_FLAGS.has(w)) data.push(urlEncodePair(value()));
    else if (w === '--json') {
      data.push(value());
      json = true;
    } else if (w === '--url') url = value();
    else if (w === '-I' || w === '--head') head = true;
    else if (w === '-G' || w === '--get') get = true;
    else if (w === '-u' || w === '--user') basic = value();
    else if (w === '-A' || w === '--user-agent') extraHeaders.push({ name: 'User-Agent', value: value() });
    else if (w === '-e' || w === '--referer') extraHeaders.push({ name: 'Referer', value: value() });
    else if (w === '-b' || w === '--cookie') {
      const c = value();
      if (c.includes('=')) extraHeaders.push({ name: 'Cookie', value: c });
      else ignored.push(`${w} ${c}`);
    } else if (w === '-F' || w === '--form' || w === '--form-string') {
      ignored.push(`${w} ${value()}`);
    } else if (VALUED_IGNORED.has(w) && !NO_VALUE_IGNORED.has(w)) ignored.push(`${w} ${value()}`);
    else if (NO_VALUE_IGNORED.has(w)) ignored.push(w);
    else if (w.startsWith('-') && w !== '-') {
      // Unknown flag: assume it takes no value unless the next word is clearly not a URL/flag.
      ignored.push(w);
    } else if (url == null) url = w;
    else ignored.push(w);
  }

  if (url == null) throw new CurlParseError('No URL in command');
  if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(url)) url = `https://${url}`;

  let body: string | null = data.length ? data.join('&') : null;
  if (get && body != null) {
    url += (url.includes('?') ? '&' : '?') + body;
    body = null;
  }
  const all = [...headers, ...extraHeaders];
  const has = (n: string) => all.some((h) => h.name.toLowerCase() === n);
  if (json) {
    if (!has('content-type')) all.push({ name: 'Content-Type', value: 'application/json' });
    if (!has('accept')) all.push({ name: 'Accept', value: 'application/json' });
  } else if (body != null && !has('content-type') && !get) {
    all.push({ name: 'Content-Type', value: 'application/x-www-form-urlencoded' });
  }
  if (basic != null && !has('authorization')) {
    let b64: string;
    try {
      b64 = btoa(unescape(encodeURIComponent(basic)));
    } catch {
      b64 = '';
    }
    all.push({ name: 'Authorization', value: `Basic ${b64}` });
  }

  const finalMethod = method ?? (head ? 'HEAD' : body != null ? 'POST' : 'GET');
  return { method: finalMethod, url, headers: all, body, ignored };
}

/** True when the text looks like it starts with a curl command (cheap check before parsing). */
export const looksLikeCurl = (text: string): boolean => /^\s*(\$\s*)?(\w+=\S*\s+)*curl(\.exe)?\b/.test(text);
