// A small HTML tokenizer for the DOM pane: enough to tint tag names, attribute names and quoted
// values the way the inspector's header tables do (syntax.key / syntax.string), text stays
// primary. It never builds a tree and never throws on broken markup — unknown input is text.

export type DomTokenKind = 'text' | 'punct' | 'tag' | 'attr' | 'string' | 'comment';

export interface DomToken {
  kind: DomTokenKind;
  text: string;
}

const NAME = /[A-Za-z0-9:_.-]/;
const WS = /\s/;

export function tokenizeHtml(src: string): DomToken[] {
  const out: DomToken[] = [];
  const push = (kind: DomTokenKind, text: string) => {
    if (!text) return;
    const last = out[out.length - 1];
    if (last && last.kind === kind && (kind === 'text' || kind === 'punct')) last.text += text;
    else out.push({ kind, text });
  };

  let i = 0;
  const n = src.length;
  while (i < n) {
    if (src[i] !== '<') {
      const j = src.indexOf('<', i);
      push('text', src.slice(i, j < 0 ? n : j));
      i = j < 0 ? n : j;
      continue;
    }
    // comments, doctype, cdata
    if (src.startsWith('<!--', i)) {
      const end = src.indexOf('-->', i + 4);
      const stop = end < 0 ? n : end + 3;
      push('comment', src.slice(i, stop));
      i = stop;
      continue;
    }
    if (src[i + 1] === '!' || src[i + 1] === '?') {
      const end = src.indexOf('>', i);
      const stop = end < 0 ? n : end + 1;
      push('comment', src.slice(i, stop));
      i = stop;
      continue;
    }
    // a tag needs a name right after `<` or `</`
    let k = i + 1;
    if (src[k] === '/') k++;
    if (k >= n || !/[A-Za-z]/.test(src[k]!)) {
      push('text', '<');
      i++;
      continue;
    }
    push('punct', src.slice(i, k));
    let j = k;
    while (j < n && NAME.test(src[j]!)) j++;
    push('tag', src.slice(k, j));
    i = j;
    // attributes until `>` or `/>`
    while (i < n) {
      const c = src[i]!;
      if (c === '>') {
        push('punct', '>');
        i++;
        break;
      }
      if (c === '/' && src[i + 1] === '>') {
        push('punct', '/>');
        i += 2;
        break;
      }
      if (c === '<') break; // unterminated tag: let the next tag start
      if (WS.test(c)) {
        let w = i;
        while (w < n && WS.test(src[w]!)) w++;
        push('text', src.slice(i, w));
        i = w;
        continue;
      }
      if (c === '=') {
        push('punct', '=');
        i++;
        continue;
      }
      if (c === '"' || c === "'") {
        const end = src.indexOf(c, i + 1);
        const stop = end < 0 ? n : end + 1;
        push('string', src.slice(i, stop));
        i = stop;
        continue;
      }
      // attribute name, or an unquoted value right after `=`
      let w = i;
      while (w < n && !WS.test(src[w]!) && src[w] !== '>' && src[w] !== '=' && !(src[w] === '/' && src[w + 1] === '>')) w++;
      if (w === i) {
        push('text', c);
        i++;
        continue;
      }
      const prev = out[out.length - 1];
      push(prev && prev.kind === 'punct' && prev.text.endsWith('=') ? 'string' : 'attr', src.slice(i, w));
      i = w;
    }
  }
  return out;
}

/** Lines of `src` that contain `needle` (case-insensitive); all lines for an empty needle. */
export function filterLines(src: string, needle: string): { lines: string[]; total: number } {
  const lines = src.split('\n');
  const q = needle.trim().toLowerCase();
  if (!q) return { lines, total: lines.length };
  return { lines: lines.filter((l) => l.toLowerCase().includes(q)), total: lines.length };
}
