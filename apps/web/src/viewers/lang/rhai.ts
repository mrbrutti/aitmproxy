// A tolerant Rhai colorizer as a CodeMirror StreamLanguage parser (UI scripting-highlight spec §1.1).
// It colours what an operator scans — keywords, literals, strings, numbers, comments, structure —
// using the foundation syntax faces; it is a colorizer, not a parser, so partial or malformed source
// (an unterminated string, a half-written `flow.`) still renders and never throws. The keyword/
// literal/operator/punctuation sets come from the generated grammar, never hard-coded here.
//
// Runtime imports of @codemirror/* are deliberately avoided (only a type-only import): this module is
// pulled into the lazy editor chunk, and its logic must add no CodeMirror weight of its own.
import type { StreamParser, StringStream } from '@codemirror/language';
import { rhaiGrammar } from './defs.gen';

/** The foundation syntax faces a token can carry (spec §1.1 `map_token`); `text` is uncoloured. */
export type SynTag = 'keyword' | 'boolean' | 'string' | 'number' | 'comment' | 'punct' | 'key' | 'text';

const KEYWORDS = new Set<string>(rhaiGrammar.keywords);
// `()` is the unit literal — two punctuation chars in the stream, so only the word literals matter here.
const LITERALS = new Set<string>(rhaiGrammar.literals.filter((l) => /^[A-Za-z]/.test(l)));

// Symbol tokens (operators + punctuation), longest first so `==` beats `=` and `::` beats `:`.
const SYMBOLS = [...rhaiGrammar.operators, ...rhaiGrammar.punctuation].sort((a, b) => b.length - a.length);

const NUMBER = new RegExp('^(?:' + rhaiGrammar.lexical.number.pattern + ')');
const IDENT = new RegExp('^' + rhaiGrammar.lexical.identifier.pattern);

interface RhaiState {
  // Depth of open block comments (nested); 0 when not inside one.
  comment: number;
  // A multiline string left open on a previous line: backtick-interpolated, or raw.
  string: null | 'interp' | 'raw';
}

/** Consume a single-line string body; returns true if the closing quote was found on this line. */
function eatString(stream: StringStream, close: string): boolean {
  let ch: string | void;
  while ((ch = stream.next()) != null) {
    if (ch === '\\') {
      stream.next();
      continue;
    }
    if (ch === close) return true;
  }
  return false; // ran to end of line unterminated
}

/** Consume a raw string body up to the `"#` terminator; returns true if found on this line. */
function eatRaw(stream: StringStream): boolean {
  while (!stream.eol()) {
    if (stream.match('"#')) return true;
    stream.next();
  }
  return false;
}

/** Consume block-comment text, tracking nesting; clears depth to 0 when balanced on this line. */
function eatBlock(stream: StringStream, state: RhaiState): void {
  while (!stream.eol()) {
    if (stream.match('/*')) {
      state.comment++;
      continue;
    }
    if (stream.match('*/')) {
      state.comment--;
      if (state.comment <= 0) {
        state.comment = 0;
        return;
      }
      continue;
    }
    stream.next();
  }
}

export const rhaiStreamParser: StreamParser<RhaiState> = {
  startState: () => ({ comment: 0, string: null }),
  token(stream, state): SynTag | null {
    // Continue a construct left open on a previous line.
    if (state.comment > 0) {
      eatBlock(stream, state);
      return 'comment';
    }
    if (state.string === 'interp') {
      if (eatString(stream, '`')) state.string = null;
      return 'string';
    }
    if (state.string === 'raw') {
      if (eatRaw(stream)) state.string = null;
      return 'string';
    }

    if (stream.eatSpace()) return null;

    if (stream.match('//')) {
      stream.skipToEnd();
      return 'comment';
    }
    if (stream.match('/*')) {
      state.comment = 1;
      eatBlock(stream, state);
      return 'comment';
    }
    if (stream.match('#"')) {
      if (!eatRaw(stream)) state.string = 'raw';
      return 'string';
    }

    const ch = stream.peek();
    if (ch === '"' || ch === "'") {
      stream.next();
      eatString(stream, ch); // unterminated colours to end of line
      return 'string';
    }
    if (ch === '`') {
      stream.next();
      if (!eatString(stream, '`')) state.string = 'interp';
      return 'string';
    }

    if (stream.match(NUMBER)) return 'number';

    const id = stream.match(IDENT) as RegExpMatchArray | null;
    if (id) {
      const w = id[0];
      if (KEYWORDS.has(w)) return 'keyword';
      if (LITERALS.has(w)) return 'boolean';
      return 'text';
    }

    for (const sym of SYMBOLS) if (stream.match(sym)) return 'punct';

    stream.next();
    return null;
  },
  languageData: { commentTokens: { line: '//', block: { open: '/*', close: '*/' } } },
};
