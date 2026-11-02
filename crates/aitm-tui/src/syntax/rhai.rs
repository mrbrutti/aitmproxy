//! A tolerant Rhai tokenizer (for colouring, not parsing), driven by the
//! shared `rhai.grammar.json`: the keyword and literal sets come from
//! [`crate::languages`], and the lexical rules (line/block comments, the four
//! string forms, numbers) re-express the grammar's described rules in a byte
//! scanner. It never panics: an unterminated string or block comment colours
//! to the end of its span and the scan resumes on the next line.

use super::SyntaxToken;
use crate::languages::{RHAI_KEYWORDS, RHAI_LITERALS};

/// Cross-line lexer state: a span a line left open.
#[derive(Clone, Copy)]
enum Carry {
    None,
    /// Inside a `/* */` block comment at this nesting depth (grammar: nested).
    Block(u32),
    /// Inside a `#"… "#` raw string.
    Raw,
    /// Inside a `` `…` `` interpolated string.
    Interp,
}

type Tok = (SyntaxToken, String);

/// Tokenizes `src` into one `(token, text)` list per line (split on `\n`); the
/// concatenation of every text, with `\n` between lines, is exactly `src`.
pub fn tokenize(src: &str) -> Vec<Vec<Tok>> {
    let mut carry = Carry::None;
    src.split('\n')
        .map(|line| {
            let mut out = Vec::new();
            scan_line(line, &mut carry, &mut out);
            out
        })
        .collect()
}

fn push(out: &mut Vec<Tok>, tok: SyntaxToken, s: &str) {
    if !s.is_empty() {
        out.push((tok, s.to_string()));
    }
}

fn scan_line(line: &str, carry: &mut Carry, out: &mut Vec<Tok>) {
    let b = line.as_bytes();
    let n = b.len();
    let mut i = 0;

    // Close any span carried from the previous line first.
    match *carry {
        Carry::Block(depth) => {
            let (end, left) = scan_block(b, 0, depth);
            push(out, SyntaxToken::Comment, &line[0..end]);
            *carry = if left == 0 {
                Carry::None
            } else {
                Carry::Block(left)
            };
            if left > 0 {
                return;
            }
            i = end;
        }
        Carry::Raw => match find(b, 0, b"\"#") {
            Some(e) => {
                push(out, SyntaxToken::Str, &line[0..e]);
                *carry = Carry::None;
                i = e;
            }
            None => {
                push(out, SyntaxToken::Str, line);
                return;
            }
        },
        Carry::Interp => match scan_string_body(b, 0, b'`') {
            Some(e) => {
                push(out, SyntaxToken::Str, &line[0..e]);
                *carry = Carry::None;
                i = e;
            }
            None => {
                push(out, SyntaxToken::Str, line);
                return;
            }
        },
        Carry::None => {}
    }

    while i < n {
        let c = b[i];
        if c.is_ascii_whitespace() {
            let s = i;
            while i < n && b[i].is_ascii_whitespace() {
                i += 1;
            }
            push(out, SyntaxToken::Text, &line[s..i]);
        } else if c == b'/' && i + 1 < n && b[i + 1] == b'/' {
            push(out, SyntaxToken::Comment, &line[i..]);
            return;
        } else if c == b'/' && i + 1 < n && b[i + 1] == b'*' {
            let (end, left) = scan_block(b, i + 2, 1);
            push(out, SyntaxToken::Comment, &line[i..end]);
            if left > 0 {
                *carry = Carry::Block(left);
                return;
            }
            i = end;
        } else if c == b'"' {
            let end = scan_string_body(b, i + 1, b'"').unwrap_or(n);
            push(out, SyntaxToken::Str, &line[i..end]);
            i = end;
        } else if c == b'\'' {
            let end = scan_string_body(b, i + 1, b'\'').unwrap_or(n);
            push(out, SyntaxToken::Str, &line[i..end]);
            i = end;
        } else if c == b'`' {
            match scan_string_body(b, i + 1, b'`') {
                Some(end) => {
                    push(out, SyntaxToken::Str, &line[i..end]);
                    i = end;
                }
                None => {
                    push(out, SyntaxToken::Str, &line[i..]);
                    *carry = Carry::Interp;
                    return;
                }
            }
        } else if c == b'#' && i + 1 < n && b[i + 1] == b'"' {
            match find(b, i + 2, b"\"#") {
                Some(end) => {
                    push(out, SyntaxToken::Str, &line[i..end]);
                    i = end;
                }
                None => {
                    push(out, SyntaxToken::Str, &line[i..]);
                    *carry = Carry::Raw;
                    return;
                }
            }
        } else if c == b'#' && i + 1 < n && b[i + 1] == b'{' {
            push(out, SyntaxToken::Punct, &line[i..i + 2]);
            i += 2;
        } else if c.is_ascii_digit() {
            let end = scan_number(b, i);
            push(out, SyntaxToken::Number, &line[i..end]);
            i = end;
        } else if c == b'_' || c.is_ascii_alphabetic() {
            let s = i;
            i += 1;
            while i < n && (b[i] == b'_' || b[i].is_ascii_alphanumeric()) {
                i += 1;
            }
            let word = &line[s..i];
            let tok = if RHAI_KEYWORDS.contains(&word) {
                SyntaxToken::Keyword
            } else if RHAI_LITERALS.contains(&word) {
                SyntaxToken::Boolean
            } else {
                SyntaxToken::Text
            };
            push(out, tok, word);
        } else {
            // A single operator / punctuation byte (ASCII).
            push(out, SyntaxToken::Punct, &line[i..i + 1]);
            i += 1;
        }
    }
}

/// Scans a block comment from `start`, with `depth` levels already open,
/// counting nested `/*` and `*/`. Returns the byte index just past the point
/// it fully closes (depth 0) or the line end, and the depth still open.
fn scan_block(b: &[u8], start: usize, mut depth: u32) -> (usize, u32) {
    let n = b.len();
    let mut i = start;
    while i < n {
        if i + 1 < n && b[i] == b'/' && b[i + 1] == b'*' {
            depth += 1;
            i += 2;
        } else if i + 1 < n && b[i] == b'*' && b[i + 1] == b'/' {
            depth -= 1;
            i += 2;
            if depth == 0 {
                return (i, 0);
            }
        } else {
            i += 1;
        }
    }
    (n, depth)
}

/// Scans a string body from `start` to the byte past the closing `quote`,
/// honouring `\` escapes; `None` when the quote is not closed on this line.
fn scan_string_body(b: &[u8], start: usize, quote: u8) -> Option<usize> {
    let n = b.len();
    let mut i = start;
    while i < n {
        if b[i] == b'\\' {
            i += 2;
            continue;
        }
        if b[i] == quote {
            return Some(i + 1);
        }
        i += 1;
    }
    None
}

/// Scans a numeric literal from `start` (a digit), returning the byte index
/// just past it. Hex/octal/binary prefixes, a fractional part and an exponent
/// are all recognised; underscores are allowed as digit separators.
fn scan_number(b: &[u8], start: usize) -> usize {
    let n = b.len();
    let mut i = start;
    if b[i] == b'0' && i + 1 < n && matches!(b[i + 1] | 0x20, b'x' | b'o' | b'b') {
        i += 2;
        while i < n && (b[i].is_ascii_hexdigit() || b[i] == b'_') {
            i += 1;
        }
        return i;
    }
    while i < n && (b[i].is_ascii_digit() || b[i] == b'_') {
        i += 1;
    }
    if i + 1 < n && b[i] == b'.' && b[i + 1].is_ascii_digit() {
        i += 1;
        while i < n && (b[i].is_ascii_digit() || b[i] == b'_') {
            i += 1;
        }
    }
    if i < n && (b[i] == b'e' || b[i] == b'E') {
        let mut j = i + 1;
        if j < n && (b[j] == b'+' || b[j] == b'-') {
            j += 1;
        }
        if j < n && b[j].is_ascii_digit() {
            i = j;
            while i < n && (b[i].is_ascii_digit() || b[i] == b'_') {
                i += 1;
            }
        }
    }
    i
}

/// Finds `needle` in `b` from `start`, returning the byte index just past it.
fn find(b: &[u8], start: usize, needle: &[u8]) -> Option<usize> {
    let m = needle.len();
    if m == 0 {
        return Some(start);
    }
    let n = b.len();
    let mut i = start;
    while i + m <= n {
        if &b[i..i + m] == needle {
            return Some(i + m);
        }
        i += 1;
    }
    None
}
