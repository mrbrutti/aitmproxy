//! A tolerant YAML tokenizer for the PoC document language, sharing the
//! [`SyntaxToken`] set with Rhai so the Findings/PoC viewer and editor colour
//! keys, strings, numbers, booleans, comments and structure identically in
//! view and edit (spec AC2). Line-oriented and forgiving: a line with no
//! `key:` still renders as text, never a panic or a blank line.

use super::SyntaxToken;

type Tok = (SyntaxToken, String);

/// Tokenizes `src` into one `(token, text)` list per line; the concatenation
/// of every text, with `\n` between lines, is exactly `src`.
pub fn tokenize(src: &str) -> Vec<Vec<Tok>> {
    src.split('\n').map(scan_line).collect()
}

fn push(out: &mut Vec<Tok>, tok: SyntaxToken, s: &str) {
    if !s.is_empty() {
        out.push((tok, s.to_string()));
    }
}

fn scan_line(line: &str) -> Vec<Tok> {
    let mut out = Vec::new();
    let b = line.as_bytes();
    let n = b.len();
    let mut i = 0;

    // Leading indentation.
    while i < n && b[i] == b' ' {
        i += 1;
    }
    push(&mut out, SyntaxToken::Text, &line[0..i]);

    // One or more "- " list markers.
    while b.get(i) == Some(&b'-') && (b.get(i + 1) == Some(&b' ') || i + 1 == n) {
        push(&mut out, SyntaxToken::Punct, "-");
        i += 1;
        let s = i;
        while i < n && b[i] == b' ' {
            i += 1;
        }
        push(&mut out, SyntaxToken::Text, &line[s..i]);
    }

    if i >= n {
        return out;
    }
    // A whole-line comment.
    if b[i] == b'#' {
        push(&mut out, SyntaxToken::Comment, &line[i..]);
        return out;
    }

    // `key:` …
    if let Some(colon) = key_colon(b, i) {
        push(&mut out, SyntaxToken::Key, &line[i..colon]);
        push(&mut out, SyntaxToken::Punct, ":");
        scan_value(line, colon + 1, &mut out);
    } else {
        scan_value(line, i, &mut out);
    }
    out
}

/// If a plain key (`[A-Za-z0-9_.-]+`) followed by `:` and then a space or the
/// line end starts at `start`, returns the byte index of that `:`.
fn key_colon(b: &[u8], start: usize) -> Option<usize> {
    let n = b.len();
    let mut i = start;
    while i < n && is_key_byte(b[i]) {
        i += 1;
    }
    if i > start && i < n && b[i] == b':' && (i + 1 == n || b[i + 1] == b' ') {
        Some(i)
    } else {
        None
    }
}

fn is_key_byte(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'_' || c == b'-' || c == b'.'
}

/// Colours the value region of a line from `start`: leading spaces as text, an
/// inline `#` comment, and the scalar itself classified as string / number /
/// boolean / text.
fn scan_value(line: &str, start: usize, out: &mut Vec<Tok>) {
    let b = line.as_bytes();
    let n = b.len();
    let mut i = start;

    let s = i;
    while i < n && b[i] == b' ' {
        i += 1;
    }
    push(out, SyntaxToken::Text, &line[s..i]);
    if i >= n {
        return;
    }
    if b[i] == b'#' {
        push(out, SyntaxToken::Comment, &line[i..]);
        return;
    }

    // The value ends at an inline " #" comment, if any.
    let mut end = n;
    let mut j = i;
    while j < n {
        if b[j] == b'#' && j > i && b[j - 1] == b' ' {
            end = j;
            break;
        }
        j += 1;
    }
    let mut vend = end;
    while vend > i && b[vend - 1] == b' ' {
        vend -= 1;
    }
    push(out, classify(&line[i..vend]), &line[i..vend]);
    push(out, SyntaxToken::Text, &line[vend..end]);
    if end < n {
        push(out, SyntaxToken::Comment, &line[end..]);
    }
}

/// Classifies a scalar value: quoted → string, numeric → number,
/// `true`/`false`/`null` → boolean, anything else → plain text.
fn classify(v: &str) -> SyntaxToken {
    let t = v.trim();
    if t.starts_with('"') || t.starts_with('\'') {
        SyntaxToken::Str
    } else if matches!(t, "true" | "false" | "null" | "~") {
        SyntaxToken::Boolean
    } else if is_number(t) {
        SyntaxToken::Number
    } else {
        SyntaxToken::Text
    }
}

fn is_number(t: &str) -> bool {
    !t.is_empty() && (t.parse::<i64>().is_ok() || t.parse::<f64>().is_ok())
}
