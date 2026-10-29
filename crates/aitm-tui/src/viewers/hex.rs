//! Hex viewer: `offset · bytes · ASCII` (§2.7).

use ratatui::text::{Line, Span};

use crate::theme::Theme;

/// Dump `data` with `per_line` bytes per row.
pub fn dump<'a>(theme: &Theme, data: &[u8], per_line: usize) -> Vec<Line<'a>> {
    let per_line = per_line.max(1);
    data.chunks(per_line)
        .enumerate()
        .map(|(i, chunk)| {
            let mut hex = String::with_capacity(per_line * 3);
            for (j, b) in chunk.iter().enumerate() {
                if j == per_line / 2 && per_line >= 8 {
                    hex.push(' ');
                }
                hex.push_str(&format!("{b:02x} "));
            }
            let pad = per_line * 3 + usize::from(per_line >= 8) - hex.len();
            hex.extend(std::iter::repeat_n(' ', pad));
            let ascii: String = chunk
                .iter()
                .map(|&b| {
                    if (0x20..0x7f).contains(&b) {
                        b as char
                    } else {
                        '·'
                    }
                })
                .collect();
            Line::from(vec![
                Span::styled(format!("{:08x}  ", i * per_line), theme.line_number()),
                Span::styled(hex, theme.text_primary()),
                Span::styled(" │ ", theme.syntax_punct()),
                Span::styled(ascii, theme.syntax_string()),
            ])
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rows_have_offset_bytes_and_ascii() {
        let t = Theme::new(true);
        let lines = dump(&t, b"GET /api\x00\xff", 8);
        let row: String = lines[0].spans.iter().map(|s| s.content.as_ref()).collect();
        assert_eq!(row, "00000000  47 45 54 20  2f 61 70 69  │ GET /api");
        let row: String = lines[1].spans.iter().map(|s| s.content.as_ref()).collect();
        assert_eq!(row, "00000008  00 ff                     │ ··");
    }
}
