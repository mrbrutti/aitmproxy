//! Image bodies degrade to a labelled placeholder (§2.10(c): "screenshots/image
//! bodies show `[image W×H type · o to open]`"); dimensions come from the
//! file header where the format makes that cheap (PNG, GIF, JPEG).

use ratatui::text::Line;

use crate::model::human_bytes;
use crate::theme::Theme;

/// `(width, height, format)` from the first bytes, if recognisable.
pub fn dimensions(data: &[u8]) -> Option<(u32, u32, &'static str)> {
    if data.len() >= 24 && data.starts_with(b"\x89PNG\r\n\x1a\n") {
        let w = u32::from_be_bytes([data[16], data[17], data[18], data[19]]);
        let h = u32::from_be_bytes([data[20], data[21], data[22], data[23]]);
        return Some((w, h, "PNG"));
    }
    if data.len() >= 10 && (data.starts_with(b"GIF87a") || data.starts_with(b"GIF89a")) {
        let w = u32::from(u16::from_le_bytes([data[6], data[7]]));
        let h = u32::from(u16::from_le_bytes([data[8], data[9]]));
        return Some((w, h, "GIF"));
    }
    if data.len() >= 4 && data.starts_with(b"\xff\xd8") {
        // Walk JPEG segments to the first SOF marker.
        let mut i = 2;
        while i + 9 < data.len() {
            if data[i] != 0xff {
                return Some((0, 0, "JPEG"));
            }
            let marker = data[i + 1];
            let len = usize::from(u16::from_be_bytes([data[i + 2], data[i + 3]]));
            if (0xc0..=0xcf).contains(&marker) && marker != 0xc4 && marker != 0xc8 && marker != 0xcc
            {
                let h = u32::from(u16::from_be_bytes([data[i + 5], data[i + 6]]));
                let w = u32::from(u16::from_be_bytes([data[i + 7], data[i + 8]]));
                return Some((w, h, "JPEG"));
            }
            i += 2 + len;
        }
        return Some((0, 0, "JPEG"));
    }
    if data.len() >= 12 && data.starts_with(b"RIFF") && &data[8..12] == b"WEBP" {
        return Some((0, 0, "WebP"));
    }
    None
}

/// The placeholder lines for an image body.
pub fn placeholder<'a>(theme: &Theme, data: &[u8], content_type: &str) -> Vec<Line<'a>> {
    let label = match dimensions(data) {
        Some((w, h, fmt)) if w > 0 => format!(
            "[image {w}×{h} {fmt} · {} · o to open]",
            human_bytes(data.len() as u64)
        ),
        Some((_, _, fmt)) => format!(
            "[image {fmt} · {} · o to open]",
            human_bytes(data.len() as u64)
        ),
        None => format!(
            "[image {content_type} · {} · o to open]",
            human_bytes(data.len() as u64)
        ),
    };
    vec![
        Line::styled(label, theme.text_secondary()),
        Line::styled(
            "Inline images need a terminal that advertises kitty or sixel graphics.",
            theme.text_tertiary(),
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_png_and_gif_headers() {
        let mut png = b"\x89PNG\r\n\x1a\n\0\0\0\rIHDR".to_vec();
        png.extend_from_slice(&1200u32.to_be_bytes());
        png.extend_from_slice(&800u32.to_be_bytes());
        assert_eq!(dimensions(&png), Some((1200, 800, "PNG")));
        let gif = b"GIF89a\x10\x00\x08\x00".to_vec();
        assert_eq!(dimensions(&gif), Some((16, 8, "GIF")));
        assert_eq!(dimensions(b"hello"), None);
        let t = Theme::new(true);
        let lines = placeholder(&t, &png, "image/png");
        let s: String = lines[0].spans.iter().map(|x| x.content.as_ref()).collect();
        assert_eq!(s, "[image 1200×800 PNG · 24 B · o to open]");
    }
}
