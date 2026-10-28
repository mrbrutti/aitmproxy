//! Clipboard via OSC 52 (§2.9 "Clipboard: OSC 52 if the terminal allows"). The
//! sequence is written to the terminal; whether it reaches the system
//! clipboard is the terminal's decision, so the UI says "copied (OSC 52)"
//! rather than promising.

use std::io::Write;

use crate::base64;

/// The OSC 52 sequence that sets the system clipboard (`c`) to `text`.
pub fn osc52(text: &str) -> String {
    format!("\x1b]52;c;{}\x07", base64::encode(text.as_bytes()))
}

/// Write the sequence to stdout. Errors are the caller's to report.
pub fn copy(text: &str) -> std::io::Result<()> {
    let mut out = std::io::stdout().lock();
    out.write_all(osc52(text).as_bytes())?;
    out.flush()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sequence_is_osc_52_with_base64_payload() {
        assert_eq!(
            osc52("https://a.test/"),
            "\x1b]52;c;aHR0cHM6Ly9hLnRlc3Qv\x07"
        );
    }
}
