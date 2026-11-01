//! `probe`: report, as one JSON line, which capabilities this process has
//! (spec §2.2, the `linux_cap_helper` file-caps row; AC17). Read-only: it
//! changes nothing on the machine.
//!
//! The core runs `aitm-l4-helper probe` on a helper it discovered and reads
//! the line to learn whether that copy carries `cap_net_raw+ep` as a file
//! capability. On macOS the same line says whether `/dev/bpf0` opens
//! read-write for this account.

use std::fmt::Write as _;

/// `CAP_NET_ADMIN` is capability number 12 (`linux/capability.h`).
const CAP_NET_ADMIN_BIT: u32 = 12;
/// `CAP_NET_RAW` is capability number 13 (`linux/capability.h`).
const CAP_NET_RAW_BIT: u32 = 13;

/// The one JSON line `probe` prints:
/// `{"cap_net_raw":bool,"cap_net_admin":bool,"bpf_rw":bool|null,"version":"…"}`.
///
/// `cap_eff` is the process's effective capability set as read from
/// `/proc/self/status` (`None` where there is no such thing, i.e. macOS, and
/// both capabilities are then `false`). `bpf_rw` is whether `/dev/bpf0` opened
/// read-write (`None` where it was not tried or does not exist).
///
/// Hand-formatted on purpose: the four non-string fields are booleans or
/// `null`, and the only string is `CARGO_PKG_VERSION`, a semver cargo has
/// already validated, so it contains no quote or backslash to escape.
pub fn probe_json(cap_eff: Option<u64>, bpf_rw: Option<bool>) -> String {
    let caps = cap_eff.unwrap_or(0);
    let cap_net_raw = caps & (1u64 << CAP_NET_RAW_BIT) != 0;
    let cap_net_admin = caps & (1u64 << CAP_NET_ADMIN_BIT) != 0;
    let bpf_rw = match bpf_rw {
        Some(true) => "true",
        Some(false) => "false",
        None => "null",
    };
    let mut line = String::with_capacity(96);
    // Writing into a String cannot fail; the result is dropped deliberately.
    let _ = write!(
        line,
        "{{\"cap_net_raw\":{cap_net_raw},\"cap_net_admin\":{cap_net_admin},\"bpf_rw\":{bpf_rw},\"version\":\"{}\"}}",
        env!("CARGO_PKG_VERSION")
    );
    line
}

/// Gather this host's inputs and format the line. Reads only: on Linux
/// `/proc/self/status`; on macOS it opens `/dev/bpf0` read-write and drops the
/// handle at once, which changes no state. `Err` carries a one-sentence
/// reason (never a command to run).
pub fn run() -> Result<String, String> {
    let cap_eff = read_cap_eff()?;
    let bpf_rw = read_bpf_rw()?;
    Ok(probe_json(cap_eff, bpf_rw))
}

/// The `CapEff:` line of a `/proc/<pid>/status` text, as a bit set.
///
/// `None` when the line is absent or not hexadecimal.
// TODO(p1b): replace with aitm_proto_l4::privilege::linux::parse_cap_eff
#[cfg(any(target_os = "linux", test))]
fn parse_cap_eff(status: &str) -> Option<u64> {
    status.lines().find_map(|line| {
        let hex = line.strip_prefix("CapEff:")?.trim();
        u64::from_str_radix(hex, 16).ok()
    })
}

#[cfg(target_os = "linux")]
fn read_cap_eff() -> Result<Option<u64>, String> {
    let status = std::fs::read_to_string("/proc/self/status")
        .map_err(|err| format!("cannot read /proc/self/status: {err}"))?;
    Ok(parse_cap_eff(&status))
}

#[cfg(target_os = "linux")]
fn read_bpf_rw() -> Result<Option<bool>, String> {
    // Linux has no /dev/bpf*; capture goes through CAP_NET_RAW sockets.
    Ok(None)
}

#[cfg(target_os = "macos")]
fn read_cap_eff() -> Result<Option<u64>, String> {
    // macOS has no capability sets.
    Ok(None)
}

#[cfg(target_os = "macos")]
fn read_bpf_rw() -> Result<Option<bool>, String> {
    use std::io::ErrorKind;
    // Opening a bpf node and dropping it attaches to no interface and sets no
    // option; nothing on the machine changes.
    match std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/bpf0")
    {
        Ok(_bpf) => Ok(Some(true)),
        Err(err) if err.kind() == ErrorKind::PermissionDenied => Ok(Some(false)),
        Err(err) if err.kind() == ErrorKind::NotFound => Ok(None),
        Err(err) => Err(format!(
            "cannot tell whether /dev/bpf0 opens read-write: {err}"
        )),
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn read_cap_eff() -> Result<Option<u64>, String> {
    Ok(None)
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn read_bpf_rw() -> Result<Option<bool>, String> {
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cap_net_raw_bit() {
        let line = probe_json(Some(0x2000), None);
        assert!(
            line.contains("\"cap_net_raw\":true,\"cap_net_admin\":false"),
            "{line}"
        );
        assert!(line.contains("\"bpf_rw\":null"), "{line}");
    }

    #[test]
    fn both_capability_bits_and_bpf_rw_true() {
        let line = probe_json(Some(0x3000), Some(true));
        assert!(
            line.contains("\"cap_net_raw\":true,\"cap_net_admin\":true"),
            "{line}"
        );
        assert!(line.contains("\"bpf_rw\":true"), "{line}");
    }

    #[test]
    fn no_cap_eff_means_both_false_and_bpf_rw_false_is_literal() {
        let line = probe_json(None, Some(false));
        assert!(
            line.contains("\"cap_net_raw\":false,\"cap_net_admin\":false"),
            "{line}"
        );
        assert!(line.contains("\"bpf_rw\":false"), "{line}");
    }

    #[test]
    fn other_capability_bits_do_not_count() {
        // Every bit except 12 and 13 set: neither capability is reported.
        let line = probe_json(Some(!0x3000), None);
        assert!(
            line.contains("\"cap_net_raw\":false,\"cap_net_admin\":false"),
            "{line}"
        );
        // Only CAP_NET_ADMIN (bit 12).
        let line = probe_json(Some(0x1000), None);
        assert!(
            line.contains("\"cap_net_raw\":false,\"cap_net_admin\":true"),
            "{line}"
        );
    }

    #[test]
    fn full_line_is_exactly_the_five_fields_and_one_line() {
        let version = env!("CARGO_PKG_VERSION");
        assert!(
            version.starts_with(|c: char| c.is_ascii_digit()),
            "CARGO_PKG_VERSION is a semver: {version:?}"
        );
        let line = probe_json(Some(0x2000), None);
        assert_eq!(
            line,
            format!(
                "{{\"cap_net_raw\":true,\"cap_net_admin\":false,\"bpf_rw\":null,\"version\":\"{version}\"}}"
            )
        );
        assert!(!line.contains('\n'), "one line, no newline: {line:?}");
    }

    #[test]
    fn parse_cap_eff_reads_the_hex_line_from_a_proc_status_excerpt() {
        // A literal excerpt of /proc/self/status for a process holding only
        // CAP_NET_RAW (bit 13) in its effective set.
        let status = "Name:\taitm-l4-helper\n\
                      Umask:\t0022\n\
                      State:\tR (running)\n\
                      Pid:\t4242\n\
                      CapInh:\t0000000000000000\n\
                      CapPrm:\t0000000000002000\n\
                      CapEff:\t0000000000002000\n\
                      CapBnd:\t000001ffffffffff\n\
                      CapAmb:\t0000000000000000\n";
        assert_eq!(parse_cap_eff(status), Some(0x2000));
        // Feeding the parsed value through probe_json gives the AC17 answer.
        let line = probe_json(parse_cap_eff(status), None);
        assert!(
            line.contains("\"cap_net_raw\":true,\"cap_net_admin\":false"),
            "{line}"
        );
    }

    #[test]
    fn parse_cap_eff_root_and_absent_and_malformed() {
        // Full root set on a 5.x kernel.
        assert_eq!(
            parse_cap_eff("CapEff:\t000001ffffffffff\n"),
            Some(0x0000_01ff_ffff_ffff)
        );
        // CapPrm must not be mistaken for CapEff.
        assert_eq!(parse_cap_eff("CapPrm:\t0000000000002000\n"), None);
        assert_eq!(parse_cap_eff(""), None);
        assert_eq!(parse_cap_eff("CapEff:\tnot-hex\n"), None);
    }

    #[test]
    fn run_yields_one_json_line_on_this_host() {
        // The platform gatherers only read (/proc/self/status, or open and
        // drop /dev/bpf0); whatever this host is, the answer is one JSON line.
        let line = run().expect("probe::run on the test host");
        assert!(line.starts_with("{\"cap_net_raw\":"), "{line}");
        assert!(line.ends_with("\"}"), "{line}");
        assert!(!line.contains('\n'), "{line:?}");
    }

    // ---- Tester edge cases (stage 5, unit p2) ------------------------------

    /// The line starts with the literal `prefix` (the three decided fields),
    /// then the version field, then the closing brace, and nothing else.
    fn assert_line(got: &str, prefix: &str) {
        assert!(got.starts_with(prefix), "{got}");
        let tail = &got[prefix.len()..];
        assert!(tail.starts_with("\"version\":\""), "{got}");
        assert!(tail.ends_with("\"}"), "{got}");
        // Four keys and one string value: ten double quotes, four colons,
        // three commas, one brace pair; so a parser sees exactly four fields.
        assert_eq!(got.matches('"').count(), 10, "{got}");
        assert_eq!(got.matches(':').count(), 4, "{got}");
        assert_eq!(got.matches(',').count(), 3, "{got}");
        assert_eq!(got.matches('{').count(), 1, "{got}");
        assert_eq!(got.matches('}').count(), 1, "{got}");
    }

    #[test]
    fn tester_all_capability_bits_set_reports_both_true() {
        assert_line(
            &probe_json(Some(u64::MAX), Some(true)),
            "{\"cap_net_raw\":true,\"cap_net_admin\":true,\"bpf_rw\":true,",
        );
        assert_line(
            &probe_json(Some(u64::MAX), Some(false)),
            "{\"cap_net_raw\":true,\"cap_net_admin\":true,\"bpf_rw\":false,",
        );
        assert_line(
            &probe_json(Some(u64::MAX), None),
            "{\"cap_net_raw\":true,\"cap_net_admin\":true,\"bpf_rw\":null,",
        );
    }

    #[test]
    fn tester_zero_and_absent_cap_eff_give_the_same_false_pair() {
        for cap_eff in [None, Some(0)] {
            assert_line(
                &probe_json(cap_eff, None),
                "{\"cap_net_raw\":false,\"cap_net_admin\":false,\"bpf_rw\":null,",
            );
            assert_line(
                &probe_json(cap_eff, Some(true)),
                "{\"cap_net_raw\":false,\"cap_net_admin\":false,\"bpf_rw\":true,",
            );
            assert_line(
                &probe_json(cap_eff, Some(false)),
                "{\"cap_net_raw\":false,\"cap_net_admin\":false,\"bpf_rw\":false,",
            );
        }
    }

    #[test]
    fn tester_neighbouring_bits_do_not_leak_into_the_two_flags() {
        // Bits 11 and 14, the neighbours of 12 and 13.
        assert_line(
            &probe_json(Some((1 << 11) | (1 << 14)), None),
            "{\"cap_net_raw\":false,\"cap_net_admin\":false,\"bpf_rw\":null,",
        );
        assert_line(
            &probe_json(Some(1 << 13), Some(false)),
            "{\"cap_net_raw\":true,\"cap_net_admin\":false,\"bpf_rw\":false,",
        );
        assert_line(
            &probe_json(Some(1 << 12), Some(true)),
            "{\"cap_net_raw\":false,\"cap_net_admin\":true,\"bpf_rw\":true,",
        );
        assert_line(
            &probe_json(Some(1 << 63), Some(true)),
            "{\"cap_net_raw\":false,\"cap_net_admin\":false,\"bpf_rw\":true,",
        );
    }

    #[test]
    fn tester_parse_cap_eff_edge_cases() {
        // CRLF line endings: trim removes the \r.
        assert_eq!(parse_cap_eff("CapEff:\t0000000000002000\r\n"), Some(0x2000));
        // Uppercase hex.
        assert_eq!(
            parse_cap_eff("CapEff:\t000001FFFFFFFFFF\n"),
            Some(0x0000_01ff_ffff_ffff)
        );
        // Sixteen f's is u64::MAX; seventeen digits overflow and are refused.
        assert_eq!(parse_cap_eff("CapEff:\tffffffffffffffff\n"), Some(u64::MAX));
        assert_eq!(parse_cap_eff("CapEff:\t10000000000000000\n"), None);
        // /proc never prints a 0x prefix, a sign or an empty value.
        assert_eq!(parse_cap_eff("CapEff:\t0x2000\n"), None);
        assert_eq!(parse_cap_eff("CapEff:\t-1\n"), None);
        assert_eq!(parse_cap_eff("CapEff:\t\n"), None);
        assert_eq!(parse_cap_eff("CapEff:"), None);
        // No tab after the colon is still the value.
        assert_eq!(parse_cap_eff("CapEff:2000\n"), Some(0x2000));
        // The first CapEff line wins over a second one.
        assert_eq!(
            parse_cap_eff("CapEff:\t0000000000002000\nCapEff:\t0000000000003000\n"),
            Some(0x2000)
        );
        // The key must start the line.
        assert_eq!(parse_cap_eff("Name:\tCapEff:\t2000\n"), None);
        assert_eq!(parse_cap_eff(" CapEff:\t2000\n"), None);
        // A lowercase key is not the key.
        assert_eq!(parse_cap_eff("capeff:\t2000\n"), None);
    }
}
