//! The one-shot's own flags (spec D7): `--bus <host:port>` and
//! `--token-file <path>`, with the environment twins `AITM_BUS` and
//! `AITM_BUS_TOKEN` read by `resolve`. They are recognised anywhere a
//! subcommand is not, exactly as `--config` and `--bus-endpoint-file` are in
//! `main`, and split out of argv before the verb's own flags are parsed.
//!
//! The usage errors here are W1 [`ErrorReport`]s of kind
//! [`ErrorKind::Usage`](aitm_term::error::ErrorKind::Usage) (exit 2, fix
//! command `aitm --help`); the refusals a resolved core draws live in
//! [`super::refuse`].

use std::net::SocketAddr;
use std::path::PathBuf;

use aitm_term::error::ErrorReport;

/// `--bus` as typed.
const BUS: &str = "--bus";
/// `--token-file` as typed.
const TOKEN_FILE: &str = "--token-file";

/// The one-shot flags split out of argv. Both are `None` when the operator
/// gave neither; `bus` is kept as text so a bad value is reported as a usage
/// error by [`parse_bus`] only once a live verb needs it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BusArgs {
    /// `--bus <host:port>`, untouched.
    pub bus: Option<String>,
    /// `--token-file <path>`.
    pub token_file: Option<PathBuf>,
}

/// Split `--bus v`, `--bus=v`, `--token-file p` and `--token-file=p` out of
/// `argv`, wherever they appear, returning them and the remaining arguments
/// in their original order.
///
/// Errors, as the operator reads them: `--bus requires a host:port`,
/// `--token-file requires a path` (a missing or empty value), `--bus may be
/// given at most once`, `--token-file may be given at most once`.
pub fn split_bus_args(argv: Vec<String>) -> Result<(BusArgs, Vec<String>), String> {
    let mut found = BusArgs::default();
    let mut rest = Vec::with_capacity(argv.len());
    let mut args = argv.into_iter();
    while let Some(arg) = args.next() {
        if let Some(value) = take_value(&arg, BUS, &mut args) {
            let value = value.ok_or_else(|| format!("{BUS} requires a host:port"))?;
            if found.bus.is_some() {
                return Err(format!("{BUS} may be given at most once"));
            }
            found.bus = Some(value);
        } else if let Some(value) = take_value(&arg, TOKEN_FILE, &mut args) {
            let value = value.ok_or_else(|| format!("{TOKEN_FILE} requires a path"))?;
            if found.token_file.is_some() {
                return Err(format!("{TOKEN_FILE} may be given at most once"));
            }
            found.token_file = Some(PathBuf::from(value));
        } else {
            rest.push(arg);
        }
    }
    Ok((found, rest))
}

/// `Some(Some(value))` when `arg` is `flag` (the value is the next token) or
/// `flag=value`; `Some(None)` when it is the flag with no, or an empty,
/// value; `None` when `arg` is not this flag at all.
fn take_value(
    arg: &str,
    flag: &str,
    args: &mut impl Iterator<Item = String>,
) -> Option<Option<String>> {
    if arg == flag {
        return Some(args.next().filter(|v| !v.is_empty()));
    }
    let value = arg.strip_prefix(flag)?.strip_prefix('=')?;
    Some(Some(value.to_string()).filter(|v| !v.is_empty()))
}

/// Parse a `--bus` value as a socket address. The error is the usage text
/// `--bus <text>: <parse error>`.
pub fn parse_bus(text: &str) -> Result<SocketAddr, String> {
    text.parse::<SocketAddr>()
        .map_err(|e| format!("{BUS} {text}: {e}"))
}

/// The operator bus is loopback-only (spec D10): any other address is the
/// usage error `--bus <addr> is not a loopback address`.
#[expect(
    clippy::result_large_err,
    reason = "the plan pins the ErrorReport return"
)]
pub fn check_loopback(addr: SocketAddr) -> Result<(), ErrorReport> {
    if addr.ip().is_loopback() {
        Ok(())
    } else {
        Err(
            ErrorReport::usage(format!("{BUS} {addr} is not a loopback address")).with_why(vec![
                "The operator bus is loopback-only; a core elsewhere needs a local tunnel."
                    .to_string(),
            ]),
        )
    }
}

/// `--bus` (or `AITM_BUS`) was given without a token.
pub fn needs_token() -> ErrorReport {
    ErrorReport::usage(format!("{BUS} needs {TOKEN_FILE} <path> or AITM_BUS_TOKEN"))
}

/// `--token-file` was given without an address.
pub fn token_file_needs_bus() -> ErrorReport {
    ErrorReport::usage(format!("{TOKEN_FILE} needs {BUS} <host:port> or AITM_BUS"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use aitm_term::error::{ErrorKind, FixCommand};
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
    use std::path::PathBuf;

    fn args(tokens: &[&str]) -> Vec<String> {
        tokens.iter().map(|t| t.to_string()).collect()
    }

    #[test]
    fn split_bus_args_takes_both_forms_anywhere() {
        let (bus, rest) = split_bus_args(args(&[
            "scope",
            "add",
            "--host",
            "x",
            "--bus",
            "127.0.0.1:1",
            "--token-file=t",
        ]))
        .unwrap();
        assert_eq!(
            bus,
            BusArgs {
                bus: Some("127.0.0.1:1".to_string()),
                token_file: Some(PathBuf::from("t")),
            }
        );
        assert_eq!(rest, args(&["scope", "add", "--host", "x"]));

        // The other two spellings, before the subcommand.
        let (bus, rest) = split_bus_args(args(&[
            "--bus=127.0.0.1:2",
            "--token-file",
            "/t/tok",
            "scope",
            "list",
        ]))
        .unwrap();
        assert_eq!(bus.bus.as_deref(), Some("127.0.0.1:2"));
        assert_eq!(bus.token_file, Some(PathBuf::from("/t/tok")));
        assert_eq!(rest, args(&["scope", "list"]));

        // No flag: argv is handed back whole and `BusArgs` is its default.
        let (bus, rest) = split_bus_args(args(&["ca", "status"])).unwrap();
        assert_eq!(bus, BusArgs::default());
        assert_eq!(rest, args(&["ca", "status"]));

        assert_eq!(
            split_bus_args(args(&["--bus"])),
            Err("--bus requires a host:port".to_string())
        );
        assert_eq!(
            split_bus_args(args(&["--bus="])),
            Err("--bus requires a host:port".to_string())
        );
        assert_eq!(
            split_bus_args(args(&["--bus", "127.0.0.1:1", "--bus=127.0.0.1:2"])),
            Err("--bus may be given at most once".to_string())
        );
        assert_eq!(
            split_bus_args(args(&["scope", "list", "--token-file"])),
            Err("--token-file requires a path".to_string())
        );
        assert_eq!(
            split_bus_args(args(&["--token-file="])),
            Err("--token-file requires a path".to_string())
        );
        assert_eq!(
            split_bus_args(args(&["--token-file", "a", "--token-file", "b"])),
            Err("--token-file may be given at most once".to_string())
        );
    }

    #[test]
    fn parse_bus_prefixes_the_flag_and_keeps_the_parse_error() {
        assert_eq!(
            parse_bus("127.0.0.1:1"),
            Ok(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1))
        );
        assert_eq!(
            parse_bus("[::1]:50512"),
            Ok(SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 50512))
        );
        assert_eq!(
            parse_bus("nonsense"),
            Err("--bus nonsense: invalid socket address syntax".to_string())
        );
        assert_eq!(
            parse_bus("127.0.0.1"),
            Err("--bus 127.0.0.1: invalid socket address syntax".to_string())
        );
    }

    #[test]
    fn check_loopback_is_a_usage_error_off_loopback() {
        let off = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)), 9090);
        let report = check_loopback(off).unwrap_err();
        assert_eq!(report.kind, ErrorKind::Usage);
        assert_eq!(report.exit_code(), 2);
        assert_eq!(report.what, "--bus 10.0.0.5:9090 is not a loopback address");
        assert_eq!(
            report.why,
            vec![
                "The operator bus is loopback-only; a core elsewhere needs a local tunnel."
                    .to_string()
            ]
        );
        assert_eq!(report.fix, None);
        assert_eq!(report.command, Some(FixCommand("aitm --help".to_string())));
        assert_eq!(report.log, None);

        assert_eq!(
            check_loopback(SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 1)),
            Ok(())
        );
        assert_eq!(
            check_loopback(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1)),
            Ok(())
        );
        // Any 127/8 address is loopback.
        assert_eq!(
            check_loopback(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), 1)),
            Ok(())
        );
    }

    #[test]
    fn needs_token_and_token_file_needs_bus_are_usage_errors() {
        let report = needs_token();
        assert_eq!(report.kind, ErrorKind::Usage);
        assert_eq!(
            report.what,
            "--bus needs --token-file <path> or AITM_BUS_TOKEN"
        );
        assert_eq!(report.why, Vec::<String>::new());
        assert_eq!(report.fix, None);
        assert_eq!(report.command, Some(FixCommand("aitm --help".to_string())));

        let report = token_file_needs_bus();
        assert_eq!(report.kind, ErrorKind::Usage);
        assert_eq!(
            report.what,
            "--token-file needs --bus <host:port> or AITM_BUS"
        );
        assert_eq!(report.why, Vec::<String>::new());
        assert_eq!(report.fix, None);
        assert_eq!(report.command, Some(FixCommand("aitm --help".to_string())));
    }
}
