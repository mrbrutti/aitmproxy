//! `aitm-tui` — run the terminal operator UI against a proxy's bus.
//!
//! ```text
//! aitm-tui --bus 127.0.0.1:9090 --token-file ~/.aitm/bus.token [--poc-dir dir]
//! ```
//! `--poc-dir` is where a built PoC (`P`) is written — `poc.build` answers
//! with the YAML text; it should be the proxy's `poc.dir` so `poc.run` can
//! read it back. `--ansi` forces the 16-colour palette, `--truecolor` the hex palette.
//! `--token t` is accepted but visible to every process on the machine
//! (`ps`); prefer `--token-file` or `AITM_BUS_TOKEN`. A bus that is not on
//! loopback is refused unless `--allow-remote-bus` is given: the token
//! travels in cleartext until the TLS bus (core follow-up F15).

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use aitm_tui::caps::TermCaps;
use aitm_tui::{RunOptions, TransportChoice};

const USAGE: &str = "usage: aitm-tui --bus host:port (--token-file p | --token t (insecure: visible in ps)) [--allow-remote-bus] [--expect-role agent|operator] [--poc-dir dir] [--ansi|--truecolor] [--poll ms]\n       --poc-dir: where P (poc.build) writes the PoC YAML; use the proxy's poc.dir so poc.run can read it\n       --expect-role: the role you expect the token to resolve to; the status line warns if it does not (it is never sent to the server)";

/// Why a non-loopback bus is refused without the flag.
const REMOTE_BUS_REFUSED: &str = "refusing a bus that is not on loopback: the token would travel in cleartext (the TLS bus is core follow-up F15). Pass --allow-remote-bus to do it anyway.";

struct Args {
    bus: Option<String>,
    token: Option<String>,
    token_file: Option<PathBuf>,
    caps: Option<TermCaps>,
    poll_ms: u64,
    allow_remote_bus: bool,
    /// `--poc-dir`: where a built PoC's YAML is written.
    poc_dir: Option<PathBuf>,
    /// `--expect-role`: the role the operator expects the token to resolve to
    /// (`agent`/`operator`); client-side only, drives the mismatch warning.
    expect_role: Option<String>,
}

/// S5: a bus address off loopback needs an explicit opt-in.
fn check_bus_address(addr: SocketAddr, allow_remote: bool) -> Result<(), String> {
    if addr.ip().is_loopback() || allow_remote {
        Ok(())
    } else {
        Err(format!("--bus {addr}: {REMOTE_BUS_REFUSED}"))
    }
}

fn parse(argv: &[String]) -> Result<Args, String> {
    let mut a = Args {
        bus: None,
        token: None,
        token_file: None,
        caps: None,
        poll_ms: 500,
        allow_remote_bus: false,
        poc_dir: None,
        expect_role: None,
    };
    let mut i = 0;
    let value = |i: &mut usize, flag: &str| -> Result<String, String> {
        *i += 1;
        argv.get(*i)
            .cloned()
            .ok_or_else(|| format!("{flag} needs a value"))
    };
    while i < argv.len() {
        match argv[i].as_str() {
            "--bus" => a.bus = Some(value(&mut i, "--bus")?),
            "--token" => a.token = Some(value(&mut i, "--token")?),
            "--token-file" => a.token_file = Some(PathBuf::from(value(&mut i, "--token-file")?)),
            "--allow-remote-bus" => a.allow_remote_bus = true,
            "--poc-dir" => a.poc_dir = Some(PathBuf::from(value(&mut i, "--poc-dir")?)),
            "--expect-role" => {
                let v = value(&mut i, "--expect-role")?;
                if v != "agent" && v != "operator" {
                    return Err(format!(
                        "--expect-role must be `agent` or `operator`, not `{v}`"
                    ));
                }
                a.expect_role = Some(v);
            }
            "--poll" => {
                a.poll_ms = value(&mut i, "--poll")?
                    .parse()
                    .map_err(|e| format!("--poll: {e}"))?
            }
            "--ansi" => a.caps = Some(TermCaps::ansi16()),
            "--truecolor" => a.caps = Some(TermCaps::full()),
            "-h" | "--help" => return Err(USAGE.to_string()),
            other => return Err(format!("unknown argument `{other}`\n{USAGE}")),
        }
        i += 1;
    }
    Ok(a)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let args = match parse(&argv) {
        Ok(a) => a,
        Err(msg) => {
            eprintln!("{msg}");
            std::process::exit(2);
        }
    };

    let transport = match args.bus {
        Some(bus) => {
            let addr: SocketAddr = bus.parse()?;
            check_bus_address(addr, args.allow_remote_bus).map_err(anyhow::Error::msg)?;
            let token = match (args.token, args.token_file) {
                (Some(t), _) => t,
                (None, Some(p)) => aitm_bus_client::read_token_file(&p)?,
                (None, None) => match std::env::var("AITM_BUS_TOKEN") {
                    Ok(t) if !t.is_empty() => t,
                    _ => anyhow::bail!("--bus needs --token-file or --token (or AITM_BUS_TOKEN)"),
                },
            };
            TransportChoice::Tcp { addr, token }
        }
        None => match std::env::var("AITM_BUS") {
            Ok(bus) if !bus.is_empty() => {
                let token = std::env::var("AITM_BUS_TOKEN").unwrap_or_default();
                if token.is_empty() {
                    anyhow::bail!("AITM_BUS is set but AITM_BUS_TOKEN is empty");
                }
                let addr: SocketAddr = bus.parse()?;
                check_bus_address(addr, args.allow_remote_bus).map_err(anyhow::Error::msg)?;
                TransportChoice::Tcp { addr, token }
            }
            _ => {
                eprintln!("{USAGE}");
                std::process::exit(2);
            }
        },
    };

    aitm_tui::run(RunOptions {
        transport,
        caps: args.caps,
        poll: Duration::from_millis(args.poll_ms.max(100)),
        startup_note: None,
        listening: None,
        poc_dir: args.poc_dir,
        expect_role: args.expect_role,
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(s: &str) -> Vec<String> {
        s.split_whitespace().map(str::to_string).collect()
    }

    /// S4: the inline token is allowed but labelled for what it is.
    #[test]
    fn usage_marks_the_inline_token_insecure() {
        assert!(
            USAGE.contains("--token t (insecure: visible in ps)"),
            "{USAGE}"
        );
        assert!(USAGE.contains("--allow-remote-bus"), "{USAGE}");
        assert!(
            !USAGE.contains("--fixture") && !USAGE.contains("--snapshot"),
            "{USAGE}"
        );
        let a = parse(&argv("--bus 127.0.0.1:9090 --token abc")).unwrap();
        assert_eq!(a.token.as_deref(), Some("abc"));
        assert!(!a.allow_remote_bus);
    }

    /// S5: a bus off loopback is refused unless `--allow-remote-bus`, and the
    /// refusal names the TLS follow-up.
    #[test]
    fn non_loopback_bus_needs_the_explicit_flag() {
        let local: SocketAddr = "127.0.0.1:9090".parse().unwrap();
        let local6: SocketAddr = "[::1]:9090".parse().unwrap();
        let remote: SocketAddr = "10.0.0.5:9090".parse().unwrap();
        assert_eq!(check_bus_address(local, false), Ok(()));
        assert_eq!(check_bus_address(local6, false), Ok(()));
        let err = check_bus_address(remote, false).unwrap_err();
        assert!(
            err.starts_with("--bus 10.0.0.5:9090: refusing a bus that is not on loopback"),
            "{err}"
        );
        assert!(err.contains("F15"), "{err}");
        assert!(err.contains("--allow-remote-bus"), "{err}");
        assert_eq!(check_bus_address(remote, true), Ok(()));
        let a = parse(&argv(
            "--bus 10.0.0.5:9090 --token-file t --allow-remote-bus",
        ))
        .unwrap();
        assert!(a.allow_remote_bus);
    }

    /// C12: `--poc-dir` names where `P` writes the built PoC; it needs a value
    /// and USAGE explains it.
    #[test]
    fn poc_dir_flag_takes_a_path_and_is_documented() {
        let a = parse(&argv(
            "--bus 127.0.0.1:9090 --token-file t --poc-dir /tmp/pocs",
        ))
        .unwrap();
        assert_eq!(
            a.poc_dir.as_deref(),
            Some(std::path::Path::new("/tmp/pocs"))
        );
        assert_eq!(
            parse(&argv("--bus 127.0.0.1:9090 --token t"))
                .unwrap()
                .poc_dir,
            None
        );
        assert_eq!(
            parse(&argv("--bus 127.0.0.1:9090 --token t --poc-dir"))
                .err()
                .as_deref(),
            Some("--poc-dir needs a value")
        );
        assert!(USAGE.contains("[--poc-dir dir]"), "{USAGE}");
        assert!(USAGE.contains("poc.build"), "{USAGE}");
    }

    /// Decision B: `--expect-role` is a client-side expectation, accepting
    /// only the two role words and documented in USAGE; any other value is a
    /// usage error rather than a silently ignored flag.
    #[test]
    fn expect_role_accepts_the_two_roles_and_rejects_anything_else() {
        let a = parse(&argv(
            "--bus 127.0.0.1:9090 --token t --expect-role operator",
        ))
        .unwrap();
        assert_eq!(a.expect_role.as_deref(), Some("operator"));
        let a = parse(&argv("--bus 127.0.0.1:9090 --token t --expect-role agent")).unwrap();
        assert_eq!(a.expect_role.as_deref(), Some("agent"));
        assert_eq!(
            parse(&argv("--bus 127.0.0.1:9090 --token t"))
                .unwrap()
                .expect_role,
            None
        );
        let err = parse(&argv("--bus 127.0.0.1:9090 --token t --expect-role admin"))
            .err()
            .unwrap();
        assert!(err.contains("expect-role"), "{err}");
        assert_eq!(
            parse(&argv("--bus 127.0.0.1:9090 --token t --expect-role"))
                .err()
                .as_deref(),
            Some("--expect-role needs a value")
        );
        assert!(USAGE.contains("--expect-role"), "{USAGE}");
    }

    /// The recorded fixture and the snapshot renderer were removed on
    /// 2026-10-31 (spec 2026-10-31-remove-fake-data-ui-modes): their flags
    /// are unknown arguments, refused with the usage, like any other typo.
    #[test]
    fn fixture_and_snapshot_flags_are_unknown_arguments() {
        for (argv_text, flag) in [
            ("--fixture", "--fixture"),
            ("--snapshot out.svg", "--snapshot"),
            ("--snapshot-core out.svg", "--snapshot-core"),
            ("--cols 100", "--cols"),
        ] {
            let err = parse(&argv(argv_text))
                .err()
                .unwrap_or_else(|| panic!("{argv_text} parsed; it must be refused"));
            assert!(
                err.starts_with(&format!("unknown argument `{flag}`")),
                "{argv_text}: {err}"
            );
            assert!(err.contains("usage: aitm-tui"), "{argv_text}: {err}");
        }
    }
}
