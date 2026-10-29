//! `aitm-tui` — run the terminal operator UI against a proxy's bus, the
//! recorded fixture, or render a snapshot of the main screen to a file.
//!
//! ```text
//! aitm-tui --bus 127.0.0.1:9090 --token-file ~/.aitm/bus.token [--poc-dir dir]
//! aitm-tui --fixture [path.json]
//! aitm-tui --snapshot out.svg [--cols 200 --rows 50] [--fixture path]
//! aitm-tui --snapshot-core out.svg      (the 56 core tools only)
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
use aitm_tui::theme::Theme;
use aitm_tui::{fixture_app, fixture_app_core, snapshot, RunOptions, TransportChoice};

const USAGE: &str = "usage: aitm-tui (--bus host:port (--token-file p | --token t (insecure: visible in ps)) [--allow-remote-bus] | --fixture [path]) [--poc-dir dir] [--ansi|--truecolor] [--poll ms]\n       aitm-tui --snapshot out.svg [--cols N --rows N]\n       aitm-tui --snapshot-core out.svg [--cols N --rows N]   (fixture limited to the 56 core tools)\n       --poc-dir: where P (poc.build) writes the PoC YAML; use the proxy's poc.dir so poc.run can read it";

/// Why a non-loopback bus is refused without the flag.
const REMOTE_BUS_REFUSED: &str = "refusing a bus that is not on loopback: the token would travel in cleartext (the TLS bus is core follow-up F15). Pass --allow-remote-bus to do it anyway.";

struct Args {
    bus: Option<String>,
    token: Option<String>,
    token_file: Option<PathBuf>,
    fixture: Option<Option<PathBuf>>,
    snapshot: Option<PathBuf>,
    /// `--snapshot-core`: the fixture with only the 56 core tools.
    snapshot_core: bool,
    cols: u16,
    rows: u16,
    caps: Option<TermCaps>,
    poll_ms: u64,
    allow_remote_bus: bool,
    /// `--poc-dir`: where a built PoC's YAML is written.
    poc_dir: Option<PathBuf>,
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
        fixture: None,
        snapshot: None,
        snapshot_core: false,
        cols: 200,
        rows: 50,
        caps: None,
        poll_ms: 500,
        allow_remote_bus: false,
        poc_dir: None,
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
            "--fixture" => {
                let next = argv.get(i + 1).filter(|n| !n.starts_with("--")).cloned();
                if next.is_some() {
                    i += 1;
                }
                a.fixture = Some(next.map(PathBuf::from));
            }
            "--snapshot" => a.snapshot = Some(PathBuf::from(value(&mut i, "--snapshot")?)),
            "--snapshot-core" => {
                a.snapshot = Some(PathBuf::from(value(&mut i, "--snapshot-core")?));
                a.snapshot_core = true;
            }
            "--allow-remote-bus" => a.allow_remote_bus = true,
            "--poc-dir" => a.poc_dir = Some(PathBuf::from(value(&mut i, "--poc-dir")?)),
            "--cols" => {
                a.cols = value(&mut i, "--cols")?
                    .parse()
                    .map_err(|e| format!("--cols: {e}"))?
            }
            "--rows" => {
                a.rows = value(&mut i, "--rows")?
                    .parse()
                    .map_err(|e| format!("--rows: {e}"))?
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

    if let Some(out) = args.snapshot {
        let app = if args.snapshot_core {
            fixture_app_core(args.cols, args.rows)
        } else {
            fixture_app(args.cols, args.rows)
        };
        let theme = Theme::new(true);
        let buf = snapshot::render(&app, &theme, args.cols, args.rows);
        let body = match out.extension().and_then(|e| e.to_str()) {
            Some("svg") => snapshot::to_svg(&buf),
            Some("ans") | Some("ansi") => snapshot::to_ansi(&buf),
            _ => snapshot::to_text(&buf),
        };
        std::fs::write(&out, body)?;
        println!("wrote {}", out.display());
        return Ok(());
    }

    let transport = match (args.fixture, args.bus) {
        (Some(path), _) => TransportChoice::Fixture(path),
        (None, Some(bus)) => {
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
        (None, None) => match std::env::var("AITM_BUS") {
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
        assert!(USAGE.contains("--snapshot-core"), "{USAGE}");
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
        assert_eq!(parse(&argv("--fixture")).unwrap().poc_dir, None);
        assert_eq!(
            parse(&argv("--fixture --poc-dir")).err().as_deref(),
            Some("--poc-dir needs a value")
        );
        assert!(USAGE.contains("[--poc-dir dir]"), "{USAGE}");
        assert!(USAGE.contains("poc.build"), "{USAGE}");
        assert!(USAGE.contains("56 core tools"), "{USAGE}");
    }

    #[test]
    fn snapshot_core_is_a_snapshot_with_the_core_fixture() {
        let a = parse(&argv("--snapshot-core out.svg --cols 100 --rows 30")).unwrap();
        assert_eq!(a.snapshot.as_deref(), Some(std::path::Path::new("out.svg")));
        assert!(a.snapshot_core);
        assert_eq!((a.cols, a.rows), (100, 30));
        let a = parse(&argv("--snapshot out.svg")).unwrap();
        assert!(!a.snapshot_core);
        assert!(parse(&argv("--snapshot-core")).is_err());
    }
}
