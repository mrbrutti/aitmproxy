//! `aitm-tui` — run the terminal operator UI against a proxy's bus, the
//! recorded fixture, or render a snapshot of the main screen to a file.
//!
//! ```text
//! aitm-tui --bus 127.0.0.1:9090 --token-file ~/.aitm/bus.token
//! aitm-tui --fixture [path.json]
//! aitm-tui --snapshot out.svg [--cols 200 --rows 50] [--fixture path]
//! ```
//! `--ansi` forces the 16-colour palette, `--truecolor` the hex palette.

use std::path::PathBuf;
use std::time::Duration;

use aitm_tui::caps::TermCaps;
use aitm_tui::theme::Theme;
use aitm_tui::{fixture_app, snapshot, RunOptions, TransportChoice};

const USAGE: &str = "usage: aitm-tui (--bus host:port (--token-file p | --token t) | --fixture [path]) [--ansi|--truecolor] [--poll ms]\n       aitm-tui --snapshot out.svg [--cols N --rows N]";

struct Args {
    bus: Option<String>,
    token: Option<String>,
    token_file: Option<PathBuf>,
    fixture: Option<Option<PathBuf>>,
    snapshot: Option<PathBuf>,
    cols: u16,
    rows: u16,
    caps: Option<TermCaps>,
    poll_ms: u64,
}

fn parse(argv: &[String]) -> Result<Args, String> {
    let mut a = Args {
        bus: None,
        token: None,
        token_file: None,
        fixture: None,
        snapshot: None,
        cols: 200,
        rows: 50,
        caps: None,
        poll_ms: 500,
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
        let app = fixture_app(args.cols, args.rows);
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
            let addr = bus.parse()?;
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
                TransportChoice::Tcp {
                    addr: bus.parse()?,
                    token,
                }
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
    })
    .await
}
