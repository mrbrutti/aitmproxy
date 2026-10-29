//! `aitm-testtarget-serve` — run the hermetic seeded-vulnerable target as a real,
//! standalone HTTP server on loopback, so an operator can point a browser + the
//! `aitm` proxy at it for the M4 live-agent acceptance (AC-M4-17).
//!
//! It is the same [`TestTarget`] the deterministic suites serve in-process, just
//! kept alive as a process: `--mode vulnerable|patched` (default vulnerable) picks
//! the seed, `--port` (default 0 = ephemeral) the loopback port. The bound base URL
//! is printed on stdout as `listening http://127.0.0.1:<port>`. The grader-only
//! planted-vuln manifest is never served (that is a property of `TestTarget`).
//!
//! Stays alive serving until the process is terminated (Ctrl-C).

use std::io::Write;
use std::process::ExitCode;

use aitm_testtarget::{SeedMode, TestTarget};

#[tokio::main]
async fn main() -> ExitCode {
    let (mode, port) = match parse_args() {
        Ok(args) => args,
        Err(msg) => {
            eprintln!("{msg}");
            eprintln!(
                "usage: aitm-testtarget-serve [--mode vulnerable|patched] [--port <0-65535>]"
            );
            return ExitCode::FAILURE;
        }
    };

    let target = match TestTarget::start_on(mode, port).await {
        Ok(target) => target,
        Err(err) => {
            eprintln!("failed to bind 127.0.0.1:{port}: {err}");
            return ExitCode::FAILURE;
        }
    };

    // One line on stdout so an operator (or the acceptance harness) can read the
    // bound URL back, flushed since stdout is block-buffered when piped.
    println!("listening {}", target.base_url());
    let _ = std::io::stdout().flush();

    // Serve until terminated; the accept loop runs in its own task behind `target`.
    std::future::pending::<()>().await;
    ExitCode::SUCCESS
}

/// Parse `--mode` and `--port` from the process arguments.
fn parse_args() -> Result<(SeedMode, u16), String> {
    let mut mode = SeedMode::Vulnerable;
    let mut port: u16 = 0;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--mode" => {
                let value = args.next().ok_or("--mode needs a value")?;
                mode = match value.as_str() {
                    "vulnerable" => SeedMode::Vulnerable,
                    "patched" => SeedMode::Patched,
                    other => return Err(format!("unknown --mode {other:?}")),
                };
            }
            "--port" => {
                let value = args.next().ok_or("--port needs a value")?;
                port = value
                    .parse()
                    .map_err(|_| format!("invalid --port {value:?}"))?;
            }
            other => return Err(format!("unexpected argument {other:?}")),
        }
    }
    Ok((mode, port))
}
