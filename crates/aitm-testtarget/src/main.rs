//! `aitm-testtarget-serve` — run the hermetic seeded-vulnerable target as a real,
//! standalone server on loopback, so an operator can point a browser + the
//! `aitm` proxy at it for the M4 live-agent acceptance (AC-M4-17), and so the
//! scanner e2e harness can boot one process with every listener (T10 spec D1).
//!
//! It is the same [`TestTarget`] the deterministic suites serve in-process, just
//! kept alive as a process. Flags: `--mode vulnerable|patched` (default
//! vulnerable), `--port N` (plain HTTP/1; default 0 = ephemeral), `--tls-port N`
//! (TLS, ALPN `h2`+`http/1.1`), `--tls-h1-port N` (TLS, ALPN `http/1.1` only),
//! `--control-port N` (the control origin), `--l4` (every L4 speaker on an
//! ephemeral port; needs `--control-port`). A listener whose flag is absent is
//! not started, so the legacy invocation starts nothing new.
//!
//! Stdout, in order, one line per started listener, then `ready`:
//! `listening http://127.0.0.1:P`, `tls https://127.0.0.1:P`,
//! `tls_h1 https://127.0.0.1:P`, `control http://127.0.0.1:P`, `ready`. L4
//! addresses are not printed; a harness reads `GET /services` on the control
//! origin. The grader-only planted-vuln manifest is never served (that is a
//! property of `TestTarget`).
//!
//! Stays alive serving until the process is terminated (Ctrl-C).

use std::io::Write;
use std::process::ExitCode;

use aitm_testtarget::{SeedMode, TestTarget};

const USAGE: &str = "usage: aitm-testtarget-serve [--mode vulnerable|patched] [--port <0-65535>] \
[--tls-port <0-65535>] [--tls-h1-port <0-65535>] [--control-port <0-65535>] [--l4]";

/// The parsed command line (spec D1 "Flags" row). `None` = listener not started.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Args {
    mode: SeedMode,
    port: u16,
    tls: Option<u16>,
    tls_h1: Option<u16>,
    control: Option<u16>,
    l4: bool,
}

#[tokio::main]
async fn main() -> ExitCode {
    let args = match parse_args() {
        Ok(args) => args,
        Err(msg) => {
            eprintln!("{msg}");
            eprintln!("{USAGE}");
            return ExitCode::FAILURE;
        }
    };

    let mut builder = TestTarget::builder(args.mode).port(args.port).l4(args.l4);
    if let Some(p) = args.tls {
        builder = builder.tls(p);
    }
    if let Some(p) = args.tls_h1 {
        builder = builder.tls_h1(p);
    }
    if let Some(p) = args.control {
        builder = builder.control(p);
    }
    let target = match builder.start().await {
        Ok(target) => target,
        Err(err) => {
            eprintln!("failed to start test target: {err}");
            return ExitCode::FAILURE;
        }
    };

    // One line per started listener, then `ready`, so an operator (or the
    // harness) can read the bound URLs back; each flushed since stdout is
    // block-buffered when piped and the harness reads line by line.
    emit(&format!("listening {}", target.base_url()));
    if let Some(url) = target.tls_url() {
        emit(&format!("tls {url}"));
    }
    if let Some(url) = target.tls_h1_url() {
        emit(&format!("tls_h1 {url}"));
    }
    if let Some(url) = target.control_url() {
        emit(&format!("control {url}"));
    }
    emit("ready");

    // Serve until terminated; the accept loops run in their own tasks behind `target`.
    std::future::pending::<()>().await;
    ExitCode::SUCCESS
}

/// Print one stdout line and flush it.
fn emit(line: &str) {
    println!("{line}");
    let _ = std::io::stdout().flush();
}

/// Parse the process arguments (see the module doc for the flags).
fn parse_args() -> Result<Args, String> {
    parse_from(std::env::args().skip(1))
}

/// Parse `args` (the arguments after the program name). `--l4` without
/// `--control-port` is rejected with `--l4 needs --control-port`.
fn parse_from<I: IntoIterator<Item = String>>(args: I) -> Result<Args, String> {
    let mut parsed = Args {
        mode: SeedMode::Vulnerable,
        port: 0,
        tls: None,
        tls_h1: None,
        control: None,
        l4: false,
    };
    let mut args = args.into_iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--mode" => {
                let value = args.next().ok_or("--mode needs a value")?;
                parsed.mode = match value.as_str() {
                    "vulnerable" => SeedMode::Vulnerable,
                    "patched" => SeedMode::Patched,
                    other => return Err(format!("unknown --mode {other:?}")),
                };
            }
            "--port" => parsed.port = port_value(&arg, args.next())?,
            "--tls-port" => parsed.tls = Some(port_value(&arg, args.next())?),
            "--tls-h1-port" => parsed.tls_h1 = Some(port_value(&arg, args.next())?),
            "--control-port" => parsed.control = Some(port_value(&arg, args.next())?),
            "--l4" => parsed.l4 = true,
            other => return Err(format!("unexpected argument {other:?}")),
        }
    }
    if parsed.l4 && parsed.control.is_none() {
        return Err("--l4 needs --control-port".to_string());
    }
    Ok(parsed)
}

/// The `<0-65535>` value of port flag `flag`.
fn port_value(flag: &str, value: Option<String>) -> Result<u16, String> {
    let value = value.ok_or_else(|| format!("{flag} needs a value"))?;
    value
        .parse()
        .map_err(|_| format!("invalid {flag} {value:?}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(args: &[&str]) -> impl Iterator<Item = String> {
        args.iter()
            .map(|s| s.to_string())
            .collect::<Vec<_>>()
            .into_iter()
    }

    #[test]
    fn parse_args_full() {
        let args = parse_from(argv(&[
            "--mode",
            "patched",
            "--tls-port",
            "0",
            "--tls-h1-port",
            "0",
            "--control-port",
            "0",
            "--l4",
        ]))
        .expect("full flag set parses");
        assert_eq!(
            args,
            Args {
                mode: SeedMode::Patched,
                port: 0,
                tls: Some(0),
                tls_h1: Some(0),
                control: Some(0),
                l4: true,
            }
        );
    }

    #[test]
    fn parse_args_legacy() {
        let args = parse_from(argv(&["--mode", "vulnerable", "--port", "0"]))
            .expect("legacy flag set parses");
        assert_eq!(args.mode, SeedMode::Vulnerable);
        assert_eq!(args.port, 0);
        assert_eq!(args.tls, None);
        assert_eq!(args.tls_h1, None);
        assert_eq!(args.control, None);
        assert!(!args.l4);
    }

    #[test]
    fn l4_needs_control() {
        let err = parse_from(argv(&["--l4"])).expect_err("--l4 alone is rejected");
        assert!(
            err.contains("--l4 needs --control-port"),
            "error must name the missing flag, got {err:?}"
        );
    }

    // --- Tester additions (stage 5): bad values, order, defaults ---

    #[test]
    fn parse_args_rejects_bad_values_and_accepts_any_order() {
        let err = parse_from(argv(&["--mode", "bogus"])).expect_err("bad mode");
        assert!(err.contains("unknown --mode"), "{err}");
        let err = parse_from(argv(&["--mode"])).expect_err("mode without value");
        assert_eq!(err, "--mode needs a value");
        let err = parse_from(argv(&["--port", "abc"])).expect_err("bad port");
        assert_eq!(err, "invalid --port \"abc\"");
        let err = parse_from(argv(&["--tls-port", "70000"])).expect_err("port out of range");
        assert_eq!(err, "invalid --tls-port \"70000\"");
        let err = parse_from(argv(&["--tls-h1-port", "-1"])).expect_err("negative port");
        assert_eq!(err, "invalid --tls-h1-port \"-1\"");
        let err = parse_from(argv(&["--control-port"])).expect_err("flag without value");
        assert_eq!(err, "--control-port needs a value");
        let err = parse_from(argv(&["--bogus"])).expect_err("unknown flag");
        assert_eq!(err, "unexpected argument \"--bogus\"");
        let err = parse_from(argv(&["8080"])).expect_err("bare positional");
        assert_eq!(err, "unexpected argument \"8080\"");
        // The l4/control rule holds whatever the flag order.
        let ok = parse_from(argv(&["--l4", "--control-port", "0"])).expect("l4 before control");
        assert!(ok.l4);
        assert_eq!(ok.control, Some(0));
        let err = parse_from(argv(&["--l4", "--port", "0"])).expect_err("l4 without control");
        assert_eq!(err, "--l4 needs --control-port");
        // No arguments: the legacy defaults.
        assert_eq!(
            parse_from(argv(&[])).expect("defaults"),
            Args {
                mode: SeedMode::Vulnerable,
                port: 0,
                tls: None,
                tls_h1: None,
                control: None,
                l4: false,
            }
        );
        // The last repeated flag wins.
        assert_eq!(
            parse_from(argv(&["--port", "1", "--port", "2"]))
                .expect("repeat")
                .port,
            2
        );
    }
}
