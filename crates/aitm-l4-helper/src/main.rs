//! `aitm-l4-helper`: the packet-capture privilege helper for aitmproxy
//! (spec `docs/superpowers/specs/2026-10-31-l4-capture-privilege-design.md`).
//!
//! One binary, five subcommands (spec §1): `bpf-permissions` and `bpf-revert`
//! (macOS), `serve` (Linux), `probe` and `version`. This file only parses the
//! command line and dispatches; `probe` lives in `probe.rs`, the other modes
//! arrive in later tasks.
#![forbid(unsafe_code)]

mod cli;
mod probe;

use std::process::ExitCode;

/// Exit status for a rejected command line (the conventional usage code).
const EXIT_USAGE: u8 = 2;
/// Exit status for a mode this build does not implement yet.
const EXIT_NOT_IMPLEMENTED: u8 = 70;
/// Exit status when `probe` could not gather its inputs.
const EXIT_PROBE_FAILED: u8 = 1;

fn main() -> ExitCode {
    let args: Vec<std::ffi::OsString> = std::env::args_os().skip(1).collect();
    let mode = match cli::parse(&args) {
        Ok(mode) => mode,
        Err(err) => {
            eprintln!("aitm-l4-helper: {err}");
            return ExitCode::from(EXIT_USAGE);
        }
    };
    match mode {
        cli::Mode::Version => {
            println!("aitm-l4-helper {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        cli::Mode::Probe => match probe::run() {
            Ok(line) => {
                println!("{line}");
                ExitCode::SUCCESS
            }
            Err(err) => {
                eprintln!("aitm-l4-helper: probe: {err}");
                ExitCode::from(EXIT_PROBE_FAILED)
            }
        },
        cli::Mode::BpfPermissions { .. }
        | cli::Mode::BpfRevert { .. }
        | cli::Mode::Serve { .. } => {
            eprintln!("aitm-l4-helper: this mode is not implemented in this task");
            ExitCode::from(EXIT_NOT_IMPLEMENTED)
        }
    }
}
