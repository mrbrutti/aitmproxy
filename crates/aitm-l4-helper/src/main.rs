//! `aitm-l4-helper`: the packet-capture privilege helper for aitmproxy
//! (spec `docs/superpowers/specs/2026-10-31-l4-capture-privilege-design.md`).
//!
//! One binary, five subcommands (spec §1): `bpf-permissions` and `bpf-revert`
//! (macOS), `serve` (Linux), `probe` and `version`. This file only parses the
//! command line and dispatches; `probe` lives in `probe.rs`, the bpf modes in
//! `bpf.rs` / `bpf_exec.rs` / `log.rs`, and `serve` arrives in a later task.
#![forbid(unsafe_code)]

// The bpf modes run only on macOS; elsewhere `main` refuses them before
// reaching these modules, so their items are unused there.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
mod bpf;
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
mod bpf_exec;
mod cli;
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
mod log;
mod probe;
// `serve` runs only on Linux; the pure checks it exports are unused elsewhere.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
mod serve;

use std::process::ExitCode;

/// Exit status for a rejected command line (the conventional usage code).
const EXIT_USAGE: u8 = 2;
/// Exit status for a mode this build does not implement yet (the `serve`
/// loop, task P2.7).
#[cfg(target_os = "linux")]
const EXIT_NOT_IMPLEMENTED: u8 = 70;
/// Exit status when `probe` could not gather its inputs.
const EXIT_PROBE_FAILED: u8 = 1;
/// Exit status when `bpf-permissions` or `bpf-revert` (or their `--dry-run`)
/// did not complete.
const EXIT_BPF_FAILED: u8 = 1;
/// Exit status for a mode on a platform that cannot run it: a bpf mode where
/// there is no `/dev/bpf*`, `serve` off Linux (`EX_UNAVAILABLE`).
const EXIT_WRONG_PLATFORM: u8 = 69;
/// Exit status when `serve` start-up (spec §5.1 steps 1–6) failed.
#[cfg(target_os = "linux")]
const EXIT_SERVE_FAILED: u8 = 1;

/// Which of the two macOS permission modes was asked for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BpfMode {
    Permissions,
    Revert,
}

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
        cli::Mode::BpfPermissions { dry_run } => run_bpf(BpfMode::Permissions, dry_run),
        cli::Mode::BpfRevert { dry_run } => run_bpf(BpfMode::Revert, dry_run),
        cli::Mode::Serve { connect } => run_serve(&connect),
    }
}

/// `serve` on Linux (spec §5.1): start-up first, which exits non-zero before
/// any other I/O on failure. The serve loop itself arrives in task P2.7; until
/// then a successful start-up reports that and exits non-zero.
#[cfg(target_os = "linux")]
fn run_serve(connect: &std::path::Path) -> ExitCode {
    let pkexec_uid = std::env::var_os("PKEXEC_UID");
    match serve::startup(connect, pkexec_uid.as_deref()) {
        Ok(_stream) => {
            eprintln!("aitm-l4-helper: serve loop arrives in task P2.7");
            ExitCode::from(EXIT_NOT_IMPLEMENTED)
        }
        Err(err) => {
            eprintln!("aitm-l4-helper: serve: {err}");
            ExitCode::from(EXIT_SERVE_FAILED)
        }
    }
}

/// Off Linux there is no pkexec-started helper to drop (spec §5 is L-C).
#[cfg(not(target_os = "linux"))]
fn run_serve(_connect: &std::path::Path) -> ExitCode {
    eprintln!("aitm-l4-helper: serve is Linux only in Phase 1");
    ExitCode::from(EXIT_WRONG_PLATFORM)
}

/// `bpf-permissions` / `bpf-revert` on macOS (spec §3.1). A dry run prints the
/// plan to stdout and changes nothing; a real run applies or reverts, logs its
/// one line (spec §3.1 step 6) and exits 0 on success, 1 otherwise.
#[cfg(target_os = "macos")]
fn run_bpf(mode: BpfMode, dry_run: bool) -> ExitCode {
    use bpf_exec::RealMacSys;

    if dry_run {
        let lines = match mode {
            BpfMode::Permissions => bpf_exec::dry_run_apply(&RealMacSys),
            BpfMode::Revert => bpf_exec::dry_run_revert(&RealMacSys),
        };
        return match lines {
            Ok(lines) => {
                for line in lines {
                    println!("{line}");
                }
                ExitCode::SUCCESS
            }
            Err(err) => {
                eprintln!("aitm-l4-helper: dry run: {err}");
                ExitCode::from(EXIT_BPF_FAILED)
            }
        };
    }
    let (line, ok) = match mode {
        BpfMode::Permissions => {
            let result = bpf_exec::apply(&RealMacSys, env!("CARGO_PKG_VERSION"), now_ms());
            (log::run_line("bpf-permissions", &result), result.is_ok())
        }
        BpfMode::Revert => {
            let result = bpf_exec::revert(&RealMacSys);
            (log::revert_line(&result), result.is_ok())
        }
    };
    log::emit(&line, ok);
    if ok {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(EXIT_BPF_FAILED)
    }
}

/// Off macOS there is no `/dev/bpf*` to fix: refuse before touching anything.
#[cfg(not(target_os = "macos"))]
fn run_bpf(_mode: BpfMode, _dry_run: bool) -> ExitCode {
    eprintln!("aitm-l4-helper: bpf modes are macOS only");
    ExitCode::from(EXIT_WRONG_PLATFORM)
}

/// Milliseconds since the Unix epoch for the receipt's `applied_at`; `0` on a
/// clock set before 1970, never a panic.
#[cfg(target_os = "macos")]
fn now_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| {
            u64::try_from(since.as_millis()).unwrap_or(u64::MAX)
        })
}
