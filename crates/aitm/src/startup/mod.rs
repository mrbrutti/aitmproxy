//! Startup: everything that knows aitmproxy on the way from `main()` to the
//! ready card (spec D1, D8, D9, D14; plan Task 7).
//!
//! `args` parses the global terminal flags (`-v`, `-vv`, `-q`, `--color`) into
//! [`TermOpts`], answers `--version`/`--help` before anything boots
//! ([`pre_boot`]) and owns the static [`SYNOPSIS`]; `errors` types the startup
//! failures and renders them as panels (Task 8); `log` opens the log file and
//! composes the three tracing layers (Task 9); `card` turns the live values
//! into the ready card (Task 10). The leaf modules are addressed by path
//! (`startup::errors::…`, `startup::log::…`, `startup::card::…`); only `args`
//! is re-exported here, because this file and `args.rs` are written by the
//! same task (the plan's C1 discipline, so parallel coders never share a
//! file).
//!
//! [`write_stdout`] is the one sanctioned direct stdout writer outside the
//! renderer and `render.rs` (spec D14): the pre-boot `--version`/`--help`
//! text, `aitm web --help`'s usage text and the `operator-token` confirmation
//! go through it.

use std::io::Write;

pub mod args;
pub mod card;
pub mod errors;
pub mod log;

pub use args::{pre_boot, split_term_args, version_line, PreBoot, TermOpts, GROUPS, SYNOPSIS};

/// Write `text` to stdout and flush it, through one lock and `write_all`
/// (never `print!`, which panics on a closed pipe and bypasses the no-bypass
/// scan). The caller decides what to do with an error; the pre-boot paths
/// exit 0 regardless, since the text was all they had to say.
pub fn write_stdout(text: &str) -> std::io::Result<()> {
    let mut out = std::io::stdout().lock();
    out.write_all(text.as_bytes())?;
    out.flush()
}
