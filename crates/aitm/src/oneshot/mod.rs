//! The one-shot: `aitm scope add --host example.com` run from a second shell
//! while a core is serving (spec R14). A **local** verb (`verbs::LOCAL_VERBS`)
//! runs on this machine through today's in-process `Cli::dispatch`; every
//! other verb is **live**: the one-shot finds the running core (`resolve`),
//! calls it over the loopback operator bus (`remote`) and prints the result
//! exactly as the in-process path would, or explains why it could not
//! (`refuse`). `args` splits the one-shot's own flags (`--bus`, `--token-file`)
//! out of argv; `run` is the entry `main` calls.
//!
//! Declarations only (plan C1): consumers use the full paths
//! (`aitm::oneshot::run::run`, `aitm::oneshot::args::split_bus_args`).

pub mod args;
pub mod refuse;
pub mod remote;
pub mod resolve;
pub mod run;
pub mod verbs;
