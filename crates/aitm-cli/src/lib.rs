//! `aitm-cli` — CLI frontend over the one command bus.
//!
//! `aitm flow replay --id <uuid>` → command `"flow.replay"` + `Params{ id }`:
//! the subcommand path maps 1:1 onto `Command::name()`, flags map onto the
//! command's `ParamDef`s by name, and the same `Command::invoke` the MCP frontend
//! calls runs against a `CommandHost` built from the attached services. The
//! host declares itself `Frontend::Cli`; a command that asks before acting
//! (`Command::confirm_prompt`) is put to a `Confirmer` unless `--yes` was given.
//! Usage errors are typed `aitm_term::error::ErrorReport`s wrapped in
//! `anyhow::Error`, and an unknown command or flag carries a `did you mean:`
//! line built by [`suggest`].

pub mod confirm;
pub mod dispatch;
pub mod suggest;

pub use confirm::{Confirmer, TtyConfirmer};
pub use dispatch::Cli;
