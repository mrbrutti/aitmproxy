//! From a `HelpRequest` to a rendered page, a typed usage error, or "not help"
//! (plan Task 14; C31, C33): the mode topics render without a registry;
//! everything else reads the config (read-only; defaults plus one warning when
//! it cannot be read), builds `describe::registry` and locates the topic
//! through `aitm_cli::Cli::locate`. An implicit request that names nothing is
//! `NotHelp` and the invocation continues as `Mode::Cli`; an explicit one is
//! an error pre-boot.
//!
//! Skeleton (plan Task 8). Task 14 adds `HelpInputs`, `Answer`,
//! `settings_for_help` and `answer`.
