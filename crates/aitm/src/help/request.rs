//! Recognising a help request in argv (plan Task 11; C32, C33): `--help`,
//! `-h`, `help [topic…]` and `<group> [<verb>] --help` are explicit requests;
//! a single bare token that is not a mode word (`aitm scope`, `aitm scpe`) is
//! an implicit one; `sysproxy-watchdog` is never intercepted.
//!
//! Skeleton (plan Task 8). Task 11 adds `HelpRequest` and `parse`.
