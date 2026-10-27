//! `aitm` — the binary's reusable assembly. `wire::build_proxy` turns a `Config`
//! into a running-ready `Proxy`; `main` drives it. Kept as a library so the
//! wiring is testable (AC-P3/AC-P4) without the process entrypoint.

pub mod wire;
