//! The `reg.add_check(meta, closure)` bridge and `ScriptCheck` (plan Task 13):
//! a Rhai check declares its `CheckMeta` and verdict closure here and becomes a
//! native `Check` the scanner engine schedules. Implemented in Task 13; this
//! module is declared up front so later tasks never re-touch `lib.rs`.
