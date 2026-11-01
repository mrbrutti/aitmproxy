//! The `probe.*` host functions and the thread-local check context they read
//! (plan Task 13): a check closure calls `probe.send`/`probe.baseline`/… against
//! the point the scheduler seeded. Implemented in Task 13; this module is
//! declared up front so later tasks never re-touch `lib.rs`.
