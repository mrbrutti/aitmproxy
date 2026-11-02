//! The schema-only command registry that help and the registry pins read
//! (spec D15 bullet 1, realised as plan C28): the same plugins
//! `wire::assemble_with_scripts` registers, in the same order, built over
//! inert handles into a bare `aitm_core::Registry` — no `Proxy`, no
//! `CertAuthority`, nothing bound, nothing written (plan rule 12). The plugin
//! list is duplicated from `wire.rs` (frozen until #267) on purpose and
//! pinned by `tests/describe_registry.rs` against the live registry's names,
//! order and schema fingerprints; once #267 lands the two share one builder.
//!
//! Skeleton (plan Task 8). Task 9 adds `DescribeInputs`, `Described`,
//! `registry`, `groups`, `fingerprint` and `is_group`.
