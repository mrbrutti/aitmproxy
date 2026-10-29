//! `aitm-plugin` — the protocol-module seam, re-exported for external authors.
//!
//! The seam types are defined in `aitm-core` so the in-tree acceptor
//! (`aitm_core::Proxy`) can register `dyn ProtocolModule` without a dependency
//! cycle. This crate re-exports them so a protocol author writes
//! `use aitm_plugin::{ProtocolModule, NextLayerHint, ModuleCtx, ByteStream};`
//! (per the plugin-system spec's worked example) and registers their module with
//! no `aitm-core` edit.

pub use aitm_core::{
    AsyncReadWrite, ByteStream, EventSink, ModuleCtx, NextLayerHint, ProtocolModule,
    UpstreamConnector, Value,
};

pub mod language;
