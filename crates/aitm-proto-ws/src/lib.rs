//! `aitm-proto-ws` — WebSocket protocol module (activates after HTTP Upgrade).

pub mod module;
pub mod sansio;

pub use module::WsModule;
pub use sansio::{Side, WsFrameMachine, WsSansIoEvent, WsStateMachine};
