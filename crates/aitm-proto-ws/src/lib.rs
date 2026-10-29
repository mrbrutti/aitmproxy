//! `aitm-proto-ws` — WebSocket protocol module (activates after HTTP Upgrade).

pub mod module;
pub mod sansio;

pub use module::{InjectFrame, InjectRegistry, WsModule};
pub use sansio::{Side, WsFrameMachine, WsSansIoEvent, WsStateMachine};
