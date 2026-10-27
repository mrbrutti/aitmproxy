//! `Body`: a message body that is streamed by default and buffered on demand.
//!
//! The streaming machinery (a backpressured handle fed by the protocol module)
//! is wired in the HTTP module (Tasks 10/11). The core only fixes the shape so
//! every crate agrees on the type; `Empty`/`Bytes` cover the buffered cases the
//! foundation exercises.

/// An opaque, backpressured handle to a body still arriving on the wire.
///
/// A placeholder in the core: the HTTP protocol module supplies the real
/// streaming implementation. Cloning shares the same logical stream.
#[derive(Debug, Clone, Default)]
pub struct StreamBody;

/// A message body. Streamed by default; `materialize` (later) buffers it when a
/// handler needs the bytes.
#[derive(Debug, Clone, Default)]
pub enum Body {
    /// No body.
    #[default]
    Empty,
    /// A fully buffered body.
    Bytes(Vec<u8>),
    /// A body still streaming from the wire.
    Streamed(StreamBody),
}
