//! The async duplex byte stream a protocol module drives, abstracting the raw
//! socket/TLS. `ByteStream` is what the acceptor hands a module and what
//! `connect_upstream` returns.

use std::pin::Pin;

use tokio::io::{AsyncRead, AsyncWrite};

/// Marker for an async, duplex, sendable stream. Blanket-implemented for every
/// type that is `AsyncRead + AsyncWrite + Send` (TCP, TLS, in-memory duplex).
pub trait AsyncReadWrite: AsyncRead + AsyncWrite + Send {}

impl<T: AsyncRead + AsyncWrite + Send> AsyncReadWrite for T {}

/// An owned, pinned, dynamically-typed duplex byte stream.
pub type ByteStream = Pin<Box<dyn AsyncReadWrite + Send>>;
