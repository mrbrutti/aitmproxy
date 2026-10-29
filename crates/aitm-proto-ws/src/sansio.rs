//! Sans-IO WebSocket frame coder (RFC 6455 framing), mirroring the HTTP split:
//! the module feeds it bytes from either side and writes out what it queues.
//! Each decoded message is held just long enough for the driver to copy it into
//! `WsFlow.messages` and emit `Message { index }`; the buffer is cleared at the
//! start of the next `on_bytes`, so the coder never retains the whole
//! conversation (the store owns the durable copy).
//!
//! Decoding accepts masked and unmasked frames from either side (a proxy
//! should see what is on the wire, not be stricter than the endpoints);
//! encoding follows the RFC: frames towards the server are masked with an
//! unpredictable key, frames towards the client are not.

use std::time::SystemTime;

use aitm_core::{WsDir, WsMessage, WsOpcode};
use anyhow::{bail, Result};

/// Pure frame coder, mirroring the sans-IO split used for HTTP.
pub trait WsStateMachine: Send {
    /// Feed bytes read from one side; get back the events they produced.
    fn on_bytes(&mut self, from: Side, buf: &[u8]) -> Result<Vec<WsSansIoEvent>>;
    /// Bytes the machine wants written to a side.
    fn poll_outbound(&mut self, to: Side) -> Option<Vec<u8>>;
    /// Author/forward a (possibly mutated) frame.
    fn send_frame(&mut self, to: Side, msg: WsMessage);
}

/// Which peer bytes came from or go to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Side {
    Client,
    Server,
}

/// What the coder produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WsSansIoEvent {
    Open,
    /// A message was appended at `index`.
    Message {
        index: usize,
    },
    Close,
}

/// Largest single-frame payload accepted.
const MAX_FRAME_PAYLOAD: u64 = 16 * 1024 * 1024;
/// Largest reassembled (fragmented) message accepted, so a stream of
/// continuation frames cannot grow memory without bound.
const MAX_MESSAGE_BYTES: usize = 16 * 1024 * 1024;

const OP_CONTINUATION: u8 = 0x0;
const OP_TEXT: u8 = 0x1;
const OP_BINARY: u8 = 0x2;
const OP_CLOSE: u8 = 0x8;
const OP_PING: u8 = 0x9;
const OP_PONG: u8 = 0xA;

/// One side's receive buffer and any fragmented message in progress.
struct Reader {
    buf: Vec<u8>,
    partial: Option<(WsOpcode, Vec<u8>)>,
}

impl Reader {
    fn new() -> Self {
        Self {
            buf: Vec::new(),
            partial: None,
        }
    }
}

/// A decoded frame, payload already unmasked.
struct Frame {
    fin: bool,
    opcode: u8,
    payload: Vec<u8>,
}

/// The WebSocket frame coder for one connection.
pub struct WsFrameMachine {
    client: Reader,
    server: Reader,
    out_client: Vec<u8>,
    out_server: Vec<u8>,
    messages: Vec<WsMessage>,
    opened: bool,
    closed: bool,
}

impl Default for WsFrameMachine {
    fn default() -> Self {
        Self::new()
    }
}

impl WsFrameMachine {
    /// A coder for a freshly upgraded connection.
    pub fn new() -> Self {
        Self {
            client: Reader::new(),
            server: Reader::new(),
            out_client: Vec::new(),
            out_server: Vec::new(),
            messages: Vec::new(),
            opened: false,
            closed: false,
        }
    }

    /// The message at `index` within the current batch (the one the latest
    /// `on_bytes` produced). Indices reset each `on_bytes` call.
    pub fn message(&self, index: usize) -> Option<&WsMessage> {
        self.messages.get(index)
    }

    /// The messages decoded by the latest `on_bytes` call (not the whole
    /// conversation — the coder does not retain past batches).
    pub fn messages(&self) -> &[WsMessage] {
        &self.messages
    }

    /// Whether a Close frame has been seen.
    pub fn is_closed(&self) -> bool {
        self.closed
    }

    fn reader_mut(&mut self, side: Side) -> &mut Reader {
        match side {
            Side::Client => &mut self.client,
            Side::Server => &mut self.server,
        }
    }

    fn out_mut(&mut self, side: Side) -> &mut Vec<u8> {
        match side {
            Side::Client => &mut self.out_client,
            Side::Server => &mut self.out_server,
        }
    }

    fn push_message(
        &mut self,
        from: Side,
        opcode: WsOpcode,
        data: Vec<u8>,
        events: &mut Vec<WsSansIoEvent>,
    ) {
        self.messages.push(WsMessage {
            dir: match from {
                Side::Client => WsDir::ClientToServer,
                Side::Server => WsDir::ServerToClient,
            },
            opcode,
            data,
            timestamp: SystemTime::now(),
            injected: false,
        });
        events.push(WsSansIoEvent::Message {
            index: self.messages.len() - 1,
        });
    }
}

impl WsStateMachine for WsFrameMachine {
    fn on_bytes(&mut self, from: Side, buf: &[u8]) -> Result<Vec<WsSansIoEvent>> {
        // Messages from the previous batch have already been copied into the
        // store and forwarded by the driver (it drains every event this call
        // returns before calling `on_bytes` again). Keeping them here would make
        // `messages` a pure duplicate of `WsFlow.messages` that grows without
        // bound; drop them so retention is one read-buffer's worth of frames, not
        // the whole conversation. `Message { index }` indices are therefore
        // relative to the batch this call produces.
        self.messages.clear();
        let mut events = Vec::new();
        if !self.opened {
            self.opened = true;
            events.push(WsSansIoEvent::Open);
        }
        if self.closed {
            return Ok(events);
        }
        self.reader_mut(from).buf.extend_from_slice(buf);

        loop {
            let Some(frame) = parse_frame(&mut self.reader_mut(from).buf)? else {
                break;
            };
            match frame.opcode {
                OP_CONTINUATION => {
                    let Some((opcode, mut data)) = self.reader_mut(from).partial.take() else {
                        bail!("continuation frame without a message in progress");
                    };
                    if data.len().saturating_add(frame.payload.len()) > MAX_MESSAGE_BYTES {
                        bail!("reassembled WebSocket message exceeds {MAX_MESSAGE_BYTES} bytes");
                    }
                    data.extend_from_slice(&frame.payload);
                    if frame.fin {
                        self.push_message(from, opcode, data, &mut events);
                    } else {
                        self.reader_mut(from).partial = Some((opcode, data));
                    }
                }
                OP_TEXT | OP_BINARY => {
                    let opcode = if frame.opcode == OP_TEXT {
                        WsOpcode::Text
                    } else {
                        WsOpcode::Binary
                    };
                    if frame.fin {
                        self.push_message(from, opcode, frame.payload, &mut events);
                    } else {
                        if self.reader_mut(from).partial.is_some() {
                            bail!("new data frame while a fragmented message is in progress");
                        }
                        self.reader_mut(from).partial = Some((opcode, frame.payload));
                    }
                }
                OP_CLOSE => {
                    self.push_message(from, WsOpcode::Close, frame.payload, &mut events);
                    events.push(WsSansIoEvent::Close);
                    self.closed = true;
                    break;
                }
                OP_PING => self.push_message(from, WsOpcode::Ping, frame.payload, &mut events),
                OP_PONG => self.push_message(from, WsOpcode::Pong, frame.payload, &mut events),
                other => bail!("reserved WebSocket opcode {other:#x}"),
            }
        }
        Ok(events)
    }

    fn poll_outbound(&mut self, to: Side) -> Option<Vec<u8>> {
        let out = self.out_mut(to);
        if out.is_empty() {
            None
        } else {
            Some(std::mem::take(out))
        }
    }

    fn send_frame(&mut self, to: Side, msg: WsMessage) {
        let opcode = match msg.opcode {
            WsOpcode::Text => OP_TEXT,
            WsOpcode::Binary => OP_BINARY,
            WsOpcode::Ping => OP_PING,
            WsOpcode::Pong => OP_PONG,
            WsOpcode::Close => OP_CLOSE,
        };
        // Frames travelling towards the server are client frames: masked.
        let masked = to == Side::Server;
        let mask_bit = if masked { 0x80 } else { 0x00 };
        let len = msg.data.len();

        let mut frame = vec![0x80 | opcode];
        if len < 126 {
            frame.push(mask_bit | len as u8);
        } else if let Ok(len16) = u16::try_from(len) {
            frame.push(mask_bit | 126);
            frame.extend_from_slice(&len16.to_be_bytes());
        } else {
            frame.push(mask_bit | 127);
            frame.extend_from_slice(&(len as u64).to_be_bytes());
        }
        if masked {
            let key = mask_key();
            frame.extend_from_slice(&key);
            frame.extend(msg.data.iter().enumerate().map(|(i, b)| b ^ key[i % 4]));
        } else {
            frame.extend_from_slice(&msg.data);
        }
        self.out_mut(to).extend_from_slice(&frame);
    }
}

/// An unpredictable 32-bit masking key (RFC 6455 5.3), from the OS RNG via
/// a v4 UUID.
fn mask_key() -> [u8; 4] {
    let uuid = uuid::Uuid::new_v4();
    let bytes = uuid.as_bytes();
    [bytes[0], bytes[1], bytes[2], bytes[3]]
}

/// Remove and decode one complete frame from the front of `buf`, or `None`
/// if it is not all there yet.
fn parse_frame(buf: &mut Vec<u8>) -> Result<Option<Frame>> {
    if buf.len() < 2 {
        return Ok(None);
    }
    let b0 = buf[0];
    let b1 = buf[1];
    if b0 & 0x70 != 0 {
        bail!("RSV bits set without a negotiated extension");
    }
    let fin = b0 & 0x80 != 0;
    let opcode = b0 & 0x0F;
    let masked = b1 & 0x80 != 0;

    let (len, mut pos) = match b1 & 0x7F {
        126 => {
            if buf.len() < 4 {
                return Ok(None);
            }
            (u64::from(u16::from_be_bytes([buf[2], buf[3]])), 4)
        }
        127 => {
            if buf.len() < 10 {
                return Ok(None);
            }
            let mut be = [0u8; 8];
            be.copy_from_slice(&buf[2..10]);
            (u64::from_be_bytes(be), 10)
        }
        n => (u64::from(n), 2),
    };
    if len > MAX_FRAME_PAYLOAD {
        bail!("WebSocket frame payload of {len} bytes exceeds {MAX_FRAME_PAYLOAD}");
    }
    if opcode >= OP_CLOSE && (len > 125 || !fin) {
        bail!("control frame fragmented or longer than 125 bytes");
    }
    let key = if masked {
        if buf.len() < pos + 4 {
            return Ok(None);
        }
        let key = [buf[pos], buf[pos + 1], buf[pos + 2], buf[pos + 3]];
        pos += 4;
        Some(key)
    } else {
        None
    };
    // `len` fits usize: it is at most MAX_FRAME_PAYLOAD.
    let total = pos + len as usize;
    if buf.len() < total {
        return Ok(None);
    }
    let mut payload = buf[pos..total].to_vec();
    if let Some(key) = key {
        for (i, byte) in payload.iter_mut().enumerate() {
            *byte ^= key[i % 4];
        }
    }
    buf.drain(..total);
    Ok(Some(Frame {
        fin,
        opcode,
        payload,
    }))
}
