//! The Linux NFQUEUE in-path backend (M5 Task 11).
//!
//! Binds an `nft ... queue num N` queue over the `nfq` crate — which talks netlink
//! directly, so no GPL `libnetfilter_queue` link and the crate keeps
//! `#![forbid(unsafe_code)]` (nfq's own `unsafe` stays internal). The queue is
//! opened on the dedicated reader thread (see [`super::start_intercept`]): its
//! `recv`/`verdict` share one `&mut` owner, and `recv` is set non-blocking so the
//! owning loop can re-check the stop flag and verdict deadlines between polls.
//!
//! Fail-closed: binding a queue needs `CAP_NET_ADMIN`; without it, `open` returns
//! [`L4Error::Unavailable`] rather than panicking.

use std::collections::HashMap;
use std::io::ErrorKind;
use std::time::Duration;

use nfq::{Queue, Verdict as NfqVerdict};

use super::{InterceptBackend, InterceptQueue, QueuedPacket, WireVerdict};
use crate::backend::L4Error;

/// The production in-path backend: Linux NFQUEUE queue number `queue_num`.
#[derive(Debug, Clone, Copy)]
pub struct NfqueueBackend {
    queue_num: u16,
}

impl NfqueueBackend {
    /// A backend bound (on `open`) to `nft` queue number `queue_num`.
    #[must_use]
    pub fn new(queue_num: u16) -> Self {
        Self { queue_num }
    }
}

impl InterceptBackend for NfqueueBackend {
    fn open(&self) -> Result<Box<dyn InterceptQueue>, L4Error> {
        let mut queue = Queue::open().map_err(|e| {
            L4Error::Unavailable(format!("NFQUEUE open failed (needs CAP_NET_ADMIN): {e}"))
        })?;
        queue.bind(self.queue_num).map_err(|e| {
            L4Error::Unavailable(format!(
                "NFQUEUE bind of queue {} failed (needs CAP_NET_ADMIN and an nft queue rule): {e}",
                self.queue_num
            ))
        })?;
        // Non-blocking recv so the reader loop polls and re-checks the stop flag and
        // the aitm-enforced verdict deadlines rather than blocking forever.
        queue.set_nonblocking(true);
        Ok(Box::new(NfqueueQueue {
            queue,
            held: HashMap::new(),
        }))
    }
}

/// A bound NFQUEUE reader. Holds each received `Message` until its verdict is
/// issued — the `nfq` `Message` has no lifetime (it owns an `Arc` of the recv
/// buffer), so a parked packet can be verdicted later, which is exactly the
/// park/mutate/forward model.
struct NfqueueQueue {
    queue: Queue,
    /// Received-but-unverdicted messages, keyed by their NFQUEUE packet id (the
    /// `handle` surfaced to the reader loop).
    held: HashMap<u32, nfq::Message>,
}

impl InterceptQueue for NfqueueQueue {
    fn next_packet(&mut self, read_timeout: Duration) -> Result<Option<QueuedPacket>, L4Error> {
        match self.queue.recv() {
            Ok(msg) => {
                let handle = msg.get_packet_id();
                let bytes = msg.get_payload().to_vec();
                // Retain the message so its verdict can be issued (now or later).
                self.held.insert(handle, msg);
                Ok(Some(QueuedPacket { handle, bytes }))
            }
            // Non-blocking: no packet ready. Sleep up to `read_timeout` so the
            // owning loop re-checks deadlines/stop instead of busy-spinning.
            Err(e) if e.kind() == ErrorKind::WouldBlock => {
                std::thread::sleep(read_timeout);
                Ok(None)
            }
            // A real recv error is fail-closed: end the reader rather than spin.
            Err(e) => Err(L4Error::Unavailable(format!("NFQUEUE recv failed: {e}"))),
        }
    }

    fn verdict(&mut self, handle: u32, verdict: WireVerdict) -> Result<(), L4Error> {
        // An unknown/already-verdicted handle is an idempotent no-op.
        let Some(mut msg) = self.held.remove(&handle) else {
            return Ok(());
        };
        match verdict {
            WireVerdict::Forward(None) => msg.set_verdict(NfqVerdict::Accept),
            WireVerdict::Forward(Some(bytes)) => {
                // Reinject a mangled payload. The caller is responsible for any
                // checksum/length fixup (the kernel drops a packet it cannot
                // re-mangle); the craft layer validates that before mutation.
                msg.set_payload(bytes);
                msg.set_verdict(NfqVerdict::Accept);
            }
            WireVerdict::Drop => msg.set_verdict(NfqVerdict::Drop),
        }
        self.queue
            .verdict(msg)
            .map_err(|e| L4Error::WireWrite(format!("NFQUEUE verdict failed: {e}")))
    }
}
