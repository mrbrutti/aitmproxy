//! The audit token of the process at the other end of a connected UNIX socket.
//!
//! macOS exposes the peer of a connected `AF_UNIX` socket as an `audit_token_t` via
//! `getsockopt(SOL_LOCAL, LOCAL_PEERTOKEN)`. The macOS NE capture feeder in `aitm`
//! hands that token to Security.framework to verify the System Extension provider's
//! code signature. Reading it needs one `unsafe` libc call, and this crate exists to
//! hold exactly that call, so every other crate in the workspace (`aitm` included)
//! keeps `unsafe_code = "forbid"`.
//!
//! The one function is **fail-closed**: any error, a short token, or any non-macOS
//! target returns `None`, never a guess.

use std::os::fd::RawFd;

/// `audit_token_t`: eight native-endian `unsigned int`s (32 bytes). Index 5 is the
/// peer's pid, as in `audit_token_to_pid`.
pub type AuditToken = [u32; 8];

/// The audit token of the process at the other end of connected UNIX socket `fd`, or
/// `None` if the kernel will not give it up (bad fd, not a connected UNIX socket,
/// short token) or this is not macOS.
///
/// `fd` is only borrowed for the call: it is not closed, and it need not outlive it.
#[must_use]
pub fn peer_audit_token(fd: RawFd) -> Option<AuditToken> {
    #[cfg(target_os = "macos")]
    {
        macos::peer_audit_token(fd)
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = fd;
        None
    }
}

#[cfg(target_os = "macos")]
mod macos {
    use std::mem::size_of;
    use std::os::fd::RawFd;

    use super::AuditToken;

    /// Size of [`AuditToken`] as the `socklen_t` `getsockopt` traffics in.
    const AUDIT_TOKEN_LEN: libc::socklen_t = size_of::<AuditToken>() as libc::socklen_t;

    #[allow(unsafe_code)]
    pub(super) fn peer_audit_token(fd: RawFd) -> Option<AuditToken> {
        let mut token: AuditToken = [0; 8];
        let mut len = AUDIT_TOKEN_LEN;
        // SAFETY: `token` is a live, writable, 4-byte-aligned buffer of exactly
        // `AUDIT_TOKEN_LEN` (32) bytes, matching `audit_token_t`; `len` is a live
        // `socklen_t` initialised to that size, so the kernel writes at most
        // `AUDIT_TOKEN_LEN` bytes into `token` and stores the written length in
        // `len`. Both pointers are valid for the duration of the call and not
        // aliased. `fd` is only an integer handed to the kernel: an invalid or
        // non-socket descriptor makes the call fail with an errno (checked below),
        // it cannot cause undefined behaviour.
        let rc = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_LOCAL,
                libc::LOCAL_PEERTOKEN,
                token.as_mut_ptr().cast::<libc::c_void>(),
                &mut len,
            )
        };
        // Fail-closed: only a successful call that filled the whole token counts.
        (rc == 0 && len == AUDIT_TOKEN_LEN).then_some(token)
    }
}

#[cfg(test)]
mod tests {
    use std::os::fd::AsRawFd;
    use std::os::unix::net::UnixStream;

    use super::peer_audit_token;

    /// A `UnixStream::pair()` peer is this very process, so the token names our pid
    /// (`audit_token_t.val[5]`). Proves the real `getsockopt` ran and the 32 bytes
    /// were read into the right place, not just that something came back.
    #[test]
    #[cfg(target_os = "macos")]
    fn socketpair_peer_token_names_this_process() {
        let (a, _b) = UnixStream::pair().unwrap();
        let token =
            peer_audit_token(a.as_raw_fd()).expect("a connected unix socket has a peer token");
        assert_eq!(token[5], std::process::id());
    }

    /// An invalid descriptor makes the kernel call fail: `None`, not a zeroed token.
    #[test]
    fn invalid_fd_has_no_token() {
        assert_eq!(peer_audit_token(-1), None);
    }

    /// A descriptor that is not a socket at all (`ENOTSOCK`) has no peer token.
    #[test]
    fn non_socket_fd_has_no_token() {
        let file = std::fs::File::open("/dev/null").unwrap();
        assert_eq!(peer_audit_token(file.as_raw_fd()), None);
    }

    /// Off macOS there is no `LOCAL_PEERTOKEN`: even a perfectly good connected
    /// socket yields no token (fail-closed).
    #[test]
    #[cfg(not(target_os = "macos"))]
    fn non_macos_never_yields_a_token() {
        let (a, _b) = UnixStream::pair().unwrap();
        assert_eq!(peer_audit_token(a.as_raw_fd()), None);
    }
}
