//! Peer-authentication seam for the macOS NE live-capture feeder.
//!
//! The Swift provider verifies the **core** before it sends a flow
//! (`PeerAuth` in `apps/mac/Extension/Sources/FlowHandoff.swift`); this module is
//! the symmetric check — the **core verifies the provider** before it sends scope or
//! feeds bytes. Any process running as the same uid can dial the 0700 socket
//! directory's sockets only if it already owns them, but a same-uid squatter that
//! wins the rendezvous race would otherwise be handed the live scope and receive
//! plaintext flow bytes; the code-signature check closes that.
//!
//! The check sits behind the [`PeerVerifier`] seam so the feeder takes an
//! `Arc<dyn PeerVerifier>`: production injects [`CodeSignatureVerifier`], tests
//! inject a stub that accepts or rejects.
//!
//! # Fail-closed
//!
//! Every path out of [`PeerVerifier::verify`] that is not an affirmative,
//! successful code-signature check returns `false`: an unreadable peer token, an
//! unresolvable `SecCode`, an unparseable requirement, a failed validity check, and
//! every non-macOS target (where there is no Security.framework to ask).
//!
//! # Known, accepted caveat
//!
//! `LOCAL_PEERTOKEN` has an inherent time-of-check/time-of-use window: it names the
//! process that connected the socket, and the check is not re-run if that process
//! later hands the descriptor on. A verified, root provider is trusted not to do
//! that, so this is outside the threat model (mirrors the milestone Review log,
//! Task 11).

use std::os::fd::RawFd;

/// Decides whether the process at the other end of a connected Unix socket is the
/// trusted peer. **Fail-closed by contract:** any doubt, any error, returns `false`.
pub trait PeerVerifier: Send + Sync {
    /// `true` only if the peer of connected socket `fd` is positively verified.
    /// The descriptor is borrowed for the duration of the call; the verifier must
    /// not close it.
    fn verify(&self, fd: RawFd) -> bool;

    /// The Apple team identifier a peer that passes [`verify`](Self::verify) was
    /// checked against — the team the verifier's requirement pins, **not** a value
    /// read from the peer's signing information (the safe `SecCode` API has no
    /// accessor for that). `None` when the verifier pins no team; the default, so
    /// a verifier that only implements `verify` still compiles.
    fn team_id(&self) -> Option<String> {
        None
    }
}

/// The code requirement the System Extension provider must satisfy. Byte-identical
/// to `PeerAuth.coreRequirement` on the Swift side: it accepts ANY binary signed by
/// an Apple-anchored certificate whose leaf subject OU is our Developer ID team.
///
/// TODO(macos-ne milestone hardening, mirrors the Swift `PeerAuth.coreRequirement`
/// TODO): once the sysex's final signing identifier is fixed, narrow this to its
/// full designated requirement, e.g. append `and identifier "<sysex signing
/// identifier>"`, so another binary from the same team (a helper, an old build)
/// cannot impersonate the provider. The team-level requirement is what the plan
/// specifies for now.
pub const PROVIDER_REQUIREMENT: &str =
    "anchor apple generic and certificate leaf[subject.OU] = \"995PCLM9KH\"";

/// The Developer ID team [`PROVIDER_REQUIREMENT`] pins (its `leaf[subject.OU]`).
/// What [`CodeSignatureVerifier::default`] reports from
/// [`PeerVerifier::team_id`]; a test pins that the requirement contains it.
pub const PROVIDER_TEAM_ID: &str = "995PCLM9KH";

/// A [`PeerVerifier`] that resolves the peer's audit token to a running `SecCode`
/// and checks it against a code-signing requirement via Security.framework.
#[derive(Debug, Clone)]
pub struct CodeSignatureVerifier {
    requirement: String,
    /// The team `requirement` pins, reported by [`PeerVerifier::team_id`]. Set only
    /// by [`Default`] (the production requirement); an arbitrary requirement need
    /// not pin a team and the verifier never parses one out of it.
    team_id: Option<String>,
}

impl CodeSignatureVerifier {
    /// A verifier that checks peers against `req` instead of
    /// [`PROVIDER_REQUIREMENT`]. A requirement that does not parse rejects every
    /// peer (fail-closed). Pins no team: [`PeerVerifier::team_id`] is `None`.
    #[must_use]
    pub fn with_requirement(req: impl Into<String>) -> Self {
        Self {
            requirement: req.into(),
            team_id: None,
        }
    }
}

impl Default for CodeSignatureVerifier {
    /// Verify against [`PROVIDER_REQUIREMENT`], which pins [`PROVIDER_TEAM_ID`].
    fn default() -> Self {
        Self {
            requirement: PROVIDER_REQUIREMENT.into(),
            team_id: Some(PROVIDER_TEAM_ID.into()),
        }
    }
}

impl PeerVerifier for CodeSignatureVerifier {
    fn team_id(&self) -> Option<String> {
        self.team_id.clone()
    }

    #[cfg(target_os = "macos")]
    fn verify(&self, fd: RawFd) -> bool {
        macos::verify_peer(fd, &self.requirement)
    }

    /// There is no Security.framework off macOS, so no peer can be verified:
    /// fail-closed. (The `requirement` is read so the field is not dead code.)
    #[cfg(not(target_os = "macos"))]
    fn verify(&self, fd: RawFd) -> bool {
        let _ = (fd, &self.requirement);
        false
    }
}

#[cfg(target_os = "macos")]
mod macos {
    //! The real check, step for step what `PeerAuth` does in Swift:
    //! `getsockopt(LOCAL_PEERTOKEN)` → `SecCodeCopyGuestWithAttributes` with
    //! `kSecGuestAttributeAudit` → `SecRequirementCreateWithString` →
    //! `SecCodeCheckValidity`. The `getsockopt` is the one `unsafe` step, so it lives
    //! in the leaf crate `aitm-peer-token` (`peer_audit_token`); everything here is
    //! safe code and this crate keeps the workspace `unsafe_code = "forbid"`.

    use std::os::fd::RawFd;

    use aitm_peer_token::{peer_audit_token, AuditToken};
    use core_foundation::base::TCFType;
    use core_foundation::data::CFData;
    use security_framework::os::macos::code_signing::{
        Flags, GuestAttributes, SecCode, SecRequirement,
    };

    /// The audit token as the raw bytes `kSecGuestAttributeAudit` expects: the
    /// in-memory representation of `audit_token_t`, as Swift's
    /// `withUnsafeBytes(of: &token) { Data($0) }`.
    fn token_bytes(token: &AuditToken) -> Vec<u8> {
        token.iter().flat_map(|word| word.to_ne_bytes()).collect()
    }

    /// Every step of the check, `None` on the first failure (fail-closed).
    fn check(fd: RawFd, requirement: &str) -> Option<()> {
        // 1. The peer's audit token off the socket.
        let token = peer_audit_token(fd)?;

        // 2. Resolve the token to the running guest `SecCode`
        //    (`SecCodeCopyGuestWithAttributes(nil, {audit: token}, [], &guest)`).
        //    `token_data` must outlive `attributes`, which holds it by reference.
        let token_data = CFData::from_buffer(&token_bytes(&token));
        let mut attributes = GuestAttributes::new();
        attributes.set_audit_token(token_data.as_concrete_TypeRef());
        // The crate spells this `copy_guest_with_attribues` (sic).
        let code = SecCode::copy_guest_with_attribues(None, &attributes, Flags::NONE).ok()?;

        // 3. Parse the requirement (`SecRequirementCreateWithString(req, [], &parsed)`).
        let parsed: SecRequirement = requirement.parse().ok()?;

        // 4. The peer must satisfy it right now (`SecCodeCheckValidity(code, [], req)`).
        code.check_validity(Flags::NONE, &parsed).ok()
    }

    /// `true` only if the peer of `fd` currently satisfies `requirement`.
    pub(super) fn verify_peer(fd: RawFd, requirement: &str) -> bool {
        check(fd, requirement).is_some()
    }
}

#[cfg(test)]
mod tests {
    use std::os::fd::{AsRawFd, RawFd};
    use std::os::unix::net::UnixStream;

    use super::super::listener::ControlChannel;
    use super::{CodeSignatureVerifier, PeerVerifier, PROVIDER_REQUIREMENT, PROVIDER_TEAM_ID};

    #[test]
    fn unsigned_peer_is_rejected() {
        let (a, _b) = UnixStream::pair().unwrap();
        assert!(!CodeSignatureVerifier::default().verify(a.as_raw_fd()));
    }

    #[test]
    fn malformed_requirement_is_rejected() {
        let (a, _b) = UnixStream::pair().unwrap();
        assert!(
            !CodeSignatureVerifier::with_requirement("this is not a requirement")
                .verify(a.as_raw_fd())
        );
    }

    #[tokio::test]
    async fn control_channel_exposes_a_valid_fd() {
        let (a, _b) = tokio::net::UnixStream::pair().unwrap();
        let raw = a.as_raw_fd();
        let channel = ControlChannel::from_stream(a);
        assert!(channel.as_raw_fd() >= 0);
        assert_eq!(channel.as_raw_fd(), raw);
    }

    /// The requirement string is a wire contract with the Swift `PeerAuth`; a
    /// silent edit here would make every real provider fail verification.
    #[test]
    fn provider_requirement_matches_the_swift_constant() {
        assert_eq!(
            PROVIDER_REQUIREMENT,
            "anchor apple generic and certificate leaf[subject.OU] = \"995PCLM9KH\""
        );
    }

    /// **CS-AC18.** The production verifier reports the team its requirement pins.
    #[test]
    fn default_verifier_pins_the_provider_team() {
        assert_eq!(
            CodeSignatureVerifier::default().team_id(),
            Some("995PCLM9KH".to_string())
        );
    }

    /// **CS-AC18.** An arbitrary requirement need not pin a team, and the verifier
    /// must not guess one by parsing it.
    #[test]
    fn custom_requirement_pins_no_team() {
        assert_eq!(
            CodeSignatureVerifier::with_requirement("identifier \"x\"").team_id(),
            None
        );
    }

    /// **CS-AC18.** The constant cannot drift from the requirement it describes.
    #[test]
    fn team_id_constant_matches_the_requirement() {
        assert!(PROVIDER_REQUIREMENT.contains(PROVIDER_TEAM_ID));
    }

    /// **CS-AC18.** `team_id` is additive with a `None` default; an implementor
    /// that only writes `verify` (its signature unchanged) still compiles.
    #[test]
    fn team_id_defaults_to_none() {
        struct Bare;
        impl PeerVerifier for Bare {
            fn verify(&self, _fd: RawFd) -> bool {
                false
            }
        }
        assert_eq!(Bare.team_id(), None);
    }

    /// The signing identifier the linker stamped on this very test binary (an
    /// arm64 macOS executable is always ad-hoc, linker-signed with its file name as
    /// identifier). Lets a test build a requirement the peer really does satisfy.
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    fn own_signing_identifier() -> String {
        let exe = std::env::current_exe().unwrap();
        exe.file_name().unwrap().to_str().unwrap().to_owned()
    }

    /// Positive control: both `false` tests above are vacuous unless the verifier
    /// can ever say `true`. A `UnixStream::pair()` peer is this process, so a
    /// requirement naming this binary's own identifier must be accepted by the full
    /// path (peer token, `SecCode` resolution, requirement parse, validity check).
    #[test]
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    fn peer_satisfying_the_requirement_is_accepted() {
        let (a, _b) = UnixStream::pair().unwrap();
        let req = format!("identifier \"{}\"", own_signing_identifier());
        assert!(CodeSignatureVerifier::with_requirement(req).verify(a.as_raw_fd()));
    }

    /// The other half of the control: a well-formed requirement the peer does not
    /// satisfy is rejected, so acceptance above is the requirement matching, not the
    /// verifier accepting everything.
    #[test]
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    fn peer_not_satisfying_a_valid_requirement_is_rejected() {
        let (a, _b) = UnixStream::pair().unwrap();
        let req = format!("identifier \"not-{}\"", own_signing_identifier());
        assert!(!CodeSignatureVerifier::with_requirement(req).verify(a.as_raw_fd()));
    }
}
