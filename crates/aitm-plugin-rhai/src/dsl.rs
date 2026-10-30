//! The `dsl` prelude helper namespace: ten flat, pure global functions the Rhai
//! catalogue (`docs/design/languages/rhai.api.json`, `dsl[]`) advertises —
//! `b64_encode`, `b64_decode`, `url_encode`, `hex_encode`, `sha256`, `md5`,
//! `rand_text_alpha`, `rand_int`, `regex_match`, `regex_extract`.
//!
//! They are the everyday payload-shaping vocabulary (encode / hash / match /
//! random) a script or a PoC Rhai `script:` step reaches for. Each is a **pure**
//! function of its arguments (plus a process-lifetime RNG for the `rand_*`
//! pair): they touch no network, store, scope, browser, clock, or filesystem,
//! so — unlike the guarded host namespaces — they are deliberately **not**
//! routed through `ScopeRateGuard` or the SSRF check. Deny-by-default is
//! unaffected because nothing here reaches outside the engine.
//!
//! Registered as unqualified global functions (`b64_encode(s)`, not
//! `dsl.b64_encode(s)`) through the M3 [`ScriptCapability`] seam, so every
//! first-party namespace stays in one list and carries a `min_api`.

use base64::Engine as _;
use rhai::{Dynamic, Engine, EvalAltResult, Position};
use sha2::Digest as _;

use crate::host_core::{ScriptCapability, ScriptServices};

/// The `dsl` namespace capability: a pure helper set, always offered (like
/// `log`), needing no [`ScriptServices`]. Deny-by-default does not apply because
/// these helpers add no ambient authority.
#[derive(Debug, Clone, Copy, Default)]
pub struct DslCapability;

impl ScriptCapability for DslCapability {
    fn namespace(&self) -> &str {
        "dsl"
    }

    fn min_api(&self) -> &str {
        "1"
    }

    fn register(&self, engine: &mut Engine, _services: &ScriptServices) {
        register_dsl(engine);
    }
}

/// Register the ten `dsl` helpers onto `engine` as flat global functions. Split
/// from [`DslCapability`] so the behaviour tests can exercise the pure helpers on
/// a bare [`crate::engine::build_engine`] without assembling a store / client /
/// guard.
pub fn register_dsl(engine: &mut Engine) {
    // --- Encoding family ----------------------------------------------------
    engine.register_fn("b64_encode", |s: &str| -> String {
        base64::engine::general_purpose::STANDARD.encode(s.as_bytes())
    });
    engine.register_fn(
        "b64_decode",
        |s: &str| -> Result<String, Box<EvalAltResult>> {
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(s.as_bytes())
                .map_err(|e| dsl_error(format!("b64_decode: invalid base64: {e}")))?;
            // Never return a lossy/corrupted string: non-UTF-8 bytes are a
            // catchable error, not silently mangled.
            String::from_utf8(bytes).map_err(|e| {
                dsl_error(format!(
                    "b64_decode: decoded bytes are not valid UTF-8: {e}"
                ))
            })
        },
    );
    // Parity with `aitm_poc::dsl::url_encode`: RFC 3986 unreserved set, uppercase
    // hex. Shared so the two surfaces never drift.
    engine.register_fn("url_encode", |s: &str| -> String {
        aitm_poc::dsl::url_encode(s)
    });
    engine.register_fn("hex_encode", |s: &str| -> String { to_hex(s.as_bytes()) });

    // --- Hashing family -----------------------------------------------------
    engine.register_fn("sha256", |s: &str| -> String {
        to_hex(&sha2::Sha256::digest(s.as_bytes()))
    });
    // MD5 is a legacy, cryptographically broken digest; it is provided only
    // because target applications still use it, never as a security primitive.
    engine.register_fn("md5", |s: &str| -> String {
        to_hex(&md5::Md5::digest(s.as_bytes()))
    });

    // --- Random family ------------------------------------------------------
    // Non-cryptographic: the shared thread-local xorshift, for unique markers,
    // not secrets.
    engine.register_fn("rand_text_alpha", |n: i64| -> String {
        aitm_poc::dsl::rand_text_alpha(n.max(0) as usize)
    });
    engine.register_fn(
        "rand_int",
        |a: i64, b: i64| -> Result<i64, Box<EvalAltResult>> {
            // Inclusive `[a, b]`; a reversed range is a script bug, surfaced as a
            // catchable error rather than silently swapped (the `aitm-poc` helper
            // is total/order-insensitive; this layer owns the policy).
            if a > b {
                return Err(dsl_error(format!(
                    "rand_int: start ({a}) must not be greater than end ({b})"
                )));
            }
            Ok(aitm_poc::dsl::rand_int(a, b))
        },
    );

    // --- Regex family -------------------------------------------------------
    engine.register_fn(
        "regex_match",
        |pat: &str, s: &str| -> Result<bool, Box<EvalAltResult>> {
            // An invalid pattern is a script defect: error, never a silent false.
            let re = regex::Regex::new(pat)
                .map_err(|e| dsl_error(format!("regex_match: invalid pattern: {e}")))?;
            Ok(re.is_match(s))
        },
    );
    engine.register_fn(
        "regex_extract",
        |pat: &str, s: &str, group: i64| -> Result<String, Box<EvalAltResult>> {
            let re = regex::Regex::new(pat)
                .map_err(|e| dsl_error(format!("regex_extract: invalid pattern: {e}")))?;
            // Ergonomic nuclei-style: no match, a group that did not participate,
            // or an out-of-range / negative group index all yield "". Only a bad
            // pattern errors.
            let extracted = re
                .captures(s)
                .and_then(|caps| usize::try_from(group).ok().and_then(|g| caps.get(g)))
                .map(|m| m.as_str().to_string())
                .unwrap_or_default();
            Ok(extracted)
        },
    );
}

/// Lowercase hex of raw bytes. Shared by `hex_encode` and the two hashers; four
/// lines, so no new crate for it.
fn to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

/// A catchable runtime error; the engine fills in the call position.
fn dsl_error(message: impl Into<String>) -> Box<EvalAltResult> {
    EvalAltResult::ErrorRuntime(Dynamic::from(message.into()), Position::NONE).into()
}
