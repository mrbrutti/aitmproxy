//! Session profile (names only) and in-memory session material (spec D7). Task 6 of the T1a plan owns this file.
//!
//! The scanner reuses an observed session by replaying the cookies and secret
//! headers of a captured in-scope flow. The *values* live only in the worker's
//! memory as a [`SessionMaterial`]; nothing on the wire — no verb result, push,
//! issue, PoC or log — ever carries a value. The only bridge from material to a
//! wire type is [`SessionMaterial::names`], which drops every value and keeps the
//! names, producing a [`SessionProfile`] (spec D7's anti-goal "no result carries
//! session material").

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::ids::FlowRef;

/// The HTTP method an auth-lost canary replays with. GET or HEAD only, never a
/// body (spec D7): a canary must not mutate state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum CanaryMethod {
    /// `GET`.
    Get,
    /// `HEAD`.
    Head,
}

/// The auth-lost canary (spec D5 status and D7 session profile share this type).
///
/// Kind-tagged on the wire: `{"kind":"none"}` when auth-lost detection is off,
/// `{"kind":"flow", ...}` when a `GET`/`HEAD` flow carrying the session material
/// is replayed every 25 probes to detect a session that stopped working.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Canary {
    /// No eligible flow: auth-lost detection is off.
    #[default]
    None,
    /// Replay this flow's method and path to check the session still works.
    Flow {
        /// The canary's method (`GET` or `HEAD`).
        method: CanaryMethod,
        /// The canary's path.
        path: String,
        /// The status the canary's response is expected to carry, when known.
        #[serde(default)]
        expected_status: Option<u16>,
    },
}

/// A session, on the wire as **names only** (spec D7). Cookies and headers are the
/// names observed on the source flow; their values never leave the worker's memory.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct SessionProfile {
    /// The origin (`scheme://host[:port]`) the session authenticates to.
    pub origin: String,
    /// The names of the session cookies (never their values).
    pub cookies: Vec<String>,
    /// The names of the secret headers (never their values).
    pub headers: Vec<String>,
    /// The captured flow the session was lifted from, when known.
    #[serde(default)]
    pub source_flow: Option<FlowRef>,
    /// When the session was observed (epoch milliseconds).
    pub observed_at: u64,
    /// The auth-lost canary derived for this session.
    pub canary: Canary,
}

/// The session's live cookie and header **values**, held only in the worker's
/// memory for the life of a job (spec D7).
///
/// This type deliberately has **no** `Serialize`/`Deserialize`: it can never
/// reach the wire. Its `Debug` prints names and `<redacted>` in place of every
/// value, so a value cannot leak through a log line either. The only way its
/// contents become a wire type is [`SessionMaterial::names`], which keeps the
/// names and drops the values.
#[derive(Clone)]
pub struct SessionMaterial {
    /// `(name, value)` for every session cookie.
    pub cookies: Vec<(String, String)>,
    /// `(name, value)` for every secret header.
    pub headers: Vec<(String, String)>,
}

impl SessionMaterial {
    /// Drop every value and keep the names, producing the wire [`SessionProfile`].
    ///
    /// This is the *only* path from in-memory material to a serializable type.
    pub fn names(
        &self,
        origin: &str,
        source_flow: Option<FlowRef>,
        observed_at: u64,
        canary: Canary,
    ) -> SessionProfile {
        SessionProfile {
            origin: origin.to_string(),
            cookies: self.cookies.iter().map(|(name, _)| name.clone()).collect(),
            headers: self.headers.iter().map(|(name, _)| name.clone()).collect(),
            source_flow,
            observed_at,
            canary,
        }
    }
}

impl fmt::Debug for SessionMaterial {
    /// Print names only; every value is `<redacted>` so a value cannot leak.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let redact = |pairs: &[(String, String)]| -> Vec<String> {
            pairs
                .iter()
                .map(|(name, _)| format!("{name}=<redacted>"))
                .collect()
        };
        f.debug_struct("SessionMaterial")
            .field("cookies", &redact(&self.cookies))
            .field("headers", &redact(&self.headers))
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canary_wire_shapes() {
        assert_eq!(
            serde_json::to_string(&Canary::None).expect("serializes"),
            r#"{"kind":"none"}"#
        );
        let flow = Canary::Flow {
            method: CanaryMethod::Get,
            path: "/account".into(),
            expected_status: None,
        };
        let json = serde_json::to_string(&flow).expect("serializes");
        assert!(json.contains(r#""method":"GET""#), "got {json}");
        assert_eq!(
            serde_json::from_str::<Canary>(&json).expect("round trips"),
            flow
        );
        assert_eq!(
            serde_json::from_str::<Canary>(r#"{"kind":"none"}"#).expect("parses"),
            Canary::None
        );
    }

    #[test]
    fn session_material_debug_redacts_values() {
        let material = SessionMaterial {
            cookies: vec![("sid".into(), "s3cr3t".into())],
            headers: vec![("authorization".into(), "Bearer abc".into())],
        };
        let shown = format!("{material:?}");
        assert!(shown.contains("sid"), "names kept: {shown}");
        assert!(shown.contains("authorization"), "names kept: {shown}");
        assert!(shown.contains("<redacted>"), "values redacted: {shown}");
        assert!(!shown.contains("s3cr3t"), "cookie value leaked: {shown}");
        assert!(
            !shown.contains("Bearer abc"),
            "header value leaked: {shown}"
        );
    }

    #[test]
    fn session_material_names_only() {
        let material = SessionMaterial {
            cookies: vec![("sid".into(), "s3cr3t".into())],
            headers: vec![("authorization".into(), "Bearer abc".into())],
        };
        let profile = material.names("http://t", None, 0, Canary::None);
        assert_eq!(profile.cookies, vec!["sid".to_string()]);
        assert_eq!(profile.headers, vec!["authorization".to_string()]);

        let json = serde_json::to_string(&profile).expect("serializes");
        assert!(!json.contains("s3cr3t"), "value leaked to the wire: {json}");
        assert!(
            !json.contains("Bearer abc"),
            "value leaked to the wire: {json}"
        );
    }
}
