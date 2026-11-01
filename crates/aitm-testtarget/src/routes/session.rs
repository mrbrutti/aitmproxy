//! Filled by Task A15 (routes/session.rs); Task A5 left the dispatch stub and
//! the [`SessionStore`] skeleton the router and `/ws` already hold.

use std::sync::Arc;

use crate::app::{AppState, RequestInfo, Resp};

/// Login sessions minted by `POST /login` and checked by `/account?tab=`,
/// `/logout-after` and the `/ws` handshake. Skeleton: no session is ever valid
/// until A15 fills it.
pub(crate) struct SessionStore {
    _sealed: (),
}

impl SessionStore {
    pub(crate) fn new() -> Self {
        SessionStore { _sealed: () }
    }

    /// Whether `id` names a live session. Always false until A15.
    #[allow(dead_code)] // A15/A17 consume this
    pub(crate) fn is_valid(&self, _id: &str) -> bool {
        false
    }
}

/// Not yet routed: Task A15 fills this. `None` lets the router fall through.
pub(crate) async fn route(_info: &RequestInfo, _state: &Arc<AppState>) -> Option<Resp> {
    None
}
