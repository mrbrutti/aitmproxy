//! Filled by Task A13 (routes/inject.rs); Task A5 left the dispatch stub.

use std::sync::Arc;

use crate::app::{AppState, RequestInfo, Resp};

/// Not yet routed: Task A13 (routes/inject.rs) fills this. `None` lets the router fall through.
pub(crate) async fn route(_info: &RequestInfo, _state: &Arc<AppState>) -> Option<Resp> {
    None
}
