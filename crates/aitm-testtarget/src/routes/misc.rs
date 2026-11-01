//! Filled by Task A16 (routes/misc.rs); Task A5 left the dispatch stub.

use std::sync::Arc;

use crate::app::{AppState, RequestInfo, Resp};

/// Not yet routed: Task A16 (routes/misc.rs) fills this. `None` lets the router fall through.
pub(crate) async fn route(_info: &RequestInfo, _state: &Arc<AppState>) -> Option<Resp> {
    None
}
