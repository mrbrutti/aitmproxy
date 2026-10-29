//! M4 Task 2: the F1 identity surface — `Frontend::Operator`, the optional
//! client label on `CommandHost`, and the `AgentPolicy` enum. No behavior
//! change yet (enforcement is Task 4); these assert the type surface exists and
//! round-trips.

use aitm_core::{
    AgentPolicy, CommandHost, Frontend, HttpFlow, HttpRequest, MemFlowStore, ProxyClient, StdGuard,
};
use futures::future::BoxFuture;

/// Compiles only if `T: Copy`.
fn assert_copy<T: Copy>() {}

/// A `ProxyClient` stub: the host needs one, but nothing here calls it.
struct StubClient;

impl ProxyClient for StubClient {
    fn send(&self, _req: HttpRequest) -> BoxFuture<'_, anyhow::Result<HttpFlow>> {
        Box::pin(async { anyhow::bail!("stub client") })
    }
}

#[test]
fn frontend_operator_is_distinct() {
    // The three roles are mutually distinct.
    assert_ne!(Frontend::Operator, Frontend::Mcp);
    assert_ne!(Frontend::Operator, Frontend::Cli);
    assert_ne!(Frontend::Mcp, Frontend::Cli);

    // Adding the variant did not cost `Frontend` its `Copy`-ness.
    assert_copy::<Frontend>();
    let role = Frontend::Operator;
    let also = role; // a move here would fail to compile without Copy
    assert_eq!(role, also);
}

#[test]
fn client_label_round_trips() {
    let store = MemFlowStore::new();
    let guard = StdGuard::default();
    let client = StubClient;

    // Absent by default.
    let host = CommandHost::new(&store, &client, &guard, None);
    assert_eq!(host.client_label(), None);

    // Set and read back.
    let host = host.with_client_label("aitm-mac");
    assert_eq!(host.client_label(), Some("aitm-mac"));

    // Setting the label leaves the role untouched (default Mcp).
    assert_eq!(host.frontend(), Frontend::Mcp);
}

#[test]
fn agent_policy_is_copy_and_distinct() {
    assert_copy::<AgentPolicy>();

    let all = [
        AgentPolicy::All,
        AgentPolicy::Auto,
        AgentPolicy::Ask,
        AgentPolicy::ReadOnly,
        AgentPolicy::Paused,
    ];
    // Every pair of distinct variants compares unequal.
    for (i, a) in all.iter().enumerate() {
        for (j, b) in all.iter().enumerate() {
            assert_eq!(i == j, a == b, "{a:?} vs {b:?}");
        }
    }
}
