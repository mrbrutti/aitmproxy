//! The `aitm` binary: build the proxy from config, then run the accept loop plus
//! the selected MCP transport, or dispatch a one-shot CLI command.
//!
//! Invoked with a subcommand (`aitm flow list`, `aitm scope add --host ex.test`)
//! it dispatches once over the CLI frontend and exits. Invoked bare it starts the
//! proxy accept loop and the MCP server (stdio or loopback-TCP per config). M1
//! uses `Config::default()`; reading a config file is a later wave.

use std::sync::Arc;

use aitm::wire::{build_proxy, TcpRequestSender};
use aitm_core::{Config, PipelineClient, ProxyClient};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cfg = Config::default();
    let proxy = build_proxy(&cfg)?;

    // Shared service handles for the frontends and the replay client.
    let registry = proxy.registry_arc();
    let store = proxy.store();
    let guard = proxy.guard();
    let client: Arc<dyn ProxyClient> = Arc::new(PipelineClient::new(
        store.clone(),
        guard.clone(),
        Arc::new(TcpRequestSender),
    ));

    let argv: Vec<String> = std::env::args().skip(1).collect();
    if !argv.is_empty() {
        // One-shot CLI dispatch.
        let cli = aitm_cli::Cli::new(registry.clone()).with_services(
            store.clone(),
            client.clone(),
            guard.clone(),
            None,
        );
        match cli.dispatch(&argv) {
            Ok(value) => {
                println!("{value:?}");
                return Ok(());
            }
            Err(err) => {
                eprintln!("{err}");
                std::process::exit(1);
            }
        }
    }

    // Otherwise, run the proxy accept loop alongside the MCP server.
    let mcp = aitm_mcp::McpServer::new(registry, cfg.mcp.transport.clone()).with_services(
        store, client, guard,
        // The live browser driver attaches once Chromium is available (Task 29).
        None,
    );

    let listen = cfg.listen;
    tokio::select! {
        result = proxy.run(listen) => result,
        result = mcp.serve() => result,
    }
}
