import Foundation

/// The fact that the embedded core bound a port other than the one the operator asked for.
///
/// When the preferred listen port (8080 by default) is busy at launch or at Restart Core, `EmbeddedCore.spawn()`
/// picks a free one and the core comes up there. Until this type existed the app showed only a different number
/// in the toolbar pill; in the 0.5.18 acceptance run the operator saw nothing until a hand killed the stray
/// process (`docs/testing/2026-11-03-release-acceptance-0.5.18/README.md`, "Incident: the harness took 8080 from
/// the operator's core"). This is the one place the fallback's words live; every surface that names the listener
/// prints them verbatim and composes none of its own
/// (spec `docs/superpowers/specs/2026-11-03-mac-listen-port-fallback-notice-design.md`, D1).
///
/// `CoreConnection.portFallback` derives it from `appliedPort` (preferred) and `proxyAddress` (bound).
public struct ListenPortFallback: Hashable, Sendable {
    /// The port the operator asked for (Settings ▸ Proxy, `proxy.preferredPort`).
    public let preferred: Int
    /// The port the core actually bound.
    public let bound: Int

    public init(preferred: Int, bound: Int) {
        self.preferred = preferred
        self.bound = bound
    }

    /// The one sentence, no trailing full stop (like every lane remedy): the pill's tooltip, Settings ▸ Proxy and
    /// the Getting Started `coreRunning` step's detail all print it as is.
    public var notice: String { "Port \(preferred) was busy; listening on \(bound)" }

    /// The Settings ▸ Proxy button that restarts the embedded core so it tries the preferred port again; title
    /// case like `ConnectionAction.title`.
    public var restartTitle: String { "Restart on \(preferred)" }

    /// The core lane's remedy: the notice, the route-line separator ` — `, and what the lane's primary action does.
    public var remedy: String { notice + " — Restart Core tries \(preferred) again" }

    /// The port after the last `:` of a `host:port` string; nil when there is none or it is not a number
    /// (`"127.0.0.1:8081"` → 8081, `"127.0.0.1"` → nil).
    static func port(from address: String) -> Int? {
        guard let colon = address.lastIndex(of: ":") else { return nil }
        return Int(address[address.index(after: colon)...])
    }
}
