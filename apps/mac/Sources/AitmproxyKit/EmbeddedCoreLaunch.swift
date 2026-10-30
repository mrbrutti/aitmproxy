import AitmBusClient
import Darwin
import Foundation
import Security

/// The pure building blocks the embedded-core manager (Task 6) spawns a child
/// `aitm` with: a per-launch bus token, a free proxy port, the `0600` config the
/// child reads, and the rendezvous-file parse that turns the core's published
/// bus address into a `BusEndpoint`.
///
/// Everything here is pure and side-effect-contained (a socket probe, a file
/// write) so it is testable without a real bundle or a live core; the actor that
/// owns the `Process` lives in the app target and is covered by the live
/// self-test (Task 9).
public enum EmbeddedCoreLaunch {
    // MARK: Teardown budgets

    /// The obscura teardown budget (in whole seconds) the generated config asks
    /// the embedded core for (`browser.obscura.stop_timeout`). The core's own
    /// quit budget is this plus a 1 s reap margin (`crates/aitm/src/main.rs`), so
    /// keeping it small bounds how long the core needs after `SIGTERM`.
    public static let obscuraStopTimeoutSeconds = 2

    /// The Swift-side `SIGTERM` → `SIGKILL` grace (in whole seconds) the embedded
    /// core manager waits before force-killing the child. It MUST exceed the
    /// core's whole obscura teardown budget (`obscuraStopTimeoutSeconds` + the
    /// core's 1 s reap margin) so a clean `SIGTERM` is always enough and `SIGKILL`
    /// never lands mid-teardown and orphans obscura (AC7).
    public static let childStopGraceSeconds = 5

    // MARK: Token

    /// A fresh 256-bit bus token, rendered as lower-case hex, drawn from the
    /// system CSPRNG. Generated once per launch, never persisted or logged — it
    /// lives only in the child's `0600` config and in the app's memory.
    public static func freshToken() -> String {
        var bytes = [UInt8](repeating: 0, count: 32)
        let status = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
        precondition(status == errSecSuccess, "the system CSPRNG failed to produce a bus token")
        return bytes.map { String(format: "%02x", $0) }.joined()
    }

    // MARK: Free-port probe

    /// Whether a TCP port on `host` can be bound right now — i.e. nothing is
    /// already listening on it. Binds without address reuse (as the real proxy
    /// does) and closes immediately, so a `true` means the port was free at the
    /// instant of the probe.
    public static func isPortFree(_ port: UInt16, host: String = "127.0.0.1") -> Bool {
        let fd = socket(AF_INET, SOCK_STREAM, 0)
        guard fd >= 0 else { return false }
        defer { close(fd) }
        var addr = sockaddr_in()
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = port.bigEndian
        addr.sin_addr.s_addr = inet_addr(host)
        let bound = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        return bound == 0
    }

    /// An OS-assigned free port on `host`: bind `:0`, read back the chosen port,
    /// release it. The caller races to claim it before anyone else — acceptable
    /// because the child does the real bind and the manager retries on failure.
    public static func anyFreePort(host: String = "127.0.0.1") -> UInt16? {
        let fd = socket(AF_INET, SOCK_STREAM, 0)
        guard fd >= 0 else { return nil }
        defer { close(fd) }
        var addr = sockaddr_in()
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = 0
        addr.sin_addr.s_addr = inet_addr(host)
        let bound = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        guard bound == 0 else { return nil }
        var out = sockaddr_in()
        var len = socklen_t(MemoryLayout<sockaddr_in>.size)
        let named = withUnsafeMutablePointer(to: &out) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                getsockname(fd, $0, &len)
            }
        }
        guard named == 0 else { return nil }
        return UInt16(bigEndian: out.sin_port)
    }

    /// The proxy port to launch on: `preferred` when it is free, otherwise an
    /// auto-chosen alternate (AC9). `nil` only if no port can be probed at all.
    public static func pickProxyPort(preferred: UInt16, host: String = "127.0.0.1") -> UInt16? {
        if preferred != 0, isPortFree(preferred, host: host) { return preferred }
        return anyFreePort(host: host)
    }

    // MARK: Restart backoff

    /// What to do after an unexpected child exit: back off and retry, or give up.
    public enum RestartDecision: Equatable, Sendable {
        /// Respawn after this exponential-backoff delay.
        case retry(after: Duration)
        /// The cap is reached — stop retrying and report `.degraded`.
        case giveUp
    }

    /// The restart decision for the `restarts`-th unexpected child exit (1-based):
    /// give up once `restarts` exceeds `maxRestarts`, otherwise retry after an
    /// exponential backoff `base * 2^(restarts - 1)` capped at `cap`. Pure, so the
    /// backoff schedule and the give-up boundary are unit-tested without spawning a
    /// process (AC8).
    public static func restartDecision(
        restarts: Int, maxRestarts: Int, base: Duration, cap: Duration
    ) -> RestartDecision {
        guard restarts <= maxRestarts else { return .giveUp }
        // Clamp the shift so `1 << shift` can never overflow if `maxRestarts` is
        // raised far in the future; at today's cap the backoff saturates long first.
        let shift = min(max(restarts - 1, 0), 16)
        return .retry(after: min(base * (1 << shift), cap))
    }

    /// The `.degraded` detail surfaced when restarts are exhausted: the failure
    /// `reason` followed by the last `tailLines` captured stderr lines (AC8), so an
    /// operator sees why the core gave up. Pure and unit-tested.
    public static func giveUpDetail(reason: String, logTail: [String], tailLines: Int) -> String {
        let tail = logTail.suffix(tailLines).joined(separator: "\n")
        return tail.isEmpty ? reason : "\(reason)\n\(tail)"
    }

    // MARK: Rendezvous-file parse

    /// Builds a `BusEndpoint` from the core's rendezvous file (Task 3): its
    /// contents are the bound bus `host:port` on one line, token-free, as
    /// `SocketAddr` prints it (`127.0.0.1:50512\n`). Pairs that address with the
    /// token the app already holds. Returns `nil` while the file is empty or
    /// half-written (no line yet, or not a valid `host:port`), so a watcher can
    /// keep polling until the core has published.
    public static func parseEndpoint(fromFileContents contents: String, token: String) -> BusEndpoint? {
        let line = contents.split(whereSeparator: \.isNewline).first.map(String.init)?
            .trimmingCharacters(in: .whitespaces) ?? ""
        guard let colon = line.lastIndex(of: ":") else { return nil }
        let host = String(line[..<colon])
        // The embedded core always binds loopback; a non-loopback host means a
        // tampered or stale rendezvous file and must never be dialed (S4).
        guard !host.isEmpty, isLoopbackHost(host),
              let port = UInt16(line[line.index(after: colon)...]) else { return nil }
        return BusEndpoint(host: host, port: port, token: token)
    }

    /// Whether `host` (as a rendezvous file writes it) is a loopback address: the
    /// only hosts the embedded core is ever reached on. IPv6 is accepted both bare
    /// (`::1`) and bracketed (`[::1]`) as `SocketAddr` prints it.
    static func isLoopbackHost(_ host: String) -> Bool {
        let bare = host.hasPrefix("[") && host.hasSuffix("]") ? String(host.dropFirst().dropLast()) : host
        return bare == "127.0.0.1" || bare == "::1" || bare == "localhost"
    }

    // MARK: Per-launch config

    /// Everything the child `aitm` needs to come up as a self-contained embedded
    /// core: a loopback bus on an ephemeral port carrying `token`, a proxy and
    /// browser-proxy on the chosen ports, the rendezvous file to publish its
    /// bound bus address to, and the bundled `obscura` beside it. Renders the
    /// `config.yaml` the binary reads via `--config`.
    public struct Config: Sendable {
        /// The bundled browser engine, passed explicitly as belt-and-braces even
        /// though co-location already lets the core discover it.
        public var obscuraBinary: URL
        public var proxyPort: UInt16
        public var browserProxyPort: UInt16
        /// The agent bus token (`mcp.transport.loopback_tcp.token`): a connection
        /// presenting it is classified `Frontend::Mcp`. The app does NOT connect
        /// with this — it is required by the loopback transport and left for an
        /// autonomous agent that may attach later.
        public var token: String
        /// The operator bus token (`mcp.operator_token`): a connection presenting
        /// it is classified `Frontend::Operator`, a present human. The app connects
        /// with THIS token so its Scope panel can widen scope at runtime (the core
        /// lets an operator widen; agents stay gated). Distinct from `token`.
        public var operatorToken: String
        public var endpointFile: URL
        /// When true, emit `upstream.ssl_insecure: true` so the proxy accepts any
        /// upstream certificate (operator opt-in from Settings ▸ Proxy; a footgun
        /// for reaching self-signed servers, never for untrusted networks).
        public var sslInsecure: Bool

        public init(
            obscuraBinary: URL,
            proxyPort: UInt16,
            browserProxyPort: UInt16,
            token: String,
            operatorToken: String,
            endpointFile: URL,
            sslInsecure: Bool = false
        ) {
            self.obscuraBinary = obscuraBinary
            self.proxyPort = proxyPort
            self.browserProxyPort = browserProxyPort
            self.token = token
            self.operatorToken = operatorToken
            self.endpointFile = endpointFile
            self.sslInsecure = sslInsecure
        }

        /// The `config.yaml` body. The bus binds `port: 0` (ephemeral, so it
        /// never collides) and publishes its resolved address to `endpoint_file`;
        /// the token and both paths are double-quoted so hex/paths never trip the
        /// YAML parser. The curated default log level comes from the core itself
        /// (Task 3) when `RUST_LOG` is unset, so it is not configured here.
        ///
        /// `obscura.stop_timeout` is pinned small (so the core's whole teardown
        /// budget stays under the Swift-side `SIGKILL` grace — AC7), and both paths
        /// are escaped for a double-quoted YAML scalar so a path with a quote or
        /// backslash cannot break the file; a path with a newline is rejected.
        ///
        /// `mcp.operator_token` is emitted alongside the agent token so the app can
        /// connect as a present human (`Frontend::Operator`) and widen scope from
        /// its Scope panel; no `scope:` block is emitted, so startup scope stays
        /// deny-by-default/empty and agents remain gated.
        public func yaml() throws -> String {
            let obscuraPath = try EmbeddedCoreLaunch.yamlDoubleQuoted(obscuraBinary.path)
            let endpointPath = try EmbeddedCoreLaunch.yamlDoubleQuoted(endpointFile.path)
            let base = """
            listen: "127.0.0.1:\(proxyPort)"
            mcp:
              transport:
                loopback_tcp:
                  port: 0
                  token: "\(token)"
                  endpoint_file: "\(endpointPath)"
              operator_token: "\(operatorToken)"
            browser:
              proxy_addr: "127.0.0.1:\(browserProxyPort)"
              obscura:
                binary: "\(obscuraPath)"
                stop_timeout: \(EmbeddedCoreLaunch.obscuraStopTimeoutSeconds)
            """
            // `ssl_insecure` is a top-level config key (sibling of `listen`); the core's
            // `deny_unknown_fields` rejects any wrapper object, so it must stay unindented.
            // Emitted only when the operator opts out of upstream TLS verification.
            return sslInsecure ? base + "\nssl_insecure: true\n" : base
        }
    }

    /// Something is wrong with a value spliced into the generated config.
    public enum ConfigError: Error, Equatable {
        /// A path carried a newline, which would break out of its YAML scalar.
        case pathContainsNewline(String)
    }

    /// Escapes a filesystem path for embedding inside a double-quoted YAML scalar:
    /// backslashes and double-quotes are backslash-escaped. A path containing a
    /// newline (`\n` or `\r`) is rejected — a newline cannot be represented inside
    /// a double-quoted scalar on one line, and allowing it would let a crafted path
    /// inject arbitrary YAML (S3). Returns the inner text to splice between quotes.
    static func yamlDoubleQuoted(_ path: String) throws -> String {
        guard !path.contains("\n"), !path.contains("\r") else {
            throw ConfigError.pathContainsNewline(path)
        }
        return path
            .replacingOccurrences(of: "\\", with: "\\\\")
            .replacingOccurrences(of: "\"", with: "\\\"")
    }

    /// Writes the per-launch config to `url` with mode `0600` and no window in
    /// which it is readable by anyone else: the file is created restricted via
    /// `open(…, 0o600)` and re-enforced with `fchmod`, so the bus token it
    /// carries never sits in a world- or group-readable file.
    public static func writeConfig(_ yaml: String, to url: URL) throws {
        // O_NOFOLLOW: never write through a symlink planted at the config path, so
        // a pre-seeded link can't redirect the token-bearing file elsewhere (S2).
        let fd = open(url.path, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW, 0o600)
        guard fd >= 0 else {
            throw CocoaError(.fileWriteUnknown, userInfo: [NSFilePathErrorKey: url.path])
        }
        defer { close(fd) }
        // A pre-existing file keeps its old mode through O_TRUNC; pin it to 0600.
        _ = fchmod(fd, 0o600)
        let data = Data(yaml.utf8)
        try data.withUnsafeBytes { raw -> Void in
            guard var cursor = raw.baseAddress else { return }
            var remaining = raw.count
            while remaining > 0 {
                let written = write(fd, cursor, remaining)
                if written <= 0 {
                    throw CocoaError(.fileWriteUnknown, userInfo: [NSFilePathErrorKey: url.path])
                }
                remaining -= written
                cursor = cursor.advanced(by: written)
            }
        }
    }
}
