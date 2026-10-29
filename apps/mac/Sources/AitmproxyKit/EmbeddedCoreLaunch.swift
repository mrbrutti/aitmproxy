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
        guard !host.isEmpty, let port = UInt16(line[line.index(after: colon)...]) else { return nil }
        return BusEndpoint(host: host, port: port, token: token)
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
        public var token: String
        public var endpointFile: URL

        public init(
            obscuraBinary: URL,
            proxyPort: UInt16,
            browserProxyPort: UInt16,
            token: String,
            endpointFile: URL
        ) {
            self.obscuraBinary = obscuraBinary
            self.proxyPort = proxyPort
            self.browserProxyPort = browserProxyPort
            self.token = token
            self.endpointFile = endpointFile
        }

        /// The `config.yaml` body. The bus binds `port: 0` (ephemeral, so it
        /// never collides) and publishes its resolved address to `endpoint_file`;
        /// the token and both paths are double-quoted so hex/paths never trip the
        /// YAML parser. The curated default log level comes from the core itself
        /// (Task 3) when `RUST_LOG` is unset, so it is not configured here.
        public func yaml() -> String {
            """
            listen: "127.0.0.1:\(proxyPort)"
            mcp:
              transport:
                loopback_tcp:
                  port: 0
                  token: "\(token)"
                  endpoint_file: "\(endpointFile.path)"
            browser:
              proxy_addr: "127.0.0.1:\(browserProxyPort)"
              obscura:
                binary: "\(obscuraBinary.path)"
            """
        }
    }

    /// Writes the per-launch config to `url` with mode `0600` and no window in
    /// which it is readable by anyone else: the file is created restricted via
    /// `open(…, 0o600)` and re-enforced with `fchmod`, so the bus token it
    /// carries never sits in a world- or group-readable file.
    public static func writeConfig(_ yaml: String, to url: URL) throws {
        let fd = open(url.path, O_WRONLY | O_CREAT | O_TRUNC, 0o600)
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
