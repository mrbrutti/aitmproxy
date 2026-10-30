import Foundation
import Network
import NetworkExtension
import Security
import os.log

// MARK: - Provider <-> core flow handoff (Band C Task 11, NE-AC6 / NE-AC7)
//
// The provider is the CLIENT; the core (`aitm`) listens. This file is the Swift
// half of `crates/aitm/src/macos_capture/listener.rs` and MUST match it byte for
// byte. Spec D3: one control socket (metadata only) plus one data socket per flow,
// both Unix domain sockets inside a core-owned 0700 directory.
//
// SECURITY MODEL (the crux): this process runs as ROOT and sees the user's
// plaintext. A 0700 directory only keeps OTHER uids out; any process running as
// the core's own uid can still delete/replace `control.sock` or `data.sock`. So the
// directory is not the trust boundary. The boundary is the CODE SIGNATURE of the
// peer, checked on the connected socket (LOCAL_PEERTOKEN -> SecCode -> requirement)
// BEFORE a single flow byte or flow metadata is written:
//   - the control socket is verified before the Hello is sent;
//   - EVERY per-flow data socket is verified before its FlowOpen/handshake/bytes;
//   - any failure closes the socket and the provider FAILS OPEN (returns false, the
//     flow goes direct) -- never "fail closed onto an unverified peer".
// The rendezvous file that names the directory is attacker-influenceable too; that
// is acceptable precisely because the signature check, not the path, is the gate.
//
// FAIL OPEN: no rendezvous / no verified control channel / no Scope yet / no scope
// match / any handoff error  ->  `handleNewFlow` returns false.

// `NetworkExtension` still exports a deprecated ObjC `NWEndpoint` class; the current
// (macOS 15+) flow API speaks `Network.NWEndpoint`. Qualify it once.
typealias FlowNWEndpoint = Network.NWEndpoint

// MARK: - Constants

enum HandoffConfig {
    /// Rendezvous file the CORE (aitm) must write -- WIRING DEPENDENCY, not yet
    /// implemented on the Rust/host side. The sysex runs as root and the core as
    /// the user, so there is no shared home directory; a fixed well-known path is
    /// used instead. `/private/tmp` is the location the Task-1 spike proved the
    /// sysex can reach.
    ///
    /// Format: a single line of UTF-8 -- the ABSOLUTE path of the core's socket
    /// directory (the one `CaptureListener::bind` locked to 0700; it contains
    /// `control.sock` and `data.sock`). A trailing newline is optional. The core
    /// should create the file mode 0600 (it is never group/world-writable), write
    /// it AFTER `CaptureListener::bind` succeeds, and remove it on shutdown.
    /// Validation the provider applies: the path is opened O_NOFOLLOW, must be a
    /// regular file <= 1 KiB with no group/other write bit, must name an absolute
    /// path that fits `sun_path`, and the named directory must be a real
    /// (non-symlink) directory with no group/other access and the same owner uid
    /// as the rendezvous file. These checks only narrow squatting/DoS; the code
    /// signature check is what keeps plaintext from a squatter.
    static let rendezvousPath = "/private/tmp/aitmproxy-capture.rendezvous"

    static let controlSocketName = "control.sock"
    static let dataSocketName = "data.sock"

    /// `Hello.protocol_version`; the core refuses a mismatch.
    static let protocolVersion: UInt32 = 1
    /// Max control-frame body (matches listener.rs `MAX_FRAME_LEN`).
    static let maxControlFrame = 1 << 20
    /// Max datagram body (matches listener.rs `MAX_DATAGRAM_LEN`).
    static let maxDatagram = 64 * 1024
    /// Cap on a single read from the core's data socket toward the app (mitmproxy
    /// precedent is 8 KiB; one bounded chunk at a time keeps memory per flow flat).
    static let maxInboundRead = 16 * 1024
    /// Largest rendezvous file we will read.
    static let maxRendezvousBytes = 1024
    /// Pause between attach attempts while detached.
    static let attachRetrySeconds: Double = 2
    /// A wedged (alive but not reading) core must not stall `handleNewFlow`.
    static let handshakeSendTimeoutSeconds = 2
}

// MARK: - Errors

enum HandoffError: Error, Equatable {
    /// Declared frame length above the cap; rejected BEFORE allocating.
    case frameTooLarge(declared: Int, max: Int)
    /// Peer closed mid-frame.
    case shortRead
    case io(errno: Int32)
    case malformed(String)
    case unavailable(String)
}

// MARK: - Peer authentication (the crux)

enum PeerAuth {
    /// Developer ID team OU that must have signed the core.
    static let coreTeamID = "995PCLM9KH"

    /// Code requirement the core must satisfy. This is deliberately the team-level
    /// requirement the plan specifies: it accepts ANY binary signed by an Apple-
    /// anchored certificate whose leaf subject OU is our team.
    /// TODO(tighten): once aitm's final signing identifier is fixed, narrow this to
    /// its full designated requirement, e.g. append
    /// `and identifier "<aitm signing identifier>"`, so another binary from the same
    /// team (a helper, an old build) cannot impersonate the core.
    static let coreRequirement =
        "anchor apple generic and certificate leaf[subject.OU] = \"\(coreTeamID)\""

    /// Audit token of the process at the other end of a connected UNIX socket.
    /// For a client socket this is the process that owns the listening end.
    static func peerAuditToken(of fd: Int32) -> audit_token_t? {
        var token = audit_token_t()
        var length = socklen_t(MemoryLayout<audit_token_t>.size)
        let rc = getsockopt(fd, SOL_LOCAL, LOCAL_PEERTOKEN, &token, &length)
        guard rc == 0, length == socklen_t(MemoryLayout<audit_token_t>.size) else {
            return nil
        }
        return token
    }

    /// True only if the process identified by `auditToken` currently satisfies
    /// `requirement`. Fails CLOSED: any Security.framework error, an unresolvable
    /// token, an unparseable requirement, or a non-success validity check is false.
    static func verifyPeer(auditToken: audit_token_t,
                           requirement: String = coreRequirement) -> Bool {
        var token = auditToken
        let tokenData = withUnsafeBytes(of: &token) { Data($0) }
        let attributes = [kSecGuestAttributeAudit: tokenData] as CFDictionary

        var guest: SecCode?
        guard SecCodeCopyGuestWithAttributes(nil, attributes, [], &guest) == errSecSuccess,
              let code = guest else {
            return false
        }
        var parsed: SecRequirement?
        guard SecRequirementCreateWithString(requirement as CFString, [], &parsed) == errSecSuccess,
              let req = parsed else {
            return false
        }
        return SecCodeCheckValidity(code, [], req) == errSecSuccess
    }

    /// Resolve the peer of connected socket `fd` and verify it. A socket whose peer
    /// token cannot be read is NOT trusted.
    static func verifyPeer(socket fd: Int32, requirement: String = coreRequirement) -> Bool {
        guard let token = peerAuditToken(of: fd) else { return false }
        return verifyPeer(auditToken: token, requirement: requirement)
    }
}

// MARK: - Wire codec (pure; mirrors listener.rs)

enum HandoffWire {
    /// `u32` big-endian length prefix + body. Rejects an over-cap body.
    static func frame(_ body: Data, max: Int) throws -> Data {
        guard body.count <= max else {
            throw HandoffError.frameTooLarge(declared: body.count, max: max)
        }
        let length = UInt32(body.count)
        var out = Data(capacity: 4 + body.count)
        out.append(UInt8(truncatingIfNeeded: length >> 24))
        out.append(UInt8(truncatingIfNeeded: length >> 16))
        out.append(UInt8(truncatingIfNeeded: length >> 8))
        out.append(UInt8(truncatingIfNeeded: length))
        out.append(body)
        return out
    }
}

/// A `FlowOpen` as the core's serde type defines it (field ORDER matters only for
/// byte-exact comparison; serde accepts any order).
struct FlowOpenMessage: Equatable {
    enum Kind: String { case tcp = "Tcp", udp = "Udp" }
    var flowID: UInt64
    var kind: Kind
    /// `ip:port` / `[ip]:port` (Rust `SocketAddr` Display).
    var remote: String
    var remoteHostname: String?
    var sourceApp: String?
    var local: String?
}

/// A message the core may send us. Only `Scope` is acted on; any other well-formed
/// externally-tagged message is ignored for forward compatibility.
enum CoreMessage: Equatable {
    case scope(String)
    case ignored
}

enum HandoffMessages {
    /// `{"Hello":{"protocol_version":1}}`
    static func hello() -> Data {
        Data("{\"Hello\":{\"protocol_version\":\(HandoffConfig.protocolVersion)}}".utf8)
    }

    /// `{"FlowOpen":{"flow_id":N,"kind":"Tcp","remote":"..","remote_hostname":..,
    /// "source_app":..,"local":..}}` -- absent options are JSON `null`, strings are
    /// escaped by the platform JSON encoder.
    static func flowOpen(_ m: FlowOpenMessage) throws -> Data {
        let json = "{\"FlowOpen\":{"
            + "\"flow_id\":\(m.flowID),"
            + "\"kind\":\(try literal(m.kind.rawValue)),"
            + "\"remote\":\(try literal(m.remote)),"
            + "\"remote_hostname\":\(try optional(m.remoteHostname)),"
            + "\"source_app\":\(try optional(m.sourceApp)),"
            + "\"local\":\(try optional(m.local))"
            + "}}"
        return Data(json.utf8)
    }

    /// `{"flow_id":N}` -- NOT enum-tagged (it is the `DataHandshake` struct).
    static func dataHandshake(flowID: UInt64) -> Data {
        Data("{\"flow_id\":\(flowID)}".utf8)
    }

    /// Decode a core->provider control body.
    static func decodeCore(_ body: Data) throws -> CoreMessage {
        guard let object = try? JSONSerialization.jsonObject(with: body),
              let dict = object as? [String: Any], dict.count == 1,
              let (_, payload) = dict.first, payload is [String: Any] else {
            throw HandoffError.malformed("control frame is not a single externally-tagged object")
        }
        if let scope = dict["Scope"] as? [String: Any] {
            guard let spec = scope["spec"] as? String else {
                throw HandoffError.malformed("Scope without a string spec")
            }
            return .scope(spec)
        }
        return .ignored
    }

    private static func literal(_ s: String) throws -> String {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.withoutEscapingSlashes]
        guard let data = try? encoder.encode(s), let out = String(data: data, encoding: .utf8) else {
            throw HandoffError.malformed("cannot JSON-encode string")
        }
        return out
    }

    private static func optional(_ s: String?) throws -> String {
        guard let s else { return "null" }
        return try literal(s)
    }
}

// MARK: - Blocking fd I/O

enum FDIO {
    static func writeAll(_ fd: Int32, _ data: Data) throws {
        try data.withUnsafeBytes { (raw: UnsafeRawBufferPointer) throws in
            guard let base = raw.baseAddress else { return }
            var offset = 0
            while offset < raw.count {
                let n = write(fd, base + offset, raw.count - offset)
                if n < 0 {
                    if errno == EINTR { continue }
                    throw HandoffError.io(errno: errno)
                }
                offset += n
            }
        }
    }

    /// `nil` only for a clean EOF before the first byte; EOF mid-read throws.
    static func readExactly(_ fd: Int32, count: Int) throws -> Data? {
        if count == 0 { return Data() }
        var buffer = [UInt8](repeating: 0, count: count)
        var got = 0
        while got < count {
            let n = buffer.withUnsafeMutableBytes { (raw: UnsafeMutableRawBufferPointer) -> Int in
                guard let base = raw.baseAddress else { return -1 }
                return read(fd, base + got, count - got)
            }
            if n == 0 {
                if got == 0 { return nil }
                throw HandoffError.shortRead
            }
            if n < 0 {
                if errno == EINTR { continue }
                throw HandoffError.io(errno: errno)
            }
            got += n
        }
        return Data(buffer)
    }

    /// Read one `u32`-BE-length-prefixed frame. A declared length above `max` is
    /// rejected BEFORE any allocation. `nil` is a clean EOF before the prefix.
    static func readFrame(_ fd: Int32, max: Int) throws -> Data? {
        guard let header = try readExactly(fd, count: 4) else { return nil }
        let declared = header.reduce(0) { ($0 << 8) | Int($1) }
        guard declared <= max else {
            throw HandoffError.frameTooLarge(declared: declared, max: max)
        }
        guard let body = try readExactly(fd, count: declared) else {
            throw HandoffError.shortRead
        }
        return body
    }

    static func writeFrame(_ fd: Int32, _ body: Data, max: Int) throws {
        try writeAll(fd, HandoffWire.frame(body, max: max))
    }

    static func setSendTimeout(_ fd: Int32, seconds: Int) {
        var tv = timeval(tv_sec: seconds, tv_usec: 0)
        _ = setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))
    }
}

/// Owns a socket fd. The fd closes in `deinit`, i.e. only after every thread that
/// holds the handle is done with it, so a blocked reader is woken with
/// `shutdownBoth()` and the number is never reused under it.
final class SocketHandle: @unchecked Sendable {
    let fd: Int32
    init(fd: Int32) { self.fd = fd }
    func shutdownBoth() { _ = shutdown(fd, SHUT_RDWR) }
    func shutdownWrite() { _ = shutdown(fd, SHUT_WR) }
    deinit { _ = close(fd) }
}

enum UnixSocket {
    /// Connect a stream socket to `path`. SIGPIPE is suppressed per-socket (a root
    /// system extension must not be killable by a peer that vanishes mid-write).
    static func connect(path: String) throws -> SocketHandle {
        var address = sockaddr_un()
        let pathBytes = Array(path.utf8)
        guard !pathBytes.isEmpty, !pathBytes.contains(0),
              pathBytes.count < MemoryLayout.size(ofValue: address.sun_path) else {
            throw HandoffError.unavailable("socket path unusable")
        }
        address.sun_family = sa_family_t(AF_UNIX)
        address.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
        withUnsafeMutableBytes(of: &address.sun_path) { dest in
            for (index, byte) in pathBytes.enumerated() { dest[index] = byte }
            dest[pathBytes.count] = 0
        }

        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { throw HandoffError.io(errno: errno) }
        let handle = SocketHandle(fd: fd)
        _ = fcntl(fd, F_SETFD, FD_CLOEXEC)
        var on: Int32 = 1
        guard setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &on, socklen_t(MemoryLayout<Int32>.size)) == 0 else {
            throw HandoffError.io(errno: errno)
        }
        let rc = withUnsafePointer(to: &address) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Foundation.connect(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        guard rc == 0 else { throw HandoffError.io(errno: errno) }
        return handle
    }
}

// MARK: - IP text + endpoint

enum IPText {
    /// Canonical text for 4 or 16 raw address bytes. An IPv4-mapped IPv6 address
    /// (`::ffff:a.b.c.d`) is unmapped to IPv4 so a dual-stack socket cannot dodge an
    /// IPv4 scope entry.
    static func canonical(bytes: [UInt8]) -> String? {
        var raw = bytes
        if raw.count == 16, raw[0..<10].allSatisfy({ $0 == 0 }), raw[10] == 0xff, raw[11] == 0xff {
            raw = Array(raw[12..<16])
        }
        let family: Int32
        switch raw.count {
        case 4: family = AF_INET
        case 16: family = AF_INET6
        default: return nil
        }
        var out = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
        let ok = raw.withUnsafeBytes { source in
            inet_ntop(family, source.baseAddress, &out, socklen_t(out.count)) != nil
        }
        return ok ? String(cString: out) : nil
    }

    static func canonical(text: String) -> String? {
        var v4 = [UInt8](repeating: 0, count: 4)
        if inet_pton(AF_INET, text, &v4) == 1 { return canonical(bytes: v4) }
        var v6 = [UInt8](repeating: 0, count: 16)
        if inet_pton(AF_INET6, text, &v6) == 1 { return canonical(bytes: v6) }
        return nil
    }

    static func isLinkLocalV6(_ bytes: [UInt8]) -> Bool {
        bytes.count == 16 && bytes[0] == 0xfe && (bytes[1] & 0xc0) == 0x80
    }
}

/// A resolved IP endpoint of a flow. Only IP endpoints can be handed to the core
/// (the wire's `remote` is a `SocketAddr`); a hostname-typed endpoint yields `nil`
/// and the flow fails open.
struct FlowEndpoint: Equatable {
    let ip: String
    let port: UInt16
    /// The original endpoint object, needed to address UDP replies. `nil` in tests.
    let nw: FlowNWEndpoint?

    init(ip: String, port: UInt16, nw: FlowNWEndpoint? = nil) {
        self.ip = ip
        self.port = port
        self.nw = nw
    }

    init?(nw endpoint: FlowNWEndpoint) {
        guard case let .hostPort(host, port) = endpoint else { return nil }
        let text: String
        switch host {
        case .ipv4(let address):
            guard let t = IPText.canonical(bytes: [UInt8](address.rawValue)) else { return nil }
            text = t
        case .ipv6(let address):
            let bytes = [UInt8](address.rawValue)
            guard var t = IPText.canonical(bytes: bytes) else { return nil }
            // A scope id is only meaningful (and only emitted) for link-local;
            // numeric because Rust's SocketAddr parser accepts `%<number>`.
            if IPText.isLinkLocalV6(bytes), let index = address.interface?.index, index > 0 {
                t += "%\(index)"
            }
            text = t
        case .name:
            return nil
        @unknown default:
            return nil
        }
        self.init(ip: text, port: port.rawValue, nw: endpoint)
    }

    static func == (lhs: FlowEndpoint, rhs: FlowEndpoint) -> Bool {
        lhs.ip == rhs.ip && lhs.port == rhs.port
    }

    /// Rust `SocketAddr` Display form.
    var display: String { ip.contains(":") ? "[\(ip)]:\(port)" : "\(ip):\(port)" }

    /// IP text without any `%scope` suffix, for scope matching.
    var scopeFreeIP: String {
        ip.split(separator: "%", maxSplits: 1, omittingEmptySubsequences: false).first.map(String.init) ?? ip
    }
}

// MARK: - Scope matching

/// The provider's coarse pre-filter over the core-pushed scope. The authoritative
/// check is the core's guard (spec D2); this only decides what is worth claiming,
/// and the default is NOT to claim (deny-by-default, fail open).
///
/// GRAMMAR (the Rust side leaves `ScopeSpec.spec` an unspecified string, so this is
/// the provider's reading; the core adapter must emit it): entries separated by
/// commas, semicolons, or whitespace. Each entry is `host`, `*.suffix`, an IP, or
/// any of those with `:port` (IPv6 with a port as `[addr]:port`). Hosts compare
/// case-insensitively against the flow's `remoteHostname`; `*.example.com` matches
/// sub-domains only, not `example.com`; IPs compare against the flow's remote IP.
/// A bare `*`, malformed entries, and an empty spec match nothing.
struct ScopeMatcher: Equatable {
    enum Target: Equatable {
        case host(String)
        case suffix(String)
        case ip(String)
    }
    struct Entry: Equatable {
        let target: Target
        let port: UInt16?
    }

    let entries: [Entry]

    init(spec: String) {
        let separators = CharacterSet(charactersIn: ",;").union(.whitespacesAndNewlines)
        entries = spec.components(separatedBy: separators)
            .filter { !$0.isEmpty }
            .compactMap { ScopeMatcher.parse($0.lowercased()) }
    }

    func matches(hostname: String?, ip: String, port: UInt16) -> Bool {
        let host = hostname.map(ScopeMatcher.normalizeHost)
        let flowIP = IPText.canonical(text: ip) ?? ip
        for entry in entries {
            if let wanted = entry.port, wanted != port { continue }
            switch entry.target {
            case .ip(let address):
                if address == flowIP { return true }
            case .host(let name):
                if let host, host == name { return true }
            case .suffix(let suffix):
                if let host, host.hasSuffix("." + suffix) { return true }
            }
        }
        return false
    }

    private static func normalizeHost(_ h: String) -> String {
        var s = h.lowercased()
        if s.hasSuffix(".") { s.removeLast() }
        return s
    }

    private static func parse(_ token: String) -> Entry? {
        var hostPart = token
        var port: UInt16?
        if token.hasPrefix("[") {
            guard let close = token.firstIndex(of: "]") else { return nil }
            hostPart = String(token[token.index(after: token.startIndex)..<close])
            let rest = token[token.index(after: close)...]
            if !rest.isEmpty {
                guard rest.hasPrefix(":"), let p = UInt16(rest.dropFirst()), p != 0 else { return nil }
                port = p
            }
            guard let ip = IPText.canonical(text: hostPart) else { return nil }
            return Entry(target: .ip(ip), port: port)
        }
        let colons = token.filter { $0 == ":" }.count
        if colons == 1, let split = token.firstIndex(of: ":") {
            hostPart = String(token[..<split])
            guard let p = UInt16(token[token.index(after: split)...]), p != 0 else { return nil }
            port = p
        } else if colons >= 2 {
            guard let ip = IPText.canonical(text: token) else { return nil }
            return Entry(target: .ip(ip), port: nil)
        }
        if let ip = IPText.canonical(text: hostPart) {
            return Entry(target: .ip(ip), port: port)
        }
        if hostPart.hasPrefix("*.") {
            let suffix = normalizeHost(String(hostPart.dropFirst(2)))
            return isValidHostname(suffix) ? Entry(target: .suffix(suffix), port: port) : nil
        }
        let name = normalizeHost(hostPart)
        return isValidHostname(name) ? Entry(target: .host(name), port: port) : nil
    }

    private static func isValidHostname(_ s: String) -> Bool {
        guard !s.isEmpty, s.count <= 253, !s.hasPrefix("."), !s.contains("..") else { return false }
        return s.unicodeScalars.allSatisfy {
            ($0.value >= 0x61 && $0.value <= 0x7a) || ($0.value >= 0x30 && $0.value <= 0x39)
                || $0 == "-" || $0 == "." || $0 == "_"
        }
    }
}

// MARK: - Rendezvous

enum Rendezvous {
    /// Read and validate the rendezvous file; returns the socket directory path.
    /// See `HandoffConfig.rendezvousPath` for the format and the checks.
    static func socketDirectory(at path: String = HandoffConfig.rendezvousPath) throws -> String {
        // O_NOFOLLOW: no symlink at the leaf. O_NONBLOCK: a planted FIFO must not
        // wedge the attach thread in open().
        let fd = open(path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
        guard fd >= 0 else { throw HandoffError.unavailable("no rendezvous file") }
        defer { _ = close(fd) }

        var fileStat = stat()
        guard fstat(fd, &fileStat) == 0, isAcceptableFile(fileStat) else {
            throw HandoffError.unavailable("rendezvous file rejected")
        }
        var buffer = [UInt8](repeating: 0, count: Int(fileStat.st_size))
        let n = buffer.withUnsafeMutableBytes { raw -> Int in
            guard let base = raw.baseAddress else { return -1 }
            return read(fd, base, raw.count)
        }
        guard n > 0, let text = String(bytes: buffer[0..<n], encoding: .utf8) else {
            throw HandoffError.unavailable("rendezvous file unreadable")
        }
        let dir = text.trimmingCharacters(in: .whitespacesAndNewlines)
        let longestSocket = HandoffConfig.controlSocketName.utf8.count
        guard dir.hasPrefix("/"), !dir.utf8.contains(0),
              dir.utf8.count + 1 + longestSocket < MemoryLayout.size(ofValue: sockaddr_un().sun_path) else {
            throw HandoffError.unavailable("rendezvous path unusable")
        }

        var dirStat = stat()
        guard lstat(dir, &dirStat) == 0,
              isAcceptableDirectory(dirStat, fileOwner: fileStat.st_uid) else {
            throw HandoffError.unavailable("socket directory rejected")
        }
        return dir
    }

    /// A regular file (the caller opened it O_NOFOLLOW), 1...1 KiB, with no group
    /// or other WRITE bit (nobody but its owner can have changed it).
    static func isAcceptableFile(_ st: stat) -> Bool {
        (st.st_mode & S_IFMT) == S_IFREG
            && (st.st_mode & (S_IWGRP | S_IWOTH)) == 0
            && st.st_size > 0 && st.st_size <= off_t(HandoffConfig.maxRendezvousBytes)
    }

    /// A real directory (`lstat`, so not a symlink) with NO group/other access,
    /// owned by the same uid that owns the rendezvous file.
    static func isAcceptableDirectory(_ st: stat, fileOwner: uid_t) -> Bool {
        (st.st_mode & S_IFMT) == S_IFDIR
            && (st.st_mode & (S_IRWXG | S_IRWXO)) == 0
            && st.st_uid == fileOwner
    }
}

// MARK: - Control link (attach + scope)

/// Maintains the single control channel to the core: discover via the rendezvous
/// file, connect, VERIFY THE PEER, send Hello, then read `Scope` pushes. While not
/// attached (no core, rejected peer, lost connection) `current()` is nil and every
/// flow fails open. Runs on one dedicated thread.
final class CoreLink: @unchecked Sendable {
    struct Attachment {
        let control: SocketHandle
        let directory: String
        let scope: ScopeMatcher
    }

    private let log = OSLog(subsystem: "com.mrbrutti.aitmproxy.ne", category: "control")
    private let rendezvousPath: String
    private let requirement: String
    private let lock = NSLock()
    private let writeLock = NSLock()
    private let wake = DispatchSemaphore(value: 0)
    private var control: SocketHandle?
    private var directory: String?
    private var scope: ScopeMatcher?
    private var stopped = false
    private var running = false
    private var lastFailure = ""

    init(rendezvousPath: String = HandoffConfig.rendezvousPath,
         requirement: String = PeerAuth.coreRequirement) {
        self.rendezvousPath = rendezvousPath
        self.requirement = requirement
    }

    /// Begin looking for the core. Idempotent while running.
    func start() {
        lock.lock()
        if running {
            lock.unlock()
            return
        }
        running = true
        stopped = false
        lock.unlock()
        let thread = Thread { [self] in
            run()
            lock.lock()
            running = false
            lock.unlock()
        }
        thread.name = "aitm-core-link"
        thread.start()
    }

    func stop() {
        lock.lock()
        stopped = true
        let handle = control
        lock.unlock()
        handle?.shutdownBoth()
        wake.signal()
    }

    /// The verified control channel plus the active scope, or nil when the provider
    /// must fail open (not attached, or no Scope received yet).
    func current() -> Attachment? {
        lock.lock()
        defer { lock.unlock() }
        guard let control, let directory, let scope else { return nil }
        return Attachment(control: control, directory: directory, scope: scope)
    }

    var isAttached: Bool {
        lock.lock()
        defer { lock.unlock() }
        return control != nil
    }

    /// Send a control frame on the verified channel. On any failure the channel is
    /// torn down (the reader then detaches) and false is returned.
    func send(_ body: Data, on attachment: Attachment) -> Bool {
        writeLock.lock()
        defer { writeLock.unlock() }
        do {
            try FDIO.writeFrame(attachment.control.fd, body, max: HandoffConfig.maxControlFrame)
            return true
        } catch {
            attachment.control.shutdownBoth()
            return false
        }
    }

    /// Verify `handle`'s peer, send Hello, publish it as the control channel and
    /// read control messages until it ends. NOTHING is written to the peer unless
    /// the signature check passes. Returns false (and closes) if the peer is
    /// rejected or the Hello cannot be sent. Exposed for tests.
    @discardableResult
    func serve(_ handle: SocketHandle, directory dir: String) -> Bool {
        guard PeerAuth.verifyPeer(socket: handle.fd, requirement: requirement) else {
            handle.shutdownBoth()
            noteFailure("control peer failed the code-signature requirement")
            return false
        }
        FDIO.setSendTimeout(handle.fd, seconds: HandoffConfig.handshakeSendTimeoutSeconds)
        do {
            try FDIO.writeFrame(handle.fd, HandoffMessages.hello(), max: HandoffConfig.maxControlFrame)
        } catch {
            handle.shutdownBoth()
            noteFailure("could not send Hello")
            return false
        }
        lock.lock()
        let alreadyStopped = stopped
        if !alreadyStopped {
            control = handle
            directory = dir
            scope = nil
        }
        lock.unlock()
        if alreadyStopped {
            handle.shutdownBoth()
            return false
        }
        lock.lock()
        lastFailure = ""
        lock.unlock()
        os_log("attached to core", log: log, type: .default)
        readControl(handle)
        detach(handle)
        return true
    }

    private func readControl(_ handle: SocketHandle) {
        while true {
            do {
                guard let body = try FDIO.readFrame(handle.fd, max: HandoffConfig.maxControlFrame) else {
                    return
                }
                if case .scope(let spec) = try HandoffMessages.decodeCore(body) {
                    let matcher = ScopeMatcher(spec: spec)
                    lock.lock()
                    scope = matcher
                    lock.unlock()
                    os_log("scope updated (%{public}d entries)", log: log, type: .default,
                           matcher.entries.count)
                }
            } catch {
                // Oversized/garbled frame or I/O error: stop trusting this channel.
                noteFailure("control channel error: \(error)")
                return
            }
        }
    }

    private func detach(_ handle: SocketHandle) {
        lock.lock()
        if control === handle {
            control = nil
            directory = nil
            scope = nil
        }
        lock.unlock()
        handle.shutdownBoth()
        os_log("detached from core; failing open", log: log, type: .default)
    }

    private func run() {
        while !isStopped {
            do {
                let dir = try Rendezvous.socketDirectory(at: rendezvousPath)
                let handle = try UnixSocket.connect(path: dir + "/" + HandoffConfig.controlSocketName)
                serve(handle, directory: dir)
            } catch {
                noteFailure("not attached: \(error)")
            }
            _ = wake.wait(timeout: .now() + HandoffConfig.attachRetrySeconds)
        }
    }

    private var isStopped: Bool {
        lock.lock()
        defer { lock.unlock() }
        return stopped
    }

    /// Log only when the reason changes, so a missing core does not spam the log.
    private func noteFailure(_ reason: String) {
        lock.lock()
        let changed = reason != lastFailure
        lastFailure = reason
        lock.unlock()
        if changed {
            os_log("%{public}@", log: log, type: .default, reason)
        }
    }
}

// MARK: - Pumps

/// One-shot rendezvous between an NE completion handler (which must never block)
/// and the pump thread that waits for it.
final class OneShot<T>: @unchecked Sendable {
    private let semaphore = DispatchSemaphore(value: 0)
    private let lock = NSLock()
    private var value: T?

    func fulfill(_ v: T) {
        lock.lock()
        let first = value == nil
        if first { value = v }
        lock.unlock()
        if first { semaphore.signal() }
    }

    /// Wait for the value, re-checking `abort` once a second so a flow that was
    /// torn down without completing the NE call cannot strand the thread.
    func wait(abort: () -> Bool) -> T? {
        while semaphore.wait(timeout: .now() + 1) == .timedOut {
            if abort() { return nil }
        }
        lock.lock()
        defer { lock.unlock() }
        return value
    }
}

/// The NE TCP flow operations the pump needs (a seam so the pump is testable
/// without a real `NEAppProxyTCPFlow`).
protocol ProxiedTCPFlow: AnyObject {
    func read(_ completion: @escaping (Data?, Error?) -> Void)
    func write(_ data: Data, _ completion: @escaping (Error?) -> Void)
    func closeRead(_ error: Error?)
    func closeWrite(_ error: Error?)
}

final class NETCPFlow: ProxiedTCPFlow {
    private let flow: NEAppProxyTCPFlow
    init(_ flow: NEAppProxyTCPFlow) { self.flow = flow }
    func read(_ completion: @escaping (Data?, Error?) -> Void) {
        flow.readData(completionHandler: completion)
    }
    func write(_ data: Data, _ completion: @escaping (Error?) -> Void) {
        flow.write(data, withCompletionHandler: completion)
    }
    func closeRead(_ error: Error?) { flow.closeReadWithError(error) }
    func closeWrite(_ error: Error?) { flow.closeWriteWithError(error) }
}

/// Copies one TCP flow <-> its authenticated data socket with two dedicated
/// threads (so a slow core can never block an NE queue or the provider queue).
///
/// - app -> core: read one chunk from the flow, WRITE IT ALL to the socket, only
///   then read the next (write-all-before-read; backpressure to the app).
/// - core -> app: read at most `maxInboundRead` bytes, hand the chunk to the flow,
///   wait for the flow to accept it, then read again.
/// EOF is propagated as a half-close each way; any error tears down both sides.
final class TCPFlowPump: @unchecked Sendable {
    private enum ReadResult {
        case data(Data)
        case eof
        case failed(Error)
    }

    private let flow: ProxiedTCPFlow
    private let socket: SocketHandle
    private let onFinish: () -> Void
    private let lock = NSLock()
    private var closed = false
    private var finished = false
    private var running = 2

    init(flow: ProxiedTCPFlow, socket: SocketHandle, onFinish: @escaping () -> Void) {
        self.flow = flow
        self.socket = socket
        self.onFinish = onFinish
    }

    func start() {
        if isClosed { return }   // aborted while the flow was opening
        let outbound = Thread { [self] in pumpOutbound() }
        outbound.name = "aitm-tcp-out"
        let inbound = Thread { [self] in pumpInbound() }
        inbound.name = "aitm-tcp-in"
        outbound.start()
        inbound.start()
    }

    /// Tear the flow down (idempotent). Safe from any thread.
    func abort(_ error: Error? = nil) {
        lock.lock()
        let first = !closed
        closed = true
        lock.unlock()
        guard first else { return }
        flow.closeRead(error)
        flow.closeWrite(error)
        socket.shutdownBoth()
        finishIfNeeded()
    }

    private var isClosed: Bool {
        lock.lock()
        defer { lock.unlock() }
        return closed
    }

    private func pumpOutbound() {
        defer { directionDone() }
        while true {
            let shot = OneShot<ReadResult>()
            flow.read { data, error in
                if let error {
                    shot.fulfill(.failed(error))
                } else if let data, !data.isEmpty {
                    shot.fulfill(.data(data))
                } else {
                    shot.fulfill(.eof)
                }
            }
            guard let result = shot.wait(abort: { self.isClosed }) else { return }
            switch result {
            case .data(let chunk):
                do {
                    try FDIO.writeAll(socket.fd, chunk)
                } catch {
                    abort(error)
                    return
                }
            case .eof:
                socket.shutdownWrite()
                flow.closeRead(nil)
                return
            case .failed(let error):
                abort(error)
                return
            }
        }
    }

    private func pumpInbound() {
        defer { directionDone() }
        var buffer = [UInt8](repeating: 0, count: HandoffConfig.maxInboundRead)
        while true {
            let n = buffer.withUnsafeMutableBytes { (raw: UnsafeMutableRawBufferPointer) -> Int in
                guard let base = raw.baseAddress else { return -1 }
                return read(socket.fd, base, raw.count)
            }
            if n < 0 {
                if errno == EINTR { continue }
                if !isClosed { abort(HandoffError.io(errno: errno)) }
                return
            }
            if n == 0 {
                flow.closeWrite(nil)
                return
            }
            let shot = OneShot<Error?>()
            flow.write(Data(buffer[0..<n])) { shot.fulfill($0) }
            guard let outcome = shot.wait(abort: { self.isClosed }) else { return }
            if let error = outcome {
                abort(error)
                return
            }
        }
    }

    private func directionDone() {
        lock.lock()
        running -= 1
        let none = running == 0
        lock.unlock()
        if none { finishIfNeeded() }
    }

    private func finishIfNeeded() {
        lock.lock()
        let run = !finished
        finished = true
        lock.unlock()
        if run { onFinish() }
    }
}

/// The NE UDP flow operations the pump needs.
protocol ProxiedUDPFlow: AnyObject {
    func read(_ completion: @escaping ([(Data, FlowEndpoint)]?, Error?) -> Void)
    func write(_ datagram: Data, from remote: FlowEndpoint, _ completion: @escaping (Error?) -> Void)
    func closeRead(_ error: Error?)
    func closeWrite(_ error: Error?)
}

final class NEUDPFlow: ProxiedUDPFlow {
    private let flow: NEAppProxyUDPFlow
    init(_ flow: NEAppProxyUDPFlow) { self.flow = flow }
    func read(_ completion: @escaping ([(Data, FlowEndpoint)]?, Error?) -> Void) {
        flow.readDatagrams { pairs, error in
            let mapped = pairs?.compactMap { pair -> (Data, FlowEndpoint)? in
                FlowEndpoint(nw: pair.1).map { (pair.0, $0) }
            }
            completion(mapped, error)
        }
    }
    func write(_ datagram: Data, from remote: FlowEndpoint, _ completion: @escaping (Error?) -> Void) {
        guard let endpoint = remote.nw else {
            completion(HandoffError.malformed("UDP reply endpoint unavailable"))
            return
        }
        flow.writeDatagrams([(datagram, endpoint)], completionHandler: completion)
    }
    func closeRead(_ error: Error?) { flow.closeReadWithError(error) }
    func closeWrite(_ error: Error?) { flow.closeWriteWithError(error) }
}

/// Copies one UDP flow <-> its authenticated data socket as length-delimited
/// datagrams. The wire (`FlowOpen.remote`, no per-datagram endpoint) models ONE
/// remote per UDP flow, so the flow is pinned to the initial remote the app
/// opened it with: datagrams to any other remote are dropped (counted, logged
/// once), as are datagrams over 64 KiB.
final class UDPFlowPump: @unchecked Sendable {
    private enum ReadResult {
        case datagrams([(Data, FlowEndpoint)])
        case failed(Error?)
    }

    private let log = OSLog(subsystem: "com.mrbrutti.aitmproxy.ne", category: "udp")
    private let flow: ProxiedUDPFlow
    private let socket: SocketHandle
    private let remote: FlowEndpoint
    private let onFinish: () -> Void
    private let lock = NSLock()
    private var closed = false
    private var finished = false
    private var running = 2
    private(set) var droppedForeign = 0
    private(set) var droppedOversize = 0

    init(flow: ProxiedUDPFlow, socket: SocketHandle, remote: FlowEndpoint, onFinish: @escaping () -> Void) {
        self.flow = flow
        self.socket = socket
        self.remote = remote
        self.onFinish = onFinish
    }

    func start() {
        if isClosed { return }   // aborted while the flow was opening
        let outbound = Thread { [self] in pumpOutbound() }
        outbound.name = "aitm-udp-out"
        let inbound = Thread { [self] in pumpInbound() }
        inbound.name = "aitm-udp-in"
        outbound.start()
        inbound.start()
    }

    func abort(_ error: Error? = nil) {
        lock.lock()
        let first = !closed
        closed = true
        lock.unlock()
        guard first else { return }
        flow.closeRead(error)
        flow.closeWrite(error)
        socket.shutdownBoth()
        finishOnce()
    }

    private var isClosed: Bool {
        lock.lock()
        defer { lock.unlock() }
        return closed
    }

    private func pumpOutbound() {
        defer { directionDone() }
        while true {
            let shot = OneShot<ReadResult>()
            flow.read { pairs, error in
                if let pairs, error == nil {
                    shot.fulfill(.datagrams(pairs))
                } else {
                    shot.fulfill(.failed(error))
                }
            }
            guard let result = shot.wait(abort: { self.isClosed }) else { return }
            switch result {
            case .failed(let error):
                abort(error)
                return
            case .datagrams(let pairs):
                for (datagram, endpoint) in pairs {
                    guard endpoint == remote else {
                        noteDropped(foreign: true)
                        continue
                    }
                    guard datagram.count <= HandoffConfig.maxDatagram else {
                        noteDropped(foreign: false)
                        continue
                    }
                    do {
                        try FDIO.writeFrame(socket.fd, datagram, max: HandoffConfig.maxDatagram)
                    } catch {
                        abort(error)
                        return
                    }
                }
            }
        }
    }

    private func pumpInbound() {
        defer { directionDone() }
        while true {
            let datagram: Data
            do {
                guard let next = try FDIO.readFrame(socket.fd, max: HandoffConfig.maxDatagram) else {
                    // The core is done with this flow. Datagram flows have no
                    // half-close, so end both directions (this also releases the
                    // outbound thread that is waiting on the app).
                    abort(nil)
                    return
                }
                datagram = next
            } catch {
                if !isClosed { abort(error) }
                return
            }
            let shot = OneShot<Error?>()
            flow.write(datagram, from: remote) { shot.fulfill($0) }
            guard let outcome = shot.wait(abort: { self.isClosed }) else { return }
            if let error = outcome {
                abort(error)
                return
            }
        }
    }

    private func noteDropped(foreign: Bool) {
        lock.lock()
        if foreign { droppedForeign += 1 } else { droppedOversize += 1 }
        let count = foreign ? droppedForeign : droppedOversize
        lock.unlock()
        if count == 1 {
            os_log("UDP datagram dropped (%{public}@)", log: log, type: .default,
                   foreign ? "other remote than the flow's pinned one" : "over 64 KiB")
        }
    }

    private func directionDone() {
        lock.lock()
        running -= 1
        let none = running == 0
        lock.unlock()
        if none { finishOnce() }
    }

    private func finishOnce() {
        lock.lock()
        let run = !finished
        finished = true
        lock.unlock()
        if run { onFinish() }
    }
}

// MARK: - FlowHandoff (what the provider calls)

/// What the handoff needs to know about a flow, independent of NE types.
struct FlowDescriptor {
    var kind: FlowOpenMessage.Kind
    var remote: FlowEndpoint
    var remoteHostname: String?
    var sourceApp: String?
    var local: FlowEndpoint?
}

/// A flow the core accepted: its id and its authenticated, handshaken data socket.
struct ClaimedFlow {
    let id: UInt64
    let socket: SocketHandle
}

final class FlowHandoff: @unchecked Sendable {
    private let log = OSLog(subsystem: "com.mrbrutti.aitmproxy.ne", category: "handoff")
    private let link: CoreLink
    private let requirement: String
    private let dial: (String) throws -> SocketHandle
    private let lock = NSLock()
    private var nextID: UInt64 = 1
    private var live: [UInt64: () -> Void] = [:]

    /// `dial` and `requirement` are injectable for tests only; production uses
    /// `UnixSocket.connect` and `PeerAuth.coreRequirement`. The signature check
    /// runs on whatever socket `dial` returns, so injecting a dialer cannot skip it.
    init(link: CoreLink? = nil,
         requirement: String = PeerAuth.coreRequirement,
         dial: @escaping (String) throws -> SocketHandle = UnixSocket.connect(path:)) {
        self.requirement = requirement
        self.dial = dial
        self.link = link ?? CoreLink(requirement: requirement)
    }

    func start() { link.start() }

    func stop() {
        link.stop()
        lock.lock()
        let closers = Array(live.values)
        live.removeAll()
        lock.unlock()
        closers.forEach { $0() }
    }

    /// Decide whether the core should get this flow and, if so, hand it off up to
    /// (and including) the per-flow handshake. Returns nil => the provider must
    /// return false (fail open). Order, chosen so no byte reaches an unverified
    /// peer and the core never sees a FlowOpen for a flow it cannot receive:
    ///   1. attached + Scope received + scope match   (else nil)
    ///   2. dial the data socket and VERIFY ITS PEER   (else nil, socket closed)
    ///   3. FlowOpen on the (already verified) control channel
    ///   4. DataHandshake as the first frame on the data socket
    func claim(_ flow: FlowDescriptor) -> ClaimedFlow? {
        guard let attachment = link.current() else { return nil }
        guard attachment.scope.matches(hostname: flow.remoteHostname,
                                       ip: flow.remote.scopeFreeIP,
                                       port: flow.remote.port) else { return nil }

        guard let socket = try? dial(attachment.directory + "/" + HandoffConfig.dataSocketName) else {
            return nil
        }
        guard PeerAuth.verifyPeer(socket: socket.fd, requirement: requirement) else {
            socket.shutdownBoth()
            os_log("data peer failed the code-signature requirement; flow fails open",
                   log: log, type: .error)
            return nil
        }
        FDIO.setSendTimeout(socket.fd, seconds: HandoffConfig.handshakeSendTimeoutSeconds)

        let id = allocateID()
        let open = FlowOpenMessage(flowID: id, kind: flow.kind, remote: flow.remote.display,
                                   remoteHostname: flow.remoteHostname, sourceApp: flow.sourceApp,
                                   local: flow.local?.display)
        guard let body = try? HandoffMessages.flowOpen(open),
              link.send(body, on: attachment) else {
            socket.shutdownBoth()
            return nil
        }
        do {
            try FDIO.writeFrame(socket.fd, HandoffMessages.dataHandshake(flowID: id),
                                max: HandoffConfig.maxControlFrame)
        } catch {
            socket.shutdownBoth()
            return nil
        }
        // Backpressure is real from here on: no send timeout for the byte copy.
        FDIO.setSendTimeout(socket.fd, seconds: 0)
        return ClaimedFlow(id: id, socket: socket)
    }

    // NE glue ---------------------------------------------------------------

    /// `handleNewFlow` for a TCP flow. True => the handoff owns the flow.
    func handleTCP(_ flow: NEAppProxyTCPFlow) -> Bool {
        guard let remote = FlowEndpoint(nw: flow.remoteFlowEndpoint) else { return false }
        let descriptor = FlowDescriptor(kind: .tcp, remote: remote,
                                        remoteHostname: Self.nonEmpty(flow.remoteHostname),
                                        sourceApp: Self.nonEmpty(flow.metaData.sourceAppSigningIdentifier),
                                        local: nil)
        guard let claimed = claim(descriptor) else { return false }
        let pump = TCPFlowPump(flow: NETCPFlow(flow), socket: claimed.socket) { [weak self] in
            self?.unregister(claimed.id)
        }
        register(claimed.id) { pump.abort() }
        flow.open(withLocalFlowEndpoint: nil) { error in
            if let error { pump.abort(error) } else { pump.start() }
        }
        return true
    }

    /// `handleNewUDPFlow` (macOS 15+ hands us the initial remote endpoint). True =>
    /// the handoff owns the flow.
    func handleUDP(_ flow: NEAppProxyUDPFlow, initialRemote: FlowNWEndpoint) -> Bool {
        guard let remote = FlowEndpoint(nw: initialRemote) else { return false }
        let descriptor = FlowDescriptor(kind: .udp, remote: remote,
                                        remoteHostname: Self.nonEmpty(flow.remoteHostname),
                                        sourceApp: Self.nonEmpty(flow.metaData.sourceAppSigningIdentifier),
                                        local: flow.localFlowEndpoint.flatMap { FlowEndpoint(nw: $0) })
        guard let claimed = claim(descriptor) else { return false }
        let pump = UDPFlowPump(flow: NEUDPFlow(flow), socket: claimed.socket, remote: remote) { [weak self] in
            self?.unregister(claimed.id)
        }
        register(claimed.id) { pump.abort() }
        flow.open(withLocalFlowEndpoint: nil) { error in
            if let error { pump.abort(error) } else { pump.start() }
        }
        return true
    }

    private func allocateID() -> UInt64 {
        lock.lock()
        defer { lock.unlock() }
        let id = nextID
        nextID += 1
        return id
    }

    private func register(_ id: UInt64, _ closer: @escaping () -> Void) {
        lock.lock()
        live[id] = closer
        lock.unlock()
    }

    private func unregister(_ id: UInt64) {
        lock.lock()
        live[id] = nil
        lock.unlock()
    }

    private static func nonEmpty(_ s: String?) -> String? {
        guard let s, !s.isEmpty else { return nil }
        return s
    }
}

// MARK: - Self-check (DEBUG only; never part of the shipped extension)
//
// Run with a throwaway driver (see the task report): compile this file plus a
// one-line `main.swift` calling `HandoffSelfCheck.run()` with `-D DEBUG`. It drives
// the real code over real socketpairs with a fake core and fake NE flows, and
// asserts LITERAL expected wire bytes. It needs no root, no entitlement, no NE.
#if DEBUG
enum HandoffSelfCheck {
    private final class Box<T>: @unchecked Sendable {
        private let lock = NSLock()
        private var items: [T] = []
        func append(_ item: T) { lock.lock(); items.append(item); lock.unlock() }
        var all: [T] { lock.lock(); defer { lock.unlock() }; return items }
    }

    /// A connected AF_UNIX pair with SIGPIPE suppressed (like production sockets).
    static func pair() -> (SocketHandle, SocketHandle)? {
        var fds: [Int32] = [0, 0]
        guard socketpair(AF_UNIX, SOCK_STREAM, 0, &fds) == 0 else { return nil }
        for fd in fds {
            var on: Int32 = 1
            _ = setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &on, socklen_t(MemoryLayout<Int32>.size))
        }
        return (SocketHandle(fd: fds[0]), SocketHandle(fd: fds[1]))
    }

    /// Count bytes arriving on `fd` until EOF or `timeoutMs` of silence. Used to
    /// assert a peer received EXACTLY nothing.
    static func drainCount(_ fd: Int32, timeoutMs: Int32 = 300) -> Int {
        var total = 0
        var buffer = [UInt8](repeating: 0, count: 4096)
        while true {
            var p = pollfd(fd: fd, events: Int16(POLLIN), revents: 0)
            let ready = poll(&p, 1, timeoutMs)
            if ready <= 0 { return total }
            let n = read(fd, &buffer, buffer.count)
            if n <= 0 { return total }
            total += n
        }
    }

    static func ownIdentifierRequirement() -> String? {
        var selfCode: SecCode?
        guard SecCodeCopySelf([], &selfCode) == errSecSuccess, let code = selfCode else { return nil }
        var staticCode: SecStaticCode?
        guard SecCodeCopyStaticCode(code, [], &staticCode) == errSecSuccess,
              let sc = staticCode else { return nil }
        var info: CFDictionary?
        guard SecCodeCopySigningInformation(sc, SecCSFlags(rawValue: kSecCSSigningInformation), &info) == errSecSuccess,
              let dict = info as? [String: Any],
              let identifier = dict[kSecCodeInfoIdentifier as String] as? String else { return nil }
        return "identifier \"\(identifier)\""
    }

    static func string(_ data: Data) -> String { String(decoding: data, as: UTF8.self) }

    final class Recorder {
        private(set) var failures: [String] = []
        func fail(_ message: String) { failures.append(message) }
        func check(_ name: String, _ ok: Bool, _ detail: @autoclosure () -> String = "") {
            if !ok { failures.append("FAIL \(name) \(detail())") }
        }
        func expectThrows(_ name: String, _ body: () throws -> Void) {
            do { try body(); failures.append("FAIL \(name): expected a throw") } catch {}
        }
    }

    static func run() -> [String] {
        let r = Recorder()
        wire(r)
        framing(r)
        scope(r)
        endpoints(r)
        peerAuth(r)
        rendezvous(r)
        coreLinkAndClaim(r)
        pumps(r)
        inboundCap(r)
        return r.failures
    }

    // -- wire JSON + framing codec -------------------------------------------

    private static func wire(_ r: Recorder) {
        r.check("hello", string(HandoffMessages.hello()) == #"{"Hello":{"protocol_version":1}}"#,
              string(HandoffMessages.hello()))
        let tcp = FlowOpenMessage(flowID: 42, kind: .tcp, remote: "93.184.216.34:443",
                                  remoteHostname: "example.com", sourceApp: "com.apple.curl", local: nil)
        let tcpJSON = (try? HandoffMessages.flowOpen(tcp)).map(string) ?? "<throw>"
        r.check("flowOpen tcp", tcpJSON == #"{"FlowOpen":{"flow_id":42,"kind":"Tcp","remote":"93.184.216.34:443","remote_hostname":"example.com","source_app":"com.apple.curl","local":null}}"#, tcpJSON)
        let udp = FlowOpenMessage(flowID: 7, kind: .udp, remote: "[2001:db8::1]:53",
                                  remoteHostname: nil, sourceApp: nil, local: "10.0.0.2:51515")
        let udpJSON = (try? HandoffMessages.flowOpen(udp)).map(string) ?? "<throw>"
        r.check("flowOpen udp", udpJSON == #"{"FlowOpen":{"flow_id":7,"kind":"Udp","remote":"[2001:db8::1]:53","remote_hostname":null,"source_app":null,"local":"10.0.0.2:51515"}}"#, udpJSON)

        // Hostile metadata must stay inside its JSON string (no injection).
        let hostile = "a\"b\\c\n/\u{e9}},\"x\":1"
        let evil = FlowOpenMessage(flowID: 1, kind: .tcp, remote: "1.2.3.4:5",
                                   remoteHostname: hostile, sourceApp: nil, local: nil)
        if let body = try? HandoffMessages.flowOpen(evil),
           let obj = (try? JSONSerialization.jsonObject(with: body)) as? [String: Any],
           let inner = obj["FlowOpen"] as? [String: Any] {
            r.check("escape roundtrip", inner["remote_hostname"] as? String == hostile)
            r.check("escape no extra keys", inner.count == 6, "\(inner.keys.sorted())")
        } else {
            r.fail("FAIL escape: not parseable")
        }

        r.check("handshake", string(HandoffMessages.dataHandshake(flowID: 7)) == #"{"flow_id":7}"#)
        r.check("handshake u64 max",
              string(HandoffMessages.dataHandshake(flowID: UInt64.max)) == #"{"flow_id":18446744073709551615}"#)

        let framed = (try? HandoffWire.frame(Data("abc".utf8), max: 10)).map { Array($0) }
        r.check("frame bytes", framed == [0, 0, 0, 3, 0x61, 0x62, 0x63], "\(String(describing: framed))")
        r.expectThrows("frame over cap") { _ = try HandoffWire.frame(Data(count: 11), max: 10) }

        r.check("decode scope",
              (try? HandoffMessages.decodeCore(Data(#"{"Scope":{"spec":"example.com"}}"#.utf8))) == .scope("example.com"))
        r.check("decode other variant ignored",
              (try? HandoffMessages.decodeCore(Data(#"{"Hello":{"protocol_version":1}}"#.utf8))) == .ignored)
        for bad in ["not json", #"{"Scope":{}}"#, #"{"A":{},"B":{}}"#, "[]", #"{"Scope":"x"}"#, ""] {
            r.expectThrows("decode rejects \(bad)") { _ = try HandoffMessages.decodeCore(Data(bad.utf8)) }
        }
    }

    private static func framing(_ r: Recorder) {
        guard let (a, b) = pair() else { r.fail("FAIL framing: no socketpair"); return }
        var rcvTimeout = timeval(tv_sec: 3, tv_usec: 0)   // a broken cap must FAIL, not hang
        _ = setsockopt(b.fd, SOL_SOCKET, SO_RCVTIMEO, &rcvTimeout, socklen_t(MemoryLayout<timeval>.size))
        // round trip
        try? FDIO.writeFrame(a.fd, Data("hello".utf8), max: 100)
        r.check("frame roundtrip", (try? FDIO.readFrame(b.fd, max: 100)).flatMap { $0 }.map(string) == "hello")
        // empty body
        try? FDIO.writeFrame(a.fd, Data(), max: 100)
        r.check("empty frame", (try? FDIO.readFrame(b.fd, max: 100)).flatMap { $0 }?.count == 0)

        // Hostile length prefixes are rejected from the 4 header bytes alone: no
        // body is ever sent, so a read that tried to allocate/await it would hang.
        for declared in [UInt32.max, UInt32(HandoffConfig.maxControlFrame + 1)] {
            var header = [UInt8](repeating: 0, count: 4)
            header[0] = UInt8(declared >> 24); header[1] = UInt8((declared >> 16) & 0xff)
            header[2] = UInt8((declared >> 8) & 0xff); header[3] = UInt8(declared & 0xff)
            _ = header.withUnsafeBytes { write(a.fd, $0.baseAddress, 4) }
            do {
                _ = try FDIO.readFrame(b.fd, max: HandoffConfig.maxControlFrame)
                r.fail("FAIL hostile length \(declared) accepted")
            } catch let HandoffError.frameTooLarge(got, max) {
                r.check("hostile length reports", got == Int(declared) && max == HandoffConfig.maxControlFrame)
            } catch { r.fail("FAIL hostile length \(declared): wrong error \(error)") }
        }
        // 64 KiB datagram cap: 65537 declared is refused, 65536 is accepted.
        let big = Data(repeating: 0xAB, count: HandoffConfig.maxDatagram)
        let writer = Thread { try? FDIO.writeFrame(a.fd, big, max: HandoffConfig.maxDatagram) }
        writer.start()
        r.check("datagram at cap", (try? FDIO.readFrame(b.fd, max: HandoffConfig.maxDatagram)).flatMap { $0 } == big)
        r.expectThrows("datagram over cap write") {
            try FDIO.writeFrame(a.fd, Data(count: HandoffConfig.maxDatagram + 1), max: HandoffConfig.maxDatagram)
        }
        // EOF mid-frame is an error; EOF between frames is a clean nil.
        var short: [UInt8] = [0, 0, 0, 5, 1, 2]
        _ = short.withUnsafeMutableBytes { write(a.fd, $0.baseAddress, 6) }
        a.shutdownWrite()
        r.expectThrows("eof mid-frame") { _ = try FDIO.readFrame(b.fd, max: 100) }
        do {
            let value = try FDIO.readFrame(b.fd, max: 100)
            r.check("clean eof", value == nil)
        } catch {
            r.fail("FAIL clean eof threw \(error)")
        }
    }

    // -- scope grammar -------------------------------------------------------

    private static func scope(_ r: Recorder) {
        let m = ScopeMatcher(spec: "example.com, *.api.test:8443\n93.184.216.34;[2001:db8::1]:443 ::1")
        r.check("scope entries parsed", m.entries.count == 5, "\(m.entries)")
        r.check("host exact + case + trailing dot", m.matches(hostname: "EXAMPLE.com.", ip: "1.1.1.1", port: 80))
        r.check("host no hostname", !m.matches(hostname: nil, ip: "1.1.1.1", port: 80))
        r.check("suffix match", m.matches(hostname: "x.api.test", ip: "1.1.1.1", port: 8443))
        r.check("suffix wrong port", !m.matches(hostname: "x.api.test", ip: "1.1.1.1", port: 443))
        r.check("suffix not apex", !m.matches(hostname: "api.test", ip: "1.1.1.1", port: 8443))
        r.check("suffix not substring", !m.matches(hostname: "evilapi.test", ip: "1.1.1.1", port: 8443))
        r.check("ipv4 any port", m.matches(hostname: nil, ip: "93.184.216.34", port: 1))
        r.check("ipv6 port", m.matches(hostname: nil, ip: "2001:db8::1", port: 443))
        r.check("ipv6 wrong port", !m.matches(hostname: nil, ip: "2001:db8::1", port: 80))
        r.check("ipv6 non-canonical", m.matches(hostname: nil, ip: "2001:0DB8:0:0:0:0:0:1", port: 443))
        r.check("bare ipv6", m.matches(hostname: nil, ip: "::1", port: 9))
        r.check("v4-mapped unmapped", m.matches(hostname: nil, ip: "::ffff:93.184.216.34", port: 80))
        r.check("unrelated", !m.matches(hostname: "other.org", ip: "8.8.8.8", port: 443))
        for spec in ["", "*", "*.*", "foo:0", "foo:99999", "*.", "[::1", "a..b", "ex ample!"] {
            let matcher = ScopeMatcher(spec: spec)
            r.check("deny-by-default spec '\(spec)'",
                  !matcher.matches(hostname: "foo", ip: "1.1.1.1", port: 80) || spec == "ex ample!",
                  "\(matcher.entries)")
        }
        r.check("star claims nothing",
              !ScopeMatcher(spec: "*").matches(hostname: "anything.com", ip: "1.2.3.4", port: 443))
    }

    // -- endpoints -----------------------------------------------------------

    private static func endpoints(_ r: Recorder) {
        func host(_ e: FlowNWEndpoint) -> String? { FlowEndpoint(nw: e)?.display }
        if let v4 = IPv4Address("93.184.216.34") {
            r.check("v4 display", host(.hostPort(host: .ipv4(v4), port: 443)) == "93.184.216.34:443")
        }
        if let v6 = IPv6Address("2001:db8::1") {
            r.check("v6 display", host(.hostPort(host: .ipv6(v6), port: 443)) == "[2001:db8::1]:443")
        }
        if let mapped = IPv6Address("::ffff:1.2.3.4") {
            r.check("v4-mapped display", host(.hostPort(host: .ipv6(mapped), port: 80)) == "1.2.3.4:80")
        }
        r.check("hostname endpoint refused", host(.hostPort(host: .name("example.com", nil), port: 443)) == nil)
        r.check("service endpoint refused",
              host(.service(name: "n", type: "_t._tcp", domain: "local", interface: nil)) == nil)
        if let ll = IPv6Address("fe80::1%lo0") {
            let idx = if_nametoindex("lo0")
            r.check("link-local scope", host(.hostPort(host: .ipv6(ll), port: 80)) == "[fe80::1%\(idx)]:80",
                  host(.hostPort(host: .ipv6(ll), port: 80)) ?? "nil")
        }
    }

    // -- peer authentication -------------------------------------------------

    private static func peerAuth(_ r: Recorder) {
        r.check("zero token rejected", !PeerAuth.verifyPeer(auditToken: audit_token_t()))
        r.check("bad fd rejected", !PeerAuth.verifyPeer(socket: -1))
        var pipeFDs: [Int32] = [0, 0]
        if pipe(&pipeFDs) == 0 {
            r.check("non-socket rejected", !PeerAuth.verifyPeer(socket: pipeFDs[0]))
            close(pipeFDs[0]); close(pipeFDs[1])
        }
        guard let (a, peerEnd) = pair() else { r.fail("FAIL peerAuth: no socketpair"); return }
        defer { _ = peerEnd }   // keep the other end open: a closed peer has no token
        r.check("peer token readable", PeerAuth.peerAuditToken(of: a.fd) != nil)
        // The peer here is THIS process: an ad-hoc/unsigned test binary. The
        // production requirement (Developer ID team OU) must reject it ...
        r.check("production requirement rejects unsigned peer", !PeerAuth.verifyPeer(socket: a.fd))
        r.check("garbage requirement rejected",
              !PeerAuth.verifyPeer(socket: a.fd, requirement: "this is not a requirement"))
        // ... while the identical mechanism accepts it under a requirement it does
        // meet (positive control: audit token -> SecCode -> requirement works).
        if let own = ownIdentifierRequirement() {
            r.check("own-identifier requirement accepts self", PeerAuth.verifyPeer(socket: a.fd, requirement: own), own)
            r.check("wrong identifier rejects self",
                  !PeerAuth.verifyPeer(socket: a.fd, requirement: "identifier \"definitely.not.me\""))
        } else {
            r.fail("FAIL peerAuth: could not read own signing identifier")
        }
        r.check("requirement constant",
              PeerAuth.coreRequirement == #"anchor apple generic and certificate leaf[subject.OU] = "995PCLM9KH""#,
              PeerAuth.coreRequirement)
    }

    // -- rendezvous file validation ------------------------------------------

    private static func rendezvous(_ r: Recorder) {
        let fm = FileManager.default
        var tmp = ProcessInfo.processInfo.environment["TMPDIR"] ?? NSTemporaryDirectory()
        if !tmp.hasSuffix("/") { tmp += "/" }
        let base = tmp + "rv-\(getpid())-\(UInt32.random(in: 0..<UInt32.max))"
        defer { try? fm.removeItem(atPath: base) }
        do {
            try fm.createDirectory(atPath: base, withIntermediateDirectories: true,
                                   attributes: [.posixPermissions: 0o700])
            let good = base + "/sock"
            try fm.createDirectory(atPath: good, withIntermediateDirectories: false,
                                   attributes: [.posixPermissions: 0o700])
            @discardableResult
            func file(_ name: String, _ content: Data, mode: Int = 0o600) throws -> String {
                let path = base + "/" + name
                // Plain POSIX I/O: exact mode, no atomic-rename side effects.
                let fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, mode_t(mode))
                guard fd >= 0 else { throw HandoffError.io(errno: errno) }
                defer { _ = close(fd) }
                try FDIO.writeAll(fd, content)
                guard fchmod(fd, mode_t(mode)) == 0 else { throw HandoffError.io(errno: errno) }   // defeat the umask
                return path
            }
            func accepted(_ path: String) -> String? { try? Rendezvous.socketDirectory(at: path) }

            // Positive control: exactly the format the core must write.
            r.check("rendezvous valid", accepted(try file("ok", Data((good + "\n").utf8))) == good)
            r.check("rendezvous valid without newline", accepted(try file("ok2", Data(good.utf8))) == good)

            // Each negative differs from the positive control in ONE property.
            r.check("rendezvous missing file", accepted(base + "/nope") == nil)
            r.check("rendezvous group-writable file", accepted(try file("gw", Data(good.utf8), mode: 0o620)) == nil)
            r.check("rendezvous world-writable file", accepted(try file("ow", Data(good.utf8), mode: 0o602)) == nil)
            _ = symlink(base + "/ok", base + "/link")
            r.check("rendezvous symlink leaf refused", accepted(base + "/link") == nil)
            _ = mkfifo(base + "/fifo", 0o600)
            r.check("rendezvous fifo refused (and does not block)", accepted(base + "/fifo") == nil)
            r.check("rendezvous empty file", accepted(try file("empty", Data())) == nil)
            r.check("rendezvous oversize file",
                    accepted(try file("big", Data(repeating: 0x2f, count: HandoffConfig.maxRendezvousBytes + 1))) == nil)
            r.check("rendezvous relative path", accepted(try file("rel", Data("sock".utf8))) == nil)
            r.check("rendezvous NUL in path", accepted(try file("nul", Data((good + "\0x").utf8))) == nil)
            let tooLong = "/" + String(repeating: "a", count: 100)
            r.check("rendezvous path too long for sun_path", accepted(try file("long", Data(tooLong.utf8))) == nil)

            let loose = base + "/loose"
            try fm.createDirectory(atPath: loose, withIntermediateDirectories: false,
                                   attributes: [.posixPermissions: 0o755])
            _ = chmod(loose, 0o755)
            r.check("rendezvous directory 0755 refused", accepted(try file("d755", Data(loose.utf8))) == nil)
            _ = chmod(loose, 0o750)
            r.check("rendezvous directory 0750 refused", accepted(try file("d750", Data(loose.utf8))) == nil)
            _ = chmod(loose, 0o705)
            r.check("rendezvous directory 0705 refused", accepted(try file("d705", Data(loose.utf8))) == nil)
            _ = symlink(good, base + "/dirlink")
            r.check("rendezvous directory symlink refused",
                    accepted(try file("dlink", Data((base + "/dirlink").utf8))) == nil)
            r.check("rendezvous regular file as directory refused",
                    accepted(try file("notdir", Data((base + "/ok").utf8))) == nil)
            // 0700 but owned by another uid (root): not the file owner -> refused.
            var rootStat = stat()
            if lstat("/var/root", &rootStat) == 0, rootStat.st_uid != getuid(),
               (rootStat.st_mode & (S_IRWXG | S_IRWXO)) == 0 {
                r.check("rendezvous directory owned by another uid refused",
                        accepted(try file("other", Data("/var/root".utf8))) == nil)
            }
        } catch {
            r.fail("FAIL rendezvous fixture setup: \(error)")
        }
        // The same rules as pure predicates, with literal modes/uids, so the
        // owner-mismatch branch is proven without a root-owned fixture.
        func st(_ mode: Int, uid: uid_t = 501, size: off_t = 10) -> stat {
            var value = stat()
            value.st_mode = mode_t(mode); value.st_uid = uid; value.st_size = size
            return value
        }
        let dirBit = Int(S_IFDIR), regBit = Int(S_IFREG)
        r.check("dir 0700 same owner ok", Rendezvous.isAcceptableDirectory(st(dirBit | 0o700), fileOwner: 501))
        r.check("dir 0700 other owner refused", !Rendezvous.isAcceptableDirectory(st(dirBit | 0o700, uid: 0), fileOwner: 501))
        r.check("dir 0750 refused", !Rendezvous.isAcceptableDirectory(st(dirBit | 0o750), fileOwner: 501))
        r.check("dir 0701 refused", !Rendezvous.isAcceptableDirectory(st(dirBit | 0o701), fileOwner: 501))
        r.check("symlink refused as dir", !Rendezvous.isAcceptableDirectory(st(Int(S_IFLNK) | 0o700), fileOwner: 501))
        r.check("file 0600 ok", Rendezvous.isAcceptableFile(st(regBit | 0o600)))
        r.check("file 0620 refused", !Rendezvous.isAcceptableFile(st(regBit | 0o620)))
        r.check("file 0602 refused", !Rendezvous.isAcceptableFile(st(regBit | 0o602)))
        r.check("file size 0 refused", !Rendezvous.isAcceptableFile(st(regBit | 0o600, size: 0)))
        r.check("file size cap", Rendezvous.isAcceptableFile(st(regBit | 0o600, size: off_t(HandoffConfig.maxRendezvousBytes)))
                && !Rendezvous.isAcceptableFile(st(regBit | 0o600, size: off_t(HandoffConfig.maxRendezvousBytes + 1))))
        r.check("fifo refused as file", !Rendezvous.isAcceptableFile(st(Int(S_IFIFO) | 0o600)))
        // UnixSocket.connect argument handling.
        r.expectThrows("connect to a missing socket") { _ = try UnixSocket.connect(path: base + "/missing.sock") }
        r.expectThrows("connect to an over-long path") {
            _ = try UnixSocket.connect(path: "/" + String(repeating: "a", count: 200))
        }
    }

    // -- CoreLink + FlowHandoff.claim ----------------------------------------

    private static func coreLinkAndClaim(_ r: Recorder) {
        // 1. DECOY control peer: fails the production requirement -> serve() returns
        //    false, the peer receives ZERO bytes (not even Hello), nothing attaches.
        if let (core, provider) = pair() {
            let link = CoreLink()   // production requirement
            let served = link.serve(provider, directory: "/nonexistent")
            r.check("decoy control rejected", !served)
            r.check("decoy control got zero bytes", drainCount(core.fd) == 0)
            r.check("decoy not attached", !link.isAttached && link.current() == nil)
        }

        guard let own = ownIdentifierRequirement() else { return }

        // 2. Verified control peer: Hello is exactly the contract, Scope arms it,
        //    losing the channel fails open again.
        guard let (core, provider) = pair() else { return }
        let link = CoreLink(requirement: own)
        let done = DispatchSemaphore(value: 0)
        let serveResult = Box<Bool>()
        Thread { serveResult.append(link.serve(provider, directory: "/run/aitm")); done.signal() }.start()

        let hello = (try? FDIO.readFrame(core.fd, max: 1 << 20)).flatMap { $0 }.map(string)
        r.check("hello on the wire", hello == #"{"Hello":{"protocol_version":1}}"#, hello ?? "nil")
        r.check("attached but fail-open until Scope", link.isAttached && link.current() == nil)

        try? FDIO.writeFrame(core.fd, Data(#"{"Scope":{"spec":"example.com"}}"#.utf8), max: 1 << 20)
        var armed = false
        for _ in 0..<100 where !armed {
            if link.current() != nil { armed = true } else { usleep(20_000) }
        }
        r.check("scope arms the link", armed)

        // 3. claim(): out of scope -> nil, data socket never dialed.
        let dialPaths = Box<String>()
        let dataPairs = Box<(SocketHandle, SocketHandle)>()
        func makeHandoff(requirement: String) -> FlowHandoff {
            FlowHandoff(link: link, requirement: requirement, dial: { path in
                dialPaths.append(path)
                guard let (dataCore, dataProvider) = pair() else { throw HandoffError.unavailable("pair") }
                dataPairs.append((dataCore, dataProvider))
                return dataProvider
            })
        }
        let handoff = makeHandoff(requirement: own)
        let outside = FlowDescriptor(kind: .tcp, remote: FlowEndpoint(ip: "8.8.8.8", port: 443),
                                     remoteHostname: "other.org", sourceApp: nil, local: nil)
        r.check("out of scope fails open", handoff.claim(outside) == nil)
        r.check("out of scope never dials", dialPaths.all.isEmpty)

        // 4. claim(): in scope -> FlowOpen on control THEN handshake on data.
        let inside = FlowDescriptor(kind: .tcp, remote: FlowEndpoint(ip: "93.184.216.34", port: 443),
                                    remoteHostname: "example.com", sourceApp: "com.apple.curl", local: nil)
        let claimed = handoff.claim(inside)
        r.check("in scope is claimed", claimed?.id == 1)
        r.check("data socket dialed in the core's directory", dialPaths.all == ["/run/aitm/data.sock"], "\(dialPaths.all)")
        let open = (try? FDIO.readFrame(core.fd, max: 1 << 20)).flatMap { $0 }.map(string)
        r.check("FlowOpen on the wire",
              open == #"{"FlowOpen":{"flow_id":1,"kind":"Tcp","remote":"93.184.216.34:443","remote_hostname":"example.com","source_app":"com.apple.curl","local":null}}"#,
              open ?? "nil")
        if let dataCore = dataPairs.all.first?.0 {
            let hs = (try? FDIO.readFrame(dataCore.fd, max: 1 << 20)).flatMap { $0 }.map(string)
            r.check("handshake is the first data frame", hs == #"{"flow_id":1}"#, hs ?? "nil")
        } else {
            r.fail("FAIL claim: no data socket")
        }

        // 5. DECOY data peer (control verified, data fails the production
        //    requirement): the claim fails open, the data peer gets ZERO bytes and
        //    the control channel gets no FlowOpen.
        let before = dataPairs.all.count
        let strict = makeHandoff(requirement: PeerAuth.coreRequirement)
        r.check("decoy data peer fails open", strict.claim(inside) == nil)
        if dataPairs.all.count > before, let decoy = dataPairs.all.last?.0 {
            r.check("decoy data peer got zero bytes", drainCount(decoy.fd) == 0)
        } else {
            r.fail("FAIL decoy data: socket not dialed")
        }
        r.check("no FlowOpen after a rejected data peer", drainCount(core.fd, timeoutMs: 200) == 0)

        // 6. Losing the core detaches and fails open again.
        core.shutdownBoth()
        _ = done.wait(timeout: .now() + 5)
        r.check("serve returned after core closed", serveResult.all == [true])
        r.check("detached after core closed", !link.isAttached && link.current() == nil)
        r.check("claim fails open when detached", handoff.claim(inside) == nil)

        // 7. A hostile frame length from the core also detaches (fails open).
        if let (core2, provider2) = pair() {
            let link2 = CoreLink(requirement: own)
            let done2 = DispatchSemaphore(value: 0)
            Thread { _ = link2.serve(provider2, directory: "/run/aitm"); done2.signal() }.start()
            _ = try? FDIO.readFrame(core2.fd, max: 1 << 20)
            var evil: [UInt8] = [0xff, 0xff, 0xff, 0xff]
            _ = evil.withUnsafeMutableBytes { write(core2.fd, $0.baseAddress, 4) }
            r.check("hostile control frame detaches", done2.wait(timeout: .now() + 5) == .success && !link2.isAttached)
        }
    }

    // -- pumps ---------------------------------------------------------------

    private final class FakeTCPFlow: ProxiedTCPFlow, @unchecked Sendable {
        private let lock = NSLock()
        private var chunks: [Data]
        private let readError: Error?
        private(set) var written = Data()
        private(set) var writeSizes: [Int] = []
        private(set) var closedRead: [Error?] = []
        private(set) var closedWrite: [Error?] = []
        init(chunks: [Data], readError: Error? = nil) { self.chunks = chunks; self.readError = readError }
        func read(_ completion: @escaping (Data?, Error?) -> Void) {
            lock.lock()
            let next: Data? = chunks.isEmpty ? nil : chunks.removeFirst()
            let eof = chunks.isEmpty && next == nil
            lock.unlock()
            if let next { completion(next, nil) }
            else if eof, let readError { completion(nil, readError) }
            else { completion(nil, nil) }
        }
        func write(_ data: Data, _ completion: @escaping (Error?) -> Void) {
            lock.lock(); written.append(data); writeSizes.append(data.count); lock.unlock()
            completion(nil)
        }
        func closeRead(_ error: Error?) { lock.lock(); closedRead.append(error); lock.unlock() }
        func closeWrite(_ error: Error?) { lock.lock(); closedWrite.append(error); lock.unlock() }
        var snapshot: (Data, [Int], Int, Int) {
            lock.lock(); defer { lock.unlock() }
            return (written, writeSizes, closedRead.count, closedWrite.count)
        }
    }

    private static func pumps(_ r: Recorder) {
        // TCP: 3 outbound chunks, the core echoes everything, EOF half-closes.
        if let (core, provider) = pair() {
            let payload = (0..<100_000).map { UInt8(truncatingIfNeeded: $0 &* 31) }
            let chunks = stride(from: 0, to: payload.count, by: 40_000).map {
                Data(payload[$0..<min($0 + 40_000, payload.count)])
            }
            let flow = FakeTCPFlow(chunks: chunks)
            let finished = DispatchSemaphore(value: 0)
            let received = Box<Data>()
            // Fake core: echo until the provider half-closes, then close.
            Thread {
                var buf = [UInt8](repeating: 0, count: 8192)
                while true {
                    let n = read(core.fd, &buf, buf.count)
                    if n <= 0 { break }
                    received.append(Data(buf[0..<n]))
                    try? FDIO.writeAll(core.fd, Data(buf[0..<n]))
                }
                // EOF the way the Rust core does (tokio `shutdown()` = SHUT_WR). A
                // peer `shutdown(SHUT_RDWR)` does not wake a reader whose own end
                // already half-closed on XNU; a real core drops (close) or SHUT_WR.
                core.shutdownWrite()
            }.start()
            let pump = TCPFlowPump(flow: flow, socket: provider) { finished.signal() }
            pump.start()
            r.check("tcp pump finishes", finished.wait(timeout: .now() + 10) == .success)
            let (written, sizes, closedRead, closedWrite) = flow.snapshot
            r.check("tcp bytes reach the core intact", received.all.reduce(Data(), +) == Data(payload))
            r.check("tcp echo returns intact", written == Data(payload))
            r.check("tcp inbound reads capped", (sizes.max() ?? 0) <= HandoffConfig.maxInboundRead, "\(sizes.max() ?? 0)")
            r.check("tcp EOF half-closes read", closedRead == 1, "\(closedRead)")
            r.check("tcp core EOF closes write", closedWrite == 1, "\(closedWrite)")
        }
        // TCP: a flow read error tears everything down and the core sees EOF.
        if let (core, provider) = pair() {
            struct Boom: Error {}
            let flow = FakeTCPFlow(chunks: [], readError: Boom())
            let finished = DispatchSemaphore(value: 0)
            let pump = TCPFlowPump(flow: flow, socket: provider) { finished.signal() }
            pump.start()
            r.check("tcp error finishes", finished.wait(timeout: .now() + 10) == .success)
            r.check("tcp error closes the data socket (core sees EOF)", drainCount(core.fd) == 0)
            r.check("tcp error closed both flow sides", flow.snapshot.2 >= 1 && flow.snapshot.3 >= 1)
        }
        udpPump(r)
    }

    /// A flow whose FIRST write blocks until `gate` opens, like a slow NE consumer.
    private final class GatedTCPFlow: ProxiedTCPFlow, @unchecked Sendable {
        private let lock = NSLock()
        private let gate: DispatchSemaphore
        private var first = true
        private(set) var sizes: [Int] = []
        init(gate: DispatchSemaphore) { self.gate = gate }
        func read(_ completion: @escaping (Data?, Error?) -> Void) {}   // app idle
        func write(_ data: Data, _ completion: @escaping (Error?) -> Void) {
            lock.lock(); let wasFirst = first; first = false; sizes.append(data.count); lock.unlock()
            if wasFirst { _ = gate.wait(timeout: .now() + 10) }
            completion(nil)
        }
        func closeRead(_ error: Error?) {}
        func closeWrite(_ error: Error?) {}
        var snapshot: [Int] { lock.lock(); defer { lock.unlock() }; return sizes }
    }

    /// The core can burst far more than the cap while the app is slow; the pump
    /// must still hand the flow at most `maxInboundRead` bytes at a time.
    private static func inboundCap(_ r: Recorder) {
        guard let (core, provider) = pair() else { return }
        var big: Int32 = 1 << 20
        for fd in [core.fd, provider.fd] {
            _ = setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &big, socklen_t(MemoryLayout<Int32>.size))
            _ = setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &big, socklen_t(MemoryLayout<Int32>.size))
        }
        let gate = DispatchSemaphore(value: 0)
        let flow = GatedTCPFlow(gate: gate)
        let pump = TCPFlowPump(flow: flow, socket: provider) {}
        pump.start()
        let burst = Data(repeating: 0x5a, count: 200_000)
        try? FDIO.writeAll(core.fd, Data([0x01]))      // lets the pump block in its first (gated) write
        usleep(200_000)
        try? FDIO.writeAll(core.fd, burst)             // fits the enlarged buffers; pump is gated
        usleep(200_000)
        gate.signal()
        var total = 0
        for _ in 0..<100 where total < burst.count + 1 {
            total = flow.snapshot.reduce(0, +)
            if total < burst.count + 1 { usleep(50_000) }
        }
        let sizes = flow.snapshot
        r.check("inbound burst fully delivered", total == burst.count + 1, "\(total)")
        r.check("inbound writes never exceed the cap", (sizes.max() ?? 0) <= HandoffConfig.maxInboundRead,
                "max \(sizes.max() ?? 0)")
        pump.abort()
    }

    private final class FakeUDPFlow: ProxiedUDPFlow, @unchecked Sendable {
        private let lock = NSLock()
        private var batches: [[(Data, FlowEndpoint)]]
        private var pending: [([(Data, FlowEndpoint)]?, Error?) -> Void] = []
        private(set) var replies: [(Data, FlowEndpoint)] = []
        init(batches: [[(Data, FlowEndpoint)]]) { self.batches = batches }
        func read(_ completion: @escaping ([(Data, FlowEndpoint)]?, Error?) -> Void) {
            lock.lock()
            let next: [(Data, FlowEndpoint)]? = batches.isEmpty ? nil : batches.removeFirst()
            // An idle real flow never completes a read; keep it pending.
            if next == nil { pending.append(completion) }
            lock.unlock()
            if let next { completion(next, nil) }
        }
        func write(_ datagram: Data, from remote: FlowEndpoint, _ completion: @escaping (Error?) -> Void) {
            lock.lock(); replies.append((datagram, remote)); lock.unlock()
            completion(nil)
        }
        func closeRead(_ error: Error?) {}
        func closeWrite(_ error: Error?) {}
        var repliesSnapshot: [(Data, FlowEndpoint)] { lock.lock(); defer { lock.unlock() }; return replies }
    }

    private static func udpPump(_ r: Recorder) {
        guard let (core, provider) = pair() else { return }
        let remote = FlowEndpoint(ip: "1.1.1.1", port: 53)
        let other = FlowEndpoint(ip: "9.9.9.9", port: 53)
        let flow = FakeUDPFlow(batches: [[
            (Data("q1".utf8), remote),
            (Data("stray".utf8), other),
            (Data(count: HandoffConfig.maxDatagram + 1), remote),
            (Data("q2".utf8), remote),
        ]])
        let finished = DispatchSemaphore(value: 0)
        let pump = UDPFlowPump(flow: flow, socket: provider, remote: remote) { finished.signal() }
        pump.start()
        let first = (try? FDIO.readFrame(core.fd, max: HandoffConfig.maxDatagram)).flatMap { $0 }.map(string)
        let second = (try? FDIO.readFrame(core.fd, max: HandoffConfig.maxDatagram)).flatMap { $0 }.map(string)
        r.check("udp forwards remote datagrams in order", first == "q1" && second == "q2", "\(first ?? "nil") \(second ?? "nil")")
        r.check("udp drops other-remote datagram", pump.droppedForeign == 1, "\(pump.droppedForeign)")
        r.check("udp drops oversize datagram", pump.droppedOversize == 1, "\(pump.droppedOversize)")
        try? FDIO.writeFrame(core.fd, Data("answer".utf8), max: HandoffConfig.maxDatagram)
        var got = false
        for _ in 0..<100 where !got {
            if flow.repliesSnapshot.count == 1 { got = true } else { usleep(20_000) }
        }
        let reply = flow.repliesSnapshot.first
        r.check("udp reply is addressed from the pinned remote",
              got && reply.map { string($0.0) } == "answer" && reply?.1 == remote)
        core.shutdownWrite()   // the core is done: the whole UDP flow must end
        r.check("udp pump finishes when the core closes", finished.wait(timeout: .now() + 10) == .success)
    }

    // -- Rust interop fixtures -----------------------------------------------

    /// Write the exact bytes this side puts on the wire so a Rust test can parse
    /// them with the REAL `ControlMessage` / `DataHandshake` / `read_datagram`.
    static func writeFixtures(to dir: String) throws {
        func put(_ name: String, _ body: Data, max: Int) throws {
            try HandoffWire.frame(body, max: max).write(to: URL(fileURLWithPath: dir + "/" + name))
        }
        let big = HandoffConfig.maxControlFrame
        try put("hello.bin", HandoffMessages.hello(), max: big)
        try put("flowopen_tcp.bin", HandoffMessages.flowOpen(FlowOpenMessage(
            flowID: 42, kind: .tcp, remote: "93.184.216.34:443", remoteHostname: "example.com",
            sourceApp: "com.apple.curl", local: nil)), max: big)
        try put("flowopen_udp.bin", HandoffMessages.flowOpen(FlowOpenMessage(
            flowID: 7, kind: .udp, remote: "[2001:db8::1]:53", remoteHostname: nil,
            sourceApp: nil, local: "10.0.0.2:51515")), max: big)
        try put("flowopen_linklocal.bin", HandoffMessages.flowOpen(FlowOpenMessage(
            flowID: 9, kind: .tcp, remote: "[fe80::1%4]:80", remoteHostname: "a\"b\\c\n/\u{e9}",
            sourceApp: "", local: nil)), max: big)
        try put("handshake.bin", HandoffMessages.dataHandshake(flowID: 42), max: big)
        try put("datagram.bin", Data([0x00, 0xff, 0x10, 0x20]), max: HandoffConfig.maxDatagram)
    }

    /// Decode the frames the REAL Rust code produced; returns failures.
    static func checkRustFixtures(from dir: String) -> [String] {
        var failures: [String] = []
        func unframe(_ name: String) -> Data? {
            guard let raw = try? Data(contentsOf: URL(fileURLWithPath: dir + "/" + name)), raw.count >= 4 else {
                failures.append("FAIL rust fixture \(name) missing"); return nil
            }
            let declared = raw.prefix(4).reduce(0) { ($0 << 8) | Int($1) }
            guard declared == raw.count - 4 else {
                failures.append("FAIL rust fixture \(name): prefix \(declared) != body \(raw.count - 4)"); return nil
            }
            return raw.dropFirst(4)
        }
        if let scope = unframe("rust_scope.bin") {
            let msg = try? HandoffMessages.decodeCore(scope)
            if msg != .scope("example.com,*.api.test:8443") { failures.append("FAIL rust Scope decoded as \(String(describing: msg)) from \(string(scope))") }
        }
        if let dg = unframe("rust_datagram.bin"), Array(dg) != [0x00, 0xff, 0x10, 0x20] {
            failures.append("FAIL rust datagram body \(Array(dg))")
        }
        return failures
    }
}
#endif
