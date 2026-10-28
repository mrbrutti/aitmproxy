/// Everything the bus client can fail with.
public enum BusError: Error, Sendable, Equatable, CustomStringConvertible {
    /// The server refused the token line (`-32001`) and closed the connection.
    case unauthorized
    /// The connection dropped (or was never open) while a call was outstanding.
    case disconnected
    /// No reply arrived within the client's per-call timeout.
    case timeout
    /// A JSON-RPC level error (`-32602` for an unknown tool or malformed arguments).
    case rpc(code: Int, message: String)
    /// The tool ran and reported failure (`isError: true`); not a protocol error.
    case tool(message: String)
    /// A socket-level failure, described.
    case transport(String)
    /// A line the server sent (or a config file) that the client could not read.
    case malformed(String)

    public var description: String {
        switch self {
        case .unauthorized: return "the bus rejected the token"
        case .disconnected: return "the bus connection closed"
        case .timeout: return "the bus did not reply in time"
        case .rpc(let code, let message): return "bus error \(code): \(message)"
        case .tool(let message): return message
        case .transport(let detail): return "bus transport failed: \(detail)"
        case .malformed(let detail): return "malformed: \(detail)"
        }
    }
}
