import Foundation

extension FlowRow {
    /// What VoiceOver reads for the row (S-069): method, status, host and
    /// path, then every badge the row shows, in the words the screen uses.
    /// VoiceOver speaks the slashes itself.
    public var accessibilityDescription: String {
        var parts = [method.label]
        switch state {
        case .complete:
            if let status { parts.append("\(status) \(StatusText.reason(status))".trimmingCharacters(in: .whitespaces)) }
        case .paused: parts.append("paused")
        case .pending: parts.append("pending")
        case .killed: parts.append("killed")
        case .failed: parts.append("failed")
        }
        parts.append(authority + path)
        if kind == .websocket { parts.append("WebSocket") }
        if isReplay { parts.append("replay") }
        if edited { parts.append("edited") }
        if origin == .agent { parts.append("agent") }
        if tls == .tunnelled { parts.append("not decrypted") }
        if tls == .pinnedOrFailed { parts.append("TLS failed") }
        if let mark { parts.append("marked \(mark.rawValue)") }
        if let comment, !comment.isEmpty { parts.append("comment: \(comment)") }
        if !inScope { parts.append("out of scope") }
        return parts.joined(separator: ", ")
    }
}
