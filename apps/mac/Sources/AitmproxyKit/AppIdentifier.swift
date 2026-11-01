import Foundation

/// Pure rules over a client's signing identifier (spec 2026-10-31-mac-app-icons-and-names, D1).
/// Foundation only: the LaunchServices and icon lookup that applies these rules lives in the app
/// target (`UI/AppIdentity.swift`); everything here is unit-tested with literal values.
public enum AppIdentifier {
    /// The identifier, then its dotted prefixes down to three components, longest first.
    /// `com.google.Chrome.helper.renderer` → `[…renderer, com.google.Chrome.helper, com.google.Chrome]`;
    /// fewer than three components → just the identifier. Three is the floor so the walk never
    /// reaches a bare vendor prefix (`com.google`) that could match an unrelated registration.
    public static func candidates(for identifier: String) -> [String] {
        let parts = identifier.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count >= 3 else { return [identifier] }
        var out = [identifier]
        var length = parts.count - 1
        while length >= 3 {
            out.append(parts[0..<length].joined(separator: "."))
            length -= 1
        }
        return out
    }

    /// `node-5555…` → `node`: an identifier with no `.` whose tail is `-` + 16 or more lowercase
    /// hex digits (the linker's ad-hoc signing form) loses the tail. Anything else is unchanged,
    /// including identifiers with a dot and tails in uppercase hex.
    public static func trimmedAdHoc(_ identifier: String) -> String {
        guard !identifier.contains(".") else { return identifier }
        // Built per call: `Regex` is not `Sendable`, so it cannot be a static constant under strict
        // concurrency; the resolver memoises per identifier, so this is never a hot path. Extended
        // delimiters so the literal parses in every language mode.
        guard let match = identifier.wholeMatch(of: #/^(.+)-([0-9a-f]{16,})$/#) else { return identifier }
        return String(match.1)
    }

    /// The name shown when no bundle resolves: `knownUnbundled`, else `trimmedAdHoc`, else
    /// `ClientInfo.displayName(forSourceApp:)` (the Kit's last-dotted-component rule).
    public static func fallbackName(for identifier: String) -> String {
        knownUnbundled[identifier] ?? ClientInfo.displayName(forSourceApp: trimmedAdHoc(identifier))
    }

    /// A bundle-supplied name made safe to show: control (Cc) and format (Cf) scalars removed —
    /// the same two categories PR B's `ClientInfo.displayName(forSourceApp:)` filters, repeated
    /// here because `Flow.swift` is not edited — whitespace and newlines trimmed, one trailing
    /// `.app` dropped, at most 64 characters; nil when nothing printable is left.
    public static func sanitized(_ name: String) -> String? {
        var text = String(String.UnicodeScalarView(name.unicodeScalars.filter { scalar in
            switch scalar.properties.generalCategory {
            case .control, .format: return false
            default: return true
            }
        }))
        text = text.trimmingCharacters(in: .whitespacesAndNewlines)
        if text.hasSuffix(".app") { text.removeLast(4) }
        text = String(text.prefix(64))
        return text.isEmpty ? nil : text
    }

    /// True when a bundle path is an XPC service, login item or helper: contains `/XPCServices/`,
    /// contains `.xpc/` or ends in `.xpc`, contains `/Contents/Library/LoginItems/`, or contains
    /// `/Helpers/`.
    public static func isServicePath(_ path: String) -> Bool {
        path.contains("/XPCServices/")
            || path.contains(".xpc/") || path.hasSuffix(".xpc")
            || path.contains("/Contents/Library/LoginItems/")
            || path.contains("/Helpers/")
    }

    /// `name` + " (Service)"; the 64-character cap applies to `name` before the suffix.
    public static func serviceLabel(_ name: String) -> String {
        String(name.prefix(64)) + " (Service)"
    }

    /// Identifiers that are never an app of their own and have an honest name. The WebKit
    /// services are one process per host app (Safari, Mail, any WKWebView): without a pid the
    /// only truthful label is the service's own name, never any one host app — a shared service
    /// is never a host app, so these ids are also never asked of LaunchServices. The xcode-select
    /// shim is listed because `tool-shim-public` names nothing. Nothing else: daemons like
    /// `com.apple.dataaccessd` already get an honest name from the last-component rule.
    public static let knownUnbundled: [String: String] = [
        "com.apple.WebKit.Networking": "WebKit Networking",
        "com.apple.WebKit.GPU": "WebKit GPU",
        "com.apple.WebKit.WebContent": "WebKit WebContent",
        "com.apple.dt.xcode_select.tool-shim-public": "developer tool",
    ]

    /// Helper identifiers LaunchServices cannot resolve whose owner is known: Firefox's helpers
    /// live nested inside `Contents/MacOS`, are not LaunchServices-registered, and their dotted
    /// prefixes never reach `org.mozilla.firefox`. No `com.apple.WebKit.*` entry, ever (see
    /// `knownUnbundled`).
    public static let ownerMap: [String: String] = [
        "org.mozilla.plugincontainer": "org.mozilla.firefox",
        "org.mozilla.firefox-gpu-helper": "org.mozilla.firefox",
        "org.mozilla.firefox-media-plugin-helper": "org.mozilla.firefox",
    ]
}

public extension ClientInfo {
    /// What groups, pins and narrowing key on: the identifier when there is one, else the name.
    var groupKey: String { bundleID ?? name }

    /// The same client with the resolved display name (and the monogram that follows it);
    /// identifier and pid unchanged. Returns `self` when the name is already that, so a settled
    /// row never changes value.
    func withResolvedName(_ name: String) -> ClientInfo {
        name == self.name ? self : ClientInfo(name: name, bundleID: bundleID, pid: pid)
    }
}
