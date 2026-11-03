import Foundation

/// The `Store.defaults` keys behind Settings ▸ Proxy's system-proxy controls (spec
/// 2026-10-31-system-proxy-automation-design §D13 "Settings ▸ Proxy"), and the one
/// parser that turns the "Bypass hosts" field into a host list.
///
/// Settings ▸ Proxy writes the keys; `EmbeddedCore.spawn()` reads them fresh on every
/// spawn so Apply & Restart Core picks them up; `EmbeddedCoreController` snapshots them
/// on `.ready` for the Apply dirty-check. Naming them once here keeps the writer and
/// the two readers on the same literal.
public enum SystemProxyPreferences {
    /// Bool, default false: "Set system proxy at launch" → the config's `system_proxy.auto`.
    public static let autoKey = "systemProxy.auto"
    /// String, default "": the "Bypass hosts" field as typed → `system_proxy.bypass`
    /// and the `bypass` param of a live `proxy.system.set`.
    public static let bypassKey = "systemProxy.bypass"
    /// The §D5 recommended list the "Bypass hosts" field shows until the operator edits it: the
    /// operator's own tooling (Claude Desktop, browsers, `gh`) does not trust the MITM CA and
    /// would fail TLS while the system proxy points at the core. A UI default for the setting,
    /// not part of the core's loopback/local `BYPASS_DEFAULT`. Read through `bypassField(_:)`.
    public static let defaultBypassField = "*.anthropic.com, api.anthropic.com, claude.ai, *.claude.ai, github.com, *.githubusercontent.com"

    /// The stored field, or the recommended list when the key has never been written — and on
    /// that first read the recommended list is WRITTEN under the key, so what the app will pass as
    /// the bypass list is readable from the store (`defaults read … systemProxy.bypass`) before the
    /// operator ever opens Settings ▸ Proxy. The release acceptance (MAC-6/MAC-15) reads it there
    /// to know which hosts "Set as System Proxy" will bypass; on 0.5.14–0.5.16 an unwritten key made
    /// that step a SKIP. Every reader (core spawn, Apply dirty-check, the live set) goes through here,
    /// so the first spawn of the embedded core is the first write. An operator's own value, including
    /// an empty field, is never touched.
    public static func bypassField(_ defaults: UserDefaults) -> String {
        if let stored = defaults.string(forKey: bypassKey) { return stored }
        defaults.set(defaultBypassField, forKey: bypassKey)
        return defaultBypassField
    }
    /// Bool, default false: the first-run sheet's "Don't ask again".
    public static let promptSuppressedKey = "systemProxy.promptSuppressed"
    /// Bool, default false: the first-run sheet has been shown once on this install.
    public static let sheetShownKey = "systemProxy.sheetShown"

    /// The "Bypass hosts" field is one line, comma and/or whitespace separated. Split on
    /// `,` and any whitespace (a pasted newline counts), trim, drop empties, keep the
    /// operator's order, and drop exact duplicates (first occurrence wins; case is left
    /// to the core, which owns the matching rules).
    public static func bypassHosts(_ field: String) -> [String] {
        let separators = CharacterSet.whitespacesAndNewlines.union(CharacterSet(charactersIn: ","))
        var seen = Set<String>()
        var hosts: [String] = []
        for piece in field.components(separatedBy: separators) {
            let host = piece.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !host.isEmpty, isPlausibleBypassHost(host), seen.insert(host).inserted else { continue }
            hosts.append(host)
        }
        return hosts
    }

    /// A piece the field will pass on: no control or illegal scalars (they would make the
    /// per-launch config unparseable and the core fail to start until the field is edited) and
    /// no leading `-` (an argv flag to `networksetup`). Matching rules stay the core's.
    static func isPlausibleBypassHost(_ host: String) -> Bool {
        guard !host.hasPrefix("-") else { return false }
        let banned = CharacterSet.controlCharacters.union(.illegalCharacters)
        return host.unicodeScalars.allSatisfy { !banned.contains($0) }
    }
}
