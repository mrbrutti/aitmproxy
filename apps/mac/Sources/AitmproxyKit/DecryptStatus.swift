import AitmBusClient
import Foundation

/// `proxy.status.decrypt` as the core reports it (v0.5.9+, spec
/// 2026-10-31-mac-traffic-route-advice-design D2): how many hosts the decryption list (Scope)
/// holds, whether anything is decrypted, and the one sentence the core asks every surface to
/// print verbatim while nothing is. Decoded once, so the step's N, the Scope entry's open/closed
/// state and the quoted sentence never come from two reads. Nil from an older core (no `decrypt`
/// key), and the Kit then falls back to the live scope count and its own copy of the words.
public struct DecryptStatus: Hashable, Sendable {
    public var scopeHosts: Int
    public var decrypting: Bool
    /// The core's `NOTHING_DECRYPTED_ADVICE` while `scopeHosts == 0`; nil once a host is in Scope.
    public var advice: String?

    public init(scopeHosts: Int, decrypting: Bool, advice: String?) {
        self.scopeHosts = scopeHosts
        self.decrypting = decrypting
        self.advice = advice
    }

    /// Nil unless `json` is the `decrypt` object: it always carries `scope_hosts`. A missing
    /// `decrypting` defaults to `scopeHosts > 0`; a null, missing, empty or whitespace-only `advice`
    /// is nil — an empty string is no sentence, and reading it as one would print an empty Scope row
    /// and a blank banner, where `ConnectionSummary.nothingDecryptedAdvice` is the fallback. A real
    /// sentence is kept verbatim (D3), padding included.
    public init?(json: JSONValue) {
        guard let scopeHosts = json["scope_hosts"]?.intValue else { return nil }
        let advice = json["advice"]?.stringValue.flatMap { $0.allSatisfy(\.isWhitespace) ? nil : $0 }
        self.init(scopeHosts: scopeHosts,
                  decrypting: json["decrypting"]?.boolValue ?? (scopeHosts > 0),
                  advice: advice)
    }
}
