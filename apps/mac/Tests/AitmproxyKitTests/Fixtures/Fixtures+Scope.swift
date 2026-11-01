@testable import AitmproxyKit
import Foundation

extension Fixtures {
    /// The three fixture hosts with plausible limits (S-047): the API throttled
    /// hard with an error budget, auth harder still, the CDN loose and budgetless.
    static let scopeEntries: [ScopeEntry] = [
        ScopeEntry(host: "api.shop-staging.test",
                   limit: RateLimit(requestsPerSecond: 10, burst: 20, backoffFactor: 2, errorBudget: 50)),
        ScopeEntry(host: "auth.shop-staging.test",
                   limit: RateLimit(requestsPerSecond: 2, burst: 5, backoffFactor: 4, errorBudget: 10)),
        ScopeEntry(host: "cdn.shop-staging.test",
                   limit: RateLimit(requestsPerSecond: 50, burst: 100, backoffFactor: 1.5)),
    ]

    /// Limits by host, for pairing with the live `scope.list`.
    static var scopeLimits: [String: RateLimit] {
        Dictionary(uniqueKeysWithValues: scopeEntries.compactMap { entry in entry.limit.map { (entry.host, $0) } })
    }
}
