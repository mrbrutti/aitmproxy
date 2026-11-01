@testable import AitmproxyKit
import AitmBusClient
import Foundation

extension Fixtures {
    /// A `scan.discover` result over the sample rows: every endpoint and every
    /// injection point names a sample flow (`endpoint_flows` is keyed by the same
    /// URL string `endpoints` lists), and the secret-named points arrive redacted,
    /// as the scanner returns them. Input for `ScanTests`.
    static let scanDiscover: JSONValue = {
        func point(_ n: Int, _ location: String, _ name: String, _ example: String) -> JSONValue {
            ["flow": .string(id(n).raw), "location": .string(location), "name": .string(name), "example": .string(example)]
        }
        let products = "http://api.shop-staging.test/api/products?category=electronics&limit=20"
        let orders = "http://api.shop-staging.test/api/orders?page=3"
        let login = "http://auth.shop-staging.test/api/auth/login"
        return [
            "endpoints": [.string(products), .string(orders), .string(login)],
            "endpoint_flows": [
                products: .string(id(41).raw),
                orders: .string(id(45).raw),
                login: .string(id(50).raw),
            ],
            "injection_points": [
                point(41, "query", "category", "electronics"),
                point(41, "query", "limit", "20"),
                point(45, "query", "page", "3"),
                point(50, "body_param", "email", "ops@shop-staging.test"),
                point(50, "body_param", "password", "<redacted>"),
                point(50, "cookie", "session", "<redacted>"),
            ],
            "pages_crawled": 3,
            "stopped_reason": nil,
        ]
    }()
}
