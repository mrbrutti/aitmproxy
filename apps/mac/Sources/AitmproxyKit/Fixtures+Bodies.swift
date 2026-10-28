import Foundation

/// Sample bodies for the Body viewer stories (S-021, S-027, S-029): one
/// message per format the picker lists, a generator for multi-megabyte JSON,
/// and a detail whose response the core truncated.
extension Fixtures {
    static func response(_ type: String, _ body: String, extra: [HTTPMessage.Header] = []) -> HTTPMessage {
        let data = Data(body.utf8)
        return HTTPMessage(
            startLine: "HTTP/2 200 OK",
            headers: [.init("content-type", type), .init("content-length", String(data.count)), .init("server", "envoy")] + extra,
            body: data)
    }

    /// A nested product payload, 40 lines pretty-printed.
    public static let prettyJSON = response("application/json; charset=utf-8", """
    {
      "id": 7,
      "name": "Headphones",
      "price": {
        "amount": 129.0,
        "currency": "EUR",
        "discount": null
      },
      "stock": {
        "warehouse": 42,
        "reserved": 3,
        "backorder": false
      },
      "tags": [
        "audio",
        "wireless",
        "noise-cancelling"
      ],
      "variants": [
        {
          "id": 71,
          "colour": "black",
          "available": true
        },
        {
          "id": 72,
          "colour": "silver",
          "available": false
        }
      ],
      "ratings": {
        "average": 4.6,
        "count": 1284
      },
      "links": {
        "self": "/api/products/7",
        "reviews": "/api/products/7/reviews"
      },
      "updated_at": "2026-10-27T11:04:58Z"
    }
    """)

    /// An order feed as one line, so the indenter has work to do.
    public static let xmlBody = response("application/xml", """
    <?xml version="1.0" encoding="UTF-8"?><orders page="3"><!-- staging export --><order id="9001" status="shipped">\
    <customer>ops@shop-staging.test</customer><items><item sku="HP-ANC-700" qty="1"/><item sku="CH-USB-C" qty="2"/>\
    </items><note><![CDATA[Leave at <reception>]]></note></order><order id="9002" status="pending"><customer/>\
    <items/></order></orders>
    """)

    /// A page with a remote script, stylesheet and image — the Rendered view must strip all three.
    public static let htmlBody = response("text/html; charset=utf-8", """
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="utf-8">
      <title>Order 9001</title>
      <link rel="stylesheet" href="https://cdn.shop-staging.test/app.css">
      <script src="https://telemetry.vendor-analytics.example/t.js"></script>
    </head>
    <body onload="track()">
      <h1>Order 9001</h1>
      <p>Thanks, <strong>ops</strong>. Your order has <em>shipped</em>.</p>
      <img src="https://cdn.shop-staging.test/hero.webp" alt="hero">
      <ul><li>Headphones × 1</li><li>Charger × 2</li></ul>
      <p><a href="https://shop-staging.test/orders/9001">Track it</a></p>
    </body>
    </html>
    """)

    public static let markdownBody = response("text/markdown; charset=utf-8", """
    # Release notes

    Version **2.4.1** of the staging API.

    - Fixed the `PATCH /api/cart` validation message
    - Added `backorder` to product stock
    - *Deprecated* `/v1/orders`; use `/api/orders`

    See the [changelog](https://shop-staging.test/changelog) for details.
    """)

    public static let formBody: HTTPMessage = {
        let data = Data("email=ops%40shop-staging.test&password=correct-horse-battery&remember=on&redirect=%2Fapi%2Fme".utf8)
        return HTTPMessage(
            startLine: "POST /api/auth/login HTTP/2",
            headers: [.init("host", "auth.shop-staging.test"), .init("content-type", "application/x-www-form-urlencoded"),
                      .init("content-length", String(data.count))],
            body: data)
    }()

    /// Two parts: a text field and a small JSON file upload.
    public static let multipartBody: HTTPMessage = {
        let boundary = "----aitm7f1c"
        let body = "--\(boundary)\r\nContent-Disposition: form-data; name=\"title\"\r\n\r\nQ4 export\r\n"
            + "--\(boundary)\r\nContent-Disposition: form-data; name=\"file\"; filename=\"orders.json\"\r\n"
            + "Content-Type: application/json\r\n\r\n{\"orders\": [9001, 9002]}\r\n--\(boundary)--\r\n"
        let data = Data(body.utf8)
        return HTTPMessage(
            startLine: "POST /api/export HTTP/2",
            headers: [.init("host", "api.shop-staging.test"), .init("content-type", "multipart/form-data; boundary=\(boundary)"),
                      .init("content-length", String(data.count))],
            body: data)
    }()

    /// A pretty-printed JSON array of at least `megabytes` MB (decimal), for the
    /// "opens without blocking a frame" self-test.
    public static func largeJSON(megabytes: Int) -> HTTPMessage {
        let target = max(1, megabytes) * 1_000_000
        var text = "[\n"
        text.reserveCapacity(target + 256)
        var n = 0
        while text.utf8.count < target {
            if n > 0 { text += ",\n" }
            text += """
              {
                "id": \(100_000 + n),
                "sku": "SKU-\(String(format: "%06d", n))",
                "name": "Item \(n)",
                "price": \(Double(n % 500) + 0.99),
                "available": \(n % 3 == 0 ? "true" : "false"),
                "warehouse": "eu-west-\(n % 4)"
              }
            """
            n += 1
        }
        text += "\n]"
        return response("application/json", text)
    }

    /// Flow 60: an 18.4 MB export of which the core sent the first 2 MB (S-027).
    public static let truncatedDetail: FlowDetail = {
        var page = largeJSON(megabytes: 2)
        page.headers = page.headers.map { $0.name == "content-length" ? .init("content-length", "18400000") : $0 }
        return FlowDetail(
            id: id(60),
            request: HTTPMessage(
                startLine: "GET /api/export?format=json HTTP/2",
                headers: [.init("host", "api.shop-staging.test"), .init("accept", "application/json"),
                          .init("user-agent", "curl/8.7.1")]),
            response: page,
            connection: ConnectionInfo(httpVersion: "HTTP/2", tlsVersion: "TLS 1.3", alpn: "h2",
                                       sni: "api.shop-staging.test", clientAddress: "127.0.0.1:52160",
                                       serverAddress: "10.0.4.12:443"),
            responseBodyExtent: BodyExtent(loaded: 2_000_000, total: 18_400_000))
    }()
}
