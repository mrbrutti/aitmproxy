import Foundation
import Testing
@testable import AitmproxyKit

/// The bodies `BodyFormatTests` formats, one per format the picker lists, and a generator for
/// multi-megabyte JSON. Every message is a `200 OK` with its content type and length.
private enum BodyFormatInputs {
    static func response(_ type: String, _ body: String) -> HTTPMessage {
        let data = Data(body.utf8)
        return HTTPMessage(
            startLine: "HTTP/2 200 OK",
            headers: [.init("content-type", type), .init("content-length", String(data.count)), .init("server", "envoy")],
            body: data)
    }

    /// A nested product payload, 40 lines pretty-printed.
    static let prettyJSON = response("application/json; charset=utf-8", """
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
    static let xml = response("application/xml", """
    <?xml version="1.0" encoding="UTF-8"?><orders page="3"><!-- staging export --><order id="9001" status="shipped">\
    <customer>ops@shop-staging.test</customer><items><item sku="HP-ANC-700" qty="1"/><item sku="CH-USB-C" qty="2"/>\
    </items><note><![CDATA[Leave at <reception>]]></note></order><order id="9002" status="pending"><customer/>\
    <items/></order></orders>
    """)

    /// A page with a remote script, stylesheet and image — the Rendered view must strip all three.
    static let html = response("text/html; charset=utf-8", """
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

    static let markdown = response("text/markdown; charset=utf-8", """
    # Release notes

    Version **2.4.1** of the staging API.

    - Fixed the `PATCH /api/cart` validation message
    - Added `backorder` to product stock
    - *Deprecated* `/v1/orders`; use `/api/orders`

    See the [changelog](https://shop-staging.test/changelog) for details.
    """)

    static let form: HTTPMessage = {
        let data = Data("email=ops%40shop-staging.test&password=correct-horse-battery&remember=on&redirect=%2Fapi%2Fme".utf8)
        return HTTPMessage(
            startLine: "POST /api/auth/login HTTP/2",
            headers: [.init("host", "auth.shop-staging.test"), .init("content-type", "application/x-www-form-urlencoded"),
                      .init("content-length", String(data.count))],
            body: data)
    }()

    /// Two parts: a text field and a small JSON file upload.
    static let multipart: HTTPMessage = {
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
    /// large-body viewer tests.
    static func largeJSON(megabytes: Int) -> HTTPMessage {
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
}

@Suite struct BodyFormatTests {
    func message(_ type: String?, _ body: String) -> HTTPMessage {
        HTTPMessage(startLine: "HTTP/2 200 OK", headers: type.map { [.init("content-type", $0)] } ?? [], body: Data(body.utf8))
    }

    @Test func pickerWordsInOrder() {
        #expect(BodyFormat.allCases.map(\.title)
                == ["Auto", "JSON", "XML", "HTML", "JS", "CSS", "Form", "Multipart", "Markdown", "Text", "Hex"])
        #expect(BodyFormat.json.id == "json")
        #expect(BodyFormat.markdown.isRenderable && BodyFormat.html.isRenderable && !BodyFormat.json.isRenderable)
        #expect(BodyFormat.json.isFoldable && BodyFormat.xml.isFoldable && !BodyFormat.html.isFoldable)
    }

    @Test func detectsFromContentType() {
        #expect(BodyFormat.detect(message("application/json; charset=utf-8", "{}")) == .json)
        #expect(BodyFormat.detect(message("application/problem+json", "{}")) == .json)
        #expect(BodyFormat.detect(message("text/xml", "<a/>")) == .xml)
        #expect(BodyFormat.detect(message("text/html", "<p>")) == .html)
        #expect(BodyFormat.detect(message("application/javascript", "1")) == .js)
        #expect(BodyFormat.detect(message("text/css", "a{}")) == .css)
        #expect(BodyFormat.detect(message("application/x-www-form-urlencoded", "a=1")) == .form)
        #expect(BodyFormat.detect(message("multipart/form-data; boundary=x", "--x\r\n")) == .multipart)
        #expect(BodyFormat.detect(message("text/markdown", "# hi")) == .markdown)
        #expect(BodyFormat.detect(message("text/plain", "hi")) == .text)
        #expect(BodyFormat.detect(message("application/pdf", "%PDF")) == .hex)
        #expect(BodyFormat.detect(message("image/png", "x")) == .hex)
        #expect(BodyFormat.detect(message("application/x-protobuf", "")) == .hex)
    }

    @Test func detectsFromBytesWhenTheTypeSaysNothing() {
        #expect(BodyFormat.detect(message(nil, "{\"a\": 1}")) == .json)
        #expect(BodyFormat.detect(message("application/octet-stream", "<root><x/></root>")) == .xml)
        #expect(BodyFormat.detect(message(nil, "<!doctype html><html></html>")) == .html)
        #expect(BodyFormat.detect(message(nil, "a=1&b=2")) == .form)
        #expect(BodyFormat.detect(message(nil, "hello")) == .text)
        #expect(BodyFormat.detect(HTTPMessage(startLine: "HTTP/2 204 No Content", headers: [])) == .text)
        let binary = HTTPMessage(startLine: "HTTP/2 200 OK", headers: [], body: Data([0xFF, 0xFE, 0x00, 0x80]))
        #expect(BodyFormat.detect(binary) == .hex)
    }

    @Test func autoResolvesAndChoicesStick() {
        let json = message("application/json", "{}")
        #expect(BodyFormat.auto.resolve(for: json) == .json)
        #expect(BodyFormat.hex.resolve(for: json) == .hex)
        #expect(BodyFormat.text.resolve(for: json) == .text)
        #expect(BodyFormat.multipartBoundary(BodyFormatInputs.multipart) == "----aitm7f1c")
        #expect(BodyFormat.multipartBoundary(json) == nil)
    }

    @Test func prettyJSONKeepsKeyOrder() throws {
        let compact = message("application/json", #"{"z":1,"a":{"y":[3,2],"b":null},"m":"x"}"#)
        let pretty = try #require(BodyFormat.prettyText(compact, as: .auto))
        #expect(pretty == "{\n  \"z\": 1,\n  \"a\": {\n    \"y\": [\n      3,\n      2\n    ],\n    \"b\": null\n  },\n  \"m\": \"x\"\n}")
        let document = try #require(BodyFormatInputs.prettyJSON.bodyText)
        #expect(BodyFormat.prettyText(BodyFormatInputs.prettyJSON, as: .json) == document, "already pretty: unchanged")
        #expect(document.split(separator: "\n").count == 40)
        #expect(BodyFormat.prettyText(message("application/json", "{not json"), as: .json) == "{not json", "falls back to the bytes")
    }

    @Test func prettyTextPerFormat() {
        #expect(BodyFormat.prettyText(BodyFormatInputs.form, as: .auto) == nil)
        #expect(BodyFormat.prettyText(BodyFormatInputs.multipart, as: .auto) == nil)
        #expect(BodyFormat.prettyText(BodyFormatInputs.prettyJSON, as: .hex) == nil)
        #expect(BodyFormat.prettyText(HTTPMessage(startLine: "HTTP/2 204 No Content", headers: []), as: .text) == nil)
        #expect(BodyFormat.prettyText(message("text/html", "<p>x</p>"), as: .auto) == "<p>x</p>", "HTML stays verbatim")
        #expect(BodyFormat.prettyText(BodyFormatInputs.markdown, as: .auto) == BodyFormatInputs.markdown.bodyText)
        #expect(BodyFormat.prettyText(BodyFormatInputs.form, as: .text) == BodyFormatInputs.form.bodyText, "Text forces the raw bytes")
        let latin1 = HTTPMessage(startLine: "HTTP/2 200 OK", headers: [.init("content-type", "text/plain")], body: Data([0x63, 0x61, 0x66, 0xE9]))
        #expect(BodyFormat.prettyText(latin1, as: .text) == nil, "not UTF-8: the caller shows hex")
    }

    @Test func xmlIndentIsExact() throws {
        let sample = #"<?xml version="1.0"?><orders page="3"><!-- note --><order id="1"><customer>ops</customer><items><item sku="A"/></items><note><![CDATA[Leave at <reception>]]></note></order><empty/></orders>"#
        let expected = """
        <?xml version="1.0"?>
        <orders page="3">
          <!-- note -->
          <order id="1">
            <customer>ops</customer>
            <items>
              <item sku="A"/>
            </items>
            <note><![CDATA[Leave at <reception>]]></note>
          </order>
          <empty/>
        </orders>
        """
        #expect(XMLPretty.pretty(sample) == expected)
        let pretty = try #require(BodyFormat.prettyText(BodyFormatInputs.xml, as: .auto))
        #expect(pretty.hasPrefix("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<orders page=\"3\">\n  <!-- staging export -->\n  <order id=\"9001\" status=\"shipped\">\n    <customer>ops@shop-staging.test</customer>\n"))
        #expect(pretty.contains("\n    <note><![CDATA[Leave at <reception>]]></note>\n"))
        #expect(pretty.hasSuffix("\n  <order id=\"9002\" status=\"pending\">\n    <customer/>\n    <items/>\n  </order>\n</orders>"))
        #expect(XMLPretty.pretty("<a><b></b><c>x</c></a>") == "<a>\n  <b></b>\n  <c>x</c>\n</a>", "empty and text leaves stay inline")
        #expect(XMLPretty.pretty("<a>\n  <b>x</b>\n</a>") == "<a>\n  <b>x</b>\n</a>", "already pretty: unchanged")
        #expect(XMLPretty.pretty("<a attr=\"x>y\"><b/></a>") == "<a attr=\"x>y\">\n  <b/>\n</a>", "a > inside a quoted attribute")
    }

    @Test func malformedXMLComesBackUnchanged() {
        for broken in ["<a><b></a>", "<a>", "</a>", "<a><!-- never closed", "<a><![CDATA[x", "<a attr=\"x>text", "<a><b>x</b>", "<a>x</b>", "text only", "", "<a <b/></a>"] {
            #expect(XMLPretty.pretty(broken) == broken, "\(broken)")
        }
        #expect(XMLPretty.prettyIfWellFormed("<a><b></a>") == nil)
        #expect(XMLPretty.prettyIfWellFormed("") == nil)
    }

    @Test func htmlSanitizerStripsRemoteLoads() throws {
        let html = try #require(BodyFormatInputs.html.bodyText)
        let safe = BodyFormat.sanitizedHTML(html)
        #expect(!safe.contains("<script"))
        #expect(!safe.contains("telemetry.vendor-analytics.example"))
        #expect(!safe.contains("<link"))
        #expect(!safe.contains("<img"))
        #expect(!safe.contains("onload"))
        #expect(safe.contains("<h1>Order 9001</h1>"))
        #expect(safe.contains("<strong>ops</strong>"))
        #expect(safe.contains("href=\"https://shop-staging.test/orders/9001\""), "links stay: they do not load on their own")
        let styled = "<div style=\"background:url(https://x/y.png)\" ONCLICK='x()'>a</div><STYLE>p{color:red}</STYLE><iframe src=x></iframe>"
        let cleaned = BodyFormat.sanitizedHTML(styled)
        #expect(cleaned == "<div style=\"background:url-blocked(https://x/y.png)\">a</div>")
    }

    @Test func bodySearchPlainAndRegex() throws {
        let text = "Alpha beta ALPHA\nalphabet"
        let plain = try BodySearch.ranges(of: "alpha", in: text, regex: false)
        #expect(plain.count == 3)
        #expect(plain.map { String(text[$0]) } == ["Alpha", "ALPHA", "alpha"])
        let regex = try BodySearch.ranges(of: "alpha\\b", in: text, regex: true)
        #expect(regex.map { String(text[$0]) } == ["Alpha", "ALPHA"])
        #expect(try BodySearch.ranges(of: "", in: text, regex: false).isEmpty)
        #expect(try BodySearch.ranges(of: "x*", in: text, regex: true).isEmpty, "empty matches are skipped")
        #expect(throws: BodySearch.InvalidPattern.self) { try BodySearch.ranges(of: "(", in: text, regex: true) }
        let many = String(repeating: "a", count: BodySearch.maxMatches + 50)
        #expect(try BodySearch.ranges(of: "a", in: many, regex: false).count == BodySearch.maxMatches)
    }

    @Test func codeAnalysisRangesLinesAndFolds() {
        let text = "{\n  \"a\": [\n    1\n  ],\n  \"é\": true\n}"
        let result = CodeAnalysis.analyseNow(text: text, contentType: "application/json")
        #expect(result.lineStarts == [0, 2, 11, 17, 22, 34])
        #expect(CodeAnalysis.lineStarts(text) == result.lineStarts)
        #expect(result.foldableLines == [0, 1])
        let ns = text as NSString
        let keys = result.runs.filter { $0.kind == .key }.map { ns.substring(with: $0.range) }
        #expect(keys == ["\"a\"", "\"é\""])
        #expect(result.runs.first { $0.kind == .boolean }.map { ns.substring(with: $0.range) } == "true")
        #expect(result.runs.first { $0.kind == .number }.map { ns.substring(with: $0.range) } == "1")
        #expect(result.runs.allSatisfy { $0.kind != .plain })

        let xml = CodeAnalysis.analyseNow(text: "<?xml?>\n<a>\n  <b>x</b>\n  <c/>\n  <d>\n  </d>\n</a>", contentType: "text/xml")
        #expect(xml.foldableLines == [1, 4])
        #expect(xml.runs.isEmpty, "no XML tokenizer yet: plain runs are not recorded")
        #expect(CodeAnalysis.lineStarts("") == [0])
        #expect(CodeAnalysis.lineStarts("a\n") == [0, 2])
        #expect(CodeAnalysis.analyseNow(text: "", contentType: nil).lineStarts == [0])
    }

    @Test func theBodiesDetectDecodeAndMeasure() {
        #expect(BodyFormat.detect(BodyFormatInputs.prettyJSON) == .json)
        #expect(BodyFormat.detect(BodyFormatInputs.xml) == .xml)
        #expect(BodyFormat.detect(BodyFormatInputs.html) == .html)
        #expect(BodyFormat.detect(BodyFormatInputs.markdown) == .markdown)
        #expect(BodyFormat.detect(BodyFormatInputs.form) == .form)
        #expect(BodyFormat.detect(BodyFormatInputs.multipart) == .multipart)
        let pairs = BodyKind.formDecode(BodyFormatInputs.form.body ?? Data())
        #expect(pairs.map(\.0) == ["email", "password", "remember", "redirect"])
        #expect(pairs[0].1 == "ops@shop-staging.test" && pairs[3].1 == "/api/me")
        let parts = BodyKind.multipartParts(BodyFormatInputs.multipart.body ?? Data(), boundary: "----aitm7f1c")
        #expect(parts.count == 2)
        #expect(parts[1].filename == "orders.json" && parts[1].contentType == "application/json")

        let big = BodyFormatInputs.largeJSON(megabytes: 1)
        #expect(big.bodyBytes >= 1_000_000)
        #expect(BodyFormat.detect(big) == .json)
        #expect(JSONTree.pretty(big.body ?? Data()) == big.bodyText, "generated pretty, so the viewer shows it as is")

        // A response the core truncated: the first 2 MB of an 18.4 MB export (S-027).
        let extent = BodyExtent(loaded: 2_000_000, total: 18_400_000)
        #expect(extent.isTruncated)
        #expect(extent.chipText == "truncated · 2 MB of 18.4 MB")
        #expect(!BodyExtent(loaded: 212, total: 212).isTruncated)
    }
}
