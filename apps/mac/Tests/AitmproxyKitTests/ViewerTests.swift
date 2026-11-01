import Foundation
import Testing
@testable import AitmproxyKit

/// Inputs for the diff and code-export suites: a login parked with one header added while it
/// waited, the last response the login endpoint sent (pretty JSON the printer must leave
/// alone), and a product listing with a query.
private enum ViewerInputs {
    static let loginRow = Make.row(seq: 50, method: .post, host: "auth.shop-staging.test", path: "/api/auth/login",
                                  state: .paused, edited: true)
    static let loginDetail = Make.detail(
        id: "00000050-0000-4000-8000-000000000050",
        request: Make.message(
            "POST /api/auth/login HTTP/2",
            [("host", "auth.shop-staging.test"), ("content-type", "application/json"), ("accept", "*/*"),
             ("user-agent", "curl/8.7.1"), ("x-forwarded-for", "127.0.0.1")],
            body: "{\n  \"email\": \"ops@shop-staging.test\",\n  \"password\": \"correct-horse-battery\",\n  \"remember\": true\n}"))
    static let loginResponse = Make.response(200, [
        ("content-type", "application/json; charset=utf-8"),
        ("set-cookie", "session=9f1c…; HttpOnly; Secure; SameSite=Lax"),
        ("cache-control", "no-store"),
        ("content-length", "318"),
    ], body: """
    {
      "token": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJvcHMiLCJyb2xlIjoiYWRtaW4ifQ.…",
      "expires_in": 3600,
      "user": {
        "id": 1042,
        "email": "ops@shop-staging.test",
        "role": "admin",
        "mfa_enrolled": false
      },
      "set_cookie": "session=…; HttpOnly; Secure; SameSite=Lax"
    }
    """)
    static let productsRow = Make.row(seq: 41, host: "api.shop-staging.test", path: "/api/products",
                                     query: "category=electronics&limit=20", status: 200)
    static let productsDetail = Make.detail(
        id: "flow-41",
        request: Make.message("GET /api/products?category=electronics&limit=20 HTTP/2",
                              [("host", "api.shop-staging.test"), ("accept", "application/json")]))
}

// MARK: - JSON tree

@Suite struct JSONTreeViewerTests {
    func parse(_ text: String) throws -> JSONNode {
        try JSONTree.parse(Data(text.utf8))
    }

    func child(_ node: JSONNode, _ key: String) throws -> JSONNode {
        try #require(node.children.first { $0.key == key })
    }

    @Test func keyOrderIsPreserved() throws {
        let root = try parse(#"{"b":1,"a":2,"c":{"z":true,"y":null}}"#)
        let c = try child(root, "c")
        #expect(root.children.map(\.key) == ["b", "a", "c"])
        #expect(c.children.map(\.key) == ["z", "y"])
        #expect(root.kind == .object(count: 3))
        #expect(c.kind == .object(count: 2))
        #expect(root.summary == "3 keys")
        #expect(c.summary == "2 keys")
    }

    @Test func pathsAndArrayKeys() throws {
        let root = try parse(#"{"user":{"roles":["admin","ops"]},"odd key":1}"#)
        let roles = try child(child(root, "user"), "roles")
        #expect(roles.path == "$.user.roles")
        #expect(roles.kind == .array(count: 2))
        #expect(roles.children.map(\.key) == ["[0]", "[1]"])
        #expect(roles.children.map(\.path) == ["$.user.roles[0]", "$.user.roles[1]"])
        #expect(roles.children[0].scalarText == "admin")
        #expect(roles.children[0].id == "$.user.roles[0]")
        let odd = try child(root, "odd key")
        #expect(odd.path == #"$["odd key"]"#)
        #expect(root.path == "$")
        #expect(root.key == nil)
    }

    @Test func numbersPrintAsWritten() throws {
        let root = try parse("[3600, 129.0, -1.5e3, 0, 1E+2]")
        #expect(root.children.map(\.scalarText) == ["3600", "129.0", "-1.5e3", "0", "1E+2"])
        #expect(root.children.allSatisfy { $0.kind == .number })
    }

    @Test func scalars() throws {
        let root = try parse(#"{"t":true,"f":false,"n":null,"s":"x"}"#)
        let t = try child(root, "t")
        let f = try child(root, "f")
        let n = try child(root, "n")
        let s = try child(root, "s")
        #expect(t.kind == .bool)
        #expect(f.scalarText == "false")
        #expect(n.kind == .null)
        #expect(s.kind == .string)
        #expect(s.syntaxKind == .string)
        #expect(n.syntaxKind == .boolean)
        #expect(root.syntaxKind == .bracket)
        let bare = try JSONTree.parse(Data("42".utf8))
        #expect(bare.scalarText == "42")
        #expect(bare.kind == .number)
    }

    @Test func escapesAndUnicode() throws {
        let root = try parse(#"["a\"b\\c\n\t\/", "\u00e9\ud83d\ude00", "caf\u00E9"]"#)
        #expect(root.children[0].scalarText == "a\"b\\c\n\t/")
        #expect(root.children[1].scalarText == "é😀")
        #expect(root.children[2].scalarText == "café")
    }

    @Test func malformedInputReportsOffset() {
        func offset(_ text: String) -> Int? {
            do {
                _ = try JSONTree.parse(Data(text.utf8))
                return nil
            } catch let error as JSONTreeError {
                return error.offset
            } catch {
                return nil
            }
        }
        #expect(offset(#"{"a": 1,, }"#) == 8)
        #expect(offset("[1, 2") == 5)
        #expect(offset(#"{"a": tru}"#) == 6)
        #expect(offset(#"{"a" 1}"#) == 5)
        #expect(offset("") == 0)
        #expect(offset("[1] x") == 4)
        #expect(offset(#"["\ud800"]"#) == 2)
        #expect(JSONTreeError(offset: 8, message: "Expected a string key").description == "Expected a string key at byte 8")
    }

    @Test func forgivingAboutTrailingCommasAndBOM() throws {
        let array = try parse("[1,2,]")
        #expect(array.kind == .array(count: 2))
        let object = try parse(#"{"a":1,}"#)
        #expect(object.kind == .object(count: 1))
        var withBOM = Data([0xEF, 0xBB, 0xBF])
        withBOM.append(contentsOf: Data(" {} ".utf8))
        let empty = try JSONTree.parse(withBOM)
        #expect(empty.kind == .object(count: 0))
        #expect(empty.summary == "0 keys")
    }

    @Test func flattenFollowsTheExpandedSet() throws {
        let root = try parse(#"{"a":{"b":1},"c":[1,2]}"#)
        let collapsed = root.flatten(expanded: [])
        #expect(collapsed.map(\.node.path) == ["$"])
        #expect(collapsed[0].isExpanded == false)

        let top = root.flatten(expanded: ["$"])
        #expect(top.map(\.node.path) == ["$", "$.a", "$.c"])
        #expect(top.map(\.depth) == [0, 1, 1])
        #expect(top[0].isExpanded == true)
        #expect(top[1].isExpanded == false)

        let deeper = root.flatten(expanded: ["$", "$.c"])
        #expect(deeper.map(\.node.path) == ["$", "$.a", "$.c", "$.c[0]", "$.c[1]"])
        #expect(deeper.map(\.depth) == [0, 1, 1, 2, 2])
        #expect(deeper.map(\.id) == deeper.map(\.node.path))

        // Expanding a node whose parent is collapsed shows nothing extra.
        #expect(root.flatten(expanded: ["$.c"]).count == 1)
        #expect(root.flatten(expanded: root.allPaths).count == 6)
    }

    @Test func filterKeepsAncestors() throws {
        let root = try parse(#"{"user":{"name":"ops","roles":["admin"]},"n":1}"#)
        #expect(root.filter("adm") == ["$", "$.user", "$.user.roles", "$.user.roles[0]"])
        #expect(root.filter("NAME") == ["$", "$.user", "$.user.name"])
        #expect(root.filter("zzz").isEmpty)
        #expect(root.filter("") == root.allPaths)
    }

    @Test func sortedKeysKeepsPaths() throws {
        let root = try parse(#"{"b":1,"a":{"d":1,"c":2},"list":[{"z":1,"y":2}]}"#)
        let sorted = root.sortedKeys()
        let a = try child(sorted, "a")
        let list = try child(sorted, "list")
        #expect(sorted.children.map(\.key) == ["a", "b", "list"])
        #expect(a.children.map(\.key) == ["c", "d"])
        #expect(a.children.map(\.path) == ["$.a.c", "$.a.d"])
        #expect(list.children[0].children.map(\.key) == ["y", "z"])
        #expect(root.children.map(\.key) == ["b", "a", "list"], "the original is untouched")
    }

    @Test func copyTextIsPrettyJSON() throws {
        let root = try parse(#"{"user":{"id":1042,"tags":[],"meta":{}},"s":"a\"b\n"}"#)
        let user = try child(root, "user")
        let s = try child(root, "s")
        #expect(JSONTree.copyText(for: user) == "{\n  \"id\": 1042,\n  \"tags\": [],\n  \"meta\": {}\n}")
        #expect(JSONTree.copyText(for: s) == #""a\"b\n""#)
        #expect(JSONTree.copyText(for: root, indent: 4).hasPrefix("{\n    \"user\": {\n        \"id\": 1042,"))
    }

    @Test func prettyLeavesAPrettyBodyUnchanged() throws {
        let body = try #require(ViewerInputs.loginResponse.body)
        let original = try #require(String(data: body, encoding: .utf8))
        #expect(JSONTree.pretty(body) == original)
        #expect(JSONTree.pretty(Data("not json".utf8)) == nil)
        #expect(JSONTree.pretty(Data(#"{"b":[1,{"c":null}],"a":"x"}"#.utf8))
                == "{\n  \"b\": [\n    1,\n    {\n      \"c\": null\n    }\n  ],\n  \"a\": \"x\"\n}")
        #expect(JSONTree.minified(Data("{ \"b\" : [ 1 , 2 ] , \"a\" : true }".utf8)) == #"{"b":[1,2],"a":true}"#)
    }
}

// MARK: - Hex dump

@Suite struct HexDumpViewerTests {
    let sample = Data([0x68, 0x65, 0x6C, 0x6C, 0x6F, 0x20, 0x77, 0x6F, 0x72, 0x6C, 0x64, 0x21, 0x0A, 0x00, 0xFF, 0x7F,
                       0x41, 0x42, 0x43])

    @Test func fullLine() {
        let lines = HexDump.lines(sample)
        #expect(lines.count == 2)
        #expect(lines[0].offset == 0)
        #expect(lines[0].offsetText == "00000000")
        #expect(lines[0].hexText == "68 65 6c 6c 6f 20 77 6f  72 6c 64 21 0a 00 ff 7f")
        #expect(lines[0].asciiText == "hello world!....")
        #expect(lines[0].id == 0)
    }

    @Test func partialLastLineIsPadded() {
        let line = HexDump.lines(sample)[1]
        #expect(line.offset == 16)
        #expect(line.offsetText == "00000010")
        #expect(line.hexText.count == 48)
        #expect(line.hexText.hasPrefix("41 42 43 "))
        #expect(line.hexText.trimmingCharacters(in: .whitespaces) == "41 42 43")
        #expect(line.asciiText == "ABC")
    }

    @Test func paging() {
        #expect(HexDump.lineCount(sample.count) == 2)
        #expect(HexDump.lineCount(0) == 0)
        #expect(HexDump.lineCount(16) == 1)
        #expect(HexDump.lineCount(17) == 2)
        let page = HexDump.lines(sample, range: 1..<5)
        #expect(page.map(\.offset) == [16])
        #expect(HexDump.lines(sample, range: 5..<9).isEmpty)
        #expect(HexDump.lines(Data(), range: 0..<1).isEmpty)
        let big = Data(repeating: 0xAB, count: 1000)
        let window = HexDump.lines(big, range: 10..<12)
        #expect(window.map(\.offset) == [160, 176])
        #expect(window[0].offsetText == "000000a0")
    }

    @Test func otherWidthsAndSlices() {
        let eight = HexDump.lines(sample, bytesPerLine: 8)
        #expect(eight.count == 3)
        #expect(eight[0].hexText == "68 65 6c 6c  6f 20 77 6f")
        #expect(eight[2].offset == 16)
        // A Data slice with a non-zero start index dumps from its own first byte.
        let slice = sample[16...]
        #expect(HexDump.lines(slice)[0].asciiText == "ABC")
        #expect(HexDump.text(Data([0x41])).hasPrefix("00000000  41 "))
    }
}

// MARK: - Diff

@Suite struct TextDiffViewerTests {
    @Test func insertDeleteEqual() {
        let diff = TextDiff(old: "a\nb\nc\nd\n", new: "a\nc\nd\ne\n")
        #expect(diff.lines.map(\.kind) == [.equal, .delete, .equal, .equal, .insert])
        #expect(diff.lines.map(\.text) == ["a", "b", "c", "d", "e"])
        #expect(diff.lines.map(\.oldLine) == [1, 2, 3, 4, nil])
        #expect(diff.lines.map(\.newLine) == [1, nil, 2, 3, 4])
        #expect(diff.hasChanges)
        #expect(diff.insertions == 1)
        #expect(diff.deletions == 1)
        #expect(!diff.truncated)
    }

    @Test func unifiedOutput() {
        let diff = TextDiff(old: "a\nb\nc\nd\n", new: "a\nc\nd\ne\n")
        #expect(diff.unified() == "--- a\n+++ b\n@@ -1,4 +1,4 @@\n a\n-b\n c\n d\n+e\n")

        let insertOnly = TextDiff(old: "", new: "x\ny")
        #expect(insertOnly.hunks().map(\.header) == ["@@ -0,0 +1,2 @@"])
        #expect(insertOnly.unified(oldName: "old", newName: "new") == "--- old\n+++ new\n@@ -0,0 +1,2 @@\n+x\n+y\n")

        let same = TextDiff(old: "same\n", new: "same\n")
        #expect(!same.hasChanges)
        #expect(same.unified() == "")

        let single = TextDiff(old: "x", new: "y")
        #expect(single.hunks().map(\.header) == ["@@ -1 +1 @@"])
    }

    @Test func hunksSplitOnDistantChanges() {
        let old = (1...20).map(String.init).joined(separator: "\n")
        var changed: [String] = (1...20).map { String($0) }
        changed[1] = "two"
        changed[17] = "eighteen"
        let new = changed.joined(separator: "\n")
        let hunks = TextDiff(old: old, new: new).hunks(contextLines: 3)
        #expect(hunks.count == 2)
        #expect(hunks[0].header == "@@ -1,5 +1,5 @@")
        #expect(hunks[1].header == "@@ -15,6 +15,6 @@")
        #expect(TextDiff(old: old, new: new).hunks(contextLines: 10).count == 1)
    }

    @Test func sideBySidePairs() {
        let pairs = TextDiff(old: "a\nb\nc\nd\n", new: "a\nc\nd\ne\n").sideBySide()
        #expect(pairs.map(\.kind) == [.equal, .delete, .equal, .equal, .insert])
        #expect(pairs[1].left?.text == "b")
        #expect(pairs[1].right == nil)
        #expect(pairs[4].left == nil)
        #expect(pairs[4].right?.text == "e")

        let change = TextDiff(old: "x\ny\n", new: "z\n").sideBySide()
        #expect(change.map(\.kind) == [.change, .delete])
        #expect(change[0].left?.text == "x")
        #expect(change[0].right?.text == "z")
        #expect(change[1].left?.text == "y")
    }

    @Test func myersHandlesRepeatedLines() {
        let diff = TextDiff(old: "a\na\nb", new: "a\nb\nb")
        #expect(diff.lines.map(\.kind) == [.equal, .delete, .insert, .equal])
        #expect(diff.lines.map(\.text) == ["a", "a", "b", "b"])

        // Patience anchors on the unique `y`; whatever the script, it must rebuild both sides.
        for (old, new) in [("x\nx\nx\ny", "y\nx\nx\nx"), ("a\nb\nc", "c\nb\na"), ("", "q\nq"), ("q\nq\n", "")] {
            let diff = TextDiff(old: old, new: new)
            #expect(diff.lines.filter { $0.oldLine != nil }.map(\.text) == TextDiff.splitLines(old))
            #expect(diff.lines.filter { $0.newLine != nil }.map(\.text) == TextDiff.splitLines(new))
            #expect(diff.lines.compactMap(\.oldLine) == (0..<TextDiff.splitLines(old).count).map { $0 + 1 })
            #expect(diff.lines.compactMap(\.newLine) == (0..<TextDiff.splitLines(new).count).map { $0 + 1 })
        }
    }

    @Test func crlfAndTrailingNewlines() {
        let diff = TextDiff(old: "a\r\nb\r\n", new: "a\nb")
        #expect(!diff.hasChanges)
        #expect(TextDiff.splitLines("a\n\nb\n") == ["a", "", "b"])
        #expect(TextDiff.splitLines("") == [])
        #expect(TextDiff.splitLines("\n") == [""])
    }

    @Test func truncatesAtTheCap() {
        let big = String(repeating: "0123456789abcdef\n", count: 140_000) // 2.38 MB
        let diff = TextDiff(old: big, new: big)
        #expect(diff.truncated)
        #expect(!diff.hasChanges)
        #expect(diff.lines.count < 140_000)
        #expect(diff.lines.count >= TextDiff.maxBytesPerSide / 17 - 1)
        #expect(!TextDiff(old: "small", new: "small").truncated)
    }

    @Test func flowDiffOverTwoDetails() throws {
        let a = ViewerInputs.loginDetail
        var b = a
        b.id = FlowID("other")
        b.request.headers = b.request.headers.map { header in
            header.name == "x-forwarded-for" ? HTTPMessage.Header(header.name, "10.0.0.1") : header
        }
        let result = FlowDiff.compare(a, b)
        #expect(result.sections.map(\.part) == [.requestHead, .requestBody, .responseHead, .responseBody])
        #expect(result.sections.map(\.diff.hasChanges) == [true, false, false, false])
        #expect(result.hasChanges)
        let head = result.sections[0].diff
        #expect(head.deletions == 1 && head.insertions == 1)
        #expect(head.lines.first { $0.kind == .delete }?.text == "x-forwarded-for: 127.0.0.1")
        #expect(head.lines.first { $0.kind == .insert }?.text == "x-forwarded-for: 10.0.0.1")
        let patch = result.unified()
        #expect(patch.hasPrefix("--- \(a.id)/requestHead\n+++ other/requestHead\n"))
        #expect(patch.contains("-x-forwarded-for: 127.0.0.1\n+x-forwarded-for: 10.0.0.1\n"))
        #expect(!FlowDiff.compare(a, a).hasChanges)
        #expect(FlowDiff.compare(a, a).unified() == "")
    }

    @Test func flowDiffNormalisesJSONBodies() {
        let a = ViewerInputs.loginDetail
        var b = a
        b.request.body = Data(#"{"email":"ops@shop-staging.test","password":"correct-horse-battery","remember":true}"#.utf8)
        #expect(!FlowDiff.compare(a, b).sections[1].diff.hasChanges)
        b.request.body = Data(#"{"email":"ops@shop-staging.test","password":"hunter2","remember":true}"#.utf8)
        let body = FlowDiff.compare(a, b).sections[1].diff
        #expect(body.deletions == 1 && body.insertions == 1)
        #expect(body.lines.first { $0.kind == .insert }?.text == "  \"password\": \"hunter2\",")
    }

    @Test func flowDiffHeadAndBodyText() {
        #expect(FlowDiff.headText(ViewerInputs.loginResponse).hasPrefix("HTTP/2 200 OK\ncontent-type: application/json; charset=utf-8\n"))
        let binary = HTTPMessage(startLine: "HTTP/2 200 OK", headers: [.init("content-type", "application/octet-stream")],
                                 body: Data([0x00, 0xFF]))
        #expect(FlowDiff.bodyText(binary) == "00000000  00 ff" + String(repeating: " ", count: 43) + "  ..")
        #expect(FlowDiff.bodyText(HTTPMessage(startLine: "GET / HTTP/2", headers: [])) == "")
    }
}

// MARK: - Code export

@Suite struct CodeExportViewerTests {
    let row = ViewerInputs.loginRow
    let detail = ViewerInputs.loginDetail

    static let expectedCurl = """
    curl -X POST 'https://auth.shop-staging.test/api/auth/login' \\
      -H 'host: auth.shop-staging.test' \\
      -H 'content-type: application/json' \\
      -H 'accept: */*' \\
      -H 'user-agent: curl/8.7.1' \\
      -H 'x-forwarded-for: 127.0.0.1' \\
      --data-raw '{
      "email": "ops@shop-staging.test",
      "password": "correct-horse-battery",
      "remember": true
    }'
    """

    @Test func curlForThePausedLogin() {
        #expect(CodeExport.curl(detail, row: row) == Self.expectedCurl)
    }

    @Test func curlDetails() {
        let get = CodeExport.Request(method: "GET", url: "https://h/x?a=1", headers: [.init("accept", "*/*")], body: nil)
        #expect(CodeExport.curl(get) == "curl 'https://h/x?a=1' \\\n  -H 'accept: */*'")

        let quoted = CodeExport.Request(method: "POST", url: "https://h/q", headers: [], body: Data(#"{"q":"it's"}"#.utf8))
        #expect(CodeExport.curl(quoted) == "curl -X POST 'https://h/q' \\\n  --data-raw '{\"q\":\"it'\\''s\"}'")
        #expect(CodeExport.shellQuote("a'b") == "'a'\\''b'")

        let encoded = CodeExport.Request(method: "GET", url: "https://h/",
                                         headers: [.init("accept-encoding", "gzip, br")], body: nil)
        #expect(CodeExport.curl(encoded) == "curl 'https://h/' \\\n  -H 'accept-encoding: gzip, br' \\\n  --compressed")
        #expect(!CodeExport.curl(encoded).contains("-k"))
        let request = CodeExport.Request(ViewerInputs.productsDetail, row: ViewerInputs.productsRow)
        #expect(request.url == "https://api.shop-staging.test/api/products?category=electronics&limit=20")
        #expect(request.method == "GET")

        let binary = CodeExport.Request(method: "POST", url: "https://h/b", headers: [], body: Data([0xFF, 0x00]))
        #expect(CodeExport.curl(binary).hasSuffix("--data-binary \"$(printf %s '/wA=' | base64 -d)\""))
        #expect(!CodeExport.curl(binary).contains("@-"))
    }

    @Test func excludedHeadersAreDroppedFromTheRequest() {
        var edited = detail
        edited.request.headers.insert(.init(":authority", "auth.shop-staging.test"), at: 0)
        edited.request.headers.append(.init("transfer-encoding", "chunked"))
        edited.request.headers.append(.init("Connection", "keep-alive"))
        edited.request.headers.append(.init("content-length", "99"))
        let request = CodeExport.Request(edited, row: row)
        #expect(request.headers.map(\.name) == ["host", "content-type", "accept", "user-agent", "x-forwarded-for"])
        let curl = CodeExport.curl(edited, row: row)
        #expect(!curl.contains("onnection") && !curl.contains("content-length") && !curl.contains(":authority"))
        #expect(request.method == "POST")
        #expect(request.url == "https://auth.shop-staging.test/api/auth/login")
    }

    @Test func otherGenerators() {
        let httpie = CodeExport.httpie(detail, row: row)
        #expect(httpie.hasPrefix("http POST 'https://auth.shop-staging.test/api/auth/login' \\\n  'host:auth.shop-staging.test' \\\n"))
        #expect(httpie.contains("--raw '{\n"))

        let python = CodeExport.pythonRequests(detail, row: row)
        #expect(python.hasPrefix("import requests\n\nurl = \"https://auth.shop-staging.test/api/auth/login\"\nheaders = {\n    \"host\": \"auth.shop-staging.test\",\n"))
        #expect(python.contains("data = \"{\\n  \\\"email\\\": \\\"ops@shop-staging.test\\\",\\n"))
        #expect(python.contains("response = requests.post(url, headers=headers, data=data)\n"))
        let custom = CodeExport.Request(method: "PURGE", url: "https://h/", headers: [], body: nil)
        #expect(CodeExport.pythonRequests(custom).contains("requests.request(\"PURGE\", url, headers=headers)"))

        let js = CodeExport.fetch(detail, row: row)
        #expect(js.hasPrefix("await fetch(\"https://auth.shop-staging.test/api/auth/login\", {\n  method: \"POST\",\n  headers: {\n"))
        #expect(js.contains("    \"content-type\": \"application/json\",\n"))
        #expect(js.contains("  body: \"{\\n  \\\"email\\\""))
        #expect(js.hasSuffix("});\n"))
    }

    @Test func rawHTTP() {
        let message = HTTPMessage(startLine: "POST /x HTTP/2", headers: [.init("host", "h"), .init("a", "b")],
                                  body: Data("hi".utf8))
        #expect(CodeExport.rawHTTP(message) == "POST /x HTTP/2\r\nhost: h\r\na: b\r\n\r\nhi")
        #expect(CodeExport.rawHTTP(HTTPMessage(startLine: "HTTP/2 204 No Content", headers: [])) == "HTTP/2 204 No Content\r\n\r\n")
    }

    @Test func parseCurlRoundTripsTheGeneratedCommand() throws {
        let edits = try #require(CodeExport.parseCurl(CodeExport.curl(detail, row: row)))
        let expected = RequestEdits(
            method: "POST", scheme: "https", authority: "auth.shop-staging.test", path: "/api/auth/login",
            headers: [
                "host": "auth.shop-staging.test", "content-type": "application/json", "accept": "*/*",
                "user-agent": "curl/8.7.1", "x-forwarded-for": "127.0.0.1",
            ],
            body: detail.request.body)
        #expect(edits == expected)

        let quoted = CodeExport.Request(method: "POST", url: "https://h/q", headers: [], body: Data(#"{"q":"it's"}"#.utf8))
        let back = try #require(CodeExport.parseCurl(CodeExport.curl(quoted)))
        #expect(back.body == quoted.body)
        #expect(back.path == "/q")
    }

    @Test func parseCurlHandlesPastedCommands() throws {
        let pasted = """
        curl 'https://api.example.com/v1/items?limit=5' \\
          -H 'Accept: application/json' \\
          -H "Authorization: Bearer abc.def" \\
          --compressed \\
          -d 'name=widget&qty=2' \\
          -k -s
        """
        let edits = try #require(CodeExport.parseCurl(pasted))
        #expect(edits.method == "POST")
        #expect(edits.scheme == "https")
        #expect(edits.authority == "api.example.com")
        #expect(edits.path == "/v1/items?limit=5")
        #expect(edits.headers == ["accept": "application/json", "authorization": "Bearer abc.def",
                                  "content-type": "application/x-www-form-urlencoded"])
        #expect(edits.body == Data("name=widget&qty=2".utf8))

        let chrome = #"curl 'http://h:8080/p' -XPUT -u user:pass -A 'ua/1' -b 'a=1; b=2' --header='X-Y: z' --data-raw $'{"a":"\x41\n"}' --insecure"#
        let c = try #require(CodeExport.parseCurl(chrome))
        #expect(c.method == "PUT")
        #expect(c.scheme == "http")
        #expect(c.authority == "h:8080")
        #expect(c.path == "/p")
        #expect(c.headers?["authorization"] == "Basic dXNlcjpwYXNz")
        #expect(c.headers?["user-agent"] == "ua/1")
        #expect(c.headers?["cookie"] == "a=1; b=2")
        #expect(c.headers?["x-y"] == "z")
        #expect(c.body == Data("{\"a\":\"A\n\"}".utf8))

        let get = try #require(CodeExport.parseCurl("curl -G -d a=1 -d 'b=2' example.com/search?x=1"))
        #expect(get.method == "GET")
        #expect(get.scheme == "http")
        #expect(get.authority == "example.com")
        #expect(get.path == "/search?x=1&a=1&b=2")
        #expect(get.body == nil)
        #expect(get.headers == nil)

        let json = try #require(CodeExport.parseCurl(#"curl --json '{"a":1}' https://h"#))
        #expect(json.method == "POST")
        #expect(json.path == "/")
        #expect(json.headers?["content-type"] == "application/json")

        let form = try #require(CodeExport.parseCurl("curl -F file=@x.png -F name=a https://h/up"))
        #expect(form.method == "POST")
        #expect(form.headers?["content-type"] == "multipart/form-data")
        #expect(form.body == nil)

        let head = try #require(CodeExport.parseCurl("curl -I https://h/"))
        #expect(head.method == "HEAD")
        #expect(CodeExport.parseCurl("wget https://h/") == nil)
        #expect(CodeExport.parseCurl("curl -s") == nil)
        #expect(CodeExport.parseCurl("$ /usr/bin/curl -o out.bin https://h/a")?.path == "/a")
    }

    @Test func shellTokenizer() {
        #expect(CodeExport.shellTokens("a 'b c' \"d \\\"e\\\"\" f\\ g") == ["a", "b c", "d \"e\"", "f g"])
        #expect(CodeExport.shellTokens("one \\\ntwo") == ["one", "two"])
        #expect(CodeExport.shellTokens("x $'a\\tb' 'it'\\''s'") == ["x", "a\tb", "it's"])
        #expect(CodeExport.shellTokens("  ") == [])
        #expect(CodeExport.shellTokens("\"unterminated") == ["unterminated"])
    }
}

// MARK: - Body kind

@Suite struct BodyKindViewerTests {
    static let png = Data([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52,
                           0x00, 0x00, 0x04, 0xB0, 0x00, 0x00, 0x03, 0x20, 0x08, 0x06, 0x00, 0x00, 0x00])
    static let jpeg = Data([0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46, 0x00, 0x01, 0x01, 0x00, 0x00, 0x01,
                            0x00, 0x01, 0x00, 0x00, 0xFF, 0xC0, 0x00, 0x11, 0x08, 0x00, 0xF0, 0x01, 0x40, 0x03, 0x01, 0x22,
                            0x00, 0x02, 0x11, 0x01, 0x03, 0x11, 0x01])
    static let gif = Data("GIF89a".utf8) + Data([0x40, 0x01, 0xF0, 0x00, 0x00, 0x00, 0x00])
    static let webpLossless = Data("RIFF".utf8) + Data([0x16, 0x00, 0x00, 0x00]) + Data("WEBPVP8L".utf8)
        + Data([0x05, 0x00, 0x00, 0x00, 0x2F, 0x01, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
    static let webpExtended = Data("RIFF".utf8) + Data([0x16, 0x00, 0x00, 0x00]) + Data("WEBPVP8X".utf8)
        + Data([0x0A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xAF, 0x04, 0x00, 0x1F, 0x03, 0x00])
    static let webpLossy = Data("RIFF".utf8) + Data([0x16, 0x00, 0x00, 0x00]) + Data("WEBPVP8 ".utf8)
        + Data([0x0A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x9D, 0x01, 0x2A, 0x40, 0x01, 0xF0, 0x00])

    @Test func sniffsImagesWithDimensions() {
        #expect(BodyKind.detect(contentType: nil, data: Self.png) == .image(format: .png, width: 1200, height: 800))
        #expect(BodyKind.detect(contentType: "application/octet-stream", data: Self.jpeg) == .image(format: .jpeg, width: 320, height: 240))
        #expect(BodyKind.detect(contentType: nil, data: Self.gif) == .image(format: .gif, width: 320, height: 240))
        #expect(BodyKind.detect(contentType: nil, data: Self.webpLossless) == .image(format: .webp, width: 2, height: 3))
        #expect(BodyKind.detect(contentType: "image/webp", data: Self.webpExtended) == .image(format: .webp, width: 1200, height: 800))
        #expect(BodyKind.detect(contentType: nil, data: Self.webpLossy) == .image(format: .webp, width: 320, height: 240))
        #expect(BodyKind.detect(contentType: "image/png", data: Data([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]))
                == .image(format: .png, width: nil, height: nil))
        #expect(BodyKind.detect(contentType: "image/jpeg", data: Data()) == .image(format: .jpeg, width: nil, height: nil))
        let svg = Data(#"<?xml version="1.0"?><svg xmlns="http://www.w3.org/2000/svg" width="24px" height="16"><rect/></svg>"#.utf8)
        #expect(BodyKind.detect(contentType: "image/svg+xml", data: svg) == .image(format: .svg, width: 24, height: 16))
        #expect(BodyKind.detect(contentType: nil, data: svg) == .image(format: .svg, width: 24, height: 16))
        #expect(ImageFormat.webp.label == "WebP")
    }

    @Test func declaredTypesWin() {
        #expect(BodyKind.detect(contentType: "application/json; charset=utf-8", data: Data("x".utf8)) == .json)
        #expect(BodyKind.detect(contentType: "application/graphql-response+json", data: Data()) == .json)
        #expect(BodyKind.detect(contentType: "text/xml", data: Data()) == .xml)
        #expect(BodyKind.detect(contentType: "application/xhtml+xml", data: Data()) == .html)
        #expect(BodyKind.detect(contentType: "text/html; charset=utf-8", data: Data()) == .html)
        #expect(BodyKind.detect(contentType: "application/javascript", data: Data()) == .javascript)
        #expect(BodyKind.detect(contentType: "text/css", data: Data()) == .css)
        #expect(BodyKind.detect(contentType: "application/x-www-form-urlencoded", data: Data()) == .form)
        #expect(BodyKind.detect(contentType: "multipart/form-data; boundary=\"XYZ 1\"", data: Data()) == .multipart(boundary: "XYZ 1"))
        #expect(BodyKind.detect(contentType: "multipart/form-data", data: Data("--abc\r\nx".utf8)) == .multipart(boundary: "abc"))
        #expect(BodyKind.detect(contentType: "application/x-protobuf", data: Data()) == .protobuf)
        #expect(BodyKind.detect(contentType: "application/msgpack", data: Data()) == .messagepack)
        #expect(BodyKind.detect(contentType: "text/plain", data: Self.png) == .text)
        #expect(BodyKind.detect(contentType: "application/pdf", data: Data("%PDF".utf8)) == .binary)
    }

    @Test func sniffsTextShapes() {
        #expect(BodyKind.detect(contentType: nil, data: Data("  {\"a\": 1}".utf8)) == .json)
        #expect(BodyKind.detect(contentType: "application/octet-stream", data: Data("[1,2]".utf8)) == .json)
        #expect(BodyKind.detect(contentType: nil, data: Data("{not json".utf8)) == .text)
        #expect(BodyKind.detect(contentType: nil, data: Data("<!DOCTYPE html><html></html>".utf8)) == .html)
        #expect(BodyKind.detect(contentType: nil, data: Data("<?xml version=\"1.0\"?><a/>".utf8)) == .xml)
        #expect(BodyKind.detect(contentType: nil, data: Data("<root><x/></root>".utf8)) == .xml)
        #expect(BodyKind.detect(contentType: nil, data: Data("a=1&b=2".utf8)) == .form)
        #expect(BodyKind.detect(contentType: nil, data: Data("hello world".utf8)) == .text)
        #expect(BodyKind.detect(contentType: nil, data: Data()) == .text)
        let multipart = Data("--XYZ\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\n1\r\n--XYZ--\r\n".utf8)
        #expect(BodyKind.detect(contentType: nil, data: multipart) == .multipart(boundary: "XYZ"))
    }

    @Test func guessesBinaryEncodings() {
        #expect(BodyKind.detect(contentType: nil, data: Data([0x08, 0x96, 0x01])) == .protobuf)
        #expect(BodyKind.detect(contentType: nil, data: Data([0x0A, 0x02, 0xFF, 0xFE, 0x15, 0x00, 0x00, 0x80, 0x3F])) == .protobuf)
        #expect(BodyKind.detect(contentType: nil, data: Data([0x82, 0xA1, 0x61, 0x01, 0xA1, 0x62, 0xC3])) == .messagepack)
        #expect(BodyKind.detect(contentType: nil, data: Data([0x93, 0x01, 0xCC, 0xFF, 0xCB, 0, 0, 0, 0, 0, 0, 0, 0])) == .messagepack)
        #expect(BodyKind.detect(contentType: nil, data: Data([0x82, 0xA1, 0x61])) == .binary, "truncated msgpack")
        #expect(BodyKind.detect(contentType: nil, data: Data([0x00, 0x00, 0xFF, 0xFE])) == .binary, "field number 0 is not protobuf")
        #expect(BodyKind.detect(contentType: "application/octet-stream", data: Data([0xFF, 0xFE, 0x00, 0x80])) == .binary)
        #expect(!BodyKind.isProtobuf(Data()))
        #expect(!BodyKind.isMessagePack(Data([0xC1])))
    }

    @Test func formDecode() {
        let pairs = BodyKind.formDecode(Data("a=1&b=hello+world&c=%20x&d&e=caf%C3%A9&bad=%zz".utf8))
        #expect(pairs.map(\.0) == ["a", "b", "c", "d", "e", "bad"])
        #expect(pairs.map(\.1) == ["1", "hello world", " x", "", "café", "%zz"])
        #expect(BodyKind.formDecode(Data()).isEmpty)
        #expect(BodyKind.formDecode(Data("q=a%3Db%26c".utf8)).map(\.1) == ["a=b&c"])
    }

    @Test func multipartSplit() {
        let body = Data(("--XYZ\r\nContent-Disposition: form-data; name=\"field1\"\r\n\r\nvalue1\r\n"
            + "--XYZ\r\nContent-Disposition: form-data; name=\"file\"; filename=\"a.txt\"\r\nContent-Type: text/plain\r\n\r\n"
            + "hello\r\nworld\r\n--XYZ--\r\n").utf8)
        let parts = BodyKind.multipartParts(body, boundary: "XYZ")
        #expect(parts.count == 2)
        #expect(parts[0].name == "field1")
        #expect(parts[0].filename == nil)
        #expect(parts[0].body == Data("value1".utf8))
        #expect(parts[0].headers.map(\.name) == ["content-disposition"])
        #expect(parts[1].name == "file")
        #expect(parts[1].filename == "a.txt")
        #expect(parts[1].contentType == "text/plain")
        #expect(parts[1].body == Data("hello\r\nworld".utf8))

        let lf = Data("preamble\n--b\nX-A: 1\n\nraw\n--b--\n".utf8)
        let lfParts = BodyKind.multipartParts(lf, boundary: "b")
        #expect(lfParts.count == 1)
        #expect(lfParts[0].header("x-a") == "1")
        #expect(lfParts[0].body == Data("raw".utf8))

        #expect(BodyKind.multipartParts(body, boundary: "nope").isEmpty)
        #expect(BodyKind.multipartParts(Data(), boundary: "XYZ").isEmpty)
        #expect(BodyKind.multipartParts(body, boundary: "").isEmpty)
        #expect(BodyKind.parameters(of: "form-data; name=\"a b\"; filename=c.txt") == ["name": "a b", "filename": "c.txt"])
    }
}
