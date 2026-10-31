import Foundation
import Testing
@testable import AitmproxyKit

/// The fixture rows that pass `text`, by seq, each with its fixture detail.
private func seqs(_ text: String) throws -> [Int] {
    let filter = try CompiledFilter(parsing: text)
    return Fixtures.rows
        .filter { filter.matches(FilterSubject(row: $0, detail: Fixtures.detail(for: $0))) }
        .map(\.seq)
}

/// The fixture rows that pass `text` with no detail loaded.
private func rowOnlySeqs(_ text: String) throws -> [Int] {
    let filter = try CompiledFilter(parsing: text)
    return Fixtures.rows.filter { filter.matches(FilterSubject(row: $0)) }.map(\.seq)
}

private func parseError(_ text: String) -> FilterParseError? {
    do {
        _ = try FilterExpression.parse(text)
        return nil
    } catch {
        return error
    }
}

private let allSeqs = Array(41...54)
private let withResponse = [41, 42, 43, 44, 45, 46, 47, 48, 53, 54]

@Suite struct FilterSyntaxTests {
    @Test(arguments: [
        "~u login",
        "~m POST & ~s",
        "~d cdn | ~c 304",
        "!~marked",
        "~hq \"user-agent: curl\"",
        "(~m GET | ~m HEAD) & ~d api",
        "~m GET & (~d cdn | ~m HEAD)",
        "~m GET & ~d cdn | ~m HEAD",
        "~q",
        "!~q",
        "~bs:json fields.quantity=2",
        "~duration:lt 30",
        "~u:glob *orders*",
        "~origin agent & !~replay",
        "~u \"a b\" & ~t json",
        "!(~m GET & ~s)",
        "~text \"bad gateway\"",
        "~size 10000",
        "~h cookie",
        "~b:contains token",
        "~client:eq curl",
        "~mark red",
        "~mark:contains e",
        "~u \"\\\"quoted\\\"\"",
        "~u \"\"",
        "~scope out",
        "~state paused",
        "~ws sent",
        "~path:eq /api/me & ~query page",
        "~comment todo",
        "~c:gt 400",
        "(~u a & ~u b) & ~u c",
    ])
    func roundTrips(_ text: String) throws {
        let parsed = try FilterExpression.parse(text)
        #expect(parsed.text == text)
        #expect(try FilterExpression.parse(parsed.text) == parsed)
    }

    @Test func canonicalises() throws {
        #expect(try FilterExpression.parse("login").text == "~u login")
        #expect(try FilterExpression.parse("\"two words\"").text == "~u \"two words\"")
        #expect(try FilterExpression.parse("~hq x ~m POST").text == "~hq x & ~m POST")
        #expect(try FilterExpression.parse("!~s").text == "~q")
        #expect(try FilterExpression.parse("~mark:contains \"\"").text == "~marked")
        #expect(try FilterExpression.parse("~c:contains \"\"").text == "~s")
        #expect(try FilterExpression.parse("  ~u   a   &~m  GET ").text == "~u a & ~m GET")
        #expect(try FilterExpression.parse("~u:re a").text == "~u a")
        #expect(try FilterExpression.parse("~m:equals GET").text == "~m GET")
        #expect(try FilterExpression.parse("~u \"~m\"") == .term(.field(.url, .regex, "~m")))
        #expect(try FilterExpression.parse("!!~s").text == "!~q")
        #expect(try FilterExpression.parse("") == .matchAll)
        #expect(try FilterExpression.parse("   ") == .matchAll)
        #expect(FilterExpression.matchAll.text == "")
    }

    @Test func precedence() throws {
        let a = FilterExpression.term(.field(.url, .regex, "a"))
        let b = FilterExpression.term(.field(.url, .regex, "b"))
        let c = FilterExpression.term(.field(.url, .regex, "c"))
        #expect(try FilterExpression.parse("a & b | c") == .or([.and([a, b]), c]))
        #expect(try FilterExpression.parse("a | b & c") == .or([a, .and([b, c])]))
        #expect(try FilterExpression.parse("!a & b") == .and([.not(a), b]))
        #expect(try FilterExpression.parse("!(a & b)") == .not(.and([a, b])))
        #expect(try FilterExpression.parse("a & b & c") == .and([a, b, c]))
        #expect(try FilterExpression.parse("(a & b) & c") == .and([.and([a, b]), c]))
        #expect(try FilterExpression.parse("a (b | c)") == .and([a, .or([b, c])]))
    }

    @Test func quoting() throws {
        #expect(try FilterExpression.parse("~u \"a \\\\ b\"") == .term(.field(.url, .regex, "a \\ b")))
        #expect(try FilterExpression.parse("~u \"(x|y)\"") == .term(.field(.url, .regex, "(x|y)")))
        #expect(FilterTerm.quote("plain") == "plain")
        #expect(FilterTerm.quote("has space") == "\"has space\"")
        #expect(FilterTerm.quote("") == "\"\"")
        #expect(FilterTerm.quote("!bang") == "\"!bang\"")
        #expect(FilterTerm.quote("a\"b") == "\"a\\\"b\"")
    }

    @Test func errorsCarryOffsets() {
        #expect(parseError("~u")?.kind == .missingValue)
        #expect(parseError("~u")?.offset == 2)
        #expect(parseError("~u &")?.offset == 3)
        #expect(parseError("~zz 1")?.kind == .unknownTerm)
        #expect(parseError("~zz 1")?.offset == 0)
        #expect(parseError("~m GET & ~")?.kind == .unknownTerm)
        #expect(parseError("~m GET & ~")?.offset == 9)
        #expect(parseError("~u:foo x")?.kind == .unknownOperator)
        #expect(parseError("~u:foo x")?.offset == 3)
        #expect(parseError("~u:text x")?.kind == .unknownOperator)
        #expect(parseError("~s:re")?.kind == .operatorNotAllowed)
        #expect(parseError("~s:re")?.offset == 3)
        #expect(parseError("~text:re x")?.kind == .operatorNotAllowed)
        #expect(parseError("(~u a")?.kind == .expectedClosingParenthesis)
        #expect(parseError("(~u a")?.offset == 5)
        #expect(parseError("~u a)")?.kind == .trailingInput)
        #expect(parseError("~u a)")?.offset == 4)
        #expect(parseError("~u \"abc")?.kind == .unterminatedQuote)
        #expect(parseError("~u \"abc")?.offset == 3)
        #expect(parseError("~u a & ")?.kind == .unexpectedEnd)
        #expect(parseError("~u a & ")?.offset == 7)
        #expect(parseError("& ~u a")?.kind == .unexpectedToken)
        #expect(parseError("& ~u a")?.offset == 0)
        #expect(parseError("~u a | )")?.kind == .unexpectedToken)
        #expect(parseError("~u a | )")?.offset == 7)
        #expect(parseError("~mark")?.kind == .missingValue)
        #expect(parseError("()")?.kind == .unexpectedToken)
        #expect(parseError("~u a") == nil)
        #expect(parseError("~marked login") == nil)
        #expect(parseError("~u a &")?.description == "Expected a filter (at 6)")
    }
}

@Suite struct FilterMatchTests {
    @Test func method() throws {
        #expect(try seqs("~m POST") == [44, 50])
        #expect(try seqs("~m post") == [44, 50])
        #expect(try seqs("~m:re ^P") == [42, 44, 50, 53])
        #expect(try seqs("~m ^P") == [])
    }

    @Test func status() throws {
        #expect(try seqs("~c 5") == [45])
        #expect(try seqs("~c 50") == [45])
        #expect(try seqs("~c 502") == [45])
        #expect(try seqs("~c 200") == [41, 42, 46, 48, 54])
        #expect(try seqs("~c 20") == [41, 42, 44, 46, 48, 54])
        #expect(try seqs("~c:contains 0") == [41, 42, 43, 44, 45, 46, 47, 48, 54])
        #expect(try seqs("~c:gt 400") == [45, 53])
        #expect(try seqs("~c:lt 300") == [41, 42, 44, 46, 47, 48, 54])
    }

    @Test func responsePresence() throws {
        #expect(try seqs("~s") == withResponse)
        #expect(try seqs("~q") == [49, 50, 51, 52])
        #expect(try seqs("!~s") == [49, 50, 51, 52])
        #expect(try seqs("!~q") == withResponse)
        #expect(try rowOnlySeqs("~s") == withResponse)
    }

    @Test func scopeOriginReplay() throws {
        #expect(try seqs("~scope out") == [44])
        #expect(try seqs("~scope in") == allSeqs.filter { $0 != 44 })
        #expect(try seqs("~origin agent") == [46, 48])
        #expect(try seqs("~origin client").count == 12)
        #expect(try seqs("~origin human") == [])
        #expect(try seqs("~replay") == [46])
        #expect(try seqs("~origin agent & !~replay") == [48])
    }

    @Test func state() throws {
        #expect(try seqs("~state paused") == [50, 51])
        #expect(try seqs("~state killed") == [49])
        #expect(try seqs("~state pending") == [52])
        #expect(try seqs("~state failed") == [])
        #expect(try seqs("~state complete") == [41, 42, 43, 44, 45, 46, 47, 48, 53, 54])
        // The Errors tile's set: transport failures, killed flows, or 5xx.
        #expect(try seqs("~state failed | ~state killed | ~c 5") == [45, 49])
    }

    @Test func marks() throws {
        #expect(try seqs("~marked") == [42, 48])
        #expect(try seqs("!~marked").count == 12)
        #expect(try seqs("~mark red") == [48])
        #expect(try seqs("~mark:eq cyan") == [42])
        #expect(try seqs("~mark:contains e") == [48])
    }

    @Test func urlHostPathQuery() throws {
        #expect(try seqs("~u login") == [50])
        #expect(try seqs("login") == [50])
        #expect(try seqs("~u orders") == [45, 46])
        #expect(try seqs("~u ^https://cdn") == [43, 52])
        #expect(try seqs("~d cdn") == [43, 52])
        #expect(try seqs("~d ^api\\.") == [41, 42, 45, 46, 47, 48, 49, 51, 53, 54])
        #expect(try seqs("~path:eq /api/orders") == [45, 46])
        #expect(try seqs("~path /api/orders") == [45, 46])
        #expect(try seqs("~query page") == [45, 46])
        #expect(try seqs("~query:contains limit=20") == [41])
        #expect(try seqs("~query:contains \"\"") == [41, 45, 46, 48])
    }

    @Test func client() throws {
        #expect(try seqs("~client curl") == [45, 49, 50])
        #expect(try seqs("~client:eq python3") == [53, 54])
        #expect(try seqs("~client ^s") == [44])
    }

    @Test func durationAndSize() throws {
        #expect(try seqs("~duration 400") == [45, 46])
        #expect(try seqs("~duration:gt 400") == [45, 46])
        #expect(try seqs("~duration:lt 30") == [43, 54])
        #expect(try seqs("~duration:eq 89") == [41])
        #expect(try seqs("~size 10000") == [41, 46])
        #expect(try seqs("~size:lt 300") == [49, 50, 54])
        #expect(try seqs("~size:gt abc") == [])
    }

    @Test func comment() throws {
        #expect(try seqs("~comment foo") == [])
        var row = Fixtures.rows[0]
        row.comment = "Check this one"
        let filter = try CompiledFilter(parsing: "~comment check")
        #expect(filter.matches(FilterSubject(row: row)))
        #expect(!filter.matches(FilterSubject(row: Fixtures.rows[0])))
    }

    @Test func webSocketDirectionIsNotAvailableYet() throws {
        #expect(try seqs("~ws sent") == [])
        #expect(try seqs("~ws received") == [])
        #expect(FilterRow(.wsDirection, .equals, "sent").validationError == nil)
    }

    @Test func requestHeaders() throws {
        #expect(try seqs("~hq x-forwarded-for") == [50])
        #expect(try seqs("~hq \"user-agent: curl\"") == [45, 49, 50])
        #expect(try seqs("~hq:eq user-agent").count == 14)
        #expect(try seqs("~hq:eq \"host: auth.shop-staging.test\"") == [50])
        #expect(try seqs("~hq:eq \"host: nowhere\"") == [])
        #expect(try seqs("~hq:contains \"accept: */*\"") == [43, 50])
        #expect(try seqs("~hq:glob \"content-type: *json\"") == [42, 44, 50, 53])
        #expect(try seqs("~hq:glob json") == [])
    }

    @Test func responseHeadersAndAnyHeader() throws {
        #expect(try seqs("~hs server") == withResponse)
        #expect(try seqs("~hs:eq \"server: envoy\"") == withResponse)
        #expect(try seqs("~h envoy") == withResponse)
        #expect(try seqs("~h x-forwarded-for") == [50])
        #expect(try seqs("~h:eq accept").count == 14)
    }

    @Test func bodies() throws {
        #expect(try seqs("~bs \"Bad Gateway\"") == [45])
        #expect(try seqs("~bs validation_failed") == [53])
        #expect(try seqs("~bs Headphones") == [41, 42, 46, 47, 48])
        #expect(try seqs("~bq password") == [50])
        #expect(try seqs("~bq quantity") == [42, 44, 53])
        #expect(try seqs("~b quantity") == [42, 44, 53])
        #expect(try seqs("~b:contains TOKEN") == [])
        #expect(try seqs("~bs:glob *gateway*") == [45])
        #expect(try seqs("~bs:eq x") == [])
    }

    @Test func contentType() throws {
        #expect(try seqs("~t html") == [45])
        #expect(try seqs("~t json") == [41, 42, 44, 46, 47, 48, 50, 53, 54])
        #expect(try seqs("~t:eq \"text/html; charset=utf-8\"") == [45])
        #expect(try seqs("~t ^image/") == [])
    }

    @Test func fullText() throws {
        #expect(try seqs("~text envoy") == withResponse)
        #expect(try seqs("~text correct-horse") == [50])
        #expect(try seqs("~text shop-staging") == allSeqs.filter { $0 != 44 })
        #expect(try rowOnlySeqs("~text orders") == [45, 46])
        #expect(try rowOnlySeqs("~text envoy") == [])
    }

    @Test func wildcards() throws {
        #expect(try seqs("~u:glob *orders*") == [45, 46])
        #expect(try seqs("~u:glob orders") == [])
        #expect(try seqs("~d:glob *.shop-staging.test").count == 13)
        #expect(try seqs("~path:glob /api/cart/items/??") == [42])
        #expect(try seqs("~path:glob /api/cart/items/?") == [])
        #expect(try seqs("~path:glob /API/*") == [41, 42, 45, 46, 48, 49, 50, 51, 53, 54])
        #expect(CompiledTerm.wildcardPattern("a.b*c?") == "^a\\.b.*c.$")
    }

    @Test func invalidRegexMatchesNothing() throws {
        #expect(try seqs("~u [a-") == [])
        #expect(try seqs("~u \"(\"") == [])
        #expect(FilterRow(.url, .regex, "[a-").validationError?.hasPrefix("Invalid regular expression") == true)
        #expect(try FilterExpression.parse("~u [a- | ~m GET").validationErrors.count == 1)
        #expect(try seqs("~u [a- | ~m GET") == [41, 43, 45, 46, 48, 51, 52])
        #expect(FilterRow(.url, .regex, "[a-z]+").validationError == nil)
    }

    @Test func jsonPath() throws {
        #expect(try seqs("~bs:json fields.quantity") == [53])
        #expect(try seqs("~bs:json \"fields.quantity=must be ≥ 1\"") == [53])
        #expect(try seqs("~bs:json \"fields.quantity = MUST BE ≥ 1\"") == [53])
        #expect(try seqs("~bs:json fields.quantity=2") == [])
        #expect(try seqs("~bs:json fields.nothing") == [])
        #expect(try seqs("~bs:json items[0].name=Headphones") == [41, 42, 46, 47, 48])
        #expect(try seqs("~bs:json items[1].price=24.5") == [41, 42, 46, 47, 48])
        #expect(try seqs("~bs:json $.items[0].price=129") == [41, 42, 46, 47, 48])
        #expect(try seqs("~bs:json items[9].id") == [])
        #expect(try seqs("~bs:json page=3") == [41, 42, 46, 47, 48])
        #expect(try seqs("~bs:json ok=true") == [41, 42, 46, 47, 48])
        #expect(try seqs("~bs:json items=x") == [])
        #expect(try seqs("~bq:json remember=true") == [50])
        #expect(try seqs("~bq:json email=ops@shop-staging.test") == [50])
        #expect(try seqs("~b:json quantity=2") == [42, 44, 53])
        #expect(try seqs("~bs:json error") == [53])
    }

    @Test func jsonPathValidation() {
        #expect(FilterRow(.url, .jsonPath, "a").validationError != nil)
        #expect(FilterRow(.responseBody, .jsonPath, "a..b").validationError != nil)
        #expect(FilterRow(.responseBody, .jsonPath, "a[x]").validationError != nil)
        #expect(FilterRow(.responseBody, .jsonPath, "").validationError != nil)
        #expect(FilterRow(.responseBody, .jsonPath, "items[0].id").validationError == nil)
        #expect(JSONPath("items[0].id")?.steps == [.key("items"), .index(0), .key("id")])
        #expect(JSONPath("$.a.b")?.steps == [.key("a"), .key("b")])
        #expect(JSONPath("[2]")?.steps == [.index(2)])
        #expect(JSONPath("a[0][1]")?.steps == [.key("a"), .index(0), .index(1)])
    }

    @Test func numericValidation() {
        #expect(FilterRow(.host, .greaterThan, "5").validationError != nil)
        #expect(FilterRow(.duration, .greaterThan, "abc").validationError != nil)
        #expect(FilterRow(.duration, .greaterThan, "500").validationError == nil)
        #expect(FilterRow(.size, .lessThan, " 1.5 ").validationError == nil)
        #expect(FilterRow(.status, .equals, "x").validationError == nil)
    }

    @Test func combinations() throws {
        #expect(try seqs("~m POST & ~scope out") == [44])
        #expect(try seqs("~m POST | ~m PATCH") == [44, 50, 53])
        #expect(try seqs("!(~m GET | ~m HEAD) & ~s") == [42, 44, 47, 53])
        #expect(try seqs("~m GET & ~d cdn | ~m HEAD") == [43, 52, 54])
        #expect(try seqs("~m GET & (~d cdn | ~m HEAD)") == [43, 52])
        #expect(try seqs("~d cdn ~c 304") == [43])
        #expect(try seqs("") == allSeqs)
    }

    @Test func missingDetailEvaluatesFalse() throws {
        #expect(try rowOnlySeqs("~hq host") == [])
        #expect(try rowOnlySeqs("!~hq host") == allSeqs)
        #expect(try rowOnlySeqs("~bs a") == [])
        #expect(try rowOnlySeqs("~b a") == [])
        #expect(try rowOnlySeqs("~h a") == [])
        #expect(try rowOnlySeqs("~t json") == [])
        #expect(try rowOnlySeqs("~bs:json a") == [])
        #expect(try rowOnlySeqs("~m POST") == [44, 50])
    }

    @Test func binaryAndOversizedBodies() throws {
        var detail = Fixtures.detail(for: Fixtures.rows[0])
        let needle = try CompiledFilter(parsing: "~bs needle")
        let needleText = try CompiledFilter(parsing: "~bs:contains needle")
        let anyA = try CompiledFilter(parsing: "~bs a")
        // "needle" starts exactly at the scan limit: not seen.
        detail.response?.body = Data(repeating: UInt8(ascii: "a"), count: CompiledFilter.bodyScanLimit) + Data("needle".utf8)
        let beyond = FilterSubject(row: Fixtures.rows[0], detail: detail)
        #expect(!needle.matches(beyond))
        #expect(!needleText.matches(beyond))
        #expect(anyA.matches(beyond))
        // "needle" ends exactly at the scan limit: seen.
        detail.response?.body = Data(repeating: UInt8(ascii: "a"), count: CompiledFilter.bodyScanLimit - 6) + Data("needle".utf8)
        let within = FilterSubject(row: Fixtures.rows[0], detail: detail)
        #expect(needle.matches(within))
        #expect(needleText.matches(within))
        detail.response?.body = Data([0xFF, 0xFE, 0x00, 0x41])
        let binary = FilterSubject(row: Fixtures.rows[0], detail: detail)
        let letterA = try CompiledFilter(parsing: "~bs A")
        let json = try CompiledFilter(parsing: "~bs:json a")
        #expect(letterA.matches(binary))
        #expect(!json.matches(binary))
    }

    @Test func conveniencesAgreeWithCompiledFilter() throws {
        let expression = try FilterExpression.parse("~m POST")
        let stack = try #require(expression.stack)
        for row in Fixtures.rows {
            let subject = FilterSubject(row: row)
            let expected = CompiledFilter(expression).matches(subject)
            #expect(expression.matches(subject) == expected)
            #expect(stack.matches(subject) == expected)
        }
    }
}

@Suite struct FilterHighlightTests {
    @Test func containsAndRegex() throws {
        let body = "<h1>502 Bad Gateway</h1>"
        let contains = try CompiledFilter(parsing: "~bs:contains gateway")
        #expect(contains.matchRanges(in: body, field: .responseBody).map { String(body[$0]) } == ["Gateway"])
        #expect(contains.matchRanges(in: body, field: .requestBody).isEmpty)
        let regex = try CompiledFilter(parsing: "~bs \\d+")
        #expect(regex.matchRanges(in: body, field: .responseBody).map { String(body[$0]) } == ["1", "502", "1"])
        #expect(regex.matchRanges(in: body, field: .url).isEmpty)
    }

    @Test func fullTextAndAnyHeaderSpanFields() throws {
        let text = "x-a: one\nx-b: One"
        let full = try CompiledFilter(parsing: "~text one")
        #expect(full.matchRanges(in: text, field: .requestHeader).count == 2)
        #expect(full.matchRanges(in: text, field: .path).count == 2)
        let header = try CompiledFilter(parsing: "~h:contains x-")
        #expect(header.matchRanges(in: text, field: .responseHeader).count == 2)
        #expect(header.matchRanges(in: text, field: .responseBody).isEmpty)
        let body = try CompiledFilter(parsing: "~b one")
        #expect(body.matchRanges(in: text, field: .requestBody).count == 2)
        #expect(body.matchRanges(in: text, field: .requestHeader).isEmpty)
    }

    @Test func negatedEqualsAndWildcardContributeNothing() throws {
        let text = "aaaa"
        #expect(try CompiledFilter(parsing: "!~bs:contains aa").matchRanges(in: text, field: .responseBody).isEmpty)
        #expect(try CompiledFilter(parsing: "!(~bs aa | ~m GET)").matchRanges(in: text, field: .responseBody).isEmpty)
        #expect(try CompiledFilter(parsing: "~bs:eq aaaa").matchRanges(in: text, field: .responseBody).isEmpty)
        #expect(try CompiledFilter(parsing: "~bs:glob a*").matchRanges(in: text, field: .responseBody).isEmpty)
        #expect(try CompiledFilter(parsing: "~bs [").matchRanges(in: text, field: .responseBody).isEmpty)
    }

    @Test func mergesOverlaps() throws {
        let text = "aaaa"
        let ranges = try CompiledFilter(parsing: "~bs:contains aa | ~bs:contains aaa")
            .matchRanges(in: text, field: .responseBody)
        #expect(ranges.count == 1)
        #expect(ranges.first.map { String(text[$0]) } == "aaaa")
        let separate = try CompiledFilter(parsing: "~bs:contains a").matchRanges(in: "a-a", field: .responseBody)
        #expect(separate.count == 2)
    }
}

@Suite struct FilterStackTests {
    @Test func stackPrints() {
        let stack = FilterStack(rows: [FilterRow(.method, .equals, "POST"), FilterRow(.scope, .equals, "out")])
        #expect(stack.text == "~m POST & ~scope out")
        #expect(FilterStack(rows: stack.rows, combinator: .or).text == "~m POST | ~scope out")
        #expect(FilterStack(rows: [FilterRow(.url, .contains, "login", negated: true)]).text == "!~u:contains login")
        #expect(FilterStack(rows: [FilterRow(.status, .contains, "")]).text == "~s")
        #expect(FilterStack(rows: [FilterRow(.status, .contains, "", negated: true)]).text == "~q")
        #expect(FilterStack(rows: [FilterRow(.mark, .contains, "")]).text == "~marked")
        #expect(FilterStack(rows: [FilterRow(.responseBody, .jsonPath, "user.role=admin")]).text
                == "~bs:json user.role=admin")
        #expect(FilterStack(rows: [FilterRow(.duration, .greaterThan, "500")]).text == "~duration 500")
        #expect(FilterStack(rows: [FilterRow(.size, .lessThan, "10")]).text == "~size:lt 10")
        #expect(FilterStack(rows: [FilterRow(.requestHeader, .contains, "cookie: a=b")]).text
                == "~hq:contains \"cookie: a=b\"")
        #expect(FilterStack(rows: [FilterRow(.url, .fullText, "x")]).text == "~text x")
        #expect(FilterStack(rows: [FilterRow(.path, .fullText, "x")]).text == "~text x")
        #expect(FilterStack().text == "")
        #expect(FilterStack().expression == .matchAll)
        #expect(FilterStack(rows: [], combinator: .or).expression == .matchAll)
    }

    @Test func flatExpressionsBecomeStacks() throws {
        let and = try #require(FilterStack(expression: FilterExpression.parse("~m POST & ~scope out & !~marked")))
        #expect(and.combinator == .and)
        #expect(and.rows == [
            FilterRow(.method, .equals, "POST"),
            FilterRow(.scope, .equals, "out"),
            FilterRow(.mark, .contains, "", negated: true),
        ])
        let or = try #require(FilterStack(expression: FilterExpression.parse("~m POST | ~m PATCH")))
        #expect(or.combinator == .or)
        #expect(or.rows.count == 2)
        let single = try #require(FilterStack(expression: FilterExpression.parse("~q")))
        #expect(single.rows == [FilterRow(.status, .contains, "", negated: true)])
        let bare = try #require(FilterStack(expression: FilterExpression.parse("login")))
        #expect(bare.rows == [FilterRow(.url, .regex, "login")])
        let empty = try #require(FilterStack(expression: FilterExpression.parse("")))
        #expect(empty.isEmpty)
    }

    @Test func nestedOrRowlessExpressionsHaveNoStack() throws {
        #expect(try FilterExpression.parse("~m GET & (~d cdn | ~m HEAD)").stack == nil)
        #expect(try FilterExpression.parse("!(~m GET | ~m HEAD)").stack == nil)
        #expect(try FilterExpression.parse("!!~s").stack == nil)
        #expect(try FilterExpression.parse("~h cookie").stack == nil)
        #expect(try FilterExpression.parse("~b token").stack == nil)
        #expect(try FilterExpression.parse("~replay").stack == nil)
        #expect(try FilterExpression.parse("~m GET & ~replay").stack == nil)
    }

    @Test func stackRoundTripsThroughText() throws {
        let stack = FilterStack(rows: [
            FilterRow(.url, .wildcard, "*orders*"),
            FilterRow(.requestHeader, .regex, "user-agent: curl", negated: true),
            FilterRow(.responseBody, .jsonPath, "items[0].id=7"),
            FilterRow(.duration, .lessThan, "500"),
            FilterRow(.origin, .equals, "agent"),
        ], combinator: .or)
        let back = try #require(FilterStack(expression: FilterExpression.parse(stack.text)))
        #expect(back == stack)
    }

    @Test func codable() throws {
        let stack = FilterStack(rows: [FilterRow(.host, .wildcard, "*.test"), FilterRow(.status, .greaterThan, "399", negated: true)],
                                combinator: .or)
        let data = try JSONEncoder().encode(stack)
        #expect(try JSONDecoder().decode(FilterStack.self, from: data) == stack)
        let json = try #require(String(data: data, encoding: .utf8))
        #expect(json.contains("\"wildcard\""))
        #expect(json.contains("\"greaterThan\""))
    }

    @Test func fieldAndOperatorCatalog() {
        #expect(FilterField.allCases.count == 20)
        #expect(FilterOperator.allCases.count == 8)
        #expect(FilterField.allCases.allSatisfy { !$0.title.isEmpty && !$0.operators.isEmpty })
        #expect(FilterOperator.allCases.allSatisfy { !$0.title.isEmpty })
        #expect(FilterField.status.operators.contains(.greaterThan))
        #expect(!FilterField.url.operators.contains(.jsonPath))
        #expect(FilterField.responseBody.operators.contains(.jsonPath))
        #expect(Set(FilterField.allCases.map(\.key)).count == FilterField.allCases.count)
    }
}

@Suite struct SavedFilterStoreTests {
    @Test func roundTripsThroughFile() throws {
        let tmp = ProcessInfo.processInfo.environment["TMPDIR"].map { URL(filePath: $0) }
            ?? FileManager.default.temporaryDirectory
        let directory = tmp.appending(path: "aitmproxy-filter-tests-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: directory) }
        let store = SavedFilterStore(stateDirectory: directory)
        #expect(store.fileURL.lastPathComponent == "filters.json")
        #expect(try store.load() == [])

        let filters = [
            SavedFilter(name: "Agent traffic", expression: "~origin agent"),
            SavedFilter(name: "Errors", expression: "~c:gt 399 | ~q"),
        ]
        try store.save(filters)
        #expect(FileManager.default.fileExists(atPath: store.fileURL.path(percentEncoded: false)))
        #expect(try store.load() == filters)

        try store.save([])
        #expect(try store.load() == [])

        for saved in filters {
            _ = try FilterExpression.parse(saved.expression)
        }
    }
}
