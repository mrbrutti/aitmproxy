import Foundation
import Testing
@testable import AitmproxyKit

/// The embedded core's persisted operator scope (`scope.json`): file round trip,
/// the load-time sanitising that keeps a tampered file from wedging the embedded
/// core, and the launch-seeding predicate (spec D1; SP-AC1, SP-AC8(a), SP-AC10,
/// SP-AC14, SP-AC15, SP-AC18).
@Suite struct EmbeddedScopeTests {
    /// A fresh, not-yet-existing path under the temp dir; callers remove it in `defer`.
    private func tempURL() -> URL {
        FileManager.default.temporaryDirectory.appending(path: "embedded-scope-\(UUID().uuidString).json")
    }

    // MARK: Round trip and path (SP-AC18)

    @Test func roundTripsThroughAFile() throws {
        let url = tempURL()
        defer { try? FileManager.default.removeItem(at: url) }

        try EmbeddedScope(hosts: ["api.example.test", "*.shop.test"]).save(to: url)

        #expect(EmbeddedScope.load(from: url) == EmbeddedScope(hosts: ["api.example.test", "*.shop.test"]))
    }

    @Test func urlEndsInScopeJSONBesideThePins() {
        let store = URL(fileURLWithPath: "/tmp/store", isDirectory: true)

        #expect(EmbeddedScope.url(in: store).lastPathComponent == "scope.json")
        #expect(EmbeddedScope.url(in: store).deletingLastPathComponent().path == "/tmp/store")
    }

    @Test func emptyScopeRoundTripsAsAnEmptyList() throws {
        let url = tempURL()
        defer { try? FileManager.default.removeItem(at: url) }

        try EmbeddedScope().save(to: url)

        let text = try String(contentsOf: url, encoding: .utf8)
        #expect(text.contains("\"hosts\""))
        #expect(EmbeddedScope.load(from: url) == EmbeddedScope())
    }

    // MARK: Missing / corrupt loads empty (SP-AC15)

    @Test func missingFileLoadsEmpty() {
        let url = tempURL()

        let loaded = EmbeddedScope.load(from: url.appendingPathExtension("missing"))

        #expect(loaded == EmbeddedScope())
        #expect(loaded.hosts == [])
    }

    @Test func corruptFileLoadsEmpty() throws {
        let url = tempURL()
        defer { try? FileManager.default.removeItem(at: url) }

        try Data("{not json".utf8).write(to: url)
        #expect(EmbeddedScope.load(from: url) == EmbeddedScope())

        try Data(#"{"hosts": "x"}"#.utf8).write(to: url)
        #expect(EmbeddedScope.load(from: url) == EmbeddedScope())
    }

    // MARK: Load sanitises (SP-AC14)

    @Test func loadDropsInvalidAndDuplicateEntries() throws {
        let url = tempURL()
        defer { try? FileManager.default.removeItem(at: url) }
        // Raw string: the file bytes carry the JSON escape `\n`, which decodes to a
        // real newline inside `bad\nhost.test`.
        let json = #"{"hosts": ["api.example.test", " api.example.test ", "*.shop.test", "", "http://x.test", "a b.test", "api.example.test", "bad\nhost.test", "localhost:8099"]}"#
        try Data(json.utf8).write(to: url)

        #expect(EmbeddedScope.load(from: url).hosts == ["api.example.test", "*.shop.test", "localhost:8099"])
    }

    @Test func sanitizedKeepsOrderAndFirstOccurrence() {
        #expect(EmbeddedScope.sanitized(["b.test", "a.test", "b.test", "  a.test"]) == ["b.test", "a.test"])
    }

    @Test func isPersistableRejectsControlCharactersScopeValidateAccepts() {
        // Documents why the rule exists: the UI validator alone lets a newline through.
        #expect(Scope.validate("bad\nhost.test") == nil)

        #expect(!EmbeddedScope.isPersistable("bad\nhost.test"))
        #expect(!EmbeddedScope.isPersistable("bad\rhost.test"))
        #expect(EmbeddedScope.isPersistable("localhost:8099"))
        #expect(EmbeddedScope.isPersistable("*.shop.test"))
        #expect(!EmbeddedScope.isPersistable(""))
    }

    // MARK: Launch seeding (SP-AC1, SP-AC8(a), SP-AC10)

    @Test func seedsAtLaunchOnlyForEmbeddedWithABundledCoreOutsideFixtures() {
        #expect(EmbeddedScope.seedsAtLaunch(activeKind: .embedded, bundledCorePresent: true, usesFixtures: false) == true)
        #expect(EmbeddedScope.seedsAtLaunch(activeKind: .external, bundledCorePresent: true, usesFixtures: false) == false)
        #expect(EmbeddedScope.seedsAtLaunch(activeKind: .embedded, bundledCorePresent: false, usesFixtures: false) == false)
        #expect(EmbeddedScope.seedsAtLaunch(activeKind: .embedded, bundledCorePresent: true, usesFixtures: true) == false)
    }

    // MARK: Tester — load edge cases (SP-AC14, SP-AC15)

    /// Writes `bytes` to its own fresh temp file, loads it, and removes the file.
    private func loaded(fromBytes bytes: String) -> EmbeddedScope {
        let url = tempURL()
        defer { try? FileManager.default.removeItem(at: url) }
        try? Data(bytes.utf8).write(to: url)
        return EmbeddedScope.load(from: url)
    }

    @Test func wrongShapedJSONLoadsEmptyNotPartially() {
        // A wrong shape voids the whole file — nothing is salvaged from it, so a half-written or
        // tampered file can never contribute a host (SP-AC15). The zero-byte case is the truncated
        // write that `save`'s atomic replace exists to prevent.
        #expect(loaded(fromBytes: "") == EmbeddedScope())
        #expect(loaded(fromBytes: "   \n") == EmbeddedScope())
        #expect(loaded(fromBytes: "{}") == EmbeddedScope())
        #expect(loaded(fromBytes: "[]") == EmbeddedScope())
        #expect(loaded(fromBytes: #"{"hosts": null}"#) == EmbeddedScope())
        #expect(loaded(fromBytes: #"{"hosts": [1, 2]}"#) == EmbeddedScope())
        #expect(loaded(fromBytes: #"{"hosts": ["api.example.test", 1]}"#) == EmbeddedScope())
        #expect(loaded(fromBytes: #"{"hosts": {"api.example.test": true}}"#) == EmbeddedScope())
    }

    @Test func unknownKeysAreIgnoredAndHostsStillLoad() {
        // Extra keys (a future field, or a `pins.json`-shaped file) do not void the file; only
        // `hosts` is read, and it is still sanitised.
        #expect(loaded(fromBytes: #"{"apps": ["Safari"], "hosts": ["api.example.test", "api.example.test"], "version": 2}"#).hosts
                == ["api.example.test"])
    }

    @Test func aDirectoryAtThePathLoadsEmpty() throws {
        let dir = FileManager.default.temporaryDirectory
            .appending(path: "embedded-scope-dir-\(UUID().uuidString)", directoryHint: .isDirectory)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }

        #expect(EmbeddedScope.load(from: dir) == EmbeddedScope())
    }

    @Test func loadTrimsEdgeWhitespaceButDropsWhitespaceOnlyEntries() {
        // Edge whitespace and newlines are trimmed, never fatal; an entry that is nothing but
        // whitespace trims to "" and is dropped like the spec's "" case (SP-AC14).
        #expect(EmbeddedScope.sanitized(["\n api.example.test \n", "\tapi.two.test\t"]) == ["api.example.test", "api.two.test"])
        #expect(EmbeddedScope.sanitized(["   ", "\t", "\n", "\r\n"]) == [])
        #expect(loaded(fromBytes: #"{"hosts": ["   ", "\t\n", "api.example.test\n"]}"#).hosts == ["api.example.test"])
    }

    @Test func loadKeepsOrDropsPortsExactlyAsScopeValidateDoes() {
        // The port rule is `Scope.validate`'s (digits, 1…65535): the file keeps exactly what the
        // Scope page would accept and drops what it would refuse.
        #expect(EmbeddedScope.isPersistable("api.example.test:1"))
        #expect(EmbeddedScope.isPersistable("api.example.test:65535"))
        #expect(EmbeddedScope.isPersistable("*.shop.test:8443"))
        #expect(!EmbeddedScope.isPersistable("api.example.test:0"))
        #expect(!EmbeddedScope.isPersistable("api.example.test:65536"))
        #expect(!EmbeddedScope.isPersistable("api.example.test:99999"))
        #expect(!EmbeddedScope.isPersistable("api.example.test:-1"))
        #expect(!EmbeddedScope.isPersistable("api.example.test:abc"))
        #expect(loaded(fromBytes: #"{"hosts": ["api.example.test:99999", "api.example.test:8080", "api.example.test:0"]}"#).hosts
                == ["api.example.test:8080"])
    }

    @Test func loadDropsSchemesPathsEdgeDotsAndIPv6LiteralsPerScopeValidate() {
        #expect(!EmbeddedScope.isPersistable("https://api.example.test"))
        #expect(!EmbeddedScope.isPersistable("api.example.test/path"))
        #expect(!EmbeddedScope.isPersistable("api.example.test."))
        #expect(!EmbeddedScope.isPersistable(".example.test"))
        #expect(!EmbeddedScope.isPersistable("*."))
        // An IPv6 literal fails the page validator's port rule, so the file cannot carry what the
        // Scope page refuses to enter.
        #expect(!EmbeddedScope.isPersistable("[::1]:8080"))
    }

    @Test func loadRejectsEveryControlAndLineSeparatorInsideAHost() {
        // `Scope.validate` refuses only a plain space; load also refuses tabs, NUL, DEL, NEL and
        // the Unicode line separators, so no character that could split a line or hide inside a
        // host reaches the YAML (SP-AC14; the bare newline is SP-AC16's belt-and-braces).
        #expect(Scope.validate("a\tb.test") == nil)          // the UI validator alone lets a tab through
        #expect(!EmbeddedScope.isPersistable("a\tb.test"))
        #expect(!EmbeddedScope.isPersistable("a\u{0}b.test"))
        #expect(!EmbeddedScope.isPersistable("a\u{7F}b.test"))
        #expect(!EmbeddedScope.isPersistable("a\u{85}b.test"))
        #expect(!EmbeddedScope.isPersistable("a\u{2028}b.test"))
        #expect(!EmbeddedScope.isPersistable("a\u{2029}b.test"))
        #expect(!EmbeddedScope.isPersistable("evil.test\r\nlisten: 0.0.0.0:1"))
        #expect(EmbeddedScope.sanitized(["a\tb.test", "ok.test", "a\u{2028}b.test"]) == ["ok.test"])
    }

    @Test func loadKeepsUnicodeAndMixedCaseVerbatim() {
        // Load neither lowercases nor punycodes: the file is the core's own `scope.list`, and the
        // core's `add_scope` folds ASCII case again at seed. Two spellings that differ only by
        // case are both kept here (string-unequal) and collapsed by the core.
        #expect(EmbeddedScope.isPersistable("bücher.example"))
        #expect(EmbeddedScope.isPersistable("xn--bcher-kva.example"))
        #expect(EmbeddedScope.sanitized(["API.Example.TEST", "api.example.test", "bücher.example"])
                == ["API.Example.TEST", "api.example.test", "bücher.example"])
        #expect(loaded(fromBytes: #"{"hosts": ["bücher.example", "API.Example.TEST"]}"#).hosts == ["bücher.example", "API.Example.TEST"])
    }

    @Test func aHugeHostListRoundTripsWholeAndInOrder() throws {
        // Oversized input: no silent cap or truncation — a long, valid list round-trips whole and
        // in order, and its duplicates collapse to one each.
        let hosts = (0..<5_000).map { "h\($0).example.test" }
        let url = tempURL()
        defer { try? FileManager.default.removeItem(at: url) }

        try EmbeddedScope(hosts: hosts).save(to: url)

        #expect(EmbeddedScope.load(from: url).hosts == hosts)
        #expect(EmbeddedScope.sanitized(hosts + hosts) == hosts)
    }

    // MARK: Tester — save edge cases (SP-AC3, SP-AC18)

    @Test func saveCreatesMissingParentDirectories() throws {
        // The store directory may not exist yet on a first run; `save` creates the whole path.
        let dir = FileManager.default.temporaryDirectory
            .appending(path: "embedded-scope-\(UUID().uuidString)", directoryHint: .isDirectory)
        defer { try? FileManager.default.removeItem(at: dir) }
        let url = dir.appending(path: "nested/deeper/scope.json")

        try EmbeddedScope(hosts: ["api.example.test"]).save(to: url)

        #expect(FileManager.default.fileExists(atPath: url.path))
        #expect(EmbeddedScope.load(from: url).hosts == ["api.example.test"])
    }

    @Test func saveReplacesThePreviousFileWholeAndEmptyingKeepsTheFile() throws {
        // Remove persists (SP-AC3): the second save replaces the first in full, and emptying the
        // scope leaves a file that still exists and loads as the empty list — never deleted.
        let url = tempURL()
        defer { try? FileManager.default.removeItem(at: url) }

        try EmbeddedScope(hosts: ["api.example.test", "*.shop.test"]).save(to: url)
        try EmbeddedScope(hosts: ["*.shop.test"]).save(to: url)
        #expect(EmbeddedScope.load(from: url).hosts == ["*.shop.test"])
        #expect(!(try String(contentsOf: url, encoding: .utf8)).contains("api.example.test"))

        try EmbeddedScope().save(to: url)
        #expect(FileManager.default.fileExists(atPath: url.path))
        #expect(EmbeddedScope.load(from: url) == EmbeddedScope())
        #expect(!(try String(contentsOf: url, encoding: .utf8)).contains("shop.test"))
    }

    @Test func aHostOnlyLoadCanRefuseNeverSurvivesALoad() throws {
        // `save` writes what it is given; `load` is the single validation point (D1). So even a
        // host that would make `Config.yaml()` throw can sit in the file yet never reach a spawn.
        let url = tempURL()
        defer { try? FileManager.default.removeItem(at: url) }

        try EmbeddedScope(hosts: ["ok.test", "evil.test\nlisten: 0.0.0.0:1", "a\tb.test"]).save(to: url)

        #expect(EmbeddedScope.load(from: url).hosts == ["ok.test"])
    }
}
