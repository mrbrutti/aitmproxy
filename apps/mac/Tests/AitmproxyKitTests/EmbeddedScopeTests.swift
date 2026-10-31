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
}
