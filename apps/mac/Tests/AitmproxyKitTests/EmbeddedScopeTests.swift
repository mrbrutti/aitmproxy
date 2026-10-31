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
        // A long, valid list under the 10 000-entry cap round-trips whole and in order, and its
        // duplicates collapse to one each (the cap itself is pinned in the fix-wave section below).
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
        // `load` validates on its own (D1), whatever wrote the file, so a host that would make
        // `Config.yaml()` throw never reaches a spawn. `save` drops it too (pinned on the raw bytes
        // below); `loadDropsInvalidAndDuplicateEntries` pins load against a hand-written file.
        let url = tempURL()
        defer { try? FileManager.default.removeItem(at: url) }

        try EmbeddedScope(hosts: ["ok.test", "evil.test\nlisten: 0.0.0.0:1", "a\tb.test"]).save(to: url)

        #expect(EmbeddedScope.load(from: url).hosts == ["ok.test"])
    }

    // MARK: Fix wave — libyaml-printable allow-list (spec D1 amendment; security S1)

    @Test func isPersistableRejectsScalarsTheCoreYAMLReaderRefuses() {
        // libyaml (the core's serde_yaml reader) refuses U+FFFE and U+FFFF, which `Scope.validate`,
        // the Cc/Cf clause and the core's own `scope.add` all accept. Persisted, such a host would
        // make the core refuse every spawn's config and wedge it in a restart loop.
        #expect(Scope.validate("foo\u{FFFF}.test") == nil)

        #expect(!EmbeddedScope.isPersistable("foo\u{FFFF}.test"))
        #expect(!EmbeddedScope.isPersistable("foo\u{FFFE}.test"))
        #expect(EmbeddedScope.sanitized(["foo\u{FFFE}.test", "ok.test", "foo\u{FFFF}.test"]) == ["ok.test"])
        #expect(loaded(fromBytes: #"{"hosts": ["foo\uFFFE.test", "ok.test", "foo\uFFFF.test"]}"#).hosts == ["ok.test"])
    }

    @Test func isPersistableAllowListIsLibyamlsNotASCII() {
        // The edges of libyaml's printable ranges: non-ASCII letters, punycode, the last BMP scalar
        // it accepts (U+FFFD) and the first supplementary one (U+10000) all stay persistable.
        #expect(EmbeddedScope.isPersistable("bücher.example"))
        #expect(EmbeddedScope.isPersistable("xn--bcher-kva.example"))
        #expect(EmbeddedScope.isPersistable("日本.example"))
        #expect(EmbeddedScope.isPersistable("\u{FFFD}.example"))
        #expect(EmbeddedScope.isPersistable("\u{10000}.example"))
    }

    // MARK: Fix wave — size, type, count and length caps (spec D1 amendment; security S2)

    @Test func aFileOverOneMebibyteLoadsEmptyAndOneAtTheLimitLoads() {
        // The padding sits in an ignored key, so the only difference between the two files is one
        // byte of length: exactly 1 MiB is read, 1 MiB + 1 is not.
        let head = #"{"hosts": ["ok.test"], "pad": ""#
        let tail = #""}"#
        func file(ofBytes n: Int) -> String {
            head + String(repeating: "x", count: n - head.utf8.count - tail.utf8.count) + tail
        }
        let atLimit = file(ofBytes: 1_048_576)
        let overLimit = file(ofBytes: 1_048_577)
        #expect(atLimit.utf8.count == 1_048_576)
        #expect(overLimit.utf8.count == 1_048_577)

        #expect(loaded(fromBytes: atLimit).hosts == ["ok.test"])
        #expect(loaded(fromBytes: overLimit) == EmbeddedScope())
    }

    @Test func aSymlinkAtThePathLoadsEmpty() throws {
        // Only a regular file is read: a link at the path is not followed (the per-launch config's
        // no-follow posture); a directory is covered above, and a FIFO would block the read.
        let target = tempURL()
        let link = tempURL()
        defer {
            try? FileManager.default.removeItem(at: link)
            try? FileManager.default.removeItem(at: target)
        }
        try Data(#"{"hosts": ["ok.test"]}"#.utf8).write(to: target)
        try FileManager.default.createSymbolicLink(at: link, withDestinationURL: target)

        #expect(EmbeddedScope.load(from: target).hosts == ["ok.test"])
        #expect(EmbeddedScope.load(from: link) == EmbeddedScope())
    }

    @Test func sanitizedKeepsAtMostTenThousandHostsTheFirstOnesInOrder() {
        let hosts = (0..<10_001).map { "h\($0).example.test" }

        let kept = EmbeddedScope.sanitized(hosts)

        #expect(kept.count == 10_000)
        #expect(kept == Array(hosts.prefix(10_000)))
        #expect(kept.last == "h9999.example.test")
        // Dropped and duplicate entries do not use up the cap.
        #expect(EmbeddedScope.sanitized(["", "h0.example.test"] + hosts) == Array(hosts.prefix(10_000)))
        // And through the file (about 300 KB, well under the size cap).
        let json = #"{"hosts": [""# + hosts.joined(separator: #"", ""#) + #""]}"#
        #expect(loaded(fromBytes: json).hosts == Array(hosts.prefix(10_000)))
    }

    @Test func sanitizedDropsAHostLongerThan1024Characters() {
        let atLimit = String(repeating: "a", count: 1_024 - ".test".count) + ".test"
        let overLimit = String(repeating: "a", count: 1_025 - ".test".count) + ".test"
        #expect(atLimit.count == 1_024)
        #expect(overLimit.count == 1_025)
        #expect(Scope.validate(overLimit) == nil)   // the page validator has no length rule

        #expect(EmbeddedScope.sanitized([overLimit, atLimit, "ok.test"]) == [atLimit, "ok.test"])
        #expect(loaded(fromBytes: #"{"hosts": [""# + overLimit + #"", ""# + atLimit + #""]}"#).hosts == [atLimit])
    }

    // MARK: Save applies load's caps (spec D1 amendment; SP-AC14, SP-AC18)

    @Test func saveWritesOnlyWhatLoadWouldKeep() throws {
        // The file only ever holds what `load` keeps, so what an action persisted is exactly what
        // the next launch seeds. Decoded raw — not via `load`, which would sanitise again — to pin
        // the bytes on disk.
        let url = tempURL()
        defer { try? FileManager.default.removeItem(at: url) }

        try EmbeddedScope(hosts: ["ok.test", "bad\nhost.test", "ok.test"]).save(to: url)

        let onDisk = try JSONDecoder().decode(EmbeddedScope.self, from: Data(contentsOf: url))
        #expect(onDisk.hosts == ["ok.test"])
        #expect(!(try String(contentsOf: url, encoding: .utf8)).contains("bad"))
    }

    @Test func saveRefusesAFileOverOneMebibyteAndWritesNothing() throws {
        // `load` reads nothing over 1 MiB, so a save that produced such a file would wipe the scope
        // at the next launch with no signal. `sanitized` caps the count at 10 000 first, so the
        // overflow is 10 000 distinct ~200-character hosts (each under the 1 024 cap): about 2 MiB.
        let hosts = (0..<10_000).map { String(repeating: "a", count: 190) + "\($0).test" }
        #expect(EmbeddedScope.sanitized(hosts).count == 10_000)
        let url = tempURL()
        defer { try? FileManager.default.removeItem(at: url) }

        let error = #expect(throws: EmbeddedScope.SaveError.self) {
            try EmbeddedScope(hosts: hosts).save(to: url)
        }

        guard case .tooLarge(let bytes)? = error else { Issue.record("expected .tooLarge, got \(String(describing: error))"); return }
        #expect(bytes > 1_048_576)
        #expect(!FileManager.default.fileExists(atPath: url.path))
    }

    @Test func saveErrorNamesTheSizeAndTheLimit() {
        // Surfaces through `BusService.persistEmbeddedScope` as "Scope change not saved: …".
        let error = EmbeddedScope.SaveError.tooLarge(bytes: 2_000_000)

        #expect(error.errorDescription == "scope.json would be 2000000 bytes; the limit is 1048576")
        #expect(error.localizedDescription == "scope.json would be 2000000 bytes; the limit is 1048576")
    }
}
