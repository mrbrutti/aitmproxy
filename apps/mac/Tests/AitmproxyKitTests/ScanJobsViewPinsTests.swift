import AitmBusClient
import Foundation
import Testing
@testable import AitmproxyKit

/// Stage 5 of the Jobs view redesign, mac PR 2 (plan Task 2.11): the pins the
/// coders' suites left to the gate's greps (AC22, AC23, AC32's timer grep), the
/// Kit halves of the live-proof criteria (AC46, AC48, AC49), and the inputs a
/// misbehaving core can still send the derived model once the decoder has refused
/// negatives and anything past 2^53. The facts builders are `ScanSurfaceTests`'s
/// (same module); the source pins read the repo the way `EmbeddedCoreLaunchTests`
/// and `ScanPack` do, five levels up from this file.
@Suite struct ScanJobsViewPinsTests {
    typealias F = ScanSurfaceTests

    /// The repo root: this file lives at apps/mac/Tests/AitmproxyKitTests/.
    static let root: URL = {
        var url = URL(fileURLWithPath: #filePath)
        for _ in 0..<5 { url.deleteLastPathComponent() }
        return url
    }()

    static func source(_ path: String) throws -> String {
        let url = root.appending(path: path)
        try #require(FileManager.default.fileExists(atPath: url.path), "missing \(url.path)")
        return try String(contentsOf: url, encoding: .utf8)
    }

    /// The four Jobs view files AC22 and AC32 grep (spec D11 *Tokens, exhaustively*).
    static let jobsViewFiles = [
        "apps/mac/Sources/Aitmproxy/Panels/ScanPanel+Jobs.swift",
        "apps/mac/Sources/Aitmproxy/Panels/ScanJobCard.swift",
        "apps/mac/Sources/Aitmproxy/Panels/ScanJobWells.swift",
        "apps/mac/Sources/Aitmproxy/Panels/ScanProgressViews.swift",
    ]

    // MARK: AC23

    /// AC23 (D12, Tasks 2.1 and 2.10): the generated token files carry the Jobs view's
    /// values exactly as the spec lists them, `tokens.json` is at 0.2.0 with every
    /// shadow alpha spelled with a leading zero (gap 16), the TUI pins the same version,
    /// the committed MCP widgets stylesheet has the card ground (gap 21), and
    /// `ScanMotion.swift` has no numeral outside its comments. `Tokens.swift` is
    /// generated and app-only, so the pin is on the file, not on `Tok`.
    @Test func tokensAndMotionCarryTheJobsViewValues() throws {
        let tokens = try Self.source("apps/mac/Sources/Aitmproxy/UI/Tokens.swift")
        #expect(tokens.contains("// Version 0.2.0."))
        #expect(tokens.contains("/// Eight sizes."), "gap 22: the size group's description names eight sizes")
        for line in [
            "static let counter: Double = 0.150",
            "static let progress: Double = 0.250",
            "static let stagger: Double = 0.060",
            "static let card = DynamicColor(light: 0xFFFFFF, dark: 0x232326)",
            "static let float = FloatingShadow(y: 12, radius: 32 / 2, lightOpacity: 0.10, darkOpacity: 0.42)",
            "static let rest = FloatingShadow(y: 4, radius: 14 / 2, lightOpacity: 0.08, darkOpacity: 0.28)",
            "static let xxl: CGFloat = 24",
            "static let display: CGFloat = 28",
        ] {
            #expect(tokens.contains(line), "Tokens.swift lacks `\(line)`")
        }

        let data = try Data(contentsOf: Self.root.appending(path: "docs/design/tokens.json"))
        let json = try #require(try JSONSerialization.jsonObject(with: data) as? [String: Any])
        func leaf(_ path: String...) -> Any? {
            var node: Any? = json
            for key in path { node = (node as? [String: Any])?[key] }
            return node
        }
        #expect(json["$version"] as? String == "0.2.0")
        #expect(leaf("motion", "counter", "$value") as? String == "150ms")
        #expect(leaf("motion", "progress", "$value") as? String == "250ms")
        #expect(leaf("motion", "stagger", "$value") as? String == "60ms")
        #expect(leaf("color", "ground", "card", "$value", "light") as? String == "#FFFFFF")
        #expect(leaf("color", "ground", "card", "$value", "dark") as? String == "#232326")
        #expect(leaf("shadow", "float", "$value", "light") as? String
                == "0 12px 32px rgba(17,24,39,0.10), 0 1px 2px rgba(17,24,39,0.06)")
        #expect(leaf("shadow", "float", "$value", "dark") as? String
                == "0 12px 32px rgba(0,0,0,0.42), 0 1px 0 rgba(255,255,255,0.04) inset")
        #expect(leaf("shadow", "rest", "$value", "light") as? String == "0 4px 14px rgba(17,24,39,0.08)")
        #expect(leaf("shadow", "rest", "$value", "dark") as? String == "0 4px 14px rgba(0,0,0,0.28)")
        #expect(leaf("typography", "size", "xxl", "$value") as? String == "24px")
        #expect(leaf("typography", "size", "display", "$value") as? String == "28px")
        #expect((leaf("typography", "size", "$description") as? String)?.hasPrefix("Eight sizes.") == true)
        for name in ["float", "rest"] {
            for mode in ["light", "dark"] {
                let css = try #require(leaf("shadow", name, "$value", mode) as? String)
                #expect(!css.contains(",."), "shadow.\(name).\(mode) has an alpha without a leading zero (gap 16)")
            }
        }

        let motion = try Self.source("apps/mac/Sources/Aitmproxy/UI/ScanMotion.swift")
        let digit = try Regex("[0-9]")
        let numeralsInCode = motion.split(separator: "\n", omittingEmptySubsequences: false)
            .filter { $0.contains(digit) && !$0.trimmingCharacters(in: .whitespaces).hasPrefix("//") }
        #expect(numeralsInCode.isEmpty, "ScanMotion.swift carries a numeral outside its comments: \(numeralsInCode)")
        for (name, token) in [
            ("counter", "counter"), ("progress", "progress"), ("state", "popover"), ("entrance", "sheet"),
            ("stagger", "stagger"), ("endSwap", "sheet"), ("hoverReveal", "hover"), ("breath", "interceptPulse"),
        ] {
            #expect(motion.contains("static let \(name) = Tok.Motion.\(token)"), "ScanMotion.\(name) is not Tok.Motion.\(token)")
        }
        #expect(motion.contains("static func ease(_ duration: Double) -> Animation { Tok.Motion.easeOut(duration) }"))
        #expect(motion.contains("static func breathe() -> Animation { Tok.Motion.pulse(breath).repeatForever(autoreverses: true) }"))
        #expect(!motion.contains("TimelineView"))

        #expect(try Self.source("crates/aitm-tui/src/tokens.rs").contains("\"0.2.0\""), "the TUI's TOKENS_VERSION pin")
        let widgets = try Self.source("crates/aitm-mcp/widgets/tokens.css")
        #expect(widgets.components(separatedBy: "--color-ground-card").count - 1 >= 2, "gap 21: the committed widgets stylesheet")
    }

    // MARK: AC22, AC32 (the view files)

    /// AC22 and AC32's second grep (D11, D12, D16), held in-process so `swift test`
    /// catches them too: no colour, radius or duration literal in the four Jobs view
    /// files; every `CGFloat`/`Double` constant inside `enum CardMetrics`; no `Timer`,
    /// `Task.sleep` or `TimelineView` (the counters come from the poll, the entrance from
    /// the state's generation, the breathing from a system-driven animation); and the
    /// views Tasks 2.6 and 2.10 deleted stay deleted everywhere under the app target.
    @Test func jobsViewsCarryNoLiteralsOrTimers() throws {
        let literal = try Regex(
            #"Color\(|\.cornerRadius\(|easeOut\(0\.[0-9]|\.animation\(\.easeOut|Animation\.(easeOut|easeIn|easeInOut|linear|spring)|TimelineView"#)
        let numeric = try Regex(#": CGFloat = [0-9]|: Double = [0-9]"#)
        var numericOutsideMetrics: [String] = []
        var metricsLines = 0
        for path in Self.jobsViewFiles {
            let lines = try Self.source(path).split(separator: "\n", omittingEmptySubsequences: false).map(String.init)
            let offenders = lines.enumerated().filter { $0.element.contains(literal) }.map { "\(path):\($0.offset + 1)" }
            #expect(offenders.isEmpty, "colour, radius or duration literals: \(offenders)")
            for word in ["Timer", "Task.sleep", "TimelineView"] {
                let hits = lines.enumerated().filter { $0.element.contains(word) }.map { "\(path):\($0.offset + 1)" }
                #expect(hits.isEmpty, "\(word) in a Jobs view: \(hits)")
            }
            // `enum CardMetrics {` at column 0 to the first `}` at column 0 after it.
            var inside = false
            for (index, line) in lines.enumerated() {
                if line.hasPrefix("enum CardMetrics") { inside = true; continue }
                if inside, line == "}" { inside = false; continue }
                guard line.contains(numeric) else { continue }
                if inside { metricsLines += 1 } else { numericOutsideMetrics.append("\(path):\(index + 1)") }
            }
        }
        #expect(numericOutsideMetrics.isEmpty, "numeric constants outside CardMetrics: \(numericOutsideMetrics)")
        #expect(metricsLines >= 10, "CardMetrics should hold the comp's constants; found \(metricsLines)")

        let appSources = try FileManager.default.subpathsOfDirectory(atPath: Self.root.appending(path: "apps/mac/Sources").path)
            .filter { $0.hasSuffix(".swift") }
        #expect(appSources.count > 50, "the walk found the app's sources")
        var survivors: [String] = []
        for path in appSources {
            let text = try Self.source("apps/mac/Sources/\(path)")
            for gone in ["ScanJobDetail", "ScanJobProgressRule", "ScanSeverityBar", "severityBarSegments", "ScanSeveritySegment",
                         "jobRowLine1", "jobRowLine2"] where text.contains(gone) {
                survivors.append("\(path): \(gone)")
            }
        }
        #expect(survivors.isEmpty, "deleted by Tasks 2.6 and 2.10, still referenced: \(survivors)")
    }

    // MARK: AC46, AC48, AC49 (the Kit halves)

    /// The Kit halves of three live-proof criteria: AC46's chip word and tone per state
    /// (the colours are the app's `ScanToneColors`, proved by frame), AC48's ledger and
    /// Issues words for `light-http`'s `1 high, 2 low`, and AC49's `tiny-budget` gauge
    /// warning, text and stopped-reason sentence at a budget of 50 (the P4 pin uses 2,000).
    @Test func kitHalvesOfTheCardLiveProofs() throws {
        let states: [(ScanJobState, ScanPhase, String, ScanJobTone)] = [
            (.running, .auditing, "Auditing", .progress), (.cancelling, .auditing, "Cancelling", .pending),
            (.done, .done, "Done", .success), (.cancelled, .done, "Cancelled", .neutral), (.failed, .done, "Failed", .danger),
        ]
        for (state, phase, word, tone) in states {
            let facts = try F.progressFacts(state: state, phase: phase)
            #expect(ScanFormat.stateWord(facts) == word)
            #expect(ScanFormat.tone(facts) == tone)
        }

        // AC48: light-http ends 1 high, 2 low on today's target.
        let lightHTTP = F.tally(high: 1, low: 2)
        #expect(ScanFormat.ledgerGroups(by: lightHTTP) == [
            ScanLedgerGroup(severity: .high, count: 1, marks: 1, word: "1 high"),
            ScanLedgerGroup(severity: .low, count: 2, marks: 2, word: "2 low"),
        ])
        #expect(ScanFormat.severityWords(by: lightHTTP, running: false) == "1 high, 2 low")
        #expect(ScanFormat.severityWordParts(by: lightHTTP).map(\.0) == [.high, .low])
        #expect(ScanFormat.severityWordParts(by: lightHTTP).map(\.1) == ["1 high", "2 low"])
        #expect(ScanFormat.issuesTileHelp(by: lightHTTP) == "3 issues: 1 high, 2 low")
        #expect(ScanFormat.grouped(lightHTTP.total) == "3", "the KPI Issues numeral")
        let standard = F.tally(low: 4)
        #expect(ScanFormat.ledgerGroups(by: standard).map(\.marks) == [4])
        #expect(ScanFormat.severityWords(by: standard, running: true) == "4 low")

        // AC49: a budget of 50 turns the gauge past 80 % (strictly more than 40 probes).
        #expect(ScanFormat.budgetWarning(sent: 41, budget: 50) == true)
        #expect(ScanFormat.budgetWarning(sent: 40, budget: 50) == false, "40 of 50 is 80 % exactly, not past it")
        #expect(ScanFormat.budgetWarning(sent: 50, budget: 50) == true)
        #expect(ScanFormat.budgetWarning(sent: 0, budget: 50) == false)
        #expect(ScanFormat.probeBudgetText(sent: 43, budget: 50) == "43 of 50")
        #expect(ScanFormat.probesTileHelp(sent: 43, budget: 50) == "43 of 50 probes sent (the probe budget, not progress)")
        let spent = try F.progressFacts(
            state: .done, phase: .done, elapsedMs: 31_000,
            edits: F.checks(done: 50, scheduled: 240) + F.compJob + F.issues() + [
                (["probes", "budget"], 50), (["probes", "sent"], 50), (["stopped_reason"], "budget"),
                (["finished_at"], .number(Double(F.finishedAt1133))),
            ])
        #expect(spent.summary.probes.budget == 50, "the terminal status wins the merge (D2), so the reason quotes its budget")
        let line = ScanFormat.findingLine(spent, timeZone: F.lisbon)
        #expect(line.reason == "Stopped early: the probe budget of 50 was spent. Raise it in the profile to go further.")
        #expect(line.text == "standard · started 11:32 by this app · finished 11:33")
        #expect(ScanFormat.stateWord(spent) == "Done")
        #expect(ScanFormat.tone(spent) == .success)
        #expect(ScanEndText.sentence(spent) == "Done in 0:31 · 120 points · 240 checks.")
        #expect(ScanEndText.rawReasonLine(.budget) == "stopped_reason: budget")
        #expect(ScanEndText.attention(spent) == [], "a spent budget is a reason, not an attention line")
        // The raw token has one home, the attention block: nothing the title row, lane, row or
        // announcement says carries it.
        for text in [line.reason ?? "", line.text, ScanEndText.sentence(spent) ?? "",
                     ScanFormat.jobAccessibilityLabel(spent), ScanFormat.endAnnouncement(spent)] {
            #expect(!text.contains("stopped_reason"), "\(text)")
        }
    }

    // MARK: What the decoder lets through

    /// The decoder refuses negatives and anything past 2^53 (`ScanWire.whole`); everything
    /// inside that reaches these words. `done` past `scheduled`, the ceiling itself, more
    /// running ids than the engine's cap, a hostile check id, malformed and oversized
    /// origins, a zero `started_at`, and the Scan Again edges of gap 32 must all read as
    /// bounded words, never a crash or an unbounded line.
    @Test func wordsSurviveWhatTheDecoderLetsThrough() throws {
        let ceiling = 9_007_199_254_740_992  // 2^53, `ScanWire.wholeNumberRange`'s top

        // done past scheduled: nothing to go and no pace, as the guards say; the fraction
        // is clamped at 1 (D8 types it 0…1), so the ring and the percent never overshoot
        // while the phase line still quotes the counters as sent (fix 2.11b).
        let over = ScanJobProgress(try F.progressFacts(
            state: .running, phase: .auditing, edits: F.checks(done: 7000, scheduled: 6468)))
        #expect(over.checksToGoText == nil)
        #expect(over.estimateText == nil)
        #expect(over.phaseLine == "7,000 of 6,468 checks")
        #expect(over.fraction == 1, "fraction \(over.fraction ?? -1)")
        #expect(over.percentText == "100\u{00A0}%", "percent \(over.percentText ?? "nil")")
        #expect(over.ring == .determinate(1))
        // The same counters on a finished job: the dimmed ring is full, not past full.
        let overDone = ScanJobProgress(try F.progressFacts(
            state: .done, phase: .done, edits: F.checks(done: 7000, scheduled: 6468)))
        #expect(overDone.ring == .finished(1))

        // The ceiling, end to end: grouped, no overflow, no crash.
        let huge = try F.progressFacts(
            state: .running, phase: .auditing, elapsedMs: ceiling, edits: F.checks(done: ceiling, scheduled: ceiling))
        let hugeProgress = ScanJobProgress(huge)
        #expect(hugeProgress.percentText == "100\u{00A0}%")
        #expect(ScanFormat.rowProgressText(huge, hugeProgress) == "100\u{00A0}% · 9,007,199,254,740,992 of 9,007,199,254,740,992")
        #expect(ScanFormat.checksToGo(done: 0, scheduled: ceiling) == "9,007,199,254,740,992 checks to go")
        #expect(ScanFormat.elapsed(ms: ceiling) == "2501999792:59:00")
        #expect(ScanFormat.elapsedWords(ms: ceiling) == "2501999792 hours 59 minutes")
        #expect(ScanFormat.jobAccessibilityLabel(huge).hasSuffix(", 2501999792 hours 59 minutes."))
        let crawlPace = try #require(ScanFormat.paceEstimate(done: 1, scheduled: ceiling, elapsedMs: 1))
        #expect(crawlPace.checksPerSecond == 1000)
        #expect(crawlPace.secondsToGo == 9_007_199_254_741)
        #expect(ScanFormat.estimateText(crawlPace) == "at this pace, about 2501999792:59:01 to go")

        // More running ids than the engine's cap of 8: the decoder keeps the first eight, so the
        // line reads `and 7 more` whatever the core sent; a hostile id is cleaned and cut to 400.
        let ids = (0..<20).map { "check-\($0)" }
        let many = ScanJobProgress(try F.progressFacts(
            state: .running, phase: .auditing, edits: F.checks(done: 1, scheduled: 2, running: ids)))
        #expect(many.nowLine == "Now: check-0 and 7 more")
        #expect(many.nowTag == "now · check-0 and 7 more")
        #expect(ScanFormat.nowClause(running: Array(ids.prefix(8))) == "check-0 and 7 more checks running now")
        let hostile = "xss\u{202E}\u{0}-reflected" + String(repeating: "a", count: 500)
        let cleaned = ScanJobProgress(try F.progressFacts(
            state: .running, phase: .auditing, edits: F.checks(done: 1, scheduled: 2, running: [hostile])))
        let nowLine = try #require(cleaned.nowLine)
        #expect(nowLine.hasPrefix("Now: xss-reflected"))
        #expect(nowLine.unicodeScalars.count == "Now: ".unicodeScalars.count + 400)
        #expect(!nowLine.unicodeScalars.contains { [.format, .control].contains($0.properties.generalCategory) })

        // Malformed origins: the heading falls back to the origin's text (bounded at decode to 200
        // scalars), and Scan Again refuses a non-http(s) target as out of scope (gap 32) whatever
        // the scope says; the arguments still echo the origins, the gate is what refuses.
        let odd = ["not a url", "ftp://x.test", "http://", "http://user@h.test:8/p"]
        let oddFacts = try F.progressFacts(
            state: .done, phase: .done, edits: [(["targets"], .array(odd.map { .string($0) })), (["job"], "scan-odd")])
        #expect(ScanFormat.jobHeading(oddFacts) == "not a url and 3 more")
        #expect(ScanFormat.jobHeadingHelp(oddFacts) == "not a url, ftp://x.test, http://, h.test:8")
        #expect(ScanFormat.hostsText(oddFacts) == "not a url, ftp://x.test, http://, h.test:8")
        var model = ScanSurfaceModel()
        model.applyStatus(try #require(oddFacts.status))
        #expect(model.scanAgainRefusal(for: "scan-odd", scopeHosts: ["not a url", "x.test", "h.test:8"], tools: F.toolsWithStart)
                == "Out of scope — add not a url to scope to scan it")
        #expect(model.scanAgainArguments(for: "scan-odd")?.args["overrides"]
                == ["target": ["origins": .array(odd.map { .string($0) })]])
        let longHost = "http://" + String(repeating: "a", count: 300)
        let long = try F.progressFacts(state: .running, phase: .auditing, edits: [(["targets"], [.string(longHost)])])
        #expect(ScanFormat.jobHeading(long).count == 200 - "http://".count, "targets are cut at 200 scalars on decode")

        // A zero `started_at` (an older core): `started by …` with no clock.
        let unclocked = try F.progressFacts(
            state: .running, phase: .auditing,
            edits: F.checks(done: 1, scheduled: 2) + F.compJob + F.issues() + [(["started_at"], 0)])
        #expect(ScanFormat.findingLine(unclocked, timeZone: F.lisbon).text == "no issues so far · standard · started by this app")

        // Gap 32: an empty profile name is sent verbatim (the engine answers `invalid_profile`
        // inline); the help and the confirm summary fall back to the generic text and `—`; empty
        // targets pass the scope gate and send `origins: []`; non-strings are dropped, not crashed on.
        let request = try #require(L4ConfirmRequest(json: [
            "structuredContent": ["status": "needs_confirmation", "prompt": "Really?", "confirm_token": "t"],
        ]))
        let nameless = try F.progressFacts(
            state: .done, phase: .done, edits: F.compJob + [(["job"], "scan-nameless"), (["profile_name"], "")])
        model.applyStatus(try #require(nameless.status))
        let namelessArgs = try #require(model.scanAgainArguments(for: "scan-nameless"))
        #expect(namelessArgs.args["profile_name"] == "")
        #expect(ScanSurfaceModel.scanAgainHelp(try #require(nameless.status)) == "Start a new job with this job's profile and target")
        #expect(ScanConfirm(tool: namelessArgs.tool, arguments: namelessArgs.args, request: request).summaryLine
                == "Profile — · 127.0.0.1:8117")
        let targetless = try F.progressFacts(
            state: .done, phase: .done, edits: [(["job"], "scan-targetless"), (["targets"], [])])
        model.applyStatus(try #require(targetless.status))
        #expect(model.scanAgainRefusal(for: "scan-targetless", scopeHosts: [], tools: F.toolsWithStart) == nil,
                "no http origin, nothing for the scope gate to refuse")
        let targetlessArgs = try #require(model.scanAgainArguments(for: "scan-targetless"))
        #expect(targetlessArgs.args["overrides"] == ["target": ["origins": []]])
        #expect(ScanSurfaceModel.scanAgainHelp(try #require(targetless.status)) == "Start a new job with profile standard")
        #expect(ScanConfirm(tool: targetlessArgs.tool, arguments: targetlessArgs.args, request: request).summaryLine
                == "Profile standard")
        #expect(ScanConfirm(
            tool: "scan.start", arguments: ["profile_name": 7, "overrides": ["target": ["origins": [1, "http://a.test"]]]],
            request: request).summaryLine == "Profile — · a.test")

        // The caption at its edges.
        #expect(ScanFormat.jobsCaption(total: 0, running: 0) == "0 jobs")
        #expect(ScanFormat.jobsCaption(total: 1, running: 1) == "1 job · 1 running")
        #expect(ScanFormat.jobsCaption(total: 1200, running: 1000) == "1,200 jobs · 1,000 running")
    }

    /// Fix 2.12a (PR 2 security Important): `paceEstimate` stays in `Double` until the
    /// seconds-to-go are known to fit under the decoder's 2^53 ms ceiling and gives up
    /// the estimate rather than trap, so a `scan.status` with in-range but enormous
    /// counters (`done 1, scheduled 2^53, elapsed_ms 2^53`: a quotient past `Int.max`;
    /// `done 1, scheduled 1e12, elapsed_ms 1e7`: seconds that fit but whose `× 1000`
    /// overflows) renders every other counter word and no estimate. The tester's
    /// ceiling case (`elapsedMs: 1`, `secondsToGo` 9,007,199,254,741) still renders.
    @Test func paceEstimateGivesUpBeforeItWouldTrap() throws {
        let ceiling = 9_007_199_254_740_992  // 2^53, `ScanWire.wholeNumberRange`'s top

        // The quotient 8.1e28 is past `Int.max`: no pace, and the progress still says
        // what it can.
        #expect(ScanFormat.paceEstimate(done: 1, scheduled: ceiling, elapsedMs: ceiling) == nil)
        let vast = ScanJobProgress(try F.progressFacts(
            state: .running, phase: .auditing, elapsedMs: ceiling, edits: F.checks(done: 1, scheduled: ceiling)))
        #expect(vast.estimateText == nil)
        #expect(vast.estimateHelp == nil)
        #expect(vast.checksToGoText == "9,007,199,254,740,991 checks to go")
        #expect(vast.phaseLine == "1 of 9,007,199,254,740,992 checks")
        #expect(vast.percentText == "0\u{00A0}%")

        // 9.99e15 seconds fit an `Int`, but `× 1000` would overflow: no pace either.
        #expect(ScanFormat.paceEstimate(done: 1, scheduled: 1_000_000_000_000, elapsedMs: 10_000_000) == nil)
        let tall = ScanJobProgress(try F.progressFacts(
            state: .running, phase: .auditing, elapsedMs: 10_000_000, edits: F.checks(done: 1, scheduled: 1_000_000_000_000)))
        #expect(tall.estimateText == nil)
        #expect(tall.estimateHelp == nil)
        #expect(tall.checksToGoText == "999,999,999,999 checks to go")

        // The tester's ceiling case still renders: the raw quotient is under the bound,
        // the rounded-up second lands at 2^53 + 8 ms, inside `Int` and `elapsed(ms:)`.
        let edge = try #require(ScanFormat.paceEstimate(done: 1, scheduled: ceiling, elapsedMs: 1))
        #expect(edge.secondsToGo == 9_007_199_254_741)
        #expect(ScanFormat.estimateText(edge) == "at this pace, about 2501999792:59:01 to go")
        // One check per millisecond less: the same bound from below, as a progress.
        let edgeProgress = ScanJobProgress(try F.progressFacts(
            state: .running, phase: .auditing, elapsedMs: 1, edits: F.checks(done: 1, scheduled: ceiling)))
        #expect(edgeProgress.estimateText == "at this pace, about 2501999792:59:01 to go")
        #expect(edgeProgress.estimateHelp == "Derived from the counters: 1 check done in 0:00, "
                + "about 1,000 checks per second, 9,007,199,254,740,991 to go.")
    }
}
