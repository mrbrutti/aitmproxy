import AitmBusClient
import AitmproxyKit
import AppKit
import Synchronization

/// Self-test for agents: drives the real session model on fixture data,
/// prints PASS or FAIL per check, and quits with exit code 0 or 1.
///   APP_STORE=/tmp/x ~/Applications/Aitmproxy.app/Contents/MacOS/Aitmproxy --selftest
/// (tools/selftest.sh does this.) Add a check for every story with logic.
@MainActor
enum SelfTest {
    static var requested: Bool { CommandLine.arguments.contains("--selftest") }
    /// Read by AppDelegate.applicationWillTerminate.
    static var exitCode: Int32 = 0
    static var failures = 0
    static var count = 0

    /// The window scene's `.task` starts the self-test. AppKit opens a bare
    /// command-line word (one that is neither `--selftest` nor part of a
    /// `-key value` pair) as a document, and SwiftUI then never opens the main
    /// window, so that `.task` never fires and the process would idle forever
    /// (seen 2026-10-31 with `--selftest -bus.activeKind external`). The watchdog
    /// turns that, and a check that never settles, into a failed run: FAIL and
    /// exit 1 when the self-test has not started by `startDeadline` or finished by
    /// `runDeadline`. It runs off the main actor so a busy main thread cannot stall it.
    nonisolated static let startDeadline: Duration = .seconds(15)
    nonisolated static let runDeadline: Duration = .seconds(240)
    nonisolated private static let started = Mutex(false)
    nonisolated private static let finished = Mutex(false)

    static func armWatchdog() {
        guard requested else { return }
        Task.detached {
            try? await Task.sleep(for: startDeadline)
            guard started.withLock({ $0 }) else {
                print("SELFTEST FAIL: not started within \(startDeadline): the main window never appeared. A bare command-line word is opened as a document; pass settings through APP_DEFAULTS_SUITE, not -key value arguments.")
                exit(1)
            }
            try? await Task.sleep(for: runDeadline - startDeadline)
            guard finished.withLock({ $0 }) else {
                print("SELFTEST FAIL: not finished within \(runDeadline)")
                exit(1)
            }
        }
    }

    static func runIfRequested(session: Session) {
        guard requested else { return }
        started.withLock { $0 = true }
        setvbuf(stdout, nil, _IOLBF, 0)
        guard Store.isOverridden else {
            print("SELFTEST refused: set APP_STORE to a folder in /tmp")
            finish(code: 1)
            return
        }
        // APP_LIVE=1: the bus pass instead of the fixture checks (SelfTest+Live.swift).
        if live { return runLive(session: session) }
        Task {
            try? await Task.sleep(for: .seconds(0.5))
            // The fixture set is Fixtures.rows + Fixtures.l4Rows; derive every count from it so
            // the self-test follows the fixtures instead of pinning a stale literal.
            let fixtureCount = Fixtures.rows.count + Fixtures.l4Rows.count
            let inScopeCount = (Fixtures.rows + Fixtures.l4Rows).filter(\.inScope).count
            check("fixtures load \(fixtureCount) rows", session.rows.count == fixtureCount)
            check("two flows are paused", session.paused.count == 2)
            check("the paused login is selected", session.focusedRow?.seq == 50)
            check("the inspector has the login detail", session.focusedDetail?.request.header("x-forwarded-for") == "127.0.0.1")

            session.chip = .json
            check("the JSON chip narrows the list", session.visibleRows.count < session.rows.count && !session.visibleRows.isEmpty)
            session.chip = .websocket
            check("the WebSocket chip keeps only WS flows", session.visibleRows.allSatisfy { $0.kind == .websocket } && session.visibleRows.count == 1)
            session.chip = .all

            session.page = .scope
            check("Scope filters to in-scope flows", session.visibleRows.allSatisfy(\.inScope) && session.visibleRows.count == inScopeCount)
            session.page = .apps

            session.select(session.rows[0].id)
            check("selecting a row focuses the inspector", session.focusedRow?.seq == 41)
            session.interceptArmed = false
            check("disarming clears the armed state", !session.interceptArmed)

            // S-045: a WebSocket flow shows its frame stream, not a request/response.
            let wsRow = session.rows.first { $0.kind == .websocket }
            session.select(wsRow?.id)
            let ws = session.focusedWSDetail
            check("selecting the WebSocket flow loads its frames", (ws?.frames.count ?? 0) == 7)
            check("the first frame pretty-prints as JSON", ws?.frames.first?.bodyKind == .json)
            check("a binary frame is detected", ws?.frames.contains { $0.opcode == "binary" && $0.bodyKind == .binary } == true)
            check("an injected frame is marked", ws?.frames.contains { $0.injected } == true)
            session.select(session.rows[0].id)

            // S-009: sorting never moves the selection; status puts rows without a code last.
            session.sort = FlowSort(key: .status, ascending: false)
            check("sorting by status puts 502 first and rows without a code last",
                  session.visibleRows.first?.status == 502 && session.visibleRows.last?.status == nil)
            check("sorting keeps the selection", session.focusedRow?.seq == 41 && session.selection.count == 1)
            session.sort = .captureOrder
            check("capture order is the default sort", session.visibleRows.map(\.seq) == session.rows.map(\.seq))

            // S-016: density moves row pitch and body size together, selection intact.
            session.density = .comfortable
            check("comfortable density is 40pt rows with 14pt text", session.density.rowHeight == 40 && session.density.bodySize == 14)
            check("changing density keeps the selection", session.focusedRow?.seq == 41)
            session.density = .dense

            // S-008: the column layout round-trips through the state folder.
            let layout = ColumnLayout(order: ["seq", "url", "method"], widths: ["url": 333], hidden: ["mark"])
            try? layout.save(to: session.columnsURL)
            let loaded = ColumnLayout.load(from: session.columnsURL)
            check("column layout persists under Store.url/columns.json", loaded == layout)
            check("a missing column width falls back to its default", loaded?.width(for: "time", default: 124) == 124)

            // S-012: multi-select summary.
            session.selection = Set(session.rows[0..<3].map(\.id))
            check("three selected rows summarise size and timing", session.selectionSummary?.text == "3 selected · 20.7 KB · 177 ms")
            session.select(session.rows[0].id)
            check("one row returns the summary to the row count", session.selectionSummary == nil)

            // S-013: grouping from the sidebar.
            session.show(.apps, group: .client("curl"))
            check("selecting curl under Apps narrows to curl's flows", session.visibleRows.count == 3 && session.visibleRows.allSatisfy { $0.client?.name == "curl" })
            session.show(.domains, group: .host("cdn.shop-staging.test"))
            check("selecting a host under Domains narrows to it", session.visibleRows.allSatisfy { $0.authority == "cdn.shop-staging.test" })
            session.show(.apps)
            check("the group header shows all flows again", session.visibleRows.count == fixtureCount)

            // S-014: pins persist and never duplicate.
            session.pin(.host("cdn.shop-staging.test"))
            session.pin(.host("cdn.shop-staging.test"))
            check("pinning a host twice stores it once", session.pins.hosts.filter { $0 == "cdn.shop-staging.test" }.count == 1)
            check("pins persist under Store.url/pins.json", Pins.load(from: session.pinsURL).hosts.contains("cdn.shop-staging.test"))
            session.unpin(.host("cdn.shop-staging.test"))
            check("unpinning removes the host", !session.pins.hosts.contains("cdn.shop-staging.test"))

            // S-015: Auto-select follows the newest flow, except from a paused row.
            session.autoSelect = true
            session.select(session.rows[0].id)
            session.rows.append(Fixtures.rows[0].withID("auto-1", seq: 60))
            check("Auto-select focuses the newest flow", session.focusedRow?.seq == 60)
            session.select(session.rows[9].id)  // the paused login
            session.rows.append(Fixtures.rows[0].withID("auto-2", seq: 61))
            check("Auto-select does not steal focus from a paused row", session.focusedRow?.seq == 50)
            session.autoSelect = false

            // S-017: marks and comments.
            let first = session.rows[0].id
            session.mark(first, .green)
            session.comment(first, "baseline")
            check("marking and commenting update the row at once", session.rows[0].mark == .green && session.rows[0].comment == "baseline")

            // S-018: pause and clear.
            session.setCapturing(false)
            await settle { !session.capturing }
            check("pausing capture flips the state", !session.capturing)
            let beforeClear = session.rows
            let focusBeforeClear = session.focused
            let selectionBeforeClear = session.selection
            session.clearSession(confirm: { _ in true })
            await settle { session.rows.isEmpty && session.clearNotice != nil }
            check("clearing empties the session", session.rows.isEmpty && session.focused == nil)
            // D2: Clear keeps one undo step (Edit > Undo Clear) and says so in the status bar.
            check("clear shows the notice with the count and registers Undo Clear",
                  session.clearNotice?.count == beforeClear.count && session.flowUndoManager.canUndo
                      && session.flowUndoManager.undoActionName == "Clear")
            session.flowUndoManager.undo()
            check("undo restores the rows, selection and focused flow",
                  session.rows == beforeClear && session.focused == focusBeforeClear && session.selection == selectionBeforeClear,
                  "rows \(session.rows.count) of \(beforeClear.count), focused \(String(describing: session.focused))")
            check("undo dismisses the notice and the step", session.clearNotice == nil && !session.flowUndoManager.canUndo)
            // Marking an out-of-scope row from the keyboard is refused like every other verb.
            let outOfScope = session.rows.first { !$0.inScope }!
            session.perform(.mark(.red), on: outOfScope.id)
            check("a mark colour on an out-of-scope row is refused with the reason",
                  session.rows.first { $0.id == outOfScope.id }?.mark == nil && session.lastError == VerbTable.outOfScopeReason(outOfScope.authority))
            session.lastError = nil
            // A refused flow.clear offers no Undo and no notice; the rows stay.
            let fixtureActions = session.actions as? FixtureActions
            fixtureActions?.clearFails = true
            session.clearSession(confirm: { _ in true })
            await settle { session.lastError != nil }
            check("a refused clear keeps the rows and offers neither Undo nor the notice",
                  !session.rows.isEmpty && session.clearNotice == nil && session.clearedFlows == nil && !session.flowUndoManager.canUndo
                      && session.lastError == "clear: flow.clear refused (fixture)", session.lastError ?? "no error")
            fixtureActions?.clearFails = false
            session.lastError = nil
            // The notice lapses on its own timer and takes the copy and the step with it.
            Session.clearNoticeSeconds = 0.2
            session.clearSession(confirm: { _ in true })
            await settle { session.rows.isEmpty && session.clearNotice != nil }
            check("the notice shows after the clear", session.clearNotice != nil && session.flowUndoManager.canUndo)
            await settle { session.clearNotice == nil }
            check("letting the notice lapse releases the copy and the step",
                  session.clearedFlows == nil && session.clearNotice == nil && !session.flowUndoManager.canUndo,
                  "copy \(session.clearedFlows == nil) notice \(session.clearNotice == nil) canUndo \(session.flowUndoManager.canUndo)")
            Session.clearNoticeSeconds = 8

            // M3: filters, saved filters, sidebar query, palette.
            session.loadFixtures()
            session.filterStack = FilterStack(rows: [FilterRow(.method, .equals, "POST")])
            check("a Method = POST row narrows to the two POSTs", session.visibleRows.map(\.seq) == [44, 50])
            session.filterStack = FilterStack(rows: [FilterRow(.method, .equals, "POST"), FilterRow(.status, .equals, "502")], combinator: .or)
            check("two rows under Any widen the list", session.visibleRows.map(\.seq) == [44, 45, 50])
            session.filterStack.combinator = .and
            check("switching to All narrows it", session.visibleRows.isEmpty)
            session.filterStack = FilterStack(rows: [FilterRow(.url, .regex, "(")])
            check("an invalid regex marks the row and matches nothing", session.filterStack.rows[0].validationError != nil && session.visibleRows.isEmpty)
            session.clearFilter()
            session.setFilterAdvanced(true)
            session.filterText = "~m POST & ~c 2"
            check("the Advanced text filters", session.filterError == nil && session.visibleRows.map(\.seq) == [44])
            session.filterText = "~m POST &"
            check("a parse error reports an offset", session.filterError != nil && session.visibleRows.count == fixtureCount)
            session.setFilterAdvanced(false)
            session.clearFilter()
            session.filterStack = FilterStack(rows: [FilterRow(.host, .contains, "cdn")])
            session.saveFilter(named: "cdn only")
            session.clearFilter()
            check("saving a filter persists it", (try? SavedFilterStore(stateDirectory: Store.url).load())?.first?.name == "cdn only")
            if let saved = session.savedFilters.first { session.applySavedFilter(saved) }
            check("applying a saved filter sets the rows and the text", session.visibleRows.count == 2 && session.currentFilterExpressionText.contains("cdn"))
            session.clearFilter()
            session.filterBarVisible = false
            session.sidebarQuery = "staging"
            check("the sidebar query matches hosts case-insensitively", session.hosts.filter { $0.0.localizedCaseInsensitiveContains("staging") }.count == 3)
            session.sidebarQuery = ""
            let items = session.paletteItems(for: "repl")
            check("the palette ranks flow.replay first for 'repl'", items.first?.title == "flow.replay")
            // Recent entries duplicate a command under the Recent section; count the Commands section only.
            check("every tool appears in the palette",
                  Set(session.paletteItems(for: "").filter { $0.section == .commands }.map(\.id)).count == session.tools.count)
            let flows = session.paletteItems(for: "auth/login")
            check("a URL fragment finds its flow", flows.contains { if case .flow = $0.kind { return $0.title.contains("auth/login") }; return false })
            // M4: compose, edit & replay, kill modes, bulk.
            session.composeDraft = ComposeDraft(method: "POST", url: "https://api.shop-staging.test/api/cart", headersText: "accept: application/json", body: "{\"q\":1}", bodyKind: .json)
            let before = session.rows.count
            await withCheckedContinuation { (c: CheckedContinuation<Void, Never>) in session.sendCompose { _ in c.resume() } }
            check("Send creates a new flow, selected, origin human", session.rows.count == before + 1 && session.focusedRow?.origin == .human && session.focusedRow?.method == .post)
            check("compose history persists newest first", ComposeHistory.load(from: session.composeURL).entries.first?.url == "https://api.shop-staging.test/api/cart")
            session.composeDraft = ComposeDraft(url: "https://telemetry.vendor-analytics.example/v2/batch")
            check("an out-of-scope URL cannot be sent", session.composeDraft.validationError(scope: session.scopeHosts)?.hasPrefix("Out of scope") == true)
            if let id = session.rows.first(where: { $0.seq == 50 })?.id {
                session.editAndReplay(id)
                check("Edit & Replay prefills Compose from the flow", session.composeVisible && session.composeDraft.url.hasSuffix("/api/auth/login") && session.composeDraft.method == "POST")
                session.composeVisible = false
            }
            session.killMode = .respond503
            if let id = session.rows.first(where: { $0.seq == 51 })?.id {
                session.kill(id)
                await settle { session.rows.first { $0.seq == 51 }?.status == 503 }
                check("Kill with Respond 503 shows the synthetic status", session.rows.first { $0.seq == 51 }?.status == 503)
            }
            session.killMode = .reset
            session.selection = Set(session.rows.filter { [41, 50].contains($0.seq) }.map(\.id))
            session.resumeSelected()
            check("bulk resume reports what it skipped", session.lastError == "Resumed 1 · skipped 1 (not paused)")
            await settle { session.rows.first { $0.seq == 50 }?.state == .complete }
            check("bulk resume resumed the paused row", session.rows.first { $0.seq == 50 }?.state == .complete)

            // S-037/S-038: a draft diffs against the proxy's request; Apply & Resume sends mutate then resume.
            session.loadFixtures()
            if let paused = session.rows.first(where: { $0.seq == 51 }) {
                session.editPaused(paused.id)
                check("`e` selects the paused row and opens Raw", session.focused == paused.id && session.requestTab == .raw)
                var m = session.details[paused.id]!.request
                m.headers.append(.init("x-debug", "1"))
                m.body = Data("{}".utf8)
                session.updateDraft(paused.id, m)
                check("the draft counts two pending edits", session.pendingEditCount(paused.id) == 2)
                let parsed = try? RawHTTP.parse(RawHTTP.render(m))
                check("the raw editor text round-trips", parsed?.headers == m.headers && parsed?.bodyText == "{}")
                session.applyAndResume(paused.id)
                await settle { session.rows.first { $0.id == paused.id }?.state == .complete }
                let after = session.rows.first { $0.id == paused.id }
                check("Apply & Resume mutated and resumed the flow", after?.state == .complete && after?.edited == true
                      && session.details[paused.id]?.request.header("x-debug") == "1" && session.editDrafts[paused.id] == nil,
                      "state=\(String(describing: after?.state)) edited=\(String(describing: after?.edited)) x-debug=\(session.details[paused.id]?.request.header("x-debug") ?? "nil") draft=\(session.editDrafts[paused.id] == nil) error=\(session.lastError ?? "-")")
            }

            // S-062: two queries over one capture; the inspector follows the focused pane; Clear acts on the capture.
            session.loadFixtures()
            session.splitView = true
            session.secondQuery.chip = .websocket
            check("the second pane has its own chip", session.secondVisibleRows.count == 1 && session.visibleRows.count == fixtureCount)
            session.focus(pane: 1, on: session.secondVisibleRows.first?.id)
            check("selecting in pane 2 focuses it and the inspector", session.focusedPane == 1 && session.focusedRow?.kind == .websocket)
            session.splitView = false
            check("leaving split view returns focus to pane 1", session.focusedPane == 0)

            // S-070: a burst of 500 rows in 10 batches of 50 appends — each batch's model update + a frame stays short.
            session.loadFixtures()
            var batches: [Duration] = []
            for batch in 0..<10 {
                let started = ContinuousClock.now
                var appended = session.rows
                for n in 0..<50 {
                    appended.append(Fixtures.rows[n % Fixtures.rows.count].withID("burst-\(batch)-\(n)", seq: 100 + batch * 50 + n))
                }
                session.rows = appended
                let model = ContinuousClock.now - started
                await Task.yield()
                try? await Task.sleep(for: .milliseconds(20))
                batches.append(ContinuousClock.now - started - .milliseconds(20))
                print("BURST batch \(batch): model \(Format.duration(model)) · with frame \(Format.duration(batches[batch]))")
            }
            let worst = batches.dropFirst().max() ?? .zero
            check("500 appended rows keep every warm batch under 50 ms (worst \(Format.duration(worst)))", worst < .milliseconds(50), Format.duration(worst))
            check("appends keep the selection", session.focusedRow?.seq == 50)
            check("the list holds \(fixtureCount + 500) rows", session.rows.count == fixtureCount + 500)

            // S-040: rules validate, test against the list, persist, and change the armed notice.
            let rule = BreakpointRule(name: "login", url: "*/api/auth/*", method: "POST")
            check("a rule tests against the current list", BreakpointRules(rules: [rule]).matchCount(of: rule, in: Fixtures.rows) == 1)
            check("an empty URL and a bad regex are rejected",
                  BreakpointRule(url: "").validationError != nil && BreakpointRule(url: "[", matching: .regex).validationError != nil)
            session.setBreakpointRules(BreakpointRules(rules: [rule, BreakpointRule(url: "*", enabled: false)]))
            check("the armed notice counts enabled rules", session.breakpointRules.armedNotice == "Intercept armed — 1 rule")
            check("rules persist under Store.url/rules.json", BreakpointRules.load(from: session.rulesURL).rules.count == 2)

            // M2 scenes: the fixture extras re-key and select correctly.
            session.loadFixtureExtras()
            let cookieRow = session.extraRow { $0.request.header("cookie") != nil }
            check("the cookie extra row exists and is re-keyed", cookieRow?.id.raw.hasPrefix("extra-") == true)
            if let cookieRow { session.select(cookieRow.id) }
            check("selecting the cookie row focuses it", session.focusedRow?.id == cookieRow?.id,
                  "focused \(session.focusedRow?.seq ?? -1) wanted \(cookieRow?.seq ?? -1)")
            check("the cookie row's detail has three request cookies",
                  session.focusedDetail.map { Cookie.cookies(in: $0.request).count } == 3)
            check("an image extra row exists", session.extraRow { ($0.response?.contentType ?? "").hasPrefix("image/") } != nil)

            if let tool = Fixtures.tools.first(where: { $0.name == "flow.replay" }) {
                let form = PaletteForm(tool: tool, session: session)
                check("a FlowId parameter becomes a flow picker preset to the focused flow", form.values["id"] == session.focused?.raw && !form.missing.isEmpty == (session.focused == nil))
            }

            // S-065: HAR out and back in, locally before F10; other formats refused by name.
            do {
                let before = session.rows.count
                let maxSeq = session.rows.map(\.seq).max() ?? 0
                let chosen = Array(session.rows.prefix(2))
                let har = FlowTransfer.export(chosen.map { ($0, session.details[$0.id]) }, as: .har)
                let file = FileManager.default.temporaryDirectory.appending(path: "selftest-\(UUID().uuidString).har")
                try? har.write(to: file, atomically: true, encoding: .utf8)
                check("importing an exported HAR appends its flows as imported",
                      session.importFile(file) && session.rows.count == before + 2
                          && session.rows.suffix(2).allSatisfy { $0.origin == .imported && $0.inScope }
                          && session.rows.last?.seq == maxSeq + 2,
                      "rows \(session.rows.count) wanted \(before + 2); last seq \(session.rows.last?.seq ?? -1)")
                check("the imported flow is selected and has its detail",
                      session.focusedRow?.origin == .imported && session.focusedDetail?.request.startLine.hasPrefix("PUT /api/cart") == true,
                      "focused \(session.focusedRow?.url ?? "-") \(session.focusedDetail?.request.startLine ?? "-")")
                let charles = FileManager.default.temporaryDirectory.appending(path: "selftest.chlz")
                try? Data().write(to: charles)
                check("a Charles file is refused by name", !session.importFile(charles) && session.lastError?.hasPrefix("Can't import selftest.chlz: Charles") == true,
                      session.lastError ?? "-")
                session.rows.removeLast(2)
                session.select(session.rows.first { $0.seq == 50 }?.id)
            }

            // Task 8: the embedded core's health dot and on-demand log panel.
            session.coreHealth.connection = CoreConnection(
                id: .fixture, kind: .embedded, endpoint: BusEndpoint(port: 0, token: ""),
                status: .starting, label: "Embedded core")
            check("the health dot maps starting to restarting", session.coreHealth.health == .restarting)
            session.coreHealth.connection?.status = .ready
            check("the health dot maps ready to running", session.coreHealth.health == .running)
            session.coreHealth.connection?.status = .degraded(reason: "gave up")
            check("the health dot maps degraded to failed", session.coreHealth.health == .failed)
            check("the core log is empty and hidden before any output", session.coreHealth.log.isEmpty && !session.coreLogVisible)
            session.coreHealth.record("proxy listening on 127.0.0.1:8080")
            check("the core log captures a line", session.coreHealth.log.lines.last?.text == "proxy listening on 127.0.0.1:8080")
            session.coreLogVisible = true
            check("Core Log opens the on-demand panel", session.coreLogVisible)
            session.coreLogVisible = false
            session.coreHealth.connection = nil
            session.coreHealth.log.removeAll()

            // S-069: the menu bar carries the brief's command map, and a bare-letter
            // shortcut never takes a letter from a text field.
            checkMenuCoverage()
            await checkTypingIsNotAVerb(session)

            print(failures == 0 ? "SELFTEST PASS \(count) checks" : "SELFTEST FAIL \(failures) of \(count) checks")
            finish(code: failures == 0 ? 0 : 1)
        }
    }

    // MARK: S-069

    private struct MenuEntry {
        var title: String
        var shortcut: Shortcut?
    }

    /// Every item of every menu, submenus included, with its key equivalent as a `Shortcut`.
    private static func allMenuItems() -> [MenuEntry] {
        var out: [MenuEntry] = []
        func walk(_ menu: NSMenu) {
            menu.update()
            for item in menu.items {
                var key = item.keyEquivalent
                var shift = item.keyEquivalentModifierMask.contains(.shift)
                if key.count == 1, key != key.lowercased() { shift = true; key = key.lowercased() }
                let mask = item.keyEquivalentModifierMask
                let shortcut = key.isEmpty ? nil
                    : Shortcut(key, command: mask.contains(.command), shift: shift, option: mask.contains(.option), control: mask.contains(.control))
                out.append(MenuEntry(title: item.title, shortcut: shortcut))
                if let submenu = item.submenu { walk(submenu) }
            }
        }
        if let main = NSApp.mainMenu { walk(main) }
        return out
    }

    private static func checkMenuCoverage() {
        let items = allMenuItems()
        for entry in CommandMap.all {
            if case .deferred(let why) = entry.scope {
                print("SKIP menu \(entry.brief): \(why)")
                continue
            }
            var missing: [String] = []
            for item in entry.items {
                let wantsKey = entry.scope == .menu ? item.shortcut : nil
                let found = items.contains { menu in item.titles.contains(menu.title) && (wantsKey == nil || menu.shortcut == wantsKey) }
                if !found { missing.append(item.titles[0] + (wantsKey.map { " \($0.display)" } ?? "")) }
            }
            check("\(entry.menu) menu has \(entry.brief)", missing.isEmpty, "missing \(missing)")
        }
    }

    /// Types `r` into the sidebar filter: the field gets the letter, nothing replays.
    private static func checkTypingIsNotAVerb(_ session: Session) async {
        NSApp.activate()
        guard let window = NSApp.windows.first(where: { $0.isVisible && !($0 is NSPanel) }) else {
            return check("a main window exists for the typing check", false)
        }
        window.makeKeyAndOrderFront(nil)
        session.sidebarFilterFocusTick += 1
        await settle { window.firstResponder is NSTextView }
        guard window.firstResponder is NSTextView else {
            return check("the sidebar filter takes focus", false, "first responder \(String(describing: window.firstResponder))")
        }
        let before = session.rows.count
        let event = NSEvent.keyEvent(with: .keyDown, location: .zero, modifierFlags: [], timestamp: ProcessInfo.processInfo.systemUptime,
                                     windowNumber: window.windowNumber, context: nil, characters: "r", charactersIgnoringModifiers: "r",
                                     isARepeat: false, keyCode: 15)
        if let event { window.sendEvent(event) }
        await settle(timeout: .seconds(1)) { session.sidebarQuery == "r" }
        check("typing r in the sidebar filter types, never replays", session.sidebarQuery == "r" && session.rows.count == before,
              "query '\(session.sidebarQuery)' rows \(session.rows.count) were \(before)")
        session.sidebarQuery = ""
        window.makeFirstResponder(nil)
    }

    /// Waits for an async action to land instead of sleeping a fixed time (the
    /// fixture actions hop through Tasks; under load a fixed sleep races them).
    static func settle(timeout: Duration = .seconds(5), until done: () -> Bool) async {
        let deadline = ContinuousClock.now + timeout
        while !done(), ContinuousClock.now < deadline {
            try? await Task.sleep(for: .milliseconds(25))
        }
    }

    static func check(_ name: String, _ ok: Bool, _ detail: String = "") {
        count += 1
        if !ok { failures += 1 }
        print(ok ? "PASS \(name)" : "FAIL \(name)\(detail.isEmpty ? "" : ": \(detail)")")
    }

    /// Quits through NSApp.terminate, never exit(), and closes sheets first.
    static func finish(code: Int32) {
        finished.withLock { $0 = true }
        exitCode = code
        for window in NSApp.windows { if let sheet = window.attachedSheet { window.endSheet(sheet) } }
        NSApp.terminate(nil)
    }
}
