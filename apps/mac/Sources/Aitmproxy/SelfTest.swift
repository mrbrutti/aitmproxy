import AitmproxyKit
import AppKit

/// Self-test for agents: drives the real session model on fixture data,
/// prints PASS or FAIL per check, and quits with exit code 0 or 1.
///   APP_STORE=/tmp/x ~/Applications/Aitmproxy.app/Contents/MacOS/Aitmproxy --selftest
/// (tools/selftest.sh does this.) Add a check for every story with logic.
@MainActor
enum SelfTest {
    static var requested: Bool { CommandLine.arguments.contains("--selftest") }
    /// Read by AppDelegate.applicationWillTerminate.
    static var exitCode: Int32 = 0
    private static var failures = 0
    private static var count = 0

    static func runIfRequested(session: Session) {
        guard requested else { return }
        setvbuf(stdout, nil, _IOLBF, 0)
        guard Store.isOverridden else {
            print("SELFTEST refused: set APP_STORE to a folder in /tmp")
            finish(code: 1)
            return
        }
        Task {
            try? await Task.sleep(for: .seconds(0.5))
            check("fixtures load 14 rows", session.rows.count == 14)
            check("two flows are paused", session.paused.count == 2)
            check("the paused login is selected", session.focusedRow?.seq == 50)
            check("the inspector has the login detail", session.focusedDetail?.request.header("x-forwarded-for") == "127.0.0.1")

            session.chip = .json
            check("the JSON chip narrows the list", session.visibleRows.count < session.rows.count && !session.visibleRows.isEmpty)
            session.chip = .websocket
            check("the WebSocket chip keeps only WS flows", session.visibleRows.allSatisfy { $0.kind == .websocket } && session.visibleRows.count == 1)
            session.chip = .all

            session.page = .scope
            check("Scope filters to in-scope flows", session.visibleRows.allSatisfy(\.inScope) && session.visibleRows.count == 13)
            session.page = .apps

            session.select(session.rows[0].id)
            check("selecting a row focuses the inspector", session.focusedRow?.seq == 41)
            session.interceptArmed = false
            check("disarming clears the armed state", !session.interceptArmed)

            // S-009: sorting never moves the selection; status puts rows without a code last.
            session.sort = FlowSort(key: .status, ascending: false)
            check("sorting by status puts 502 first and paused last",
                  session.visibleRows.first?.status == 502 && session.visibleRows.last?.state != .complete)
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
            check("the group header shows all flows again", session.visibleRows.count == 14)

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
            try? await Task.sleep(for: .milliseconds(50))
            check("pausing capture flips the state", !session.capturing)
            session.clearSession(confirm: { _ in true })
            try? await Task.sleep(for: .milliseconds(50))
            check("clearing empties the session", session.rows.isEmpty && session.focused == nil)

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
            check("a parse error reports an offset", session.filterError != nil && session.visibleRows.count == 14)
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
            check("every tool appears in the palette", session.paletteItems(for: "").filter { if case .command = $0.kind { return true }; return false }.count == Fixtures.tools.count)
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
                try? await Task.sleep(for: .milliseconds(50))
                check("Kill with Respond 503 shows the synthetic status", session.rows.first { $0.seq == 51 }?.status == 503)
            }
            session.killMode = .reset
            session.selection = Set(session.rows.filter { [41, 50].contains($0.seq) }.map(\.id))
            session.resumeSelected()
            check("bulk resume reports what it skipped", session.lastError == "Resumed 1 · skipped 1 (not paused)")
            try? await Task.sleep(for: .milliseconds(500))
            check("bulk resume resumed the paused row", session.rows.first { $0.seq == 50 }?.state == .complete)

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

            print(failures == 0 ? "SELFTEST PASS \(count) checks" : "SELFTEST FAIL \(failures) of \(count) checks")
            finish(code: failures == 0 ? 0 : 1)
        }
    }

    private static func check(_ name: String, _ ok: Bool, _ detail: String = "") {
        count += 1
        if !ok { failures += 1 }
        print(ok ? "PASS \(name)" : "FAIL \(name)\(detail.isEmpty ? "" : ": \(detail)")")
    }

    /// Quits through NSApp.terminate, never exit(), and closes sheets first.
    static func finish(code: Int32) {
        exitCode = code
        for window in NSApp.windows { if let sheet = window.attachedSheet { window.endSheet(sheet) } }
        NSApp.terminate(nil)
    }
}
