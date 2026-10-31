import AitmBusClient
import AitmproxyKit
import AppKit

/// The live self-test: with `APP_LIVE=1` and a running `aitm` (its config at
/// `AITM_CONFIG`), every `FlowActions` call goes over the real bus through
/// `BusService`, the path the fixture self-test never touches.
///   AITM_CONFIG=… APP_STORE=/tmp/x APP_LIVE=1 Aitmproxy --selftest   (tools/selftest-live.sh)
/// Commands the core lacks yet (F6 mark/comment, F7 pause/clear) must come
/// back as recorded errors, never as a hang or a crash.
extension SelfTest {
    static var live: Bool { ProcessInfo.processInfo.environment["APP_LIVE"] == "1" }

    static func runLive(session: Session) {
        let upstream = ProcessInfo.processInfo.environment["APP_LIVE_UPSTREAM"] ?? "127.0.0.1:8099"
        Task {
            print("LIVE self-test · config \(BusService.configURL.path) · upstream \(upstream)")
            await settle(timeout: .seconds(10)) { if case .connected = session.bus { return true } else { return false } }
            guard case .connected(let address) = session.bus else {
                check("bus connects", false, "\(session.bus)")
                return finishLive()
            }
            check("bus connects (\(address))", true)
            // tools/list lands a beat after the connected state.
            await settle { !session.tools.isEmpty }
            let names = session.tools.map(\.name).sorted()
            print("tools/list: \(names.joined(separator: " "))")
            check("tools/list has flow.intercept, flow.list, flow.get, request.send, scope.add",
                  ["flow.intercept", "flow.list", "flow.get", "request.send", "scope.add"].allSatisfy(names.contains))

            // scope.add through the actions seam; scope.list refreshes.
            session.addScope(upstream)
            await settle { session.scopeHosts.contains(upstream) }
            check("scope.add lands in scope.list", session.scopeHosts.contains(upstream), "scope \(session.scopeHosts) err \(session.lastError ?? "-")")

            // flow.intercept both ways: the call that recursed in b7d3163.
            session.arm(true)
            await settle { session.interceptArmed }
            check("flow.intercept {enabled: true} arms", session.interceptArmed && session.lastError == nil, session.lastError ?? "")
            session.arm(false)
            await settle { !session.interceptArmed }
            check("flow.intercept {enabled: false} disarms", !session.interceptArmed && session.lastError == nil, session.lastError ?? "")

            // request.send → a flow the poll picks up with flow.list + flow.get.
            let before = session.rows.count
            session.composeDraft = ComposeDraft(method: "GET", url: "http://\(upstream)/")
            var sent: Bool?
            session.sendCompose { sent = $0 }
            await settle(timeout: .seconds(10)) { sent != nil && session.rows.count > before }
            check("request.send creates a flow that flow.list / flow.get show", sent == true && session.rows.count > before,
                  "sent \(sent.map(String.init) ?? "nil") rows \(session.rows.count) was \(before) err \(session.lastError ?? "-")")
            guard let row = session.rows.last else { return finishLive() }
            await settle(timeout: .seconds(5)) { session.rows.first { $0.id == row.id }?.status != nil }
            let status = session.rows.first { $0.id == row.id }?.status
            check("the sent flow completes with a status (\(status.map(String.init) ?? "none"))", status != nil)

            // F5: flow.detail returns the FULL request/response — the content the
            // operator reviews and edits. This is the gap the summary-only flow.get left.
            check("tools/list has flow.detail (F5)", names.contains("flow.detail"))
            await session.loadDetail(row.id)
            if let det = session.details[row.id] {
                // request.send carries no headers of its own; the request line must be there.
                check("flow.detail returns the request line", det.request.startLine.contains("/"), det.request.startLine)
                check("flow.detail returns the response with a body to review",
                      det.response != nil && (det.response?.body?.isEmpty == false),
                      "resp \(det.response?.startLine ?? "nil") bytes \(det.response?.body?.count ?? -1)")
            } else {
                check("flow.detail returned a detail for review", false, "no detail; err \(session.lastError ?? "-")")
            }

            // flow.replay adds a flow and selects it.
            let count = session.rows.count
            session.replay(row.id)
            await settle(timeout: .seconds(10)) { session.rows.count > count }
            check("flow.replay adds a flow and selects it", session.rows.count > count && session.lastError == nil && session.focused != row.id,
                  "rows \(session.rows.count) was \(count) focused \(session.focused?.raw ?? "-") err \(session.lastError ?? "-")")

            // Armed: a real client (curl through the proxy) parks; resume one, kill one.
            // The proxy's own request.send client is not intercepted, so curl it is.
            session.arm(true)
            await settle { session.interceptArmed }
            if let curl1 = curlThroughProxy(upstream, listen: session.listenAddress) {
                await settle(timeout: .seconds(6)) { !session.paused.isEmpty }
                if let parked = session.paused.first {
                    // F5 + edit path: the parked request's full content (line + the client's
                    // real headers) is available to review and edit — a real curl sends headers.
                    await session.loadDetail(parked.id)
                    let pd = session.details[parked.id]
                    check("a parked request exposes its line + headers for editing (flow.detail)",
                          pd?.request.startLine.contains("/") == true && pd?.request.headers.isEmpty == false,
                          "detail \(pd?.request.startLine ?? "nil") headers \(pd?.request.headers.count ?? -1)")
                    session.resume(parked.id)
                    await settle(timeout: .seconds(6)) { !session.paused.contains { $0.id == parked.id } && !curl1.isRunning }
                    check("flow.resume releases a parked flow and the client gets its response",
                          !session.paused.contains { $0.id == parked.id } && !curl1.isRunning && curl1.terminationStatus == 0 && session.lastError == nil,
                          "paused \(session.paused.count) curl running \(curl1.isRunning) exit \(curl1.terminationStatus) err \(session.lastError ?? "-")")
                } else {
                    check("a request through the armed proxy parks", false, "rows \(session.rows.count) paused 0; curl running \(curl1.isRunning)")
                    curl1.terminate()
                }
                if let curl2 = curlThroughProxy(upstream, listen: session.listenAddress) {
                    await settle(timeout: .seconds(6)) { !session.paused.isEmpty }
                    if let parked = session.paused.first {
                        session.kill(parked.id)
                        await settle(timeout: .seconds(6)) { !session.paused.contains { $0.id == parked.id } && !curl2.isRunning }
                        let state = session.rows.first { $0.id == parked.id }?.state
                        check("flow.kill is accepted and releases the parked flow",
                              !session.paused.contains { $0.id == parked.id } && !curl2.isRunning && session.lastError == nil,
                              "paused \(session.paused.count) curl running \(curl2.isRunning) err \(session.lastError ?? "-")")
                        // Core gap (2026-10-28): the chain wakes on the same oneshot for kill and
                        // resume and marks the flow Resumed, so the request is forwarded and the
                        // client gets its 2xx. Reported to the core; strict when APP_LIVE_STRICT=1.
                        let aborted = curl2.terminationStatus != 0 && state != .complete
                        if ProcessInfo.processInfo.environment["APP_LIVE_STRICT"] == "1" {
                            check("flow.kill denies the client a response (curl exit \(curl2.terminationStatus), row \(state.map { "\($0)" } ?? "gone"))", aborted)
                        } else if !aborted {
                            print("GAP core flow.kill forwarded the request like resume (curl exit \(curl2.terminationStatus), row \(state.map { "\($0)" } ?? "gone")); APP_LIVE_STRICT=1 fails on this")
                        }
                    } else {
                        check("a second request through the armed proxy parks", false, "paused 0")
                        curl2.terminate()
                    }
                }
            } else {
                print("SKIP flow.resume / flow.kill: /usr/bin/curl could not start")
            }
            session.arm(false)
            await settle { !session.interceptArmed }

            // F6 / F7: the call is made, the outcome is recorded, nothing hangs.
            let pending: [(String, () -> Void)] = [
                ("flow.mark", { session.mark(row.id, .red) }),
                ("flow.comment", { session.comment(row.id, "live self-test") }),
                ("proxy.pause", { session.setCapturing(false) }),
                ("flow.clear", { session.clearSession() }),
            ]
            for (name, act) in pending {
                act()
                await settle(timeout: .seconds(5)) { session.activity.entries.contains { $0.command == name } }
                let entry = session.activity.entries.last { $0.command == name }
                let outcome = entry.map { $0.result == .ok ? "ok" : $0.result.text + (names.contains(name) ? "" : ", not on the bus yet") } ?? "not recorded"
                check("\(name) reaches the bus and is recorded (\(outcome))", entry != nil, session.lastError ?? "")
            }
            if !session.capturing { session.setCapturing(true) }

            // D2 on a live bus: an undone Clear survives the poll (the core has dropped the flows;
            // the app keeps its copy ahead of the core's list for at least four 500 ms polls).
            if names.contains("flow.clear") {
                await settle(timeout: .seconds(5)) { session.rows.isEmpty && session.clearNotice != nil }
                let cleared = session.clearedFlows?.rows.map(\.id) ?? []
                check("flow.clear empties the list and offers Undo Clear (\(cleared.count) flows)",
                      session.rows.isEmpty && !cleared.isEmpty && session.flowUndoManager.canUndo, session.lastError ?? "")
                session.flowUndoManager.undo()
                // Four of BusService's 500 ms polls.
                try? await Task.sleep(for: .seconds(2))
                let present = cleared.filter { id in session.rows.contains { $0.id == id } }
                check("Undo Clear puts the \(cleared.count) flows back and they survive four polls (\(present.count) present)",
                      !cleared.isEmpty && present.count == cleared.count, "rows \(session.rows.map(\.seq))")
                session.forgetClearedFlows()
            } else {
                print("SKIP Undo Clear: flow.clear not on the bus")
            }

            let recorded = session.activity.entries.filter { $0.origin == .operator }.count
            check("every action is in the activity log (\(recorded) operator entries)", recorded >= 11)

            checkHumanInputPath(session)
            finishLive()
        }
    }

    /// The human-input path (keyboard + the real menu bar), NOT the MCP bus: a
    /// real key equivalent dispatched through `NSApp.mainMenu` must drive the UI,
    /// proving an operator can work the app directly. Pixel-level mouse
    /// computer-use (clicking rendered rows) needs a CUA harness and is out of a
    /// headless self-test; the menu audit (checkMenuCoverage) proves every action
    /// is reachable, and this proves the keyboard actually dispatches one.
    private static func checkHumanInputPath(_ session: Session) {
        guard let menu = NSApp.mainMenu,
              let window = NSApp.windows.first(where: { $0.isVisible && !($0 is NSPanel) }) else {
            return check("a main window exists for the human-input check", false)
        }
        window.makeKeyAndOrderFront(nil)
        let before = session.paletteVisible
        // ⌘K = View ▸ Command Palette. Dispatched as a real key equivalent through the menu.
        if let event = NSEvent.keyEvent(with: .keyDown, location: .zero, modifierFlags: .command,
                                        timestamp: ProcessInfo.processInfo.systemUptime, windowNumber: window.windowNumber,
                                        context: nil, characters: "k", charactersIgnoringModifiers: "k",
                                        isARepeat: false, keyCode: 40) {
            _ = menu.performKeyEquivalent(with: event)
        }
        check("a real menu key equivalent (⌘K) drives the UI from the keyboard, not the bus",
              session.paletteVisible != before, "palette \(session.paletteVisible) was \(before)")
        session.paletteVisible = false
    }

    /// `curl -x <listen> http://<upstream>/`, left running: while intercept is
    /// armed it sits parked until the test resumes or kills its flow.
    private static func curlThroughProxy(_ upstream: String, listen: String) -> Process? {
        let curl = Process()
        curl.executableURL = URL(fileURLWithPath: "/usr/bin/curl")
        // -f: an HTTP error page counts as failure too, so a killed flow never exits 0.
        curl.arguments = ["-sf", "-o", "/dev/null", "--max-time", "20", "-x", "http://\(listen)", "http://\(upstream)/"]
        curl.standardError = FileHandle.nullDevice
        do {
            try curl.run()
            return curl
        } catch {
            return nil
        }
    }

    private static func finishLive() {
        print(failures == 0 ? "LIVE SELFTEST PASS \(count) checks" : "LIVE SELFTEST FAIL \(failures) of \(count) checks")
        finish(code: failures == 0 ? 0 : 1)
    }
}
