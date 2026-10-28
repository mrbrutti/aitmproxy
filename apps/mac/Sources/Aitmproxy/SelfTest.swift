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
