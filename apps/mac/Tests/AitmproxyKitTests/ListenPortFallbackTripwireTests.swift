import Foundation
import Testing

/// Tripwire on the app surfaces of the listen-port fallback notice (spec
/// `docs/superpowers/specs/2026-11-03-mac-listen-port-fallback-notice-design.md`, D9): a source pin
/// that Settings ▸ Proxy, the toolbar pill, the Flows empty state and the `proxy.status` poll read the
/// Kit fact (`ListenPortFallback`, `ConnectionSummary.coreAddressShown`, `Session.effectiveListenAddress`)
/// and spell none of its words themselves; the live proof (spec D10) is the behaviour test.
@Suite struct ListenPortFallbackTripwireTests {
    /// `apps/mac`: test file → `AitmproxyKitTests` → `Tests` → `apps/mac`.
    static let macRoot = URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()

    static func text(_ relativePath: String) throws -> String {
        try String(contentsOf: macRoot.appending(path: relativePath), encoding: .utf8)
    }

    @Test func settingsProxyPrintsTheKitWordsAndOffersTheRestart() throws {
        let settings = try Self.text("Sources/Aitmproxy/SettingsView.swift")
        #expect(settings.contains("portFallback"))
        #expect(settings.contains("restartTitle"))
        // Spec D5: the bare row is gone and the view composes no words of its own.
        #expect(!settings.contains("\"Bound address\""))
        #expect(!settings.contains("\"Port "))
        #expect(!settings.contains("was busy"))
        // Spec D5, the footnote's last sentence.
        #expect(!settings.contains("shown above as the bound address"))
        #expect(settings.contains("picks a free one and says so above."))
    }

    @Test func theToolbarPillReadsCoreAddressShown() throws {
        let toolbar = try Self.text("Sources/Aitmproxy/Shell/ShellToolbar.swift")
        #expect(toolbar.contains("coreAddressShown"))
        // Spec D4: the replaced condition must not survive beside the new one.
        #expect(!toolbar.contains("summary.core.state == .ok"))
        #expect(!toolbar.contains("\"Port "))
        #expect(!toolbar.contains("was busy"))
    }

    @Test func theFlowsEmptyStateQuotesTheEffectiveAddress() throws {
        let shell = try Self.text("Sources/Aitmproxy/Shell/ShellView.swift")
        #expect(shell.contains("listen: session.effectiveListenAddress"))
        #expect(!shell.contains("listen: session.listenAddress"))
    }

    @Test func theProxyStatusPollWritesTheBoundAddress() throws {
        let bus = try Self.text("Sources/Aitmproxy/Bus/BusService.swift")
        #expect(bus.contains("status[\"address\"]"))
    }
}
