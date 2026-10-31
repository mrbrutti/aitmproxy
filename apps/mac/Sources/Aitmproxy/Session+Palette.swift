import AitmBusClient
import AitmproxyKit
import AppKit

/// Palette (S-035, S-036): bus commands, local actions and recent items.
extension Session {
    func runCommand(_ name: String, _ args: [String: JSONValue]) async throws -> JSONValue {
        guard let commandRunner else { throw BusError.disconnected }
        do {
            let value = try await commandRunner(name, args)
            commandRecorder?(name, args, nil)
            return value
        } catch {
            commandRecorder?(name, args, BusService.describe(error))
            throw error
        }
    }

    func rememberPaletteUse(_ item: PaletteItem) {
        recentPaletteIDs.removeAll { $0 == item.id }
        recentPaletteIDs.insert(item.id, at: 0)
        recentPaletteIDs = Array(recentPaletteIDs.prefix(5))
        if !Store.isOverridden { UserDefaults.standard.set(recentPaletteIDs, forKey: "palette.recent") }
    }

    func paletteItems(for query: String) -> [PaletteItem] {
        var all: [PaletteItem] = []
        for tool in tools {
            all.append(PaletteItem(id: "cmd:\(tool.name)", section: .commands, title: tool.name, subtitle: tool.description,
                                   shortcut: nil, method: nil, kind: .command(tool)))
        }
        let locals: [(String, String, String?, () -> Void)] = [
            (interceptArmed ? "Disarm Intercept" : "Arm Intercept", "Stop or start parking every request", "i", { [self] in arm(!interceptArmed) }),
            ("Compose Request…", "Write and send a new request", "⌘N", { [self] in openCompose() }),
            (capturing ? "Pause Capture" : "Resume Capture", "Stop or start recording flows", "⇧⌘R", { [self] in setCapturing(!capturing) }),
            ("Clear Session", "Drop every flow", "⌘⌫", { [self] in clearSession(confirm: ClearConfirmation.ask) }),
            (autoSelect ? "Stop Auto-select" : "Auto-select New Flows", "Follow the newest flow as it arrives", "⇧⌘A", { [self] in autoSelect.toggle() }),
            ("Filter Bar", "Stack filters over the list", "⌘F", { [self] in filterBarVisible.toggle() }),
            ("Inspector Below", "Horizontal layout", "⌥⌘1", { [self] in layout = .horizontal }),
            ("Inspector Right", "Vertical layout", "⌥⌘2", { [self] in layout = .vertical }),
            ("Inspector Detached", "The inspector in its own window", "⌥⌘3", { [self] in layout = .detached }),
            (splitView ? "Single List" : "Split View", "Two lists over one capture", "⌥⌘4", { [self] in splitView.toggle() }),
        ]
        for (title, subtitle, shortcut, action) in locals {
            all.append(PaletteItem(id: "local:\(title)", section: .local, title: title, subtitle: subtitle, shortcut: shortcut, method: nil, kind: .local(action)))
        }
        var setup: [(String, String, () -> Void)] = [
            ("Certificate Authority…", "Status, export, install the proxy's CA", { [self] in show(.ca) }),
            ("Configuration…", "The proxy's effective config", { [self] in show(.config) }),
            ("Overview", "Session statistics", { [self] in show(.overview) }),
            ("Connection Log", "CONNECTs, TLS, ALPN, SNI", { [self] in show(.connections) }),
            ("Activity Log", "Every command from every frontend", { [self] in activityLogVisible.toggle() }),
            ("Add Host to Scope…", "Authorise a host for testing", { [self] in scopeSheetVisible = true }),
            ("Open Browser", "Show the embedded browser", { [self] in show(.browser) }),
        ]
        // Offered only when the core lists scan.discover; opening the page never scans.
        if scanEnabled {
            setup.append(("Scan…", "Crawl an in-scope target for endpoints and injection points", { [self] in show(.scan) }))
        }
        for (title, subtitle, action) in setup {
            all.append(PaletteItem(id: "setup:\(title)", section: .setup, title: title, subtitle: subtitle, shortcut: nil, method: nil, kind: .local(action)))
        }
        for saved in savedFilters {
            all.append(PaletteItem(id: "filter:\(saved.id)", section: .filters, title: "Filter: \(saved.name)", subtitle: saved.expression,
                                   shortcut: nil, method: nil, kind: .savedFilter(saved)))
        }
        if !query.isEmpty {
            for row in rows {
                all.append(PaletteItem(id: "flow:\(row.id.raw)", section: .flows, title: row.url,
                                       subtitle: "\(row.status.map(String.init) ?? (row.state == .paused ? "paused" : "—")) · \(row.client?.name ?? "")",
                                       shortcut: nil, method: row.method, kind: .flow(row.id)))
            }
        }
        let trimmed = query.trimmingCharacters(in: .whitespaces)
        var ranked: [(PaletteItem, Int)] = all.compactMap { item in
            if trimmed.isEmpty { return (item, 1) }
            let score = Fuzzy.score(trimmed, name: item.title, description: item.subtitle)
            return score > 0 ? (item, score) : nil
        }
        // Recent on top (only when nothing is typed), then by score within section order.
        if trimmed.isEmpty {
            let recent = ranked.filter { recentPaletteIDs.contains($0.0.id) }.map { item, score -> (PaletteItem, Int) in
                var r = item; r.section = .recent; r.id = "recent:" + item.id; return (r, score)
            }
            ranked = recent.sorted { recentPaletteIDs.firstIndex(of: String($0.0.id.dropFirst(7))) ?? 0 < recentPaletteIDs.firstIndex(of: String($1.0.id.dropFirst(7))) ?? 0 } + ranked
        }
        let order = PaletteSection.allCases
        // A literal hit on the title (a URL containing "shop", a verb containing "repl") outranks
        // a fuzzy subsequence hit from another section, so typing a host surfaces its flows
        // before commands whose descriptions happen to spell the letters.
        func literal(_ item: PaletteItem) -> Bool {
            !trimmed.isEmpty && item.title.localizedCaseInsensitiveContains(trimmed)
        }
        return ranked
            .sorted { a, b in
                let la = literal(a.0), lb = literal(b.0)
                if la != lb { return la }
                let sa = order.firstIndex(of: a.0.section) ?? 0, sb = order.firstIndex(of: b.0.section) ?? 0
                return sa == sb ? a.1 > b.1 : sa < sb
            }
            .prefix(60).map(\.0)
    }
}
