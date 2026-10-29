import AitmBusClient
import AitmproxyKit
import AppKit
import UniformTypeIdentifiers

/// Import by drop or File ▸ Import… (⌘O) and File ▸ Export Selection… (⌘E)
/// (S-065). Until the proxy takes `flow.import` / `flow.export` (F10), HAR is
/// read and written here; other formats are refused by name.
extension Session {
    /// File ▸ Import… (⌘O): an open panel for the formats the app knows.
    func chooseImport() {
        let panel = NSOpenPanel()
        panel.allowsMultipleSelection = true
        panel.canChooseDirectories = false
        panel.allowedContentTypes = Self.importTypes
        panel.message = "Import flows from a HAR file (mitmproxy, Proxyman and Charles files need the proxy, F10)."
        guard panel.runModal() == .OK else { return }
        importFiles(panel.urls)
    }

    static var importTypes: [UTType] {
        [UTType(filenameExtension: "har"), .json, UTType(filenameExtension: "mitm"), UTType(filenameExtension: "proxymanlog"),
         UTType(filenameExtension: "chlz"), UTType(filenameExtension: "chls")].compactMap { $0 }
    }

    /// Each file in turn; the first refusal shows as an alert and stops the batch.
    func importFiles(_ urls: [URL]) {
        for url in urls {
            if !importFile(url) { return }
        }
    }

    /// True when the file was taken in (or handed to the proxy).
    @discardableResult
    func importFile(_ url: URL) -> Bool {
        let name = url.lastPathComponent
        guard let data = try? Data(contentsOf: url) else {
            refuse("Can't import \(name): the file could not be read.")
            return false
        }
        if tools.contains(where: { $0.name == "flow.import" }) {
            perform("import") { [self] in _ = try await runCommand("flow.import", ["path": .string(url.path)]) }
            return true
        }
        do {
            let flows = try FlowTransfer.importFile(name: name, data: data, firstSeq: (rows.map(\.seq).max() ?? 0) + 1)
            importFlows(flows)
            lastError = nil
            return true
        } catch {
            refuse(error.message)
            return false
        }
    }

    /// Appends imported flows to the capture (local, before F10), in scope when their host is.
    func importFlows(_ flows: [(FlowRow, FlowDetail)]) {
        for (row, detail) in flows {
            var row = row
            row.inScope = scopeHosts.contains { Scope.matches(row.authority, $0) }
            rows.append(row)
            details[row.id] = detail
        }
        if let last = flows.last { select(last.0.id) }
    }

    private func refuse(_ message: String) {
        lastError = message
        guard !Store.usesFixtures else { return }
        let alert = NSAlert()
        alert.messageText = "Import failed"
        alert.informativeText = message
        alert.alertStyle = .warning
        alert.addButton(withTitle: "OK")
        alert.runModal()
    }

    /// File ▸ Export Selection… ▸ format: the selection, else the focused row, else every visible row.
    var exportRows: [FlowRow] {
        if selection.count > 1 { return selectedRows }
        if let focusedRow { return [focusedRow] }
        return visibleRows
    }

    func exportSelection(as format: ExportFormat) {
        let chosen = exportRows
        guard !chosen.isEmpty else { return }
        if tools.contains(where: { $0.name == "flow.export" }) {
            let ids: JSONValue = .array(chosen.map { .string($0.id.raw) })
            perform("export") { [self] in _ = try await runCommand("flow.export", ["ids": ids, "format": .string(format.rawValue)]) }
            return
        }
        let text = FlowTransfer.export(chosen.map { ($0, details[$0.id]) }, as: format)
        let panel = NSSavePanel()
        panel.nameFieldStringValue = FlowTransfer.suggestedFilename(format)
        panel.allowedContentTypes = [UTType(filenameExtension: format.fileExtension) ?? .data]
        panel.canCreateDirectories = true
        guard panel.runModal() == .OK, let url = panel.url else { return }
        do {
            try text.write(to: url, atomically: true, encoding: .utf8)
            lastError = nil
        } catch {
            lastError = "export: \(error.localizedDescription)"
        }
    }
}
