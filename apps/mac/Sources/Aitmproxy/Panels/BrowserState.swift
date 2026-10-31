import AitmBusClient
import AitmproxyKit
import AppKit
import Foundation
import Observation
import UniformTypeIdentifiers

/// One page in the Browser view. The core drives a single obscura page until
/// F14 brings tabs, so these are the app's own; the active tab is the page.
struct BrowserTab: Identifiable, Hashable {
    var id = UUID()
    var title: String
    var url: String
    var lastFrame: Data?
    var isLoading = false
    /// The page's history as this app has driven it: how many entries, and
    /// which one is showing. Back / Forward enable from these.
    var historyCount = 0
    var historyIndex = 0

    var canGoBack: Bool { historyIndex > 0 }
    var canGoForward: Bool { historyIndex < historyCount - 1 }

    /// A new navigation drops any forward entries and becomes the latest.
    mutating func pushHistory() {
        if historyCount == 0 {
            historyIndex = 0
            historyCount = 1
        } else {
            historyIndex += 1
            historyCount = historyIndex + 1
        }
    }
}

/// The Browser view's state (S-054, S-055): tabs, the live frame stream,
/// the console and the DOM outline, every action a `browser.*` command.
@Observable
final class BrowserState {
    unowned let session: Session
    var tabs: [BrowserTab] = []
    var currentID: UUID?
    var consoleLines: [String] = []
    var domOutline: [String] = []
    var consoleVisible = false
    var domVisible = false
    /// The URL field's text; follows the tab, then the operator's typing.
    var urlText = ""
    /// Bumped by `newTab()` so the URL field takes focus.
    var urlFocusTick = 0
    /// True while frames are being polled.
    private(set) var live = false
    /// Frames per second over the last ten arrivals.
    private(set) var fps: Double = 0
    /// True when the last screenshot failed: the chip reads "Paused".
    private(set) var stalled = false
    @ObservationIgnored private var liveTask: Task<Void, Never>?
    @ObservationIgnored private var frameTimes: [Date] = []

    /// 500 ms between `browser.screenshot`s until `browser.screencast` (F14) streams.
    static let liveInterval: Duration = .milliseconds(500)

    init(session: Session) {
        self.session = session
        if Store.usesFixtures {
            let page = Fixtures.browserPage
            var tab = BrowserTab(title: page.title, url: page.url, lastFrame: page.png)
            tab.pushHistory()
            tabs = [tab]
            currentID = tab.id
            urlText = page.url
            domOutline = Fixtures.domOutline
        }
        syncCount()
    }

    var current: BrowserTab? {
        get { tabs.first { $0.id == currentID } }
        set {
            guard let newValue, let index = tabs.firstIndex(where: { $0.id == newValue.id }) else { return }
            tabs[index] = newValue
        }
    }

    /// The bus is connected, or fixtures stand in for it.
    var available: Bool {
        if Store.usesFixtures { return true }
        if case .connected = session.bus { return true }
        return false
    }

    var liveChipText: String {
        guard live, !stalled, current?.lastFrame != nil else { return "Paused" }
        return "Live · \(fps < 0.95 ? String(format: "%.1f", fps) : String(Int(fps.rounded()))) fps"
    }

    // MARK: Tabs

    func newTab() {
        let tab = BrowserTab(title: "New Tab", url: "")
        tabs.append(tab)
        select(tab.id)
        urlFocusTick += 1
        syncCount()
    }

    func select(_ id: UUID) {
        currentID = id
        urlText = current?.url ?? ""
    }

    func close(_ id: UUID) {
        guard let index = tabs.firstIndex(where: { $0.id == id }) else { return }
        tabs.remove(at: index)
        if currentID == id {
            let next = tabs.indices.contains(index) ? tabs[index] : tabs.last
            currentID = next?.id
            urlText = next?.url ?? ""
        }
        if tabs.isEmpty { stopLive() }
        syncCount()
    }

    private func syncCount() { session.browserTabs = tabs.count }

    // MARK: Navigation

    /// `browser.navigate {url}`; a bare host gets `https://`.
    func navigate(_ raw: String) async {
        let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return }
        let url = trimmed.contains("://") ? trimmed : "https://" + trimmed
        if current == nil { newTab() }
        guard var tab = current else { return }
        tab.isLoading = true
        tab.url = url
        current = tab
        urlText = url
        defer { if var done = current { done.isLoading = false; current = done } }
        if Store.usesFixtures {
            tab.title = URL(string: url)?.host() ?? url
            tab.pushHistory()
            current = tab
            consoleLines.append("navigate \(url) → 200 (fixture)")
            return
        }
        do {
            let outcome = try await session.runCommand("browser.navigate", ["url": .string(url)])
            let finalURL = outcome["final_url"]?.stringValue ?? url
            tab.url = finalURL
            tab.title = URL(string: finalURL)?.host() ?? finalURL
            tab.pushHistory()
            current = tab
            urlText = finalURL
            if let status = outcome["status"]?.intValue { consoleLines.append("navigate \(finalURL) → \(status)") }
            _ = await screenshot()
        } catch {
            fail("navigate", error)
        }
    }

    // Until F14 adds history commands, back/forward/reload go through `browser.eval`;
    // the tab's own history depth moves with them so the buttons enable honestly.
    func back() async {
        guard let tab = current, tab.canGoBack else { return }
        // The index moves only once the page did, so a failed eval leaves the buttons honest.
        guard await evalQuietly("history.back()"), var moved = current else { return }
        moved.historyIndex -= 1
        current = moved
        await syncLocation(pushing: false)
    }

    func forward() async {
        guard let tab = current, tab.canGoForward else { return }
        guard await evalQuietly("history.forward()"), var moved = current else { return }
        moved.historyIndex += 1
        current = moved
        await syncLocation(pushing: false)
    }

    func reload() async { _ = await evalQuietly("location.reload()") }

    /// True when the expression ran on the page.
    @discardableResult
    private func evalQuietly(_ expr: String) async -> Bool {
        guard !Store.usesFixtures else { consoleLines.append("› \(expr)"); return true }
        do {
            _ = try await session.runCommand("browser.eval", ["expr": .string(expr)])
            _ = await screenshot()
            return true
        } catch {
            fail("browser", error)
            return false
        }
    }

    /// A click, a keystroke or an eval can navigate the page (a link, a form, `location = …`).
    /// Read where the page is now; when it moved, the tab follows and, unless the move was
    /// our own back/forward, it is a new history entry so Back/Forward stay truthful.
    private func syncLocation(pushing: Bool = true) async {
        guard !Store.usesFixtures, var tab = current else { return }
        guard let href = try? await session.runCommand("browser.eval", ["expr": .string("location.href")]).stringValue,
              !href.isEmpty, href != tab.url else { return }
        tab.url = href
        tab.title = URL(string: href)?.host() ?? href
        if pushing { tab.pushHistory() }
        current = tab
        urlText = href
    }

    // MARK: Frames

    /// `browser.screenshot` → PNG bytes (base64 over the bus); stores the frame and the arrival time.
    @discardableResult
    func screenshot() async -> Data? {
        guard let tab = current else { return nil }
        if Store.usesFixtures {
            noteFrame()
            return tab.lastFrame
        }
        do {
            let value = try await session.runCommand("browser.screenshot", [:])
            guard let text = value.stringValue, let data = Data(base64Encoded: text) else {
                stalled = true
                return nil
            }
            if var updated = current, updated.id == tab.id {
                updated.lastFrame = data
                current = updated
            }
            noteFrame()
            return data
        } catch {
            stalled = true
            if !live { fail("screenshot", error) }
            return nil
        }
    }

    private func noteFrame() {
        stalled = false
        let now = Date()
        frameTimes.append(now)
        if frameTimes.count > 10 { frameTimes.removeFirst(frameTimes.count - 10) }
        if frameTimes.count >= 2, let first = frameTimes.first {
            let span = now.timeIntervalSince(first)
            fps = span > 0 ? Double(frameTimes.count - 1) / span : 0
        }
    }

    func startLive() {
        guard liveTask == nil, available else { return }
        live = true
        liveTask = Task { [weak self] in
            while !Task.isCancelled {
                _ = await self?.screenshot()
                try? await Task.sleep(for: Self.liveInterval)
            }
        }
    }

    func stopLive() {
        liveTask?.cancel()
        liveTask = nil
        live = false
        fps = 0
        frameTimes.removeAll()
    }

    /// Writes the current frame as PNG where the operator chooses.
    func saveScreenshot() {
        guard let data = current?.lastFrame else { return }
        let panel = NSSavePanel()
        panel.nameFieldStringValue = "\(current?.title ?? "page").png"
        panel.allowedContentTypes = [.png]
        guard panel.runModal() == .OK, let url = panel.url else { return }
        do { try data.write(to: url) } catch { session.lastError = "save screenshot: \(error.localizedDescription)" }
    }

    // MARK: Input relay

    /// `browser.click {x, y}` in page pixels; `point` is already in the frame's pixel space.
    func click(at point: CGPoint, imageSize: CGSize) async {
        guard imageSize.width > 0, imageSize.height > 0 else { return }
        let x = min(max(point.x, 0), imageSize.width), y = min(max(point.y, 0), imageSize.height)
        if Store.usesFixtures { consoleLines.append("click (\(Int(x)), \(Int(y)))"); return }
        do {
            _ = try await session.runCommand("browser.click", ["x": .number(Double(x)), "y": .number(Double(y))])
            _ = await screenshot()
            await syncLocation()
        } catch {
            fail("click", error)
        }
    }

    /// `browser.type` needs a selector: the focused element (`:focus`) is where a keystroke goes.
    func type(_ text: String) async {
        guard !text.isEmpty else { return }
        if Store.usesFixtures { consoleLines.append("type \(text.debugDescription)"); return }
        do {
            _ = try await session.runCommand("browser.type", ["selector": ":focus", "text": .string(text)])
            _ = await screenshot()
            await syncLocation()
        } catch {
            fail("type", error)
        }
    }

    /// `browser.eval {expr}` → the console: the expression, then its value.
    func eval(_ expr: String) async {
        let trimmed = expr.trimmingCharacters(in: .whitespaces)
        guard !trimmed.isEmpty else { return }
        consoleLines.append("› \(trimmed)")
        if Store.usesFixtures { consoleLines.append(trimmed); return }
        do {
            let value = try await session.runCommand("browser.eval", ["expr": .string(trimmed)])
            consoleLines.append(value.stringValue ?? value.serialized())
            await syncLocation()
        } catch {
            consoleLines.append("✕ \(BusService.describe(error))")
        }
    }

    /// `browser.get_dom` → an indented outline of the page's elements.
    func dom() async {
        if Store.usesFixtures { domOutline = Fixtures.domOutline; return }
        do {
            let html = try await session.runCommand("browser.get_dom", [:]).stringValue ?? ""
            domOutline = DOMOutline.lines(from: html)
        } catch {
            fail("get_dom", error)
        }
    }

    private func fail(_ what: String, _ error: Error) {
        session.lastError = "browser \(what): \(BusService.describe(error))"
    }
}

/// Turns outer HTML into one line per element, indented by depth: tag, id,
/// classes, a few attributes, then the first words of its own text.
enum DOMOutline {
    private static let voidTags: Set<String> = ["area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "source", "track", "wbr"]

    static func lines(from html: String, maxLines: Int = 2000) -> [String] {
        var lines: [String] = []
        var depth = 0
        var rest = Substring(html)
        while let open = rest.firstIndex(of: "<"), lines.count < maxLines {
            let text = rest[rest.startIndex..<open].trimmingCharacters(in: .whitespacesAndNewlines)
            if !text.isEmpty, let last = lines.indices.last { lines[last] += "  " + text.split(separator: " ").prefix(8).joined(separator: " ") }
            guard let close = rest[open...].firstIndex(of: ">") else { break }
            let tag = rest[rest.index(after: open)..<close]
            rest = rest[rest.index(after: close)...]
            if tag.hasPrefix("!") || tag.hasPrefix("?") { continue }
            if tag.hasPrefix("/") { depth = max(depth - 1, 0); continue }
            let parts = tag.split(separator: " ", maxSplits: 1, omittingEmptySubsequences: true)
            let name = parts.first.map { String($0).lowercased() } ?? ""
            var attrs = parts.count > 1 ? String(parts[1]) : ""
            let selfClosing = attrs.hasSuffix("/")
            if selfClosing { attrs.removeLast() }
            lines.append(String(repeating: "  ", count: depth) + name + describe(attrs))
            if !selfClosing, !voidTags.contains(name) { depth += 1 }
            if name == "script" || name == "style", let end = rest.range(of: "</\(name)", options: .caseInsensitive) {
                rest = rest[end.lowerBound...]
            }
        }
        return lines
    }

    /// `#id.class1.class2 href="/" type="submit"` from the tag's attribute text.
    private static func describe(_ attrs: String) -> String {
        var id = "", classes = "", others: [String] = []
        for pair in attrs.split(separator: "\" ", omittingEmptySubsequences: true) {
            let kv = pair.split(separator: "=", maxSplits: 1).map { $0.trimmingCharacters(in: CharacterSet(charactersIn: " \"")) }
            guard kv.count == 2 else { if !kv.isEmpty, !kv[0].isEmpty { others.append(kv[0]) }; continue }
            switch kv[0] {
            case "id": id = "#" + kv[1]
            case "class": classes = kv[1].split(separator: " ").map { "." + $0 }.joined()
            case "href", "src", "name", "type", "action", "method", "rel", "lang": others.append("\(kv[0])=\"\(kv[1])\"")
            default: break
            }
        }
        return id + classes + (others.isEmpty ? "" : " " + others.prefix(3).joined(separator: " "))
    }
}
