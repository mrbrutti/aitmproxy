import AitmproxyKit
import Quartz
import UniformTypeIdentifiers

/// Quick Look of the focused flow's body (S-010 Space; Flow ▸ Quick Look
/// Body). The body is written to a temp file named after the flow, with the
/// extension its content type implies, so the panel's title and renderer fit.
/// The list (`FlowKeyTable`) is the panel's controller: Space toggles it.
final class BodyQuickLook: NSObject, QLPreviewPanelDataSource, QLPreviewPanelDelegate {
    static let shared = BodyQuickLook()
    private(set) var url: URL?
    private let folder = FileManager.default.temporaryDirectory.appending(path: "Aitmproxy-quicklook")

    /// Writes the response body (the request's when there is no response).
    /// False when there is nothing to show.
    @discardableResult
    func prepare(_ detail: FlowDetail, row: FlowRow) -> Bool {
        let message = detail.response ?? detail.request
        guard let body = message.body, !body.isEmpty else {
            url = nil
            return false
        }
        let mime = message.contentType.map { String($0.split(separator: ";")[0]).trimmingCharacters(in: .whitespaces) }
        let ext = mime.flatMap { UTType(mimeType: $0) }?.preferredFilenameExtension ?? "txt"
        var name = row.path.split(separator: "/").last.map(String.init) ?? "body"
        if URL(fileURLWithPath: name).pathExtension.isEmpty { name += ".\(ext)" }
        do {
            try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
            let file = folder.appending(path: "\(row.seq)-\(name)")
            try body.write(to: file)
            url = file
            return true
        } catch {
            url = nil
            return false
        }
    }

    func numberOfPreviewItems(in panel: QLPreviewPanel!) -> Int { url == nil ? 0 : 1 }

    func previewPanel(_ panel: QLPreviewPanel!, previewItemAt index: Int) -> (any QLPreviewItem)! { url as NSURL? }
}
