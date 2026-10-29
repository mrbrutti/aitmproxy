import AitmBusClient
import Foundation

/// Files the app can take in (S-065). Until the proxy's `flow.import` (F10)
/// lands, only HAR is read here; the others are recognised so the refusal
/// can name them.
public enum ImportFormat: String, Sendable {
    case har, mitmproxy, proxyman, charles

    public var title: String {
        switch self {
        case .har: "HAR"
        case .mitmproxy: "mitmproxy"
        case .proxyman: "Proxyman"
        case .charles: "Charles"
        }
    }
}

/// Why a file was not imported, in the alert's words.
public struct ImportRefusal: Error, Equatable, Sendable {
    public var name: String
    public var detected: ImportFormat?

    public var message: String {
        if let detected { return "Can't import \(name): \(detected.title) files are not supported until the proxy imports them (F10)." }
        return "Can't import \(name): not a HAR, mitmproxy, Proxyman or Charles file."
    }
}

/// What the app writes out.
public enum ExportFormat: String, CaseIterable, Sendable {
    case har, csv, curl

    public var title: String {
        switch self {
        case .har: "HAR"
        case .csv: "CSV"
        case .curl: "cURL Batch"
        }
    }

    public var fileExtension: String {
        switch self {
        case .har: "har"
        case .csv: "csv"
        case .curl: "sh"
        }
    }
}

/// Import and export of captured flows as files.
public enum FlowTransfer {
    /// The format a file name and its first bytes suggest.
    public static func detect(name: String, data: Data) -> ImportFormat? {
        let ext = (name as NSString).pathExtension.lowercased()
        switch ext {
        case "har": return .har
        case "mitm", "flows", "dump": return .mitmproxy
        case "proxymanlog", "proxymanlogv2": return .proxyman
        case "chlz", "chls", "chlsj": return .charles
        default: break
        }
        guard let head = String(data: data.prefix(512), encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines) else { return nil }
        if head.hasPrefix("{"), head.contains("\"log\"") { return .har }
        return nil
    }

    /// The rows and details in a file, numbered from `firstSeq`; throws the
    /// refusal for anything but HAR.
    public static func importFile(name: String, data: Data, firstSeq: Int) throws(ImportRefusal) -> [(FlowRow, FlowDetail)] {
        guard detect(name: name, data: data) == .har else { throw ImportRefusal(name: name, detected: detect(name: name, data: data)) }
        guard let flows = try? importHAR(data, firstSeq: firstSeq) else { throw ImportRefusal(name: name, detected: nil) }
        return flows
    }

    /// HAR 1.2 entries → flows with the `imported` origin. Bodies come from
    /// `postData.text` and `content.text` (base64 when `encoding` says so).
    public static func importHAR(_ data: Data, firstSeq: Int) throws -> [(FlowRow, FlowDetail)] {
        let json = try JSONValue.parse(data)
        guard let entries = json["log"]?["entries"]?.arrayValue else { throw ImportRefusal(name: "HAR", detected: .har) }
        let iso = ISO8601DateFormatter()
        iso.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        let plain = ISO8601DateFormatter()
        var out: [(FlowRow, FlowDetail)] = []
        for (index, entry) in entries.enumerated() {
            guard let request = entry["request"], let urlText = request["url"]?.stringValue,
                  let components = URLComponents(string: urlText) else { continue }
            let method = HTTPMethod(request["method"]?.stringValue ?? "GET")
            let scheme = components.scheme ?? "https"
            var authority = components.host ?? ""
            if let port = components.port { authority += ":\(port)" }
            let path = components.path.isEmpty ? "/" : components.path
            let query = components.query
            let httpVersion = request["httpVersion"]?.stringValue ?? "HTTP/1.1"
            let requestBody = body(request["postData"])
            let requestMessage = HTTPMessage(startLine: "\(method.label) \(path)\(query.map { "?\($0)" } ?? "") \(httpVersion)",
                                             headers: headers(request["headers"]), body: requestBody)
            var responseMessage: HTTPMessage?
            var status: Int?
            if let response = entry["response"], let code = response["status"]?.intValue, code > 0 {
                status = code
                let text = response["statusText"]?.stringValue ?? ""
                responseMessage = HTTPMessage(startLine: "\(response["httpVersion"]?.stringValue ?? httpVersion) \(code) \(text)".trimmingCharacters(in: .whitespaces),
                                              headers: headers(response["headers"]), body: body(response["content"]))
            }
            let started = entry["startedDateTime"]?.stringValue.flatMap { iso.date(from: $0) ?? plain.date(from: $0) }
            let duration = entry["time"]?.doubleValue.map { Duration.milliseconds(Int($0.rounded())) }
            let id = FlowID("import-\(firstSeq + index)-\(UUID().uuidString.prefix(8))")
            let row = FlowRow(id: id, seq: firstSeq + index, method: method, scheme: scheme, authority: authority, path: path,
                              query: query, status: status, state: status == nil ? .failed : .complete, origin: .imported,
                              startedAt: started, duration: duration,
                              requestBytes: Int64(requestBody?.count ?? 0), responseBytes: responseMessage.map { Int64($0.body?.count ?? 0) },
                              tls: scheme == "https" ? .decrypted : .none)
            let detail = FlowDetail(id: id, request: requestMessage, response: responseMessage,
                                    connection: ConnectionInfo(httpVersion: httpVersion))
            out.append((row, detail))
        }
        return out
    }

    /// The file text for `flows` in `format`.
    public static func export(_ flows: [(FlowRow, FlowDetail?)], as format: ExportFormat, startedAt: Date = Date()) -> String {
        switch format {
        case .har:
            let entries = flows.compactMap { row, detail in detail.map { HAR.entry(for: $0, row: row, startedAt: row.startedAt ?? startedAt) } }
            return HAR.log(entries: entries)
        case .csv:
            var lines = ["seq,method,url,status,client,time,duration_ms,request_bytes,response_bytes"]
            for (row, _) in flows {
                lines.append([String(row.seq), row.method.label, row.url, row.status.map(String.init) ?? "", row.client?.name ?? "",
                              row.startedAt.map { ISO8601DateFormatter().string(from: $0) } ?? "", row.duration.map { String(Int(milliseconds($0))) } ?? "",
                              row.requestBytes.map(String.init) ?? "", row.responseBytes.map(String.init) ?? ""]
                    .map(csvField).joined(separator: ","))
            }
            return lines.joined(separator: "\n") + "\n"
        case .curl:
            var lines = ["#!/bin/sh", "# \(flows.count) request\(flows.count == 1 ? "" : "s") exported from aitmproxy"]
            for (row, detail) in flows {
                lines.append("")
                lines.append("# \(row.seq) \(row.method.label) \(row.url)")
                if let detail { lines.append(CodeExport.curl(detail, row: row)) } else { lines.append("curl '\(row.url)'") }
            }
            return lines.joined(separator: "\n") + "\n"
        }
    }

    /// `aitmproxy-2026-10-28-1105.har`
    public static func suggestedFilename(_ format: ExportFormat, date: Date = Date()) -> String {
        let f = DateFormatter()
        f.locale = Locale(identifier: "en_US_POSIX")
        f.dateFormat = "yyyy-MM-dd-HHmm"
        return "aitmproxy-\(f.string(from: date)).\(format.fileExtension)"
    }

    // MARK: Helpers

    private static func headers(_ value: JSONValue?) -> [HTTPMessage.Header] {
        (value?.arrayValue ?? []).compactMap { h in
            guard let name = h["name"]?.stringValue, let value = h["value"]?.stringValue else { return nil }
            return HTTPMessage.Header(name.lowercased(), value)
        }
    }

    private static func body(_ value: JSONValue?) -> Data? {
        guard let text = value?["text"]?.stringValue, !text.isEmpty else { return nil }
        if value?["encoding"]?.stringValue == "base64" { return Data(base64Encoded: text) }
        return Data(text.utf8)
    }

    private static func csvField(_ s: String) -> String {
        s.contains(where: { $0 == "," || $0 == "\"" || $0 == "\n" }) ? "\"\(s.replacingOccurrences(of: "\"", with: "\"\""))\"" : s
    }

    private static func milliseconds(_ d: Duration) -> Double {
        let (s, attos) = d.components
        return Double(s) * 1000 + Double(attos) / 1_000_000_000_000_000
    }
}
