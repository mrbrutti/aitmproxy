import Foundation
// Apple's own HTTP stack (what Safari uses): which protocol does URLSession negotiate with
// cloudflare-quic.com / quic.nginx.org? Three sequential loads so Alt-Svc can promote to h3.
final class D: NSObject, URLSessionTaskDelegate {
    func urlSession(_ s: URLSession, task: URLSessionTask, didFinishCollecting metrics: URLSessionTaskMetrics) {
        for t in metrics.transactionMetrics {
            print("  metrics:", t.request.url?.host ?? "?", "protocol=\(t.networkProtocolName ?? "nil")",
                  "reused=\(t.isReusedConnection)", "remote=\(t.remoteAddress ?? "?"):\(t.remotePort ?? 0)")
        }
    }
}
let d = D()
let cfg = URLSessionConfiguration.ephemeral
let session = URLSession(configuration: cfg, delegate: d, delegateQueue: nil)
let sem = DispatchSemaphore(value: 0)
func fetch(_ u: String, _ done: @escaping () -> Void) {
    var req = URLRequest(url: URL(string: u)!)
    req.assumesHTTP3Capable = true
    session.dataTask(with: req) { data, resp, err in
        print(u, "->", (resp as? HTTPURLResponse)?.statusCode ?? -1, err.map { "error \($0.localizedDescription)" } ?? "ok", data?.count ?? 0, "bytes")
        done()
    }.resume()
}
fetch("https://cloudflare-quic.com/") { fetch("https://cloudflare-quic.com/") { fetch("https://cloudflare-quic.com/") {
    fetch("https://quic.nginx.org/") { fetch("https://quic.nginx.org/") { sem.signal() } } } } }
_ = sem.wait(timeout: .now() + 60)
