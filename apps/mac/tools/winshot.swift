import Cocoa
// Capture one on-screen window of an app by owner name (computer-use proof shots).
//   swift winshot.swift <ownerName> <out.png> [titleContains]
// Prints the window number it captured, or exits 1 when the app has no on-screen window.
let args = CommandLine.arguments
guard args.count >= 3 else {
    FileHandle.standardError.write(Data("usage: winshot.swift <ownerName> <out.png> [titleContains]\n".utf8)); exit(2)
}
let owner = args[1], out = args[2], titleNeedle = args.count > 3 ? args[3] : nil
let list = CGWindowListCopyWindowInfo([.optionOnScreenOnly, .excludeDesktopElements], kCGNullWindowID) as? [[String: Any]] ?? []
let candidates = list.filter { info in
    (info[kCGWindowOwnerName as String] as? String) == owner
        && (info[kCGWindowLayer as String] as? Int) == 0
        && ((info[kCGWindowBounds as String] as? [String: Any])?["Width"] as? Double ?? 0) > 400
        && (titleNeedle.map { ((info[kCGWindowName as String] as? String) ?? "").contains($0) } ?? true)
}
guard let win = candidates.first, let number = win[kCGWindowNumber as String] as? Int else {
    FileHandle.standardError.write(Data("no on-screen window for \(owner)\n".utf8)); exit(1)
}
// A stale PNG from an earlier run must never pass as this run's proof.
try? FileManager.default.removeItem(atPath: out)
let shot = Process()
shot.executableURL = URL(fileURLWithPath: "/usr/sbin/screencapture")
shot.arguments = ["-x", "-o", "-l", String(number), out]
do { try shot.run() } catch { FileHandle.standardError.write(Data("screencapture failed to start: \(error)\n".utf8)); exit(1) }
shot.waitUntilExit()
guard shot.terminationStatus == 0 else { exit(Int32(shot.terminationStatus)) }
// window number, then the window's screen bounds in points (x y w h) for pixel-path clicks.
let b = win[kCGWindowBounds as String] as? [String: Any] ?? [:]
print(number, Int(b["X"] as? Double ?? 0), Int(b["Y"] as? Double ?? 0), Int(b["Width"] as? Double ?? 0), Int(b["Height"] as? Double ?? 0))
exit(FileManager.default.fileExists(atPath: out) ? 0 : 1)
