import Cocoa

// Post a real left mouse click at a global screen point (pixel-level computer-use).
//   swift cgclick.swift <x> <y>
let args = CommandLine.arguments
guard args.count >= 3, let x = Double(args[1]), let y = Double(args[2]) else {
    FileHandle.standardError.write(Data("usage: cgclick.swift <x> <y>\n".utf8)); exit(2)
}
let p = CGPoint(x: x, y: y)
CGWarpMouseCursorPosition(p)
usleep(30_000)
func post(_ type: CGEventType) {
    if let e = CGEvent(mouseEventSource: nil, mouseType: type, mouseCursorPosition: p, mouseButton: .left) {
        e.post(tap: .cghidEventTap)
    }
}
post(.leftMouseDown)
usleep(50_000)
post(.leftMouseUp)
usleep(30_000)
