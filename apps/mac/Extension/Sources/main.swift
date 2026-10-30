import Foundation
import NetworkExtension

// System-extension entry point. Register the provider machinery as early as
// possible (Apple's requirement), then park on the run loop so the extension
// stays resident. Proven by the Task-1 spike
// (docs/research/experiments/2026-10-29-macos-ne-spike.md).
autoreleasepool {
    NEProvider.startSystemExtensionMode()
}
dispatchMain()
