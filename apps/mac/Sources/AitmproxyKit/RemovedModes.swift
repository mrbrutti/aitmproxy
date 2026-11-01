/// The fake-data switches removed on 2026-10-31 (spec 2026-10-31-remove-fake-data-ui-modes,
/// D3 item 8). A launch that still sets one of them is refused in
/// `applicationDidFinishLaunching`, before any window or live stack exists: otherwise a
/// stale script, alias or memory note would silently run the full live app on the
/// operator's real defaults. Presence is the stale invocation, so any value counts, an
/// empty one included.
public enum RemovedModes {
    static let variables = ["APP_FIXTURES", "APP_SNAPSHOT", "APP_SNAPSHOT_PAGES", "APP_KIT_GALLERY", "APP_L4_EMBEDDED"]

    /// The refusal line for the first removed variable present in `environment`; nil when none is.
    public static func refusal(environment: [String: String]) -> String? {
        variables.first { environment[$0] != nil }
            .map { "\($0) was removed on 2026-10-31 with the fixture modes; see apps/mac/CLAUDE.md" }
    }
}
