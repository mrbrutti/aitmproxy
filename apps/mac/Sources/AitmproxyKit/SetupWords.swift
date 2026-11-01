/// The first-run sheet's own words (spec 2026-10-31-system-proxy-automation-design §D13 and §D17.8;
/// order per the per-host-decryption decision), one home for the sheet and its test.
public enum SetupWords {
    public static let sheetTitle = "Set up aitmproxy on this Mac"
    /// Row 1's title (Matt's words, §D13 "Step order and words"); the route's line is the fact under it.
    public static let systemProxyRowTitle = "Set aitmproxy as the system proxy"
    /// Row 1's checklist, verbatim (§D13 "First-run sheet").
    public static let systemProxyChecklist = [
        "Route every proxy-aware app through aitmproxy",
        "Remember and restore your previous proxy setting",
        "Revert automatically if the app quits or crashes",
    ]
    /// Under row 1's button (§D13, Architect's call): the button sets now AND turns on the launch
    /// preference, because the core restores on quit and a one-time set would be gone at the next launch.
    public static let systemProxyAutoCaption = "Also turns on “Set system proxy at launch” in Settings ▸ Proxy"
    public static let scopeCaption = "Nothing is decrypted until a host is in Scope"
}
