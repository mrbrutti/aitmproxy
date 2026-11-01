/// The first-run sheet's own words (spec 2026-10-31-system-proxy-automation-design §D13 and §D17.8;
/// order per the per-host-decryption decision), one home for the sheet and its test.
public enum SetupWords {
    public static let sheetTitle = "Set up aitmproxy on this Mac"
    /// Row 1's title while the system-proxy route is unknown (no `proxy.status` answer yet); once the
    /// route is known the row carries the Getting-started step's title, the route's own line.
    public static let systemProxyRowTitle = "Set aitmproxy as the system proxy"
    /// Under row 1's button (§D13, Architect's call): the button sets now AND turns on the launch
    /// preference, because the core restores on quit and a one-time set would be gone at the next launch.
    public static let systemProxyAutoCaption = "Also turns on “Set system proxy at launch” in Settings ▸ Proxy"
    public static let scopeCaption = "Nothing is decrypted until a host is in Scope"
}
