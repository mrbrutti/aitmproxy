import Foundation

/// Which core the app talks to, as a persisted, user-changeable choice (spec O1).
/// `embedded` is the default: the app runs and manages its own bundled core.
/// `external` points the app at an already-running core (host/port/token from
/// Settings, `config.yaml`, or `--bus`). `remote` is reserved on
/// `CoreConnection.Kind` and is not a selectable active choice yet, so it is not
/// a case here.
public enum ActiveCoreKind: String, Codable, Sendable, CaseIterable, Identifiable {
    case embedded
    case external

    public var id: String { rawValue }

    /// Operator-facing name for the Settings picker.
    public var title: String {
        switch self {
        case .embedded: "Embedded (bundled core)"
        case .external: "External (connect to a running core)"
        }
    }
}

/// What the active-connection state machine drives when the choice changes. The
/// live app backs this with the embedded-core controller (Task 6) and the bus
/// client; tests back it with a fake so the switch is assertable without a child
/// process.
///
/// `activateEmbedded` (re)starts the embedded core and points the bus at it;
/// `activateExternal` stops the embedded core and points the bus at the operator's
/// external endpoint. Switching is therefore start/stop + make-active, which is
/// why choosing external never permanently disables embedded.
@MainActor
public protocol ActiveConnectionDriver: AnyObject {
    /// Whether the embedded core is currently running.
    var isEmbeddedRunning: Bool { get }
    /// Make the embedded core the active connection, starting it if needed.
    func activateEmbedded()
    /// Make the external core the active connection; stop the embedded core.
    func activateExternal()
}

/// Where the active-core choice persists so it round-trips across launches. The
/// live app backs this with `UserDefaults`; tests use an in-memory stand-in.
public protocol ActiveKindPersistence: AnyObject {
    func load() -> ActiveCoreKind?
    func save(_ kind: ActiveCoreKind)
}

/// `UserDefaults`-backed persistence for the active-core choice, under
/// Whether the status bar's Expected-role warning applies. The embedded core always
/// connects the app as operator, so the warning describes an external core: it is
/// suppressed only while the embedded core is the ACTIVE connection and present. An
/// external connection with a dormant embedded controller still warns.
public func roleWarningApplies(activeKind: ActiveCoreKind, embeddedConnectionPresent: Bool) -> Bool {
    !(activeKind == .embedded && embeddedConnectionPresent)
}

/// `bus.activeKind` (the key `BusSettings` binds to as well).
public final class UserDefaultsActiveKindPersistence: ActiveKindPersistence {
    public static let key = "bus.activeKind"
    private let defaults: UserDefaults

    public init(defaults: UserDefaults = .standard) { self.defaults = defaults }

    public func load() -> ActiveCoreKind? {
        defaults.string(forKey: Self.key).flatMap(ActiveCoreKind.init(rawValue:))
    }

    public func save(_ kind: ActiveCoreKind) {
        defaults.set(kind.rawValue, forKey: Self.key)
    }
}

/// The active core connection as switchable, persistent state (AC10): it owns the
/// current `ActiveCoreKind`, persists every change, and drives the embedded/
/// external transition. Default `.embedded`; selecting `.external` stops the
/// embedded core, selecting `.embedded` (re)starts it — so external is an
/// override, never a permanent disable.
///
/// Construction is side-effect-free: call `activate()` once at launch to apply the
/// restored choice. The UI exposes exactly one active choice today; the registry
/// seam (Task 4) keeps the door open for several at once.
@MainActor
public final class ActiveConnectionModel {
    public private(set) var activeKind: ActiveCoreKind

    private let driver: ActiveConnectionDriver
    private let persistence: ActiveKindPersistence

    public init(driver: ActiveConnectionDriver, persistence: ActiveKindPersistence) {
        self.driver = driver
        self.persistence = persistence
        self.activeKind = persistence.load() ?? .embedded
    }

    /// Whether the embedded core is currently running (for the health surface).
    public var isEmbeddedRunning: Bool { driver.isEmbeddedRunning }

    /// Apply the current (restored) choice. Call once at launch so the app brings
    /// up the connection the operator last chose.
    public func activate() { apply(activeKind) }

    /// Switch the active connection and persist the choice. Starts or stops the
    /// embedded core as the new choice requires.
    public func select(_ kind: ActiveCoreKind) {
        activeKind = kind
        persistence.save(kind)
        apply(kind)
    }

    private func apply(_ kind: ActiveCoreKind) {
        switch kind {
        case .embedded: driver.activateEmbedded()
        case .external: driver.activateExternal()
        }
    }
}
