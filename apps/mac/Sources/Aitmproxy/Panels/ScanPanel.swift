import AitmBusClient
import AitmproxyKit
import Observation
import SwiftUI

/// The Scan page's state (scanner-integration Stage 1): the launch form, the last
/// `scan.discover` result, and the intents. Held by the session as `session.scan`,
/// like `poc`. The data and the launch gate are the Kit's `ScanState` / `ScanForm`.
///
/// Viewing the page never scans: only `launch()` reaches the bus, and it passes the
/// scope gate (deny-by-default) first.
@Observable
final class ScanPanelState {
    @ObservationIgnored unowned let session: Session

    var form = ScanForm(tool: nil, scopeHosts: [])
    var model = ScanState()

    init(session: Session) { self.session = session }

    var running: Bool { model.running }
    var endpoints: [String] { model.endpoints }
    var points: [InjectionPoint] { model.points }
    var error: String? { model.error }

    /// The bus lists `scan.discover`; without it the page degrades instead of breaking.
    var offered: Bool { session.scanEnabled }
    /// Why the current target cannot be scanned; nil when it can.
    var refusal: String? { form.scopeError(scopeHosts: session.scopeHosts) }
    var canLaunch: Bool { offered && !model.running && refusal == nil }

    /// The in-scope hosts a scan can start from (never a `*.wildcard`).
    var scopeChoices: [String] { ScanForm.concreteHosts(in: session.scopeHosts) }

    /// Re-reads the tool schema and scope into the form; a typed target is kept.
    func syncForm() {
        form.sync(tool: session.tools.first { $0.name == ScanForm.toolName }, scopeHosts: session.scopeHosts)
    }

    // MARK: Intents

    /// The in-flight crawl, held so Cancel can stop waiting on it.
    @ObservationIgnored private var scanTask: Task<Void, Never>?

    /// Start a crawl and keep its task so the running state can be cancelled.
    func start() { scanTask = Task { await launch() } }

    /// Stop waiting on the crawl and clear the running state. The bus call cannot be
    /// recalled, so a late result is dropped (the `Task.isCancelled` guard in `launch`).
    func cancelScan() {
        scanTask?.cancel()
        scanTask = nil
        model.running = false
    }

    /// `scan.discover {target, max_depth?, max_pages?}` → the endpoints and injection points it found.
    func launch() async {
        guard let args = model.beginLaunch(form: form, scopeHosts: session.scopeHosts, tools: session.tools) else { return }
        let value: JSONValue
        do {
            value = try await session.runCommand(ScanForm.toolName, args)
        } catch {
            if Task.isCancelled { return }
            model.fail(BusService.describe(error))
            return
        }
        guard !Task.isCancelled else { return }
        do {
            model.finish(try ScanResult(json: value))
        } catch {
            model.fail("scan.discover returned a result this app cannot read")
        }
    }

    func select(_ index: Int) { model.selected = index }

    /// The flow an injection point was seen in is still in the flow list.
    func canOpen(_ point: InjectionPoint) -> Bool { isListed(point.flowID) }

    /// Open the point's flow in the inspector: select it and show the flow list. A flow
    /// that is no longer listed is refused, not selected.
    func open(_ point: InjectionPoint) { openFlow(point.flowID) }

    /// The flow the crawl fetched this endpoint in, or nil when the result links none
    /// (the row is then plain).
    func flowID(forEndpoint url: String) -> FlowID? { model.flowID(forEndpoint: url) }

    /// The result links this endpoint to a flow.
    func isLinked(endpoint url: String) -> Bool { flowID(forEndpoint: url) != nil }

    /// The endpoint is linked and its flow is still in the flow list.
    func canOpen(endpoint url: String) -> Bool { flowID(forEndpoint: url).map(isListed) ?? false }

    /// Open the endpoint's flow like an injection point's. An unlinked endpoint does
    /// nothing; a linked flow that is no longer listed is refused, not selected.
    func open(endpoint url: String) {
        guard let flow = flowID(forEndpoint: url) else { return }
        openFlow(flow)
    }

    private func isListed(_ flow: FlowID) -> Bool { session.rows.contains { $0.id == flow } }

    private func openFlow(_ flow: FlowID) {
        guard isListed(flow) else {
            session.lastError = "flow \(flow.raw) is not in the flow list (cleared, or not captured here)"
            return
        }
        session.select(flow)
        session.show(.apps)
    }

    // MARK: - Scanner v2 surface (T9)

    /// The four-tab surface's state (Kit, no SwiftUI): profiles, jobs, site map,
    /// issues, the pending launch and the push flags. The legacy members above are
    /// untouched and the two halves never share a value: `points` stays the legacy
    /// injection-point list the sidebar counts.
    var surface = ScanSurfaceModel()

    /// Restarts the page's poll task (`.task(id:)`). A launch bumps it so the new
    /// job is read at once instead of at the next whole tick.
    var pollGeneration = 0

    /// Bumped by `focusLaunch()`: the Profiles footer scrolls into view and Start
    /// Scan takes focus.
    var launchFocusTick = 0

    /// The profile the Delete Profile dialog is asking about; nil closes it.
    var deleteCandidate: String?

    /// The name typed into the Duplicate… popover.
    var duplicateName: String?

    /// When the `scan.profile.list` in flight started, nil when none is.
    var profilesLoadingSince: Date?

    /// That load has been in flight for more than 500 ms, which is the only time
    /// the header shows a spinner (D11: the cached list is shown first).
    var profilesLoadingSlow = false

    /// The last `scan.checks` read failed. Rendered inside the editor's Checks
    /// block; the catalogue already loaded stays (D11).
    var checksError: String?

    /// The Site map tab's last read failed. The Kit model carries `profilesError`,
    /// `jobsError` and `issuesError` but no site-map slot, so the page keeps this
    /// one; like the others it never blanks the list it could not refresh.
    var sitemapError: String?

    // MARK: Surface queries

    /// Which Scan page this bus can back (D11), feature-detected, never assumed.
    var mode: ScanSurface.Mode { ScanSurface.mode(for: session.tools) }

    /// The bus lists `scan.start`.
    var surfaceOffered: Bool { ScanSurface.isOffered(in: session.tools) }

    /// Why a launch may not be sent, nil when it may: the one gate every launch
    /// passes (D9). Computed, so a scope or tools change updates it with no read.
    var launchRefusal: String? { surface.launchRefusal(scopeHosts: session.scopeHosts, tools: session.tools) }

    /// The job Cancel Scan would stop: the Kit's choice by the merged state (the
    /// selected job while queued or running; with nothing selected the only such
    /// job; never a cancelling one and never a job other than the selected, Jobs
    /// view D2), and nothing at all while the verbs are gated off by the link
    /// (Jobs view D6).
    var cancelTarget: String? { verbsEnabled ? surface.cancelTarget : nil }

    var canCancel: Bool { cancelTarget != nil }

    /// The wall clock in epoch milliseconds, set once a second by `clockTask` so the
    /// link's age clause moves without a render-time clock (Jobs view D6).
    var nowMs = ScanPanelState.clockMs

    /// The verb gate without the clock (plan fix 1.5h): the rows, the context menu,
    /// the header's verb slot, `cancelTarget` and `cancel(job:)` read this, so the
    /// 1 Hz `nowMs` re-evaluates only the inline error that reads `link`.
    var verbsEnabled: Bool { ScanJobsLink.verbsEnabled(bus: session.bus, readFailedAt: surface.readFailedAt) }

    /// How the Jobs view is linked to the core right now: the bus state, the last
    /// Jobs read's outcome (list, status or cancel; D6 amendment) and the age of the
    /// values on screen (Jobs view D6). Computed each render; only the inline error
    /// reads it (its age clause moves with `nowMs`); the verbs read `verbsEnabled`.
    var link: ScanJobsLink {
        ScanJobsLink.make(bus: session.bus, readFailedAt: surface.readFailedAt, jobsLoadedAt: surface.jobsLoadedAt, now: nowMs)
    }

    private static var clockMs: Int { Int(Date().timeIntervalSince1970 * 1000) }

    // MARK: Surface reads

    /// `scan.profile.list`. A failure keeps the profiles already listed (D11).
    func refreshProfiles() async {
        let started = Date()
        profilesLoadingSince = started
        let slowMark = Task { [weak self] in
            try? await Task.sleep(for: .milliseconds(500))
            guard let self, !Task.isCancelled, profilesLoadingSince == started else { return }
            profilesLoadingSlow = true
        }
        defer {
            slowMark.cancel()
            profilesLoadingSince = nil
            profilesLoadingSlow = false
        }
        do {
            let value = try await session.runCommand("scan.profile.list", [:])
            surface.applyProfiles(try ScanProfileListResult(json: value))
        } catch {
            surface.profilesError = scanUnableText("load profiles", BusService.describe(error))
        }
    }

    /// `scan.profile.get {name}` into the editor; the session preview follows it,
    /// because the preview is per target origin.
    func loadProfile(_ name: String) async {
        do {
            let value = try await session.runCommand("scan.profile.get", ["name": .string(name)])
            surface.applyProfile(try ScanProfile(json: value))
            surface.profilesError = nil
        } catch {
            surface.profilesError = scanUnableText("load profile \(name)", BusService.describe(error))
            return
        }
        await refreshSessionPreview()
    }

    /// `scan.checks {}`: the catalogue the Checks tree groups.
    func refreshChecks() async {
        do {
            let value = try await session.runCommand("scan.checks", [:])
            surface.applyChecks(try ScanChecksResult(json: value))
            checksError = nil
        } catch {
            checksError = scanUnableText("load checks", BusService.describe(error))
        }
    }

    /// `scan.session.preview {target}` for the edited profile's first origin, only
    /// while its session mode is Observed. A failure, no origin or no names at all
    /// leaves the preview nil, which the editor reads as `ScanFormat.noSessionText`.
    func refreshSessionPreview() async {
        guard let profile = surface.editedProfile, profile.session.mode == .observed,
              let origin = profile.target.origins.first else {
            surface.sessionPreview = nil
            return
        }
        guard let value = try? await session.runCommand("scan.session.preview", ["target": .string(origin)]),
              let preview = try? ScanSessionProfile(json: value),
              !(preview.cookies.isEmpty && preview.headers.isEmpty) else {
            surface.sessionPreview = nil
            return
        }
        surface.sessionPreview = preview
    }

    /// `l4.scope.list {}`, and only when the bus lists it: an L4 lane needs a scope
    /// entry with the Inject capability. Unknown stays unknown (nil), which the
    /// launch gate reads as "not available" — deny by default.
    func refreshL4Scope() async {
        guard ScanSurface.has("l4.scope.list", in: session.tools) else {
            surface.l4InjectScopeKnown = nil
            return
        }
        do {
            let value = try await session.runCommand("l4.scope.list", [:])
            let entries = value["entries"]?.arrayValue ?? value.arrayValue ?? []
            surface.l4InjectScopeKnown = entries.contains { $0["capability"]?.stringValue == "inject" }
        } catch {
            surface.l4InjectScopeKnown = nil
        }
    }

    /// `scan.list {}`: the job rows, stamped with the clock so the link can say how
    /// old they are. A failure keeps the rows and their counters and stamps the
    /// failure instead (Jobs view D6).
    func refreshList() async {
        do {
            let value = try await session.runCommand("scan.list", [:])
            surface.applyList(try ScanListResult(json: value), now: Self.clockMs)
            // The list landing is the one point that re-arms a status read: the jobs it
            // dropped are pruned and any job that still owes a read is claimable again.
            statusReads.settle(afterList: surface.jobs, stored: surface.statuses)
        } catch {
            surface.noteReadFailure(text: scanUnableText("list jobs", BusService.describe(error)), now: Self.clockMs)
        }
    }

    /// `scan.status {job}`: the counters of one job, and its list row. A failure
    /// marks the link like a failed list (Jobs view D6 amendment: the poll reads the
    /// selected job's status first, so against a frozen core this times out first).
    /// A success clears nothing: one job answering is not proof the list does, so only
    /// the next list that lands clears the failure (D6; `applyList` is the one clearing point).
    func refreshStatus(_ job: String) async {
        do {
            let value = try await session.runCommand("scan.status", ["job": .string(job)])
            surface.applyStatus(try ScanJobStatus(json: value))
        } catch {
            surface.noteReadFailure(text: scanUnableText("read job \(job)", BusService.describe(error)), now: Self.clockMs)
        }
    }

    /// `scan.issues` under the current filters; `append` adds the next page.
    func refreshIssues(append: Bool = false) async {
        loadedIssueFilters = surface.filters
        var args = surface.filters.arguments()
        if append, let cursor = surface.issuesCursor { args["cursor"] = .string(cursor) }
        do {
            let value = try await session.runCommand("scan.issues", args)
            surface.applyIssues(try ScanIssuesResult(json: value), append: append)
        } catch {
            surface.issuesError = scanUnableText("load issues", BusService.describe(error))
        }
    }

    /// `scan.issue {id}`: the evidence of one issue, for the detail pane.
    func loadIssue(_ id: String) async {
        do {
            let value = try await session.runCommand("scan.issue", ["id": .string(id)])
            surface.applyIssue(try ScanIssue(json: value))
        } catch {
            surface.issuesError = scanUnableText("load issue \(id)", BusService.describe(error))
        }
    }

    /// `scan.sitemap` for the chosen job (all jobs when none); `append` adds the
    /// next page behind Load More.
    func refreshSitemap(append: Bool = false) async {
        loadedSitemapJob = .some(surface.sitemapJob)
        var args: [String: JSONValue] = [:]
        if let job = surface.sitemapJob { args["job"] = .string(job) }
        if append, let cursor = surface.sitemap?.nextCursor { args["cursor"] = .string(cursor) }
        do {
            let value = try await session.runCommand("scan.sitemap", args)
            surface.applySitemap(try ScanSitemapResult(json: value), append: append)
            sitemapError = nil
        } catch {
            sitemapError = scanUnableText("load the site map", BusService.describe(error))
        }
    }

    // MARK: Polling (D8)

    /// The `scan.status` reads the poll has claimed under rule 2 of the re-read rule
    /// (Jobs view D2): the Kit's ledger of (job, list-row-terminal) keys. A claim is
    /// never undone by the read's own outcome; `refreshList` settles the ledger when a
    /// list lands, pruning the jobs the list dropped and re-arming every job that still
    /// owes a read, so a failed status read is retried after the next list.
    @ObservationIgnored private var statusReads = ScanStatusReadLedger()
    /// The jobs whose `scan.cancel` is on the wire, so a second press within one round
    /// trip sends nothing and the header reads the cancelling word meanwhile. Observed,
    /// so the header flips to the cancelling word on the press, not on the reply.
    private var cancelsInFlight: Set<String> = []
    /// The filters the loaded issues page was read under; a change re-reads it.
    @ObservationIgnored private var loadedIssueFilters: ScanIssueFilters?
    /// The job the loaded site-map page was read for, wrapped so "all jobs" (nil)
    /// is distinguishable from "nothing read yet".
    @ObservationIgnored private var loadedSitemapJob: String??
    /// The issue whose detail was asked for, so a failed read does not spin.
    @ObservationIgnored private var loadedIssueDetail: String?
    /// The "Saved <name>" line this state put up, so the 4 s timer only clears
    /// a line nothing else has replaced.
    @ObservationIgnored private var savedLine: String?

    /// The Jobs age clock (Jobs view D6, D16): the state's one clock, started by
    /// `poll()` and cancelled when it returns, so it runs exactly while the Scan page
    /// is on screen. It is its own task, not a poll tick, because the poll loop is
    /// sequential: while a bus read hangs for the client's 30 s timeout no tick runs,
    /// and a hung read must not stop the age clock (the link read "from 0:02 ago"
    /// over values 36 s old). It touches `nowMs` and nothing else; no view owns a
    /// `Timer`.
    @ObservationIgnored private var clockTask: Task<Void, Never>?

    /// Runs exactly while the Scan page is on screen (`.task(id: pollGeneration)`):
    /// the first-visit reads, then a 250 ms tick. Each tick serves the push flags
    /// first — that is D8's coalescing — then the timers. A read that fails sets
    /// its own error and leaves every counter and row exactly as it was (D11).
    /// The age clock starts and stops with this task; it is cancelled by handle, not
    /// by property, so a generation bump's new clock survives the old poll's return.
    func poll() async {
        let clock = startClock()
        defer {
            clock.cancel()
            if clockTask == clock { clockTask = nil }
        }
        await firstVisitLoads()
        var tick = 0
        while !Task.isCancelled {
            await pollTick(tick)
            do {
                try await Task.sleep(for: .milliseconds(250))
            } catch {
                return
            }
            tick += 1
        }
    }

    /// Replaces the previous clock (a generation bump starts the new poll before the
    /// old one has returned), takes a fresh reading so the first second on screen is not
    /// the stale value from the last visit, and loops: sleep 1 s, set `nowMs`.
    /// Cancellation ends it.
    private func startClock() -> Task<Void, Never> {
        clockTask?.cancel()
        nowMs = Self.clockMs
        let clock = Task { [weak self] in
            while !Task.isCancelled {
                try? await Task.sleep(for: .seconds(1))
                guard !Task.isCancelled, let self else { return }
                self.nowMs = Self.clockMs
            }
        }
        clockTask = clock
        return clock
    }

    private func pollTick(_ tick: Int) async {
        guard surfaceOffered else { return }
        // Push flags first: `noteJobEvent` only ever flags, so the values on screen
        // come from `scan.status` / `scan.list` / `scan.issues`, never from the line.
        let flagged = surface.refreshNeeded
        let listFlagged = surface.listRefreshNeeded
        let issuesFlagged = surface.issuesRefreshNeeded
        surface.clearRefreshFlags()
        // A page leave or a launch's `pollGeneration` bump cancels this task between
        // reads; every await below is a point where the next read must not start.
        for job in flagged.sorted() {
            guard !Task.isCancelled else { return }
            await refreshStatus(job)
        }
        guard !Task.isCancelled else { return }
        if listFlagged { await refreshList() }
        guard !Task.isCancelled else { return }
        if issuesFlagged, surface.tab == .issues { await refreshIssues() }

        // Timers: the list every 2 s.
        guard !Task.isCancelled else { return }
        if tick.isMultiple(of: 8), !listFlagged { await refreshList() }
        // The selected job every 1 s until its stored status is terminal, and the
        // once-or-twice reads every other listed job is owed (Jobs view D2).
        guard !Task.isCancelled else { return }
        if tick.isMultiple(of: 4) { await pollStatuses(flagged: flagged) }
        guard !Task.isCancelled else { return }
        if surface.tab == .issues {
            // Issues every 2 s while a job is running, offset from the list beat.
            if tick % 8 == 4, !issuesFlagged, !surface.runningJobs.isEmpty { await refreshIssues() }
            guard !Task.isCancelled else { return }
            await loadIssuesIfFiltersChanged()
            guard !Task.isCancelled else { return }
            await loadSelectedIssueDetail()
        }
        guard !Task.isCancelled else { return }
        if surface.tab == .sitemap { await loadSitemapIfJobChanged() }
    }

    /// The re-read rule (Jobs view D2). Rule 1: the selected job is read every beat
    /// while its STORED status is missing or non-terminal (`selectedNeedsStatusRead`),
    /// not while the list row is (the list turns terminal first; the stored status
    /// must follow it there or the detail freezes at its last live read, C1). A
    /// terminal stored status is final. Rule 2: every other listed job is read when
    /// `needsStatusRead` says so and `statusReads` has no claim under the same key
    /// (the job and whether its row was terminal). A claim is never undone by the
    /// read's own outcome: a failed read against a core that is not answering would
    /// otherwise retry at 1 Hz and flip the link every second. The ledger is settled
    /// only when the next list lands (`refreshList`), the proof the core answers, which
    /// prunes the jobs the list dropped and re-arms every job that still owes a read,
    /// so a failed status read is retried after that list. A job the push flags already
    /// read this tick is left alone.
    private func pollStatuses(flagged: Set<String>) async {
        var readThisBeat = flagged
        if let job = surface.selectedJob, !flagged.contains(job),
           ScanSurfaceModel.selectedNeedsStatusRead(stored: surface.statuses[job]) {
            readThisBeat.insert(job)
            await refreshStatus(job)
        }
        for summary in surface.jobs {
            guard !Task.isCancelled else { return }
            let job = summary.job
            guard !readThisBeat.contains(job),
                  ScanSurfaceModel.needsStatusRead(summary: summary, stored: surface.statuses[job]) else { continue }
            guard statusReads.claim(job, summaryIsTerminal: summary.state.isTerminal) else { continue }
            await refreshStatus(job)
        }
    }

    /// The reads a first visit needs so no tab opens blank: the profiles, the check
    /// catalogue, the L4 scope when the bus has it, then a profile in the editor.
    private func firstVisitLoads() async {
        guard surfaceOffered, surface.profiles.isEmpty else { return }
        await refreshProfiles()
        await refreshChecks()
        await refreshL4Scope()
        await loadDefaultProfile()
    }

    /// `standard` when the core ships it, else the first profile listed.
    private func loadDefaultProfile() async {
        guard surface.editedProfile == nil, let first = surface.profiles.first else { return }
        let name = surface.profiles.first { $0.name == "standard" }?.name ?? first.name
        await loadProfile(name)
    }

    /// The Issues tab reads its page once per filter set; the filters are the
    /// verb's parameters, so a changed filter is a new read, not a local sieve.
    private func loadIssuesIfFiltersChanged() async {
        guard loadedIssueFilters != surface.filters else { return }
        await refreshIssues()
    }

    private func loadSitemapIfJobChanged() async {
        guard loadedSitemapJob != .some(surface.sitemapJob) else { return }
        await refreshSitemap()
    }

    private func loadSelectedIssueDetail() async {
        guard let id = surface.selectedIssue else {
            loadedIssueDetail = nil
            return
        }
        guard loadedIssueDetail != id else { return }
        loadedIssueDetail = id
        await loadIssue(id)
    }

    // MARK: Surface intents: launch (D9)

    /// Start Scan / Map Only. The gate is checked before anything is sent.
    func startScan(map: Bool) {
        Task { await launch(map: map) }
    }

    /// `scan.start` / `scan.map`. A refused launch never reaches the bus: the
    /// refusal becomes the footer's status line and the call is not made.
    func launch(map: Bool) async {
        // One launch at a time: a confirm sheet or an in-flight call owns the bus until it settles.
        guard surface.confirm == nil, !surface.launchInFlight else { return }
        // The footer and the button's help already show the refusal; echoing it into the
        // status line would outlive the refusal once the operator fixes the cause.
        guard launchRefusal == nil else { return }
        let call = surface.launchArguments(map: map)
        surface.launchInFlight = true
        await send(tool: call.tool, args: call.args)
    }

    /// The second half of the handshake: the identical arguments plus `_confirm`.
    /// A second Start Scan while the first is on the wire sends nothing.
    func confirmLaunch() async {
        guard let confirm = surface.confirm, !surface.launchInFlight else { return }
        surface.launchInFlight = true
        await send(tool: confirm.tool, args: confirm.confirmedArguments)
    }

    /// Cancel on the confirm sheet: nothing more is sent. Only the pending confirm
    /// is cleared; a confirmed call already on the wire keeps `launchInFlight`
    /// until `send` settles it, so the footer cannot start a second job meanwhile.
    func dismissConfirm() {
        surface.confirm = nil
    }

    /// One launch call, read as D9 reads it: a `needs_confirmation` answer first,
    /// then a start result, and a thrown error last.
    private func send(tool: String, args: [String: JSONValue]) async {
        let origins = surface.editedProfile?.target.origins ?? []
        let value: JSONValue
        do {
            value = try await session.runCommand(tool, args)
        } catch {
            surface.applyLaunchError(ScanLaunchError(busMessage: BusService.describe(error), origins: origins))
            return
        }
        if let request = L4ConfirmRequest(json: value) {
            surface.applyConfirm(tool: tool, args: args, request: request)
            return
        }
        do {
            surface.applyStart(try ScanStartResult(json: value))
        } catch {
            surface.applyLaunchError(ScanLaunchError(
                code: nil, message: "\(tool) returned a result this app cannot read", origins: origins))
            return
        }
        pollGeneration += 1
    }

    // MARK: Surface intents: jobs

    /// `scan.cancel {job}`. The issues the job already found stay. Sends nothing for
    /// a job whose merged state is already cancelling or terminal, while the link has
    /// the verbs gated off, or while its own cancel is still on the wire (Jobs view D2,
    /// D6): pressing Cancel twice, even within one round trip, is one cancel.
    func cancel(job: String) async {
        guard surface.mayCancel(job: job), verbsEnabled, !cancelsInFlight.contains(job) else { return }
        cancelsInFlight.insert(job)
        defer { cancelsInFlight.remove(job) }
        do {
            let value = try await session.runCommand("scan.cancel", ["job": .string(job)])
            if let status = try? ScanJobStatus(json: value) {
                surface.applyStatus(status)
            } else {
                await refreshStatus(job)
            }
        } catch {
            surface.noteReadFailure(text: scanUnableText("cancel job \(job)", BusService.describe(error)), now: Self.clockMs)
        }
    }

    /// Whether `job`'s `scan.cancel` is on the wire: the header reads the cancelling
    /// word (disabled) meanwhile, before the core has called the job cancelling.
    func cancelInFlight(_ job: String) -> Bool { cancelsInFlight.contains(job) }

    /// Cancel Scan (⌥⌘.): the selected job while queued or running; with nothing
    /// selected, the only running one (Jobs view D2 amendment).
    func cancelSelectedOrOnlyRunning() {
        guard let job = cancelTarget else { return }
        Task { await cancel(job: job) }
    }

    // MARK: Surface intents: profiles

    /// `scan.profile.save {profile}`: the edited profile becomes the saved one and
    /// the footer says so for four seconds.
    func saveProfile() async {
        guard let profile = surface.editedProfile else { return }
        do {
            let value = try await session.runCommand("scan.profile.save", ["profile": profile.json()])
            let result = try ScanProfileSaveResult(json: value)
            surface.loadedProfile = profile
            let line = "Saved \(result.saved)"
            surface.setStatusLine(line)
            clearStatusLine(line, after: .seconds(4))
        } catch {
            surface.setStatusLine(scanUnableText("save profile", BusService.describe(error)))
            return
        }
        await refreshProfiles()
    }

    /// Duplicate…: the edited values under a new name, unsaved and unloaded, so a
    /// launch sends the whole profile and Save Profile writes a new file. The name
    /// rule is checked here, not only by the popover's button: a name the core
    /// could not store as a file never becomes a profile's.
    func duplicateProfile(as name: String) {
        guard var profile = surface.editedProfile else { return }
        let trimmed = name.trimmingCharacters(in: .whitespaces)
        guard ScanSurface.isValidProfileName(trimmed) else { return }
        profile.name = trimmed
        surface.loadedProfile = nil
        surface.editedProfile = profile
        // Through `select(profile:)`: picking the duplicate starts afresh like any pick.
        surface.select(profile: trimmed)
        duplicateName = nil
    }

    /// `scan.profile.delete {name}`. The editor never ends up blank: the first
    /// profile left takes its place. `deleted: false` (nothing on file under that
    /// name) is said in the footer, not treated as a failure.
    func deleteProfile(_ name: String) async {
        deleteCandidate = nil
        do {
            let value = try await session.runCommand("scan.profile.delete", ["name": .string(name)])
            let result = try ScanProfileDeleteResult(json: value)
            if !result.deleted {
                let line = scanNothingToDeleteText(name: name)
                surface.setStatusLine(line)
                clearStatusLine(line, after: .seconds(4))
            }
        } catch {
            surface.profilesError = scanUnableText("delete profile \(name)", BusService.describe(error))
            return
        }
        if surface.selectedProfile == name {
            surface.selectedProfile = nil
            surface.loadedProfile = nil
            surface.editedProfile = nil
        }
        await refreshProfiles()
        await loadDefaultProfile()
    }

    // MARK: Surface intents: issues

    /// `scan.issue.update {id, status}`. The pill moves at once and moves back if
    /// the core refuses, so the list never claims a status the core does not hold.
    func updateIssueStatus(_ id: String, _ status: ScanIssueStatus) async {
        guard let previous = issueStatus(id) else { return }
        setIssueStatus(id, status)
        do {
            let value = try await session.runCommand(
                "scan.issue.update", ["id": .string(id), "status": .string(status.rawValue)])
            surface.applyIssue(try ScanIssue(json: value))
            surface.issuesError = nil
        } catch {
            setIssueStatus(id, previous)
            surface.issuesError = scanUnableText("update the issue", BusService.describe(error))
        }
    }

    /// `scan.issue.update {id, status, note}`: the note with the status it has now.
    func saveNote(_ id: String, note: String) async {
        guard let status = issueStatus(id) else { return }
        do {
            let value = try await session.runCommand(
                "scan.issue.update",
                ["id": .string(id), "status": .string(status.rawValue), "note": .string(note)])
            surface.applyIssue(try ScanIssue(json: value))
            surface.issuesError = nil
        } catch {
            surface.issuesError = scanUnableText("save the note", BusService.describe(error))
        }
    }

    private func issueStatus(_ id: String) -> ScanIssueStatus? {
        if surface.issueDetail?.id == id { return surface.issueDetail?.status }
        return surface.issues.first { $0.id == id }?.status
    }

    private func setIssueStatus(_ id: String, _ status: ScanIssueStatus) {
        if let index = surface.issues.firstIndex(where: { $0.id == id }) { surface.issues[index].status = status }
        if surface.issueDetail?.id == id { surface.issueDetail?.status = status }
    }

    // MARK: Surface intents: links out

    /// Open a flow the scanner names in the inspector, by the legacy rule: a flow
    /// that is no longer listed is refused, never silently selected.
    func openFlow(_ id: String) {
        guard isListed(id) else {
            session.lastError = "flow \(id) is not in the flow list (cleared, or not captured here)"
            return
        }
        session.select(FlowID(id))
        session.show(.apps)
    }

    /// That flow id is still in this app's flow list.
    func isListed(_ id: String) -> Bool { session.rows.contains { $0.id.raw == id } }

    /// `GET /search` for a listed flow; nil when the app never saw it, so the row
    /// can fall back to the bare id.
    func flowLabel(_ id: String) -> String? {
        guard let row = session.rows.first(where: { $0.id.raw == id }) else { return nil }
        return "\(row.method.label) \(row.path)"
    }

    /// Open the PoC an issue points at on the Findings page. The match is the
    /// Kit's `ScanFindingLink.match` over the findings' PoC paths, nothing looser;
    /// a reference no finding carries is refused, never guessed.
    func openPoC(ref: String) {
        if session.poc.findings.isEmpty { session.poc.load() }
        let findings = session.poc.findings
        guard let index = ScanFindingLink.match(pocRef: ref, in: findings.map(\.pocPath)) else {
            session.lastError = "PoC \(ref) is not in this app's findings list"
            return
        }
        session.show(.findings)
        session.poc.select(findings[index].id)
    }

    // MARK: Surface intents: navigation

    /// Show Issues: the Issues tab filtered to one job (all jobs when nil).
    func showIssues(job: String?) {
        surface.filters.job = job
        surface.tab = .issues
    }

    /// Show Site Map: the Site map tab for one job (all jobs when nil).
    func showSitemap(job: String?) {
        surface.sitemapJob = job
        surface.tab = .sitemap
    }

    /// Start Scan… from the menu or the palette: the Scan page, Profiles, launch focused.
    func focusLaunch() {
        surface.tab = .profiles
        launchFocusTick += 1
        session.show(.scan)
    }

    /// A `notifications/aitm/job` line: a trigger for the poll loop, never a value
    /// on screen. The sink that calls this is the follow-on PR's.
    func noteJobEvent(_ params: JSONValue) {
        surface.noteJobEvent(params)
    }

    /// The legacy Add Host to Scope… path, reused by an out-of-scope origin row.
    func openScopeSheet(for host: String) {
        session.scopeSheetHost = host
        session.scopeSheetVisible = true
    }

    /// The tools list or the scope changed: `launchRefusal` is computed, so only the
    /// L4 scope — which lives on the bus — has to be read again.
    func refreshGate() {
        guard surfaceOffered else { return }
        Task { await refreshL4Scope() }
    }

    /// Takes a status line down after a while, and only while it is still the line
    /// this state put up.
    private func clearStatusLine(_ line: String, after delay: Duration) {
        savedLine = line
        Task { [weak self] in
            try? await Task.sleep(for: delay)
            guard let self, savedLine == line, surface.statusLine == line else { return }
            surface.setStatusLine(nil)
            savedLine = nil
        }
    }
}

/// The Scan page. Which page that is depends only on what the bus lists (D11):
/// the scanner-v2 surface when `scan.start` is there, the legacy one-shot crawl
/// form when only `scan.discover` is, and an unavailable state otherwise. Opening
/// any of them never scans.
struct ScanPanel: View {
    @Bindable var state: ScanPanelState

    var body: some View {
        switch state.mode {
        case .surface: ScanSurfaceView(state: state)
        case .legacy: LegacyScanPanel(state: state)
        case .unavailable: ScanUnavailablePanel()
        }
    }
}

/// The core lists no scanner verb at all: degraded, never broken.
private struct ScanUnavailablePanel: View {
    var body: some View {
        ContentUnavailableView {
            Label("Scan is unavailable", systemImage: Tok.Glyph.search)
        } description: {
            Text("The core lists neither scan.start nor scan.discover (it needs the scanner plugin).")
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(Tok.Ground.surface.color)
        .gridArea("scan", inset: 0)
    }
}

/// The scanner-v2 Scan page (D2): the page header, the four tabs on one strip,
/// the selected tab, and the page's modals. The poll task lives here, so the page
/// reads `scan.list` / `scan.status` / `scan.issues` exactly while it is on screen
/// and stops the moment the operator leaves it (D8).
struct ScanSurfaceView: View {
    @Bindable var state: ScanPanelState

    var body: some View {
        VStack(spacing: 0) {
            PageHeader("Scan") {
                // The cached list shows first; the spinner appears only when a
                // profiles load has been in flight for more than 500 ms (D11).
                if state.profilesLoadingSlow {
                    ProgressView()
                        .controlSize(.small)
                        .help("Loading profiles")
                }
            }
            PaneTabs(title: "", tabs: tabs, selected: selection) { EmptyView() }
            tab
                .frame(maxWidth: .infinity, maxHeight: .infinity)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(Tok.Ground.surface.color)
        .scanModals(state)
        .task(id: state.pollGeneration) { await state.poll() }
        .onChange(of: state.session.tools) { state.refreshGate() }
        .onChange(of: state.session.scopeHosts) { state.refreshGate() }
        .gridArea("scan", inset: 0)
    }

    private var tabs: [ScanTabItem] {
        ScanTab.allCases.map { ScanTabItem(tab: $0, title: state.surface.tabTitle($0)) }
    }

    private var selection: Binding<ScanTabItem> {
        Binding(
            get: { ScanTabItem(tab: state.surface.tab, title: state.surface.tabTitle(state.surface.tab)) },
            set: { state.surface.tab = $0.tab }
        )
    }

    @ViewBuilder private var tab: some View {
        switch state.surface.tab {
        case .profiles: ScanProfilesTab(state: state)
        case .jobs: ScanJobsTab(state: state)
        case .sitemap: ScanSitemapTab(state: state)
        case .issues: ScanIssuesTab(state: state)
        }
    }
}

/// `PaneTabs` renders a tab's `description`, so the counted title ("Jobs 2") rides
/// along as the description while identity stays the `ScanTab` itself — a count
/// that changes must not look like a different tab.
struct ScanTabItem: Hashable, CustomStringConvertible {
    var tab: ScanTab
    var title: String

    var description: String { title }

    static func == (lhs: ScanTabItem, rhs: ScanTabItem) -> Bool { lhs.tab == rhs.tab }

    func hash(into hasher: inout Hasher) { hasher.combine(tab) }
}

/// The legacy Scan page, shown when the core lists `scan.discover` but not
/// `scan.start` (D11): a launch bar on top (target bound to the scope, depth and
/// page budget from the tool schema), then a master list of endpoints and
/// injection points on the left and the selected injection point on the right.
struct LegacyScanPanel: View {
    @Bindable var state: ScanPanelState

    var body: some View {
        VStack(spacing: 0) {
            if state.offered {
                launchBar
                    .gridProbe("scan-launch", area: "scan", edge: nil)
                Rule()
                HStack(spacing: 0) {
                    lists
                        .frame(width: 320)
                        .gridProbe("scan-lists", area: "scan", edge: nil)
                    VRule()
                    ScanPointDetail(state: state)
                        .frame(maxWidth: .infinity, maxHeight: .infinity)
                }
            } else {
                unavailable
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(Tok.Ground.surface.color)
        .gridArea("scan", inset: 0)
        // Opening the page seeds the form; it never starts a crawl.
        .onAppear { state.syncForm() }
        .onChange(of: state.session.tools) { state.syncForm() }
        .onChange(of: state.session.scopeHosts) { state.syncForm() }
    }

    // MARK: Launch

    private var launchBar: some View {
        VStack(alignment: .leading, spacing: Space.sm) {
            HStack(alignment: .bottom, spacing: Space.md) {
                field("Target") {
                    TextField("http://host/", text: $state.form.target)
                        .scanFieldChrome()
                        .onSubmit { if state.canLaunch { launch() } }
                }
                field("In scope") {
                    FlatMenu(title: "Choose host", width: 160) {
                        if state.scopeChoices.isEmpty {
                            Button("No concrete host in scope") {}.disabled(true)
                        }
                        ForEach(state.scopeChoices, id: \.self) { host in
                            Button(host) { state.form.target = ScanForm.seedURL(for: host) }
                        }
                    }
                }
                .frame(width: 160)
                if state.form.hasMaxDepth {
                    field("Depth") { TextField("auto", text: $state.form.maxDepth).scanFieldChrome() }
                        .frame(width: 64)
                }
                if state.form.hasMaxPages {
                    field("Pages") { TextField("auto", text: $state.form.maxPages).scanFieldChrome() }
                        .frame(width: 64)
                }
                PrimaryButton(state.running ? "Scanning…" : "Scan", hint: "⌘⏎") { launch() }
                    .disabled(!state.canLaunch)
                    .keyboardShortcut(.return, modifiers: .command)
                    .help(state.refusal ?? "Crawl the target and list its endpoints and injection points (⌘⏎)")
            }
            status
        }
        .padding(.horizontal, Space.md)
        .padding(.vertical, Space.sm)
    }

    /// One line: what is in flight, what went wrong, why the target cannot launch, or what the last crawl found.
    private var status: some View {
        HStack(spacing: Space.sm) {
            if state.running {
                ProgressView().controlSize(.small)
                Text("Crawling \(state.model.target ?? "")…").foregroundStyle(Tok.Ink.secondary.color)
                FlatButton("Cancel") { state.cancelScan() }
            } else if let error = state.error {
                Text(error).foregroundStyle(Tok.Status.serverError.color)
            } else if let refusal = state.refusal {
                Text(refusal).foregroundStyle(Tok.Intercept.deep.color)
                if let host = state.form.authority {
                    FlatButton("Add Host to Scope…") {
                        state.session.scopeSheetHost = host
                        state.session.scopeSheetVisible = true
                    }
                }
            } else if state.model.hasResult {
                Text(state.model.summary).foregroundStyle(Tok.Ink.secondary.color)
                if let reason = state.model.stoppedReason {
                    Text("stopped: \(reason)").foregroundStyle(Tok.Intercept.deep.color)
                }
            } else {
                Text("Idle — opening this page never scans. Scan crawls the target above.").foregroundStyle(Tok.Ink.tertiary.color)
            }
            Spacer(minLength: 0)
        }
        .font(Tok.Face.ui(Tok.Typography.Size.sm))
        .lineLimit(1)
        .frame(minHeight: Tok.Size.control)
    }

    private func launch() { state.start() }

    private func field<Content: View>(_ label: String, @ViewBuilder content: () -> Content) -> some View {
        VStack(alignment: .leading, spacing: Space.xs) {
            Text(label).font(Tok.Face.ui(Tok.Typography.Size.sm)).foregroundStyle(Tok.Ink.secondary.color)
            content()
        }
    }

    // MARK: Results

    /// Endpoints is a supporting list: cap it to its rows (up to a few) so a short
    /// crawl leaves no dead band, and let the injection-points list take the rest.
    private static let maxEndpointRows = 8

    private var endpointListHeight: CGFloat {
        CGFloat(min(max(state.endpoints.count, 2), Self.maxEndpointRows)) * Tok.Size.Row.dense
    }

    private var lists: some View {
        VStack(spacing: 0) {
            sectionHead("Endpoints", count: state.endpoints.count)
            endpointList
                .frame(height: endpointListHeight)
            Rule()
            sectionHead("Injection points", count: state.points.count)
            pointList
                .frame(maxHeight: .infinity)
        }
    }

    private func sectionHead(_ title: String, count: Int) -> some View {
        HStack {
            Text(title.uppercased()).font(Tok.Face.ui(Tok.Typography.Size.xs, .medium)).tracking(0.5)
                .foregroundStyle(Tok.Ink.tertiary.color)
            Spacer(minLength: Space.sm)
            Text("\(count)").font(Tok.Face.ui(Tok.Typography.Size.sm)).foregroundStyle(Tok.Ink.tertiary.color)
        }
        .padding(.horizontal, Space.md)
        .frame(height: Tok.Size.columnHeader)
        .overlay(alignment: .bottom) { Rule() }
        .accessibilityElement(children: .combine)
        .accessibilityAddTraits(.isHeader)
    }

    @ViewBuilder private var endpointList: some View {
        if state.endpoints.isEmpty {
            placeholder(state.model.hasResult ? "No endpoints reached" : "None yet — Scan crawls an in-scope target")
        } else {
            ScrollView {
                LazyVStack(spacing: 0) {
                    // An endpoint the result links to a flow opens it, like an injection point; the rest stay plain.
                    ForEach(Array(state.endpoints.enumerated()), id: \.offset) { _, url in
                        ScanEndpointRow(url: url, linked: state.isLinked(endpoint: url), openable: state.canOpen(endpoint: url)) {
                            state.open(endpoint: url)
                        }
                    }
                }
            }
        }
    }

    @ViewBuilder private var pointList: some View {
        if state.points.isEmpty {
            placeholder(state.model.hasResult ? "No injection points found" : "None yet")
        } else {
            ScrollView {
                LazyVStack(spacing: 0) {
                    ForEach(Array(state.points.enumerated()), id: \.offset) { index, point in
                        ScanPointRow(point: point, selected: index == state.model.selected)
                            .contentShape(Rectangle())
                            .onTapGesture(count: 2) {
                                state.select(index)
                                state.open(point)
                            }
                            .onTapGesture { state.select(index) }
                    }
                }
            }
        }
    }

    private func placeholder(_ text: String) -> some View {
        Text(text)
            .font(Tok.Face.ui(Tok.Typography.Size.md))
            .foregroundStyle(Tok.Ink.tertiary.color)
            .padding(.horizontal, Space.md)
            .padding(.vertical, Space.sm)
            .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
    }

    /// The core does not list `scan.discover` (no scanner plugin): degraded, never broken.
    private var unavailable: some View {
        ContentUnavailableView {
            Label("Scan is unavailable", systemImage: Tok.Glyph.search)
        } description: {
            Text("scan.discover is not on this bus (it needs the scanner plugin).")
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}

/// One reached endpoint, its URL exactly as the scanner returned it. When the result
/// links the endpoint to the flow it was fetched in (`linked`), the row opens that flow:
/// double-click, the trailing chevron, or Open Flow in the context menu. An unlinked row
/// stays a plain, selectable URL.
struct ScanEndpointRow: View {
    var url: String
    /// The result carries a flow id for this endpoint.
    var linked: Bool
    /// That flow is still in the flow list, so opening it can succeed.
    var openable: Bool
    /// The chevron's tooltip while the flow can be opened.
    var help: String = "Open Flow"
    var open: () -> Void

    var body: some View {
        HStack(spacing: Space.sm) {
            if linked {
                // Double-click opens the flow, so the text is not selectable here; Copy URL stays in the menu.
                label
                Button(action: open) {
                    Image(systemName: Tok.Glyph.chevron)
                        .font(.system(size: Tok.Size.iconInline))
                        .foregroundStyle(Tok.Ink.tertiary.color)
                        .frame(width: Space.lg, height: Tok.Size.Row.dense)
                        .contentShape(Rectangle())
                }
                .buttonStyle(PressStyle())
                .disabled(!openable)
                .help(openable ? help : "This flow is no longer in the flow list (cleared, or not captured here).")
            } else {
                label.textSelection(.enabled)
            }
        }
        .padding(.leading, Space.md)
        .padding(.trailing, linked ? Space.sm : Space.md)
        .frame(maxWidth: .infinity, minHeight: Tok.Size.Row.dense, alignment: .leading)
        .contentShape(Rectangle())
        .opensOnDoubleClick(linked, open)
        .overlay(alignment: .bottom) { Rule(color: Tok.Line.rule) }
        .contextMenu {
            if linked {
                Button("Open Flow", action: open).disabled(!openable)
            }
            Button("Copy URL") {
                Pasteboard.copy(url, sensitive: true)
            }
        }
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(url)
        .accessibilityAddTraits(linked ? .isButton : [])
        .accessibilityActions {
            if linked { Button("Open Flow", action: open) }
        }
    }

    private var label: some View {
        Text(url)
            .font(Tok.Face.data(Tok.Typography.Size.md))
            .foregroundStyle(Tok.Ink.primary.color)
            .lineLimit(1)
            .truncationMode(.middle)
            .frame(maxWidth: .infinity, alignment: .leading)
    }
}

/// One injection point: name and location, then the example exactly as the scanner returned it.
struct ScanPointRow: View {
    var point: InjectionPoint
    var selected: Bool

    var body: some View {
        VStack(alignment: .leading, spacing: Space.xs) {
            HStack(spacing: Space.sm) {
                Text(point.name).font(Tok.Face.ui(Tok.Typography.Size.md, .medium))
                    .foregroundStyle(Tok.Ink.primary.color).lineLimit(1)
                Spacer(minLength: Space.xs)
                // The neutral grey pill pair: a location is not a severity.
                Badge(text: point.location, pair: Tok.Severity.info, uppercase: false)
            }
            Text(point.example.isEmpty ? "—" : point.example)
                .font(Tok.Face.data(Tok.Typography.Size.sm))
                .foregroundStyle(Tok.Ink.secondary.color)
                .lineLimit(1)
                .truncationMode(.tail)
        }
        .padding(.horizontal, Space.md)
        .padding(.vertical, Space.sm)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(selected ? Tok.Ground.active.color : .clear)
        .overlay(alignment: .bottom) { Rule(color: Tok.Line.rule) }
        .accessibilityElement(children: .ignore)
        .accessibilityLabel("\(point.name), \(point.location), \(point.example.isEmpty ? "no example" : point.example)")
        .accessibilityAddTraits(selected ? .isSelected : [])
    }
}

/// The selected injection point: where it lives, its example verbatim, and the flow it opens.
struct ScanPointDetail: View {
    @Bindable var state: ScanPanelState

    var body: some View {
        if let point = state.model.selectedPoint {
            VStack(spacing: 0) {
                header(point)
                Rule()
                ScrollView {
                    VStack(alignment: .leading, spacing: Space.lg) {
                        ScanSectionTitle("Example")
                        Text(point.example.isEmpty ? "(empty)" : point.example)
                            .font(Tok.Face.data(Tok.Typography.Size.md))
                            .foregroundStyle(point.example.isEmpty ? Tok.Ink.tertiary.color : Tok.Ink.primary.color)
                            .textSelection(.enabled)
                            .padding(Space.sm)
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .background(Tok.Ground.raised.color, in: RoundedRectangle(cornerRadius: Tok.Radius.control))
                        Hint(text: "Shown as the scanner returned it; secrets are redacted at the source.")

                        ScanSectionTitle("Flow")
                        flowReference(point)
                        if !state.canOpen(point) {
                            Hint(text: "This flow is no longer in the flow list (cleared, or not captured here).")
                        }
                    }
                    .padding(Space.md)
                    .frame(maxWidth: .infinity, alignment: .leading)
                }
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        } else if state.model.hasResult {
            scanSummary
        } else {
            ContentUnavailableView {
                Label("No scan yet", systemImage: Tok.Glyph.search)
            } description: {
                Text("Scan an in-scope target above to crawl its endpoints and injection points.")
            } actions: {
                PrimaryButton(state.running ? "Scanning…" : "Scan") { state.start() }
                    .disabled(!state.canLaunch)
                    .help(state.refusal ?? "Crawl the target above (⌘⏎)")
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
        }
    }

    /// With a result but nothing selected, the detail pane shows the crawl's coverage
    /// instead of sitting empty: counts and the injection points broken down by type.
    private var scanSummary: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: Space.lg) {
                ScanSectionTitle("Coverage")
                HStack(alignment: .top, spacing: Space.section) {
                    stat("Endpoints", "\(state.endpoints.count)")
                    stat("Injection points", "\(state.points.count)")
                }
                if !state.points.isEmpty {
                    ScanSectionTitle("Injection points by type")
                    typeBreakdown
                }
                if let reason = state.model.stoppedReason {
                    Hint(text: "Crawl stopped: \(reason)")
                }
                Hint(text: "Pick an injection point on the left to see its example and open its flow.")
            }
            .padding(Space.md)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
    }

    /// Injection points grouped by `location` (query / body_param / cookie / …), each a
    /// colored proportion bar — the audit's injection-type distribution.
    private var typeBreakdown: some View {
        let groups: [(location: String, count: Int)] = Dictionary(grouping: state.points, by: \.location)
            .map { (location: $0.key, count: $0.value.count) }
            .sorted { $0.count == $1.count ? $0.location < $1.location : $0.count > $1.count }
        let total = max(1, state.points.count)
        // Kept narrow so each count sits by its bar's end, not 500 pt away.
        return VStack(alignment: .leading, spacing: Space.sm) {
            ForEach(Array(groups.enumerated()), id: \.offset) { item in
                let group = item.element
                HStack(spacing: Space.md) {
                    Text(group.location)
                        .font(Tok.Face.data(Tok.Typography.Size.sm)).foregroundStyle(Tok.Ink.secondary.color)
                        .frame(width: 120, alignment: .leading).lineLimit(1).truncationMode(.tail)
                    GeometryReader { geo in
                        RoundedRectangle(cornerRadius: Tok.Radius.badge)
                            .fill(Self.typeColor(item.offset))
                            .frame(width: max(2, geo.size.width * Double(group.count) / Double(total)))
                    }
                    .frame(height: 8)
                    Text("\(group.count)")
                        .font(Tok.Face.data(Tok.Typography.Size.sm, .medium)).foregroundStyle(Tok.Ink.primary.color)
                        .frame(width: 32, alignment: .trailing)
                }
                .accessibilityElement(children: .ignore)
                .accessibilityLabel("\(group.location), \(group.count)")
            }
        }
        .frame(maxWidth: 320, alignment: .leading)
    }

    private static let typeColors: [Color] = ChartPalette.categorical

    private static func typeColor(_ index: Int) -> Color { typeColors[index % typeColors.count] }

    private func stat(_ label: String, _ value: String) -> some View {
        VStack(alignment: .leading, spacing: Space.xs) {
            Text(label.uppercased()).font(Tok.Face.ui(Tok.Typography.Size.xs, .medium)).tracking(0.6)
                .foregroundStyle(Tok.Ink.tertiary.color)
            Text(value).font(Tok.Face.data(Tok.Typography.Size.xl, .medium)).foregroundStyle(Tok.Ink.primary.color)
                .lineLimit(1).minimumScaleFactor(0.7)
        }
    }

    /// The injection point's flow as a method badge + URL (when still listed), not a raw UUID.
    @ViewBuilder private func flowReference(_ point: InjectionPoint) -> some View {
        if let row = state.session.rows.first(where: { $0.id == point.flowID }) {
            HStack(spacing: Space.sm) {
                Badge(text: row.method.label, pair: row.method.badge)
                Text("\(row.authority)\(row.path)")
                    .font(Tok.Face.data(Tok.Typography.Size.md)).foregroundStyle(Tok.Ink.primary.color)
                    .lineLimit(1).truncationMode(.middle).textSelection(.enabled)
            }
        } else {
            Text(point.flow)
                .font(Tok.Face.data(Tok.Typography.Size.sm)).foregroundStyle(Tok.Ink.tertiary.color)
                .textSelection(.enabled)
        }
    }

    private func header(_ point: InjectionPoint) -> some View {
        HStack(spacing: Space.md) {
            Text(point.name).font(Tok.Face.ui(Tok.Typography.Size.xl, .medium)).foregroundStyle(Tok.Ink.primary.color)
                .lineLimit(1)
            Badge(text: point.location, pair: Tok.Severity.info, uppercase: false)
            Spacer(minLength: Space.sm)
            FlatButton("Open Flow") { state.open(point) }
                .disabled(!state.canOpen(point))
        }
        .padding(.horizontal, Space.md)
        .frame(height: Tok.Size.inspectorHeader)
    }
}

// MARK: - Shared chrome

/// A section title on any Scan tab: tracked xs caps in tertiary, read as a
/// header. With `count`, the count sits beside it in the same ink (the site
/// map's "INSERTION POINTS 3").
struct ScanSectionTitle: View {
    var title: String
    var count: Int?

    init(_ title: String, count: Int? = nil) {
        self.title = title
        self.count = count
    }

    var body: some View {
        HStack(spacing: Space.sm) {
            Text(title.uppercased())
                .font(Tok.Face.ui(Tok.Typography.Size.xs, .medium))
                .tracking(0.6)
                .foregroundStyle(Tok.Ink.tertiary.color)
            if let count {
                Text("\(count)")
                    .font(Tok.Face.ui(Tok.Typography.Size.xs))
                    .foregroundStyle(Tok.Ink.tertiary.color)
                    .monospacedDigit()
            }
        }
        .accessibilityElement(children: .combine)
        .accessibilityAddTraits(.isHeader)
    }
}

/// A failed read or update, inline (D11): the list it could not refresh stays
/// as it was. Selectable so the reason can be copied into a bug report. `inset`
/// is the list inset it sits in; 0 inside a block that carries its own.
struct ScanInlineError: View {
    var text: String
    var inset: CGFloat = Space.md

    var body: some View {
        Text(text)
            .font(Tok.Face.ui(Tok.Typography.Size.sm))
            .foregroundStyle(Tok.Status.serverError.color)
            .lineLimit(2)
            .textSelection(.enabled)
            .padding(.horizontal, inset)
            .padding(.vertical, Space.xs)
            .frame(maxWidth: .infinity, alignment: .leading)
            .accessibilityElement(children: .ignore)
            .accessibilityLabel("Error: \(text)")
    }
}

/// A label over a value; `—` in tertiary for a value the bus has not told us yet.
struct ScanStat: View {
    var label: String
    var value: String?

    init(_ label: String, _ value: String?) {
        self.label = label
        self.value = value
    }

    var body: some View {
        VStack(alignment: .leading, spacing: Space.xs) {
            Text(label)
                .font(Tok.Face.ui(Tok.Typography.Size.xs))
                .foregroundStyle(Tok.Ink.tertiary.color)
            Text(value ?? "—")
                .font(Tok.Face.data(Tok.Typography.Size.md, .medium))
                .foregroundStyle((value == nil ? Tok.Ink.tertiary : Tok.Ink.primary).color)
                .lineLimit(1)
                .textSelection(.enabled)
        }
    }
}

private extension View {
    /// Runs `action` on a double-click when `enabled`. Left off otherwise so an unlinked
    /// row's selectable text keeps its own double-click.
    @ViewBuilder func opensOnDoubleClick(_ enabled: Bool, _ action: @escaping () -> Void) -> some View {
        if enabled { onTapGesture(count: 2, perform: action) } else { self }
    }
}

extension View {
    /// The Scan page's text field, on every tab: plain, on `surface`, a
    /// control-border outline. `face` is the data face unless the field holds
    /// prose (the Issues note).
    func scanFieldChrome(face: Font = Tok.Face.data(Tok.Typography.Size.md)) -> some View {
        textFieldStyle(.plain)
            .font(face)
            .padding(.horizontal, Space.sm)
            .frame(height: Tok.Size.control)
            .background(Tok.Ground.surface.color, in: RoundedRectangle(cornerRadius: Tok.Radius.control))
            .overlay(RoundedRectangle(cornerRadius: Tok.Radius.control).strokeBorder(Tok.Line.control.color))
    }
}
