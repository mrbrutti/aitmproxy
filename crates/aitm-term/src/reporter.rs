//! The in-place `Reporter`: the `Renderer` state machine, the render thread
//! and the `Phase` API (spec D4, T4, T5, M1, M1p, M7; plan task 6, calls C3,
//! C4, C5, C6, C7, C10, C11, C23, C24).
//!
//! Every human-facing line `aitm` writes during startup goes through one
//! [`Reporter`]. A public call becomes a [`Msg`] on a `std::sync::mpsc`
//! channel; one OS thread named `aitm-term` owns the sink and the [`Renderer`]
//! state machine that draws. The thread starts lazily on the first message
//! and sleeps on `recv_timeout(100 ms)` only while a phase is live, so the
//! spinner advances one frame per wake-up and nothing runs when nothing is
//! live. [`Reporter::card`], [`Reporter::error`], [`Reporter::finish`] and
//! [`Reporter::finish_and_clear`] block on an acknowledgement (2 s at most);
//! `finish` closes the channel, joins the thread and leaves the reporter in a
//! synchronous plain-line mode so a late warning still prints (C10).
//!
//! The `Renderer` is pure over its inputs: time comes from a [`Clock`], the
//! terminal width from an injected probe, and every byte goes to one
//! `io::Write`. Unit tests drive `handle` and `tick` directly with a fake
//! clock and an in-memory sink and never sleep.
//!
//! Rendering has two forms, chosen by `caps.animate` (C6). The **rich** form
//! draws a live region in place: a frame is a synchronized update
//! (`ESC[?2026h` … `ESC[?2026l`) that moves the cursor up over the live lines
//! drawn last time, rewrites each line after `ESC[1G ESC[2K` (collapsed and
//! warning lines first, then the live lines) and leaves the cursor below the
//! last live line, visible (C3). The **plain** form writes one line per
//! event and never emits an escape byte or a carriage return. When the caps
//! select ASCII glyphs, every written line also has `·` and `…` replaced by
//! the ASCII twins, so a `LANG=C` terminal sees no byte above 0x7f (spec
//! AC-W1-10; paths and URLs contain neither character).

use std::borrow::Cow;
use std::fmt;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender, SyncSender};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, PoisonError};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use crossterm::cursor::{MoveToColumn, MoveUp};
use crossterm::terminal::{BeginSynchronizedUpdate, Clear, ClearType, EndSynchronizedUpdate};
use crossterm::Command;

use crate::caps::Caps;
pub use crate::caps::Verbosity;
use crate::card::Card;
use crate::clock::{Clock, SystemClock};
use crate::error::ErrorReport;
use crate::event::{EventSender, UiEvent};
use crate::glyphs::Glyphs;
use crate::style::{paint, Role};
use crate::text;

/// Spec T4: a phase younger than this is not drawn, and a `done`/`fail` of
/// such a phase prints nothing in one-shot mode (C4). It is also the ticker's
/// wake-up interval, so the spinner runs at ten frames a second.
pub const FIRST_DRAW_DELAY: Duration = Duration::from_millis(100);

/// How long a blocking call waits for the render thread before giving up on
/// it (plan C10). A sink that blocks this long is a stalled pipe, and the
/// thread is abandoned rather than freezing startup.
const ACK_TIMEOUT: Duration = Duration::from_secs(2);

const THREAD_NAME: &str = "aitm-term";

/// The indent under the header (spec T3).
const INDENT: &str = "  ";

/// What the API sends to the render thread.
enum Msg {
    Header {
        wordmark: String,
        version: String,
    },
    PhaseStart {
        id: u64,
        label: String,
        at: Instant,
    },
    Progress {
        id: u64,
        done: u64,
        total: Option<u64>,
    },
    PhaseDone {
        id: u64,
        summary: String,
        at: Instant,
    },
    PhaseFail {
        id: u64,
        what: String,
        at: Instant,
    },
    Warn(String),
    Event(UiEvent),
    Card(Card),
    Error {
        report: ErrorReport,
        /// The `~` home for the rich panel (`Reporter::display_home`).
        home: Option<PathBuf>,
    },
    Checklist(bool),
    /// Flush the sink and acknowledge.
    Flush(SyncSender<()>),
    /// Erase everything below the header (rich), flush and acknowledge.
    Clear(SyncSender<()>),
}

/// A phase that has started and not ended.
struct Live {
    id: u64,
    label: String,
    started: Instant,
    progress: Option<(u64, Option<u64>)>,
}

/// The drawing state machine. It owns the sink and knows nothing about
/// threads or channels; [`Renderer::handle`] applies one message and
/// [`Renderer::tick`] advances the spinner.
struct Renderer {
    caps: Caps,
    glyphs: &'static Glyphs,
    verbosity: Verbosity,
    checklist: bool,
    clock: Arc<dyn Clock>,
    sink: Box<dyn Write + Send>,
    /// The terminal width, probed on every frame (spec T5); `None` falls back
    /// to `caps.width`.
    width_probe: Box<dyn Fn() -> Option<u16> + Send>,
    running: Vec<Live>,
    /// Lines that scroll above the live region on the next frame.
    pending: Vec<String>,
    /// Live lines on screen after the last frame.
    live_lines_drawn: usize,
    /// Lines below the header that stay (collapsed phases, warnings, the
    /// card, a panel), for `finish_and_clear`.
    scrolled: usize,
    /// 1 once the rich header's trailing blank line is on screen.
    header_blank: usize,
    /// Spinner frame index.
    frame: usize,
}

impl Renderer {
    fn new(
        caps: Caps,
        verbosity: Verbosity,
        checklist: bool,
        clock: Arc<dyn Clock>,
        sink: Box<dyn Write + Send>,
        width_probe: Box<dyn Fn() -> Option<u16> + Send>,
    ) -> Renderer {
        Renderer {
            caps,
            glyphs: Glyphs::for_caps(&caps),
            verbosity,
            checklist,
            clock,
            sink,
            width_probe,
            running: Vec::new(),
            pending: Vec::new(),
            live_lines_drawn: 0,
            scrolled: 0,
            header_blank: 0,
            frame: 0,
        }
    }

    fn rich(&self) -> bool {
        self.caps.animate
    }

    fn quiet(&self) -> bool {
        self.verbosity == Verbosity::Quiet
    }

    fn has_live(&self) -> bool {
        !self.running.is_empty()
    }

    /// After `finish`: plain lines only, on the caller's thread (C10). Phases
    /// still open keep their start time so a late `done` prints its line.
    fn into_plain(mut self) -> Renderer {
        self.caps.animate = false;
        self
    }

    fn width(&self) -> usize {
        usize::from((self.width_probe)().unwrap_or(self.caps.width))
    }

    /// The one place bytes leave the renderer. ASCII glyph sets also get
    /// `·` → `-` and `…` → `...` (the table's own `sep` and `ellipsis`), so a
    /// `LANG=C` terminal sees no byte above 0x7f. Write errors are ignored on
    /// purpose: a closed stderr never ends startup (C10).
    fn write_text(&mut self, s: &str) {
        let s = self.asciify(s);
        let _ = self.sink.write_all(s.as_bytes());
        let _ = self.sink.flush();
    }

    fn asciify<'a>(&self, s: &'a str) -> Cow<'a, str> {
        if self.caps.unicode || !s.contains(['·', '…']) {
            return Cow::Borrowed(s);
        }
        Cow::Owned(
            s.replace('·', self.glyphs.sep)
                .replace('…', self.glyphs.ellipsis),
        )
    }

    fn handle(&mut self, msg: Msg) {
        match msg {
            Msg::Header { wordmark, version } => self.header(&wordmark, &version),
            Msg::PhaseStart { id, label, at } => {
                // Quiet drops phases entirely, so there is nothing to track.
                if !self.quiet() {
                    self.running.push(Live {
                        id,
                        label,
                        started: at,
                        progress: None,
                    });
                }
            }
            Msg::Progress { id, done, total } => {
                if let Some(live) = self.running.iter_mut().find(|l| l.id == id) {
                    live.progress = Some((done, total));
                }
            }
            Msg::PhaseDone { id, summary, at } => {
                if let Some(elapsed) = self.take_phase(id, at) {
                    let line = self.done_line(&summary, elapsed);
                    self.emit(line);
                }
            }
            Msg::PhaseFail { id, what, at } => {
                if self.take_phase(id, at).is_some() {
                    let line = self.fail_line(&what);
                    self.emit(line);
                }
            }
            Msg::Warn(line) => {
                let line = if self.rich() {
                    format!(
                        "{INDENT}{} {line}",
                        paint(&self.caps, Role::Warning, self.glyphs.warn)
                    )
                } else {
                    format!("warning: {line}")
                };
                self.emit(line);
            }
            Msg::Event(ev) => {
                let line = self.event_line(&ev);
                self.emit(line);
            }
            Msg::Card(card) => self.card(&card),
            Msg::Error { report, home } => self.error(&report, home.as_deref()),
            Msg::Checklist(on) => self.checklist = on,
            Msg::Flush(ack) => {
                let _ = self.sink.flush();
                let _ = ack.send(());
            }
            Msg::Clear(ack) => {
                self.clear();
                let _ = ack.send(());
            }
        }
    }

    /// Removes the phase and says whether its end line prints: always with
    /// the checklist on, otherwise only when the phase reached the
    /// first-draw delay (C4). `None` for an unknown id (a phase started under
    /// `Quiet`, or already ended).
    fn take_phase(&mut self, id: u64, at: Instant) -> Option<Duration> {
        let pos = self.running.iter().position(|l| l.id == id)?;
        let live = self.running.remove(pos);
        let elapsed = at.saturating_duration_since(live.started);
        (self.checklist || elapsed >= FIRST_DRAW_DELAY).then_some(elapsed)
    }

    fn done_line(&self, summary: &str, elapsed: Duration) -> String {
        let duration = (self.verbosity >= Verbosity::Verbose)
            .then(|| format!(" {} in {} ms", self.glyphs.sep, elapsed.as_millis()));
        if self.rich() {
            let mut line = format!(
                "{INDENT}{} {summary}",
                paint(&self.caps, Role::Success, self.glyphs.done)
            );
            if let Some(duration) = duration {
                line.push_str(&paint(&self.caps, Role::Dim, &duration));
            }
            line
        } else {
            format!("{summary}{}", duration.unwrap_or_default())
        }
    }

    fn fail_line(&self, what: &str) -> String {
        if self.rich() {
            format!(
                "{INDENT}{} {what}",
                paint(&self.caps, Role::Danger, self.glyphs.failed)
            )
        } else {
            format!("error: {what}")
        }
    }

    /// `! message · k=v · k=v` (fields dim) in rich mode, `warning: message
    /// k=v` in plain; ERROR events use the failed glyph and `error:`. An
    /// event with no `message` field names its target instead, so a
    /// fields-only event never prints a bare `warning: ` line.
    fn event_line(&self, ev: &UiEvent) -> String {
        let is_error = ev.level == tracing::Level::ERROR;
        let text = if ev.message.is_empty() {
            ev.target.as_str()
        } else {
            ev.message.as_str()
        };
        if self.rich() {
            let glyph = if is_error {
                paint(&self.caps, Role::Danger, self.glyphs.failed)
            } else {
                paint(&self.caps, Role::Warning, self.glyphs.warn)
            };
            let mut line = format!("{INDENT}{glyph} {text}");
            if !ev.fields.is_empty() {
                let tail: String = ev
                    .fields
                    .iter()
                    .map(|(k, v)| format!(" {} {k}={v}", self.glyphs.sep))
                    .collect();
                line.push_str(&paint(&self.caps, Role::Dim, &tail));
            }
            line
        } else {
            let prefix = if is_error { "error: " } else { "warning: " };
            let mut line = format!("{prefix}{text}");
            for (k, v) in &ev.fields {
                line.push(' ');
                line.push_str(k);
                line.push('=');
                line.push_str(v);
            }
            line
        }
    }

    /// A finished line: scrolled above the live region in rich mode, written
    /// straight out in plain mode.
    fn emit(&mut self, line: String) {
        if self.rich() {
            self.pending.push(line);
            self.redraw();
        } else {
            self.write_text(&format!("{line}\n"));
        }
    }

    fn header(&mut self, wordmark: &str, version: &str) {
        if self.quiet() {
            return;
        }
        if self.rich() {
            let mut line = String::new();
            if !self.glyphs.mark.is_empty() {
                line.push_str(&paint(&self.caps, Role::Accent, self.glyphs.mark));
                line.push(' ');
            }
            line.push_str(&paint(&self.caps, Role::Accent, wordmark));
            line.push(' ');
            line.push_str(version);
            line.push_str("\n\n");
            self.write_text(&line);
            self.header_blank = 1;
        } else {
            self.write_text(&format!("{wordmark} {version}\n"));
        }
    }

    /// One rich frame: everything pending scrolls above the live region, the
    /// live lines are redrawn, the cursor ends below the last live line.
    /// Nothing is written when there is nothing to show.
    fn redraw(&mut self) {
        let now = self.clock.now();
        let width = self.width();
        let glyphs = self.glyphs;
        let spinner = glyphs.spinner[self.frame % glyphs.spinner.len()];
        let live: Vec<String> = self
            .running
            .iter()
            .filter(|l| now.saturating_duration_since(l.started) >= FIRST_DRAW_DELAY)
            .map(|l| {
                let mut line = format!("{INDENT}{spinner} {}", l.label);
                match l.progress {
                    Some((done, Some(total))) => line.push_str(&format!(" {done}/{total}")),
                    Some((done, None)) => line.push_str(&format!(" {done}")),
                    None => {}
                }
                line
            })
            .collect();
        let pending = std::mem::take(&mut self.pending);
        if pending.is_empty() && live.is_empty() && self.live_lines_drawn == 0 {
            return;
        }

        let mut out = String::new();
        push_cmd(&mut out, BeginSynchronizedUpdate);
        if self.live_lines_drawn > 0 {
            push_cmd(&mut out, MoveUp(clamp_u16(self.live_lines_drawn)));
        }
        for line in pending.iter().chain(live.iter()) {
            push_cmd(&mut out, MoveToColumn(0));
            push_cmd(&mut out, Clear(ClearType::CurrentLine));
            out.push_str(&text::truncate(line, width, glyphs.ellipsis));
            out.push('\n');
        }
        // Live lines that vanished without a collapsed line (none in normal
        // use): blank them and step back over them.
        let shortfall = self
            .live_lines_drawn
            .saturating_sub(pending.len() + live.len());
        for _ in 0..shortfall {
            push_cmd(&mut out, MoveToColumn(0));
            push_cmd(&mut out, Clear(ClearType::CurrentLine));
            out.push('\n');
        }
        if shortfall > 0 {
            push_cmd(&mut out, MoveUp(clamp_u16(shortfall)));
        }
        push_cmd(&mut out, EndSynchronizedUpdate);
        self.write_text(&out);

        self.scrolled += pending.len();
        self.live_lines_drawn = live.len();
    }

    /// One ticker wake-up: redraw the live region when a phase is old enough
    /// to show, advancing the spinner when the region was already on screen.
    fn tick(&mut self) {
        if !self.rich() || self.running.is_empty() {
            return;
        }
        let now = self.clock.now();
        let due = self
            .running
            .iter()
            .any(|l| now.saturating_duration_since(l.started) >= FIRST_DRAW_DELAY);
        if !due {
            return;
        }
        if self.live_lines_drawn > 0 {
            self.frame = self.frame.wrapping_add(1);
        }
        self.redraw();
    }

    fn card(&mut self, card: &Card) {
        if self.quiet() {
            return;
        }
        if self.rich() {
            self.redraw();
            let text = card.render_rich(&self.caps, self.glyphs);
            self.write_text(&format!("\n{text}"));
            // `main` prints the card after every phase has ended. Should a
            // phase still be live, its lines are now above the card and stay
            // there as ordinary lines; the live region restarts below.
            self.scrolled += self.live_lines_drawn + 1 + text.lines().count();
            self.live_lines_drawn = 0;
        } else {
            self.write_text(&card.render_plain(self.glyphs));
        }
    }

    /// The ticker stops: every live phase collapses as a failed line, then a
    /// blank line and the panel follow the live region.
    fn error(&mut self, report: &ErrorReport, home: Option<&Path>) {
        if self.rich() {
            let failed = paint(&self.caps, Role::Danger, self.glyphs.failed);
            for live in std::mem::take(&mut self.running) {
                self.pending
                    .push(format!("{INDENT}{failed} {}", live.label));
            }
            self.redraw();
            let text = report.render_rich(&self.caps, self.glyphs, home);
            self.write_text(&format!("\n{text}"));
            self.scrolled += 1 + text.lines().count();
        } else {
            self.write_text(&report.render_plain(self.glyphs));
        }
    }

    /// `finish_and_clear` (C11, M7): erase every line below the header and
    /// the header's blank line, one `ESC[1A ESC[2K` per line, leaving the
    /// cursor directly under the header. Plain mode has nothing to erase.
    fn clear(&mut self) {
        if self.rich() {
            let lines = self.scrolled + self.live_lines_drawn + self.header_blank;
            let mut out = String::new();
            for _ in 0..lines {
                push_cmd(&mut out, MoveUp(1));
                push_cmd(&mut out, Clear(ClearType::CurrentLine));
            }
            self.write_text(&out);
            self.scrolled = 0;
            self.live_lines_drawn = 0;
            self.header_blank = 0;
            self.running.clear();
        }
        let _ = self.sink.flush();
    }
}

/// Appends a crossterm command's ANSI bytes; writing into a `String` cannot fail.
fn push_cmd(out: &mut String, cmd: impl Command) {
    let _ = cmd.write_ansi(out);
}

fn clamp_u16(n: usize) -> u16 {
    u16::try_from(n).unwrap_or(u16::MAX)
}

/// The render thread's loop: one message at a time, a tick on every 100 ms
/// silence while a phase is live, exit when every sender is gone.
fn run(mut renderer: Renderer, rx: Receiver<Msg>) -> Renderer {
    loop {
        let next = if renderer.rich() && renderer.has_live() {
            rx.recv_timeout(FIRST_DRAW_DELAY)
        } else {
            rx.recv().map_err(|_| RecvTimeoutError::Disconnected)
        };
        match next {
            Ok(msg) => renderer.handle(msg),
            Err(RecvTimeoutError::Timeout) => renderer.tick(),
            Err(RecvTimeoutError::Disconnected) => break,
        }
    }
    renderer
}

/// Where the renderer lives.
enum State {
    /// No message yet: the renderer waits here for the thread to start.
    Idle(Renderer),
    Running {
        tx: Sender<Msg>,
        thread: JoinHandle<Option<Renderer>>,
    },
    /// After `finish`: synchronous plain-line rendering, or nothing when the
    /// thread was abandoned on a stalled sink (its output is stuck anyway).
    Finished(Option<Renderer>),
}

struct Inner {
    caps: Caps,
    glyphs: &'static Glyphs,
    verbosity: Verbosity,
    clock: Arc<dyn Clock>,
    /// Set once by `with_home`; read through `display_home`.
    home: OnceLock<PathBuf>,
    next_id: AtomicU64,
    state: Mutex<State>,
}

/// The reporting handle (spec D4). Cheap to clone; every clone shares one
/// render thread and one sink.
#[derive(Clone)]
pub struct Reporter {
    inner: Arc<Inner>,
}

impl fmt::Debug for Reporter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Reporter")
            .field("caps", &self.inner.caps)
            .field("verbosity", &self.inner.verbosity)
            .finish_non_exhaustive()
    }
}

/// `crossterm::terminal::size()` for the live region; only consulted when the
/// caps animate, which implies a TTY (spec T5).
fn measure_width() -> Option<u16> {
    crossterm::terminal::size()
        .ok()
        .map(|(cols, _rows)| cols)
        .filter(|cols| *cols > 0)
}

impl Reporter {
    /// A reporter over `sink` with the system clock.
    pub fn new(caps: Caps, sink: Box<dyn Write + Send>, verbosity: Verbosity) -> Reporter {
        Self::with_clock(caps, sink, verbosity, Arc::new(SystemClock))
    }

    /// A reporter whose 100 ms rule reads `clock`.
    pub fn with_clock(
        caps: Caps,
        sink: Box<dyn Write + Send>,
        verbosity: Verbosity,
        clock: Arc<dyn Clock>,
    ) -> Reporter {
        let width_probe: Box<dyn Fn() -> Option<u16> + Send> = if caps.animate {
            Box::new(measure_width)
        } else {
            Box::new(|| None)
        };
        let renderer = Renderer::new(
            caps,
            verbosity,
            false,
            Arc::clone(&clock),
            sink,
            width_probe,
        );
        Reporter {
            inner: Arc::new(Inner {
                caps,
                glyphs: Glyphs::for_caps(&caps),
                verbosity,
                clock,
                home: OnceLock::new(),
                next_id: AtomicU64::new(1),
                state: Mutex::new(State::Idle(renderer)),
            }),
        }
    }

    /// A reporter on the process's stderr.
    pub fn stderr(caps: Caps, verbosity: Verbosity) -> Reporter {
        Self::new(caps, Box::new(std::io::stderr()), verbosity)
    }

    /// Checklist policy (C4): `true` (serving modes) prints a done line for
    /// every phase; `false` (one-shot, the default) prints nothing for a
    /// phase that ends within the first-draw delay.
    pub fn checklist(self, on: bool) -> Reporter {
        {
            let mut state = self.lock();
            match &mut *state {
                State::Idle(renderer) | State::Finished(Some(renderer)) => {
                    renderer.checklist = on;
                }
                State::Running { tx, .. } => {
                    let _ = tx.send(Msg::Checklist(on));
                }
                State::Finished(None) => {}
            }
        }
        self
    }

    /// The operator's home, for `~` shortening (C7). Set once; `None` leaves
    /// it unset.
    pub fn with_home(self, home: Option<PathBuf>) -> Reporter {
        if let Some(home) = home {
            let _ = self.inner.home.set(home);
        }
        self
    }

    pub fn caps(&self) -> &Caps {
        &self.inner.caps
    }

    pub fn glyphs(&self) -> &'static Glyphs {
        self.inner.glyphs
    }

    pub fn verbosity(&self) -> Verbosity {
        self.inner.verbosity
    }

    /// The home to shorten paths with: `Some` only when the caps animate
    /// (a pipe may not be the operator's shell; M1p) and a home is set.
    pub fn display_home(&self) -> Option<&Path> {
        if self.inner.caps.animate {
            self.inner.home.get().map(PathBuf::as_path)
        } else {
            None
        }
    }

    /// `p` with the home shortened to `~` when [`Reporter::display_home`]
    /// allows it (spec T6).
    pub fn display_path(&self, p: &Path) -> String {
        text::tilde(p, self.display_home())
    }

    /// The header line (`›•‹ aitmproxy 0.5.11`); serving modes only (C4).
    pub fn header(&self, wordmark: &str, version: &str) {
        self.send(Msg::Header {
            wordmark: wordmark.to_string(),
            version: version.to_string(),
        });
    }

    /// Starts a phase; it ends through [`Phase::done`], [`Phase::fail`],
    /// [`Phase::finish_with`] or, on drop, as `done(label)`.
    pub fn phase(&self, label: &str) -> Phase {
        let id = self.inner.next_id.fetch_add(1, Ordering::Relaxed);
        self.send(Msg::PhaseStart {
            id,
            label: label.to_string(),
            at: self.inner.clock.now(),
        });
        Phase {
            reporter: self.clone(),
            id,
            label: label.to_string(),
            ended: false,
        }
    }

    /// A warning line above the live region (`! …`), `warning: …` when plain.
    pub fn warn(&self, line: &str) {
        self.send(Msg::Warn(line.to_string()));
    }

    /// A WARN+ tracing event folded into the view (spec D7).
    pub fn event(&self, ev: UiEvent) {
        self.send(Msg::Event(ev));
    }

    /// The ready card; blocks until it is on the sink.
    pub fn card(&self, card: &Card) {
        self.send(Msg::Card(card.clone()));
        self.send_and_wait(Msg::Flush);
    }

    /// The error panel; stops the live region first and blocks until the
    /// panel is on the sink.
    pub fn error(&self, report: &ErrorReport) {
        self.send(Msg::Error {
            report: report.clone(),
            home: self.display_home().map(Path::to_path_buf),
        });
        self.send_and_wait(Msg::Flush);
    }

    /// Stops the ticker and joins the render thread, keeping every line on
    /// screen. Idempotent; afterwards every call renders synchronously in
    /// plain-line form (C10).
    pub fn finish(&self) {
        self.shutdown(Msg::Flush);
    }

    /// The TUI handover (D11, C11): like [`Reporter::finish`], but first
    /// erases every line below the header so the cursor sits directly under
    /// it.
    pub fn finish_and_clear(&self) {
        self.shutdown(Msg::Clear);
    }

    /// The sender the `UiLayer` delivers to (plan C9).
    pub fn events(&self) -> EventSender {
        let reporter = self.clone();
        EventSender::new(move |ev| reporter.event(ev))
    }

    /// A poisoned lock still holds a usable state: the renderer never panics
    /// while holding it, and an API caller's panic must not silence the rest
    /// of startup.
    fn lock(&self) -> MutexGuard<'_, State> {
        self.inner
            .state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    fn send(&self, msg: Msg) {
        let mut state = self.lock();
        if matches!(&*state, State::Idle(_)) {
            start_thread(&mut state);
        }
        let unsent = match &mut *state {
            State::Running { tx, .. } => match tx.send(msg) {
                Ok(()) => return,
                Err(mpsc::SendError(msg)) => msg,
            },
            State::Finished(Some(renderer)) => {
                renderer.handle(msg);
                return;
            }
            State::Finished(None) | State::Idle(_) => return,
        };
        // Only reached when the render thread is gone (it panicked): take
        // the renderer back if it survived and continue synchronously.
        let previous = std::mem::replace(&mut *state, State::Finished(None));
        if let State::Running { thread, .. } = previous {
            *state = State::Finished(thread.join().ok().flatten().map(Renderer::into_plain));
        }
        if let State::Finished(Some(renderer)) = &mut *state {
            renderer.handle(unsent);
        }
    }

    /// Sends a message that acknowledges and waits for the acknowledgement,
    /// `ACK_TIMEOUT` at most. A synchronous renderer has already acknowledged
    /// by the time `send` returns; a dropped message disconnects at once.
    fn send_and_wait(&self, make: fn(SyncSender<()>) -> Msg) {
        let (ack, acked) = mpsc::sync_channel(1);
        self.send(make(ack));
        let _ = acked.recv_timeout(ACK_TIMEOUT);
    }

    /// `finish` and `finish_and_clear`: the last message, then close the
    /// channel and join the thread, then switch to synchronous plain lines.
    fn shutdown(&self, last: fn(SyncSender<()>) -> Msg) {
        let mut state = self.lock();
        let previous = std::mem::replace(&mut *state, State::Finished(None));
        *state = match previous {
            State::Idle(mut renderer) => {
                let (ack, _acked) = mpsc::sync_channel(1);
                renderer.handle(last(ack));
                State::Finished(Some(renderer.into_plain()))
            }
            State::Running { tx, thread } => {
                let (ack, acked) = mpsc::sync_channel(1);
                let sent = tx.send(last(ack)).is_ok();
                drop(tx);
                if sent && acked.recv_timeout(ACK_TIMEOUT).is_ok() {
                    State::Finished(thread.join().ok().flatten().map(Renderer::into_plain))
                } else {
                    // Stalled sink or dead thread: abandon it rather than
                    // block startup; later output has nowhere to go.
                    State::Finished(None)
                }
            }
            // A second finish: nothing to drain, nothing to clear.
            finished @ State::Finished(_) => finished,
        };
    }
}

/// Moves the idle renderer onto the `aitm-term` thread. Should the OS refuse
/// a thread, the renderer stays on the caller's side and renders plain lines
/// synchronously, so no output is lost.
fn start_thread(state: &mut State) {
    let State::Idle(renderer) = std::mem::replace(state, State::Finished(None)) else {
        return;
    };
    let (tx, rx) = mpsc::channel();
    let slot = Arc::new(Mutex::new(Some(renderer)));
    let worker = Arc::clone(&slot);
    let spawned = std::thread::Builder::new()
        .name(THREAD_NAME.to_string())
        .spawn(move || {
            let renderer = worker.lock().unwrap_or_else(PoisonError::into_inner).take();
            renderer.map(|renderer| run(renderer, rx))
        });
    *state = match spawned {
        Ok(thread) => State::Running { tx, thread },
        Err(_) => {
            let renderer = slot.lock().unwrap_or_else(PoisonError::into_inner).take();
            State::Finished(renderer.map(Renderer::into_plain))
        }
    };
}

/// A running step of startup (spec D4). Ends exactly once: through
/// [`Phase::done`], [`Phase::fail`], [`Phase::finish_with`] or, when dropped
/// without any of them, as `done(label)`.
pub struct Phase {
    reporter: Reporter,
    id: u64,
    label: String,
    ended: bool,
}

impl Phase {
    /// `done/total` after the label on the live line (`⠹ loading detections
    /// 12/49`); `done` alone when the total is unknown.
    pub fn progress(&self, done: u64, total: Option<u64>) {
        self.reporter.send(Msg::Progress {
            id: self.id,
            done,
            total,
        });
    }

    /// `✓ <summary>`.
    pub fn done(mut self, summary: &str) {
        let at = self.reporter.inner.clock.now();
        self.end(Msg::PhaseDone {
            id: self.id,
            summary: summary.to_string(),
            at,
        });
    }

    /// `✕ <what>`; the panel that follows names the cause.
    pub fn fail(mut self, what: &str) {
        let at = self.reporter.inner.clock.now();
        self.end(Msg::PhaseFail {
            id: self.id,
            what: what.to_string(),
            at,
        });
    }

    /// Ends the phase from a result: `done(summary(&value))` on `Ok`,
    /// `fail(label)` on `Err`. The result is returned unchanged.
    pub fn finish_with<T, E>(
        self,
        result: Result<T, E>,
        summary: impl FnOnce(&T) -> String,
    ) -> Result<T, E> {
        match &result {
            Ok(value) => self.done(&summary(value)),
            Err(_) => {
                let label = self.label.clone();
                self.fail(&label);
            }
        }
        result
    }

    fn end(&mut self, msg: Msg) {
        if !self.ended {
            self.ended = true;
            self.reporter.send(msg);
        }
    }
}

impl Drop for Phase {
    fn drop(&mut self) {
        if !self.ended {
            let at = self.reporter.inner.clock.now();
            let summary = std::mem::take(&mut self.label);
            self.end(Msg::PhaseDone {
                id: self.id,
                summary,
                at,
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::card::{Card, Row};
    use crate::error::ErrorReport;
    use crate::event::UiEvent;
    use crate::glyphs::RICH;
    use crate::testing::{FakeClock, SharedSink};
    use std::sync::mpsc;
    use std::time::{Duration, Instant};

    const BEGIN: &str = "\x1b[?2026h";
    const END: &str = "\x1b[?2026l";
    /// Column 1 then clear the line: what every redrawn line starts with.
    const CLR: &str = "\x1b[1G\x1b[2K";
    const UP1: &str = "\x1b[1A";

    /// A pipe on a UTF-8 locale (M1p): no TTY, no animation, rich glyphs.
    fn utf8_pipe() -> Caps {
        Caps {
            unicode: true,
            ..Caps::plain()
        }
    }

    fn rich_caps(color: bool, unicode: bool) -> Caps {
        Caps {
            tty: true,
            color,
            unicode,
            animate: true,
            width: 80,
            ci: false,
        }
    }

    fn renderer(
        caps: Caps,
        verbosity: Verbosity,
        checklist: bool,
        clock: Arc<FakeClock>,
        sink: &SharedSink,
    ) -> Renderer {
        renderer_with_width(caps, verbosity, checklist, clock, sink, 80)
    }

    fn renderer_with_width(
        caps: Caps,
        verbosity: Verbosity,
        checklist: bool,
        clock: Arc<FakeClock>,
        sink: &SharedSink,
        columns: u16,
    ) -> Renderer {
        Renderer::new(
            caps,
            verbosity,
            checklist,
            clock,
            Box::new(sink.clone()),
            Box::new(move || Some(columns)),
        )
    }

    fn start(r: &mut Renderer, clock: &FakeClock, id: u64, label: &str) {
        r.handle(Msg::PhaseStart {
            id,
            label: label.to_string(),
            at: clock.now(),
        });
    }

    fn done(r: &mut Renderer, clock: &FakeClock, id: u64, summary: &str) {
        r.handle(Msg::PhaseDone {
            id,
            summary: summary.to_string(),
            at: clock.now(),
        });
    }

    fn header(r: &mut Renderer) {
        r.handle(Msg::Header {
            wordmark: "aitmproxy".to_string(),
            version: "0.5.11".to_string(),
        });
    }

    fn browser_event() -> UiEvent {
        UiEvent {
            level: tracing::Level::WARN,
            target: "aitm_browser::obscura".to_string(),
            message: "embedded browser unavailable; browser.* commands will error".to_string(),
            fields: vec![
                ("engine".to_string(), "obscura".to_string()),
                ("error".to_string(), "nope".to_string()),
            ],
        }
    }

    fn port_report() -> ErrorReport {
        ErrorReport::failure("cannot start: the proxy port 127.0.0.1:8080 is already in use")
            .with_command("lsof -nP -iTCP:8080 -sTCP:LISTEN")
    }

    fn bus_card() -> Card {
        Card {
            headline: "aitmproxy · listening 127.0.0.1:8080".to_string(),
            headline_role: Role::Success,
            rows: vec![Row {
                label: "Bus",
                value: "stdio (MCP)".to_string(),
                value_role: Role::Plain,
                next: None,
            }],
        }
    }

    fn no_escape_bytes(sink: &SharedSink) {
        let bytes = sink.bytes();
        assert!(
            !bytes.contains(&0x1b),
            "no ESC byte allowed: {:?}",
            sink.text()
        );
        assert!(!bytes.contains(&b'\r'), "no CR allowed: {:?}", sink.text());
    }

    #[test]
    fn plain_checklist_prints_one_line_per_phase_and_no_escape_bytes() {
        let sink = SharedSink::new();
        let reporter =
            Reporter::new(utf8_pipe(), Box::new(sink.clone()), Verbosity::Normal).checklist(true);
        reporter.header("aitmproxy", "0.5.11");
        reporter
            .phase("reading config")
            .done("config defaults · /tmp/h/config.yaml not found");
        reporter.phase("binding ports").fail("binding ports");
        reporter.warn(
            "log file unavailable: /tmp/h/logs/aitm.log (Permission denied) · running without a log",
        );
        reporter.finish();

        assert_eq!(
            sink.text(),
            "aitmproxy 0.5.11\n\
             config defaults · /tmp/h/config.yaml not found\n\
             error: binding ports\n\
             warning: log file unavailable: /tmp/h/logs/aitm.log (Permission denied) · running without a log\n"
        );
        no_escape_bytes(&sink);
    }

    #[test]
    fn one_shot_suppresses_phases_that_finish_under_100_ms() {
        let clock = FakeClock::new();
        let sink = SharedSink::new();
        let mut r = renderer(
            Caps::plain(),
            Verbosity::Normal,
            false,
            clock.clone(),
            &sink,
        );

        start(&mut r, &clock, 1, "loading detections");
        clock.advance(Duration::from_millis(20));
        done(&mut r, &clock, 1, "49 detections ready");
        assert_eq!(
            sink.text(),
            "",
            "a 20 ms phase prints nothing in one-shot mode"
        );

        start(&mut r, &clock, 2, "loading detections");
        clock.advance(Duration::from_millis(150));
        done(&mut r, &clock, 2, "49 detections ready");
        assert_eq!(sink.text(), "49 detections ready\n");
    }

    #[test]
    fn checklist_prints_fast_phases_too() {
        let clock = FakeClock::new();
        let sink = SharedSink::new();
        let mut r = renderer(Caps::plain(), Verbosity::Normal, true, clock.clone(), &sink);

        start(&mut r, &clock, 1, "reading config");
        clock.advance(Duration::from_millis(20));
        done(&mut r, &clock, 1, "config /tmp/h/config.yaml");
        assert_eq!(sink.text(), "config /tmp/h/config.yaml\n");
    }

    #[test]
    fn quiet_keeps_warnings_and_errors_only() {
        let sink = SharedSink::new();
        let reporter =
            Reporter::new(Caps::plain(), Box::new(sink.clone()), Verbosity::Quiet).checklist(true);
        reporter.header("aitmproxy", "0.5.11");
        reporter.phase("reading config").done("config defaults");
        reporter.warn("x");
        reporter.card(&bus_card());
        reporter.error(&port_report());

        assert_eq!(
            sink.text(),
            "warning: x\n\
             error: cannot start: the proxy port 127.0.0.1:8080 is already in use\n\
             \x20 fix: lsof -nP -iTCP:8080 -sTCP:LISTEN\n"
        );
        reporter.finish();
        no_escape_bytes(&sink);
    }

    #[test]
    fn rich_header_bytes() {
        let sink = SharedSink::new();
        let mut r = renderer(
            rich_caps(false, true),
            Verbosity::Normal,
            false,
            FakeClock::new(),
            &sink,
        );
        header(&mut r);
        assert_eq!(sink.text(), "›•‹ aitmproxy 0.5.11\n\n");

        let ascii = SharedSink::new();
        let mut r = renderer(
            rich_caps(false, false),
            Verbosity::Normal,
            false,
            FakeClock::new(),
            &ascii,
        );
        header(&mut r);
        assert_eq!(ascii.text(), "aitmproxy 0.5.11\n\n");

        let colored = SharedSink::new();
        let mut r = renderer(
            rich_caps(true, true),
            Verbosity::Normal,
            false,
            FakeClock::new(),
            &colored,
        );
        header(&mut r);
        assert_eq!(
            colored.text(),
            "\x1b[34m›•‹\x1b[0m \x1b[34maitmproxy\x1b[0m 0.5.11\n\n"
        );

        // Quiet drops the header entirely.
        let quiet = SharedSink::new();
        let mut r = renderer(
            rich_caps(false, true),
            Verbosity::Quiet,
            false,
            FakeClock::new(),
            &quiet,
        );
        header(&mut r);
        assert_eq!(quiet.text(), "");
    }

    #[test]
    fn rich_phase_is_drawn_after_the_first_draw_delay_and_collapses_in_place() {
        let clock = FakeClock::new();
        let sink = SharedSink::new();
        let mut r = renderer(
            rich_caps(false, true),
            Verbosity::Normal,
            false,
            clock.clone(),
            &sink,
        );

        start(&mut r, &clock, 1, "loading detections");
        clock.advance(Duration::from_millis(50));
        r.tick();
        assert!(!sink.text().contains('⠋'), "{:?}", sink.text());
        assert_eq!(sink.text(), "", "nothing is drawn before 100 ms");

        clock.advance(Duration::from_millis(100));
        r.tick();
        let first = format!("{BEGIN}{CLR}  ⠋ loading detections\n{END}");
        assert_eq!(sink.text(), first);
        assert!(sink.text().contains("\x1b[?2026h"));
        assert!(sink.text().contains("  ⠋ loading detections\n"));
        assert!(sink.text().contains("\x1b[?2026l"));
        assert!(
            !sink.text().contains("\x1b[1A"),
            "no cursor-up before a line was drawn"
        );

        done(&mut r, &clock, 1, "49 detections ready");
        let text = sink.text();
        assert!(text.contains("\x1b[1A"));
        assert!(text.contains("\x1b[1G\x1b[2K"));
        assert!(text.ends_with("  ✓ 49 detections ready\n\x1b[?2026l"));
        assert_eq!(
            text,
            format!("{first}{BEGIN}{UP1}{CLR}  ✓ 49 detections ready\n{END}")
        );
    }

    #[test]
    fn rich_spinner_advances_one_frame_per_tick() {
        let clock = FakeClock::new();
        let sink = SharedSink::new();
        let mut r = renderer(
            rich_caps(false, true),
            Verbosity::Normal,
            false,
            clock.clone(),
            &sink,
        );

        start(&mut r, &clock, 1, "loading detections");
        clock.advance(Duration::from_millis(150));
        r.tick();
        let after_first = sink.text();
        assert!(after_first.contains("  ⠋ loading detections\n"));

        clock.advance(Duration::from_millis(100));
        r.tick();
        let latest = sink.text()[after_first.len()..].to_string();
        assert_eq!(
            latest,
            format!("{BEGIN}{UP1}{CLR}  ⠙ loading detections\n{END}")
        );
    }

    #[test]
    fn rich_warning_is_inserted_above_the_live_region() {
        let clock = FakeClock::new();
        let sink = SharedSink::new();
        let mut r = renderer(
            rich_caps(false, true),
            Verbosity::Normal,
            false,
            clock.clone(),
            &sink,
        );

        start(&mut r, &clock, 1, "loading detections");
        clock.advance(Duration::from_millis(150));
        r.tick();
        let before = sink.text();

        r.handle(Msg::Warn(
            "embedded browser unavailable; browser.* commands will error".to_string(),
        ));
        let frame = sink.text()[before.len()..].to_string();
        assert_eq!(
            frame,
            format!(
                "{BEGIN}{UP1}{CLR}  ! embedded browser unavailable; browser.* commands will error\n\
                 {CLR}  ⠋ loading detections\n{END}"
            )
        );
    }

    #[test]
    fn event_formats_fields_in_both_modes() {
        let plain = SharedSink::new();
        let mut r = renderer(
            Caps::plain(),
            Verbosity::Normal,
            false,
            FakeClock::new(),
            &plain,
        );
        r.handle(Msg::Event(browser_event()));
        assert_eq!(
            plain.text(),
            "warning: embedded browser unavailable; browser.* commands will error engine=obscura error=nope\n"
        );

        // The full line is 94 columns wide: a 120-column terminal shows it whole.
        let rich = SharedSink::new();
        let mut r = renderer_with_width(
            rich_caps(false, true),
            Verbosity::Normal,
            false,
            FakeClock::new(),
            &rich,
            120,
        );
        r.handle(Msg::Event(browser_event()));
        assert_eq!(
            rich.text(),
            format!(
                "{BEGIN}{CLR}  ! embedded browser unavailable; browser.* commands will error · engine=obscura · error=nope\n{END}"
            )
        );

        // At 80 columns the line is end-truncated with the ellipsis (spec T5, plan C5).
        let narrow = SharedSink::new();
        let mut r = renderer(
            rich_caps(false, true),
            Verbosity::Normal,
            false,
            FakeClock::new(),
            &narrow,
        );
        r.handle(Msg::Event(browser_event()));
        assert_eq!(
            narrow.text(),
            format!(
                "{BEGIN}{CLR}  ! embedded browser unavailable; browser.* commands will error · engine=obscur…\n{END}"
            )
        );

        // ERROR level: `error:` in plain, the failed glyph in rich.
        let boom = UiEvent {
            level: tracing::Level::ERROR,
            target: "aitm::wire".to_string(),
            message: "boom".to_string(),
            fields: Vec::new(),
        };
        let plain = SharedSink::new();
        let mut r = renderer(
            Caps::plain(),
            Verbosity::Normal,
            false,
            FakeClock::new(),
            &plain,
        );
        r.handle(Msg::Event(boom.clone()));
        assert!(plain.text().starts_with("error: "), "{:?}", plain.text());
        assert_eq!(plain.text(), "error: boom\n");
        let rich = SharedSink::new();
        let mut r = renderer(
            rich_caps(false, true),
            Verbosity::Normal,
            false,
            FakeClock::new(),
            &rich,
        );
        r.handle(Msg::Event(boom));
        assert_eq!(rich.text(), format!("{BEGIN}{CLR}  ✕ boom\n{END}"));

        // An event with no message names its target, so no bare `warning: `
        // line appears.
        let plain = SharedSink::new();
        let mut r = renderer(
            Caps::plain(),
            Verbosity::Normal,
            false,
            FakeClock::new(),
            &plain,
        );
        r.handle(Msg::Event(UiEvent {
            level: tracing::Level::WARN,
            target: "aitm::wire".to_string(),
            message: String::new(),
            fields: vec![("engine".to_string(), "obscura".to_string())],
        }));
        assert_eq!(plain.text(), "warning: aitm::wire engine=obscura\n");
    }

    #[test]
    fn verbose_appends_the_duration() {
        let clock = FakeClock::new();
        let sink = SharedSink::new();
        let mut r = renderer(utf8_pipe(), Verbosity::Verbose, false, clock.clone(), &sink);

        start(&mut r, &clock, 1, "loading detections");
        clock.advance(Duration::from_millis(150));
        done(&mut r, &clock, 1, "49 detections ready");
        assert_eq!(sink.text(), "49 detections ready · in 150 ms\n");

        // ASCII glyphs turn the separator into `-` (orchestrator addendum).
        let ascii = SharedSink::new();
        let mut r = renderer(
            Caps::plain(),
            Verbosity::Verbose,
            false,
            clock.clone(),
            &ascii,
        );
        start(&mut r, &clock, 2, "loading detections");
        clock.advance(Duration::from_millis(150));
        done(&mut r, &clock, 2, "49 detections ready");
        assert_eq!(ascii.text(), "49 detections ready - in 150 ms\n");
    }

    #[test]
    fn finish_and_clear_erases_everything_below_the_header() {
        let clock = FakeClock::new();
        let sink = SharedSink::new();
        let mut r = renderer(
            rich_caps(false, true),
            Verbosity::Normal,
            true,
            clock.clone(),
            &sink,
        );
        header(&mut r);
        start(&mut r, &clock, 1, "reading config");
        done(&mut r, &clock, 1, "config /tmp/h/config.yaml");
        start(&mut r, &clock, 2, "loading detections");
        done(&mut r, &clock, 2, "49 detections ready");
        start(&mut r, &clock, 3, "starting obscura");
        clock.advance(Duration::from_millis(150));
        r.tick();
        assert!(
            sink.text().contains("  ⠋ starting obscura\n"),
            "{:?}",
            sink.text()
        );

        let (ack, acked) = mpsc::sync_channel(1);
        r.handle(Msg::Clear(ack));
        assert_eq!(acked.try_recv(), Ok(()), "Clear must ack");

        let erase = "\x1b[1A\x1b[2K";
        let text = sink.text();
        assert!(text.ends_with(&erase.repeat(4)), "{text:?}");
        assert!(
            !text.ends_with(&erase.repeat(5)),
            "exactly four lines: three below the header plus its blank line: {text:?}"
        );
    }

    #[test]
    fn error_renders_the_panel_after_the_live_region() {
        let clock = FakeClock::new();
        let sink = SharedSink::new();
        let caps = rich_caps(false, true);
        let mut r = renderer(caps, Verbosity::Normal, false, clock.clone(), &sink);

        start(&mut r, &clock, 1, "loading detections");
        clock.advance(Duration::from_millis(150));
        r.tick();
        let before = sink.text();

        let report = port_report();
        r.handle(Msg::Error {
            report: report.clone(),
            home: None,
        });
        let panel = report.render_rich(&caps, &RICH, None);
        let text = sink.text();
        assert!(text.ends_with(&format!("\n{panel}")), "{text:?}");
        assert_eq!(
            text,
            format!("{before}{BEGIN}{UP1}{CLR}  ✕ loading detections\n{END}\n{panel}")
        );
    }

    #[test]
    fn finish_is_idempotent_and_the_reporter_keeps_working_afterwards() {
        let sink = SharedSink::new();
        let reporter =
            Reporter::new(Caps::plain(), Box::new(sink.clone()), Verbosity::Normal).checklist(true);
        reporter.phase("reading config").done("config defaults");

        let started = Instant::now();
        reporter.finish();
        reporter.finish();
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "a second finish must return at once"
        );
        assert_eq!(sink.text(), "config defaults\n");

        reporter.warn("late");
        assert_eq!(sink.text(), "config defaults\nwarning: late\n");

        reporter.phase("x").done("y");
        assert_eq!(sink.text(), "config defaults\nwarning: late\ny\n");

        reporter.events().send(browser_event());
        assert_eq!(
            sink.text(),
            "config defaults\nwarning: late\ny\n\
             warning: embedded browser unavailable; browser.* commands will error engine=obscura error=nope\n"
        );
        no_escape_bytes(&sink);
    }

    #[test]
    fn phase_finish_with_and_drop_end_the_phase() {
        let sink = SharedSink::new();
        let reporter =
            Reporter::new(Caps::plain(), Box::new(sink.clone()), Verbosity::Normal).checklist(true);

        let ok: Result<u32, String> = reporter
            .phase("loading detections")
            .finish_with(Ok(49), |n| format!("{n} detections ready"));
        assert_eq!(ok, Ok(49));

        let err: Result<u32, String> = reporter
            .phase("binding ports")
            .finish_with(Err("boom".to_string()), |n| format!("{n} ready"));
        assert_eq!(err, Err("boom".to_string()));

        {
            let _dropped = reporter.phase("starting obscura");
        }

        reporter.finish();
        assert_eq!(
            sink.text(),
            "49 detections ready\nerror: binding ports\nstarting obscura\n"
        );
    }

    #[test]
    fn ascii_glyphs_replace_the_separator_and_ellipsis_in_every_line() {
        let clock = FakeClock::new();
        let sink = SharedSink::new();
        let mut r = renderer(
            rich_caps(false, false),
            Verbosity::Normal,
            true,
            clock.clone(),
            &sink,
        );
        start(&mut r, &clock, 1, "binding ports");
        done(
            &mut r,
            &clock,
            1,
            "proxy listening 127.0.0.1:8080 · browser proxy 127.0.0.1:8081",
        );
        assert_eq!(
            sink.text(),
            format!(
                "{BEGIN}{CLR}  + proxy listening 127.0.0.1:8080 - browser proxy 127.0.0.1:8081\n{END}"
            )
        );
        r.handle(Msg::Warn("a long one…".to_string()));
        r.handle(Msg::Card(bus_card()));
        r.handle(Msg::Error {
            report: ErrorReport::failure("cannot start · see the log"),
            home: None,
        });
        let text = sink.text();
        assert!(text.contains("  ! a long one...\n"), "{text:?}");
        assert!(
            text.contains(
                "\n* aitmproxy - listening 127.0.0.1:8080\n  Bus           stdio (MCP)\n"
            ),
            "{text:?}"
        );
        assert!(
            text.ends_with("\nx cannot start - see the log\n"),
            "{text:?}"
        );
        assert!(
            sink.bytes().iter().all(|b| *b < 0x80),
            "ASCII glyphs must leave no byte >= 0x80: {text:?}"
        );

        let plain = SharedSink::new();
        let mut r = renderer(
            Caps::plain(),
            Verbosity::Normal,
            true,
            clock.clone(),
            &plain,
        );
        start(&mut r, &clock, 2, "binding ports");
        done(
            &mut r,
            &clock,
            2,
            "proxy listening 127.0.0.1:8080 · browser proxy 127.0.0.1:8081",
        );
        assert_eq!(
            plain.text(),
            "proxy listening 127.0.0.1:8080 - browser proxy 127.0.0.1:8081\n"
        );
        assert!(plain.bytes().iter().all(|b| *b < 0x80));
    }

    #[test]
    fn reporter_and_phase_are_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<Reporter>();
        assert_send_sync::<Phase>();
    }

    #[test]
    fn display_path_shortens_home_only_when_animating() {
        let home = PathBuf::from("/Users/matt");
        let log = Path::new("/Users/matt/Library/Application Support/aitmproxy/logs/aitm.log");

        let rich = Reporter::new(
            rich_caps(false, true),
            Box::new(SharedSink::new()),
            Verbosity::Normal,
        )
        .with_home(Some(home.clone()));
        assert_eq!(rich.display_home(), Some(home.as_path()));
        assert_eq!(
            rich.display_path(log),
            "~/Library/Application Support/aitmproxy/logs/aitm.log"
        );
        assert!(std::ptr::eq(rich.glyphs(), &RICH));
        assert_eq!(rich.verbosity(), Verbosity::Normal);
        assert_eq!(rich.caps(), &rich_caps(false, true));

        let plain = Reporter::new(
            Caps::plain(),
            Box::new(SharedSink::new()),
            Verbosity::Normal,
        )
        .with_home(Some(home));
        assert_eq!(plain.display_home(), None);
        assert_eq!(
            plain.display_path(log),
            "/Users/matt/Library/Application Support/aitmproxy/logs/aitm.log"
        );

        let unset = Reporter::new(
            rich_caps(false, true),
            Box::new(SharedSink::new()),
            Verbosity::Normal,
        );
        assert_eq!(unset.display_home(), None);
    }
}
