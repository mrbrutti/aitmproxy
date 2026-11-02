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
//! live. The queue holds 256 messages: a warning or event that finds it full
//! is dropped and counted (S3); every other message waits for room, and
//! [`Reporter::card`], [`Reporter::error`], [`Reporter::finish`] and
//! [`Reporter::finish_and_clear`] then wait for an acknowledgement, each call
//! 2 s at most in all (C10, S5). A queue still full, or an acknowledgement
//! still missing, after that means the sink has stalled: the thread is
//! abandoned, the message is dropped and every later call returns at once
//! with nowhere to write. Otherwise `finish` closes the channel, joins the
//! thread and leaves the reporter in a synchronous plain-line mode so a late
//! warning still prints (C10); only [`Reporter::note`] keeps its `✓` there,
//! for the `stdin closed` line `main` prints after the serving loop ends.
//! [`Reporter::quiesce`] marks that end: from then on tracing events are
//! dropped at the door (the log file keeps them) while `note`, `warn` and
//! `error` still print (spec D4/D7, AC-W1-33).
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
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender, TryRecvError, TrySendError};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, PoisonError};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use crossterm::cursor::{MoveToColumn, MoveUp};
use crossterm::terminal::{BeginSynchronizedUpdate, Clear, ClearType, EndSynchronizedUpdate};
use crossterm::Command;

use crate::caps::Caps;
pub use crate::caps::Verbosity;
use crate::card::{Card, Row, INDENT};
use crate::clock::{Clock, SystemClock};
use crate::error::{ErrorReport, FixCommand};
use crate::event::{EventSender, UiEvent};
use crate::glyphs::Glyphs;
use crate::style::{paint, Role};
use crate::text;

/// Spec T4: a phase younger than this is not drawn, and a `done`/`fail` of
/// such a phase prints nothing in one-shot mode (C4). It is also the ticker's
/// wake-up interval, so the spinner runs at ten frames a second.
pub(crate) const FIRST_DRAW_DELAY: Duration = Duration::from_millis(100);

/// How long a blocking call waits for the render thread before giving up on
/// it (plan C10): for room in a full queue and for the acknowledgement
/// together (S5). A sink that blocks this long is a stalled pipe, and the
/// thread is abandoned rather than freezing startup.
const ACK_TIMEOUT: Duration = Duration::from_secs(2);

/// How often a non-droppable message re-tries a full queue while it waits
/// for room (S5).
const ENQUEUE_POLL: Duration = Duration::from_millis(5);

const THREAD_NAME: &str = "aitm-term";

/// The render queue's capacity (fix task S3). Warnings and events beyond it
/// are dropped and counted rather than queued without bound: a flood of
/// per-connection WARNs is attacker-triggerable. Every other message kind
/// waits for room, `ACK_TIMEOUT` at most (S5).
const QUEUE_CAPACITY: usize = 256;

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
    /// A success line outside any phase (`Reporter::note`).
    Note(String),
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
    /// Warnings and events dropped by `Reporter::send` while the queue was
    /// full, not yet reported (S3); shared with the `Reporter`.
    suppressed: Arc<AtomicUsize>,
    /// Set by `into_plain`: after `finish` every line is plain whatever the
    /// caps say, the note excepted, which keeps its `✓` on a terminal (spec
    /// Open question 3; `main` prints it after the serving loop ends).
    finished: bool,
}

impl Renderer {
    fn new(
        caps: Caps,
        verbosity: Verbosity,
        checklist: bool,
        clock: Arc<dyn Clock>,
        sink: Box<dyn Write + Send>,
        width_probe: Box<dyn Fn() -> Option<u16> + Send>,
        suppressed: Arc<AtomicUsize>,
    ) -> Renderer {
        Renderer {
            caps,
            glyphs: Glyphs::for_caps(&caps),
            verbosity,
            checklist,
            clock,
            sink,
            width_probe,
            suppressed,
            running: Vec::new(),
            pending: Vec::new(),
            live_lines_drawn: 0,
            scrolled: 0,
            header_blank: 0,
            frame: 0,
            finished: false,
        }
    }

    /// Rich rendering: the caps animate and `finish` has not happened (C6,
    /// C10).
    fn rich(&self) -> bool {
        self.caps.animate && !self.finished
    }

    fn quiet(&self) -> bool {
        self.verbosity == Verbosity::Quiet
    }

    fn has_live(&self) -> bool {
        !self.running.is_empty()
    }

    /// After `finish`: plain lines only, on the caller's thread (C10), the
    /// note excepted (see [`Renderer::note`]). The caps stay as detected;
    /// only the flag changes. Phases still open keep their start time so a
    /// late `done` prints its line.
    fn into_plain(mut self) -> Renderer {
        self.finished = true;
        self
    }

    /// The caps for this frame: `caps` with the width probed now (spec T5),
    /// the startup width when the probe has nothing.
    fn frame_caps(&self) -> Caps {
        Caps {
            width: (self.width_probe)().unwrap_or(self.caps.width),
            ..self.caps
        }
    }

    fn width(&self) -> usize {
        usize::from(self.frame_caps().width)
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
                let line = self.warn_line(&line);
                self.emit(line);
            }
            Msg::Event(ev) => {
                let line = self.event_line(&ev);
                self.emit(line);
            }
            Msg::Note(line) => self.note(&line),
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

    /// `! <line>` (rich, the glyph painted Warning) or `warning: <line>`.
    fn warn_line(&self, line: &str) -> String {
        if self.rich() {
            format!(
                "{INDENT}{} {line}",
                paint(&self.caps, Role::Warning, self.glyphs.warn)
            )
        } else {
            format!("warning: {line}")
        }
    }

    /// One line for the warnings dropped while the queue was full, printed
    /// when the queue next drains (S3); the counter is reset. Warnings show
    /// under `-q`, so their count does too.
    fn report_suppressed(&mut self) {
        let n = self.suppressed.swap(0, Ordering::AcqRel);
        if n == 0 {
            return;
        }
        let plural = if n == 1 { "" } else { "s" };
        let line = self.warn_line(&format!("{n} warning{plural} suppressed"));
        self.emit(line);
    }

    /// `✓ <line>` (rich, the glyph painted Success) or `<line>` (plain): a
    /// success note outside any phase, a done line without a duration. Quiet
    /// drops it like every other non-warning line. The glyph form follows
    /// `caps.animate` alone, not [`Renderer::rich`], so on a terminal it
    /// stays after `finish`: the live region is empty by then, so `emit`
    /// writes the line straight out, no cursor movement and no synchronized
    /// update, only the glyph's own SGR when colour is on. Every other
    /// post-finish line takes the plain form.
    fn note(&mut self, line: &str) {
        if self.quiet() {
            return;
        }
        let line = if self.caps.animate {
            format!(
                "{INDENT}{} {line}",
                paint(&self.caps, Role::Success, self.glyphs.done)
            )
        } else {
            line.to_string()
        };
        self.emit(line);
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

    /// The ticker stops: every live phase collapses as a failed line (`✕
    /// <label>` rich, `error: <label>` plain), then the panel follows. In the
    /// rich form one blank line separates it from whatever was drawn since
    /// the header (spec: one blank line between blocks; the header carries
    /// its own, and a one-shot panel is the first thing on screen, so neither
    /// case gets another). The rich panel wraps at the width probed for this
    /// frame, not the width measured at startup.
    fn error(&mut self, report: &ErrorReport, home: Option<&Path>) {
        let running = std::mem::take(&mut self.running);
        if self.rich() {
            for live in running {
                let line = self.fail_line(&live.label);
                self.pending.push(line);
            }
            self.redraw();
            let text = report.render_rich(&self.frame_caps(), self.glyphs, home);
            let lines = text.lines().count();
            if self.scrolled > 0 {
                self.write_text(&format!("\n{text}"));
                self.scrolled += 1 + lines;
            } else {
                self.write_text(&text);
                self.scrolled += lines;
            }
        } else {
            for live in running {
                let line = self.fail_line(&live.label);
                self.write_text(&format!("{line}\n"));
            }
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
/// silence while a phase is live, exit when every sender is gone. Each time
/// the queue drains (and once more at the close) the warnings dropped while
/// it was full are reported (S3).
fn run(mut renderer: Renderer, rx: Receiver<Msg>) -> Renderer {
    loop {
        let next = match rx.try_recv() {
            Ok(msg) => Ok(msg),
            Err(TryRecvError::Disconnected) => Err(RecvTimeoutError::Disconnected),
            Err(TryRecvError::Empty) => {
                renderer.report_suppressed();
                if renderer.rich() && renderer.has_live() {
                    rx.recv_timeout(FIRST_DRAW_DELAY)
                } else {
                    rx.recv().map_err(|_| RecvTimeoutError::Disconnected)
                }
            }
        };
        match next {
            Ok(msg) => renderer.handle(msg),
            Err(RecvTimeoutError::Timeout) => renderer.tick(),
            Err(RecvTimeoutError::Disconnected) => break,
        }
    }
    renderer.report_suppressed();
    renderer
}

/// Where the renderer lives.
enum State {
    /// No message yet: the renderer waits here for the thread to start.
    Idle(Renderer),
    Running {
        tx: SyncSender<Msg>,
        thread: JoinHandle<Option<Renderer>>,
    },
    /// After `finish`: synchronous plain-line rendering, or nothing when the
    /// thread was abandoned on a stalled sink, by `shutdown` or by a
    /// non-droppable send that found the queue full for `ACK_TIMEOUT` (S5);
    /// its output is stuck anyway.
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
    /// Warnings and events dropped on a full queue, until the renderer
    /// reports them (S3).
    suppressed: Arc<AtomicUsize>,
    /// Set by `quiesce` once the serving loop has ended: tracing events
    /// are dropped at the door from then on (spec D4/D7, AC-W1-33).
    quiesced: AtomicBool,
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
        // The live region re-measures on every frame (spec T5); animation
        // implies a TTY, so the probe is only installed where it can answer.
        let width_probe: Box<dyn Fn() -> Option<u16> + Send> = if caps.animate {
            Box::new(crate::caps::measure_width)
        } else {
            Box::new(|| None)
        };
        let suppressed = Arc::new(AtomicUsize::new(0));
        let renderer = Renderer::new(
            caps,
            verbosity,
            false,
            Arc::clone(&clock),
            sink,
            width_probe,
            Arc::clone(&suppressed),
        );
        Reporter {
            inner: Arc::new(Inner {
                caps,
                glyphs: Glyphs::for_caps(&caps),
                verbosity,
                clock,
                home: OnceLock::new(),
                next_id: AtomicU64::new(1),
                suppressed,
                quiesced: AtomicBool::new(false),
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
        let set = {
            let mut state = self.lock();
            match &mut *state {
                State::Idle(renderer) | State::Finished(Some(renderer)) => {
                    renderer.checklist = on;
                    true
                }
                State::Running { .. } | State::Finished(None) => false,
            }
        };
        if !set {
            // The thread owns the renderer: the toggle travels like every
            // other non-droppable message, bounded (S5).
            self.send(Msg::Checklist(on));
        }
        self
    }

    /// The operator's home, for `~` shortening (C7). Set-once: the first
    /// `Some` wins; later calls, `None` included, are ignored, so a `None`
    /// from an unset `HOME` never clears a home set earlier.
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
        clean(&text::tilde(p, self.display_home()))
    }

    /// The header line (`›•‹ aitmproxy 0.5.11`); serving modes only (C4).
    pub fn header(&self, wordmark: &str, version: &str) {
        self.send(Msg::Header {
            wordmark: clean(wordmark),
            version: clean(version),
        });
    }

    /// Starts a phase; it ends through [`Phase::done`], [`Phase::fail`],
    /// [`Phase::finish_with`] or, on drop, as `done(label)`.
    pub fn phase(&self, label: &str) -> Phase {
        let label = clean(label);
        let id = self.inner.next_id.fetch_add(1, Ordering::Relaxed);
        self.send(Msg::PhaseStart {
            id,
            label: label.clone(),
            at: self.inner.clock.now(),
        });
        Phase {
            reporter: self.clone(),
            id,
            label,
            ended: false,
        }
    }

    /// A warning line above the live region (`! …`), `warning: …` when plain.
    pub fn warn(&self, line: &str) {
        self.send(Msg::Warn(clean(line)));
    }

    /// A one-line success note outside any phase: `  ✓ <line>` rich, `<line>`
    /// plain, nothing under `-q`. Usable at any time, after
    /// [`Reporter::finish`] included; `main` prints `stdin closed · stdio
    /// MCP transport ended` with it when the stdio MCP transport ends (spec
    /// Open question 3), which is after the serving loop and so after
    /// `finish`. It is the one message that keeps its glyph after `finish()`:
    /// on a TTY the post-finish synchronous path still writes `  ✓ <line>`
    /// (the live region is empty, so no cursor moves), while every other
    /// late line takes the plain form (C10).
    pub fn note(&self, line: &str) {
        self.send(Msg::Note(clean(line)));
    }

    /// Marks the end of the serving loop on an orderly exit (spec D4/D7,
    /// AC-W1-33): from now on a tracing event handed to [`Reporter::event`]
    /// or to the [`Reporter::events`] sender is dropped before it touches
    /// the queue or the post-`finish` synchronous path, so a dependency's
    /// teardown noise (the browser's CDP socket closing logs an ERROR) is
    /// never the operator's last line; the log file's own layer still
    /// records it. `note`, `warn`, `error`, `card` and `finish` are
    /// unaffected. Idempotent; never undone. A flag rather than a `Msg`
    /// because `main` calls it after `finish()`, when no render thread
    /// exists.
    pub fn quiesce(&self) {
        self.inner.quiesced.store(true, Ordering::Release);
    }

    /// A WARN+ tracing event folded into the view (spec D7); dropped once
    /// the reporter is quiesced.
    pub fn event(&self, ev: UiEvent) {
        if self.inner.quiesced.load(Ordering::Acquire) {
            return;
        }
        self.send(Msg::Event(sanitize_event(ev)));
    }

    /// The ready card; blocks until it is on the sink, `ACK_TIMEOUT` at most.
    pub fn card(&self, card: &Card) {
        let deadline = Instant::now() + ACK_TIMEOUT;
        self.send_by(Msg::Card(sanitize_card(card)), deadline);
        self.send_and_wait(Msg::Flush, deadline);
    }

    /// The error panel; stops the live region first and blocks until the
    /// panel is on the sink, `ACK_TIMEOUT` at most.
    pub fn error(&self, report: &ErrorReport) {
        let deadline = Instant::now() + ACK_TIMEOUT;
        self.send_by(
            Msg::Error {
                report: sanitize_report(report),
                home: self.display_home().map(Path::to_path_buf),
            },
            deadline,
        );
        self.send_and_wait(Msg::Flush, deadline);
    }

    /// Stops the ticker and joins the render thread, keeping every line on
    /// screen. Idempotent; afterwards every call renders synchronously in
    /// plain-line form (C10), [`Reporter::note`] alone keeping its glyph.
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

    /// Hands `msg` to the render thread, starting it on the first message;
    /// a non-droppable message waits for room `ACK_TIMEOUT` at most.
    fn send(&self, msg: Msg) {
        self.send_by(msg, Instant::now() + ACK_TIMEOUT);
    }

    /// [`Reporter::send`] with the instant a non-droppable message stops
    /// waiting for room in a full queue (S5), so a call that sends twice
    /// (`card`, `error`) is bounded as a whole. The wait runs under the
    /// state lock, so every caller is bounded by the same deadline.
    fn send_by(&self, msg: Msg, deadline: Instant) {
        let mut state = self.lock();
        if matches!(&*state, State::Idle(_)) {
            start_thread(&mut state);
        }
        let unsent = match &mut *state {
            State::Running { tx, .. } => match msg {
                // Attacker-triggerable volume never blocks on the queue and
                // never queues without bound (S3): a full queue drops the
                // warning and counts it for the renderer to report.
                Msg::Warn(_) | Msg::Event(_) => match tx.try_send(msg) {
                    Ok(()) => return,
                    Err(TrySendError::Full(_)) => {
                        self.inner.suppressed.fetch_add(1, Ordering::Relaxed);
                        return;
                    }
                    Err(TrySendError::Disconnected(msg)) => msg,
                },
                // Every other kind waits for room until `deadline` (S5). A
                // queue still full then sits behind a sink that has stalled
                // for `ACK_TIMEOUT`: the thread is abandoned as `shutdown`
                // abandons it, the message is dropped, and later output has
                // nowhere to go.
                msg => match send_until(tx, msg, deadline) {
                    Enqueued::Sent => return,
                    Enqueued::Full => {
                        *state = State::Finished(None);
                        return;
                    }
                    Enqueued::Disconnected(msg) => msg,
                },
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
    /// until `deadline` at most for the two together. A synchronous renderer
    /// has already acknowledged by the time `send_by` returns; a dropped
    /// message disconnects at once.
    fn send_and_wait(&self, make: fn(SyncSender<()>) -> Msg, deadline: Instant) {
        let (ack, acked) = mpsc::sync_channel(1);
        self.send_by(make(ack), deadline);
        let _ = acked.recv_timeout(deadline.saturating_duration_since(Instant::now()));
    }

    /// `finish` and `finish_and_clear`: the last message, then close the
    /// channel and join the thread, then switch to synchronous plain lines.
    /// The last message waits for room and for its acknowledgement
    /// `ACK_TIMEOUT` at most in all (S5), counted from the call so that the
    /// wait for the state lock is part of it (S8).
    fn shutdown(&self, last: fn(SyncSender<()>) -> Msg) {
        // S8: the bound starts before the lock wait, as in `send`, `card` and
        // `error`, so every public call shares one `ACK_TIMEOUT` even while
        // another caller holds the state lock inside `send_until`.
        let deadline = Instant::now() + ACK_TIMEOUT;
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
                let sent = matches!(send_until(&tx, last(ack), deadline), Enqueued::Sent);
                drop(tx);
                let remaining = deadline.saturating_duration_since(Instant::now());
                if sent && acked.recv_timeout(remaining).is_ok() {
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

/// Every content string is neutralised with [`text::sanitize`] here, as it
/// enters a message, never on the way out: the renderer's own SGR and cursor
/// codes must pass `write_text` untouched. WARN/ERROR text and fields from
/// any crate, `anyhow` chains, phase summaries and Rhai `log.warn` text can
/// carry a client-supplied authority, and an `ESC ]`/`BEL`/C1 inside it must
/// not reach the operator's terminal.
fn clean(s: &str) -> String {
    text::sanitize(s).into_owned()
}

fn sanitize_event(ev: UiEvent) -> UiEvent {
    UiEvent {
        level: ev.level,
        target: clean(&ev.target),
        message: clean(&ev.message),
        fields: ev
            .fields
            .iter()
            .map(|(name, value)| (clean(name), clean(value)))
            .collect(),
    }
}

/// Labels are `&'static str` from spec T3's fixed set and stay as they are.
fn sanitize_card(card: &Card) -> Card {
    Card {
        headline: clean(&card.headline),
        headline_role: card.headline_role,
        rows: card
            .rows
            .iter()
            .map(|row| Row {
                label: row.label,
                value: clean(&row.value),
                value_role: row.value_role,
                next: row.next.as_deref().map(clean),
            })
            .collect(),
    }
}

fn sanitize_report(report: &ErrorReport) -> ErrorReport {
    ErrorReport {
        kind: report.kind.clone(),
        what: clean(&report.what),
        why: report.why.iter().map(String::as_str).map(clean).collect(),
        fix: report.fix.as_deref().map(clean),
        command: report
            .command
            .as_ref()
            .map(|FixCommand(command)| FixCommand(clean(command))),
        log: report.log.as_deref().map(sanitize_path),
    }
}

/// The log path as the panel will display it, control characters
/// neutralised; a clean path is kept as is (its bytes matter when it is not
/// UTF-8, and `display()` would lose them).
fn sanitize_path(path: &Path) -> PathBuf {
    match text::sanitize(&path.display().to_string()) {
        Cow::Borrowed(_) => path.to_path_buf(),
        Cow::Owned(cleaned) => PathBuf::from(cleaned),
    }
}

/// The outcome of [`send_until`].
enum Enqueued {
    /// The message is in the queue.
    Sent,
    /// The queue was still full at the deadline; the message is dropped.
    Full,
    /// The render thread is gone; the message comes back for synchronous
    /// handling.
    Disconnected(Msg),
}

/// `try_send` repeated every `ENQUEUE_POLL` until it succeeds, the thread is
/// gone, or `deadline` passes with the queue still full (S5): the one way a
/// non-droppable message enters the queue, so no caller blocks on it for
/// longer than `ACK_TIMEOUT`.
fn send_until(tx: &SyncSender<Msg>, mut msg: Msg, deadline: Instant) -> Enqueued {
    loop {
        match tx.try_send(msg) {
            Ok(()) => return Enqueued::Sent,
            Err(TrySendError::Full(back)) => {
                if Instant::now() >= deadline {
                    return Enqueued::Full;
                }
                msg = back;
                std::thread::sleep(ENQUEUE_POLL);
            }
            Err(TrySendError::Disconnected(back)) => return Enqueued::Disconnected(back),
        }
    }
}

/// Moves the idle renderer onto the `aitm-term` thread. Should the OS refuse
/// a thread, the renderer stays on the caller's side and renders plain lines
/// synchronously, so no output is lost.
fn start_thread(state: &mut State) {
    let State::Idle(renderer) = std::mem::replace(state, State::Finished(None)) else {
        return;
    };
    let (tx, rx) = mpsc::sync_channel(QUEUE_CAPACITY);
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
            summary: clean(summary),
            at,
        });
    }

    /// `✕ <what>`; the panel that follows names the cause.
    pub fn fail(mut self, what: &str) {
        let at = self.reporter.inner.clock.now();
        self.end(Msg::PhaseFail {
            id: self.id,
            what: clean(what),
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
            Arc::new(AtomicUsize::new(0)),
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

    // ---- tester additions: thread lifecycle, failing sinks, narrow and
    // empty inputs, and the design rules checked in the bytes ----

    /// A sink that records which thread wrote each chunk, so a test can
    /// tell the render thread's output from the caller's.
    #[derive(Clone, Default)]
    struct ThreadTaggingSink(Arc<Mutex<Chunks>>);

    /// What a [`ThreadTaggingSink`] holds: the writing thread's name and
    /// the bytes, per write.
    type Chunks = Vec<(Option<String>, Vec<u8>)>;

    impl ThreadTaggingSink {
        fn writers(&self) -> Vec<Option<String>> {
            self.0
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .iter()
                .map(|(name, _)| name.clone())
                .collect()
        }

        fn text(&self) -> String {
            let bytes: Vec<u8> = self
                .0
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .iter()
                .flat_map(|(_, chunk)| chunk.iter().copied())
                .collect();
            String::from_utf8_lossy(&bytes).into_owned()
        }
    }

    impl Write for ThreadTaggingSink {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            let name = std::thread::current().name().map(str::to_string);
            self.0
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push((name, buf.to_vec()));
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// A sink whose every write and flush fails, like a closed stderr; it
    /// counts the attempts so a test can prove it was really used.
    #[derive(Clone, Default)]
    struct FailingSink(Arc<std::sync::atomic::AtomicUsize>);

    impl Write for FailingSink {
        fn write(&mut self, _buf: &[u8]) -> std::io::Result<usize> {
            self.0.fetch_add(1, Ordering::Relaxed);
            Err(std::io::Error::other("stderr closed"))
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Err(std::io::Error::other("stderr closed"))
        }
    }

    /// Every `ESC [ … <final>` sequence in `bytes`, in order; panics on an
    /// ESC that starts no CSI or on an unterminated one.
    fn csi_sequences(bytes: &[u8]) -> Vec<String> {
        let mut out = Vec::new();
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i] != 0x1b {
                i += 1;
                continue;
            }
            assert_eq!(bytes.get(i + 1), Some(&b'['), "bare ESC at byte {i}");
            let start = i;
            i += 2;
            while i < bytes.len() && !(0x40..=0x7e).contains(&bytes[i]) {
                i += 1;
            }
            assert!(i < bytes.len(), "unterminated CSI at byte {start}");
            out.push(String::from_utf8_lossy(&bytes[start..=i]).into_owned());
            i += 1;
        }
        out
    }

    /// Spec T2 and plan C2/C3: the classic 16-colour SGR codes, dim, bold,
    /// reset, column 1, clear line, cursor up and the synchronized-update
    /// brackets. Nothing else may leave the renderer.
    fn is_allowed_csi(seq: &str) -> bool {
        const FIXED: [&str; 11] = [
            "\x1b[34m",
            "\x1b[32m",
            "\x1b[33m",
            "\x1b[31m",
            "\x1b[2m",
            "\x1b[1m",
            "\x1b[0m",
            "\x1b[1G",
            "\x1b[2K",
            "\x1b[?2026h",
            "\x1b[?2026l",
        ];
        if FIXED.contains(&seq) {
            return true;
        }
        seq.strip_prefix("\x1b[")
            .and_then(|s| s.strip_suffix('A'))
            .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
    }

    fn ca_card() -> Card {
        Card {
            headline: "aitmproxy · listening 127.0.0.1:8080 · CA untrusted".to_string(),
            headline_role: Role::Success,
            rows: vec![
                Row {
                    label: "CA",
                    value: "untrusted".to_string(),
                    value_role: Role::Warning,
                    next: Some("aitm ca install".to_string()),
                },
                Row {
                    label: "Log",
                    value: "/Users/matt/x.log".to_string(),
                    value_role: Role::Dim,
                    next: None,
                },
            ],
        }
    }

    fn boom_event() -> UiEvent {
        UiEvent {
            level: tracing::Level::ERROR,
            target: "aitm::wire".to_string(),
            message: "boom".to_string(),
            fields: Vec::new(),
        }
    }

    #[test]
    fn a_thousand_plain_phases_print_one_line_each_and_no_control_bytes() {
        let sink = SharedSink::new();
        let reporter =
            Reporter::new(utf8_pipe(), Box::new(sink.clone()), Verbosity::Normal).checklist(true);
        for i in 0..1000 {
            reporter
                .phase(&format!("phase {i}"))
                .done(&format!("step {i} ready"));
        }
        reporter.finish();

        let text = sink.text();
        let lines: Vec<&str> = text.split_terminator('\n').collect();
        assert_eq!(lines.len(), 1000);
        for (i, line) in lines.iter().enumerate() {
            assert_eq!(*line, format!("step {i} ready"));
        }
        assert_eq!(text.matches('\n').count(), 1000);
        no_escape_bytes(&sink);
        assert!(matches!(&*reporter.lock(), State::Finished(Some(_))));
    }

    #[test]
    fn reporter_starts_no_thread_until_the_first_message_and_joins_it_on_finish() {
        // Nothing sent: no thread is ever started, and finish leaves the
        // renderer on the caller's side.
        let idle = Reporter::new(
            Caps::plain(),
            Box::new(SharedSink::new()),
            Verbosity::Normal,
        );
        assert!(matches!(&*idle.lock(), State::Idle(_)));
        idle.finish();
        assert!(matches!(&*idle.lock(), State::Finished(Some(_))));

        let sink = ThreadTaggingSink::default();
        let reporter =
            Reporter::new(Caps::plain(), Box::new(sink.clone()), Verbosity::Normal).checklist(true);
        reporter.phase("reading config").done("config defaults");
        assert!(matches!(&*reporter.lock(), State::Running { .. }));
        reporter.finish();
        // `Finished(Some)` is reached only through `JoinHandle::join`: the
        // `aitm-term` thread has exited (AC-W1-30, unit half).
        assert!(matches!(&*reporter.lock(), State::Finished(Some(_))));

        reporter.warn("late");
        assert_eq!(sink.text(), "config defaults\nwarning: late\n");
        let me = std::thread::current().name().map(str::to_string);
        assert_ne!(me.as_deref(), Some(THREAD_NAME));
        assert_eq!(
            sink.writers(),
            vec![Some(THREAD_NAME.to_string()), me],
            "the phase line came from the render thread; after finish the caller writes"
        );
    }

    #[test]
    fn finish_from_another_thread_leaves_a_live_phase_working() {
        let sink = SharedSink::new();
        let reporter =
            Reporter::new(Caps::plain(), Box::new(sink.clone()), Verbosity::Normal).checklist(true);
        let phase = reporter.phase("starting obscura");

        let other = reporter.clone();
        std::thread::spawn(move || other.finish())
            .join()
            .expect("finish on another thread must not panic");
        assert!(matches!(&*reporter.lock(), State::Finished(Some(_))));

        // The phase that outlived the thread ends synchronously, in plain form.
        phase.done("obscura probed 0.3.1");
        assert_eq!(sink.text(), "obscura probed 0.3.1\n");

        // A phase dropped after finish still prints its label.
        drop(reporter.phase("checking CA trust"));
        assert_eq!(sink.text(), "obscura probed 0.3.1\nchecking CA trust\n");
        no_escape_bytes(&sink);
    }

    #[test]
    fn a_failing_sink_never_panics_and_every_blocking_call_returns() {
        for caps in [Caps::plain(), rich_caps(true, true)] {
            let sink = FailingSink::default();
            let attempts = Arc::clone(&sink.0);
            let reporter = Reporter::new(caps, Box::new(sink), Verbosity::Normal).checklist(true);
            let started = Instant::now();

            reporter.header("aitmproxy", "0.5.11");
            let phase = reporter.phase("loading detections");
            phase.progress(12, Some(49));
            phase.done("49 detections ready");
            reporter.phase("binding ports").fail("binding ports");
            reporter.warn("log file unavailable");
            reporter.event(browser_event());
            reporter.card(&bus_card());
            reporter.error(&port_report());
            reporter.finish();
            reporter.warn("late");
            reporter.finish_and_clear();

            assert!(
                started.elapsed() < Duration::from_secs(1),
                "no blocking call may wait on a sink that fails at once ({caps:?})"
            );
            let n = attempts.load(Ordering::Relaxed);
            assert!(
                n >= 6,
                "the sink must have been written to ({caps:?}): {n} attempts"
            );
            assert!(matches!(&*reporter.lock(), State::Finished(Some(_))));
        }
    }

    #[test]
    fn checklist_can_be_turned_on_while_the_thread_runs() {
        let clock = FakeClock::new();
        let sink = SharedSink::new();
        let reporter = Reporter::with_clock(
            Caps::plain(),
            Box::new(sink.clone()),
            Verbosity::Normal,
            clock.clone(),
        );
        let first = reporter.phase("reading config");
        clock.advance(Duration::from_millis(20));
        first.done("first");
        assert!(matches!(&*reporter.lock(), State::Running { .. }));

        let reporter = reporter.checklist(true);
        let second = reporter.phase("loading detections");
        clock.advance(Duration::from_millis(20));
        second.done("second");
        reporter.finish();
        assert_eq!(
            sink.text(),
            "second\n",
            "the fast first phase stays silent; the toggle reached the thread"
        );
    }

    #[test]
    fn finish_and_clear_in_plain_mode_erases_nothing() {
        let sink = SharedSink::new();
        let reporter =
            Reporter::new(Caps::plain(), Box::new(sink.clone()), Verbosity::Normal).checklist(true);
        reporter.header("aitmproxy", "0.5.11");
        reporter.phase("reading config").done("config defaults");
        reporter.finish_and_clear();
        assert_eq!(sink.text(), "aitmproxy 0.5.11\nconfig defaults\n");
        no_escape_bytes(&sink);
        assert!(matches!(&*reporter.lock(), State::Finished(Some(_))));
    }

    #[test]
    fn plain_output_carries_no_control_byte_on_any_path_even_with_colour_allowed() {
        // `CLICOLOR_FORCE=1 aitm 2>file`: colour allowed, no animation. Spec
        // D4: the plain form never emits an escape byte or a carriage return.
        let clock = FakeClock::new();
        let sink = SharedSink::new();
        let caps = Caps {
            color: true,
            ..utf8_pipe()
        };
        let mut r = renderer(caps, Verbosity::Verbose, true, clock.clone(), &sink);
        header(&mut r);
        start(&mut r, &clock, 1, "binding ports");
        r.handle(Msg::Progress {
            id: 1,
            done: 1,
            total: Some(2),
        });
        clock.advance(Duration::from_millis(150));
        r.tick();
        done(
            &mut r,
            &clock,
            1,
            "proxy listening 127.0.0.1:8080 · browser proxy 127.0.0.1:8081",
        );
        start(&mut r, &clock, 2, "binding ports");
        r.handle(Msg::PhaseFail {
            id: 2,
            what: "binding ports".to_string(),
            at: clock.now(),
        });
        r.handle(Msg::Warn("log file unavailable".to_string()));
        r.handle(Msg::Event(browser_event()));
        r.handle(Msg::Event(boom_event()));
        r.handle(Msg::Card(ca_card()));
        r.handle(Msg::Error {
            report: port_report().with_log(Some(PathBuf::from("/Users/matt/x.log"))),
            home: Some(PathBuf::from("/Users/matt")),
        });
        let (ack, acked) = mpsc::sync_channel(1);
        r.handle(Msg::Clear(ack));
        assert_eq!(acked.try_recv(), Ok(()));
        let (ack, acked) = mpsc::sync_channel(1);
        r.handle(Msg::Flush(ack));
        assert_eq!(acked.try_recv(), Ok(()));

        assert_eq!(
            sink.text(),
            "aitmproxy 0.5.11\n\
             proxy listening 127.0.0.1:8080 · browser proxy 127.0.0.1:8081 · in 150 ms\n\
             error: binding ports\n\
             warning: log file unavailable\n\
             warning: embedded browser unavailable; browser.* commands will error engine=obscura error=nope\n\
             error: boom\n\
             CA: untrusted · aitm ca install\n\
             Log: /Users/matt/x.log\n\
             error: cannot start: the proxy port 127.0.0.1:8080 is already in use\n\
             \x20 fix: lsof -nP -iTCP:8080 -sTCP:LISTEN\n\
             \x20 log: /Users/matt/x.log\n"
        );
        no_escape_bytes(&sink);
    }

    #[test]
    fn rich_output_uses_only_the_sixteen_colour_sgr_and_the_cursor_codes() {
        for unicode in [true, false] {
            let clock = FakeClock::new();
            let sink = SharedSink::new();
            let mut r = renderer_with_width(
                rich_caps(true, unicode),
                Verbosity::Verbose,
                true,
                clock.clone(),
                &sink,
                120,
            );
            header(&mut r);
            start(&mut r, &clock, 1, "loading detections");
            start(&mut r, &clock, 2, "starting obscura");
            r.handle(Msg::Progress {
                id: 1,
                done: 12,
                total: Some(49),
            });
            clock.advance(Duration::from_millis(150));
            r.tick();
            clock.advance(Duration::from_millis(100));
            r.tick();
            r.handle(Msg::Warn("log file unavailable".to_string()));
            r.handle(Msg::Event(browser_event()));
            r.handle(Msg::Event(boom_event()));
            done(&mut r, &clock, 1, "49 detections ready");
            r.handle(Msg::PhaseFail {
                id: 2,
                what: "starting obscura".to_string(),
                at: clock.now(),
            });
            r.handle(Msg::Card(ca_card()));
            r.handle(Msg::Error {
                report: port_report().with_log(Some(PathBuf::from("/Users/matt/x.log"))),
                home: Some(PathBuf::from("/Users/matt")),
            });
            let (ack, _acked) = mpsc::sync_channel(1);
            r.handle(Msg::Clear(ack));

            let bytes = sink.bytes();
            let text = sink.text();
            let seqs = csi_sequences(&bytes);
            for seq in &seqs {
                assert!(
                    is_allowed_csi(seq),
                    "forbidden sequence {seq:?} (unicode={unicode}) in {text:?}"
                );
            }
            // The run really exercised every allowed family, so the
            // allow-list check above is not vacuous.
            for must in [
                "\x1b[34m",
                "\x1b[32m",
                "\x1b[33m",
                "\x1b[31m",
                "\x1b[2m",
                "\x1b[0m",
                "\x1b[1G",
                "\x1b[2K",
                "\x1b[1A",
                "\x1b[2A",
                "\x1b[?2026h",
                "\x1b[?2026l",
            ] {
                assert!(
                    seqs.iter().any(|s| s == must),
                    "{must:?} missing (unicode={unicode}) in {text:?}"
                );
            }
            assert!(
                !bytes.contains(&b'\r'),
                "no CR (unicode={unicode}): {text:?}"
            );
            assert!(!text.contains("\x1b[9"), "bright SGR forbidden: {text:?}");
            assert!(
                !text.contains("38;5") && !text.contains("48;5") && !text.contains("38;2"),
                "256/true colour forbidden: {text:?}"
            );
            if !unicode {
                assert!(
                    bytes.iter().all(|b| *b < 0x80),
                    "ASCII glyphs must leave no byte >= 0x80: {text:?}"
                );
            }
        }
    }

    #[test]
    fn ten_column_terminal_truncates_live_lines_and_prints_the_fix_command_whole() {
        let clock = FakeClock::new();
        let sink = SharedSink::new();
        let caps = Caps {
            width: 10,
            ..rich_caps(false, true)
        };
        let mut r = renderer_with_width(caps, Verbosity::Normal, false, clock.clone(), &sink, 10);
        start(&mut r, &clock, 1, "loading detections");
        clock.advance(Duration::from_millis(150));
        r.tick();
        assert_eq!(sink.text(), format!("{BEGIN}{CLR}  ⠋ loadi…\n{END}"));
        assert_eq!(text::width("  ⠋ loadi…"), 10);

        r.handle(Msg::Progress {
            id: 1,
            done: 12,
            total: Some(49),
        });
        clock.advance(Duration::from_millis(100));
        r.tick();
        let text = sink.text();
        assert!(
            text.ends_with(&format!("{BEGIN}{UP1}{CLR}  ⠙ loadi…\n{END}")),
            "{text:?}"
        );

        r.handle(Msg::Error {
            report: port_report(),
            home: None,
        });
        let text = sink.text();
        assert!(
            text.ends_with(&format!(
                "{BEGIN}{UP1}{CLR}  ✕ loadi…\n{END}\n\
                 ✕ cannot start: the proxy port 127.0.0.1:8080 is already in use\n\
                 \n\
                 \x20 ▸ lsof -nP -iTCP:8080 -sTCP:LISTEN\n"
            )),
            "{text:?}"
        );
    }

    #[test]
    fn width_probe_without_a_measurement_falls_back_to_the_caps_width() {
        let sink = SharedSink::new();
        let caps = Caps {
            width: 40,
            ..rich_caps(false, true)
        };
        let mut r = Renderer::new(
            caps,
            Verbosity::Normal,
            false,
            FakeClock::new(),
            Box::new(sink.clone()),
            Box::new(|| None),
            Arc::new(AtomicUsize::new(0)),
        );
        r.handle(Msg::Event(browser_event()));
        assert_eq!(
            sink.text(),
            format!("{BEGIN}{CLR}  ! embedded browser unavailable; brows…\n{END}")
        );
        assert_eq!(text::width("  ! embedded browser unavailable; brows…"), 40);
    }

    #[test]
    fn a_label_wider_than_the_terminal_is_truncated_in_rich_and_whole_in_plain() {
        let long = "x".repeat(200);
        let clock = FakeClock::new();
        let sink = SharedSink::new();
        let mut r = renderer(
            rich_caps(false, true),
            Verbosity::Normal,
            true,
            clock.clone(),
            &sink,
        );
        start(&mut r, &clock, 1, &long);
        clock.advance(Duration::from_millis(150));
        r.tick();
        let live = format!("  ⠋ {}…", "x".repeat(75));
        assert_eq!(sink.text(), format!("{BEGIN}{CLR}{live}\n{END}"));
        assert_eq!(text::width(&live), 80);

        done(&mut r, &clock, 1, &long);
        let collapsed = format!("  ✓ {}…", "x".repeat(75));
        let text = sink.text();
        assert!(
            text.ends_with(&format!("{BEGIN}{UP1}{CLR}{collapsed}\n{END}")),
            "{text:?}"
        );

        // Plain mode never truncates: the summary is printed whole.
        let plain = SharedSink::new();
        let mut r = renderer(utf8_pipe(), Verbosity::Normal, true, clock.clone(), &plain);
        start(&mut r, &clock, 2, &long);
        done(&mut r, &clock, 2, &long);
        assert_eq!(plain.text(), format!("{long}\n"));
    }

    #[test]
    fn progress_follows_the_label_on_the_live_line() {
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
        r.handle(Msg::Progress {
            id: 1,
            done: 12,
            total: Some(49),
        });
        clock.advance(Duration::from_millis(150));
        r.tick();
        assert_eq!(
            sink.text(),
            format!("{BEGIN}{CLR}  ⠋ loading detections 12/49\n{END}")
        );

        r.handle(Msg::Progress {
            id: 1,
            done: 20,
            total: None,
        });
        // Progress for a phase that does not exist is ignored.
        r.handle(Msg::Progress {
            id: 99,
            done: 1,
            total: Some(1),
        });
        clock.advance(Duration::from_millis(100));
        r.tick();
        let text = sink.text();
        assert!(
            text.ends_with(&format!(
                "{BEGIN}{UP1}{CLR}  ⠙ loading detections 20\n{END}"
            )),
            "{text:?}"
        );

        // Plain mode shows no progress: the phase prints nothing until it ends.
        let plain = SharedSink::new();
        let mut r = renderer(
            Caps::plain(),
            Verbosity::Normal,
            true,
            clock.clone(),
            &plain,
        );
        start(&mut r, &clock, 2, "loading detections");
        r.handle(Msg::Progress {
            id: 2,
            done: 12,
            total: Some(49),
        });
        r.tick();
        assert_eq!(plain.text(), "");
        done(&mut r, &clock, 2, "49 detections ready");
        assert_eq!(plain.text(), "49 detections ready\n");
    }

    #[test]
    fn empty_warning_and_empty_event_lines() {
        let empty_event = UiEvent {
            level: tracing::Level::WARN,
            target: "aitm::wire".to_string(),
            message: String::new(),
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
        r.handle(Msg::Warn(String::new()));
        r.handle(Msg::Event(empty_event.clone()));
        assert_eq!(plain.text(), "warning: \nwarning: aitm::wire\n");

        let rich = SharedSink::new();
        let mut r = renderer(
            rich_caps(false, true),
            Verbosity::Normal,
            false,
            FakeClock::new(),
            &rich,
        );
        r.handle(Msg::Warn(String::new()));
        r.handle(Msg::Event(empty_event));
        assert_eq!(
            rich.text(),
            format!("{BEGIN}{CLR}  ! \n{END}{BEGIN}{CLR}  ! aitm::wire\n{END}")
        );
    }

    #[test]
    fn a_redacted_event_renders_token_equals_redacted_in_both_modes() {
        let ev = UiEvent {
            level: tracing::Level::WARN,
            target: "aitm::web".to_string(),
            message: "bridge token minted".to_string(),
            fields: vec![("token".to_string(), crate::event::REDACTED.to_string())],
        };

        let plain = SharedSink::new();
        let mut r = renderer(
            Caps::plain(),
            Verbosity::Normal,
            false,
            FakeClock::new(),
            &plain,
        );
        r.handle(Msg::Event(ev.clone()));
        assert_eq!(
            plain.text(),
            "warning: bridge token minted token=<redacted>\n"
        );

        let rich = SharedSink::new();
        let mut r = renderer(
            rich_caps(true, true),
            Verbosity::Normal,
            false,
            FakeClock::new(),
            &rich,
        );
        r.handle(Msg::Event(ev));
        assert_eq!(
            rich.text(),
            format!(
                "{BEGIN}{CLR}  \x1b[33m!\x1b[0m bridge token minted\x1b[2m · token=<redacted>\x1b[0m\n{END}"
            )
        );
    }

    #[test]
    fn quiet_rich_draws_no_live_region_but_still_shows_events_and_the_panel() {
        let clock = FakeClock::new();
        let sink = SharedSink::new();
        let mut r = renderer_with_width(
            rich_caps(false, true),
            Verbosity::Quiet,
            true,
            clock.clone(),
            &sink,
            120,
        );
        header(&mut r);
        start(&mut r, &clock, 1, "loading detections");
        clock.advance(Duration::from_millis(150));
        r.tick();
        done(&mut r, &clock, 1, "49 detections ready");
        r.handle(Msg::Card(bus_card()));
        assert_eq!(
            sink.text(),
            "",
            "header, phases and card are dropped under -q"
        );

        r.handle(Msg::Event(browser_event()));
        r.handle(Msg::Error {
            report: port_report(),
            home: None,
        });
        assert_eq!(
            sink.text(),
            format!(
                "{BEGIN}{CLR}  ! embedded browser unavailable; browser.* commands will error · engine=obscura · error=nope\n{END}\n\
                 ✕ cannot start: the proxy port 127.0.0.1:8080 is already in use\n\
                 \n\
                 \x20 ▸ lsof -nP -iTCP:8080 -sTCP:LISTEN\n"
            )
        );
    }

    #[test]
    fn finish_and_clear_counts_the_card_and_its_blank_line() {
        let clock = FakeClock::new();
        let sink = SharedSink::new();
        let mut r = renderer(
            rich_caps(false, true),
            Verbosity::Normal,
            true,
            clock.clone(),
            &sink,
        );
        header(&mut r); // header + its blank line: 1 to erase
        start(&mut r, &clock, 1, "reading config");
        done(&mut r, &clock, 1, "config defaults"); // 1 collapsed line
        r.handle(Msg::Card(bus_card())); // blank line + 2 card lines
        let (ack, acked) = mpsc::sync_channel(1);
        r.handle(Msg::Clear(ack));
        assert_eq!(acked.try_recv(), Ok(()));

        let erase = "\x1b[1A\x1b[2K";
        let text = sink.text();
        assert!(text.ends_with(&erase.repeat(5)), "{text:?}");
        assert!(!text.ends_with(&erase.repeat(6)), "{text:?}");

        // A second clear has nothing left to erase.
        let (ack, _acked) = mpsc::sync_channel(1);
        r.handle(Msg::Clear(ack));
        assert_eq!(sink.text(), text);
    }

    #[test]
    fn live_lines_that_end_silently_are_blanked_on_the_next_frame() {
        // Two drawn phases end with an `at` before the first-draw delay
        // (one-shot mode prints nothing for them): the next frame has one
        // line to show over two on screen, so the second is blanked and the
        // cursor steps back over it.
        let clock = FakeClock::new();
        let sink = SharedSink::new();
        let mut r = renderer(
            rich_caps(false, true),
            Verbosity::Normal,
            false,
            clock.clone(),
            &sink,
        );
        let t0 = clock.now();
        start(&mut r, &clock, 1, "a");
        start(&mut r, &clock, 2, "b");
        clock.advance(Duration::from_millis(150));
        r.tick();
        let drawn = sink.text();
        assert_eq!(drawn, format!("{BEGIN}{CLR}  ⠋ a\n{CLR}  ⠋ b\n{END}"));

        let early = t0 + Duration::from_millis(50);
        r.handle(Msg::PhaseDone {
            id: 1,
            summary: "a".to_string(),
            at: early,
        });
        r.handle(Msg::PhaseDone {
            id: 2,
            summary: "b".to_string(),
            at: early,
        });
        assert_eq!(sink.text(), drawn, "a silent end draws nothing by itself");

        r.handle(Msg::Warn("w".to_string()));
        let text = sink.text();
        assert_eq!(
            &text[drawn.len()..],
            format!("{BEGIN}\x1b[2A{CLR}  ! w\n{CLR}\n{UP1}{END}")
        );
    }
    // ---- fix task (panel pass 1): S1 escape injection, Q4 error panel,
    // F4 leading blank line ----

    /// S1 / AC-W1-31: a WARN whose field carries an OSC title change, a BEL,
    /// a C1 CSI (U+009B, `ESC [` in one byte; Sp13) and a line break, through
    /// the real `UiLayer` → reporter → render thread path.
    #[test]
    fn a_warn_event_carrying_osc_bel_and_newline_renders_as_one_clean_line() {
        use crate::tracing_layer::UiLayer;
        use tracing_subscriber::layer::SubscriberExt;

        let sink = SharedSink::new();
        let reporter = Reporter::new(
            rich_caps(true, true),
            Box::new(sink.clone()),
            Verbosity::Normal,
        );
        let subscriber = tracing_subscriber::registry()
            .with(UiLayer::new(reporter.events(), tracing::Level::WARN));
        tracing::subscriber::with_default(subscriber, || {
            tracing::warn!(error = %"a\x1b]0;x\x07b\u{9b}2J\n c", "boom");
        });
        reporter.finish();

        let bytes = sink.bytes();
        let text = sink.text();
        assert!(
            !text.contains("\x1b]"),
            "no OSC may reach the sink: {text:?}"
        );
        assert!(
            !bytes.contains(&0x07),
            "no BEL may reach the sink: {text:?}"
        );
        assert!(
            !text.contains('\u{9b}'),
            "no C1 CSI may reach the sink: {text:?}"
        );
        assert_eq!(
            text::strip_sgr(&text).matches('\n').count(),
            1,
            "the event occupies exactly one line: {text:?}"
        );
        for seq in csi_sequences(&bytes) {
            assert!(
                is_allowed_csi(&seq),
                "only the renderer's own sequences may appear: {seq:?} in {text:?}"
            );
        }
        assert_eq!(
            text,
            format!(
                "{BEGIN}{CLR}  \x1b[33m!\x1b[0m boom\x1b[2m · error=a\u{FFFD}]0;x\u{FFFD}b\u{FFFD}2J  c\x1b[0m\n{END}"
            )
        );
    }

    /// S1, the finding's literal: a cursor-up sequence inside a phase summary.
    #[test]
    fn plain_phase_summary_with_a_cursor_sequence_is_neutralised() {
        let sink = SharedSink::new();
        let reporter =
            Reporter::new(Caps::plain(), Box::new(sink.clone()), Verbosity::Normal).checklist(true);
        reporter.phase("x").done("a\x1b[2Ab");
        reporter.finish();
        assert_eq!(sink.text(), "a\u{FFFD}[2Ab\n");
        assert_eq!(sink.bytes().iter().filter(|b| **b == 0x1b).count(), 0);
    }

    /// S1: every content string a caller hands the reporter is neutralised
    /// where it enters; plain mode, byte for byte.
    #[test]
    fn plain_reporter_neutralises_control_characters_at_every_entry_point() {
        let sink = SharedSink::new();
        let reporter =
            Reporter::new(Caps::plain(), Box::new(sink.clone()), Verbosity::Normal).checklist(true);
        reporter.header("aitm\x1bproxy", "0.5\n11");
        reporter.phase("bind\x07ing").fail("bind\x07ing");
        drop(reporter.phase("drop\rped"));
        reporter.warn("w\x1b]0;t\x07");
        reporter.card(&Card {
            headline: "h".to_string(),
            headline_role: Role::Success,
            rows: vec![Row {
                label: "Bus",
                value: "stdio\u{9b}2J (MCP)".to_string(),
                value_role: Role::Plain,
                next: Some("aitm\u{9b}1A x".to_string()),
            }],
        });
        reporter.error(
            &ErrorReport::failure("cannot start\nok: all good")
                .with_why(vec!["a\tb".to_string()])
                .with_fix("c\rd")
                .with_command("lsof\x1b[2K -i")
                .with_log(Some(PathBuf::from("/tmp/a\x1b]0;x\x07.log"))),
        );
        reporter.finish();

        assert_eq!(
            sink.text(),
            "aitm\u{FFFD}proxy 0.5 11\n\
             error: bind\u{FFFD}ing\n\
             drop ped\n\
             warning: w\u{FFFD}]0;t\u{FFFD}\n\
             Bus: stdio\u{FFFD}2J (MCP) - aitm\u{FFFD}1A x\n\
             error: cannot start ok: all good\n\
             \x20 a b\n\
             \x20 c d\n\
             \x20 fix: lsof\u{FFFD}[2K -i\n\
             \x20 log: /tmp/a\u{FFFD}]0;x\u{FFFD}.log\n"
        );
        assert_eq!(sink.bytes().iter().filter(|b| **b == 0x1b).count(), 0);
        assert!(!sink.bytes().contains(&0x07));
        assert_eq!(
            reporter.display_path(Path::new("/tmp/a\x1bb")),
            "/tmp/a\u{FFFD}b"
        );
    }

    /// S1: a C1 control (U+009B, a one-byte CSI) in a card row value and
    /// headline renders as U+FFFD in the rich form.
    #[test]
    fn rich_card_row_value_with_a_c1_control_renders_the_replacement_character() {
        let sink = SharedSink::new();
        let reporter = Reporter::new(
            rich_caps(false, true),
            Box::new(sink.clone()),
            Verbosity::Normal,
        );
        reporter.card(&Card {
            headline: "h\u{9b}".to_string(),
            headline_role: Role::Success,
            rows: vec![Row {
                label: "Bus",
                value: "stdio\u{9b}2J (MCP)".to_string(),
                value_role: Role::Plain,
                next: None,
            }],
        });
        reporter.finish();
        assert_eq!(
            sink.text(),
            "\n● h\u{FFFD}\n  Bus           stdio\u{FFFD}2J (MCP)\n"
        );
        assert!(!sink.text().contains('\u{9b}'));
    }

    /// Q4 (a): the panel wraps at the width probed for this frame, not the
    /// width measured at startup.
    #[test]
    fn error_panel_wraps_at_the_probed_width_not_the_startup_width() {
        let sink = SharedSink::new();
        // Started at 80 columns; the terminal is 40 wide when the panel is drawn.
        let mut r = renderer_with_width(
            rich_caps(false, true),
            Verbosity::Normal,
            false,
            FakeClock::new(),
            &sink,
            40,
        );
        let report = ErrorReport::failure("cannot start").with_why(vec![
            "It is most likely held by another running `aitm`, the aitmproxy macOS app's embedded core, or another program.".to_string(),
        ]);
        r.handle(Msg::Error {
            report: report.clone(),
            home: None,
        });
        assert_eq!(
            sink.text(),
            "✕ cannot start\n\
             \x20 It is most likely held by another\n\
             \x20 running `aitm`, the aitmproxy macOS\n\
             \x20 app's embedded core, or another\n\
             \x20 program.\n"
        );
        assert_eq!(
            sink.text(),
            report.render_rich(
                &Caps {
                    width: 40,
                    ..rich_caps(false, true)
                },
                &RICH,
                None
            )
        );
    }

    /// Q4 (b): in plain mode a phase still live at error time is collapsed
    /// as `error: <label>` before the panel, as the rich form does with `✕`.
    #[test]
    fn plain_error_collapses_live_phases_as_error_lines_before_the_panel() {
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
        start(&mut r, &clock, 2, "starting obscura");
        clock.advance(Duration::from_millis(150));
        r.handle(Msg::Error {
            report: port_report(),
            home: None,
        });
        assert_eq!(
            sink.text(),
            "error: loading detections\n\
             error: starting obscura\n\
             error: cannot start: the proxy port 127.0.0.1:8080 is already in use\n\
             \x20 fix: lsof -nP -iTCP:8080 -sTCP:LISTEN\n"
        );
        // The phases are gone: a late end prints nothing more.
        done(&mut r, &clock, 1, "49 detections ready");
        assert_eq!(sink.text().matches('\n').count(), 4);
        no_escape_bytes(&sink);
    }

    /// F4: the one-shot usage panel is the first thing on screen; it starts
    /// with the glyph, not a blank line. After a header and a collapsed
    /// phase, exactly one blank line separates them from the panel.
    #[test]
    fn a_panel_as_the_first_rich_output_has_no_leading_blank_line() {
        let sink = SharedSink::new();
        let caps = rich_caps(true, true);
        let mut r = renderer(caps, Verbosity::Normal, false, FakeClock::new(), &sink);
        r.handle(Msg::Error {
            report: port_report(),
            home: None,
        });
        let text = sink.text();
        assert!(
            text.starts_with("\x1b[31m✕\x1b[0m cannot start"),
            "{text:?}"
        );
        assert!(!text.starts_with('\n'), "{text:?}");
        assert_eq!(text, port_report().render_rich(&caps, &RICH, None));

        // Through the public API too: a usage error before anything else.
        let sink = SharedSink::new();
        let reporter = Reporter::new(
            rich_caps(false, true),
            Box::new(sink.clone()),
            Verbosity::Normal,
        );
        reporter.error(&ErrorReport::usage(
            "usage: aitm tui (takes no further arguments)",
        ));
        reporter.finish();
        assert_eq!(
            sink.text(),
            "✕ usage: aitm tui (takes no further arguments)\n\n  ▸ aitm --help\n"
        );

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
        done(&mut r, &clock, 1, "config defaults");
        r.handle(Msg::Error {
            report: port_report(),
            home: None,
        });
        let panel = port_report().render_rich(&rich_caps(false, true), &RICH, None);
        assert_eq!(
            sink.text(),
            format!("›•‹ aitmproxy 0.5.11\n\n{BEGIN}{CLR}  ✓ config defaults\n{END}\n{panel}")
        );
    }
    // ---- fix task (panel pass 1): N1 `Reporter::note`, S3 bounded queue,
    // Q9 `with_home` ----

    /// N1: the one-line success note `main` prints when the stdio MCP
    /// transport ends (spec Open question 3), usable at any time, after
    /// `finish()` included.
    #[test]
    fn note_prints_one_success_line_in_every_mode_including_after_finish() {
        const LINE: &str = "stdin closed · stdio MCP transport ended";

        let sink = SharedSink::new();
        let reporter = Reporter::new(utf8_pipe(), Box::new(sink.clone()), Verbosity::Normal);
        reporter.finish();
        reporter.note(LINE);
        assert_eq!(sink.text(), "stdin closed · stdio MCP transport ended\n");
        no_escape_bytes(&sink);

        // Rich: a done line without a phase, in the same frame as every
        // other finished line; the visible text is `  ✓ <line>`.
        let sink = SharedSink::new();
        let reporter = Reporter::new(
            rich_caps(false, true),
            Box::new(sink.clone()),
            Verbosity::Normal,
        );
        reporter.note(LINE);
        reporter.finish();
        assert_eq!(
            sink.text(),
            format!("{BEGIN}{CLR}  ✓ stdin closed · stdio MCP transport ended\n{END}")
        );
        assert_eq!(
            text::strip_sgr(&sink.text()),
            "  ✓ stdin closed · stdio MCP transport ended\n"
        );

        // The glyph is painted Success when colour is on.
        let sink = SharedSink::new();
        let reporter = Reporter::new(
            rich_caps(true, true),
            Box::new(sink.clone()),
            Verbosity::Normal,
        );
        reporter.note(LINE);
        reporter.finish();
        assert_eq!(
            sink.text(),
            format!(
                "{BEGIN}{CLR}  \x1b[32m✓\x1b[0m stdin closed · stdio MCP transport ended\n{END}"
            )
        );

        // ASCII twins on an ASCII terminal: no byte above 0x7f.
        let sink = SharedSink::new();
        let reporter = Reporter::new(
            rich_caps(false, false),
            Box::new(sink.clone()),
            Verbosity::Normal,
        );
        reporter.note(LINE);
        reporter.finish();
        assert_eq!(
            sink.text(),
            format!("{BEGIN}{CLR}  + stdin closed - stdio MCP transport ended\n{END}")
        );
        assert!(sink.bytes().iter().all(|b| *b < 0x80));

        // Quiet suppresses it, before and after finish.
        let sink = SharedSink::new();
        let reporter = Reporter::new(Caps::plain(), Box::new(sink.clone()), Verbosity::Quiet);
        reporter.note(LINE);
        reporter.finish();
        reporter.note(LINE);
        assert_eq!(sink.text(), "");

        // Sanitised like every other content string.
        let sink = SharedSink::new();
        let reporter = Reporter::new(Caps::plain(), Box::new(sink.clone()), Verbosity::Normal);
        reporter.note("a\x1b[2Ab\nc");
        reporter.finish();
        assert_eq!(sink.text(), "a\u{FFFD}[2Ab c\n");
    }

    /// Fix task (spec Open question 3 / AC-W1-32 wiring gap): `main` calls
    /// `note` after the serving `select!` returns, which is after
    /// `finish()`. On a TTY the note keeps its `✓` there, the one post-finish
    /// message that does: the live region is empty, so the line is written
    /// straight out with no cursor movement and no synchronized update.
    /// Plain caps keep the bare line; Quiet stays silent.
    #[test]
    fn note_after_finish_keeps_its_glyph_on_a_tty_and_moves_no_cursor() {
        const LINE: &str = "stdin closed · stdio MCP transport ended";

        // Rich, no colour: header, a done phase, finish, then the note.
        let clock = FakeClock::new();
        let sink = SharedSink::new();
        let reporter = Reporter::with_clock(
            rich_caps(false, true),
            Box::new(sink.clone()),
            Verbosity::Normal,
            clock.clone(),
        )
        .checklist(true);
        reporter.header("aitmproxy", "0.5.11");
        reporter.phase("reading config").done("config defaults");
        reporter.finish();
        let before = sink.text();
        assert_eq!(
            before,
            format!("›•‹ aitmproxy 0.5.11\n\n{BEGIN}{CLR}  ✓ config defaults\n{END}"),
            "the live renderer drew a rich frame before finish"
        );
        reporter.note(LINE);
        let text = sink.text();
        assert!(text.starts_with(&before), "{text:?}");
        let tail = &text[before.len()..];
        assert_eq!(tail, "  ✓ stdin closed · stdio MCP transport ended\n");
        assert!(
            text.ends_with("  ✓ stdin closed · stdio MCP transport ended\n"),
            "{text:?}"
        );

        // With colour the glyph is painted Success and nothing else written
        // after the finish is an escape: no MoveUp, no column/clear, no
        // synchronized-update bracket.
        let clock = FakeClock::new();
        let sink = SharedSink::new();
        let reporter = Reporter::with_clock(
            rich_caps(true, true),
            Box::new(sink.clone()),
            Verbosity::Normal,
            clock.clone(),
        )
        .checklist(true);
        reporter.header("aitmproxy", "0.5.11");
        reporter.phase("reading config").done("config defaults");
        reporter.finish();
        let before = sink.text();
        assert!(
            before.ends_with(&format!("{CLR}  \x1b[32m✓\x1b[0m config defaults\n{END}")),
            "{before:?}"
        );
        reporter.note(LINE);
        let text = sink.text();
        let tail = &text[before.len()..];
        assert_eq!(
            tail,
            "  \x1b[32m✓\x1b[0m stdin closed · stdio MCP transport ended\n"
        );
        assert!(
            !text::strip_sgr(tail).contains('\x1b'),
            "only SGR after finish: {tail:?}"
        );
        for seq in [BEGIN, END, CLR, UP1] {
            assert!(
                !tail.contains(seq),
                "{seq:?} written after finish: {tail:?}"
            );
        }

        // An ASCII rich terminal after finish: the ASCII twins, no byte
        // above 0x7f.
        let sink = SharedSink::new();
        let reporter = Reporter::new(
            rich_caps(false, false),
            Box::new(sink.clone()),
            Verbosity::Normal,
        );
        reporter.finish();
        reporter.note(LINE);
        assert_eq!(
            sink.text(),
            "  + stdin closed - stdio MCP transport ended\n"
        );
        assert!(sink.bytes().iter().all(|b| *b < 0x80));

        // Plain stays the bare line after finish: a UTF-8 pipe keeps `·`,
        // `Caps::plain()` (no Unicode) gets the ASCII twin.
        let sink = SharedSink::new();
        let reporter = Reporter::new(utf8_pipe(), Box::new(sink.clone()), Verbosity::Normal);
        reporter.finish();
        reporter.note(LINE);
        assert_eq!(sink.text(), "stdin closed · stdio MCP transport ended\n");
        no_escape_bytes(&sink);

        let sink = SharedSink::new();
        let reporter = Reporter::new(Caps::plain(), Box::new(sink.clone()), Verbosity::Normal);
        reporter.finish();
        reporter.note(LINE);
        assert_eq!(sink.text(), "stdin closed - stdio MCP transport ended\n");
        no_escape_bytes(&sink);

        // Quiet on a TTY prints nothing after finish either.
        let sink = SharedSink::new();
        let reporter = Reporter::new(
            rich_caps(false, true),
            Box::new(sink.clone()),
            Verbosity::Quiet,
        );
        reporter.finish();
        reporter.note(LINE);
        assert_eq!(sink.text(), "");

        // Every other post-finish message keeps its plain form on a TTY.
        let sink = SharedSink::new();
        let reporter = Reporter::new(
            rich_caps(false, true),
            Box::new(sink.clone()),
            Verbosity::Normal,
        )
        .checklist(true);
        reporter.finish();
        reporter.warn("late");
        reporter.phase("x").done("y");
        reporter.phase("z").fail("z");
        assert_eq!(sink.text(), "warning: late\ny\nerror: z\n");
        no_escape_bytes(&sink);

        // Still sanitised, still the glyph form: the content never carries
        // its own escape to the terminal.
        let sink = SharedSink::new();
        let reporter = Reporter::new(
            rich_caps(false, true),
            Box::new(sink.clone()),
            Verbosity::Normal,
        );
        reporter.finish();
        reporter.note("a\x1b[2Ab\nc");
        assert_eq!(sink.text(), "  ✓ a\u{FFFD}[2Ab c\n");
    }

    /// S3: the line the renderer prints for warnings dropped while its
    /// queue was full, in both forms, singular and plural, counter reset.
    #[test]
    fn suppressed_warnings_line_in_both_modes() {
        let sink = SharedSink::new();
        let mut r = renderer(
            Caps::plain(),
            Verbosity::Normal,
            false,
            FakeClock::new(),
            &sink,
        );
        r.report_suppressed();
        assert_eq!(sink.text(), "", "nothing dropped, nothing said");
        r.suppressed.store(1, Ordering::Relaxed);
        r.report_suppressed();
        r.report_suppressed();
        assert_eq!(
            sink.text(),
            "warning: 1 warning suppressed\n",
            "the counter is reset once reported"
        );
        r.suppressed.store(44, Ordering::Relaxed);
        r.report_suppressed();
        assert_eq!(
            sink.text(),
            "warning: 1 warning suppressed\nwarning: 44 warnings suppressed\n"
        );

        // Rich, and under -q: warnings still show, so does their count.
        let sink = SharedSink::new();
        let mut r = renderer(
            rich_caps(true, true),
            Verbosity::Quiet,
            false,
            FakeClock::new(),
            &sink,
        );
        r.suppressed.store(3, Ordering::Relaxed);
        r.report_suppressed();
        assert_eq!(
            sink.text(),
            format!("{BEGIN}{CLR}  \x1b[33m!\x1b[0m 3 warnings suppressed\n{END}")
        );
    }

    /// A sink whose writes block until the test opens the gate, so the
    /// render thread can be held mid-line while the queue fills. It reports
    /// each write attempt on `entered` first.
    #[derive(Clone)]
    struct GatedSink {
        inner: SharedSink,
        entered: mpsc::Sender<()>,
        gate: Arc<(Mutex<bool>, std::sync::Condvar)>,
    }

    impl GatedSink {
        fn new() -> (GatedSink, mpsc::Receiver<()>) {
            let (entered, entered_rx) = mpsc::channel();
            let sink = GatedSink {
                inner: SharedSink::new(),
                entered,
                gate: Arc::new((Mutex::new(false), std::sync::Condvar::new())),
            };
            (sink, entered_rx)
        }

        fn open(&self) {
            let (lock, cv) = &*self.gate;
            *lock.lock().unwrap_or_else(PoisonError::into_inner) = true;
            cv.notify_all();
        }
    }

    impl Write for GatedSink {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            let _ = self.entered.send(());
            let (lock, cv) = &*self.gate;
            let mut open = lock.lock().unwrap_or_else(PoisonError::into_inner);
            while !*open {
                open = cv.wait(open).unwrap_or_else(PoisonError::into_inner);
            }
            drop(open);
            self.inner.write(buf)
        }

        fn flush(&mut self) -> std::io::Result<()> {
            self.inner.flush()
        }
    }

    /// S3: with the render thread held on a stalled write, warnings beyond
    /// the queue's capacity are dropped and counted, no caller blocks, and
    /// the count is reported once as the queue drains.
    #[test]
    fn warnings_beyond_the_queue_capacity_are_dropped_counted_and_reported() {
        let (sink, entered) = GatedSink::new();
        let reporter = Reporter::new(Caps::plain(), Box::new(sink.clone()), Verbosity::Normal);
        reporter.warn("first");
        entered
            .recv_timeout(Duration::from_secs(5))
            .expect("the render thread must reach the sink");
        // The thread is inside the write of `first`; the queue is empty.
        let started = Instant::now();
        for i in 2..=QUEUE_CAPACITY + 11 {
            reporter.warn(&format!("w{i}"));
        }
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "a full queue must not block a warning"
        );
        assert_eq!(reporter.inner.suppressed.load(Ordering::Relaxed), 10);

        sink.open();
        reporter.finish();

        let mut expected = String::from("warning: first\n");
        for i in 2..=QUEUE_CAPACITY + 1 {
            expected.push_str(&format!("warning: w{i}\n"));
        }
        expected.push_str("warning: 10 warnings suppressed\n");
        assert_eq!(sink.inner.text(), expected);
        assert_eq!(reporter.inner.suppressed.load(Ordering::Relaxed), 0);
        assert!(matches!(&*reporter.lock(), State::Finished(Some(_))));
    }

    /// Q9: `with_home` is set-once — the first `Some` wins; later calls,
    /// `None` included, change nothing.
    #[test]
    fn with_home_keeps_the_first_home_and_ignores_later_calls() {
        let first = PathBuf::from("/Users/matt");
        let reporter = Reporter::new(
            rich_caps(false, true),
            Box::new(SharedSink::new()),
            Verbosity::Normal,
        )
        .with_home(None)
        .with_home(Some(first.clone()))
        .with_home(Some(PathBuf::from("/Users/other")))
        .with_home(None);
        assert_eq!(reporter.display_home(), Some(first.as_path()));
        assert_eq!(
            reporter.display_path(Path::new("/Users/matt/x.log")),
            "~/x.log"
        );
        assert_eq!(
            reporter.display_path(Path::new("/Users/other/x.log")),
            "/Users/other/x.log"
        );
    }
    // ---- fix task (panel pass 2): S5 bounded sends, Q14 `finished` flag,
    // Sp13 AC-W1-31 literal ----

    /// Q14: `into_plain` records that the renderer finished and leaves the
    /// caps it was built with untouched; `rich()` reads both, `note` reads
    /// `caps.animate` alone for its glyph form. The bytes out are unchanged.
    #[test]
    fn into_plain_leaves_the_caps_untouched_and_turns_rich_off() {
        let caps = rich_caps(true, true);
        let sink = SharedSink::new();
        let r = renderer(caps, Verbosity::Normal, true, FakeClock::new(), &sink);
        assert!(r.rich());
        let mut r = r.into_plain();
        assert!(r.finished);
        assert!(!r.rich(), "a finished renderer draws plain lines");
        assert_eq!(
            r.caps, caps,
            "into_plain must record a flag, not rewrite the caps"
        );
        // Post-finish: a warning in plain form, the note with its glyph.
        r.handle(Msg::Warn("late".to_string()));
        r.handle(Msg::Note("stdin closed".to_string()));
        assert_eq!(
            sink.text(),
            "warning: late\n  \x1b[32m✓\x1b[0m stdin closed\n"
        );

        // A renderer that was never rich stays plain through and through.
        let sink = SharedSink::new();
        let r = renderer(
            Caps::plain(),
            Verbosity::Normal,
            true,
            FakeClock::new(),
            &sink,
        );
        let mut r = r.into_plain();
        assert!(!r.rich());
        assert_eq!(r.caps, Caps::plain());
        r.handle(Msg::Note("stdin closed".to_string()));
        assert_eq!(sink.text(), "stdin closed\n");
    }

    /// S5: a non-droppable message (the card here) on a full queue waits for
    /// room `ACK_TIMEOUT` at most. A sink stalled for that long is a dead
    /// pipe, so the render thread is abandoned as `shutdown` abandons it: the
    /// call returns, its message is dropped, every later call returns at
    /// once, and the thread drains what was queued when the sink moves again.
    #[test]
    fn a_blocking_message_on_a_full_queue_returns_after_the_ack_timeout_and_abandons_the_thread() {
        let (sink, entered) = GatedSink::new();
        let reporter = Reporter::new(Caps::plain(), Box::new(sink.clone()), Verbosity::Normal);
        reporter.warn("first");
        entered
            .recv_timeout(Duration::from_secs(5))
            .expect("the render thread must reach the sink");
        // The thread is inside the write of `first`; fill the queue exactly.
        for i in 2..=QUEUE_CAPACITY + 1 {
            reporter.warn(&format!("w{i}"));
        }
        assert_eq!(
            reporter.inner.suppressed.load(Ordering::Relaxed),
            0,
            "the queue holds exactly QUEUE_CAPACITY warnings"
        );

        // `card` runs on another thread so that a regression to an
        // unbounded block fails this test instead of hanging it.
        let (returned, returned_rx) = mpsc::channel();
        let blocked = reporter.clone();
        let started = Instant::now();
        let caller = std::thread::spawn(move || {
            blocked.card(&bus_card());
            let _ = returned.send(started.elapsed());
        });
        let elapsed = returned_rx
            .recv_timeout(Duration::from_secs(3))
            .expect("card() must return within 3 s on a stalled sink with a full queue");
        caller.join().expect("the caller thread must not panic");
        assert!(
            elapsed >= ACK_TIMEOUT,
            "card() gave up before the 2 s bound: {elapsed:?}"
        );
        assert!(elapsed < Duration::from_secs(3), "{elapsed:?}");
        assert!(
            matches!(&*reporter.lock(), State::Finished(None)),
            "the stalled thread is abandoned"
        );

        // Afterwards nothing blocks and nothing panics.
        let started = Instant::now();
        reporter.warn("late");
        reporter.phase("p").done("d");
        reporter.note("n");
        reporter.error(&port_report());
        reporter.finish();
        reporter.finish_and_clear();
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "no call may wait on an abandoned thread"
        );
        assert_eq!(reporter.inner.suppressed.load(Ordering::Relaxed), 0);

        // The sink moves again: the abandoned thread drains the queued
        // warnings and exits. The card never arrives, nor does anything
        // sent after the abandonment.
        sink.open();
        let mut expected = String::from("warning: first\n");
        for i in 2..=QUEUE_CAPACITY + 1 {
            expected.push_str(&format!("warning: w{i}\n"));
        }
        let drained = Instant::now();
        while sink.inner.text() != expected && drained.elapsed() < Duration::from_secs(5) {
            std::thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(sink.inner.text(), expected);
    }

    /// The chromiumoxide ERROR that reaches the `UiLayer` when `aitm` closes
    /// the embedded browser during an orderly teardown (live dry-run D1).
    fn ws_close_event() -> UiEvent {
        UiEvent {
            level: tracing::Level::ERROR,
            target: "chromiumoxide::conn".to_string(),
            message: "WS Connection error: Ws(Protocol(ResetWithoutClosingHandshake))".to_string(),
            fields: Vec::new(),
        }
    }

    /// Fix task (spec D4/D7, AC-W1-33, live dry-run D1): once the serving
    /// loop has ended `main` quiesces the reporter, so a dependency's
    /// teardown ERROR is no longer folded into the view while the reporter's
    /// own `note`, `warn` and `error` still print. The hook runs after
    /// `finish()`, when no render thread exists; a UTF-8 pipe is plain mode
    /// with the `·` separator (the §9 stdin-EOF case).
    #[test]
    fn quiesce_drops_tracing_events_but_keeps_notes_and_warnings() {
        const LINE: &str = "stdin closed · stdio MCP transport ended";

        let sink = SharedSink::new();
        let reporter =
            Reporter::new(utf8_pipe(), Box::new(sink.clone()), Verbosity::Normal).checklist(true);
        reporter.header("aitmproxy", "0.5.11");
        reporter.phase("reading config").done("config defaults");
        reporter.finish();
        let before = sink.text();
        assert_eq!(before, "aitmproxy 0.5.11\nconfig defaults\n");

        reporter.quiesce();
        reporter.event(ws_close_event());
        assert_eq!(
            sink.text(),
            before,
            "a quiesced reporter drops tracing events"
        );
        reporter.events().send(ws_close_event());
        assert_eq!(sink.text(), before, "the UiLayer's sender honours it too");

        reporter.note(LINE);
        let mut expected = format!("{before}{LINE}\n");
        assert_eq!(sink.text(), expected);

        reporter.warn("late");
        expected.push_str("warning: late\n");
        assert_eq!(sink.text(), expected);

        let report = port_report();
        reporter.error(&report);
        expected.push_str(&report.render_plain(reporter.glyphs()));
        assert_eq!(sink.text(), expected);
        assert!(
            sink.text()
                .contains("cannot start: the proxy port 127.0.0.1:8080 is already in use"),
            "{:?}",
            sink.text()
        );

        // Idempotent and never undone; a quiesce drop is not an S3
        // suppression, so no `n warnings suppressed` line follows.
        reporter.quiesce();
        reporter.event(ws_close_event());
        assert_eq!(sink.text(), expected);
        assert!(!sink.text().contains("WS Connection error"));
        assert!(!sink.text().contains("suppressed"));
        assert_eq!(reporter.inner.suppressed.load(Ordering::Relaxed), 0);
        no_escape_bytes(&sink);

        // `Caps::plain()` proper (no UTF-8): the same rule, ASCII twins.
        let sink = SharedSink::new();
        let reporter = Reporter::new(Caps::plain(), Box::new(sink.clone()), Verbosity::Normal);
        reporter.finish();
        reporter.quiesce();
        reporter.event(ws_close_event());
        reporter.note(LINE);
        assert_eq!(sink.text(), "stdin closed - stdio MCP transport ended\n");
        assert!(sink.bytes().iter().all(|b| *b < 0x80));
    }

    /// The flag is read where a `UiEvent` enters, so an event sent before
    /// `quiesce()` is already in the queue and still prints when the
    /// renderer drains, while one sent after it never reaches the channel,
    /// through `event()` or through the `EventSender` alike.
    #[test]
    fn quiesce_is_not_retroactive_and_the_events_sender_honours_it() {
        let sink = SharedSink::new();
        let reporter = Reporter::new(utf8_pipe(), Box::new(sink.clone()), Verbosity::Normal);
        let sender = reporter.events();
        reporter.event(ws_close_event());
        sender.send(browser_event());
        reporter.quiesce();
        sender.send(ws_close_event());
        reporter.event(browser_event());
        reporter.warn("late");
        reporter.finish();
        assert_eq!(
            sink.text(),
            "error: WS Connection error: Ws(Protocol(ResetWithoutClosingHandshake))\n\
             warning: embedded browser unavailable; browser.* commands will error engine=obscura error=nope\n\
             warning: late\n"
        );
        assert_eq!(
            reporter.inner.suppressed.load(Ordering::Relaxed),
            0,
            "a quiesce drop is not an S3 suppression"
        );
    }

    /// On a TTY (the Ctrl-C case): after `finish()` the event is dropped
    /// before the synchronous renderer sees it and the note keeps its `✓`;
    /// before `finish()`, with the render thread live, the event never
    /// reaches the queue, so the final frame holds only what was drawn.
    #[test]
    fn quiesce_on_a_tty_drops_the_event_and_keeps_the_note_glyph() {
        const LINE: &str = "stdin closed · stdio MCP transport ended";
        let frame = format!("›•‹ aitmproxy 0.5.11\n\n{BEGIN}{CLR}  ✓ config defaults\n{END}");

        let clock = FakeClock::new();
        let sink = SharedSink::new();
        let reporter = Reporter::with_clock(
            rich_caps(false, true),
            Box::new(sink.clone()),
            Verbosity::Normal,
            clock.clone(),
        )
        .checklist(true);
        reporter.header("aitmproxy", "0.5.11");
        reporter.phase("reading config").done("config defaults");
        reporter.finish();
        assert_eq!(sink.text(), frame);
        reporter.quiesce();
        reporter.event(ws_close_event());
        reporter.events().send(ws_close_event());
        assert_eq!(sink.text(), frame, "nothing after the frame");
        reporter.note(LINE);
        let text = sink.text();
        assert_eq!(
            &text[frame.len()..],
            "  ✓ stdin closed · stdio MCP transport ended\n"
        );
        assert!(!text.contains("WS Connection error"), "{text:?}");
        assert!(!text.contains('✕'), "no failed glyph: {text:?}");

        let clock = FakeClock::new();
        let sink = SharedSink::new();
        let reporter = Reporter::with_clock(
            rich_caps(false, true),
            Box::new(sink.clone()),
            Verbosity::Normal,
            clock.clone(),
        )
        .checklist(true);
        reporter.header("aitmproxy", "0.5.11");
        reporter.phase("reading config").done("config defaults");
        reporter.quiesce();
        reporter.event(ws_close_event());
        reporter.events().send(ws_close_event());
        reporter.finish();
        assert_eq!(sink.text(), frame);
    }
}
