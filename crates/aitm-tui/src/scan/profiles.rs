//! The Profiles tab's state (spec D3, D11): the list, the editor over one
//! `ScanProfile` draft, the check tree and the origin picker, plus the D8
//! origin rule ([`origin_choices`], [`typed_origin`]) the picker, the
//! `:scan <origin>` command and the legacy seed share.

use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv6Addr};

use aitm_scan_model::{
    Accuracy, Canary, CheckMeta, CheckSelection, ChecksResult, CrawlStrategy, HttpVersionPolicy,
    Intensity, L4Seed, L4TargetSpec, L4Transport, LaneKind, OnLost, ProfileListEntry,
    ProfileListResult, RecordProbes, ScanProfile, SessionMode, SessionProfile, Speed, UseBrowser,
};

use super::{lane_token, step, Dir, ScanError};
use crate::model::FlowRow;
use crate::text::{truncate, width};

/// The most `scan.profile.list` rows kept at fold (spec D6, hostile-core
/// bounds; the builder's number: a profile directory of a few dozen files
/// is large).
pub const PROFILES_MAX: usize = 256;

/// The most `scan.checks` entries kept at fold (hostile-core bounds; the
/// builder's number: the bundled catalogue is a few dozen checks).
pub const CHECKS_MAX: usize = 1024;

/// The longest a selector (a check id, a class, a profile name) may be, in
/// bytes, to be kept at fold. A selector is sent back verbatim
/// (`scan.profile.get {name}`, `checks.include`), so an over-long one is
/// dropped rather than cut: a cut selector would name nothing.
pub const SELECTOR_MAX: usize = 128;

/// The widest any display-only string of a folded reply grows, in cells
/// (a check's name, description and remediation, a session's names and
/// canary path, a save reply's path).
const VALUE_MAX: usize = 200;

/// The most cookie and header names a session preview keeps.
const SESSION_NAMES_MAX: usize = 32;

/// The most `previews` entries kept; the map is emptied when a new origin
/// would exceed it (a cheap bound: the editor shows one origin's preview).
const PREVIEWS_MAX: usize = 64;

/// The detail of the uncoded error a `scan.profile.get` reply gets when its
/// `name` is not the key of the tag it answers (spec D6, hostile-core
/// bounds): nothing is folded from such a reply.
pub const OTHER_PROFILE: &str = "reply named a different profile";

/// The detail of the uncoded error a `scan.profile.get` reply gets when
/// the profile is over the draft bounds ([`fold_profile`]; fix round G,
/// G45): the draft is echoed back on `w` and `s`, so it is refused whole,
/// never cut.
pub const PROFILE_BOUNDS: &str = "profile exceeds bounds";

/// The most origins a profile reply may carry to be adopted as the draft
/// (fix round G, G45; the builder's number).
pub const ORIGINS_MAX: usize = 64;
/// The longest an origin of a profile reply may be, in bytes.
const ORIGIN_BYTES_MAX: usize = 2048;
/// The most L4 targets, `audit.ignore` rules and `l4.seeds` a profile
/// reply may carry.
const PROFILE_LIST_MAX: usize = 64;
/// The longest a seed's hex or base64 string may be, in bytes.
const SEED_BYTES_MAX: usize = 1 << 20;

/// The detail of the uncoded error a `scan.session.preview` reply gets when
/// its `origin` is not the key of the tag it answers.
pub const OTHER_ORIGIN: &str = "reply named a different origin";

/// What a bad `t` line is refused with (plan task 10).
pub const L4_TARGET_ERROR: &str = "L4 target must be ip:port[/tcp|udp][ grammar]";

/// Which pane of the Profiles tab holds the cursor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ProfilePane {
    #[default]
    List,
    Fields,
    Origins,
    Checks,
}

/// The widest name and lanes text of the folded profile list, in cells,
/// measured once at fold (fix round G, G51) so a frame clamps two numbers
/// instead of measuring every row.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ListWidths {
    pub name: usize,
    pub lanes: usize,
}

/// The Profiles tab.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct ProfilesState {
    /// `scan.profile.list`'s entries, each row's lanes sorted and deduped
    /// at fold (the four kinds at most; fix round G, G51).
    pub list: Vec<ProfileListEntry>,
    /// The rows' lanes column, index for index with `list`
    /// ([`lanes_text`] of each row's lanes, built once at fold).
    pub lanes_text: Vec<String>,
    /// The widest name and lanes text of `list`, measured at fold.
    pub widest: ListWidths,
    /// The list cursor.
    pub cursor: usize,
    pub pane: ProfilePane,
    /// The open editor, if any.
    pub editor: Option<ProfileEditor>,
    /// `scan.checks`' catalogue, the check tree's leaves.
    pub checks: Vec<CheckMeta>,
    /// `scan.session.preview` results by origin (names only are in the type).
    pub previews: BTreeMap<String, SessionProfile>,
    /// This tab's last error.
    pub error: Option<ScanError>,
}

/// Where an origin choice in the picker came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OriginSource {
    /// An HTTP scope entry.
    FromScope,
    /// A host seen in the flow list.
    FromFlows,
    /// Typed by the operator (`o`).
    Typed,
}

/// One row of the origin picker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OriginChoice {
    pub origin: String,
    pub source: OriginSource,
}

/// A check-tree node's own selector state (spec D3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TriState {
    #[default]
    Default,
    Include,
    Exclude,
}

/// The mark a builtin profile carries in the list (spec D11 mockup:
/// `passive-only ·`; the builder's glyph, flat monochrome).
pub const BUILTIN_MARK: &str = "·";

/// The tri-state glyphs of the check tree (spec "Left to the builder",
/// `◆ ◇ ○` or similar; flat monochrome, D13): a filled diamond for a
/// selector the profile includes, a hollow one for the engine's default,
/// a barred circle for one it excludes. All three are one cell wide.
pub const INCLUDE_GLYPH: &str = "◆";
pub const DEFAULT_GLYPH: &str = "◇";
pub const EXCLUDE_GLYPH: &str = "⊘";

/// The collapse markers before a lane or class node of the check tree
/// (builder's glyphs): `▾` while its children are shown, `▸` while they
/// are hidden (`h` / `l`); a check node has none.
pub const OPEN_MARK: &str = "▾";
pub const COLLAPSED_MARK: &str = "▸";

impl TriState {
    /// The node's glyph: [`INCLUDE_GLYPH`], [`DEFAULT_GLYPH`] or
    /// [`EXCLUDE_GLYPH`].
    pub fn glyph(self) -> &'static str {
        match self {
            TriState::Default => DEFAULT_GLYPH,
            TriState::Include => INCLUDE_GLYPH,
            TriState::Exclude => EXCLUDE_GLYPH,
        }
    }
}

/// The editor over one profile draft.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct ProfileEditor {
    /// The profile name the draft was loaded from; `None` for a new profile.
    pub loaded_from: Option<String>,
    /// Loaded from a builtin (save asks for a new name).
    pub builtin: bool,
    /// The whole typed copy; fields outside [`EDITOR_FIELDS`] round-trip
    /// untouched.
    pub draft: ScanProfile,
    /// Edited since load or save.
    pub dirty: bool,
    /// Index into [`EDITOR_FIELDS`].
    pub field: usize,
    /// Cursor in the flattened check tree.
    pub tree_cursor: usize,
    /// Collapsed tree node keys.
    pub collapsed: BTreeSet<String>,
    /// Cursor in the origin picker.
    pub origin_cursor: usize,
    /// The origin picker's rows.
    pub origin_choices: Vec<OriginChoice>,
}

/// The editor's fields, in the fixed D3 order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EditorField {
    Name,
    Origins,
    L4Targets,
    LaneHttp,
    LaneWs,
    LaneL4Packet,
    LaneL4Stream,
    Intensity,
    Speed,
    Accuracy,
    Checks,
    CrawlStrategy,
    UseBrowser,
    MaxDepth,
    MaxPages,
    SubmitForms,
    SessionMode,
    OnLost,
    BudgetProbes,
    BudgetTimeS,
    BudgetMaxIssues,
    HttpVersion,
    RecordProbes,
}

/// Every editor field, in the order the Fields pane walks them (spec D3).
pub const EDITOR_FIELDS: [EditorField; 23] = [
    EditorField::Name,
    EditorField::Origins,
    EditorField::L4Targets,
    EditorField::LaneHttp,
    EditorField::LaneWs,
    EditorField::LaneL4Packet,
    EditorField::LaneL4Stream,
    EditorField::Intensity,
    EditorField::Speed,
    EditorField::Accuracy,
    EditorField::Checks,
    EditorField::CrawlStrategy,
    EditorField::UseBrowser,
    EditorField::MaxDepth,
    EditorField::MaxPages,
    EditorField::SubmitForms,
    EditorField::SessionMode,
    EditorField::OnLost,
    EditorField::BudgetProbes,
    EditorField::BudgetTimeS,
    EditorField::BudgetMaxIssues,
    EditorField::HttpVersion,
    EditorField::RecordProbes,
];

impl EditorField {
    /// The field's label. The spec names the fields only by their D3
    /// identifiers (`name, origins, l4_targets, ...`), so the label is that
    /// identifier verbatim: it matches the YAML key an operator reads in a
    /// saved profile (builder's decision).
    pub fn label(self) -> &'static str {
        match self {
            EditorField::Name => "name",
            EditorField::Origins => "origins",
            EditorField::L4Targets => "l4_targets",
            EditorField::LaneHttp => "lane_http",
            EditorField::LaneWs => "lane_ws",
            EditorField::LaneL4Packet => "lane_l4_packet",
            EditorField::LaneL4Stream => "lane_l4_stream",
            EditorField::Intensity => "intensity",
            EditorField::Speed => "speed",
            EditorField::Accuracy => "accuracy",
            EditorField::Checks => "checks",
            EditorField::CrawlStrategy => "crawl_strategy",
            EditorField::UseBrowser => "use_browser",
            EditorField::MaxDepth => "max_depth",
            EditorField::MaxPages => "max_pages",
            EditorField::SubmitForms => "submit_forms",
            EditorField::SessionMode => "session_mode",
            EditorField::OnLost => "on_lost",
            EditorField::BudgetProbes => "budget_probes",
            EditorField::BudgetTimeS => "budget_time_s",
            EditorField::BudgetMaxIssues => "budget_max_issues",
            EditorField::HttpVersion => "http_version",
            EditorField::RecordProbes => "record_probes",
        }
    }
}

/// What a typed or seeded origin is refused with when its host is not a
/// name, an IPv4 address or an IPv6 address (spec D8, hand-off from the fix
/// round A re-review): `host:abc`, `a:b:c`, an empty host. The reducer
/// toasts it and sends nothing.
pub const ORIGIN_HOST_ERROR: &str =
    "origin host must be a name, an IPv4 address or a bracketed IPv6 address";

/// What an origin is refused with when its port is not a number from 1 to
/// 65535 (builder's rule: the authority is validated whole, so a bad port
/// is named as a port, not as a host).
pub const ORIGIN_PORT_ERROR: &str = "origin port must be a number from 1 to 65535";

/// The scheme of a typed origin must be `http` or `https` (builder's rule:
/// the scan lanes speak HTTP; an L4 target is the profile's `l4_targets`
/// field, not an origin).
pub const ORIGIN_SCHEME_ERROR: &str = "origin scheme must be http or https";

/// The D8 origin picker rule: for each concrete (non-wildcard, non-empty)
/// entry of `scope`, `https://host` tagged [`OriginSource::FromScope`], then
/// one `http://host[:port]` tagged [`OriginSource::FromFlows`] per distinct
/// plain-http authority (`FlowRow.scheme == "http"`) of that host among
/// `flows`, the port kept when it is not 80; a wildcard entry yields nothing
/// (the view lists it greyed). An entry carrying a port keeps it in its
/// https origin (an authority entry is an authority); an IPv6 host is
/// bracketed; an entry that fails the authority rule is skipped. No origin
/// is listed twice.
pub fn origin_choices(scope: &[String], flows: &[FlowRow]) -> Vec<OriginChoice> {
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut out = Vec::new();
    let mut push = |origin: String, source: OriginSource, out: &mut Vec<OriginChoice>| {
        if seen.insert(origin.clone()) {
            out.push(OriginChoice { origin, source });
        }
    };
    for entry in scope {
        if entry.is_empty() || entry.starts_with("*.") {
            continue;
        }
        let Ok((host, port)) = authority_parts(entry) else {
            continue;
        };
        push(
            origin("https", &host, port.filter(|p| *p != 443)),
            OriginSource::FromScope,
            &mut out,
        );
        for flow in flows.iter().filter(|f| f.scheme == "http") {
            let Ok((flow_host, flow_port)) = authority_parts(&flow.authority) else {
                continue;
            };
            if !flow_host.eq_ignore_ascii_case(&host) {
                continue;
            }
            push(
                origin("http", &host, flow_port.filter(|p| *p != 80)),
                OriginSource::FromFlows,
                &mut out,
            );
        }
    }
    out
}

/// The D8 rule for a typed origin (`:scan <origin>`, the `o` prompt, the
/// legacy seed): with a scheme, the scheme is kept and the origin is the
/// authority alone (no path, query or fragment; the port as typed); a bare
/// host (or `host:port`) gets the first choice [`origin_choices`] would give
/// it as a scope entry. The host is validated by [`authority_parts`]: an
/// IPv6 host, bare or bracketed, is bracketed in the origin; any other host
/// still carrying a colon after the port rule, or an empty one, is
/// [`ORIGIN_HOST_ERROR`]. The scheme must be `http` or `https`
/// ([`ORIGIN_SCHEME_ERROR`]).
pub fn typed_origin(raw: &str, flows: &[FlowRow]) -> Result<String, String> {
    let s = raw.trim();
    match s.split_once("://") {
        Some((scheme, rest)) => {
            let scheme = scheme.to_ascii_lowercase();
            if scheme != "http" && scheme != "https" {
                return Err(ORIGIN_SCHEME_ERROR.to_string());
            }
            let (host, port) = authority_parts(authority_of(rest))?;
            Ok(origin(&scheme, &host, port))
        }
        None => {
            let authority = authority_of(s);
            authority_parts(authority)?;
            origin_choices(&[authority.to_string()], flows)
                .into_iter()
                .next()
                .map(|c| c.origin)
                .ok_or_else(|| ORIGIN_HOST_ERROR.to_string())
        }
    }
}

/// Fold a `scan.profile.get` reply into the draft the editor opens over
/// (fix round G, G45, G53; D6 hostile-core bounds). The draft is sent back
/// whole on `w` and `s`, so an over-bounds profile is refused, not cut: an
/// uncoded [`PROFILE_BOUNDS`] error under `tag` when `target.origins` has
/// more than [`ORIGINS_MAX`] entries or one that is empty or over 2048
/// bytes, `target.l4` more than 64 targets or one whose `ip` is not an
/// address (bracket-stripped, as [`parse_l4_target`] reads it) or whose
/// `grammar` is over [`SELECTOR_MAX`] bytes or carries a control
/// character, `checks.include`/`exclude` more than [`CHECKS_MAX`] selectors
/// or one that fails the selector rule, `audit.ignore` more than 64 rules,
/// or `l4.seeds` more than 64 seeds or one whose string is over 1 MiB.
/// Within bounds the lanes are sorted and deduped (the four kinds at
/// most) and the profile is returned.
pub fn fold_profile(tag: &str, mut profile: ScanProfile) -> Result<ScanProfile, ScanError> {
    let target = &profile.target;
    let checks = &profile.checks;
    let within = target.origins.len() <= ORIGINS_MAX
        && target
            .origins
            .iter()
            .all(|o| !o.is_empty() && o.len() <= ORIGIN_BYTES_MAX)
        && target.l4.len() <= PROFILE_LIST_MAX
        && target.l4.iter().all(l4_target_within)
        && checks.include.len() <= CHECKS_MAX
        && checks.exclude.len() <= CHECKS_MAX
        && checks
            .include
            .iter()
            .chain(&checks.exclude)
            .all(|s| usable_selector(s))
        && profile.audit.ignore.len() <= PROFILE_LIST_MAX
        && profile.l4.seeds.len() <= PROFILE_LIST_MAX
        && profile.l4.seeds.iter().all(seed_within);
    if !within {
        return Err(ScanError::uncoded(tag, PROFILE_BOUNDS));
    }
    profile.lanes.sort();
    profile.lanes.dedup();
    Ok(profile)
}

/// Whether an L4 target of a profile reply is within bounds (G53): its ip
/// parses as an address once the brackets are stripped, and its grammar,
/// when named, is a usable selector without control characters.
fn l4_target_within(t: &L4TargetSpec) -> bool {
    t.ip.len() <= SELECTOR_MAX
        && t.ip
            .trim_start_matches('[')
            .trim_end_matches(']')
            .parse::<IpAddr>()
            .is_ok()
        && t.grammar
            .as_deref()
            .is_none_or(|g| g.len() <= SELECTOR_MAX && !g.chars().any(char::is_control))
}

/// Whether an L4 seed of a profile reply is within bounds: a flow seed
/// always is (the id is typed), a hex or base64 seed within
/// [`SEED_BYTES_MAX`] bytes.
fn seed_within(seed: &L4Seed) -> bool {
    match seed {
        L4Seed::Flow { .. } => true,
        L4Seed::Hex { hex: s } | L4Seed::Base64 { base64: s } => s.len() <= SEED_BYTES_MAX,
    }
}

/// `scheme://host[:port]`.
fn origin(scheme: &str, host: &str, port: Option<u16>) -> String {
    match port {
        Some(p) => format!("{scheme}://{host}:{p}"),
        None => format!("{scheme}://{host}"),
    }
}

/// The authority of a URL remainder: up to the first `/`, `?` or `#`.
fn authority_of(rest: &str) -> &str {
    rest.find(['/', '?', '#']).map_or(rest, |i| &rest[..i])
}

/// Split an authority into its host and port under the D8 rule. A
/// bracketed IPv6 literal (`[::1]`, `[::1]:8080`) and a bare one (`::1`)
/// both give the bracketed, normalised address; `host:digits` with one
/// colon gives the host and its port; a host left with a colon after that
/// (`host:abc`, `a:b:c`), or an empty host, is [`ORIGIN_HOST_ERROR`]; a port
/// outside 1 to 65535 is [`ORIGIN_PORT_ERROR`]. Pure, so the Site map's
/// legacy nodes and the origin rule parse an authority one way.
pub fn authority_parts(authority: &str) -> Result<(String, Option<u16>), String> {
    let s = authority.trim();
    if let Some(rest) = s.strip_prefix('[') {
        let (v6, tail) = rest.split_once(']').ok_or(ORIGIN_HOST_ERROR)?;
        let ip: Ipv6Addr = v6.parse().map_err(|_| ORIGIN_HOST_ERROR)?;
        let port = match tail {
            "" => None,
            t => Some(parse_port(t.strip_prefix(':').ok_or(ORIGIN_HOST_ERROR)?)?),
        };
        return Ok((format!("[{ip}]"), port));
    }
    let (host, port) = match s.rsplit_once(':') {
        Some((h, p))
            if !h.contains(':') && !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()) =>
        {
            (h, Some(parse_port(p)?))
        }
        _ => (s, None),
    };
    if host.is_empty() {
        return Err(ORIGIN_HOST_ERROR.to_string());
    }
    if let Ok(ip) = host.parse::<Ipv6Addr>() {
        return Ok((format!("[{ip}]"), port));
    }
    if host.contains(':') {
        return Err(ORIGIN_HOST_ERROR.to_string());
    }
    Ok((host.to_string(), port))
}

/// A port from its digits: 1 to 65535, else [`ORIGIN_PORT_ERROR`].
fn parse_port(digits: &str) -> Result<u16, String> {
    match digits.parse::<u16>() {
        Ok(p) if p > 0 => Ok(p),
        _ => Err(ORIGIN_PORT_ERROR.to_string()),
    }
}

/// What `e` (`ScanEdit`) does on a field (spec D11): cycle an enum, toggle
/// a bool or a lane, open the `ScanField` prompt for a number or the name,
/// open the `ScanL4Target` prompt, or focus the Origins or Checks pane.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldKind {
    /// Free text (`name`).
    Text,
    /// A `u32` / `u64`.
    Number,
    /// A bool or a lane: Space and `e` both flip it.
    Toggle,
    /// An enum: `e` steps it forward.
    Cycle,
    /// `origins`: `e` focuses the Origins pane.
    Origins,
    /// `l4_targets`: `e` opens the L4 target prompt.
    L4Targets,
    /// `checks`: `e` focuses the Checks pane.
    Checks,
}

impl EditorField {
    /// How the field is edited.
    pub fn kind(self) -> FieldKind {
        match self {
            EditorField::Name => FieldKind::Text,
            EditorField::Origins => FieldKind::Origins,
            EditorField::L4Targets => FieldKind::L4Targets,
            EditorField::LaneHttp
            | EditorField::LaneWs
            | EditorField::LaneL4Packet
            | EditorField::LaneL4Stream
            | EditorField::SubmitForms => FieldKind::Toggle,
            EditorField::Intensity
            | EditorField::Speed
            | EditorField::Accuracy
            | EditorField::CrawlStrategy
            | EditorField::UseBrowser
            | EditorField::SessionMode
            | EditorField::OnLost
            | EditorField::HttpVersion
            | EditorField::RecordProbes => FieldKind::Cycle,
            EditorField::Checks => FieldKind::Checks,
            EditorField::MaxDepth
            | EditorField::MaxPages
            | EditorField::BudgetProbes
            | EditorField::BudgetTimeS
            | EditorField::BudgetMaxIssues => FieldKind::Number,
        }
    }

    /// The lane a lane field stands for.
    fn lane(self) -> Option<LaneKind> {
        match self {
            EditorField::LaneHttp => Some(LaneKind::Http),
            EditorField::LaneWs => Some(LaneKind::Ws),
            EditorField::LaneL4Packet => Some(LaneKind::L4Packet),
            EditorField::LaneL4Stream => Some(LaneKind::L4Stream),
            _ => None,
        }
    }
}

/// The enum rings `e` cycles, each in the contract's declaration order.
const INTENSITIES: [Intensity; 4] = [
    Intensity::Passive,
    Intensity::Light,
    Intensity::Medium,
    Intensity::Intrusive,
];
const SPEEDS: [Speed; 3] = [Speed::Fast, Speed::Normal, Speed::Thorough];
const ACCURACIES: [Accuracy; 3] = [
    Accuracy::FewerFalseNegatives,
    Accuracy::Normal,
    Accuracy::FewerFalsePositives,
];
const STRATEGIES: [CrawlStrategy; 3] = [
    CrawlStrategy::Fast,
    CrawlStrategy::Normal,
    CrawlStrategy::Thorough,
];
const BROWSERS: [UseBrowser; 3] = [UseBrowser::Auto, UseBrowser::Always, UseBrowser::Never];
const SESSION_MODES: [SessionMode; 2] = [SessionMode::Observed, SessionMode::None];
const ON_LOSTS: [OnLost; 2] = [OnLost::Stop, OnLost::Continue];
const HTTP_VERSIONS: [HttpVersionPolicy; 4] = [
    HttpVersionPolicy::Auto,
    HttpVersionPolicy::H1,
    HttpVersionPolicy::H2,
    HttpVersionPolicy::H2c,
];
const RECORDINGS: [RecordProbes; 2] = [RecordProbes::IssuesOnly, RecordProbes::All];

/// The wire token of a contract enum (`medium`, `fewer_false_negatives`):
/// what the editor shows and the YAML carries. Empty for a value serde
/// cannot write (none of the rings has one).
pub(crate) fn token<T: serde::Serialize>(v: &T) -> String {
    serde_json::to_value(v)
        .ok()
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_default()
}

impl ProfileEditor {
    /// An editor over `draft`, loaded from the profile `loaded_from` (`None`
    /// for a new one), `builtin` when that profile ships with aitmproxy (a
    /// save asks for another name). The picker rows start empty: the
    /// reducer fills them with [`ProfileEditor::refresh_origins`].
    pub fn new(draft: ScanProfile, loaded_from: Option<String>, builtin: bool) -> Self {
        Self {
            loaded_from,
            builtin,
            draft,
            dirty: false,
            field: 0,
            tree_cursor: 0,
            collapsed: BTreeSet::new(),
            origin_cursor: 0,
            origin_choices: Vec::new(),
        }
    }

    /// The field under the Fields cursor.
    pub fn field(&self) -> EditorField {
        EDITOR_FIELDS[self.field.min(EDITOR_FIELDS.len() - 1)]
    }

    /// The current value of the field under the cursor as text: what the
    /// `ScanField` prompt is prefilled with ([`ProfileEditor::text_of`] of
    /// [`ProfileEditor::field`]).
    pub fn field_text(&self) -> String {
        self.text_of(self.field())
    }

    /// The current value of `field` as text: the one text rule the prompt
    /// prefill and the Fields block share (fix round G, G52), read without
    /// moving the cursor or copying the editor.
    pub fn text_of(&self, field: EditorField) -> String {
        let d = &self.draft;
        let on_off = |b: bool| if b { "on" } else { "off" }.to_string();
        match field {
            EditorField::Name => d.name.clone(),
            EditorField::Origins => {
                if d.target.origins.is_empty() {
                    "none".to_string()
                } else {
                    d.target.origins.join(", ")
                }
            }
            EditorField::L4Targets => {
                if d.target.l4.is_empty() {
                    "none".to_string()
                } else {
                    d.target
                        .l4
                        .iter()
                        .map(l4_target_text)
                        .collect::<Vec<_>>()
                        .join(", ")
                }
            }
            f @ (EditorField::LaneHttp
            | EditorField::LaneWs
            | EditorField::LaneL4Packet
            | EditorField::LaneL4Stream) => on_off(f.lane().is_some_and(|l| d.lanes.contains(&l))),
            EditorField::Intensity => token(&d.intensity),
            EditorField::Speed => token(&d.speed),
            EditorField::Accuracy => token(&d.accuracy),
            EditorField::Checks => format!(
                "include {} · exclude {}",
                d.checks.include.len(),
                d.checks.exclude.len()
            ),
            EditorField::CrawlStrategy => token(&d.crawl.strategy),
            EditorField::UseBrowser => token(&d.crawl.use_browser),
            EditorField::MaxDepth => d.crawl.max_depth.to_string(),
            EditorField::MaxPages => d.crawl.max_pages.to_string(),
            EditorField::SubmitForms => on_off(d.crawl.submit_forms),
            EditorField::SessionMode => token(&d.session.mode),
            EditorField::OnLost => token(&d.session.on_lost),
            EditorField::BudgetProbes => d.budget.probes.to_string(),
            EditorField::BudgetTimeS => d.budget.time_s.to_string(),
            EditorField::BudgetMaxIssues => d.budget.max_issues.to_string(),
            EditorField::HttpVersion => token(&d.http.version),
            EditorField::RecordProbes => token(&d.http.record_probes),
        }
    }

    /// Step an enum field forward (declaration order, wrapping), flip a
    /// bool or a lane. Any other field is left alone. Returns whether the
    /// draft changed; a change marks it dirty.
    pub fn cycle(&mut self, field: EditorField) -> bool {
        let d = &mut self.draft;
        let changed = match field {
            EditorField::Intensity => {
                d.intensity = step(&INTENSITIES, d.intensity, Dir::Next);
                true
            }
            EditorField::Speed => {
                d.speed = step(&SPEEDS, d.speed, Dir::Next);
                true
            }
            EditorField::Accuracy => {
                d.accuracy = step(&ACCURACIES, d.accuracy, Dir::Next);
                true
            }
            EditorField::CrawlStrategy => {
                d.crawl.strategy = step(&STRATEGIES, d.crawl.strategy, Dir::Next);
                true
            }
            EditorField::UseBrowser => {
                d.crawl.use_browser = step(&BROWSERS, d.crawl.use_browser, Dir::Next);
                true
            }
            EditorField::SessionMode => {
                d.session.mode = step(&SESSION_MODES, d.session.mode, Dir::Next);
                true
            }
            EditorField::OnLost => {
                d.session.on_lost = step(&ON_LOSTS, d.session.on_lost, Dir::Next);
                true
            }
            EditorField::HttpVersion => {
                d.http.version = step(&HTTP_VERSIONS, d.http.version, Dir::Next);
                true
            }
            EditorField::RecordProbes => {
                d.http.record_probes = step(&RECORDINGS, d.http.record_probes, Dir::Next);
                true
            }
            EditorField::SubmitForms => {
                d.crawl.submit_forms = !d.crawl.submit_forms;
                true
            }
            f => match f.lane() {
                Some(lane) => {
                    if let Some(i) = d.lanes.iter().position(|l| *l == lane) {
                        d.lanes.remove(i);
                    } else {
                        d.lanes.push(lane);
                        // `LaneKind` orders by declaration, so the list
                        // reads as the Fields pane does.
                        d.lanes.sort();
                        d.lanes.dedup();
                    }
                    true
                }
                None => false,
            },
        };
        self.dirty |= changed;
        changed
    }

    /// Write `text` into a text or number field: the name as typed
    /// (trimmed), a number parsed as the field's width; a number field
    /// given anything else is refused with `<label> must be a number`, and
    /// a field that is not text at all with `<label> is not a text field`.
    /// A write marks the draft dirty.
    pub fn set_text(&mut self, field: EditorField, text: &str) -> Result<(), String> {
        let text = text.trim();
        let number = || format!("{} must be a number", field.label());
        let d = &mut self.draft;
        match field {
            EditorField::Name => d.name = text.to_string(),
            EditorField::MaxDepth => d.crawl.max_depth = text.parse().map_err(|_| number())?,
            EditorField::MaxPages => d.crawl.max_pages = text.parse().map_err(|_| number())?,
            EditorField::BudgetProbes => d.budget.probes = text.parse().map_err(|_| number())?,
            EditorField::BudgetTimeS => d.budget.time_s = text.parse().map_err(|_| number())?,
            EditorField::BudgetMaxIssues => {
                d.budget.max_issues = text.parse().map_err(|_| number())?
            }
            other => return Err(format!("{} is not a text field", other.label())),
        }
        self.dirty = true;
        Ok(())
    }

    /// Add `origin` to the draft unless it is there already. Returns
    /// whether it was added (a change marks the draft dirty).
    pub fn add_origin(&mut self, origin: &str) -> bool {
        if self.draft.target.origins.iter().any(|o| o == origin) {
            return false;
        }
        self.draft.target.origins.push(origin.to_string());
        self.dirty = true;
        true
    }

    /// Remove `origin` from the draft. Returns whether it was there.
    pub fn remove_origin(&mut self, origin: &str) -> bool {
        let before = self.draft.target.origins.len();
        self.draft.target.origins.retain(|o| o != origin);
        let removed = self.draft.target.origins.len() != before;
        self.dirty |= removed;
        removed
    }

    /// Add an L4 target unless an equal one is there. Returns whether it
    /// was added.
    pub fn add_l4_target(&mut self, target: L4TargetSpec) -> bool {
        if self.draft.target.l4.contains(&target) {
            return false;
        }
        self.draft.target.l4.push(target);
        self.dirty = true;
        true
    }

    /// Space on the check tree: cycle the node's own selector through
    /// [`toggle_selector`] and mark the draft dirty.
    pub fn toggle_node(&mut self, selector: &str) {
        toggle_selector(&mut self.draft.checks, selector);
        self.dirty = true;
    }

    /// Rebuild the picker rows from the D8 rule over `scope` and `flows`,
    /// keeping the origins the operator typed (`o`) that the rule does not
    /// list, and settle the picker cursor onto the rows.
    pub fn refresh_origins(&mut self, scope: &[String], flows: &[FlowRow]) {
        let mut rows = origin_choices(scope, flows);
        for typed in self
            .origin_choices
            .iter()
            .filter(|c| c.source == OriginSource::Typed)
        {
            if !rows.iter().any(|r| r.origin == typed.origin) {
                rows.push(typed.clone());
            }
        }
        self.origin_choices = rows;
        self.origin_cursor = self
            .origin_cursor
            .min(self.origin_choices.len().saturating_sub(1));
    }

    /// Record an origin the operator typed as a picker row (so `a` and `d`
    /// reach it), once.
    pub fn note_typed_origin(&mut self, origin: &str) {
        if !self.origin_choices.iter().any(|c| c.origin == origin) {
            self.origin_choices.push(OriginChoice {
                origin: origin.to_string(),
                source: OriginSource::Typed,
            });
        }
    }

    /// The picker row under the Origins cursor.
    pub fn highlighted_origin(&self) -> Option<&str> {
        self.origin_choices
            .get(self.origin_cursor)
            .map(|c| c.origin.as_str())
    }
}

/// `ip:port/proto[ grammar]`, the way [`parse_l4_target`] reads it.
pub fn l4_target_text(t: &L4TargetSpec) -> String {
    let proto = match t.proto {
        L4Transport::Tcp => "tcp",
        L4Transport::Udp => "udp",
    };
    match &t.grammar {
        Some(g) => format!("{}:{}/{proto} {g}", t.ip, t.port),
        None => format!("{}:{}/{proto}", t.ip, t.port),
    }
}

/// Read an L4 target from `ip:port[/tcp|udp][ grammar]` (plan task 10):
/// an IPv4 or bracketed IPv6 address, a port from 1 to 65535, `tcp` when
/// no transport is named, and at most one word of grammar after a space.
/// Anything else is [`L4_TARGET_ERROR`].
pub fn parse_l4_target(s: &str) -> Result<L4TargetSpec, String> {
    let err = || L4_TARGET_ERROR.to_string();
    let mut words = s.split_whitespace();
    let head = words.next().ok_or_else(err)?;
    let grammar = words.next().map(str::to_string);
    if words.next().is_some() {
        return Err(err());
    }
    let (addr, proto) = match head.split_once('/') {
        Some((addr, "tcp")) => (addr, L4Transport::Tcp),
        Some((addr, "udp")) => (addr, L4Transport::Udp),
        Some(_) => return Err(err()),
        None => (head, L4Transport::Tcp),
    };
    let (host, port) = authority_parts(addr).map_err(|_| err())?;
    let port = port.ok_or_else(err)?;
    let ip: IpAddr = host
        .trim_start_matches('[')
        .trim_end_matches(']')
        .parse()
        .map_err(|_| err())?;
    Ok(L4TargetSpec {
        ip: ip.to_string(),
        port,
        proto,
        grammar,
    })
}

/// One row of the flattened check tree (spec D3, D11): a lane at depth 0,
/// a class at depth 1, a check at depth 2, each with the one selector its
/// toggle writes (`lane:<lane>`, `<class>`, `<id>`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TreeNode {
    pub depth: u8,
    /// What the row prints: the lane token, the class, the check id.
    pub label: String,
    /// The selector this node's toggle writes.
    pub selector: String,
    /// The check id, on a check node only.
    pub id: Option<String>,
}

/// The lane to class to check tree over `checks` (spec D11), flattened in
/// display order: lanes in declaration order, classes by name under each
/// lane a check lists, check ids by name under their class; a node whose
/// selector is in `collapsed` hides what is under it. A check in two lanes
/// appears under both (the engine resolves a selector lane-free).
pub fn check_tree(checks: &[CheckMeta], collapsed: &BTreeSet<String>) -> Vec<TreeNode> {
    let mut lanes: BTreeMap<LaneKind, BTreeMap<&str, BTreeSet<&str>>> = BTreeMap::new();
    for check in checks {
        for lane in &check.lanes {
            lanes
                .entry(*lane)
                .or_default()
                .entry(check.class.as_str())
                .or_default()
                .insert(check.id.as_str());
        }
    }
    let mut out = Vec::new();
    for (lane, classes) in lanes {
        let lane_selector = format!("lane:{}", lane_token(lane));
        let lane_open = !collapsed.contains(&lane_selector);
        out.push(TreeNode {
            depth: 0,
            label: lane_token(lane).to_string(),
            selector: lane_selector,
            id: None,
        });
        if !lane_open {
            continue;
        }
        for (class, ids) in classes {
            let class_open = !collapsed.contains(class);
            out.push(TreeNode {
                depth: 1,
                label: class.to_string(),
                selector: class.to_string(),
                id: None,
            });
            if !class_open {
                continue;
            }
            for id in ids {
                out.push(TreeNode {
                    depth: 2,
                    label: id.to_string(),
                    selector: id.to_string(),
                    id: Some(id.to_string()),
                });
            }
        }
    }
    out
}

/// A node's own selector state (spec D3): `Exclude` when `selector` is in
/// `exclude` (applied after `include`, so it is what the engine does with a
/// selector listed in both), `Include` when in `include`, `Default`
/// otherwise. Only the node's own selector is read: an id under a listed
/// class reads `Default`.
pub fn tri_state(selection: &CheckSelection, selector: &str) -> TriState {
    if selection.exclude.iter().any(|s| s == selector) {
        TriState::Exclude
    } else if selection.include.iter().any(|s| s == selector) {
        TriState::Include
    } else {
        TriState::Default
    }
}

/// Cycle `selector` through Default, Include, Exclude, Default (spec D3),
/// writing exactly that selector and touching no other entry.
pub fn toggle_selector(selection: &mut CheckSelection, selector: &str) {
    match tri_state(selection, selector) {
        TriState::Default => selection.include.push(selector.to_string()),
        TriState::Include => {
            selection.include.retain(|s| s != selector);
            selection.exclude.push(selector.to_string());
        }
        TriState::Exclude => {
            selection.exclude.retain(|s| s != selector);
            selection.include.retain(|s| s != selector);
        }
    }
}

/// The editor's session line (spec D11): `session: none` for an
/// unauthenticated profile; for an observed one, the preview of the first
/// origin as `session: observed · <cookie and header names> (names) ·
/// canary <METHOD> <path>`, or what is still missing (an origin, or the
/// preview the reducer asked for). Names only ever reach this line: the
/// type carries none of the values (D7) and [`ProfilesState::fold_preview`]
/// cuts a name at any `=`.
pub fn session_line(editor: &ProfileEditor, previews: &BTreeMap<String, SessionProfile>) -> String {
    if editor.draft.session.mode == SessionMode::None {
        return "session: none".to_string();
    }
    let Some(origin) = editor.draft.target.origins.first() else {
        return "session: observed · add an origin (o) to preview it".to_string();
    };
    let Some(preview) = previews.get(origin) else {
        return "session: observed · preview pending".to_string();
    };
    let names: Vec<&str> = preview
        .cookies
        .iter()
        .chain(preview.headers.iter())
        .map(String::as_str)
        .collect();
    let names = if names.is_empty() {
        "no session names".to_string()
    } else {
        names.join(", ")
    };
    let canary = match &preview.canary {
        Canary::None => "canary none".to_string(),
        Canary::Flow { method, path, .. } => format!("canary {} {path}", token(method)),
    };
    format!("session: observed · {names} (names) · {canary}")
}

/// `http ws`: lanes in their wire tokens joined by a space, empty for no
/// lane (the list column; the Jobs detail spells `none`).
pub fn lanes_text(lanes: &[LaneKind]) -> String {
    lanes
        .iter()
        .map(|l| lane_token(*l))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Whether a wire string may be used as a selector or a name the TUI sends
/// back verbatim: non-empty and at most [`SELECTOR_MAX`] bytes.
fn usable_selector(s: &str) -> bool {
    !s.is_empty() && s.len() <= SELECTOR_MAX
}

/// [`truncate`] to [`VALUE_MAX`], skipping the walk when the string is
/// within the cap in bytes.
fn cut(s: &mut String) {
    if s.len() > VALUE_MAX {
        *s = truncate(s, VALUE_MAX);
    }
}

/// A session name as the line may show it: cut at the first `=`, `;` or
/// whitespace (a name has none; a core that sends `name=value` leaks
/// nothing past the name), then bounded.
fn session_name(name: &str) -> String {
    let end = name
        .find(|c: char| c == '=' || c == ';' || c.is_whitespace())
        .unwrap_or(name.len());
    let mut s = name[..end].to_string();
    cut(&mut s);
    s
}

impl ProfilesState {
    /// Fold a `scan.profile.list` reply (spec D10). Hostile-core bounds
    /// (D6): a row whose name is empty or longer than [`SELECTOR_MAX`] is
    /// dropped (the name is the key `scan.profile.get` takes back), the
    /// list is cut to [`PROFILES_MAX`], and the cursor is clamped.
    ///
    /// Each row's lanes are sorted and deduped here and its lanes text and
    /// the two column widths are measured here, once (fix round G, G51),
    /// so a frame only copies.
    pub fn fold_list(&mut self, mut list: ProfileListResult) {
        list.profiles.retain(|p| usable_selector(&p.name));
        list.profiles.truncate(PROFILES_MAX);
        let mut widest = ListWidths::default();
        self.lanes_text = list
            .profiles
            .iter_mut()
            .map(|p| {
                p.summary.lanes.sort();
                p.summary.lanes.dedup();
                let lanes = lanes_text(&p.summary.lanes);
                widest.name = widest.name.max(width(&p.name));
                widest.lanes = widest.lanes.max(width(&lanes));
                lanes
            })
            .collect();
        self.widest = widest;
        self.list = list.profiles;
        self.cursor = self.cursor.min(self.list.len().saturating_sub(1));
    }

    /// Fold a `scan.checks` reply (spec D10). Hostile-core bounds: a check
    /// whose id or class is unusable as a selector is dropped, the
    /// catalogue is cut to [`CHECKS_MAX`], the display strings to
    /// [`VALUE_MAX`] cells, the lane list to its four distinct values, and
    /// the tree cursor is clamped onto the rebuilt tree.
    pub fn fold_checks(&mut self, mut result: ChecksResult) {
        result
            .checks
            .retain(|c| usable_selector(&c.id) && usable_selector(&c.class));
        result.checks.truncate(CHECKS_MAX);
        for check in &mut result.checks {
            cut(&mut check.name);
            cut(&mut check.description);
            if let Some(r) = check.remediation.as_mut() {
                cut(r);
            }
            check.lanes.sort();
            check.lanes.dedup();
            check.kinds.truncate(32);
            if let Some(t) = check.wants_traits.as_mut() {
                t.truncate(32);
            }
        }
        self.checks = result.checks;
        if let Some(editor) = self.editor.as_mut() {
            let rows = check_tree(&self.checks, &editor.collapsed).len();
            editor.tree_cursor = editor.tree_cursor.min(rows.saturating_sub(1));
        }
    }

    /// Fold a `scan.session.preview` reply for `origin` (the tag's key).
    /// Names only are kept, each cut at any `=` and bounded, at most
    /// [`SESSION_NAMES_MAX`] of each kind; the map is emptied before it
    /// would grow past [`PREVIEWS_MAX`] origins.
    pub fn fold_preview(&mut self, origin: &str, mut preview: SessionProfile) {
        preview.cookies.truncate(SESSION_NAMES_MAX);
        preview.headers.truncate(SESSION_NAMES_MAX);
        for name in preview.cookies.iter_mut().chain(preview.headers.iter_mut()) {
            *name = session_name(name);
        }
        cut(&mut preview.origin);
        if let Canary::Flow { path, .. } = &mut preview.canary {
            cut(path);
        }
        if self.previews.len() >= PREVIEWS_MAX && !self.previews.contains_key(origin) {
            self.previews.clear();
        }
        self.previews.insert(origin.to_string(), preview);
    }

    /// The row under the list cursor.
    pub fn cursor_entry(&self) -> Option<&ProfileListEntry> {
        self.list.get(self.cursor)
    }

    /// The flattened check tree for the open editor's collapse state (an
    /// empty tree without one).
    pub fn tree(&self) -> Vec<TreeNode> {
        match &self.editor {
            Some(e) => check_tree(&self.checks, &e.collapsed),
            None => Vec::new(),
        }
    }

    /// The tree node under the Checks cursor.
    pub fn cursor_node(&self) -> Option<TreeNode> {
        let editor = self.editor.as_ref()?;
        check_tree(&self.checks, &editor.collapsed)
            .into_iter()
            .nth(editor.tree_cursor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The authority rule behind D8: brackets and bare IPv6 normalise, one
    /// colon with digits is a port, anything else with a colon is refused.
    #[test]
    fn authority_parts_apply_the_host_and_port_rule() {
        assert_eq!(authority_parts("h"), Ok(("h".to_string(), None)));
        assert_eq!(authority_parts("h:8080"), Ok(("h".to_string(), Some(8080))));
        assert_eq!(authority_parts("::1"), Ok(("[::1]".to_string(), None)));
        assert_eq!(
            authority_parts("[0:0:0:0:0:0:0:1]:443"),
            Ok(("[::1]".to_string(), Some(443)))
        );
        assert_eq!(
            authority_parts("fe80::1:8080"),
            Ok(("[fe80::1:8080]".to_string(), None)),
            "an unbracketed v6 with a trailing group is the address, not a port"
        );
        for bad in ["h:abc", "a:b:c", "", "[::1", "[zz]", "[::1]x"] {
            assert_eq!(
                authority_parts(bad),
                Err(ORIGIN_HOST_ERROR.to_string()),
                "{bad:?}"
            );
        }
        for bad in ["h:0", "h:65536", "[::1]:99999"] {
            assert_eq!(
                authority_parts(bad),
                Err(ORIGIN_PORT_ERROR.to_string()),
                "{bad:?}"
            );
        }
    }

    /// Fix round G, G45/G53: each draft bound refuses the whole profile
    /// with the one detail; a profile within them folds with its lanes
    /// sorted and deduped.
    #[test]
    fn fold_profile_refuses_each_bound_and_dedupes_lanes() {
        let refused = |p: ScanProfile| {
            fold_profile("scan.profile.get:x", p).map_err(|e| e.detail)
                == Err(PROFILE_BOUNDS.into())
        };
        let mut p = ScanProfile {
            lanes: vec![LaneKind::Ws, LaneKind::Http, LaneKind::Http],
            ..ScanProfile::default()
        };
        let ok = fold_profile("scan.profile.get:x", p.clone()).expect("within bounds");
        assert_eq!(ok.lanes, vec![LaneKind::Http, LaneKind::Ws]);

        let mut q = p.clone();
        q.target.origins = vec!["https://h".into(); ORIGINS_MAX + 1];
        assert!(refused(q));
        let mut q = p.clone();
        q.target.origins = vec![String::new()];
        assert!(refused(q));
        let mut q = p.clone();
        q.target.origins = vec!["o".repeat(ORIGIN_BYTES_MAX + 1)];
        assert!(refused(q));
        let l4 = L4TargetSpec {
            ip: "10.0.0.1".into(),
            port: 53,
            proto: L4Transport::Udp,
            grammar: None,
        };
        let mut q = p.clone();
        q.target.l4 = vec![l4.clone(); PROFILE_LIST_MAX + 1];
        assert!(refused(q));
        let mut q = p.clone();
        q.target.l4 = vec![L4TargetSpec {
            ip: "not-an-ip".into(),
            ..l4.clone()
        }];
        assert!(refused(q));
        let mut q = p.clone();
        q.target.l4 = vec![L4TargetSpec {
            ip: "[::1]".into(),
            grammar: Some("dns\u{7}".into()),
            ..l4.clone()
        }];
        assert!(refused(q), "a control character in the grammar");
        let mut q = p.clone();
        q.target.l4 = vec![L4TargetSpec {
            ip: "[::1]".into(),
            grammar: Some("dns".into()),
            ..l4
        }];
        assert!(fold_profile("t", q).is_ok(), "a bracketed v6 ip parses");
        let mut q = p.clone();
        q.checks.include = vec!["c".into(); CHECKS_MAX + 1];
        assert!(refused(q));
        let mut q = p.clone();
        q.checks.exclude = vec!["x".repeat(SELECTOR_MAX + 1)];
        assert!(refused(q));
        let mut q = p.clone();
        q.audit.ignore = vec![Default::default(); PROFILE_LIST_MAX + 1];
        assert!(refused(q));
        let mut q = p.clone();
        q.l4.seeds = vec![L4Seed::Hex { hex: "00".into() }; PROFILE_LIST_MAX + 1];
        assert!(refused(q));
        let mut q = p.clone();
        q.l4.seeds = vec![L4Seed::Base64 {
            base64: "A".repeat(SEED_BYTES_MAX + 1),
        }];
        assert!(refused(q));
        p.l4.seeds = vec![L4Seed::Hex { hex: "00".into() }];
        assert!(fold_profile("t", p).is_ok());
    }

    #[test]
    fn typed_origin_refuses_a_scheme_other_than_http() {
        assert_eq!(
            typed_origin("ftp://h/", &[]),
            Err(ORIGIN_SCHEME_ERROR.to_string())
        );
        assert_eq!(
            typed_origin("HTTPS://H:443", &[]),
            Ok("https://H:443".to_string()),
            "a typed port is kept as typed"
        );
    }

    #[test]
    fn toggle_selector_cycles_one_selector_only() {
        let mut sel = CheckSelection {
            include: vec!["a".into()],
            exclude: vec!["b".into()],
        };
        toggle_selector(&mut sel, "c");
        assert_eq!(sel.include, vec!["a".to_string(), "c".to_string()]);
        toggle_selector(&mut sel, "c");
        assert_eq!(sel.include, vec!["a".to_string()]);
        assert_eq!(sel.exclude, vec!["b".to_string(), "c".to_string()]);
        toggle_selector(&mut sel, "c");
        assert_eq!(sel.include, vec!["a".to_string()]);
        assert_eq!(sel.exclude, vec!["b".to_string()]);
        // Listed in both: exclude wins, and the next toggle clears both.
        let mut both = CheckSelection {
            include: vec!["x".into()],
            exclude: vec!["x".into()],
        };
        assert_eq!(tri_state(&both, "x"), TriState::Exclude);
        toggle_selector(&mut both, "x");
        assert_eq!(both, CheckSelection::default());
    }

    #[test]
    fn session_names_are_cut_at_the_first_separator() {
        assert_eq!(session_name("sid"), "sid");
        assert_eq!(session_name("sid=abc"), "sid");
        assert_eq!(session_name("sid; Path=/"), "sid");
        assert_eq!(session_name("x y"), "x");
        assert_eq!(session_name("=v"), "");
    }

    #[test]
    fn every_field_has_a_kind_and_a_text() {
        // The name is the one field whose text may be empty (an unnamed
        // draft prefills an empty prompt), so the draft gets one here.
        let editor = ProfileEditor::new(
            ScanProfile {
                name: "named".into(),
                ..ScanProfile::default()
            },
            None,
            false,
        );
        for (i, f) in EDITOR_FIELDS.iter().enumerate() {
            let mut e = editor.clone();
            e.field = i;
            assert_eq!(e.field(), *f);
            assert!(!e.field_text().is_empty(), "{f:?} prints something");
        }
        let mut e = editor.clone();
        assert!(!e.cycle(EditorField::Name), "a text field does not cycle");
        assert!(!e.dirty);
        assert!(e.cycle(EditorField::LaneL4Stream));
        assert_eq!(e.draft.lanes, vec![LaneKind::Http, LaneKind::L4Stream]);
        assert!(e.dirty);
        assert_eq!(
            e.set_text(EditorField::Speed, "fast"),
            Err("speed is not a text field".to_string())
        );
        assert_eq!(
            e.set_text(EditorField::BudgetTimeS, "-1"),
            Err("budget_time_s must be a number".to_string())
        );
        assert_eq!(e.set_text(EditorField::BudgetTimeS, " 90 "), Ok(()));
        assert_eq!(e.draft.budget.time_s, 90);
    }

    #[test]
    fn editor_fields_are_distinct_and_labelled() {
        let labels: BTreeSet<&str> = EDITOR_FIELDS.iter().map(|f| f.label()).collect();
        assert_eq!(labels.len(), EDITOR_FIELDS.len());
        assert_eq!(EDITOR_FIELDS[0].label(), "name");
        assert_eq!(EDITOR_FIELDS[22].label(), "record_probes");
    }
}
