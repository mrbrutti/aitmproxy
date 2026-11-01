//! The Profiles tab's state (spec D3, D11): the list, the editor over one
//! `ScanProfile` draft, the check tree and the origin picker, plus the D8
//! origin rule ([`origin_choices`], [`typed_origin`]) the picker, the
//! `:scan <origin>` command and the legacy seed share.

use std::collections::{BTreeMap, BTreeSet};
use std::net::Ipv6Addr;

use aitm_scan_model::{CheckMeta, ProfileListEntry, ScanProfile, SessionProfile};

use super::ScanError;
use crate::model::FlowRow;

/// Which pane of the Profiles tab holds the cursor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ProfilePane {
    #[default]
    List,
    Fields,
    Origins,
    Checks,
}

/// The Profiles tab.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct ProfilesState {
    /// `scan.profile.list`'s entries.
    pub list: Vec<ProfileListEntry>,
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
    fn editor_fields_are_distinct_and_labelled() {
        let labels: BTreeSet<&str> = EDITOR_FIELDS.iter().map(|f| f.label()).collect();
        assert_eq!(labels.len(), EDITOR_FIELDS.len());
        assert_eq!(EDITOR_FIELDS[0].label(), "name");
        assert_eq!(EDITOR_FIELDS[22].label(), "record_probes");
    }
}
