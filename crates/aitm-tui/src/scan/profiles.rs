//! The Profiles tab's state (spec D3, D11): the list, the editor over one
//! `ScanProfile` draft, the check tree and the origin picker.

use std::collections::{BTreeMap, BTreeSet};

use aitm_scan_model::{CheckMeta, ProfileListEntry, ScanProfile, SessionProfile};

use super::ScanError;

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn editor_fields_are_distinct_and_labelled() {
        let labels: BTreeSet<&str> = EDITOR_FIELDS.iter().map(|f| f.label()).collect();
        assert_eq!(labels.len(), EDITOR_FIELDS.len());
        assert_eq!(EDITOR_FIELDS[0].label(), "name");
        assert_eq!(EDITOR_FIELDS[22].label(), "record_probes");
    }
}
