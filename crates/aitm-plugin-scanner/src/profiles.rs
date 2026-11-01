//! Profile resolution, validation, clamping and the saved-profile store
//! (spec D3/D11).
//!
//! A scan profile reaches the engine from one of four places: inline in
//! `scan.start`, by name from the `scanner.profiles:` config section, by name
//! from `<findings.dir>/scan/profiles/<name>.yaml`, or as one of the built-ins
//! in `aitm_scan_model`. [`Profiles`] is the one door to all four, so precedence
//! (saved beats config beats built-in), validation and clamping happen in
//! exactly one place and every refusal is the spec D3 wire form
//! `scan: <code>: <message>`.
//!
//! Clamping is deliberately not a refusal: a generous profile still runs, cut
//! down to the administrator's ceilings, and every cut is reported in
//! `scan.start`'s `clamped` list.

use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};

use aitm_scan_model::{
    builtin, builtin_profiles, is_builtin_name, scan_error, Clamped, LaneKind, ProfileDeleteResult,
    ProfileListEntry, ProfileSaveResult, ProfileSummary, ProfileTarget, ScanErrorCode, ScanProfile,
};

use crate::config::{Ceilings, ScannerConfig};
use crate::util::scan_dir;

/// The longest a saved profile name may be, in characters.
const MAX_PROFILE_NAME: usize = 64;

/// Build an `invalid_profile` refusal in the spec D3 wire form.
fn invalid(message: impl fmt::Display) -> anyhow::Error {
    scan_error(ScanErrorCode::InvalidProfile, message)
}

/// Whether a name may become a file under `<findings.dir>/scan/profiles/`:
/// `^[a-z0-9][a-z0-9._-]{0,63}$`.
///
/// This is also the engine's path-traversal guard (wave-1 security review). A
/// name is turned into a file name by [`Profiles::saved_path`] and nowhere
/// else, and only after this returns `true`. Because it is an allowlist, every
/// shape that could leave `<findings.dir>/scan/profiles/` is already out: an
/// empty name, a `/` or `\` separator, `..`, a NUL byte, and a leading `.`
/// (the first character must be a lowercase letter or a digit). Such a name is
/// refused by `save` and `delete` with `invalid_profile` and is never looked
/// for on disk by `get`.
pub fn is_valid_profile_name(name: &str) -> bool {
    let mut chars = name.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !first.is_ascii_lowercase() && !first.is_ascii_digit() {
        return false;
    }
    name.chars().count() <= MAX_PROFILE_NAME
        && chars
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '_' | '-'))
}

/// What `scan.start` and `scan.map` were asked to scan: the three mutually
/// exclusive profile selectors and the optional partial-profile override (spec
/// D3). [`Profiles::resolve`] turns one of these into a validated profile.
#[derive(Debug, Clone, Default)]
pub struct StartArgs {
    /// A complete profile, inline.
    pub profile: Option<ScanProfile>,
    /// The name of a saved, configured or built-in profile.
    pub profile_name: Option<String>,
    /// An origin shorthand: the configured default profile, pointed at it.
    pub target: Option<String>,
    /// A partial profile merged over the selected one.
    pub overrides: Option<serde_json::Value>,
}

/// Every profile the engine can resolve: the config section's, the ones saved
/// on disk, and (through `aitm_scan_model`) the built-ins.
#[derive(Debug, Clone)]
pub struct Profiles {
    /// Profiles from the `scanner.profiles:` config section, by name.
    config: BTreeMap<String, ScanProfile>,
    /// `<findings.dir>/scan/profiles`, or `None` when the scanner has no
    /// findings directory and therefore keeps no profiles on disk.
    saved_dir: Option<PathBuf>,
}

impl Profiles {
    /// The profile store this configuration describes.
    pub fn new(cfg: &ScannerConfig) -> Self {
        Self {
            config: cfg.profiles.clone(),
            saved_dir: cfg
                .findings_dir
                .as_ref()
                .map(|dir| scan_dir(dir, "profiles")),
        }
    }

    /// Where a saved profile with this name would live, or `None` when there is
    /// no profiles directory or the name may not become a file name.
    fn saved_path(&self, name: &str) -> Option<PathBuf> {
        if !is_valid_profile_name(name) {
            return None;
        }
        self.saved_dir
            .as_ref()
            .map(|dir| dir.join(format!("{name}.yaml")))
    }

    /// Every profile on disk, by name. A file that cannot be read or parsed is
    /// skipped: one hand-edited YAML must not blank `scan.profile.list`.
    fn saved_profiles(&self) -> BTreeMap<String, ScanProfile> {
        let mut out = BTreeMap::new();
        let Some(dir) = &self.saved_dir else {
            return out;
        };
        let Ok(entries) = std::fs::read_dir(dir) else {
            return out;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("yaml") {
                continue;
            }
            let Some(name) = path.file_stem().and_then(|s| s.to_str()) else {
                continue;
            };
            if !is_valid_profile_name(name) {
                continue;
            }
            if let Ok(profile) = read_saved(&path) {
                out.insert(name.to_string(), profile);
            }
        }
        out
    }

    /// Every profile a picker can offer, name-sorted (spec D3
    /// `scan.profile.list`).
    ///
    /// Built-ins, then the config section, then the saved profiles: a later
    /// layer's profile replaces an earlier one of the same name, so the summary
    /// shown is the profile [`Profiles::get`] would return.
    pub fn list(&self) -> Vec<ProfileListEntry> {
        let mut by_name: BTreeMap<String, ScanProfile> = BTreeMap::new();
        for profile in builtin_profiles() {
            by_name.insert(profile.name.clone(), profile);
        }
        for (name, profile) in &self.config {
            by_name.insert(name.clone(), profile.clone());
        }
        for (name, profile) in self.saved_profiles() {
            by_name.insert(name, profile);
        }
        by_name
            .into_iter()
            .map(|(name, profile)| ProfileListEntry {
                builtin: is_builtin_name(&name),
                summary: ProfileSummary::from(&profile),
                name,
            })
            .collect()
    }

    /// The profile with this name: saved beats config beats built-in.
    ///
    /// An unknown name is `not_found`; a saved file that cannot be read or
    /// parsed is `invalid_profile` naming the file, never a silent fallback to
    /// the built-in of the same name.
    pub fn get(&self, name: &str) -> anyhow::Result<ScanProfile> {
        if let Some(path) = self.saved_path(name) {
            if path.is_file() {
                return read_saved(&path);
            }
        }
        if let Some(profile) = self.config.get(name) {
            return Ok(profile.clone());
        }
        if let Some(profile) = builtin(name) {
            return Ok(profile);
        }
        Err(scan_error(
            ScanErrorCode::NotFound,
            format!("profile `{name}`"),
        ))
    }

    /// Write a profile to `<findings.dir>/scan/profiles/<name>.yaml` as
    /// human-readable YAML (spec D3 `scan.profile.save`).
    ///
    /// Refused with `invalid_profile` when the profile has no name, when the
    /// name is a built-in's or is not a valid file name, when the profile does
    /// not [`validate`], or when there is no findings directory to write to.
    pub fn save(&self, profile: &ScanProfile) -> anyhow::Result<ProfileSaveResult> {
        let name = profile.name.as_str();
        if name.is_empty() {
            return Err(invalid("a saved profile needs a `name`"));
        }
        if is_builtin_name(name) {
            return Err(invalid(format!(
                "`{name}` is a built-in profile and cannot be saved over"
            )));
        }
        if !is_valid_profile_name(name) {
            return Err(invalid(format!(
                "profile name `{name}` must be lowercase letters, digits, `.`, `_` or `-`, \
                 start with a letter or digit, and be at most {MAX_PROFILE_NAME} characters"
            )));
        }
        validate(profile).map_err(invalid)?;
        // The one place a saved profile's path is built is `saved_path`, so
        // `save`, `get` and `delete` can never disagree about where it lives.
        let path = self.saved_path(name).ok_or_else(|| {
            invalid("`findings.dir` is not set, so there is nowhere to save a profile")
        })?;
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)
                .map_err(|e| invalid(format!("cannot create {}: {e}", dir.display())))?;
        }
        let yaml = serde_yaml::to_string(profile)
            .map_err(|e| invalid(format!("profile `{name}` cannot be written as YAML: {e}")))?;
        std::fs::write(&path, yaml)
            .map_err(|e| invalid(format!("cannot write {}: {e}", path.display())))?;
        Ok(ProfileSaveResult {
            saved: name.to_string(),
            path: path.display().to_string(),
        })
    }

    /// Remove a saved profile (spec D3 `scan.profile.delete`). Idempotent:
    /// deleting what is not there reports `deleted: false`. A built-in's name,
    /// or a name that is not a valid file name, is `invalid_profile`.
    pub fn delete(&self, name: &str) -> anyhow::Result<ProfileDeleteResult> {
        if is_builtin_name(name) {
            return Err(invalid(format!(
                "`{name}` is a built-in profile and cannot be deleted"
            )));
        }
        if !is_valid_profile_name(name) {
            return Err(invalid(format!("`{name}` is not a saved profile name")));
        }
        let Some(path) = self.saved_path(name) else {
            // No findings directory: nothing was ever saved.
            return Ok(ProfileDeleteResult { deleted: false });
        };
        match std::fs::remove_file(&path) {
            Ok(()) => Ok(ProfileDeleteResult { deleted: true }),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                Ok(ProfileDeleteResult { deleted: false })
            }
            Err(e) => Err(invalid(format!("cannot delete {}: {e}", path.display()))),
        }
    }

    /// The profile a `scan.start` or `scan.map` call runs (spec D3).
    ///
    /// Exactly one of `profile`, `profile_name` and `target` selects it;
    /// `overrides` is then merged over it and the result must [`validate`].
    /// Clamping is the caller's next step, not this one's, because the clamp
    /// list belongs in the `scan.start` result.
    pub fn resolve(&self, cfg: &ScannerConfig, args: StartArgs) -> anyhow::Result<ScanProfile> {
        let mut profile = match (args.profile, args.profile_name, args.target) {
            (Some(profile), None, None) => profile,
            (None, Some(name), None) => self.get(&name)?,
            (None, None, Some(target)) => {
                let origin = normalize_origin(&target).map_err(invalid)?;
                let mut profile = self.get(&cfg.default_profile)?;
                profile.target = ProfileTarget {
                    origins: vec![origin],
                    ..profile.target
                };
                profile
            }
            _ => {
                return Err(invalid(
                    "give exactly one of `profile`, `profile_name`, `target`",
                ))
            }
        };
        if let Some(overrides) = args.overrides {
            profile = apply_overrides(&profile, overrides)?;
        }
        validate(&profile).map_err(invalid)?;
        Ok(profile)
    }
}

/// Read one saved profile, reporting the file in any refusal.
fn read_saved(path: &Path) -> anyhow::Result<ScanProfile> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| invalid(format!("cannot read {}: {e}", path.display())))?;
    serde_yaml::from_str(&text).map_err(|e| invalid(format!("{}: {e}", path.display())))
}

/// Merge a partial profile over a resolved one (spec D3 `overrides`).
///
/// The merge is done on JSON, not on the struct, so a caller may name any
/// nested key without the engine enumerating them: objects merge key by key,
/// and a scalar or array replaces what it covers. The merged tree is re-parsed
/// as a [`ScanProfile`], so `deny_unknown_fields` turns a mistyped key into an
/// `invalid_profile` naming it rather than a line that silently does nothing.
fn apply_overrides(
    profile: &ScanProfile,
    overrides: serde_json::Value,
) -> anyhow::Result<ScanProfile> {
    if overrides.is_null() {
        return Ok(profile.clone());
    }
    if !overrides.is_object() {
        return Err(invalid("`overrides` must be an object of profile keys"));
    }
    let mut merged = serde_json::to_value(profile)
        .map_err(|e| invalid(format!("the profile cannot be read as JSON: {e}")))?;
    merge_json(&mut merged, overrides);
    serde_json::from_value(merged).map_err(|e| invalid(format!("`overrides`: {e}")))
}

/// Recursively merge `patch` into `base`: objects merge, anything else replaces.
fn merge_json(base: &mut serde_json::Value, patch: serde_json::Value) {
    match (base, patch) {
        (serde_json::Value::Object(base), serde_json::Value::Object(patch)) => {
            for (key, value) in patch {
                match base.get_mut(&key) {
                    Some(slot) => merge_json(slot, value),
                    None => {
                        base.insert(key, value);
                    }
                }
            }
        }
        (slot, patch) => *slot = patch,
    }
}

/// Normalize an HTTP origin to the `http(s)://host[:port]` form every other
/// scanner surface compares against (spec D2).
///
/// Scheme and host are lowercased, a trailing `/` is dropped and an explicit
/// port is kept. A port that is the scheme's default (`:80` on http, `:443` on
/// https) is dropped, because `http://h:80` and `http://h` are the same origin
/// and the scanner must not treat them as two. Userinfo, a path, a query and a
/// fragment are refused: an origin carries none of them, and silently dropping
/// one would scan something other than what the operator wrote.
///
/// The normal form itself is [`crate::util::normalize_origin`]'s, the one every
/// module compares origins in. That form also knows `ws`/`wss` (an issue's
/// target can be a WebSocket origin); a *profile* origin is
/// `http(s)://host[:port]` (spec D3 `ScanProfile.target.origins`), so a
/// WebSocket scheme is refused here rather than silently accepted.
pub fn normalize_origin(s: &str) -> Result<String, String> {
    let origin = crate::util::normalize_origin(s)?;
    if !(origin.starts_with("http://") || origin.starts_with("https://")) {
        return Err(format!(
            "`{}` is not a profile origin: its scheme is not `http` or `https`",
            s.trim()
        ));
    }
    Ok(origin)
}

/// Whether a profile is runnable, with a message naming the field that is not
/// (spec D3 `invalid_profile`, call B23).
///
/// Everything here is checkable without touching the network or the scope: scope
/// (`out_of_scope`) and lane availability (`lane_unavailable`) are separate
/// refusals the caller makes afterwards.
pub fn validate(p: &ScanProfile) -> Result<(), String> {
    if p.name.trim().is_empty() {
        return Err("a profile needs a `name`".to_string());
    }
    if p.target.origins.is_empty() && p.target.l4.is_empty() {
        return Err("target has no origins and no l4 targets".to_string());
    }
    for origin in &p.target.origins {
        normalize_origin(origin).map_err(|e| format!("`target.origins`: {e}"))?;
    }
    if p.lanes.is_empty() {
        return Err("`lanes` is empty: a profile runs at least one lane".to_string());
    }
    let has_l4_lane = p
        .lanes
        .iter()
        .any(|lane| matches!(lane, LaneKind::L4Packet | LaneKind::L4Stream));
    if has_l4_lane && p.target.l4.is_empty() {
        return Err("an l4 lane needs at least one `target.l4` entry".to_string());
    }
    if !p.target.l4.is_empty() && !has_l4_lane {
        return Err("`target.l4` is set but `lanes` names no l4 lane".to_string());
    }
    for (i, rule) in p.audit.ignore.iter().enumerate() {
        if !rule.is_valid() {
            return Err(format!(
                "`audit.ignore` rule {i} sets no key, so it would ignore every insertion point"
            ));
        }
    }
    if p.budget.probes < 1 {
        return Err("`budget.probes` must be at least 1".to_string());
    }
    if p.budget.time_s < 1 {
        return Err("`budget.time_s` must be at least 1".to_string());
    }
    if p.budget.check_timeout_s < 1 {
        return Err("`budget.check_timeout_s` must be at least 1".to_string());
    }
    Ok(())
}

/// Cut every profile figure down to its configured ceiling, reporting each cut
/// (spec D3/D11).
///
/// `check_timeout_ceiling_s` is `scanner.check_timeout_s`, which is a ceiling
/// like the rest but lives outside the `ceilings:` block. A value above a
/// ceiling is never a refusal: the job runs, bounded, and the caller sees the
/// clamp in `scan.start`'s `clamped` list.
///
/// `budget.check_timeout_s` is clamped by the **lower** of
/// `check_timeout_ceiling_s` and `ceilings.time_s` (wave-1 security review): one
/// check may never be allowed to outlast the whole job, and an unbounded `u64`
/// reaches `Instant + Duration` arithmetic in the scripting engine, where a
/// large enough value overflows.
pub fn clamp(
    p: &mut ScanProfile,
    ceilings: &Ceilings,
    check_timeout_ceiling_s: u64,
) -> Vec<Clamped> {
    let mut clamped = Vec::new();
    clamp_field(
        &mut p.budget.probes,
        ceilings.probes,
        "budget.probes",
        &mut clamped,
    );
    clamp_field(
        &mut p.budget.time_s,
        ceilings.time_s,
        "budget.time_s",
        &mut clamped,
    );
    clamp_field(
        &mut p.budget.max_issues,
        ceilings.max_issues,
        "budget.max_issues",
        &mut clamped,
    );
    clamp_field(
        &mut p.budget.check_timeout_s,
        check_timeout_ceiling_s.min(ceilings.time_s),
        "budget.check_timeout_s",
        &mut clamped,
    );
    clamp_field(&mut p.l4.cases, ceilings.l4_cases, "l4.cases", &mut clamped);
    clamp_field(
        &mut p.l4.max_bytes_per_s,
        ceilings.l4_bytes_per_s,
        "l4.max_bytes_per_s",
        &mut clamped,
    );
    clamp_field(
        &mut p.ws.max_frame_bytes,
        ceilings.ws_frame_bytes,
        "ws.max_frame_bytes",
        &mut clamped,
    );
    clamped
}

/// Clamp one field and record it if it moved.
fn clamp_field<T: Copy + Ord + Into<u64>>(
    value: &mut T,
    ceiling: T,
    field: &str,
    clamped: &mut Vec<Clamped>,
) {
    if *value > ceiling {
        clamped.push(Clamped {
            field: field.to_string(),
            requested: (*value).into(),
            applied: ceiling.into(),
        });
        *value = ceiling;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aitm_scan_model::{Budget, L4Options, L4TargetSpec, LaneKind, WsOptions};
    use std::path::{Path, PathBuf};

    /// A throwaway findings directory that removes itself when the test ends,
    /// pass or panic. `tempfile` is not a dependency of this crate, so the plan
    /// allows `std::env::temp_dir()` plus a UUID subdirectory instead.
    struct TempFindings(PathBuf);

    impl TempFindings {
        fn new() -> Self {
            let dir = std::env::temp_dir().join(format!(
                "aitm-scan-profiles-{}",
                uuid::Uuid::new_v4().simple()
            ));
            std::fs::create_dir_all(&dir).expect("the temporary findings dir is created");
            Self(dir)
        }

        fn path(&self) -> &Path {
            &self.0
        }

        fn config(&self) -> ScannerConfig {
            ScannerConfig {
                findings_dir: Some(self.0.clone()),
                ..ScannerConfig::default()
            }
        }
    }

    impl Drop for TempFindings {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// A profile that passes [`validate`]: named, with one origin.
    fn named_profile(name: &str) -> ScanProfile {
        ScanProfile {
            name: name.to_string(),
            target: ProfileTarget {
                origins: vec!["http://127.0.0.1:8080".to_string()],
                l4: Vec::new(),
            },
            ..ScanProfile::default()
        }
    }

    /// Spec D3: `target` alone runs the profile named by `scanner.default_profile`
    /// with that one origin substituted.
    #[test]
    fn target_alone_uses_the_default_profile() {
        let cfg = ScannerConfig::default();
        let profiles = Profiles::new(&cfg);

        let resolved = profiles
            .resolve(
                &cfg,
                StartArgs {
                    target: Some("http://127.0.0.1:8080/".to_string()),
                    ..StartArgs::default()
                },
            )
            .expect("a bare target resolves");

        assert_eq!(resolved.name, "standard");
        assert_eq!(
            resolved.target.origins,
            vec!["http://127.0.0.1:8080".to_string()]
        );
        assert_eq!(resolved.lanes, vec![LaneKind::Http, LaneKind::Ws]);
    }

    /// Spec D3: exactly one of `profile`, `profile_name`, `target`. Zero and two
    /// are both `invalid_profile`.
    #[test]
    fn two_selectors_is_invalid_profile() {
        let cfg = ScannerConfig::default();
        let profiles = Profiles::new(&cfg);

        let err = profiles
            .resolve(
                &cfg,
                StartArgs {
                    profile: Some(named_profile("inline")),
                    target: Some("http://127.0.0.1:8080".to_string()),
                    ..StartArgs::default()
                },
            )
            .expect_err("two selectors are refused");
        assert!(
            err.to_string().starts_with("scan: invalid_profile:"),
            "two selectors: {err}"
        );

        let err = profiles
            .resolve(&cfg, StartArgs::default())
            .expect_err("no selector is refused");
        assert!(
            err.to_string().starts_with("scan: invalid_profile:"),
            "no selector: {err}"
        );
    }

    /// B23 (T1a follow-up 3): a nameless or targetless profile is refused, and
    /// the message says which of the two is missing.
    #[test]
    fn empty_name_or_target_is_invalid_profile() {
        let err = validate(&ScanProfile::default()).expect_err("a nameless profile is refused");
        assert!(err.contains("name"), "nameless: {err}");

        let targetless = ScanProfile {
            name: "named".to_string(),
            ..ScanProfile::default()
        };
        let err = validate(&targetless).expect_err("a targetless profile is refused");
        assert!(err.contains("target"), "targetless: {err}");

        // The refusal reaches the caller as the D3 wire form.
        let cfg = ScannerConfig::default();
        let err = Profiles::new(&cfg)
            .resolve(
                &cfg,
                StartArgs {
                    profile: Some(targetless),
                    ..StartArgs::default()
                },
            )
            .expect_err("resolve refuses it too");
        assert!(
            err.to_string().starts_with("scan: invalid_profile:"),
            "wire form: {err}"
        );
    }

    /// Spec D3/D11: a profile value above a ceiling is clamped, not refused, and
    /// every clamp is reported with its dotted profile path.
    #[test]
    fn clamp_reports_each_field() {
        let ceilings = Ceilings::default();

        let mut profile = ScanProfile {
            name: "greedy".to_string(),
            budget: Budget {
                probes: 50_000,
                ..Budget::default()
            },
            ..ScanProfile::default()
        };
        assert_eq!(
            clamp(&mut profile, &ceilings, 60),
            vec![Clamped {
                field: "budget.probes".to_string(),
                requested: 50_000,
                applied: 20_000,
            }]
        );
        assert_eq!(profile.budget.probes, 20_000);

        // Every clamped field, in order, with the ceiling it was clamped to.
        let mut all = ScanProfile {
            name: "greediest".to_string(),
            budget: Budget {
                probes: 50_000,
                time_s: 100_000,
                max_issues: 9_000,
                check_timeout_s: 600,
                ..Budget::default()
            },
            ws: WsOptions {
                max_frame_bytes: 8_388_608,
                ..WsOptions::default()
            },
            l4: L4Options {
                cases: 9_999,
                max_bytes_per_s: 4_000_000,
                ..L4Options::default()
            },
            ..ScanProfile::default()
        };
        assert_eq!(
            clamp(&mut all, &ceilings, 60),
            vec![
                Clamped {
                    field: "budget.probes".to_string(),
                    requested: 50_000,
                    applied: 20_000,
                },
                Clamped {
                    field: "budget.time_s".to_string(),
                    requested: 100_000,
                    applied: 7_200,
                },
                Clamped {
                    field: "budget.max_issues".to_string(),
                    requested: 9_000,
                    applied: 4_096,
                },
                Clamped {
                    field: "budget.check_timeout_s".to_string(),
                    requested: 600,
                    applied: 60,
                },
                Clamped {
                    field: "l4.cases".to_string(),
                    requested: 9_999,
                    applied: 5_000,
                },
                Clamped {
                    field: "l4.max_bytes_per_s".to_string(),
                    requested: 4_000_000,
                    applied: 1_048_576,
                },
                Clamped {
                    field: "ws.max_frame_bytes".to_string(),
                    requested: 8_388_608,
                    applied: 4_194_304,
                },
            ]
        );
        assert_eq!(all.budget.time_s, 7_200);
        assert_eq!(all.budget.max_issues, 4_096);
        assert_eq!(all.budget.check_timeout_s, 60);
        assert_eq!(all.l4.cases, 5_000);
        assert_eq!(all.l4.max_bytes_per_s, 1_048_576);
        assert_eq!(all.ws.max_frame_bytes, 4_194_304);

        // A profile under every ceiling is left exactly as written.
        let mut modest = named_profile("modest");
        let before = modest.clone();
        assert_eq!(clamp(&mut modest, &ceilings, 60), Vec::new());
        assert_eq!(modest, before);
    }

    /// Spec D3: `overrides` is a partial profile merged over the resolved one —
    /// nested objects merge key by key, and a mistyped key is `invalid_profile`
    /// naming the key rather than a silently ignored line.
    #[test]
    fn override_merges_nested_and_rejects_unknown() {
        let cfg = ScannerConfig::default();
        let profiles = Profiles::new(&cfg);

        let resolved = profiles
            .resolve(
                &cfg,
                StartArgs {
                    target: Some("http://127.0.0.1:8080".to_string()),
                    overrides: Some(serde_json::json!({ "budget": { "probes": 5 } })),
                    ..StartArgs::default()
                },
            )
            .expect("the override resolves");
        assert_eq!(resolved.budget.probes, 5, "the named key is replaced");
        assert_eq!(
            resolved.budget.time_s, 600,
            "its siblings survive the merge"
        );
        assert_eq!(
            resolved.target.origins,
            vec!["http://127.0.0.1:8080".to_string()],
            "the target survives the merge"
        );

        let err = profiles
            .resolve(
                &cfg,
                StartArgs {
                    target: Some("http://127.0.0.1:8080".to_string()),
                    overrides: Some(serde_json::json!({ "budgte": { "probes": 5 } })),
                    ..StartArgs::default()
                },
            )
            .expect_err("a mistyped key is refused");
        assert!(
            err.to_string().starts_with("scan: invalid_profile:"),
            "wire form: {err}"
        );
        assert!(err.to_string().contains("budgte"), "names the key: {err}");
    }

    /// Spec D3/D11: a saved profile is human-readable YAML under
    /// `<findings.dir>/scan/profiles/`, and save, get, list and delete agree.
    #[test]
    fn save_get_list_delete_round_trip() {
        let tmp = TempFindings::new();
        let cfg = tmp.config();
        let profiles = Profiles::new(&cfg);

        let mine = named_profile("my-api");
        let saved = profiles.save(&mine).expect("the profile is saved");
        assert_eq!(saved.saved, "my-api");
        assert!(
            saved.path.ends_with("scan/profiles/my-api.yaml"),
            "saved to {}",
            saved.path
        );
        assert_eq!(
            PathBuf::from(&saved.path),
            tmp.path().join("scan").join("profiles").join("my-api.yaml")
        );

        let text = std::fs::read_to_string(&saved.path).expect("the file is readable");
        assert!(
            text.lines().any(|line| line == "name: my-api"),
            "human-readable YAML, got:\n{text}"
        );

        assert_eq!(
            profiles
                .get("my-api")
                .expect("the saved profile is read back"),
            mine
        );

        let listed = profiles.list();
        let entry = listed
            .iter()
            .find(|e| e.name == "my-api")
            .expect("the saved profile is listed");
        assert!(!entry.builtin, "a saved profile is not a built-in");
        assert_eq!(entry.summary, ProfileSummary::from(&mine));
        assert!(
            listed.iter().any(|e| e.name == "standard" && e.builtin),
            "the built-ins are listed too"
        );
        let names: Vec<&str> = listed.iter().map(|e| e.name.as_str()).collect();
        let mut sorted = names.clone();
        sorted.sort_unstable();
        assert_eq!(names, sorted, "the list is name-sorted");

        assert!(
            profiles.delete("my-api").expect("delete runs").deleted,
            "the first delete removes it"
        );
        assert!(
            !profiles
                .delete("my-api")
                .expect("delete runs again")
                .deleted,
            "the second delete reports nothing to do"
        );
        assert!(profiles.get("my-api").is_err(), "a deleted profile is gone");
    }

    /// Spec D3: `scan.profile.save` refuses a built-in name, and so does delete —
    /// the shipped profiles cannot be shadowed or removed.
    #[test]
    fn builtin_name_cannot_be_saved_or_deleted() {
        let tmp = TempFindings::new();
        let cfg = tmp.config();
        let profiles = Profiles::new(&cfg);

        let err = profiles
            .save(&named_profile("standard"))
            .expect_err("a built-in name is refused");
        assert!(
            err.to_string().starts_with("scan: invalid_profile:"),
            "save: {err}"
        );
        assert!(err.to_string().contains("standard"), "names it: {err}");

        let err = profiles
            .delete("standard")
            .expect_err("deleting a built-in is refused");
        assert!(
            err.to_string().starts_with("scan: invalid_profile:"),
            "delete: {err}"
        );

        // The built-in is still there.
        assert_eq!(
            profiles.get("standard").expect("still resolves").name,
            "standard"
        );
    }

    /// Spec D11: saved profiles need `findings.dir`. Without it the scanner is
    /// memory-only and says so rather than writing somewhere surprising.
    #[test]
    fn no_findings_dir_refuses_save() {
        let cfg = ScannerConfig::default();
        assert!(cfg.findings_dir.is_none());

        let err = Profiles::new(&cfg)
            .save(&named_profile("my-api"))
            .expect_err("there is nowhere to save");
        assert!(
            err.to_string().starts_with("scan: invalid_profile:"),
            "wire form: {err}"
        );
        assert!(
            err.to_string().contains("findings.dir"),
            "says what is missing: {err}"
        );
    }

    /// Spec D2: an origin is `http(s)://host[:port]` — scheme and host lowercased,
    /// an explicit port kept, the trailing slash dropped, userinfo and a path
    /// refused.
    #[test]
    fn normalize_origin_shapes() {
        assert_eq!(
            normalize_origin("HTTP://Example.test:8080/"),
            Ok("http://example.test:8080".to_string())
        );
        assert_eq!(
            normalize_origin("https://example.test"),
            Ok("https://example.test".to_string())
        );
        assert_eq!(
            normalize_origin("  http://example.test/  "),
            Ok("http://example.test".to_string()),
            "surrounding whitespace is trimmed"
        );

        for bad in [
            "http://u:p@h/",
            "http://h/path",
            "ftp://h",
            "example.test",
            "http://",
            "",
        ] {
            assert!(normalize_origin(bad).is_err(), "`{bad}` is not an origin");
        }
    }

    /// Wave-2/3 security fix: `budget.check_timeout_s: 0` is floored like
    /// `probes` and `time_s` — a zero wall budget would time every check out
    /// at once — and `save` refuses it as `invalid_profile` naming the field.
    #[test]
    fn check_timeout_zero_is_invalid_profile() {
        let mut profile = named_profile("zero-timeout");
        profile.budget.check_timeout_s = 0;

        let err = validate(&profile).expect_err("a zero check timeout is invalid");
        assert!(err.contains("budget.check_timeout_s"), "{err}");

        let tmp = TempFindings::new();
        let profiles = Profiles::new(&tmp.config());
        let err = profiles.save(&profile).expect_err("save refuses it");
        assert!(
            err.to_string().starts_with("scan: invalid_profile:"),
            "{err}"
        );
        assert!(err.to_string().contains("budget.check_timeout_s"), "{err}");
    }

    /// A saved profile wins over a config profile, which wins over a built-in,
    /// and an unknown name is `not_found` (spec D3's precedence).
    #[test]
    fn get_prefers_saved_then_config_then_builtin() {
        let tmp = TempFindings::new();
        let mut cfg = tmp.config();
        cfg.profiles.insert(
            "from-config".to_string(),
            ScanProfile {
                intensity: aitm_scan_model::Intensity::Light,
                ..named_profile("from-config")
            },
        );
        cfg.profiles
            .insert("shadowed".to_string(), named_profile("shadowed"));
        let profiles = Profiles::new(&cfg);

        assert_eq!(
            profiles
                .get("from-config")
                .expect("config profile")
                .intensity,
            aitm_scan_model::Intensity::Light
        );
        assert_eq!(
            profiles.get("standard").expect("built-in profile").name,
            "standard"
        );

        let saved = ScanProfile {
            intensity: aitm_scan_model::Intensity::Passive,
            ..named_profile("shadowed")
        };
        profiles.save(&saved).expect("saves over the config name");
        assert_eq!(profiles.get("shadowed").expect("saved profile wins"), saved);

        let err = profiles
            .get("nope")
            .expect_err("an unknown name is refused");
        assert_eq!(err.to_string(), "scan: not_found: profile `nope`");
    }

    /// Wave-1 security review: a name that would walk out of the profiles
    /// directory never reaches the filesystem — not even to create a file — it
    /// cannot be saved, cannot be deleted, and resolves only against the
    /// in-memory maps.
    #[test]
    fn a_traversing_name_never_touches_the_filesystem() {
        let tmp = TempFindings::new();
        let cfg = tmp.config();
        let profiles = Profiles::new(&cfg);

        for bad in [
            "../x",
            "../escape",
            "../../etc/passwd",
            "..\\x",
            "sub/dir",
            ".hidden",
            "nul\0byte",
            "Upper",
            "",
            "-leading",
        ] {
            let err = profiles
                .save(&named_profile(bad))
                .expect_err("an unsafe name is refused");
            assert!(
                err.to_string().starts_with("scan: invalid_profile:"),
                "save `{bad}`: {err}"
            );

            let err = profiles
                .delete(bad)
                .expect_err("an unsafe name is refused by delete too");
            assert!(
                err.to_string().starts_with("scan: invalid_profile:"),
                "delete `{bad}`: {err}"
            );

            assert!(profiles.get(bad).is_err(), "`{bad}` resolves to no profile");
        }

        // Nothing was written anywhere: not in the profiles directory, not
        // beside it, not above it.
        let profiles_dir = tmp.path().join("scan").join("profiles");
        let written: Vec<PathBuf> = std::fs::read_dir(&profiles_dir)
            .into_iter()
            .flatten()
            .flatten()
            .map(|e| e.path())
            .collect();
        assert!(written.is_empty(), "files were created: {written:?}");
        let escaped: Vec<PathBuf> = std::fs::read_dir(tmp.path())
            .expect("the findings dir is readable")
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.extension().and_then(|e| e.to_str()) == Some("yaml"))
            .collect();
        assert!(escaped.is_empty(), "files escaped upwards: {escaped:?}");
    }

    /// Wave-1 security review: one check may never be allowed to outlast the
    /// whole job, so `budget.check_timeout_s` is clamped by `ceilings.time_s`
    /// too — an unbounded `u64` would reach `Instant + Duration` arithmetic in
    /// the scripting engine.
    #[test]
    fn check_timeout_is_clamped_by_the_time_ceiling() {
        let ceilings = Ceilings {
            time_s: 100,
            ..Ceilings::default()
        };
        let mut profile = ScanProfile {
            budget: Budget {
                time_s: 100,
                check_timeout_s: u64::MAX,
                ..Budget::default()
            },
            ..named_profile("slow-check")
        };

        // Even with `scanner.check_timeout_s` set absurdly high, the job's own
        // time ceiling wins.
        assert_eq!(
            clamp(&mut profile, &ceilings, u64::MAX),
            vec![Clamped {
                field: "budget.check_timeout_s".to_string(),
                requested: u64::MAX,
                applied: 100,
            }]
        );
        assert_eq!(profile.budget.check_timeout_s, 100);

        // The lower of the two ceilings is the one applied.
        let mut profile = ScanProfile {
            budget: Budget {
                time_s: 100,
                check_timeout_s: 5_000,
                ..Budget::default()
            },
            ..named_profile("slow-check")
        };
        assert_eq!(
            clamp(&mut profile, &ceilings, 30),
            vec![Clamped {
                field: "budget.check_timeout_s".to_string(),
                requested: 5_000,
                applied: 30,
            }]
        );
        assert_eq!(profile.budget.check_timeout_s, 30);
    }

    /// An L4 lane needs an L4 target and an L4 target needs an L4 lane; a profile
    /// with neither pairing is refused before a packet is built.
    #[test]
    fn l4_lane_and_target_must_agree() {
        let lane_only = ScanProfile {
            name: "lane-only".to_string(),
            lanes: vec![LaneKind::L4Stream],
            target: ProfileTarget {
                origins: vec!["http://127.0.0.1:8080".to_string()],
                l4: Vec::new(),
            },
            ..ScanProfile::default()
        };
        let err = validate(&lane_only).expect_err("an L4 lane with no L4 target is refused");
        assert!(err.contains("l4"), "{err}");

        let target_only = ScanProfile {
            name: "target-only".to_string(),
            lanes: vec![LaneKind::Http],
            target: ProfileTarget {
                origins: vec!["http://127.0.0.1:8080".to_string()],
                l4: vec![L4TargetSpec {
                    ip: "127.0.0.1".to_string(),
                    port: 9000,
                    ..L4TargetSpec::default()
                }],
            },
            ..ScanProfile::default()
        };
        let err = validate(&target_only).expect_err("an L4 target with no L4 lane is refused");
        assert!(err.contains("lane"), "{err}");

        let paired = ScanProfile {
            lanes: vec![LaneKind::Http, LaneKind::L4Stream],
            ..target_only
        };
        assert_eq!(validate(&paired), Ok(()));
    }

    /// The rest of `validate`'s rules, each with the value that trips it.
    #[test]
    fn validate_refuses_empty_lanes_bad_rules_and_zero_budgets() {
        let base = named_profile("rules");

        let no_lanes = ScanProfile {
            lanes: Vec::new(),
            ..base.clone()
        };
        assert!(validate(&no_lanes)
            .expect_err("no lane is refused")
            .contains("lane"));

        let bad_origin = ScanProfile {
            target: ProfileTarget {
                origins: vec!["not-an-origin".to_string()],
                l4: Vec::new(),
            },
            ..base.clone()
        };
        assert!(validate(&bad_origin)
            .expect_err("a bad origin is refused")
            .contains("not-an-origin"));

        let bad_rule = ScanProfile {
            audit: aitm_scan_model::AuditOptions {
                ignore: vec![aitm_scan_model::IgnoreRule::default()],
                ..aitm_scan_model::AuditOptions::default()
            },
            ..base.clone()
        };
        assert!(validate(&bad_rule)
            .expect_err("an empty ignore rule is refused")
            .contains("ignore"));

        let no_probes = ScanProfile {
            budget: Budget {
                probes: 0,
                ..Budget::default()
            },
            ..base.clone()
        };
        assert!(validate(&no_probes)
            .expect_err("a zero probe budget is refused")
            .contains("budget.probes"));

        let no_time = ScanProfile {
            budget: Budget {
                time_s: 0,
                ..Budget::default()
            },
            ..base
        };
        assert!(validate(&no_time)
            .expect_err("a zero time budget is refused")
            .contains("budget.time_s"));
    }

    // ---- tester additions (edges of the saved store and the resolver) -----

    /// A hand-edited saved file that no longer parses is `invalid_profile`
    /// naming the file — never a silent fallback to a config or built-in
    /// profile of the same name — and `list()` skips it rather than going blank.
    #[test]
    fn a_malformed_saved_file_is_invalid_profile_not_a_silent_fallback() {
        let tmp = TempFindings::new();
        let mut cfg = tmp.config();
        cfg.profiles
            .insert("broken".to_string(), named_profile("broken"));
        let profiles = Profiles::new(&cfg);

        let dir = tmp.path().join("scan").join("profiles");
        std::fs::create_dir_all(&dir).expect("the profiles dir is created");
        std::fs::write(dir.join("broken.yaml"), "name: [unclosed\n  lanes: :::\n")
            .expect("the broken file is written");
        std::fs::write(dir.join("good.yaml"), "name: good\nlanes: [http]\n")
            .expect("the good file is written");

        let err = profiles
            .get("broken")
            .expect_err("a broken saved file must not fall back to the config profile");
        assert!(
            err.to_string().starts_with("scan: invalid_profile:"),
            "wire form: {err}"
        );
        assert!(
            err.to_string().contains("broken.yaml"),
            "names the file: {err}"
        );

        let listed = profiles.list();
        assert!(
            listed.iter().any(|e| e.name == "good" && !e.builtin),
            "the readable saved profile is listed: {listed:?}"
        );
        assert!(
            listed.iter().any(|e| e.name == "standard" && e.builtin),
            "the built-ins are still listed: {listed:?}"
        );
        // The broken file shadows nothing in the list: the config entry shows.
        assert_eq!(
            listed.iter().filter(|e| e.name == "broken").count(),
            1,
            "one entry for the name, from the config layer: {listed:?}"
        );
    }

    /// Spec D2 origin normal form: a port that is the scheme's default is the
    /// same origin as no port at all, and `overrides` must be an object.
    #[test]
    fn default_ports_and_non_object_overrides() {
        assert_eq!(
            normalize_origin("http://h:80/"),
            Ok("http://h".to_string()),
            "`:80` on http is the default port"
        );
        assert_eq!(
            normalize_origin("HTTPS://H.Example:443"),
            Ok("https://h.example".to_string()),
            "`:443` on https is the default port"
        );
        assert_eq!(
            normalize_origin("http://h:443"),
            Ok("http://h:443".to_string()),
            "a non-default port is kept"
        );
        assert!(
            normalize_origin("http://h/?q=1").is_err(),
            "a query is refused"
        );
        assert!(
            normalize_origin("http://h/#frag").is_err(),
            "a fragment is refused"
        );

        let cfg = ScannerConfig::default();
        let profiles = Profiles::new(&cfg);
        for bad in [serde_json::json!([1, 2]), serde_json::json!("probes=5")] {
            let err = profiles
                .resolve(
                    &cfg,
                    StartArgs {
                        target: Some("http://127.0.0.1:8080".to_string()),
                        overrides: Some(bad.clone()),
                        ..StartArgs::default()
                    },
                )
                .expect_err("a non-object override is refused");
            assert!(
                err.to_string().starts_with("scan: invalid_profile:"),
                "{bad}: {err}"
            );
            assert!(err.to_string().contains("overrides"), "{bad}: {err}");
        }

        let unchanged = profiles
            .resolve(
                &cfg,
                StartArgs {
                    target: Some("http://127.0.0.1:8080".to_string()),
                    overrides: Some(serde_json::Value::Null),
                    ..StartArgs::default()
                },
            )
            .expect("a null override is no override");
        assert_eq!(unchanged.name, "standard");
    }

    /// `target` alone needs the configured default profile to exist; an
    /// operator who misspelt `scanner.default_profile` sees `not_found`
    /// naming it, not a scan of some other profile.
    #[test]
    fn target_with_an_unknown_default_profile_is_not_found() {
        let cfg = ScannerConfig {
            default_profile: "nope".to_string(),
            ..ScannerConfig::default()
        };
        let err = Profiles::new(&cfg)
            .resolve(
                &cfg,
                StartArgs {
                    target: Some("http://127.0.0.1:8080".to_string()),
                    ..StartArgs::default()
                },
            )
            .expect_err("an unknown default profile is refused");
        assert_eq!(err.to_string(), "scan: not_found: profile `nope`");

        // And a `profile_name` that no layer holds is the same refusal.
        let err = Profiles::new(&cfg)
            .resolve(
                &cfg,
                StartArgs {
                    profile_name: Some("missing".to_string()),
                    ..StartArgs::default()
                },
            )
            .expect_err("an unknown profile name is refused");
        assert_eq!(err.to_string(), "scan: not_found: profile `missing`");
    }
}
