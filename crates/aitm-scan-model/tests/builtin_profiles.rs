//! The built-in scan profiles and the profile tree's defaults (spec D2, D11).
//!
//! Profiles are operator-authored YAML, so these tests read and write them the way
//! an operator's file is read and written: block-style YAML, every default filled
//! in, a mistyped key rejected rather than silently ignored.

use aitm_scan_model::{
    builtin, builtin_profiles, is_builtin_name, Accuracy, CrawlStrategy, HttpVersionPolicy,
    IgnoreRule, InsertionKind, Intensity, LaneKind, OnLost, PointTrait, RecordProbes, ScanProfile,
    SessionMode, Speed, UseBrowser, BUILTIN_PROFILE_NAMES,
};

#[test]
fn every_builtin_round_trips_yaml_and_json() {
    let profiles = builtin_profiles();

    let names: Vec<&str> = profiles.iter().map(|p| p.name.as_str()).collect();
    assert_eq!(names, BUILTIN_PROFILE_NAMES.to_vec());
    assert_eq!(profiles.len(), 7);

    for profile in &profiles {
        let yaml = serde_yaml::to_string(profile).expect("profile serializes as YAML");
        let from_yaml: ScanProfile =
            serde_yaml::from_str(&yaml).expect("profile parses back from YAML");
        assert_eq!(&from_yaml, profile, "YAML round trip of {}", profile.name);

        let json = serde_json::to_string(profile).expect("profile serializes as JSON");
        let from_json: ScanProfile =
            serde_json::from_str(&json).expect("profile parses back from JSON");
        assert_eq!(&from_json, profile, "JSON round trip of {}", profile.name);

        assert_eq!(builtin(&profile.name).as_ref(), Some(profile));
        assert!(is_builtin_name(&profile.name));
    }

    assert!(builtin("nope").is_none());
    assert!(!is_builtin_name("nope"));
}

#[test]
fn builtin_shapes_match_the_spec() {
    let passive = builtin("passive-only").expect("passive-only is built in");
    assert_eq!(passive.lanes, vec![LaneKind::Http]);
    assert_eq!(passive.intensity, Intensity::Passive);
    assert_eq!(passive.crawl.max_pages, 0);
    assert_eq!(passive.crawl.use_browser, UseBrowser::Never);

    let map_only = builtin("map-only").expect("map-only is built in");
    assert_eq!(map_only.intensity, Intensity::Passive);
    assert_eq!(map_only.crawl.max_pages, 200, "map-only crawls (call A5)");

    let light = builtin("light-http").expect("light-http is built in");
    assert_eq!(light.intensity, Intensity::Light);
    assert_eq!(light.speed, Speed::Fast);

    let standard = builtin("standard").expect("standard is built in");
    assert_eq!(standard.lanes, vec![LaneKind::Http, LaneKind::Ws]);
    assert_eq!(standard.intensity, Intensity::Medium);
    assert_eq!(standard.speed, Speed::Normal);
    assert_eq!(standard.accuracy, Accuracy::Normal);

    let thorough = builtin("thorough").expect("thorough is built in");
    assert_eq!(thorough.lanes, vec![LaneKind::Http, LaneKind::Ws]);
    assert_eq!(thorough.intensity, Intensity::Medium);
    assert_eq!(thorough.speed, Speed::Thorough);
    assert_eq!(thorough.accuracy, Accuracy::FewerFalseNegatives);
    assert_eq!(thorough.crawl.strategy, CrawlStrategy::Thorough);

    let stream_safe = builtin("l4-stream-safe").expect("l4-stream-safe is built in");
    assert_eq!(stream_safe.lanes, vec![LaneKind::L4Stream]);
    assert_eq!(stream_safe.intensity, Intensity::Medium);
    assert_eq!(stream_safe.l4.cases, 200);
    assert!(!stream_safe.l4.dry_run);

    let full = builtin("l4-full").expect("l4-full is built in");
    assert_eq!(full.lanes, vec![LaneKind::L4Packet, LaneKind::L4Stream]);
    assert_eq!(full.intensity, Intensity::Medium);
    assert_eq!(full.l4.cases, 500);

    for profile in builtin_profiles() {
        assert!(
            profile.target.origins.is_empty() && profile.target.l4.is_empty(),
            "{}: target is filled in by scan.start",
            profile.name
        );
    }
}

#[test]
fn standard_yaml_reads_as_prose() {
    let standard = builtin("standard").expect("standard is built in");
    let yaml = serde_yaml::to_string(&standard).expect("serializes as YAML");

    for expected in ["name: standard", "intensity: medium", "- ws"] {
        assert!(
            yaml.lines().any(|line| line.trim() == expected),
            "expected a line `{expected}` in:\n{yaml}"
        );
    }

    assert!(!yaml.contains("{\""), "flow-style map in:\n{yaml}");
    assert!(!yaml.contains("{ "), "flow-style map in:\n{yaml}");
}

#[test]
fn minimal_yaml_fills_every_default() {
    let yaml = "name: mini\ntarget:\n  origins: [\"http://127.0.0.1:8080\"]\n";
    let profile: ScanProfile = serde_yaml::from_str(yaml).expect("minimal profile parses");

    assert_eq!(profile.name, "mini");
    assert_eq!(
        profile.target.origins,
        vec!["http://127.0.0.1:8080".to_string()]
    );
    assert!(profile.target.l4.is_empty());
    assert_eq!(profile.lanes, vec![LaneKind::Http]);
    assert_eq!(profile.intensity, Intensity::Medium);
    assert_eq!(profile.speed, Speed::Normal);
    assert_eq!(profile.accuracy, Accuracy::Normal);

    assert_eq!(profile.crawl.strategy, CrawlStrategy::Normal);
    assert_eq!(profile.crawl.max_depth, 3);
    assert_eq!(profile.crawl.max_pages, 200);
    assert!(profile.crawl.submit_forms);
    assert!(profile.crawl.click_handlers);
    assert!(profile.crawl.robots);
    assert!(profile.crawl.sitemap);
    assert_eq!(profile.crawl.use_browser, UseBrowser::Auto);

    assert_eq!(profile.budget.probes, 2000);
    assert_eq!(profile.budget.time_s, 600);
    assert_eq!(profile.budget.max_issues, 1024);
    assert_eq!(profile.budget.check_timeout_s, 60);
    assert_eq!(profile.budget.per_host_errors.consecutive, 10);
    assert!((profile.budget.per_host_errors.ratio - 0.5).abs() < f32::EPSILON);

    assert_eq!(profile.audit.max_points_per_request, 64);
    assert_eq!(profile.audit.frequent_point_threshold, 8);
    assert_eq!(profile.audit.kinds, InsertionKind::ALL.to_vec());
    assert_eq!(
        profile.audit.ignore,
        vec![IgnoreRule {
            point_trait: Some(PointTrait::Session),
            ..Default::default()
        }]
    );

    assert_eq!(profile.session.mode, SessionMode::Observed);
    assert_eq!(profile.session.from_flow, None);
    assert_eq!(profile.session.on_lost, OnLost::Stop);

    assert_eq!(profile.ws.reply_window_ms, 1500);
    assert_eq!(profile.ws.max_frame_bytes, 1_048_576);

    assert_eq!(profile.l4.cases, 500);
    assert_eq!(profile.l4.reproduce_count, 3);
    assert_eq!(profile.l4.liveness_every, 25);
    assert_eq!(profile.l4.consecutive_timeouts, 20);
    assert_eq!(profile.l4.max_bytes_per_s, 65_536);
    assert!(profile.l4.seeds.is_empty());
    assert!(!profile.l4.dry_run);

    assert_eq!(profile.http.version, HttpVersionPolicy::Auto);
    assert_eq!(profile.http.record_probes, RecordProbes::IssuesOnly);

    assert!(profile.checks.include.is_empty());
    assert!(profile.checks.exclude.is_empty());
}

#[test]
fn unknown_key_is_rejected() {
    let err = serde_yaml::from_str::<ScanProfile>("name: typo\nbudgte:\n  probes: 5\n")
        .expect_err("a mistyped key is an error, not a silent default");
    assert!(
        err.to_string().contains("budgte"),
        "error should name the key: {err}"
    );
}
