//! Did-you-mean for unknown commands and flags (spec D15, AC-W2-3; plan C37).
//!
//! Two rules, so a near-miss yields one name rather than every name that is
//! equally wrong:
//!
//! 1. **Prefix wins.** When the non-empty input is a prefix of one or more
//!    candidates, those are the suggestions (`sc` → `scan, scope, script`).
//! 2. **Else the closest tier only.** Candidates within [`MAX_DISTANCE`] are
//!    kept only at the minimum distance found (`scpe` → `scope` alone, since
//!    `scan` is two edits away).
//!
//! Either way the result holds distinct names, sorted by name, at most
//! [`MAX_SUGGESTIONS`] of them. The edit distance is our own (AC-W2-10: no
//! new crate).

/// The largest edit distance at which a candidate is still a suggestion.
pub const MAX_DISTANCE: usize = 2;

/// The most suggestions one `did you mean:` line carries.
pub const MAX_SUGGESTIONS: usize = 3;

/// Optimal-string-alignment Damerau–Levenshtein distance over `char`s: an
/// insertion, a deletion, a substitution or an adjacent transposition each
/// cost one. Case-sensitive.
pub fn distance(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let (m, n) = (a.len(), b.len());
    // `d[i][j]` is the distance between `a[..i]` and `b[..j]`; column 0 and
    // row 0 are pure deletions and pure insertions.
    let mut d: Vec<Vec<usize>> = (0..=m)
        .map(|i| {
            let mut row = vec![0; n + 1];
            row[0] = i;
            row
        })
        .collect();
    d[0] = (0..=n).collect();
    for i in 1..=m {
        for j in 1..=n {
            let cost = usize::from(a[i - 1] != b[j - 1]);
            let mut best = (d[i - 1][j] + 1)
                .min(d[i][j - 1] + 1)
                .min(d[i - 1][j - 1] + cost);
            if i > 1 && j > 1 && a[i - 1] == b[j - 2] && a[i - 2] == b[j - 1] {
                best = best.min(d[i - 2][j - 2] + 1);
            }
            d[i][j] = best;
        }
    }
    d[m][n]
}

/// The candidates worth offering for `input`, by the two rules in the module
/// doc: distinct, sorted by name, at most [`MAX_SUGGESTIONS`].
pub fn suggest<'a>(input: &str, candidates: impl IntoIterator<Item = &'a str>) -> Vec<&'a str> {
    let candidates: Vec<&'a str> = candidates.into_iter().collect();

    // Rule 1: prefix wins.
    let mut found: Vec<&'a str> = if input.is_empty() {
        Vec::new()
    } else {
        candidates
            .iter()
            .copied()
            .filter(|candidate| candidate.starts_with(input))
            .collect()
    };

    // Rule 2: else the closest tier only.
    if found.is_empty() {
        let scored: Vec<(usize, &'a str)> = candidates
            .iter()
            .map(|&candidate| (distance(input, candidate), candidate))
            .filter(|&(edits, _)| edits <= MAX_DISTANCE)
            .collect();
        if let Some(closest) = scored.iter().map(|&(edits, _)| edits).min() {
            found = scored
                .into_iter()
                .filter(|&(edits, _)| edits == closest)
                .map(|(_, candidate)| candidate)
                .collect();
        }
    }

    found.sort_unstable();
    found.dedup();
    found.truncate(MAX_SUGGESTIONS);
    found
}

/// The `did you mean: a, b` line, or `None` when there is nothing to offer.
pub fn did_you_mean(suggestions: &[&str]) -> Option<String> {
    if suggestions.is_empty() {
        return None;
    }
    Some(format!("did you mean: {}", suggestions.join(", ")))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The 19 group names of the registry with the bundled catalogue on.
    const GROUPS: [&str; 19] = [
        "agent", "browser", "ca", "capture", "check", "config", "findings", "flow", "l4", "map",
        "poc", "proxy", "request", "scan", "scope", "script", "session", "tls", "ws",
    ];

    #[test]
    fn distance_counts_edits_and_one_transposition() {
        assert_eq!(distance("scpe", "scope"), 1);
        assert_eq!(distance("scoep", "scope"), 1);
        assert_eq!(distance("flwo", "flow"), 1);
        assert_eq!(distance("abc", "abc"), 0);
        assert_eq!(distance("", "abc"), 3);
        assert_eq!(distance("kitten", "sitting"), 3);
        assert_eq!(distance("ca", "ab"), 2);
    }

    #[test]
    fn suggest_returns_close_names_sorted_and_capped() {
        assert_eq!(suggest("scpe", GROUPS), vec!["scope"]);
        // Rule 1: a prefix of three groups lists all three, sorted.
        assert_eq!(suggest("sc", GROUPS), vec!["scan", "scope", "script"]);
        // Rule 2: `scan` is at distance 2, `scope` at 1; only the closest tier.
        assert_ne!(suggest("scpe", GROUPS), vec!["scope", "scan"]);
        assert_eq!(suggest("flwo", GROUPS), vec!["flow"]);
        assert!(suggest("zzzzzz", GROUPS).is_empty());
        assert_eq!(
            suggest("a", ["ab", "ac", "ad", "ae"]),
            vec!["ab", "ac", "ad"]
        );
        assert_eq!(suggest("tabel", ["list", "get", "table"]), vec!["table"]);
        assert_eq!(suggest("ab", ["abc", "abc"]), vec!["abc"]);
    }

    #[test]
    fn did_you_mean_joins_with_commas() {
        assert_eq!(
            did_you_mean(&["scope", "script"]),
            Some("did you mean: scope, script".into())
        );
        assert_eq!(did_you_mean(&[]), None);
    }

    // ---- tester, wave-2 pass 1 (AC-W2-3/10; plan C37) ----

    /// Verbs with underscores and three-segment (dotted) verb names go
    /// through the same two rules: a dash for an underscore or a dropped one
    /// is one edit, so the right verb is the only suggestion; a prefix of a
    /// dotted name lists every verb under it, sorted. Edits are counted over
    /// chars, the match is case-sensitive, and the cap applies after sorting.
    #[test]
    fn suggest_over_underscored_and_three_segment_verbs() {
        let browser = [
            "navigate",
            "click",
            "type",
            "eval",
            "get_dom",
            "screenshot",
            "confine",
        ];
        assert_eq!(suggest("getdom", browser), vec!["get_dom"]);
        assert_eq!(suggest("get-dom", browser), vec!["get_dom"]);
        assert_eq!(suggest("get_", browser), vec!["get_dom"]);
        let l4 = ["recon", "tcp_probe", "udp_probe", "interfaces"];
        // `udp_probe` is two edits away; only the closest tier is offered.
        assert_eq!(suggest("tcp-probe", l4), vec!["tcp_probe"]);
        assert_eq!(suggest("probe", l4), Vec::<&str>::new());
        let tls = ["passthrough.add", "passthrough.list", "passthrough.remove"];
        assert_eq!(
            suggest("passthrough", tls),
            vec!["passthrough.add", "passthrough.list", "passthrough.remove"]
        );
        assert_eq!(suggest("passthrough.ad", tls), vec!["passthrough.add"]);
        assert_eq!(suggest("passthrough.lst", tls), vec!["passthrough.list"]);
        assert_eq!(distance("scöpe", "scope"), 1);
        assert_eq!(suggest("Scope", GROUPS), vec!["scope"]);
        assert_eq!(distance("ab", "ba"), 1);
        assert_eq!(distance("abcd", "badc"), 2);
        assert_eq!(distance("", ""), 0);
        // An empty input is a prefix of nothing (rule 1 is skipped) and two
        // edits from every two-letter name (rule 2).
        assert_eq!(suggest("", GROUPS), vec!["ca", "l4", "ws"]);
        assert_eq!(MAX_DISTANCE, 2);
        assert_eq!(MAX_SUGGESTIONS, 3);
        // Four groups start with `s`; the first three by name survive the cap.
        assert_eq!(suggest("s", GROUPS), vec!["scan", "scope", "script"]);
        assert_eq!(suggest("x", Vec::<&str>::new()), Vec::<&str>::new());
        // Exactly three edits is one too many (`pe` → `scope`: two insertions
        // and a substitution), so nothing is offered.
        assert_eq!(distance("pe", "scope"), 3);
        assert_eq!(suggest("pe", ["scope", "flow"]), Vec::<&str>::new());
    }
}
