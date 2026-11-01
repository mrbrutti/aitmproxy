//! The timing oracle behind every blind time-based technique.
//!
//! A time-based check never sleeps: it asks the target for a delay, reads the
//! `elapsed_ms` the lane measured, and hands the series to [`fit`] (spec D4,
//! "Timing without `sleep`"). [`fit`] is a plain least-squares regression of the
//! baseline-corrected response times against the delays that were asked for, and
//! [`correlated`] applies ZAP's published acceptance rule to the result
//! (`docs/research/17-burp-style-scanner-architecture.md` §3.6).
//!
//! Both are `pub` and free of any scanner state so that the Rhai host function
//! `probe.timing_fit` can reuse them verbatim: the native catalogue and the
//! scripted one must agree on what "correlated" means, or two checks for one
//! class would disagree about the same target.
//!
//! The regression runs in `f64` and is narrowed to the `f32` the model carries,
//! so a long series cannot lose precision to accumulation.

use aitm_scan_model::Timing;

/// How far [`Timing::r`] may fall short of a perfect `1.0` and still count as
/// correlated (ZAP's `CORRELATION_ERROR_RANGE`).
pub const CORRELATION_ERROR_RANGE: f32 = 0.15;

/// How far [`Timing::slope`] may stray from the ideal one second of delay per
/// second requested and still count as correlated (ZAP's `SLOPE_ERROR_RANGE`).
pub const SLOPE_ERROR_RANGE: f32 = 0.30;

/// The ideal slope of a perfectly obeyed delay: one second of extra response
/// time, in milliseconds, for every second requested.
const IDEAL_SLOPE_MS_PER_S: f32 = 1000.0;

/// The named handle for this module's algorithm (spec D4).
///
/// The oracle holds no state — the whole algorithm is [`fit`] plus
/// [`correlated`] — so this is a marker a catalogue entry can name when it
/// documents which oracle decided its verdict.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TimingOracle;

/// Least-squares fit of the observed delay against the delay that was requested.
///
/// `requested_s` is in seconds, `observed_ms` and `baseline_ms` in milliseconds.
/// Each observation is corrected by the median of `baseline_ms` — a median, not
/// a mean, so one slow unpayloaded request cannot move the correction — and the
/// fit runs on those corrected milliseconds against the requested seconds.
/// The resulting [`Timing::slope`] is therefore **milliseconds per second** —
/// near `1000.0` when the target obeyed the delay, which is exactly what
/// [`Timing::slope`]'s own documentation promises — and [`Timing::r`] is the
/// Pearson correlation coefficient of the same fit.
///
/// The correction subtracts the same constant from every observation, so it
/// moves only the intercept: neither `slope` nor `r` changes by one bit whether
/// the baseline is subtracted, mis-estimated or absent. It is applied anyway
/// because the corrected series is what the evidence means — "the payload added
/// this much time" — and because an intercept would become observable the moment
/// the model carried one. Do not read a timing verdict as depending on it.
///
/// The function is **total**: fewer than two points, mismatched series lengths,
/// no variance in either axis, or any non-finite intermediate all yield
/// `slope: 0.0, r: 0.0`, which [`correlated`] rejects. A check can therefore call
/// it on whatever it managed to collect without guarding first.
#[must_use]
pub fn fit(requested_s: &[f32], observed_ms: &[u32], baseline_ms: &[u32]) -> Timing {
    let timing = |slope: f32, r: f32| Timing {
        requested_s: requested_s.to_vec(),
        observed_ms: observed_ms.to_vec(),
        baseline_ms: baseline_ms.to_vec(),
        slope,
        r,
    };

    if requested_s.len() != observed_ms.len() || requested_s.len() < 2 {
        return timing(0.0, 0.0);
    }

    let base = median_ms(baseline_ms);
    let xs: Vec<f64> = requested_s.iter().map(|x| f64::from(*x)).collect();
    let ys: Vec<f64> = observed_ms.iter().map(|y| f64::from(*y) - base).collect();

    let n = xs.len() as f64;
    let mean_x = xs.iter().sum::<f64>() / n;
    let mean_y = ys.iter().sum::<f64>() / n;

    let mut cov = 0.0_f64;
    let mut var_x = 0.0_f64;
    let mut var_y = 0.0_f64;
    for (x, y) in xs.iter().zip(ys.iter()) {
        let dx = x - mean_x;
        let dy = y - mean_y;
        cov += dx * dy;
        var_x += dx * dx;
        var_y += dy * dy;
    }

    // No spread on either axis means there is nothing to correlate: every
    // payload asked for the same delay, or every response took the same time.
    if var_x <= 0.0 || var_y <= 0.0 {
        return timing(0.0, 0.0);
    }

    let slope = cov / var_x;
    let r = cov / (var_x * var_y).sqrt();
    if !slope.is_finite() || !r.is_finite() {
        return timing(0.0, 0.0);
    }

    timing(slope as f32, r as f32)
}

/// ZAP's acceptance rule: the fit is correlated when `r` is within
/// [`CORRELATION_ERROR_RANGE`] of `1.0` **and** the slope is within
/// [`SLOPE_ERROR_RANGE`] of one second of delay per second requested.
///
/// Both halves matter. A flat series can correlate well with the request pattern
/// while barely moving (slope rejects it), and a series that swings by the right
/// amount in the wrong direction has the right magnitude but a negative `r`
/// (correlation rejects it).
#[must_use]
pub fn correlated(t: &Timing) -> bool {
    (1.0 - t.r).abs() <= CORRELATION_ERROR_RANGE
        && (1.0 - t.slope / IDEAL_SLOPE_MS_PER_S).abs() <= SLOPE_ERROR_RANGE
}

/// The median of the unpayloaded response times, in milliseconds; `0.0` when no
/// baseline was collected (the observations then stand uncorrected).
fn median_ms(baseline_ms: &[u32]) -> f64 {
    if baseline_ms.is_empty() {
        return 0.0;
    }
    let mut sorted: Vec<u32> = baseline_ms.to_vec();
    sorted.sort_unstable();
    let mid = sorted.len() / 2;
    if sorted.len().is_multiple_of(2) {
        (f64::from(sorted[mid - 1]) + f64::from(sorted[mid])) / 2.0
    } else {
        f64::from(sorted[mid])
    }
}

#[cfg(test)]
mod tests {
    use super::{correlated, fit};

    #[test]
    fn fit_reports_a_correlated_alternating_delay() {
        let t = fit(
            &[1.0, 3.0, 1.0, 3.0],
            &[1040, 3060, 1030, 3090],
            &[38, 41, 39, 40],
        );
        assert!(t.r >= 0.99, "r was {}", t.r);
        assert!((950.0..=1050.0).contains(&t.slope), "slope was {}", t.slope);
        assert!(correlated(&t));
    }

    #[test]
    fn fit_rejects_a_flat_response_set() {
        let t = fit(
            &[1.0, 3.0, 1.0, 3.0],
            &[1040, 1050, 1030, 1060],
            &[38, 41, 39, 40],
        );
        assert!(!correlated(&t), "slope {} r {}", t.slope, t.r);
    }

    #[test]
    fn fit_rejects_an_anticorrelated_set() {
        let t = fit(
            &[1.0, 3.0, 1.0, 3.0],
            &[3000, 1000, 3000, 1000],
            &[38, 41, 39, 40],
        );
        assert!(t.r <= -0.9, "r was {}", t.r);
        assert!(!correlated(&t));
    }

    #[test]
    fn fit_is_total_on_degenerate_input() {
        for t in [fit(&[], &[], &[]), fit(&[1.0], &[1000], &[40])] {
            assert_eq!(t.slope, 0.0);
            assert_eq!(t.r, 0.0);
            assert!(t.r.is_finite());
            assert!(!correlated(&t));
        }
    }

    /// Mismatched series and a flat request axis are the two ways a caller can
    /// hand the oracle a set it cannot regress; neither may panic or divide by
    /// zero. The series it was given still comes back on the `Timing`, so the
    /// evidence shows what was collected even when the fit is refused.
    #[test]
    fn fit_refuses_mismatched_and_varianceless_series() {
        let mismatched = fit(&[1.0, 3.0, 1.0], &[1040, 3060], &[39]);
        assert_eq!((mismatched.slope, mismatched.r), (0.0, 0.0));
        assert_eq!(mismatched.requested_s, vec![1.0, 3.0, 1.0]);
        assert_eq!(mismatched.observed_ms, vec![1040, 3060]);

        let no_x_spread = fit(&[2.0, 2.0, 2.0, 2.0], &[1040, 3060, 1030, 3090], &[39]);
        assert_eq!((no_x_spread.slope, no_x_spread.r), (0.0, 0.0));
        assert!(!correlated(&no_x_spread));

        let no_y_spread = fit(&[1.0, 3.0, 1.0, 3.0], &[1000, 1000, 1000, 1000], &[39]);
        assert_eq!((no_y_spread.slope, no_y_spread.r), (0.0, 0.0));
        assert!(!correlated(&no_y_spread));
    }

    /// The baseline correction subtracts one constant from every observation,
    /// so it cannot move `slope` or `r` — not when it is a wild over-estimate,
    /// not when it is missing entirely. A later reader must not mistake it for
    /// something a verdict depends on, and the raw series the check collected
    /// must still reach the evidence unaltered.
    #[test]
    fn the_baseline_correction_moves_neither_slope_nor_r() {
        let requested = [1.0, 3.0, 1.0, 3.0];
        let observed = [1040, 3060, 1030, 3090];

        let normal = fit(&requested, &observed, &[38, 41, 39, 40]);
        let outlier = fit(&requested, &observed, &[38, 41, 39, 9000]);
        let absent = fit(&requested, &observed, &[]);

        assert_eq!((outlier.slope, outlier.r), (normal.slope, normal.r));
        assert_eq!((absent.slope, absent.r), (normal.slope, normal.r));
        assert!(correlated(&outlier), "slope {}", outlier.slope);

        // The evidence carries what was collected, not what was corrected.
        assert_eq!(outlier.baseline_ms, vec![38, 41, 39, 9000]);
        assert_eq!(outlier.observed_ms, vec![1040, 3060, 1030, 3090]);
        assert_eq!(outlier.requested_s, vec![1.0, 3.0, 1.0, 3.0]);
    }

    /// The correction itself: a median of the sorted baseline, robust to one
    /// slow unpayloaded request, and `0.0` when no baseline was collected.
    #[test]
    fn median_ms_is_the_middle_of_the_sorted_baseline() {
        assert_eq!(super::median_ms(&[]), 0.0);
        assert_eq!(super::median_ms(&[41]), 41.0);
        assert_eq!(super::median_ms(&[41, 38, 39]), 39.0);
        assert_eq!(super::median_ms(&[41, 38, 39, 40]), 39.5);
        // One 9-second outlier in four moves the median by one millisecond,
        // where a mean would have put the correction above 2200 ms.
        assert_eq!(super::median_ms(&[38, 39, 41, 9000]), 40.0);
    }

    /// The published constants are the contract `probe.timing_fit` reuses; a
    /// silent re-tune here would change every blind timing verdict in the
    /// catalogue, native and scripted alike.
    #[test]
    fn acceptance_constants_are_zaps_published_values() {
        assert_eq!(super::CORRELATION_ERROR_RANGE, 0.15);
        assert_eq!(super::SLOPE_ERROR_RANGE, 0.30);

        // The edges of the rule: r just inside and the slope just outside.
        let edge = |slope: f32, r: f32| aitm_scan_model::Timing {
            requested_s: Vec::new(),
            observed_ms: Vec::new(),
            baseline_ms: Vec::new(),
            slope,
            r,
        };
        assert!(correlated(&edge(1000.0, 0.86)));
        assert!(!correlated(&edge(1000.0, 0.84)));
        assert!(correlated(&edge(1290.0, 1.0)));
        assert!(!correlated(&edge(1310.0, 1.0)));
    }
}
