//! Path templates, filename heuristics and value traits.
//!
//! Two jobs, both pure string work (spec D8.1, D2):
//!
//! - [`path_template`] folds a concrete request path into the site-map template
//!   the operator sees, so `/account/42` and `/account/43` are one node
//!   `/account/{id}` instead of one node per customer.
//! - [`traits_for`] labels a value with the [`PointTrait`]s a scheduler uses to
//!   skip checks that cannot apply (`open-redirect` wants `url`,
//!   `path-traversal` wants `filename`; spec D4 scheduling).
//!
//! Every rule here is a shape heuristic on a short string. None of it decodes,
//! fetches or trusts the value, and none of it ever logs one: a trait is a
//! label, never evidence.

use aitm_scan_model::PointTrait;

/// Longest run of digits still read as an identifier by [`is_id_like`].
///
/// Twenty digits is `u64::MAX`'s width; past that a numeric string is data, not
/// a key, and labelling it `id` would only schedule access-control checks on
/// noise.
const MAX_ID_DIGITS: usize = 20;

/// Hex length of a Mongo-style object id (12 bytes).
const OID_HEX_LEN: usize = 24;

/// Longest extension [`looks_like_filename`] accepts after the final dot.
const MAX_EXTENSION_LEN: usize = 8;

/// Shortest value [`traits_for`] will call base64.
///
/// Short groups of four base64-legal characters are overwhelmingly ordinary
/// words and ids, so the trait would cost more in wasted probes than it buys.
const MIN_BASE64_LEN: usize = 16;

/// The site-map template for `path`: ids folded, query dropped.
///
/// Per segment, in order: all ASCII digits becomes `{id}`, a `8-4-4-4-12` hex
/// UUID (any case) becomes `{uuid}`, exactly 24 hex characters becomes `{oid}`,
/// anything else is kept verbatim. An empty path is `/`; a trailing slash is
/// kept, because `/a/` and `/a` are different routes to many servers.
pub(crate) fn path_template(path: &str) -> String {
    let path = match path.find('?') {
        Some(cut) => &path[..cut],
        None => path,
    };
    if path.is_empty() {
        return "/".to_string();
    }
    let mut out = String::with_capacity(path.len());
    for (index, segment) in path.split('/').enumerate() {
        if index > 0 {
            out.push('/');
        }
        out.push_str(template_segment(segment));
    }
    out
}

/// The template for one path segment, or the segment itself.
fn template_segment(segment: &str) -> &str {
    placeholder_for(segment).unwrap_or(segment)
}

/// The template placeholder [`path_template`] renders `segment` as, or `None`
/// when it is kept verbatim: `{id}` for all digits, `{uuid}` for a UUID, `{oid}`
/// for a 24-hex object id (S-M2, so a point naming an id-like segment shows the
/// placeholder instead of the token).
pub(crate) fn placeholder_for(segment: &str) -> Option<&'static str> {
    if is_all_digits(segment) {
        Some("{id}")
    } else if is_uuid(segment) {
        Some("{uuid}")
    } else if is_oid(segment) {
        Some("{oid}")
    } else {
        None
    }
}

/// Whether a path segment is an opaque token whose example must be withheld: a
/// UUID, or a run of 16 or more hex characters (a 24-hex object id, a 64-hex
/// reset token, a session handle). A plain numeric id is not opaque — its
/// example is safe to show (S-M2).
pub(crate) fn is_opaque_token(segment: &str) -> bool {
    is_uuid(segment) || (segment.len() >= 16 && is_hex(segment))
}

/// Whether `segment` reads as a file name rather than a route component.
///
/// True when it is not a bare number, carries a dot that is neither the first
/// nor the last character, and the text after the final dot is 1 to
/// [`MAX_EXTENSION_LEN`] ASCII alphanumerics. So `summary.pdf` and `v1.2` are
/// file names; `reports`, `7`, `.htaccess` and `a.` are not.
pub(crate) fn looks_like_filename(segment: &str) -> bool {
    if is_all_digits(segment) {
        return false;
    }
    let Some(dot) = segment.rfind('.') else {
        return false;
    };
    if dot == 0 || dot + 1 >= segment.len() {
        return false;
    }
    let extension = &segment[dot + 1..];
    extension.len() <= MAX_EXTENSION_LEN && extension.chars().all(|c| c.is_ascii_alphanumeric())
}

/// Whether `value` has the shape of an identifier: digits, a UUID, or an oid.
pub(crate) fn is_id_like(value: &str) -> bool {
    (is_all_digits(value) && value.len() <= MAX_ID_DIGITS) || is_uuid(value) || is_oid(value)
}

/// The traits carried by `value`, in [`PointTrait`]'s declaration order.
///
/// The order is the enum's (`Url, Filename, Number, Email, Base64, Json, Id`)
/// so two points with the same traits always compare and serialise equal.
/// Traits are not exclusive: `42` is both a number and an id. `Session` is
/// never returned here — it depends on the point's name and kind, which only
/// `points.rs` knows.
pub(crate) fn traits_for(value: &str) -> Vec<PointTrait> {
    let mut traits = Vec::new();
    let clean = !value.chars().any(char::is_whitespace);
    let email = clean && is_email(value);

    if clean && is_url(value) {
        traits.push(PointTrait::Url);
    }
    // An email address ends in a dot plus two to four letters, so the file-name
    // shape matches it as well; the more specific label wins (plan task 8 pins
    // `traits_for("a@b.co") == [Email]`).
    if clean && !email && looks_like_filename(last_path_segment(value)) {
        traits.push(PointTrait::Filename);
    }
    if is_number(value) {
        traits.push(PointTrait::Number);
    }
    if email {
        traits.push(PointTrait::Email);
    }
    if is_base64(value) {
        traits.push(PointTrait::Base64);
    }
    if is_json(value) {
        traits.push(PointTrait::Json);
    }
    if is_id_like(value) {
        traits.push(PointTrait::Id);
    }
    traits
}

/// Whether `value` is a non-empty run of ASCII digits.
fn is_all_digits(value: &str) -> bool {
    !value.is_empty() && value.bytes().all(|b| b.is_ascii_digit())
}

/// Whether `value` is `8-4-4-4-12` hex characters, upper or lower case.
fn is_uuid(value: &str) -> bool {
    let mut groups = value.split('-');
    let widths = [8_usize, 4, 4, 4, 12];
    for width in widths {
        match groups.next() {
            Some(group) if group.len() == width && is_hex(group) => {}
            _ => return false,
        }
    }
    groups.next().is_none()
}

/// Whether `value` is exactly 24 hex characters (a Mongo-style object id).
fn is_oid(value: &str) -> bool {
    value.len() == OID_HEX_LEN && is_hex(value)
}

/// Whether every byte of `value` is a hex digit.
fn is_hex(value: &str) -> bool {
    value.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Whether `value` points somewhere: absolute, protocol-relative, or site-root.
///
/// `/` alone is excluded: every path starts with it, so it carries no signal.
fn is_url(value: &str) -> bool {
    value.starts_with("http://")
        || value.starts_with("https://")
        || value.starts_with("//")
        || (value.starts_with('/') && value.len() > 1)
}

/// Whether `value` parses as a whole number or a finite decimal.
///
/// `inf` and `NaN` parse as `f64` but are not numbers any server echoes, so
/// they are rejected.
fn is_number(value: &str) -> bool {
    value.parse::<i64>().is_ok() || value.parse::<f64>().is_ok_and(f64::is_finite)
}

/// Whether `value` has the shape `local@domain.tld`.
///
/// Exactly one `@`, with a dot somewhere after it. Caller checks whitespace.
fn is_email(value: &str) -> bool {
    let mut parts = value.split('@');
    let (Some(local), Some(domain), None) = (parts.next(), parts.next(), parts.next()) else {
        return false;
    };
    !local.is_empty() && domain.contains('.')
}

/// Whether `value` is a plausible base64 blob.
///
/// Length a multiple of four and at least [`MIN_BASE64_LEN`], the standard
/// alphabet only, `=` padding (at most two) only at the end, and not a bare
/// run of digits — a 16-digit account number is an id, not a blob.
fn is_base64(value: &str) -> bool {
    if value.len() < MIN_BASE64_LEN || !value.len().is_multiple_of(4) || is_all_digits(value) {
        return false;
    }
    let body = value.trim_end_matches('=');
    if value.len() - body.len() > 2 {
        return false;
    }
    !body.is_empty()
        && body
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/')
}

/// Whether `value` opens like JSON and parses as JSON.
///
/// The cheap first-character test keeps `serde_json` off every scalar value.
fn is_json(value: &str) -> bool {
    (value.starts_with('{') || value.starts_with('['))
        && serde_json::from_str::<serde_json::Value>(value).is_ok()
}

/// The text after the last `/`, or all of `value` when it has none.
fn last_path_segment(value: &str) -> &str {
    match value.rfind('/') {
        Some(slash) => &value[slash + 1..],
        None => value,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::{is_id_like, looks_like_filename, path_template, traits_for};
    use aitm_scan_model::PointTrait::{Base64, Email, Filename, Id, Json, Number, Url};

    #[test]
    fn path_template_pins() {
        assert_eq!(path_template("/account/42/notes"), "/account/{id}/notes");
        assert_eq!(
            path_template("/u/550e8400-e29b-41d4-a716-446655440000/"),
            "/u/{uuid}/"
        );
        assert_eq!(path_template("/o/507f1f77bcf86cd799439011"), "/o/{oid}");
        assert_eq!(
            path_template("/files/reports/summary.pdf?x=1"),
            "/files/reports/summary.pdf"
        );
        assert_eq!(path_template(""), "/");
        assert_eq!(path_template("/v1.2/x"), "/v1.2/x");
    }

    #[test]
    fn filename_pins() {
        assert!(looks_like_filename("summary.pdf"));
        assert!(!looks_like_filename("reports"));
        assert!(!looks_like_filename("7"));
        assert!(!looks_like_filename(".htaccess"));
        assert!(!looks_like_filename("a."));
        assert!(looks_like_filename("v1.2"));
    }

    #[test]
    fn is_id_like_pins() {
        assert!(is_id_like("42"));
        assert!(is_id_like("550e8400-e29b-41d4-a716-446655440000"));
        assert!(is_id_like("507f1f77bcf86cd799439011"));
        assert!(!is_id_like(""));
        assert!(!is_id_like("123456789012345678901"));
        assert!(!is_id_like("summary.pdf"));
    }

    #[test]
    fn traits_pins() {
        assert_eq!(traits_for("https://e.test/x"), vec![Url]);
        assert_eq!(traits_for("/cb"), vec![Url]);
        assert_eq!(traits_for("42"), vec![Number, Id]);
        assert_eq!(traits_for("a@b.co"), vec![Email]);
        assert_eq!(traits_for("{\"a\":1}"), vec![Json]);
        assert_eq!(traits_for("summary.pdf"), vec![Filename]);
        assert_eq!(traits_for("QUJDREVGR0hJSktMTU5PUA=="), vec![Base64]);
        assert_eq!(traits_for("550e8400-e29b-41d4-a716-446655440000"), vec![Id]);
        assert_eq!(traits_for("hello"), Vec::new());
    }
}
