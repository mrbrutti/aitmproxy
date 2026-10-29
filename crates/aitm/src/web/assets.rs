//! The embedded web UI: the asset table `build.rs` generates from
//! `apps/web/dist`, and the routing over it (SPA fallback, cache policy, the
//! "not built" page when `dist/` was absent at compile time).

/// `(path relative to dist, bytes, content type)` — see `build.rs`.
pub type AssetTable = &'static [(&'static str, &'static [u8], &'static str)];

include!(concat!(env!("OUT_DIR"), "/web_assets.rs"));

/// Vite's hashed bundles live here; their names change when their bytes do.
const HASHED_PREFIX: &str = "assets/";

/// Shown at `/` when the binary was built without `apps/web/dist`.
pub const NOT_BUILT_HTML: &str = "<!doctype html><meta charset=\"utf-8\"><title>aitmproxy</title>\
<style>body{font:15px/1.5 system-ui,sans-serif;max-width:40em;margin:4em auto;padding:0 1em}\
code{background:#eee;padding:0 .3em}</style>\
<h1>aitmproxy web UI is not built</h1>\
<p>Run <code>npm ci &amp;&amp; npm run build</code> in <code>apps/web</code>, then rebuild \
<code>aitm</code>.</p>";

/// One servable file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Asset {
    pub body: &'static [u8],
    pub content_type: &'static str,
    pub cache_control: &'static str,
}

/// What a request path maps to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Resolved {
    /// 200 with the file.
    Asset(Asset),
    /// 200 with [`NOT_BUILT_HTML`]: an app route, but there is no `index.html`.
    NotBuilt,
    /// 404.
    NotFound,
}

/// Resolve a request path (no query string) against the embedded table.
pub fn resolve(path: &str) -> Resolved {
    resolve_in(ASSETS, path)
}

/// [`resolve`] over an explicit table (unit-testable without a `dist/`).
///
/// `/` and any path whose last segment has no extension are app routes: they
/// serve `index.html` (`Cache-Control: no-store`, so a rebuilt UI is picked up
/// immediately). Hashed `assets/*` are immutable for a year; anything else is
/// revalidated. Nothing is read from disk at runtime.
pub fn resolve_in(table: AssetTable, path: &str) -> Resolved {
    let rel = path.trim_start_matches('/');
    if !rel.is_empty() {
        if let Some(asset) = find(table, rel) {
            return Resolved::Asset(asset);
        }
    }
    if !is_app_route(rel) {
        return Resolved::NotFound;
    }
    match find(table, "index.html") {
        Some(index) => Resolved::Asset(index),
        None => Resolved::NotBuilt,
    }
}

/// Exact lookup of one file (no fallback).
pub fn lookup(path: &str) -> Option<(&'static [u8], &'static str)> {
    find(ASSETS, path.trim_start_matches('/')).map(|a| (a.body, a.content_type))
}

fn find(table: AssetTable, rel: &str) -> Option<Asset> {
    table
        .iter()
        .find(|(name, _, _)| *name == rel)
        .map(|(name, body, content_type)| Asset {
            body,
            content_type,
            cache_control: cache_control_for(name),
        })
}

fn cache_control_for(name: &str) -> &'static str {
    if name == "index.html" {
        "no-store"
    } else if name.starts_with(HASHED_PREFIX) {
        "public, max-age=31536000, immutable"
    } else {
        "no-cache"
    }
}

/// `/`, `/flows`, `/flows/abc` are app routes; `/favicon.ico` is a file.
fn is_app_route(rel: &str) -> bool {
    let last = rel.rsplit('/').next().unwrap_or_default();
    !last.contains('.')
}

#[cfg(test)]
mod tests {
    use super::*;

    static TABLE: AssetTable = &[
        ("index.html", b"<html>", "text/html; charset=utf-8"),
        (
            "assets/index-abc123.js",
            b"js",
            "text/javascript; charset=utf-8",
        ),
        ("favicon.svg", b"<svg/>", "image/svg+xml"),
    ];

    static EMPTY: AssetTable = &[];

    fn asset(r: Resolved) -> Asset {
        match r {
            Resolved::Asset(a) => a,
            other => panic!("expected an asset, got {other:?}"),
        }
    }

    #[test]
    fn root_serves_index_with_no_store() {
        let a = asset(resolve_in(TABLE, "/"));
        assert_eq!(a.body, b"<html>");
        assert_eq!(a.content_type, "text/html; charset=utf-8");
        assert_eq!(a.cache_control, "no-store");
    }

    #[test]
    fn app_routes_fall_back_to_index() {
        assert_eq!(resolve_in(TABLE, "/flows"), resolve_in(TABLE, "/"));
        assert_eq!(resolve_in(TABLE, "/flows/42/edit"), resolve_in(TABLE, "/"));
        assert_eq!(resolve_in(TABLE, "/index.html"), resolve_in(TABLE, "/"));
    }

    #[test]
    fn hashed_assets_are_immutable() {
        let a = asset(resolve_in(TABLE, "/assets/index-abc123.js"));
        assert_eq!(a.body, b"js");
        assert_eq!(a.cache_control, "public, max-age=31536000, immutable");
    }

    #[test]
    fn other_files_revalidate() {
        let a = asset(resolve_in(TABLE, "/favicon.svg"));
        assert_eq!(a.content_type, "image/svg+xml");
        assert_eq!(a.cache_control, "no-cache");
    }

    #[test]
    fn missing_files_are_not_found_not_index() {
        assert_eq!(resolve_in(TABLE, "/assets/nope.js"), Resolved::NotFound);
        assert_eq!(resolve_in(TABLE, "/robots.txt"), Resolved::NotFound);
        assert_eq!(resolve_in(TABLE, "/a.b/c.d"), Resolved::NotFound);
    }

    #[test]
    fn without_index_app_routes_are_not_built_and_files_are_404() {
        assert_eq!(resolve_in(EMPTY, "/"), Resolved::NotBuilt);
        assert_eq!(resolve_in(EMPTY, "/flows"), Resolved::NotBuilt);
        assert_eq!(resolve_in(EMPTY, "/assets/x.js"), Resolved::NotFound);
    }

    #[test]
    fn embedded_table_has_unique_relative_paths() {
        let mut names: Vec<&str> = ASSETS.iter().map(|(n, _, _)| *n).collect();
        let before = names.len();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), before);
        assert!(names
            .iter()
            .all(|n| !n.starts_with('/') && !n.contains("..")));
    }
}
