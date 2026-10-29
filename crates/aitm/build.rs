//! Embeds the built web operator UI (`apps/web/dist`, a Vite build) into the
//! binary for `aitm web` (F15). Generates `$OUT_DIR/web_assets.rs` holding
//!
//! ```ignore
//! pub static ASSETS: &[(&str, &[u8], &str)] = &[
//!     ("index.html", include_bytes!("…/dist/index.html"), "text/html; charset=utf-8"),
//!     …
//! ];
//! ```
//!
//! `dist/` is git-ignored, so it is routinely absent: that yields an empty
//! table (the server then serves a "not built" page), never a build error.

use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};

fn main() {
    let manifest_dir = PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").expect("manifest dir"));
    let out_dir = PathBuf::from(std::env::var_os("OUT_DIR").expect("OUT_DIR"));
    let dist = manifest_dir
        .join("..")
        .join("..")
        .join("apps")
        .join("web")
        .join("dist");
    let dist = dist.canonicalize().unwrap_or(dist);

    // Re-run when the dist directory appears, disappears, or changes shape;
    // each embedded file is registered as it is collected.
    println!("cargo:rerun-if-changed={}", dist.display());

    let mut files = Vec::new();
    if dist.is_dir() {
        collect(&dist, &dist, &mut files);
    }
    files.sort();

    let mut out = String::from("pub static ASSETS: &[(&str, &[u8], &str)] = &[\n");
    for (rel, abs) in &files {
        println!("cargo:rerun-if-changed={}", abs.display());
        let abs_str = abs.to_str().expect("asset path is UTF-8");
        out.push_str(&format!(
            "    ({rel:?}, include_bytes!({abs_str:?}), {mime:?}),\n",
            mime = mime_for(rel)
        ));
    }
    out.push_str("];\n");

    let mut f = fs::File::create(out_dir.join("web_assets.rs")).expect("create web_assets.rs");
    f.write_all(out.as_bytes()).expect("write web_assets.rs");
}

/// Collect every regular file under `dir` as (`path relative to root`, absolute path).
fn collect(root: &Path, dir: &Path, files: &mut Vec<(String, PathBuf)>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            println!("cargo:rerun-if-changed={}", path.display());
            collect(root, &path, files);
        } else if path.is_file() {
            let rel = path
                .strip_prefix(root)
                .expect("under root")
                .components()
                .map(|c| c.as_os_str().to_string_lossy().into_owned())
                .collect::<Vec<_>>()
                .join("/");
            files.push((rel, path));
        }
    }
}

fn mime_for(path: &str) -> &'static str {
    let ext = path.rsplit('.').next().unwrap_or_default();
    match ext.to_ascii_lowercase().as_str() {
        "html" => "text/html; charset=utf-8",
        "js" | "mjs" => "text/javascript; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "webp" => "image/webp",
        "ico" => "image/x-icon",
        "json" | "map" => "application/json",
        "txt" => "text/plain; charset=utf-8",
        "woff" => "font/woff",
        "woff2" => "font/woff2",
        "webmanifest" => "application/manifest+json",
        "wasm" => "application/wasm",
        _ => "application/octet-stream",
    }
}
