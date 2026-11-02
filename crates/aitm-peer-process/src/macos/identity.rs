//! The macOS identity step (spec D5, steps 2-3): an executable path becomes the
//! `CFBundleIdentifier` of its innermost `.app` / `.xpc` / `.appex` bundle, else
//! the executable's basename. The path itself is never stored or logged.
//!
//! No `unsafe` here: the `core-foundation` crate owns the CF object lifetimes.

use core_foundation::bundle::CFBundle;
use core_foundation::string::CFString;
use core_foundation::url::CFURL;

use crate::macos::bundle_path::innermost_bundle;

/// The `CFBundleIdentifier` of the bundle directory at `bundle_path`
/// (`CFURL::from_path(p, true)` → `CFBundle::new` → `info_dictionary()`).
/// `None` when the directory is not a readable bundle, has no identifier, or the
/// identifier is not a string.
pub(crate) fn bundle_identifier(bundle_path: &str) -> Option<String> {
    let url = CFURL::from_path(bundle_path, true)?;
    let bundle = CFBundle::new(url)?;
    let info = bundle.info_dictionary();
    let key = CFString::from_static_string("CFBundleIdentifier");
    let value = info.find(key)?;
    let id = value.downcast::<CFString>()?.to_string();
    (!id.is_empty()).then_some(id)
}

/// D5 steps 2-3: the innermost bundle's identifier when `path` lies inside a
/// bundle whose `Info.plist` names one, else the final path component. `None`
/// only when `path` has no final component (empty, or ends in `/`).
pub(crate) fn identity_for_path(path: &str) -> Option<String> {
    innermost_bundle(path)
        .and_then(bundle_identifier)
        .or_else(|| basename(path))
}

fn basename(path: &str) -> Option<String> {
    let base = path.rsplit('/').next()?;
    (!base.is_empty()).then(|| base.to_string())
}

#[cfg(test)]
mod tests {
    use super::{bundle_identifier, identity_for_path};

    /// D5 steps 2-3 against real system bundles and a bare executable.
    #[test]
    fn identity_for_path_fixtures() {
        assert_eq!(identity_for_path("/usr/bin/curl"), Some("curl".to_string()));
        assert_eq!(
            identity_for_path("/System/Library/Frameworks/WebKit.framework/Versions/A/XPCServices/com.apple.WebKit.Networking.xpc/Contents/MacOS/com.apple.WebKit.Networking"),
            Some("com.apple.WebKit.Networking".to_string())
        );
        assert_eq!(
            identity_for_path("/System/Applications/Calculator.app/Contents/MacOS/Calculator"),
            Some("com.apple.calculator".to_string())
        );
        // The bundle read fails (no such directory) → basename.
        assert_eq!(
            identity_for_path("/nonexistent/Foo.app/Contents/MacOS/Foo"),
            Some("Foo".to_string())
        );
    }

    #[test]
    fn bundle_identifier_reads_a_system_bundle_and_fails_closed() {
        assert_eq!(
            bundle_identifier("/System/Applications/Calculator.app"),
            Some("com.apple.calculator".to_string())
        );
        assert_eq!(bundle_identifier("/nonexistent/Foo.app"), None);
        // A directory that exists but is not a bundle has no identifier.
        assert_eq!(bundle_identifier("/usr/bin"), None);
    }

    #[test]
    fn unusable_paths_have_no_identity() {
        assert_eq!(identity_for_path(""), None);
        assert_eq!(identity_for_path("/usr/bin/"), None);
    }
}
