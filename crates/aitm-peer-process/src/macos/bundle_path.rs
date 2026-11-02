//! Which bundle an executable path belongs to (spec D5 step 2): the **innermost**
//! `.app`, `.xpc` or `.appex` directory on the path, so `/usr/bin/python3`'s real
//! executable inside `Xcode.app/…/Python.app` names `com.apple.python3`, not Xcode.

// Consumed by the macOS identity step; the module is not cfg-gated (so the rule
// is tested on every host) but only macOS has a caller outside the tests.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
/// The prefix of `path` through its last non-final component ending in `.app`,
/// `.xpc` or `.appex`, or `None` when no such component exists. The final
/// component (the executable itself) never counts, so `/tmp/x.app` is `None`.
pub(crate) fn innermost_bundle(path: &str) -> Option<&str> {
    const SUFFIXES: [&str; 3] = [".app", ".xpc", ".appex"];
    // Byte offset just past the last `/`: every component at or after it is the
    // final (executable) component and never counts.
    let last_slash = path.rfind('/')?;
    let dirs = &path[..last_slash];
    let mut end = dirs.len();
    loop {
        let start = dirs[..end].rfind('/').map_or(0, |i| i + 1);
        let component = &dirs[start..end];
        if SUFFIXES
            .iter()
            .any(|s| component.len() > s.len() && component.ends_with(s))
        {
            return Some(&path[..end]);
        }
        if start == 0 {
            return None;
        }
        end = start - 1;
    }
}

#[cfg(test)]
mod tests {
    use super::innermost_bundle;

    #[test]
    fn python_inside_xcode_names_the_inner_python_app() {
        let path = "/Applications/Xcode.app/Contents/Developer/Library/Frameworks/Python3.framework/Versions/3.9/Resources/Python.app/Contents/MacOS/Python";
        assert_eq!(
            innermost_bundle(path),
            Some("/Applications/Xcode.app/Contents/Developer/Library/Frameworks/Python3.framework/Versions/3.9/Resources/Python.app")
        );
    }

    #[test]
    fn chrome_helper_names_the_inner_helper_app() {
        let path = "/Applications/Google Chrome.app/Contents/Frameworks/Google Chrome Framework.framework/Versions/1/Helpers/Google Chrome Helper (Renderer).app/Contents/MacOS/Google Chrome Helper (Renderer)";
        let got = innermost_bundle(path).expect("a bundle");
        assert!(
            got.ends_with("Google Chrome Helper (Renderer).app"),
            "{got}"
        );
        assert_eq!(
            got,
            "/Applications/Google Chrome.app/Contents/Frameworks/Google Chrome Framework.framework/Versions/1/Helpers/Google Chrome Helper (Renderer).app"
        );
    }

    #[test]
    fn webkit_networking_names_the_xpc_service() {
        let path = "/System/Library/Frameworks/WebKit.framework/Versions/A/XPCServices/com.apple.WebKit.Networking.xpc/Contents/MacOS/com.apple.WebKit.Networking";
        let got = innermost_bundle(path).expect("a bundle");
        assert!(got.ends_with("com.apple.WebKit.Networking.xpc"), "{got}");
        assert_eq!(
            got,
            "/System/Library/Frameworks/WebKit.framework/Versions/A/XPCServices/com.apple.WebKit.Networking.xpc"
        );
    }

    #[test]
    fn a_bare_executable_has_no_bundle() {
        assert_eq!(innermost_bundle("/usr/bin/curl"), None);
    }

    #[test]
    fn the_executable_itself_is_not_a_bundle() {
        assert_eq!(innermost_bundle("/tmp/x.app"), None);
    }

    #[test]
    fn an_appex_is_recognised_and_a_framework_is_not() {
        assert_eq!(
            innermost_bundle(
                "/Applications/Foo.app/Contents/PlugIns/Share.appex/Contents/MacOS/Share"
            ),
            Some("/Applications/Foo.app/Contents/PlugIns/Share.appex")
        );
        assert_eq!(
            innermost_bundle("/System/Library/Frameworks/WebKit.framework/Versions/A/WebKit"),
            None
        );
    }

    #[test]
    fn a_suffix_must_be_the_whole_extension() {
        // "Fooapp" and ".application" are not bundles.
        assert_eq!(innermost_bundle("/x/Fooapp/bin/foo"), None);
        assert_eq!(innermost_bundle("/x/Foo.application/bin/foo"), None);
    }

    /// Nothing to split, or a hidden directory literally named `.app`: no bundle.
    #[test]
    fn degenerate_paths_have_no_bundle() {
        assert_eq!(innermost_bundle(""), None);
        assert_eq!(innermost_bundle("curl"), None);
        assert_eq!(innermost_bundle("/"), None);
        assert_eq!(innermost_bundle("/x/.app/bin/foo"), None);
    }

    /// `proc_pidpath` is absolute, but the rule does not depend on it.
    #[test]
    fn a_relative_path_works_from_its_first_component() {
        assert_eq!(
            innermost_bundle("Foo.app/Contents/MacOS/Foo"),
            Some("Foo.app")
        );
    }

    /// The suffix match is case-sensitive: `Foo.APP` is left to the basename
    /// fallback rather than guessed at (fail closed).
    #[test]
    fn the_suffix_match_is_case_sensitive() {
        assert_eq!(
            innermost_bundle("/Applications/Foo.APP/Contents/MacOS/Foo"),
            None
        );
    }
}
