//! Argument parsing for `aitm-l4-helper` (spec §1 subcommands, §5.1 step 1).
//!
//! Parsed by hand over the arguments after `argv[0]`; no environment variable
//! is read here. Every message is wording the helper may print to a terminal:
//! it names this binary's own subcommands and never a shell command for the
//! operator to type (plan Rule 2).

use std::ffi::OsString;
use std::fmt;
use std::path::{Path, PathBuf};

/// The exact subcommand names, in the order the usage line lists them.
const SUBCOMMANDS: &str = "bpf-permissions, bpf-revert, serve, probe, version";

/// The `sockaddr_un.sun_path` limit: 108 bytes including the trailing NUL, so
/// a path of at most 107 bytes (spec §5.1 step 1).
const MAX_SOCKET_PATH_BYTES: usize = 107;

/// What the operator (or the core, or launchd) asked the helper to do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Mode {
    /// macOS: make `/dev/bpf*` `root:access_bpf 0660` (spec §3).
    BpfPermissions { dry_run: bool },
    /// macOS: undo `BpfPermissions`.
    BpfRevert { dry_run: bool },
    /// Linux: connect to the core's Unix socket and serve capture and inject
    /// behind the L4 guard (spec §5.1).
    Serve { connect: PathBuf },
    /// Report what this host would need, without changing anything.
    Probe,
    /// Print `aitm-l4-helper <version>`.
    Version,
}

/// A rejected command line. `Display` is the message printed to stderr; it
/// names this binary's own subcommands and never a shell command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UsageError {
    MissingSubcommand,
    UnknownSubcommand(String),
    /// `serve` was given anything other than exactly `--connect <path>`.
    ServeShape,
    ConnectPathNotAbsolute,
    ConnectPathTooLong,
    UnexpectedArgument(String),
}

impl fmt::Display for UsageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UsageError::MissingSubcommand => {
                write!(f, "missing subcommand (expected one of: {SUBCOMMANDS})")
            }
            UsageError::UnknownSubcommand(name) => {
                write!(
                    f,
                    "unknown subcommand: {name} (expected one of: {SUBCOMMANDS})"
                )
            }
            UsageError::ServeShape => write!(f, "serve takes exactly: serve --connect <path>"),
            UsageError::ConnectPathNotAbsolute => {
                write!(f, "serve --connect <path>: the path must be absolute")
            }
            UsageError::ConnectPathTooLong => write!(
                f,
                "serve --connect <path>: the path must be at most {MAX_SOCKET_PATH_BYTES} bytes"
            ),
            UsageError::UnexpectedArgument(arg) => write!(f, "unexpected argument: {arg}"),
        }
    }
}

impl std::error::Error for UsageError {}

/// Parse the arguments after `argv[0]`. Reads no environment variable.
pub fn parse(args: &[OsString]) -> Result<Mode, UsageError> {
    let (first, rest) = args.split_first().ok_or(UsageError::MissingSubcommand)?;
    match first.to_str() {
        Some("bpf-permissions") => {
            let dry_run = parse_dry_run(rest)?;
            Ok(Mode::BpfPermissions { dry_run })
        }
        Some("bpf-revert") => {
            let dry_run = parse_dry_run(rest)?;
            Ok(Mode::BpfRevert { dry_run })
        }
        Some("serve") => parse_serve(rest),
        Some("probe") => {
            no_more_arguments(rest)?;
            Ok(Mode::Probe)
        }
        Some("version") => {
            no_more_arguments(rest)?;
            Ok(Mode::Version)
        }
        _ => Err(UsageError::UnknownSubcommand(lossy(first))),
    }
}

/// `[]` or `["--dry-run"]`; anything else is an unexpected argument.
fn parse_dry_run(rest: &[OsString]) -> Result<bool, UsageError> {
    match rest.split_first() {
        None => Ok(false),
        Some((flag, tail)) if flag == "--dry-run" => {
            no_more_arguments(tail)?;
            Ok(true)
        }
        Some((other, _)) => Err(UsageError::UnexpectedArgument(lossy(other))),
    }
}

/// Exactly `--connect <path>`, the path absolute and at most 107 bytes.
fn parse_serve(rest: &[OsString]) -> Result<Mode, UsageError> {
    let (flag, tail) = rest.split_first().ok_or(UsageError::ServeShape)?;
    if flag != "--connect" {
        return Err(UsageError::ServeShape);
    }
    let (path, tail) = tail.split_first().ok_or(UsageError::ServeShape)?;
    no_more_arguments(tail)?;
    let path = Path::new(path);
    if !path.is_absolute() {
        return Err(UsageError::ConnectPathNotAbsolute);
    }
    if path.as_os_str().len() > MAX_SOCKET_PATH_BYTES {
        return Err(UsageError::ConnectPathTooLong);
    }
    Ok(Mode::Serve {
        connect: path.to_path_buf(),
    })
}

fn no_more_arguments(rest: &[OsString]) -> Result<(), UsageError> {
    match rest.first() {
        None => Ok(()),
        Some(extra) => Err(UsageError::UnexpectedArgument(lossy(extra))),
    }
}

fn lossy(arg: &OsString) -> String {
    arg.to_string_lossy().into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;
    use std::path::PathBuf;

    fn args(items: &[&str]) -> Vec<OsString> {
        items.iter().map(OsString::from).collect()
    }

    #[test]
    fn serve_with_absolute_connect_path_parses() {
        let mode = parse(&args(&[
            "serve",
            "--connect",
            "/run/user/1000/aitm/l4-helper-1.sock",
        ]))
        .expect("serve --connect <abs> parses");
        assert_eq!(
            mode,
            Mode::Serve {
                connect: PathBuf::from("/run/user/1000/aitm/l4-helper-1.sock"),
            }
        );
    }

    #[test]
    fn serve_with_relative_connect_path_is_an_error() {
        let err = parse(&args(&["serve", "--connect", "run/aitm/l4.sock"]))
            .expect_err("relative path refused");
        assert_eq!(
            err.to_string(),
            "serve --connect <path>: the path must be absolute"
        );
    }

    #[test]
    fn serve_connect_path_of_108_bytes_is_an_error_and_107_is_ok() {
        // "/" + 106 'a's = 107 bytes: the longest sockaddr_un path.
        let ok_path = format!("/{}", "a".repeat(106));
        assert_eq!(ok_path.len(), 107);
        let mode = parse(&args(&["serve", "--connect", &ok_path])).expect("107 bytes is ok");
        assert_eq!(
            mode,
            Mode::Serve {
                connect: PathBuf::from(&ok_path)
            }
        );

        let long_path = format!("/{}", "a".repeat(107));
        assert_eq!(long_path.len(), 108);
        let err = parse(&args(&["serve", "--connect", &long_path])).expect_err("108 bytes refused");
        assert_eq!(
            err.to_string(),
            "serve --connect <path>: the path must be at most 107 bytes"
        );
    }

    #[test]
    fn serve_with_an_extra_argument_is_an_error() {
        let err = parse(&args(&["serve", "--connect", "/a", "x"])).expect_err("extra arg refused");
        assert_eq!(err.to_string(), "unexpected argument: x");
    }

    #[test]
    fn bpf_permissions_dry_run_parses() {
        let mode = parse(&args(&["bpf-permissions", "--dry-run"])).expect("parses");
        assert_eq!(mode, Mode::BpfPermissions { dry_run: true });
        let mode = parse(&args(&["bpf-permissions"])).expect("parses");
        assert_eq!(mode, Mode::BpfPermissions { dry_run: false });
        let mode = parse(&args(&["bpf-revert", "--dry-run"])).expect("parses");
        assert_eq!(mode, Mode::BpfRevert { dry_run: true });
    }

    #[test]
    fn serve_does_not_accept_dry_run() {
        let err = parse(&args(&["serve", "--dry-run"])).expect_err("serve --dry-run refused");
        assert_eq!(
            err.to_string(),
            "serve takes exactly: serve --connect <path>"
        );
    }

    #[test]
    fn probe_and_version_parse_and_take_no_arguments() {
        assert_eq!(parse(&args(&["probe"])).expect("parses"), Mode::Probe);
        assert_eq!(parse(&args(&["version"])).expect("parses"), Mode::Version);
        let err = parse(&args(&["probe", "--dry-run"])).expect_err("probe takes no args");
        assert_eq!(err.to_string(), "unexpected argument: --dry-run");
        let err = parse(&args(&["version", "x"])).expect_err("version takes no args");
        assert_eq!(err.to_string(), "unexpected argument: x");
    }

    #[test]
    fn unknown_or_missing_subcommand_is_an_error() {
        let err = parse(&args(&["frobnicate"])).expect_err("unknown refused");
        assert_eq!(
            err.to_string(),
            "unknown subcommand: frobnicate (expected one of: bpf-permissions, bpf-revert, serve, probe, version)"
        );
        let err = parse(&args(&[])).expect_err("missing refused");
        assert_eq!(
            err.to_string(),
            "missing subcommand (expected one of: bpf-permissions, bpf-revert, serve, probe, version)"
        );
    }

    #[test]
    fn serve_connect_requires_a_value() {
        let err = parse(&args(&["serve", "--connect"])).expect_err("missing value refused");
        assert_eq!(
            err.to_string(),
            "serve takes exactly: serve --connect <path>"
        );
    }

    #[test]
    fn usage_messages_never_name_a_shell_command() {
        // Plan Rule 2: no message tells anyone to run a command. Collect every
        // error the parser can produce and check the forbidden words.
        let cases: &[&[&str]] = &[
            &[],
            &["frobnicate"],
            &["serve"],
            &["serve", "--connect"],
            &["serve", "--connect", "rel"],
            &["serve", "--connect", "/a", "x"],
            &["serve", "--dry-run"],
            &["bpf-permissions", "--other"],
            &["probe", "x"],
        ];
        for case in cases {
            let msg = parse(&args(case))
                .expect_err("each case is an error")
                .to_string();
            for word in [
                "sudo",
                "setcap",
                "chmod",
                "chgrp",
                "chown",
                "dseditgroup",
                "launchctl",
                "pkexec",
            ] {
                assert!(
                    !msg.contains(word),
                    "{case:?}: message {msg:?} names {word}"
                );
            }
        }
    }

    // ---- Tester edge cases (stage 5, unit p2) ------------------------------

    #[test]
    fn tester_connect_given_twice_is_an_unexpected_argument() {
        let err = parse(&args(&["serve", "--connect", "/a", "--connect", "/b"]))
            .expect_err("second --connect refused");
        assert_eq!(err, UsageError::UnexpectedArgument("--connect".to_string()));
        assert_eq!(err.to_string(), "unexpected argument: --connect");
        // Any flag after the path is refused the same way.
        let err = parse(&args(&["serve", "--connect", "/a", "--dry-run"]))
            .expect_err("flag after the path refused");
        assert_eq!(err.to_string(), "unexpected argument: --dry-run");
    }

    #[test]
    fn tester_connect_path_limit_counts_bytes_not_characters() {
        // "/" + 53 x "é" (2 bytes each) = 107 bytes but only 54 characters.
        let path = format!("/{}", "é".repeat(53));
        assert_eq!(path.len(), 107);
        assert_eq!(path.chars().count(), 54);
        assert_eq!(
            parse(&args(&["serve", "--connect", &path])),
            Ok(Mode::Serve {
                connect: PathBuf::from(&path)
            })
        );
        // One more ASCII byte: 108 bytes, refused.
        let long = format!("{path}a");
        assert_eq!(long.len(), 108);
        assert_eq!(
            parse(&args(&["serve", "--connect", &long])),
            Err(UsageError::ConnectPathTooLong)
        );
        // "/" + 26 x "😀" (4 bytes each) + "aa" = 107 bytes, 29 characters.
        let emoji = format!("/{}aa", "😀".repeat(26));
        assert_eq!(emoji.len(), 107);
        assert_eq!(emoji.chars().count(), 29);
        assert!(parse(&args(&["serve", "--connect", &emoji])).is_ok());
        let emoji_long = format!("/{}aaa", "😀".repeat(26));
        assert_eq!(emoji_long.len(), 108);
        assert_eq!(
            parse(&args(&["serve", "--connect", &emoji_long])),
            Err(UsageError::ConnectPathTooLong)
        );
    }

    #[test]
    fn tester_double_dash_is_never_special() {
        assert_eq!(
            parse(&args(&["--"])),
            Err(UsageError::UnknownSubcommand("--".to_string()))
        );
        assert_eq!(
            parse(&args(&["serve", "--", "--connect", "/a"])),
            Err(UsageError::ServeShape)
        );
        assert_eq!(
            parse(&args(&["probe", "--"])),
            Err(UsageError::UnexpectedArgument("--".to_string()))
        );
        assert_eq!(
            parse(&args(&["serve", "--connect", "/a", "--"])),
            Err(UsageError::UnexpectedArgument("--".to_string()))
        );
        // A path literally named "--" is a relative path.
        assert_eq!(
            parse(&args(&["serve", "--connect", "--"])),
            Err(UsageError::ConnectPathNotAbsolute)
        );
    }

    #[test]
    fn tester_subcommands_are_case_sensitive_and_help_flags_are_unknown() {
        for bad in [
            "Probe",
            "PROBE",
            "Version",
            "BPF-Permissions",
            "Serve",
            "bpf_permissions",
            "bpf-permission",
            "-h",
            "--help",
            "--version",
            " probe",
            "probe ",
        ] {
            assert_eq!(
                parse(&args(&[bad])),
                Err(UsageError::UnknownSubcommand(bad.to_string())),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn tester_empty_or_relative_connect_path_is_refused_before_the_length_check() {
        assert_eq!(
            parse(&args(&["serve", "--connect", ""])),
            Err(UsageError::ConnectPathNotAbsolute)
        );
        let long_relative = "a".repeat(200);
        assert_eq!(
            parse(&args(&["serve", "--connect", &long_relative])),
            Err(UsageError::ConnectPathNotAbsolute)
        );
        // "/" alone is absolute and short: the parser accepts it (the path
        // check in serve::startup refuses it later as not a socket).
        assert_eq!(
            parse(&args(&["serve", "--connect", "/"])),
            Ok(Mode::Serve {
                connect: PathBuf::from("/")
            })
        );
    }

    #[test]
    fn tester_dry_run_twice_or_out_of_place_is_an_unexpected_argument() {
        assert_eq!(
            parse(&args(&["bpf-permissions", "--dry-run", "--dry-run"])),
            Err(UsageError::UnexpectedArgument("--dry-run".to_string()))
        );
        assert_eq!(
            parse(&args(&["bpf-revert", "--dry-run", "x"])),
            Err(UsageError::UnexpectedArgument("x".to_string()))
        );
        assert_eq!(
            parse(&args(&["bpf-revert", "x", "--dry-run"])),
            Err(UsageError::UnexpectedArgument("x".to_string()))
        );
        assert_eq!(
            parse(&args(&["bpf-revert", "--Dry-Run"])),
            Err(UsageError::UnexpectedArgument("--Dry-Run".to_string()))
        );
    }

    #[cfg(unix)]
    #[test]
    fn tester_non_utf8_subcommand_is_unknown_and_a_non_utf8_path_still_parses() {
        use std::os::unix::ffi::OsStringExt;
        let bad = OsString::from_vec(vec![b'p', 0xff, b'r', b'o', b'b', b'e']);
        let err = parse(&[bad]).expect_err("non-UTF-8 subcommand refused");
        assert_eq!(
            err,
            UsageError::UnknownSubcommand("p\u{fffd}robe".to_string())
        );
        assert_eq!(
            err.to_string(),
            "unknown subcommand: p\u{fffd}robe (expected one of: bpf-permissions, bpf-revert, serve, probe, version)"
        );
        // A socket path is bytes: absolute and within the limit, it parses
        // even when it is not UTF-8.
        let path = OsString::from_vec(b"/tmp/\xff.sock".to_vec());
        let mode = parse(&[
            OsString::from("serve"),
            OsString::from("--connect"),
            path.clone(),
        ])
        .expect("non-UTF-8 absolute path parses");
        assert_eq!(
            mode,
            Mode::Serve {
                connect: PathBuf::from(path)
            }
        );
        // A non-UTF-8 flag where --connect belongs is the serve shape error.
        let flag = OsString::from_vec(b"--conn\xffect".to_vec());
        assert_eq!(
            parse(&[OsString::from("serve"), flag, OsString::from("/a")]),
            Err(UsageError::ServeShape)
        );
    }
}
