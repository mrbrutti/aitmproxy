//! Global terminal flags, pre-boot dispatch and the static synopsis (spec D8,
//! D9, M3; plan C19, C26).
//!
//! Three things happen before anything boots. [`pre_boot`] looks at the raw
//! argv and answers `--version`/`--help` from constants ([`version_line`],
//! [`SYNOPSIS`]), so no config is read, no runtime starts and no CA is minted
//! (AC-W1-1, AC-W1-2). [`split_term_args`] then strips the terminal flags
//! (`-v`, `-vv`, `--verbose`, `-q`, `--quiet`, `--color`) from the tokens
//! before the mode word into a [`TermOpts`] and hands the rest to the mode
//! parser unchanged (AC-W1-12). Finally [`TermOpts::detect_caps`] turns the
//! flags and the environment into the [`Caps`] the reporter draws with, with
//! animation off whenever the raw tracing stream is on (`-v`, `-vv`,
//! `RUST_LOG`; spec D2 rule 5, AC-W1-20).

use aitm_term::caps::{Caps, ColorChoice, Verbosity};

/// The terminal flags every invocation accepts before its mode word
/// (spec D9). `Default` is the bare invocation: normal verbosity, `--color
/// auto`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TermOpts {
    /// `-q` → `Quiet`; nothing → `Normal`; `-v` → `Verbose`; `-vv` → `Debug`.
    pub verbosity: Verbosity,
    /// `--color auto|always|never`.
    pub color: ColorChoice,
}

impl TermOpts {
    /// The pure half of capability detection: [`Caps::from_parts`] with this
    /// invocation's `--color`, then animation off when the raw tracing stream
    /// is on, so the live region and the stream never interleave (spec D2
    /// rule 5): `-v`/`-vv`, or a non-empty `RUST_LOG`.
    pub fn caps_from_parts(
        &self,
        tty: bool,
        width: Option<u16>,
        env: &dyn Fn(&str) -> Option<String>,
    ) -> Caps {
        self.settle_animation(
            Caps::from_parts(tty, width, self.color, env),
            env("RUST_LOG"),
        )
    }

    /// [`Self::caps_from_parts`] over the real stderr and the process
    /// environment.
    pub fn detect_caps(&self) -> Caps {
        self.settle_animation(
            Caps::detect_stderr(self.color),
            std::env::var("RUST_LOG").ok(),
        )
    }

    fn settle_animation(&self, caps: Caps, rust_log: Option<String>) -> Caps {
        let raw_stream =
            self.verbosity >= Verbosity::Verbose || rust_log.is_some_and(|v| !v.is_empty());
        if raw_stream {
            caps.without_animation()
        } else {
            caps
        }
    }
}

/// The flags whose value is the next token; the scan steps over the value so
/// `--config -v` (a file literally named `-v`) is never read as a flag and a
/// `-v` after the value still is (plan C26).
const VALUED_FLAGS: &[&str] = &["--config", "--script", "--bus-endpoint-file"];

/// Strip the terminal flags from the raw argv (spec D9; plan C26).
///
/// Scans until the first bare word (the mode word or a command group), stepping
/// over the values of `VALUED_FLAGS`; every other token, including unknown
/// `-x` flags and `-V` (pre-boot already answered it), is left for the mode
/// parser, as is everything from the bare word on. Each `-v`/`--verbose`
/// raises one level and `-vv` two, capped at `Debug`; `-q`/`--quiet` is
/// `Quiet`; `--color <v>` and `--color=<v>` take `auto`, `always` or `never`.
///
/// Errors are usage errors (exit 2): `-v` with `-q`, a `--color` without a
/// value, a `--color` value outside the three words.
pub fn split_term_args(argv: Vec<String>) -> Result<(TermOpts, Vec<String>), String> {
    let mut rest = Vec::with_capacity(argv.len());
    let mut verbose: u8 = 0;
    let mut quiet = false;
    let mut color = ColorChoice::Auto;
    let mut tokens = argv.into_iter();
    while let Some(token) = tokens.next() {
        if !token.starts_with('-') {
            // The mode word: everything from here on belongs to the mode parser.
            rest.push(token);
            rest.extend(tokens);
            break;
        }
        if let Some(value) = token.strip_prefix("--color=") {
            color = parse_color(value)?;
            continue;
        }
        match token.as_str() {
            "-v" | "--verbose" => verbose = verbose.saturating_add(1),
            "-vv" => verbose = verbose.saturating_add(2),
            "-q" | "--quiet" => quiet = true,
            "--color" => {
                let value = tokens
                    .next()
                    .ok_or_else(|| "--color requires a value".to_string())?;
                color = parse_color(&value)?;
            }
            flag if VALUED_FLAGS.contains(&flag) => {
                rest.push(token);
                if let Some(value) = tokens.next() {
                    rest.push(value);
                }
            }
            _ => rest.push(token),
        }
    }
    if quiet && verbose > 0 {
        return Err("`-v` and `-q` cannot be combined".to_string());
    }
    let verbosity = if quiet {
        Verbosity::Quiet
    } else {
        match verbose {
            0 => Verbosity::Normal,
            1 => Verbosity::Verbose,
            _ => Verbosity::Debug,
        }
    };
    Ok((TermOpts { verbosity, color }, rest))
}

fn parse_color(value: &str) -> Result<ColorChoice, String> {
    match value {
        "auto" => Ok(ColorChoice::Auto),
        "always" => Ok(ColorChoice::Always),
        "never" => Ok(ColorChoice::Never),
        other => Err(format!(
            "--color expects auto, always or never, got `{other}`"
        )),
    }
}

/// What `main()` answers before `parse_invocation`, the runtime, any config
/// read, tracing sink, script tier or CA (spec D8).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PreBoot {
    /// `--version`, `-V`, `version`: print [`version_line`] and exit 0.
    Version,
    /// `--help`, `-h`, `help`: print [`SYNOPSIS`] and exit 0.
    Help,
}

/// The pre-boot fast path: the first token, after stepping over `--config <p>`
/// and `--config=<p>`, is one of the version or help aliases. Anything else,
/// including `web --help` (the mode's own help) and an empty argv, boots.
pub fn pre_boot(argv: &[String]) -> Option<PreBoot> {
    let mut tokens = argv.iter();
    let first = loop {
        let token = tokens.next()?;
        if token == "--config" {
            tokens.next()?;
            continue;
        }
        if token.starts_with("--config=") {
            continue;
        }
        break token;
    };
    match first.as_str() {
        "--version" | "-V" | "version" => Some(PreBoot::Version),
        "--help" | "-h" | "help" => Some(PreBoot::Help),
        _ => None,
    }
}

/// `aitm <CARGO_PKG_VERSION>`, without a newline (AC-W1-1).
pub fn version_line() -> String {
    format!("aitm {}", env!("CARGO_PKG_VERSION"))
}

/// The built-in command groups: the first segments of what the binary
/// registers with a default config and no bundled catalogue (plan C19). The
/// `check` and `l4` groups come from the bundled Rhai scripts, which the
/// operator can turn off or replace, and the `L4Module`'s own verbs register
/// only when `l4.enabled`, so none of them is listed. Pinned to the live
/// registry by `tests/synopsis_groups.rs` (AC-W1-2).
pub const GROUPS: &[&str] = &[
    "agent", "browser", "ca", "capture", "config", "findings", "flow", "map", "poc", "proxy",
    "request", "scan", "scope", "script", "session", "tls", "ws",
];

/// The `aitm --help` text (spec M3's wave-1 block, verbatim, with the package
/// version in place of the mock-up's). A constant, because the registry cannot
/// be built without minting the CA (spec D8); wave 2 generates the full help.
pub const SYNOPSIS: &str = concat!(
    "aitm ",
    env!("CARGO_PKG_VERSION"),
    " — intercepting proxy for authorized security testing\n",
    "\n",
    "Usage:\n",
    "  aitm                      run the proxy with the MCP agent transport\n",
    "  aitm web [options]        run the proxy and the web operator UI\n",
    "  aitm tui                  run the proxy and the terminal operator UI\n",
    "  aitm <group> <verb> [--flag <value>]...\n",
    "                            run one command and exit\n",
    "  aitm operator-token generate [--force]\n",
    "\n",
    "Groups:\n",
    "  agent  browser  ca  capture  config  findings  flow  map  poc  proxy\n",
    "  request  scan  scope  script  session  tls  ws\n",
    "\n",
    "Options:\n",
    "  --config <path>           config file (env AITM_CONFIG)\n",
    "  --script <path>           load an extra Rhai script (repeatable)\n",
    "  -v, -vv                   show INFO / DEBUG tracing on stderr\n",
    "  -q                        errors only\n",
    "  --color <auto|always|never>\n",
    "  --version, -V             print the version and exit\n",
    "  --help, -h                print this help\n",
    "\n",
    "Learn more:\n",
    "  aitm web --help           the web UI's options\n",
    "  Nothing is decrypted until a host is in Scope.  aitm scope add --host <host>\n",
    "  Trust the CA:  aitm ca install\n",
);

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::BTreeMap;

    fn argv(tokens: &[&str]) -> Vec<String> {
        tokens.iter().map(|t| t.to_string()).collect()
    }

    fn split(tokens: &[&str]) -> Result<(TermOpts, Vec<String>), String> {
        split_term_args(argv(tokens))
    }

    fn opts(verbosity: Verbosity, color: ColorChoice) -> TermOpts {
        TermOpts { verbosity, color }
    }

    /// An environment made of the given pairs; every other name is unset.
    fn env_of(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let map: BTreeMap<String, String> = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        move |k: &str| map.get(k).cloned()
    }

    /// A UTF-8 xterm login: a TTY that animates unless something says no.
    const TTY_ENV: &[(&str, &str)] = &[("TERM", "xterm-256color"), ("LANG", "en_US.UTF-8")];

    #[test]
    fn split_term_args_strips_global_flags_before_the_first_word() {
        assert_eq!(
            split(&["-v", "--color=never", "scope", "list", "-v"]),
            Ok((
                opts(Verbosity::Verbose, ColorChoice::Never),
                argv(&["scope", "list", "-v"])
            ))
        );
    }

    #[test]
    fn split_term_args_levels_and_quiet() {
        assert_eq!(
            split(&["-vv"]),
            Ok((opts(Verbosity::Debug, ColorChoice::Auto), Vec::new()))
        );
        assert_eq!(
            split(&["--verbose", "--verbose"]),
            Ok((opts(Verbosity::Debug, ColorChoice::Auto), Vec::new()))
        );
        assert_eq!(
            split(&["-v", "-v", "-v"]),
            Ok((opts(Verbosity::Debug, ColorChoice::Auto), Vec::new())),
            "three -v are capped at Debug"
        );
        assert_eq!(
            split(&["-q"]),
            Ok((opts(Verbosity::Quiet, ColorChoice::Auto), Vec::new()))
        );
        assert_eq!(
            split(&["--quiet", "web"]),
            Ok((opts(Verbosity::Quiet, ColorChoice::Auto), argv(&["web"])))
        );
    }

    #[test]
    fn split_term_args_steps_over_valued_flags() {
        assert_eq!(
            split(&["--config", "x", "-v", "web"]),
            Ok((
                opts(Verbosity::Verbose, ColorChoice::Auto),
                argv(&["--config", "x", "web"])
            ))
        );
        assert_eq!(
            split(&["--script", "a.rhai", "-q"]),
            Ok((
                opts(Verbosity::Quiet, ColorChoice::Auto),
                argv(&["--script", "a.rhai"])
            ))
        );
        assert_eq!(
            split(&["--bus-endpoint-file=/f", "--color", "always"]),
            Ok((
                opts(Verbosity::Normal, ColorChoice::Always),
                argv(&["--bus-endpoint-file=/f"])
            ))
        );
    }

    #[test]
    fn split_term_args_errors() {
        assert_eq!(
            split(&["-v", "-q"]),
            Err("`-v` and `-q` cannot be combined".to_string())
        );
        assert_eq!(
            split(&["--color", "bogus"]),
            Err("--color expects auto, always or never, got `bogus`".to_string())
        );
        assert_eq!(
            split(&["--color"]),
            Err("--color requires a value".to_string())
        );
    }

    #[test]
    fn split_term_args_leaves_unknown_and_version_flags_alone() {
        assert_eq!(
            split(&["--flag-first"]),
            Ok((TermOpts::default(), argv(&["--flag-first"])))
        );
        assert_eq!(split(&["-V"]), Ok((TermOpts::default(), argv(&["-V"]))));
        assert_eq!(
            TermOpts::default(),
            opts(Verbosity::Normal, ColorChoice::Auto)
        );
    }

    #[test]
    fn caps_from_parts_disables_animation_for_verbose_and_rust_log() {
        let normal = TermOpts::default();
        let rust_log_env = env_of(&[
            ("TERM", "xterm-256color"),
            ("LANG", "en_US.UTF-8"),
            ("RUST_LOG", "info"),
        ]);
        assert!(
            !normal
                .caps_from_parts(true, Some(120), &rust_log_env)
                .animate,
            "RUST_LOG=info restores the raw stream: no in-place drawing"
        );

        let verbose = opts(Verbosity::Verbose, ColorChoice::Auto);
        assert!(
            !verbose
                .caps_from_parts(true, Some(120), &env_of(TTY_ENV))
                .animate,
            "-v restores the raw stream: no in-place drawing"
        );
        let debug = opts(Verbosity::Debug, ColorChoice::Auto);
        assert!(
            !debug
                .caps_from_parts(true, Some(120), &env_of(TTY_ENV))
                .animate
        );

        let caps = normal.caps_from_parts(true, Some(120), &env_of(TTY_ENV));
        assert_eq!(
            caps,
            Caps {
                tty: true,
                color: true,
                unicode: true,
                animate: true,
                width: 120,
                ci: false,
            }
        );

        let empty_rust_log = env_of(&[
            ("TERM", "xterm-256color"),
            ("LANG", "en_US.UTF-8"),
            ("RUST_LOG", ""),
        ]);
        assert!(
            normal
                .caps_from_parts(true, Some(120), &empty_rust_log)
                .animate,
            "an empty RUST_LOG is not active"
        );

        let never = opts(Verbosity::Normal, ColorChoice::Never);
        assert!(
            !never
                .caps_from_parts(true, Some(120), &env_of(TTY_ENV))
                .color,
            "--color reaches Caps::from_parts"
        );
    }

    #[test]
    fn pre_boot_recognises_every_alias_and_skips_config() {
        for token in ["--version", "-V", "version"] {
            assert_eq!(pre_boot(&argv(&[token])), Some(PreBoot::Version), "{token}");
        }
        for token in ["--help", "-h", "help"] {
            assert_eq!(pre_boot(&argv(&[token])), Some(PreBoot::Help), "{token}");
        }
        assert_eq!(
            pre_boot(&argv(&["--config", "x", "--version"])),
            Some(PreBoot::Version)
        );
        assert_eq!(pre_boot(&argv(&["--config=x", "-h"])), Some(PreBoot::Help));
        assert_eq!(pre_boot(&argv(&["scope", "list"])), None);
        assert_eq!(pre_boot(&argv(&["web", "--help"])), None);
        assert_eq!(pre_boot(&[]), None);
        assert_eq!(pre_boot(&argv(&["--config"])), None);
    }

    #[test]
    fn version_line_is_aitm_and_the_package_version() {
        assert_eq!(
            version_line(),
            format!("aitm {}", env!("CARGO_PKG_VERSION"))
        );
    }

    #[test]
    fn synopsis_first_line_and_groups_block() {
        let first = format!(
            "aitm {} — intercepting proxy for authorized security testing",
            env!("CARGO_PKG_VERSION")
        );
        assert_eq!(SYNOPSIS.lines().next(), Some(first.as_str()));

        let block = "\nGroups:\n  agent  browser  ca  capture  config  findings  flow  map  poc  proxy\n  request  scan  scope  script  session  tls  ws\n";
        assert!(
            SYNOPSIS.contains(block),
            "the Groups block is not verbatim:\n{SYNOPSIS}"
        );
        let words: Vec<&str> = block
            .trim_start_matches("\nGroups:\n")
            .split_whitespace()
            .collect();
        assert_eq!(words.as_slice(), GROUPS);
        assert_eq!(GROUPS.len(), 17);

        assert!(
            SYNOPSIS.ends_with("  Trust the CA:  aitm ca install\n"),
            "the synopsis must end with the CA line and one newline:\n{SYNOPSIS}"
        );
        assert!(!SYNOPSIS.ends_with("\n\n"));
    }
}
