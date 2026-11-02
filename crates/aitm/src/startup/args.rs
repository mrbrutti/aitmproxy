//! Global terminal flags and the pre-boot version answer (spec D8, D9; plan
//! C19, C26, C32).
//!
//! Three things happen before anything boots. [`pre_boot`] looks at the raw
//! argv and answers `--version` from a constant ([`version_line`]), so no
//! config is read, no runtime starts and no CA is minted (AC-W1-1). Help is
//! not answered here since wave 2 (plan C32, AC-W2-7): every help form —
//! `--help`, `-h`, `help [topic…]`, a bare group, `<group> <verb> --help` —
//! is recognised by `help::request::parse` inside `parse_invocation` and
//! answered by [`crate::help`] from the schema-only registry, which reads
//! the config but creates nothing. [`split_term_args`] then strips the terminal flags
//! (`-v`, `-vv`, `--verbose`, `-q`, `--quiet`, `--color`) from the tokens
//! before the mode word into a [`TermOpts`] and hands the rest to the mode
//! parser unchanged (AC-W1-12). Finally [`TermOpts::detect_caps`] turns the
//! flags and the environment into the [`Caps`] the reporter draws with, with
//! animation off whenever the raw tracing stream is on (`-v`, `-vv`,
//! `RUST_LOG`; spec D2 rule 5, AC-W1-20). [`rust_log_active`] is the one
//! definition of "`RUST_LOG` is on" that this module and `log.rs` share; it
//! lives here because `log.rs` already imports [`TermOpts`] from this module
//! (quality Q17: no import cycle between the two).

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
            self.verbosity >= Verbosity::Verbose || rust_log_active(rust_log.as_deref());
        if raw_stream {
            caps.without_animation()
        } else {
            caps
        }
    }
}

/// The one definition of "`RUST_LOG` is active" (quality Q2, tester F4):
/// the value is set and non-empty after trimming, the way the file directive
/// has always read it. Every consumer — the caps' animation switch
/// ([`TermOpts::caps_from_parts`]), the raw stderr stream and the file
/// directive in `log.rs` — reads it through here, so `RUST_LOG=" "` is
/// inactive everywhere at once.
pub(crate) fn rust_log_active(value: Option<&str>) -> bool {
    value.is_some_and(|v| !v.trim().is_empty())
}

/// The flags whose value is the next token; the scan steps over the value so
/// `--config -v` (a file literally named `-v`) is never read as a flag and a
/// `-v` after the value still is (plan C26).
const VALUED_FLAGS: &[&str] = &["--config", "--script", "--bus-endpoint-file"];

/// What one value-less terminal switch does to the parsed [`TermOpts`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Switch {
    /// Raise the verbosity this many levels (capped at `Debug`).
    Verbose(u8),
    /// `-q`: errors only.
    Quiet,
}

/// The value-less terminal flags and their effect: the ONE list
/// [`split_term_args`] strips and [`pre_boot`] steps over before matching
/// the alias (tester F3, quality Q18). `--color` is the one valued terminal
/// flag and is handled beside `--config`.
const TERM_SWITCHES: &[(&str, Switch)] = &[
    ("-v", Switch::Verbose(1)),
    ("-vv", Switch::Verbose(2)),
    ("--verbose", Switch::Verbose(1)),
    ("-q", Switch::Quiet),
    ("--quiet", Switch::Quiet),
];

/// The switch `token` spells, if it is one of [`TERM_SWITCHES`].
fn term_switch(token: &str) -> Option<Switch> {
    TERM_SWITCHES
        .iter()
        .find(|(flag, _)| *flag == token)
        .map(|(_, switch)| *switch)
}

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
        match term_switch(&token) {
            Some(Switch::Verbose(levels)) => {
                verbose = verbose.saturating_add(levels);
                continue;
            }
            Some(Switch::Quiet) => {
                quiet = true;
                continue;
            }
            None => {}
        }
        match token.as_str() {
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
    /// returned by nothing since wave 2; T15 deletes it together with
    /// `main.rs`'s match arm
    Help,
}

/// The pre-boot fast path: the first token, after stepping over `--config <p>`
/// / `--config=<p>` and the terminal flags [`split_term_args`] knows (`-v`,
/// `-vv`, `--verbose`, `-q`, `--quiet`, `--color <v>`, `--color=<v>`; tester
/// F3, so `aitm -v --version` never boots the host), is one of the version
/// aliases. Anything else returns `None` — the help aliases included, since
/// wave 2 (plan C32): `--help`, `-h` and `help` are `help::request::parse`'s
/// inside `parse_invocation`, after the terminal flags are split — as does an
/// empty argv. A flag's value is never read as the alias: `--config
/// --version` names a file and `--color --version` names a colour.
pub fn pre_boot(argv: &[String]) -> Option<PreBoot> {
    let mut tokens = argv.iter();
    let first = loop {
        let token = tokens.next()?;
        if token == "--config" || token == "--color" {
            tokens.next()?;
            continue;
        }
        if token.starts_with("--config=") || token.starts_with("--color=") {
            continue;
        }
        if term_switch(token).is_some() {
            continue;
        }
        break token;
    };
    match first.as_str() {
        "--version" | "-V" | "version" => Some(PreBoot::Version),
        _ => None,
    }
}

/// `aitm <CARGO_PKG_VERSION>`, without a newline (AC-W1-1).
pub fn version_line() -> String {
    format!("aitm {}", env!("CARGO_PKG_VERSION"))
}

/// Wave 1's static `aitm --help` text (spec M3's wave-1 block, with the
/// package version in place of the mock-up's). Printed by nothing since wave
/// 2: [`pre_boot`] no longer answers help and [`crate::help`] builds the pages
/// from the schema-only registry (plan C32). Still declared only because
/// `main.rs`'s `PreBoot::Help` arm names it; T15 deletes it together with
/// that arm and the variant.
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
    "  agent  browser  ca  capture  check  config  findings  flow  map  poc\n",
    "  proxy  request  scan  scope  script  session  tls  ws\n",
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
        // Quality Q2 / tester F4: one definition of "RUST_LOG is active"
        // (`rust_log_active`, trimmed and non-empty), so a
        // blank value does not switch the raw stream on for the caps while
        // `raw_stream` leaves it off.
        let blank_rust_log = env_of(&[
            ("TERM", "xterm-256color"),
            ("LANG", "en_US.UTF-8"),
            ("RUST_LOG", " "),
        ]);
        assert!(
            normal
                .caps_from_parts(true, Some(120), &blank_rust_log)
                .animate,
            "a blank RUST_LOG is not active either"
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
    fn version_line_is_aitm_and_the_package_version() {
        assert_eq!(
            version_line(),
            format!("aitm {}", env!("CARGO_PKG_VERSION"))
        );
    }

    // ---- tester, whole-branch pass (plan C26, spec D8/D9, AC-W1-1/2/12) ----

    /// The equals form of a valued flag is one token, so it rides through and
    /// the terminal flags around it are still stripped; a valued flag's value
    /// is never read as a terminal flag; a valued flag with nothing after it
    /// is handed on as is for the mode parser to reject (plan C26).
    #[test]
    fn split_term_args_equals_form_and_flag_shaped_values() {
        assert_eq!(
            split(&["--config=/etc/aitm.yaml", "-v", "scope", "list"]),
            Ok((
                opts(Verbosity::Verbose, ColorChoice::Auto),
                argv(&["--config=/etc/aitm.yaml", "scope", "list"])
            ))
        );
        assert_eq!(
            split(&["--script=a.rhai", "-q", "--bus-endpoint-file=/f", "web"]),
            Ok((
                opts(Verbosity::Quiet, ColorChoice::Auto),
                argv(&["--script=a.rhai", "--bus-endpoint-file=/f", "web"])
            ))
        );
        // `--config -v` names a file called `-v`: no level is raised.
        assert_eq!(
            split(&["--config", "-v", "web"]),
            Ok((TermOpts::default(), argv(&["--config", "-v", "web"])))
        );
        assert_eq!(
            split(&["--script", "-q"]),
            Ok((TermOpts::default(), argv(&["--script", "-q"])))
        );
        // Nothing after a valued flag: handed on; the mode parser reports the
        // missing path.
        assert_eq!(
            split(&["--config"]),
            Ok((TermOpts::default(), argv(&["--config"])))
        );
        assert_eq!(split(&[]), Ok((TermOpts::default(), Vec::new())));
    }

    #[test]
    fn split_term_args_color_edge_cases_and_repeated_flags() {
        assert_eq!(
            split(&["--color="]),
            Err("--color expects auto, always or never, got ``".to_string())
        );
        assert_eq!(
            split(&["--color=Never"]),
            Err("--color expects auto, always or never, got `Never`".to_string()),
            "the three words are lowercase"
        );
        // `--color` takes the next token whatever it is: a mode word in that
        // position is a bad value, not a mode.
        assert_eq!(
            split(&["--color", "scope", "list"]),
            Err("--color expects auto, always or never, got `scope`".to_string())
        );
        // The last `--color` wins, in either spelling.
        assert_eq!(
            split(&["--color", "always", "--color=never"]),
            Ok((opts(Verbosity::Normal, ColorChoice::Never), Vec::new()))
        );
        assert_eq!(
            split(&["--color=never", "--color", "auto"]),
            Ok((opts(Verbosity::Normal, ColorChoice::Auto), Vec::new()))
        );
        // Terminal flags after the mode word belong to the mode parser.
        assert_eq!(
            split(&["scope", "list", "--color", "never", "-q", "-vv"]),
            Ok((
                TermOpts::default(),
                argv(&["scope", "list", "--color", "never", "-q", "-vv"])
            ))
        );
        // `-q` twice is Quiet; `-q` with any verbose spelling, in any order,
        // around any valued flag, is the one error.
        assert_eq!(
            split(&["-q", "--quiet"]),
            Ok((opts(Verbosity::Quiet, ColorChoice::Auto), Vec::new()))
        );
        for bad in [
            &["--quiet", "--verbose"][..],
            &["-vv", "-q"],
            &["-q", "-v", "web"],
            &["-v", "--config", "x", "-q"],
        ] {
            assert_eq!(
                split(bad),
                Err("`-v` and `-q` cannot be combined".to_string()),
                "{bad:?}"
            );
        }
    }

    /// A pipe never animates whatever `--color` says (spec D2 rule 7);
    /// `-q` is the reporter's business and leaves the caps alone; `CI` on a
    /// TTY means plain lines (D2 rule 5, plan C22).
    #[test]
    fn caps_from_parts_pipe_quiet_and_ci() {
        let always = opts(Verbosity::Normal, ColorChoice::Always);
        let piped = always.caps_from_parts(false, None, &env_of(TTY_ENV));
        assert!(!piped.tty);
        assert!(!piped.animate, "a pipe never animates: {piped:?}");
        assert_eq!(piped.width, 80, "80 when unknown");

        let quiet = opts(Verbosity::Quiet, ColorChoice::Auto);
        assert_eq!(
            quiet.caps_from_parts(true, Some(100), &env_of(TTY_ENV)),
            TermOpts::default().caps_from_parts(true, Some(100), &env_of(TTY_ENV)),
            "-q changes no capability"
        );

        let ci = env_of(&[
            ("TERM", "xterm-256color"),
            ("LANG", "en_US.UTF-8"),
            ("CI", ""),
        ]);
        let caps = TermOpts::default().caps_from_parts(true, Some(100), &ci);
        assert!(caps.ci, "CI present with an empty value counts (plan C22)");
        assert!(!caps.animate, "CI on a TTY: plain lines");
    }

    /// Quality Q17: `log.rs` imports `TermOpts` from this module, so this
    /// module never imports from `log.rs` (the "is `RUST_LOG` active"
    /// predicate lives here, with the flags it belongs beside); a reverse
    /// import is a cycle between the two startup leaves.
    #[test]
    fn args_never_imports_from_the_log_module() {
        let offenders: Vec<&str> = include_str!("args.rs")
            .lines()
            .filter(|line| line.trim_start().starts_with("use crate::startup::log"))
            .collect();
        assert!(
            offenders.is_empty(),
            "args.rs imports from log.rs (log.rs imports TermOpts from args.rs): {offenders:?}"
        );
    }

    /// Quality Q2 / tester F4 / Q17: the one predicate every consumer reads
    /// (`caps_from_parts` here, `raw_stream` and the file directive in
    /// `log.rs`). Unset, empty and blank are inactive; anything with a
    /// non-space character is active, however it is padded.
    #[test]
    fn rust_log_active_is_trimmed_non_empty() {
        assert!(!rust_log_active(None));
        assert!(!rust_log_active(Some("")));
        assert!(!rust_log_active(Some(" ")));
        assert!(!rust_log_active(Some("\t\n")));
        assert!(rust_log_active(Some("info")));
        assert!(rust_log_active(Some(" warn ")));
        assert!(rust_log_active(Some("x")));
    }

    /// Quality Q18: `TERM_SWITCHES` is the ONE list of value-less terminal
    /// switches; `split_term_args` strips every entry (and each one changes
    /// the parsed opts) and `pre_boot` steps over every entry, so a switch
    /// added to the table is honoured by both scans at once.
    #[test]
    fn every_term_switch_is_stripped_by_split_term_args_and_stepped_over_by_pre_boot() {
        assert_eq!(TERM_SWITCHES.len(), 5, "-v, -vv, --verbose, -q, --quiet");
        for &(flag, switch) in TERM_SWITCHES {
            let (parsed, rest) =
                split(&[flag, "scope", "list"]).unwrap_or_else(|err| panic!("{flag}: {err}"));
            assert_eq!(
                rest,
                argv(&["scope", "list"]),
                "{flag} was left in the argv"
            );
            let expected = match switch {
                Switch::Verbose(1) => Verbosity::Verbose,
                Switch::Verbose(_) => Verbosity::Debug,
                Switch::Quiet => Verbosity::Quiet,
            };
            assert_eq!(parsed, opts(expected, ColorChoice::Auto), "{flag}");
            assert_eq!(
                pre_boot(&argv(&[flag, "--version"])),
                Some(PreBoot::Version),
                "{flag} was not stepped over"
            );
        }
    }

    /// Spec D8 as wave 2 reads it (plan C32): `pre_boot` answers the three
    /// version aliases after stepping over `--config <p>`/`--config=<p>` and
    /// every terminal flag `split_term_args` knows, so `aitm -v --version`
    /// and `aitm --color never version` never boot the host (tester F3); the
    /// alias must be the whole first token, a flag's value is never read as
    /// the alias, and nothing after the alias matters.
    #[test]
    fn pre_boot_recognises_the_version_aliases_and_steps_over_flags() {
        for alias in ["--version", "-V", "version"] {
            assert_eq!(pre_boot(&argv(&[alias])), Some(PreBoot::Version), "{alias}");
        }
        for flags in [
            &["--config", "x"][..],
            &["--config=x"],
            &["-v"],
            &["-vv"],
            &["--verbose"],
            &["-q"],
            &["--quiet"],
            &["-q", "-v"],
            &["--color", "never"],
            &["--color=never"],
            &["--config", "a", "--config=b"],
            &["--color", "auto", "--config", "x", "-vv"],
        ] {
            for alias in ["--version", "-V", "version"] {
                let mut tokens: Vec<&str> = flags.to_vec();
                tokens.push(alias);
                assert_eq!(
                    pre_boot(&argv(&tokens)),
                    Some(PreBoot::Version),
                    "{tokens:?}"
                );
            }
        }
        // Nothing after the alias matters; `-V` is pre-boot's own alias, not
        // a verbosity flag.
        assert_eq!(
            pre_boot(&argv(&["version", "--config"])),
            Some(PreBoot::Version)
        );
        assert_eq!(pre_boot(&argv(&["-V", "-v"])), Some(PreBoot::Version));

        // A flag's value is never the alias: `--config --version` names a
        // file and `--color --version` a colour.
        assert_eq!(pre_boot(&argv(&["--config", "--version"])), None);
        assert_eq!(pre_boot(&argv(&["--color", "--version"])), None);
        // Only `--config` and the terminal flags are stepped over.
        assert_eq!(pre_boot(&argv(&["--script", "a.rhai", "--version"])), None);
        // Flags alone, a command word, an empty argv: boot.
        for boots in [
            &["--config=x"][..],
            &["--config", "x"],
            &["--config"],
            &["--color"],
            &["-v"],
            &["scope", "list"],
            &["-q", "scope", "list"],
            &["web", "--help"],
            &[],
        ] {
            assert_eq!(pre_boot(&argv(boots)), None, "{boots:?}");
        }
        // The alias is the whole token, case-sensitive.
        for not_alias in ["--version=1", "-Vv", "Version", "VERSION", "--Version", ""] {
            assert_eq!(pre_boot(&argv(&[not_alias])), None, "{not_alias:?}");
        }
    }

    /// Plan C32 (AC-W2-7, one help path): the help aliases are no longer
    /// pre-boot's. `--help`, `-h`, `help` and `help <topic…>`, with or
    /// without stepped-over flags before them, return `None`, so they reach
    /// `help::request::parse` inside `parse_invocation` and are answered by
    /// `crate::help` from the schema-only registry.
    #[test]
    fn pre_boot_leaves_help_to_the_help_resolver() {
        for tokens in [
            &["--help"][..],
            &["-h"],
            &["help"],
            &["help", "scope"],
            &["help", "scope", "add"],
            &["--color", "never", "-h"],
            &["--color=never", "--help"],
            &["--config=x", "-h"],
            &["--config", "x", "--help"],
            &["-v", "--help"],
            &["--help", "scope", "list"],
            &["scope", "--help"],
            &["scope", "add", "--help"],
            &["web", "--help"],
            &["tui", "--help"],
            &["-hh"],
            &["--helpme"],
            &["HELP"],
            &["--Help"],
        ] {
            assert_eq!(pre_boot(&argv(tokens)), None, "{tokens:?}");
        }
    }
}
