//! The state file: what we wrote and what was there before, so a crash or a
//! later process can restore it (spec §D7). `Previous` is the snapshot the
//! platform trait restores from; `StateFile` is the on-disk envelope.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Context;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use crate::{Mechanism, ServiceRow, Wrote};

/// The snapshot taken before the first mutating command, per mechanism.
/// Linux values are the raw `gsettings get` / `kreadconfig` text, restored
/// verbatim.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Previous {
    Networksetup {
        services: Vec<ServiceRow>,
    },
    Gsettings {
        keys: BTreeMap<String, String>,
    },
    Kde {
        kioslaverc: BTreeMap<String, String>,
        gsettings: Option<BTreeMap<String, String>>,
    },
}

/// The §D7 document: what we wrote, what was there before, and who wrote
/// it. Written with mode `0600`, atomically, before the first mutating
/// command; removed by an orderly unset, a completed restore, or the
/// "another tool owns it" rule.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct StateFile {
    pub version: u32,
    /// `macos` | `linux` | `windows` (the Rust OS word).
    pub platform: String,
    pub mechanism: Mechanism,
    /// RFC 3339, UTC, whole seconds.
    pub saved_at: String,
    pub pid: u32,
    pub wrote: Wrote,
    pub previous: Previous,
}

impl StateFile {
    /// The only document version this build reads or writes.
    pub const VERSION: u32 = 1;

    /// A fresh envelope stamped with this host's OS word and the current time.
    pub fn new(mechanism: Mechanism, pid: u32, wrote: Wrote, previous: Previous) -> StateFile {
        StateFile {
            version: Self::VERSION,
            platform: platform_word().to_string(),
            mechanism,
            saved_at: now_rfc3339(),
            pid,
            wrote,
            previous,
        }
    }

    /// Read the file. Absent → `Ok(None)`. Unreadable, unparsable or
    /// `version != 1` → the file is renamed to `<file>.corrupt-<unix secs>`,
    /// logged at `warn`, and reported as absent. Only a failed quarantine is
    /// an error.
    pub fn load(path: &Path) -> anyhow::Result<Option<StateFile>> {
        let bytes = match fs::read(path) {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => {
                return quarantine(path, &format!("unreadable: {e}")).map(|()| None);
            }
        };
        let version = match serde_json::from_slice::<VersionOnly>(&bytes) {
            Ok(v) => v.version,
            Err(e) => {
                return quarantine(path, &format!("not a JSON document: {e}")).map(|()| None);
            }
        };
        if version != Self::VERSION {
            return quarantine(
                path,
                &format!("version {version}, this build reads {}", Self::VERSION),
            )
            .map(|()| None);
        }
        match serde_json::from_slice::<StateFile>(&bytes) {
            Ok(file) => Ok(Some(file)),
            Err(e) => quarantine(path, &format!("malformed: {e}")).map(|()| None),
        }
    }

    /// Create the parent directory, write `<path>.tmp-<pid>` with mode
    /// `0600`, fsync, rename over `path`.
    pub fn save_atomic(&self, path: &Path) -> anyhow::Result<()> {
        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
        }
        let tmp = temp_path(path);
        let mut body = serde_json::to_vec_pretty(self).context("encode state file")?;
        body.push(b'\n');
        let written = write_private(&tmp, &body);
        if let Err(e) = written {
            let _ = fs::remove_file(&tmp);
            return Err(e).with_context(|| format!("write {}", tmp.display()));
        }
        if let Err(e) = fs::rename(&tmp, path) {
            let _ = fs::remove_file(&tmp);
            return Err(e)
                .with_context(|| format!("rename {} over {}", tmp.display(), path.display()));
        }
        Ok(())
    }

    /// Remove the file; `Ok(false)` when it was already absent.
    pub fn remove(path: &Path) -> anyhow::Result<bool> {
        match fs::remove_file(path) {
            Ok(()) => Ok(true),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(e).with_context(|| format!("remove {}", path.display())),
        }
    }

    /// The services `previous` can restore: each macOS row by name;
    /// `gsettings`; `kde` (plus `gsettings` when the KDE snapshot has one).
    pub fn service_names(&self) -> Vec<String> {
        match &self.previous {
            Previous::Networksetup { services } => {
                services.iter().map(|row| row.service.clone()).collect()
            }
            Previous::Gsettings { .. } => vec!["gsettings".to_string()],
            Previous::Kde { gsettings, .. } => {
                let mut names = vec!["kde".to_string()];
                if gsettings.is_some() {
                    names.push("gsettings".to_string());
                }
                names
            }
        }
    }
}

/// Just enough of the document to check `version` before the full parse.
#[derive(serde::Deserialize)]
struct VersionOnly {
    version: u32,
}

/// `std::env::consts::OS`, which already spells `macos`/`linux`/`windows`.
fn platform_word() -> &'static str {
    std::env::consts::OS
}

/// Now, UTC, RFC 3339 at whole-second precision (`2026-10-31T17:02:11Z`).
fn now_rfc3339() -> String {
    let now = OffsetDateTime::now_utc();
    now.replace_nanosecond(0)
        .unwrap_or(now)
        .format(&Rfc3339)
        .unwrap_or_else(|_| now.unix_timestamp().to_string())
}

fn unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// `<path>.tmp-<pid>` beside the target so the rename stays on one filesystem.
fn temp_path(path: &Path) -> PathBuf {
    let mut name = path
        .file_name()
        .map(|n| n.to_os_string())
        .unwrap_or_else(|| OsString::from(crate::STATE_FILE_NAME));
    name.push(format!(".tmp-{}", std::process::id()));
    path.with_file_name(name)
}

/// `<path>.corrupt-<unix secs>`, with `-1`, `-2`, … appended when that name
/// is already taken so two quarantines in one second keep both files.
fn corrupt_path(path: &Path) -> PathBuf {
    let base = path
        .file_name()
        .map(|n| n.to_os_string())
        .unwrap_or_else(|| OsString::from(crate::STATE_FILE_NAME));
    let secs = unix_secs();
    let mut n = 0u32;
    loop {
        let mut name = base.clone();
        if n == 0 {
            name.push(format!(".corrupt-{secs}"));
        } else {
            name.push(format!(".corrupt-{secs}-{n}"));
        }
        let candidate = path.with_file_name(name);
        if !candidate.exists() {
            return candidate;
        }
        n += 1;
    }
}

/// Move a bad file aside and say why; the caller then treats it as absent.
fn quarantine(path: &Path, why: &str) -> anyhow::Result<()> {
    let target = corrupt_path(path);
    fs::rename(path, &target).with_context(|| {
        format!(
            "state file {} is {why} and could not be moved to {}",
            path.display(),
            target.display()
        )
    })?;
    tracing::warn!(
        file = %path.display(),
        moved_to = %target.display(),
        "system proxy state file {why}; moved aside and treated as absent"
    );
    Ok(())
}

/// Create-or-truncate `path` readable by the owner only, write, fsync.
fn write_private(path: &Path, body: &[u8]) -> io::Result<()> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    #[cfg(unix)]
    {
        // `mode` applies only when the file is created; an existing temp
        // file from an earlier crash keeps its old bits unless we set them.
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
    }
    file.write_all(body)?;
    file.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;
    use crate::{Mechanism, Wrote, STATE_FILE_NAME};

    /// The §D7 document, verbatim.
    const SPEC_DOCUMENT: &str = r#"{
  "version": 1,
  "platform": "macos",
  "mechanism": "networksetup",
  "saved_at": "2026-10-31T17:02:11Z",
  "pid": 48213,
  "wrote": { "host": "127.0.0.1", "port": 8080,
             "bypass": ["*.local", "169.254/16", "localhost", "127.0.0.1", "::1"] },
  "previous": {
    "kind": "networksetup",
    "services": [
      { "service": "Display Ethernet",
        "http":  { "enabled": true, "host": "127.0.0.1", "port": 9090 },
        "https": { "enabled": true, "host": "127.0.0.1", "port": 9090 },
        "bypass": ["*.local", "169.254/16"] },
      { "service": "Wi-Fi",
        "http":  { "enabled": false, "host": "", "port": 0 },
        "https": { "enabled": false, "host": "", "port": 0 },
        "bypass": ["*.local", "169.254/16"] }
    ]
  }
}"#;

    /// The §D7 Linux `previous` variants, verbatim.
    const GSETTINGS_PREVIOUS: &str = r#"{ "kind": "gsettings", "keys": { "org.gnome.system.proxy mode": "'none'", "org.gnome.system.proxy.http host": "''", "org.gnome.system.proxy.http port": "8080", "org.gnome.system.proxy.https host": "''", "org.gnome.system.proxy.https port": "0", "org.gnome.system.proxy ignore-hosts": "['localhost', '127.0.0.0/8', '::1']" } }"#;
    const KDE_PREVIOUS: &str = r#"{ "kind": "kde", "kioslaverc": { "ProxyType": "0", "httpProxy": "", "httpsProxy": "", "NoProxyFor": "" }, "gsettings": null }"#;

    /// A fresh, unique directory under the OS temp dir; the caller removes it.
    fn temp_dir(tag: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock after 1970")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("aitm-sysproxy-{tag}-{nanos}"));
        fs::create_dir_all(&dir).expect("create temp dir");
        dir
    }

    fn corrupt_siblings(dir: &std::path::Path) -> Vec<String> {
        let mut names: Vec<String> = fs::read_dir(dir)
            .expect("read temp dir")
            .map(|e| {
                e.expect("dir entry")
                    .file_name()
                    .to_string_lossy()
                    .into_owned()
            })
            .filter(|n| n.starts_with(&format!("{STATE_FILE_NAME}.corrupt-")))
            .collect();
        names.sort();
        names
    }

    /// SP-AC5 (round-trip half), §D7.
    #[test]
    fn round_trips_the_spec_document() {
        let parsed: StateFile = serde_json::from_str(SPEC_DOCUMENT).expect("spec document parses");
        assert_eq!(parsed.version, 1);
        assert_eq!(parsed.version, StateFile::VERSION);
        assert_eq!(parsed.platform, "macos");
        assert_eq!(parsed.mechanism, Mechanism::Networksetup);
        assert_eq!(parsed.saved_at, "2026-10-31T17:02:11Z");
        assert_eq!(parsed.pid, 48213);
        assert_eq!(parsed.wrote.host, "127.0.0.1");
        assert_eq!(parsed.wrote.port, 8080);
        assert_eq!(
            parsed.wrote.bypass,
            vec!["*.local", "169.254/16", "localhost", "127.0.0.1", "::1"]
        );
        let Previous::Networksetup { services } = &parsed.previous else {
            panic!("previous is networksetup, got {:?}", parsed.previous);
        };
        assert_eq!(services.len(), 2);
        assert_eq!(services[0].service, "Display Ethernet");
        assert!(services[0].http.enabled);
        assert_eq!(services[0].https.port, 9090);
        assert_eq!(services[1].service, "Wi-Fi");
        assert!(!services[1].http.enabled);
        assert_eq!(services[1].http.host, "");
        assert_eq!(services[1].http.port, 0);
        assert_eq!(services[1].bypass, vec!["*.local", "169.254/16"]);
        assert_eq!(
            parsed.service_names(),
            vec!["Display Ethernet".to_string(), "Wi-Fi".to_string()]
        );

        // Serialising keeps the `kind` tag and the wire words.
        let json: serde_json::Value = serde_json::to_value(&parsed).expect("state file serialises");
        assert_eq!(json["previous"]["kind"], "networksetup");
        assert_eq!(json["mechanism"], "networksetup");
        assert_eq!(json["version"], 1);

        // Absent file → Ok(None); save then load → Some(equal); mode 0600.
        let dir = temp_dir("roundtrip");
        let path = dir.join(STATE_FILE_NAME);
        assert_eq!(StateFile::load(&path).expect("absent loads"), None);
        parsed.save_atomic(&path).expect("save");
        assert!(path.is_file(), "state file exists after save");
        assert!(
            !dir.join(format!("{STATE_FILE_NAME}.tmp-{}", std::process::id()))
                .exists(),
            "temp file renamed away"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&path).expect("metadata").permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "mode is 0600, got {mode:o}");
        }
        let loaded = StateFile::load(&path).expect("load");
        assert_eq!(loaded, Some(parsed.clone()));

        // A nested parent directory is created on the way.
        let nested = dir.join("a").join("b").join(STATE_FILE_NAME);
        parsed
            .save_atomic(&nested)
            .expect("save into missing parent");
        assert_eq!(StateFile::load(&nested).expect("load nested"), Some(parsed));

        fs::remove_dir_all(&dir).expect("remove temp dir");
    }

    /// §D7: the Linux `previous` variants, and `new` fills the envelope.
    #[test]
    fn linux_previous_variants_and_new_envelope() {
        let gs: Previous = serde_json::from_str(GSETTINGS_PREVIOUS).expect("gsettings parses");
        let Previous::Gsettings { keys } = &gs else {
            panic!("gsettings variant, got {gs:?}");
        };
        assert_eq!(keys.len(), 6);
        assert_eq!(keys["org.gnome.system.proxy mode"], "'none'");
        assert_eq!(keys["org.gnome.system.proxy.http host"], "''");
        assert_eq!(keys["org.gnome.system.proxy.http port"], "8080");
        assert_eq!(
            keys["org.gnome.system.proxy ignore-hosts"],
            "['localhost', '127.0.0.0/8', '::1']"
        );

        let kde: Previous = serde_json::from_str(KDE_PREVIOUS).expect("kde parses");
        let Previous::Kde {
            kioslaverc,
            gsettings,
        } = &kde
        else {
            panic!("kde variant, got {kde:?}");
        };
        assert_eq!(kioslaverc["ProxyType"], "0");
        assert_eq!(kioslaverc["httpProxy"], "");
        assert_eq!(kioslaverc["NoProxyFor"], "");
        assert_eq!(gsettings, &None);

        let wrote = Wrote {
            host: "127.0.0.1".into(),
            port: 8080,
            bypass: vec!["localhost".into()],
        };
        let file = StateFile::new(Mechanism::Gsettings, 4242, wrote.clone(), gs);
        assert_eq!(file.version, 1);
        assert_eq!(file.pid, 4242);
        assert_eq!(file.mechanism, Mechanism::Gsettings);
        assert_eq!(file.wrote, wrote);
        assert_eq!(file.platform, std::env::consts::OS);
        assert!(
            ["macos", "linux", "windows"].contains(&file.platform.as_str()),
            "platform word, got {}",
            file.platform
        );
        // RFC 3339, UTC, whole seconds: `YYYY-MM-DDTHH:MM:SSZ`.
        assert_eq!(file.saved_at.len(), 20, "saved_at = {}", file.saved_at);
        assert!(file.saved_at.ends_with('Z'));
        assert_eq!(&file.saved_at[4..5], "-");
        assert_eq!(&file.saved_at[10..11], "T");
        assert!(file.saved_at.starts_with("20"));
        assert_eq!(file.service_names(), vec!["gsettings".to_string()]);

        let kde_file = StateFile::new(Mechanism::Kde, 1, wrote.clone(), kde);
        assert_eq!(kde_file.service_names(), vec!["kde".to_string()]);
        let kde_with_gs = StateFile::new(
            Mechanism::Kde,
            1,
            wrote,
            Previous::Kde {
                kioslaverc: BTreeMap::new(),
                gsettings: Some(BTreeMap::new()),
            },
        );
        assert_eq!(
            kde_with_gs.service_names(),
            vec!["kde".to_string(), "gsettings".to_string()]
        );

        // The Linux envelopes round-trip through the file too.
        let dir = temp_dir("linux");
        let path = dir.join(STATE_FILE_NAME);
        kde_with_gs.save_atomic(&path).expect("save kde");
        assert_eq!(StateFile::load(&path).expect("load kde"), Some(kde_with_gs));
        file.save_atomic(&path).expect("save gsettings over kde");
        assert_eq!(StateFile::load(&path).expect("load gsettings"), Some(file));
        fs::remove_dir_all(&dir).expect("remove temp dir");
    }

    /// §D7: unreadable or `version != 1` → renamed `<file>.corrupt-<timestamp>`, absent.
    #[test]
    fn corrupt_file_is_renamed_and_treated_absent() {
        let dir = temp_dir("corrupt");
        let path = dir.join(STATE_FILE_NAME);

        fs::write(&path, r#"{"version": 2}"#).expect("write v2");
        assert_eq!(StateFile::load(&path).expect("v2 loads as absent"), None);
        assert!(!path.exists(), "the corrupt file is moved away");
        let after_v2 = corrupt_siblings(&dir);
        assert_eq!(after_v2.len(), 1, "one corrupt sibling: {after_v2:?}");
        assert_eq!(
            fs::read_to_string(dir.join(&after_v2[0])).expect("read quarantined"),
            r#"{"version": 2}"#
        );
        let suffix = after_v2[0]
            .strip_prefix(&format!("{STATE_FILE_NAME}.corrupt-"))
            .expect("prefix");
        assert!(
            suffix
                .split('-')
                .next()
                .is_some_and(|s| s.parse::<u64>().is_ok()),
            "timestamp suffix, got {suffix}"
        );

        fs::write(&path, "not json").expect("write garbage");
        assert_eq!(
            StateFile::load(&path).expect("garbage loads as absent"),
            None
        );
        assert!(!path.exists());
        let after_garbage = corrupt_siblings(&dir);
        assert_eq!(
            after_garbage.len(),
            2,
            "both quarantined, none overwritten: {after_garbage:?}"
        );

        // A good `version: 1` document with a wrong-typed field is corrupt too.
        fs::write(&path, r#"{"version": 1, "pid": "x"}"#).expect("write bad field");
        assert_eq!(
            StateFile::load(&path).expect("bad field loads as absent"),
            None
        );
        assert_eq!(corrupt_siblings(&dir).len(), 3);

        fs::remove_dir_all(&dir).expect("remove temp dir");
    }

    #[test]
    fn remove_reports_presence() {
        let dir = temp_dir("remove");
        let path = dir.join(STATE_FILE_NAME);
        assert!(!StateFile::remove(&path).expect("remove absent"));

        let file: StateFile = serde_json::from_str(SPEC_DOCUMENT).expect("spec document parses");
        file.save_atomic(&path).expect("save");
        assert!(StateFile::remove(&path).expect("remove present"));
        assert!(!path.exists());
        assert!(!StateFile::remove(&path).expect("remove again"));

        fs::remove_dir_all(&dir).expect("remove temp dir");
    }
}
