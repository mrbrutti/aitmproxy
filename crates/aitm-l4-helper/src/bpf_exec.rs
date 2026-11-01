//! The macOS `/dev/bpf*` permission executor (spec §3.1 steps 1–5, T2; AC6,
//! AC13, AC14 helper half).
//!
//! [`apply`] and [`revert`] carry out the steps [`crate::bpf::plan_apply`] and
//! [`crate::bpf::plan_revert`] return, through the [`MacSys`] trait. Every
//! unit test runs against a recording fake; [`RealMacSys`] is the std-only
//! implementation launchd runs as root on a signed install. The helper takes
//! no input: every path and every argv below is fixed, and no message here
//! tells anyone to type a command (plan Rule 2).

use aitm_proto_l4::privilege::contract::{Receipt, BPF_GROUP, RECEIPT_DIR, RECEIPT_SCHEMA};

use crate::bpf::{plan_apply, plan_revert, render, ConsoleUser, NodeFacts, Step};

/// The one directory-service tool the helper runs, by absolute path.
pub const DSEDITGROUP: &str = "/usr/sbin/dseditgroup";

/// The real name (`-r`) the helper gives the group it creates.
const GROUP_REAL_NAME: &str = "Aitmproxy packet capture";

/// The only mode the receipt directory may have (spec §3.1 step 5).
const RECEIPT_DIR_MODE: u32 = 0o755;

/// What `stat` says about [`RECEIPT_DIR`] without following a symlink.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirMeta {
    pub is_dir: bool,
    pub is_symlink: bool,
    pub uid: u32,
    pub gid: u32,
    /// Permission bits (`st_mode & 0o7777`).
    pub mode: u32,
}

/// Everything the executor asks of the machine. Each method does exactly one
/// thing so a test can record and script it; `Err` carries a one-sentence
/// reason that names no command for anyone to run.
pub trait MacSys {
    /// `stat` every existing `/dev/bpfN`, N in 0–255, without following symlinks.
    fn list_nodes(&self) -> Result<Vec<NodeFacts>, String>;
    /// Open `/dev/bpf0`..`/dev/bpf255` read-only and drop each handle until
    /// 256 nodes exist (spec §3.1 step 1).
    fn precreate_nodes(&self) -> Result<(), String>;
    /// `chown uid:gid /dev/bpf{n}`.
    fn chown(&self, n: u32, uid: u32, gid: u32) -> Result<(), String>;
    /// `chmod mode /dev/bpf{n}`.
    fn chmod(&self, n: u32, mode: u32) -> Result<(), String>;
    /// The gid of [`BPF_GROUP`], or `None` when the group does not exist.
    fn group_gid(&self) -> Result<Option<u32>, String>;
    /// Run [`DSEDITGROUP`] with exactly `argv` after the program name; exit 0
    /// is `Ok`.
    fn run_dseditgroup(&self, argv: &[&str]) -> Result<(), String>;
    /// The user logged in at the console and whether they are an admin;
    /// `None` at the login window.
    fn console_user(&self) -> Result<Option<ConsoleUser>, String>;
    /// The bytes of the receipt file, or `None` when there is none.
    fn read_receipt(&self) -> Result<Option<Vec<u8>>, String>;
    /// Write the receipt so a reader sees either the old or the new one.
    fn write_receipt_atomic(&self, bytes: &[u8]) -> Result<(), String>;
    /// Remove the receipt file; a missing file is `Ok`.
    fn delete_receipt(&self) -> Result<(), String>;
    /// `lstat` of [`RECEIPT_DIR`], or `None` when it does not exist.
    fn receipt_dir_meta(&self) -> Result<Option<DirMeta>, String>;
    /// Create [`RECEIPT_DIR`] as `root:wheel` 0755.
    fn create_receipt_dir(&self) -> Result<(), String>;
}

/// Judge the receipt directory as found: only a real directory owned by
/// `root:wheel` with mode 0755 is accepted (spec §3.1 step 5, T2).
fn check_receipt_dir(meta: &DirMeta) -> Result<(), String> {
    if meta.is_symlink {
        return Err(format!("{RECEIPT_DIR} is a symlink; nothing was changed"));
    }
    if !meta.is_dir {
        return Err(format!(
            "{RECEIPT_DIR} is not a directory; nothing was changed"
        ));
    }
    if meta.uid != 0 || meta.gid != 0 {
        return Err(format!(
            "{RECEIPT_DIR} is owned by uid {} gid {} (expected root:wheel); nothing was changed",
            meta.uid, meta.gid
        ));
    }
    if meta.mode & 0o777 != RECEIPT_DIR_MODE {
        return Err(format!(
            "{RECEIPT_DIR} has mode {:04o} (expected {RECEIPT_DIR_MODE:04o}); nothing was changed",
            meta.mode & 0o7777
        ));
    }
    Ok(())
}

/// Make sure the receipt directory is ours: absent → create it; present →
/// accept only what [`check_receipt_dir`] accepts. Runs before anything else
/// in [`apply`], so a refused directory means no node, group or receipt was
/// touched.
fn ensure_receipt_dir(sys: &dyn MacSys) -> Result<(), String> {
    match sys.receipt_dir_meta()? {
        None => sys.create_receipt_dir(),
        Some(meta) => check_receipt_dir(&meta),
    }
}

/// The prior receipt, if any. A receipt that exists but does not parse (or is
/// another schema) is an error: the run must not guess what it added before.
fn read_prior(sys: &dyn MacSys) -> Result<Option<Receipt>, String> {
    match sys.read_receipt()? {
        None => Ok(None),
        Some(bytes) => Receipt::parse(&bytes)
            .map(Some)
            .map_err(|err| format!("existing receipt not readable: {err}")),
    }
}

/// `bpf-permissions` (spec §3.1 steps 1–5). Returns the receipt it wrote.
///
/// Order: receipt directory check, prior receipt, node pre-creation, facts,
/// plan, steps in plan order, receipt. A failing chown, chmod or directory
/// service call stops the run with `Err`; what was already changed stays and
/// the next launch re-applies it.
pub fn apply(sys: &dyn MacSys, version: &str, now_ms: u64) -> Result<Receipt, String> {
    ensure_receipt_dir(sys)?;
    let prior = read_prior(sys)?;
    sys.precreate_nodes()?;
    let nodes = sys.list_nodes()?;
    let mut resolved_gid = sys.group_gid()?;
    let console = sys.console_user()?;
    let steps = plan_apply(&nodes, resolved_gid, prior.as_ref(), console.as_ref());

    let mut nodes_set: u32 = 0;
    let mut errors: Vec<String> = Vec::new();
    let mut members_added: Vec<String> = prior
        .as_ref()
        .map(|receipt| receipt.members_added.clone())
        .unwrap_or_default();
    let mut receipt = None;

    for step in steps {
        match step {
            Step::CreateGroup => {
                sys.run_dseditgroup(&["-o", "create", "-r", GROUP_REAL_NAME, BPF_GROUP])?;
                resolved_gid = sys.group_gid()?;
                if resolved_gid.is_none() {
                    return Err(format!(
                        "group {BPF_GROUP} was created but has no gid; no node was changed"
                    ));
                }
            }
            Step::Chown { n, gid } => {
                let gid = gid.or(resolved_gid).ok_or_else(|| {
                    format!("group {BPF_GROUP} does not exist; /dev/bpf{n} was not changed")
                })?;
                sys.chown(n, 0, gid)?;
                nodes_set = nodes_set.saturating_add(1);
            }
            Step::Chmod { n, mode } => sys.chmod(n, mode)?,
            Step::Refuse { n, why } => errors.push(format!("/dev/bpf{n}: {why}")),
            Step::AddMember(user) => {
                sys.run_dseditgroup(&["-o", "edit", "-a", &user, "-t", "user", BPF_GROUP])?;
                members_added.push(user);
            }
            Step::RemoveMember(user) => {
                return Err(format!("the apply plan asked to remove {user}; refusing"));
            }
            Step::DeleteReceipt => {
                return Err("the apply plan asked to delete the receipt; refusing".to_string());
            }
            Step::WriteReceipt => {
                let gid = resolved_gid
                    .ok_or_else(|| format!("group {BPF_GROUP} has no gid; no receipt written"))?;
                let built = Receipt {
                    schema: RECEIPT_SCHEMA,
                    helper_version: version.to_string(),
                    applied_at: now_ms,
                    group: BPF_GROUP.to_string(),
                    gid,
                    nodes: nodes_set,
                    members_added: std::mem::take(&mut members_added),
                    errors: std::mem::take(&mut errors),
                };
                sys.write_receipt_atomic(&built.to_json())?;
                receipt = Some(built);
            }
        }
    }
    receipt.ok_or_else(|| "the apply plan ended without writing a receipt".to_string())
}

/// `bpf-revert` (spec §3.1, last paragraph). Every valid node goes back to
/// `root:wheel` 0600, exactly the users the receipt says this helper added
/// are removed from the group, and the receipt is deleted. With no receipt
/// the nodes still go back and nobody is removed.
pub fn revert(sys: &dyn MacSys) -> Result<(), String> {
    // The same directory rule as `apply`: never read or delete through a
    // symlink or a directory someone else owns (T2). Absent means no receipt.
    let prior = match sys.receipt_dir_meta()? {
        None => None,
        Some(meta) => {
            check_receipt_dir(&meta)?;
            read_prior(sys)?
        }
    };
    let nodes = sys.list_nodes()?;
    let steps = plan_revert(&nodes, prior.as_ref());
    for step in steps {
        match step {
            Step::Chown { n, gid } => {
                let gid = gid.ok_or_else(|| {
                    format!("the revert plan gave no gid for /dev/bpf{n}; refusing")
                })?;
                sys.chown(n, 0, gid)?;
            }
            Step::Chmod { n, mode } => sys.chmod(n, mode)?,
            Step::Refuse { .. } => {}
            Step::RemoveMember(user) => {
                sys.run_dseditgroup(&["-o", "edit", "-d", &user, "-t", "user", BPF_GROUP])?;
            }
            Step::DeleteReceipt => sys.delete_receipt()?,
            Step::CreateGroup | Step::AddMember(_) | Step::WriteReceipt => {
                return Err("the revert plan asked to add or create; refusing".to_string());
            }
        }
    }
    Ok(())
}

/// How many `/dev/bpfN` nodes exist on a machine after step 1 (`BPF_MAX_DEVICES`).
const NODE_TOTAL: usize = 256;

/// The prior receipt for a `--dry-run`, read-only. Where the real run would
/// create the directory, stop on it or fail to read it, the dry run pushes one
/// line saying so and plans as if there were no receipt. `missing` finishes
/// the line for an absent directory (what the real run would do about it).
fn dry_prior(sys: &dyn MacSys, lines: &mut Vec<String>, missing: &str) -> Option<Receipt> {
    match sys.receipt_dir_meta() {
        Err(err) => {
            lines.push(format!("receipt directory not readable: {err}"));
            None
        }
        Ok(None) => {
            lines.push(format!(
                "receipt directory {RECEIPT_DIR} is missing; {missing}"
            ));
            None
        }
        Ok(Some(meta)) => {
            if let Err(why) = check_receipt_dir(&meta) {
                lines.push(format!("the run would stop: {why}"));
                return None;
            }
            match read_prior(sys) {
                Ok(prior) => prior,
                Err(err) => {
                    lines.push(format!("the run would stop: {err}"));
                    None
                }
            }
        }
    }
}

/// `bpf-permissions --dry-run` (spec §3.1, last paragraph): the lines the run
/// would print, read-only, for any user. Gathers the facts [`apply`] gathers
/// (receipt directory, prior receipt, nodes, group, console user) but never
/// pre-creates a node, creates the directory, changes an owner, a mode or the
/// directory service, or writes. Facts an unprivileged user cannot read are
/// reported as a line and planned around conservatively; only the node list
/// is required.
pub fn dry_run_apply(sys: &dyn MacSys) -> Result<Vec<String>, String> {
    let mut lines = Vec::new();
    let prior = dry_prior(sys, &mut lines, "bpf-permissions would create it");
    let nodes = sys.list_nodes()?;
    if nodes.len() < NODE_TOTAL {
        lines.push(format!(
            "{} of {NODE_TOTAL} nodes exist; bpf-permissions would create the rest first",
            nodes.len()
        ));
    }
    let group_gid = match sys.group_gid() {
        Ok(gid) => gid,
        Err(err) => {
            lines.push(format!(
                "group {BPF_GROUP} could not be looked up ({err}); planning as if it were absent"
            ));
            None
        }
    };
    let console = match sys.console_user() {
        Ok(console) => console,
        Err(err) => {
            lines.push(format!(
                "console user could not be determined ({err}); planning as if nobody were logged in"
            ));
            None
        }
    };
    lines.extend(render(&plan_apply(
        &nodes,
        group_gid,
        prior.as_ref(),
        console.as_ref(),
    )));
    Ok(lines)
}

/// `bpf-revert --dry-run`: the lines the run would print, read-only, for any
/// user. Same facts as [`revert`], no change to anything.
pub fn dry_run_revert(sys: &dyn MacSys) -> Result<Vec<String>, String> {
    let mut lines = Vec::new();
    let prior = dry_prior(sys, &mut lines, "there is no receipt to read");
    let nodes = sys.list_nodes()?;
    lines.extend(render(&plan_revert(&nodes, prior.as_ref())));
    Ok(lines)
}

/// The gid in a `dscl . -read /Groups/<name> PrimaryGroupID` reply, which is
/// one line of the form `PrimaryGroupID: 701`.
fn parse_primary_group_id(stdout: &str) -> Option<u32> {
    stdout
        .lines()
        .find_map(|line| line.strip_prefix("PrimaryGroupID:"))
        .and_then(|rest| rest.trim().parse::<u32>().ok())
}

/// The implementation launchd runs as root (spec §3.1). std only; every path
/// and argv is fixed.
#[cfg(target_os = "macos")]
pub struct RealMacSys;

#[cfg(target_os = "macos")]
mod real {
    use super::{parse_primary_group_id, DirMeta, MacSys, RealMacSys, DSEDITGROUP};
    use crate::bpf::{ConsoleUser, NodeFacts};
    use aitm_proto_l4::privilege::contract::{BPF_GROUP, RECEIPT_DIR, RECEIPT_PATH};
    use std::fs;
    use std::io;
    use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
    use std::path::{Path, PathBuf};
    use std::process::{Command, Output, Stdio};

    /// `/dev/bpf0`..`/dev/bpf255` (`BPF_MAX_DEVICES`).
    const NODE_COUNT: u32 = 256;
    /// The directory-service reader used to look the group up.
    const DSCL: &str = "/usr/bin/dscl";
    /// Resolves a uid to an account name (`id -un <uid>`).
    const ID_BIN: &str = "/usr/bin/id";
    /// What `dscl` prints when the record does not exist.
    const DSCL_NOT_FOUND: &str = "eDSRecordNotFound";
    /// Mode of the receipt file (spec §3.1 step 5).
    const RECEIPT_MODE: u32 = 0o644;
    /// Where the receipt is staged before the rename.
    const RECEIPT_TMP: &str = "/Library/Application Support/Aitmproxy/.l4-helper.json.tmp";

    fn node_path(n: u32) -> PathBuf {
        PathBuf::from(format!("/dev/bpf{n}"))
    }

    fn describe(what: &str, path: &Path, err: &io::Error) -> String {
        format!("{what} {}: {err}", path.display())
    }

    /// Run a fixed program with a fixed argv, no shell, stdin from `/dev/null`.
    fn run(program: &str, argv: &[&str]) -> Result<Output, String> {
        Command::new(program)
            .args(argv)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .map_err(|err| format!("could not run {program}: {err}"))
    }

    impl MacSys for RealMacSys {
        fn list_nodes(&self) -> Result<Vec<NodeFacts>, String> {
            let mut nodes = Vec::with_capacity(NODE_COUNT as usize);
            for n in 0..NODE_COUNT {
                let path = node_path(n);
                let meta = match fs::symlink_metadata(&path) {
                    Ok(meta) => meta,
                    Err(err) if err.kind() == io::ErrorKind::NotFound => continue,
                    Err(err) => return Err(describe("stat", &path, &err)),
                };
                nodes.push(NodeFacts {
                    n,
                    is_char: meta.file_type().is_char_device(),
                    rdev: meta.rdev(),
                    uid: meta.uid(),
                    gid: meta.gid(),
                    mode: meta.mode() & 0o7777,
                });
            }
            Ok(nodes)
        }

        fn precreate_nodes(&self) -> Result<(), String> {
            // XNU clones `/dev/bpf{N+1}` when `/dev/bpfN` is opened. Opening
            // each existing node in turn, read-only, walks the chain out to
            // 255. A node that is busy (open elsewhere) still exists, so the
            // walk continues; a missing node ends the walk and the planner
            // reports what exists.
            let last = node_path(NODE_COUNT - 1);
            for n in 0..NODE_COUNT {
                if fs::symlink_metadata(&last).is_ok() {
                    return Ok(());
                }
                match fs::File::open(node_path(n)) {
                    Ok(handle) => drop(handle),
                    Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(()),
                    Err(_) => continue,
                }
            }
            Ok(())
        }

        fn chown(&self, n: u32, uid: u32, gid: u32) -> Result<(), String> {
            let path = node_path(n);
            // `lchown`: never follow a symlink planted at a node's path.
            std::os::unix::fs::lchown(&path, Some(uid), Some(gid))
                .map_err(|err| describe("chown", &path, &err))
        }

        fn chmod(&self, n: u32, mode: u32) -> Result<(), String> {
            let path = node_path(n);
            fs::set_permissions(&path, fs::Permissions::from_mode(mode))
                .map_err(|err| describe("chmod", &path, &err))
        }

        fn group_gid(&self) -> Result<Option<u32>, String> {
            let record = format!("/Groups/{BPF_GROUP}");
            let out = run(DSCL, &[".", "-read", &record, "PrimaryGroupID"])?;
            let stdout = String::from_utf8_lossy(&out.stdout);
            let stderr = String::from_utf8_lossy(&out.stderr);
            if out.status.success() {
                return parse_primary_group_id(&stdout).map(Some).ok_or_else(|| {
                    format!("group {BPF_GROUP} exists but its PrimaryGroupID could not be read")
                });
            }
            if stdout.contains(DSCL_NOT_FOUND) || stderr.contains(DSCL_NOT_FOUND) {
                return Ok(None);
            }
            Err(format!(
                "could not look up group {BPF_GROUP}: {}",
                stderr.trim()
            ))
        }

        fn run_dseditgroup(&self, argv: &[&str]) -> Result<(), String> {
            let out = run(DSEDITGROUP, argv)?;
            if out.status.success() {
                Ok(())
            } else {
                Err(format!(
                    "directory service change failed ({}): {}",
                    out.status,
                    String::from_utf8_lossy(&out.stderr).trim()
                ))
            }
        }

        fn console_user(&self) -> Result<Option<ConsoleUser>, String> {
            let console = Path::new("/dev/console");
            let uid = fs::metadata(console)
                .map_err(|err| describe("stat", console, &err))?
                .uid();
            if uid == 0 {
                // The login window owns the console: nobody is logged in.
                return Ok(None);
            }
            let uid_text = uid.to_string();
            let out = run(ID_BIN, &["-un", &uid_text])?;
            if !out.status.success() {
                return Err(format!("could not resolve console uid {uid} to a name"));
            }
            let name = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if name.is_empty() {
                return Err(format!("console uid {uid} resolved to an empty name"));
            }
            // Exit 0 means member; anything else (not a member, or an error)
            // adds nobody, the conservative outcome.
            let is_admin = run(DSEDITGROUP, &["-o", "checkmember", "-m", &name, "admin"])?
                .status
                .success();
            Ok(Some(ConsoleUser { name, is_admin }))
        }

        fn read_receipt(&self) -> Result<Option<Vec<u8>>, String> {
            match fs::read(RECEIPT_PATH) {
                Ok(bytes) => Ok(Some(bytes)),
                Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(None),
                Err(err) => Err(describe("read", Path::new(RECEIPT_PATH), &err)),
            }
        }

        fn write_receipt_atomic(&self, bytes: &[u8]) -> Result<(), String> {
            use std::io::Write as _;
            let tmp = Path::new(RECEIPT_TMP);
            // A stale staging file (or anything planted at its path) is
            // removed, then the file is created fresh so no symlink is
            // followed.
            match fs::remove_file(tmp) {
                Ok(()) => {}
                Err(err) if err.kind() == io::ErrorKind::NotFound => {}
                Err(err) => return Err(describe("remove", tmp, &err)),
            }
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(RECEIPT_MODE)
                .open(tmp)
                .map_err(|err| describe("create", tmp, &err))?;
            file.write_all(bytes)
                .and_then(|()| file.sync_all())
                .map_err(|err| describe("write", tmp, &err))?;
            drop(file);
            // umask may have narrowed the mode, and BSD gives a new file the
            // parent directory's group: pin both to what the spec says.
            fs::set_permissions(tmp, fs::Permissions::from_mode(RECEIPT_MODE))
                .map_err(|err| describe("chmod", tmp, &err))?;
            std::os::unix::fs::lchown(tmp, Some(0), Some(0))
                .map_err(|err| describe("chown", tmp, &err))?;
            fs::rename(tmp, RECEIPT_PATH)
                .map_err(|err| describe("rename", Path::new(RECEIPT_PATH), &err))
        }

        fn delete_receipt(&self) -> Result<(), String> {
            match fs::remove_file(RECEIPT_PATH) {
                Ok(()) => Ok(()),
                Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
                Err(err) => Err(describe("remove", Path::new(RECEIPT_PATH), &err)),
            }
        }

        fn receipt_dir_meta(&self) -> Result<Option<DirMeta>, String> {
            match fs::symlink_metadata(RECEIPT_DIR) {
                Ok(meta) => Ok(Some(DirMeta {
                    is_dir: meta.file_type().is_dir(),
                    is_symlink: meta.file_type().is_symlink(),
                    uid: meta.uid(),
                    gid: meta.gid(),
                    mode: meta.mode() & 0o7777,
                })),
                Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(None),
                Err(err) => Err(describe("stat", Path::new(RECEIPT_DIR), &err)),
            }
        }

        fn create_receipt_dir(&self) -> Result<(), String> {
            let dir = Path::new(RECEIPT_DIR);
            fs::create_dir(dir).map_err(|err| describe("create", dir, &err))?;
            // The parent is `root:admin`, and BSD gives a new directory its
            // parent's group, so the group is set explicitly to `wheel`.
            std::os::unix::fs::lchown(dir, Some(0), Some(0))
                .map_err(|err| describe("chown", dir, &err))?;
            fs::set_permissions(dir, fs::Permissions::from_mode(super::RECEIPT_DIR_MODE))
                .map_err(|err| describe("chmod", dir, &err))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bpf::{ConsoleUser, NodeFacts};
    use aitm_proto_l4::privilege::contract::{Receipt, BPF_GROUP, RECEIPT_SCHEMA};
    use std::cell::RefCell;

    /// The major number macOS gives the bpf clone devices on a typical install.
    const BPF_MAJOR: u64 = 23;

    /// Every call the executor made on the fake, in order, with its arguments.
    #[derive(Debug, Clone, PartialEq, Eq)]
    enum Call {
        ListNodes,
        PrecreateNodes,
        Chown { n: u32, uid: u32, gid: u32 },
        Chmod { n: u32, mode: u32 },
        GroupGid,
        Dseditgroup(Vec<String>),
        ConsoleUser,
        ReadReceipt,
        WriteReceipt(Vec<u8>),
        DeleteReceipt,
        ReceiptDirMeta,
        CreateReceiptDir,
    }

    /// A scripted, recording `MacSys`. Nothing here touches the machine.
    struct Fake {
        calls: RefCell<Vec<Call>>,
        dir: Option<DirMeta>,
        /// When set, `receipt_dir_meta` fails with this message instead.
        dir_error: Option<String>,
        nodes: Vec<NodeFacts>,
        /// The gid `group_gid` answers right now.
        gid: RefCell<Option<u32>>,
        /// What `group_gid` answers after a `-o create` ran.
        gid_after_create: Option<u32>,
        console: Option<ConsoleUser>,
        receipt: RefCell<Option<Vec<u8>>>,
        /// Tester: when set, `chown` of this node is recorded, then fails.
        fail_chown_at: Option<u32>,
        /// Tester: when set, a `dseditgroup` whose argv holds this operation
        /// word (`create` or `edit`) is recorded, then fails.
        fail_dseditgroup_op: Option<&'static str>,
        /// Tester: when set, `group_gid` fails with this text.
        group_gid_error: Option<String>,
        /// Tester: when set, `console_user` fails with this text.
        console_error: Option<String>,
    }

    impl Fake {
        fn new(nodes: Vec<NodeFacts>, gid: Option<u32>, console: Option<ConsoleUser>) -> Fake {
            Fake {
                calls: RefCell::new(Vec::new()),
                dir: Some(good_dir()),
                dir_error: None,
                nodes,
                gid: RefCell::new(gid),
                gid_after_create: gid,
                console,
                receipt: RefCell::new(None),
                fail_chown_at: None,
                fail_dseditgroup_op: None,
                group_gid_error: None,
                console_error: None,
            }
        }

        fn record(&self, call: Call) {
            self.calls.borrow_mut().push(call);
        }

        fn calls(&self) -> Vec<Call> {
            self.calls.borrow().clone()
        }

        fn written_receipt(&self) -> Receipt {
            let bytes = self.calls().into_iter().find_map(|c| match c {
                Call::WriteReceipt(bytes) => Some(bytes),
                _ => None,
            });
            let bytes = match bytes {
                Some(bytes) => bytes,
                None => panic!("no receipt was written: {:?}", self.calls()),
            };
            match Receipt::parse(&bytes) {
                Ok(receipt) => receipt,
                Err(err) => panic!("the written receipt must parse: {err}"),
            }
        }
    }

    impl MacSys for Fake {
        fn list_nodes(&self) -> Result<Vec<NodeFacts>, String> {
            self.record(Call::ListNodes);
            Ok(self.nodes.clone())
        }
        fn precreate_nodes(&self) -> Result<(), String> {
            self.record(Call::PrecreateNodes);
            Ok(())
        }
        fn chown(&self, n: u32, uid: u32, gid: u32) -> Result<(), String> {
            self.record(Call::Chown { n, uid, gid });
            if self.fail_chown_at == Some(n) {
                return Err(format!("the fake refused node {n}"));
            }
            Ok(())
        }
        fn chmod(&self, n: u32, mode: u32) -> Result<(), String> {
            self.record(Call::Chmod { n, mode });
            Ok(())
        }
        fn group_gid(&self) -> Result<Option<u32>, String> {
            self.record(Call::GroupGid);
            if let Some(err) = &self.group_gid_error {
                return Err(err.clone());
            }
            Ok(*self.gid.borrow())
        }
        fn run_dseditgroup(&self, argv: &[&str]) -> Result<(), String> {
            let mut full = vec![DSEDITGROUP.to_string()];
            full.extend(argv.iter().map(|a| (*a).to_string()));
            self.record(Call::Dseditgroup(full));
            if let Some(op) = self.fail_dseditgroup_op {
                if argv.contains(&op) {
                    return Err("the fake refused the directory service change".to_string());
                }
            }
            if argv.get(1) == Some(&"create") {
                *self.gid.borrow_mut() = self.gid_after_create;
            }
            Ok(())
        }
        fn console_user(&self) -> Result<Option<ConsoleUser>, String> {
            self.record(Call::ConsoleUser);
            if let Some(err) = &self.console_error {
                return Err(err.clone());
            }
            Ok(self.console.clone())
        }
        fn read_receipt(&self) -> Result<Option<Vec<u8>>, String> {
            self.record(Call::ReadReceipt);
            Ok(self.receipt.borrow().clone())
        }
        fn write_receipt_atomic(&self, bytes: &[u8]) -> Result<(), String> {
            self.record(Call::WriteReceipt(bytes.to_vec()));
            *self.receipt.borrow_mut() = Some(bytes.to_vec());
            Ok(())
        }
        fn delete_receipt(&self) -> Result<(), String> {
            self.record(Call::DeleteReceipt);
            *self.receipt.borrow_mut() = None;
            Ok(())
        }
        fn receipt_dir_meta(&self) -> Result<Option<DirMeta>, String> {
            self.record(Call::ReceiptDirMeta);
            match &self.dir_error {
                Some(err) => Err(err.clone()),
                None => Ok(self.dir.clone()),
            }
        }
        fn create_receipt_dir(&self) -> Result<(), String> {
            self.record(Call::CreateReceiptDir);
            Ok(())
        }
    }

    fn good_dir() -> DirMeta {
        DirMeta {
            is_dir: true,
            is_symlink: false,
            uid: 0,
            gid: 0,
            mode: 0o755,
        }
    }

    fn node(n: u32, major: u64) -> NodeFacts {
        NodeFacts {
            n,
            is_char: true,
            rdev: (major << 24) | u64::from(n),
            uid: 0,
            gid: 0,
            mode: 0o600,
        }
    }

    fn all_nodes() -> Vec<NodeFacts> {
        (0..256).map(|n| node(n, BPF_MAJOR)).collect()
    }

    fn admin(name: &str) -> ConsoleUser {
        ConsoleUser {
            name: name.to_string(),
            is_admin: true,
        }
    }

    fn receipt(members_added: &[&str]) -> Receipt {
        Receipt {
            schema: RECEIPT_SCHEMA,
            helper_version: "0.5.8".to_string(),
            applied_at: 1_761_000_000_000,
            group: BPF_GROUP.to_string(),
            gid: 701,
            nodes: 256,
            members_added: members_added.iter().map(|m| (*m).to_string()).collect(),
            errors: Vec::new(),
        }
    }

    fn touches_the_machine(call: &Call) -> bool {
        matches!(
            call,
            Call::PrecreateNodes
                | Call::Chown { .. }
                | Call::Chmod { .. }
                | Call::Dseditgroup(_)
                | Call::WriteReceipt(_)
                | Call::DeleteReceipt
                | Call::CreateReceiptDir
        )
    }

    fn dseditgroup_calls(calls: &[Call]) -> Vec<Vec<String>> {
        calls
            .iter()
            .filter_map(|c| match c {
                Call::Dseditgroup(argv) => Some(argv.clone()),
                _ => None,
            })
            .collect()
    }

    fn argv(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|p| (*p).to_string()).collect()
    }

    #[test]
    fn symlinked_receipt_dir_writes_nothing() {
        let mut sys = Fake::new(all_nodes(), Some(701), Some(admin("matt")));
        sys.dir = Some(DirMeta {
            is_dir: false,
            is_symlink: true,
            uid: 0,
            gid: 0,
            mode: 0o755,
        });
        let result = apply(&sys, "0.5.9", 1_762_000_000_000);
        let err = match result {
            Err(err) => err,
            Ok(receipt) => panic!("a symlinked receipt dir must be refused, got {receipt:?}"),
        };
        assert!(err.contains("symlink"), "the error names the cause: {err}");
        let calls = sys.calls();
        assert_eq!(calls, vec![Call::ReceiptDirMeta]);
        assert!(
            !calls.iter().any(touches_the_machine),
            "nothing may be touched: {calls:?}"
        );
    }

    #[test]
    fn foreign_owned_receipt_dir_writes_nothing() {
        let mut sys = Fake::new(all_nodes(), Some(701), Some(admin("matt")));
        sys.dir = Some(DirMeta {
            uid: 501,
            ..good_dir()
        });
        let err = match apply(&sys, "0.5.9", 1_762_000_000_000) {
            Err(err) => err,
            Ok(receipt) => panic!("a foreign-owned receipt dir must be refused, got {receipt:?}"),
        };
        assert!(
            err.contains("501"),
            "the error names the owner found: {err}"
        );
        assert_eq!(sys.calls(), vec![Call::ReceiptDirMeta]);

        // Wrong group, wrong mode and not-a-directory are refused the same way.
        for (label, dir) in [
            (
                "gid 80",
                DirMeta {
                    gid: 80,
                    ..good_dir()
                },
            ),
            (
                "mode 0775",
                DirMeta {
                    mode: 0o775,
                    ..good_dir()
                },
            ),
            (
                "mode 0777",
                DirMeta {
                    mode: 0o777,
                    ..good_dir()
                },
            ),
            (
                "a plain file",
                DirMeta {
                    is_dir: false,
                    ..good_dir()
                },
            ),
        ] {
            let mut sys = Fake::new(all_nodes(), Some(701), Some(admin("matt")));
            sys.dir = Some(dir);
            assert!(
                apply(&sys, "0.5.9", 1_762_000_000_000).is_err(),
                "{label} must be refused"
            );
            assert_eq!(sys.calls(), vec![Call::ReceiptDirMeta], "{label}");
        }
    }

    #[test]
    fn missing_receipt_dir_is_created_before_anything_else() {
        let mut sys = Fake::new(all_nodes(), Some(701), None);
        sys.dir = None;
        let receipt = match apply(&sys, "0.5.9", 1_762_000_000_000) {
            Ok(receipt) => receipt,
            Err(err) => panic!("apply must succeed: {err}"),
        };
        let calls = sys.calls();
        assert_eq!(calls[0], Call::ReceiptDirMeta);
        assert_eq!(calls[1], Call::CreateReceiptDir);
        assert_eq!(receipt.members_added, Vec::<String>::new());
        assert_eq!(receipt.nodes, 256);
    }

    #[test]
    fn dseditgroup_argv_exact() {
        let sys = Fake::new(all_nodes(), None, Some(admin("matt")));
        let mut sys = sys;
        sys.gid_after_create = Some(702);
        if let Err(err) = apply(&sys, "0.5.9", 1_762_000_000_000) {
            panic!("apply must succeed: {err}");
        }
        assert_eq!(
            dseditgroup_calls(&sys.calls()),
            vec![
                argv(&[
                    "/usr/sbin/dseditgroup",
                    "-o",
                    "create",
                    "-r",
                    "Aitmproxy packet capture",
                    "access_bpf",
                ]),
                argv(&[
                    "/usr/sbin/dseditgroup",
                    "-o",
                    "edit",
                    "-a",
                    "matt",
                    "-t",
                    "user",
                    "access_bpf",
                ]),
            ]
        );
        assert_eq!(DSEDITGROUP, "/usr/sbin/dseditgroup");
    }

    #[test]
    fn receipt_fields() {
        let sys = Fake::new(all_nodes(), Some(701), Some(admin("matt")));
        let returned = match apply(&sys, "0.5.9", 1_762_000_000_000) {
            Ok(receipt) => receipt,
            Err(err) => panic!("apply must succeed: {err}"),
        };
        let written = sys.written_receipt();
        assert_eq!(returned, written);
        assert_eq!(written.schema, 1);
        assert_eq!(written.helper_version, "0.5.9");
        assert_eq!(written.applied_at, 1_762_000_000_000);
        assert_eq!(written.group, "access_bpf");
        assert_eq!(written.gid, 701);
        assert_eq!(written.nodes, 256);
        assert_eq!(written.members_added, vec!["matt".to_string()]);
        assert_eq!(written.errors, Vec::<String>::new());

        let calls = sys.calls();
        for n in 0..256 {
            assert!(
                calls.contains(&Call::Chown {
                    n,
                    uid: 0,
                    gid: 701
                }),
                "/dev/bpf{n} must be chowned root:701"
            );
            assert!(
                calls.contains(&Call::Chmod { n, mode: 0o660 }),
                "/dev/bpf{n} must be chmodded 0660"
            );
        }
        // No group creation when the group already exists.
        assert_eq!(dseditgroup_calls(&calls).len(), 1);
        // Nodes are pre-created before they are listed, and the receipt is
        // written last.
        let precreate = calls.iter().position(|c| *c == Call::PrecreateNodes);
        let list = calls.iter().position(|c| *c == Call::ListNodes);
        assert!(precreate < list, "precreate before list: {calls:?}");
        assert!(
            matches!(calls.last(), Some(Call::WriteReceipt(_))),
            "the receipt is written last: {:?}",
            calls.last()
        );
    }

    #[test]
    fn second_apply_carries_members_forward() {
        let sys = Fake::new(all_nodes(), Some(701), Some(admin("matt")));
        *sys.receipt.borrow_mut() = Some(receipt(&["matt"]).to_json());
        if let Err(err) = apply(&sys, "0.5.9", 1_762_000_000_000) {
            panic!("apply must succeed: {err}");
        }
        assert_eq!(
            dseditgroup_calls(&sys.calls()),
            Vec::<Vec<String>>::new(),
            "a second run adds nobody"
        );
        let written = sys.written_receipt();
        assert_eq!(written.members_added, vec!["matt".to_string()]);
        assert_eq!(written.helper_version, "0.5.9");
        assert_eq!(written.applied_at, 1_762_000_000_000);
    }

    #[test]
    fn malformed_prior_receipt_is_an_error() {
        let sys = Fake::new(all_nodes(), Some(701), Some(admin("matt")));
        *sys.receipt.borrow_mut() = Some(b"{".to_vec());
        assert!(apply(&sys, "0.5.9", 1_762_000_000_000).is_err());
        assert!(
            !sys.calls().iter().any(touches_the_machine),
            "a malformed receipt stops the run before any change: {:?}",
            sys.calls()
        );

        let sys = Fake::new(all_nodes(), Some(701), Some(admin("matt")));
        *sys.receipt.borrow_mut() = Some(br#"{"schema":2}"#.to_vec());
        let err = match apply(&sys, "0.5.9", 1_762_000_000_000) {
            Err(err) => err,
            Ok(receipt) => panic!("a schema-2 receipt must be refused, got {receipt:?}"),
        };
        assert!(err.contains("schema 2"), "{err}");
    }

    #[test]
    fn chown_after_create_group_uses_the_resolved_gid() {
        let mut sys = Fake::new(all_nodes(), None, Some(admin("matt")));
        sys.gid_after_create = Some(702);
        let receipt = match apply(&sys, "0.5.9", 1_762_000_000_000) {
            Ok(receipt) => receipt,
            Err(err) => panic!("apply must succeed: {err}"),
        };
        let chowns: Vec<(u32, u32, u32)> = sys
            .calls()
            .into_iter()
            .filter_map(|c| match c {
                Call::Chown { n, uid, gid } => Some((n, uid, gid)),
                _ => None,
            })
            .collect();
        assert_eq!(chowns.len(), 256);
        assert!(
            chowns.iter().all(|(_, uid, gid)| *uid == 0 && *gid == 702),
            "every chown uses the gid resolved after create: {chowns:?}"
        );
        assert_eq!(receipt.gid, 702);
        // The create ran before the first chown.
        let calls = sys.calls();
        let create = calls.iter().position(
            |c| matches!(c, Call::Dseditgroup(a) if a.get(2).map(String::as_str) == Some("create")),
        );
        let first_chown = calls.iter().position(|c| matches!(c, Call::Chown { .. }));
        assert!(create < first_chown, "{calls:?}");
    }

    #[test]
    fn create_group_that_leaves_no_gid_is_an_error() {
        let mut sys = Fake::new(all_nodes(), None, Some(admin("matt")));
        sys.gid_after_create = None;
        assert!(apply(&sys, "0.5.9", 1_762_000_000_000).is_err());
        let calls = sys.calls();
        assert!(
            !calls
                .iter()
                .any(|c| matches!(c, Call::Chown { .. } | Call::Chmod { .. })),
            "no node is touched without a gid: {calls:?}"
        );
        assert!(
            !calls.iter().any(|c| matches!(c, Call::WriteReceipt(_))),
            "no receipt is written: {calls:?}"
        );
    }

    #[test]
    fn revert_removes_only_members_added_and_deletes_the_receipt() {
        let sys = Fake::new(all_nodes(), Some(701), Some(admin("matt")));
        *sys.receipt.borrow_mut() = Some(receipt(&["matt"]).to_json());
        if let Err(err) = revert(&sys) {
            panic!("revert must succeed: {err}");
        }
        let calls = sys.calls();
        assert_eq!(
            dseditgroup_calls(&calls),
            vec![argv(&[
                "/usr/sbin/dseditgroup",
                "-o",
                "edit",
                "-d",
                "matt",
                "-t",
                "user",
                "access_bpf",
            ])]
        );
        for n in 0..256 {
            assert!(
                calls.contains(&Call::Chown { n, uid: 0, gid: 0 }),
                "/dev/bpf{n} goes back to root:wheel"
            );
            assert!(
                calls.contains(&Call::Chmod { n, mode: 0o600 }),
                "/dev/bpf{n} goes back to 0600"
            );
        }
        assert_eq!(calls.last(), Some(&Call::DeleteReceipt));
        assert!(
            !calls
                .iter()
                .any(|c| matches!(c, Call::WriteReceipt(_) | Call::PrecreateNodes)),
            "revert writes no receipt and creates no node: {calls:?}"
        );

        // No receipt: the nodes still go back, nobody is removed.
        let sys = Fake::new(all_nodes(), Some(701), Some(admin("matt")));
        if let Err(err) = revert(&sys) {
            panic!("revert must succeed: {err}");
        }
        let calls = sys.calls();
        assert_eq!(dseditgroup_calls(&calls), Vec::<Vec<String>>::new());
        assert!(calls.contains(&Call::Chown {
            n: 0,
            uid: 0,
            gid: 0
        }));
        assert_eq!(calls.last(), Some(&Call::DeleteReceipt));
    }

    #[test]
    fn revert_refuses_a_symlinked_receipt_dir() {
        let mut sys = Fake::new(all_nodes(), Some(701), None);
        sys.dir = Some(DirMeta {
            is_dir: false,
            is_symlink: true,
            ..good_dir()
        });
        assert!(revert(&sys).is_err());
        assert_eq!(sys.calls(), vec![Call::ReceiptDirMeta]);
    }

    #[test]
    fn refused_node_is_recorded_in_errors_and_left_alone() {
        let mut nodes = all_nodes();
        nodes[3] = node(3, 42);
        let sys = Fake::new(nodes, Some(701), None);
        let receipt = match apply(&sys, "0.5.9", 1_762_000_000_000) {
            Ok(receipt) => receipt,
            Err(err) => panic!("apply must succeed: {err}"),
        };
        assert_eq!(
            receipt.errors,
            vec!["/dev/bpf3: major 42 differs from /dev/bpf0's major 23".to_string()]
        );
        assert_eq!(receipt.nodes, 255);
        let calls = sys.calls();
        assert!(
            !calls
                .iter()
                .any(|c| matches!(c, Call::Chown { n: 3, .. } | Call::Chmod { n: 3, .. })),
            "/dev/bpf3 is left alone: {calls:?}"
        );
        assert!(calls.contains(&Call::Chown {
            n: 4,
            uid: 0,
            gid: 701
        }));
    }

    #[test]
    fn primary_group_id_parses_the_dscl_line() {
        assert_eq!(parse_primary_group_id("PrimaryGroupID: 701\n"), Some(701));
        assert_eq!(parse_primary_group_id("PrimaryGroupID: 80"), Some(80));
        assert_eq!(parse_primary_group_id(""), None);
        assert_eq!(parse_primary_group_id("PrimaryGroupID: abc\n"), None);
        assert_eq!(parse_primary_group_id("RecordName: access_bpf\n"), None);
    }

    #[test]
    fn dry_run_apply_touches_nothing() {
        let sys = Fake::new(all_nodes(), Some(701), Some(admin("matt")));
        let lines = match dry_run_apply(&sys) {
            Ok(lines) => lines,
            Err(err) => panic!("dry run must succeed: {err}"),
        };
        let expected = render(&plan_apply(
            &all_nodes(),
            Some(701),
            None,
            Some(&admin("matt")),
        ));
        assert_eq!(lines, expected);
        assert_eq!(lines.len(), 256 * 2 + 2);
        assert_eq!(lines[0], "chown root:access_bpf /dev/bpf0");
        assert_eq!(lines[1], "chmod 0660 /dev/bpf0");
        assert_eq!(lines[512], "add matt to access_bpf");
        assert_eq!(
            lines[513],
            "write receipt /Library/Application Support/Aitmproxy/l4-helper.json"
        );

        let calls = sys.calls();
        assert!(
            !calls.iter().any(touches_the_machine),
            "a dry run touches nothing: {calls:?}"
        );
        assert!(
            !calls.iter().any(|c| matches!(c, Call::PrecreateNodes)),
            "a dry run pre-creates no node: {calls:?}"
        );
        // It did gather the facts the real run would.
        for wanted in [
            Call::ReceiptDirMeta,
            Call::ReadReceipt,
            Call::ListNodes,
            Call::GroupGid,
            Call::ConsoleUser,
        ] {
            assert!(calls.contains(&wanted), "{wanted:?} missing from {calls:?}");
        }
    }

    #[test]
    fn dry_run_apply_without_the_group_prints_the_whole_plan() {
        let sys = Fake::new(all_nodes(), None, Some(admin("matt")));
        let lines = match dry_run_apply(&sys) {
            Ok(lines) => lines,
            Err(err) => panic!("dry run must succeed: {err}"),
        };
        assert_eq!(lines[0], "create group access_bpf");
        assert_eq!(lines[1], "chown root:access_bpf /dev/bpf0");
        assert_eq!(
            dseditgroup_calls(&sys.calls()),
            Vec::<Vec<String>>::new(),
            "no group is created on a dry run"
        );
    }

    #[test]
    fn dry_run_reports_a_missing_or_unreadable_receipt_dir_as_a_line() {
        // Missing directory: a line, then the plan as on a first run.
        let mut sys = Fake::new(all_nodes(), Some(701), Some(admin("matt")));
        sys.dir = None;
        let lines = match dry_run_apply(&sys) {
            Ok(lines) => lines,
            Err(err) => panic!("dry run must succeed: {err}"),
        };
        assert_eq!(
            lines[0],
            "receipt directory /Library/Application Support/Aitmproxy is missing; bpf-permissions would create it"
        );
        assert_eq!(lines[1], "chown root:access_bpf /dev/bpf0");
        assert!(lines.contains(&"add matt to access_bpf".to_string()));
        assert!(
            !sys.calls().contains(&Call::CreateReceiptDir),
            "a dry run creates no directory"
        );

        // Unreadable directory (as for an unprivileged user): a line, then the plan.
        let mut sys = Fake::new(all_nodes(), Some(701), None);
        sys.dir_error = Some(
            "stat /Library/Application Support/Aitmproxy: Permission denied (os error 13)"
                .to_string(),
        );
        let lines = match dry_run_apply(&sys) {
            Ok(lines) => lines,
            Err(err) => panic!("dry run must succeed: {err}"),
        };
        assert_eq!(
            lines[0],
            "receipt directory not readable: stat /Library/Application Support/Aitmproxy: Permission denied (os error 13)"
        );
        assert_eq!(lines[1], "chown root:access_bpf /dev/bpf0");
        assert!(!sys.calls().contains(&Call::ReadReceipt));

        // A refused directory is a line too; the real run would stop there.
        let mut sys = Fake::new(all_nodes(), Some(701), None);
        sys.dir = Some(DirMeta {
            is_dir: false,
            is_symlink: true,
            ..good_dir()
        });
        let lines = match dry_run_revert(&sys) {
            Ok(lines) => lines,
            Err(err) => panic!("dry run must succeed: {err}"),
        };
        assert_eq!(
            lines[0],
            "the run would stop: /Library/Application Support/Aitmproxy is a symlink; nothing was changed"
        );
        assert_eq!(lines[1], "chown root:wheel /dev/bpf0");
    }

    #[test]
    fn dry_run_apply_notes_nodes_still_to_create() {
        let nodes: Vec<NodeFacts> = (0..4).map(|n| node(n, BPF_MAJOR)).collect();
        let sys = Fake::new(nodes, Some(701), None);
        let lines = match dry_run_apply(&sys) {
            Ok(lines) => lines,
            Err(err) => panic!("dry run must succeed: {err}"),
        };
        assert_eq!(
            lines[0],
            "4 of 256 nodes exist; bpf-permissions would create the rest first"
        );
        assert_eq!(lines[1], "chown root:access_bpf /dev/bpf0");
        assert_eq!(lines.len(), 1 + 4 * 2 + 1);
        assert!(!sys.calls().contains(&Call::PrecreateNodes));
    }

    #[test]
    fn dry_run_revert_touches_nothing() {
        let sys = Fake::new(all_nodes(), Some(701), Some(admin("matt")));
        *sys.receipt.borrow_mut() = Some(receipt(&["matt"]).to_json());
        let lines = match dry_run_revert(&sys) {
            Ok(lines) => lines,
            Err(err) => panic!("dry run must succeed: {err}"),
        };
        let prior = receipt(&["matt"]);
        assert_eq!(lines, render(&plan_revert(&all_nodes(), Some(&prior))));
        assert_eq!(lines[0], "chown root:wheel /dev/bpf0");
        assert_eq!(lines[512], "remove matt from access_bpf");
        assert_eq!(
            lines[513],
            "delete receipt /Library/Application Support/Aitmproxy/l4-helper.json"
        );
        let calls = sys.calls();
        assert!(
            !calls.iter().any(touches_the_machine),
            "a dry run touches nothing: {calls:?}"
        );
        assert!(
            sys.receipt.borrow().is_some(),
            "the receipt is still there after a dry run"
        );
    }

    // ---- Tester edge cases (stage 5, unit p2) ------------------------------

    /// The words plan Rule 2 forbids, matched as whole words.
    fn names_a_command(msg: &str) -> Option<&'static str> {
        const FORBIDDEN: [&str; 8] = [
            "sudo",
            "setcap",
            "chmod",
            "chgrp",
            "chown",
            "dseditgroup",
            "launchctl",
            "pkexec",
        ];
        msg.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
            .find_map(|word| FORBIDDEN.iter().copied().find(|f| *f == word))
    }

    fn is_mutation(c: &Call) -> bool {
        matches!(
            c,
            Call::Chown { .. } | Call::Chmod { .. } | Call::WriteReceipt(_) | Call::Dseditgroup(_)
        )
    }

    #[test]
    fn tester_chown_failure_mid_run_stops_before_the_receipt() {
        let mut sys = Fake::new(all_nodes(), Some(701), Some(admin("matt")));
        sys.fail_chown_at = Some(5);
        let err =
            apply(&sys, "0.5.9", 1_762_000_000_000).expect_err("a failed chown stops the run");
        assert_eq!(err, "the fake refused node 5");
        let calls = sys.calls();
        for n in 0..5 {
            assert!(
                calls.contains(&Call::Chown {
                    n,
                    uid: 0,
                    gid: 701
                }),
                "/dev/bpf{n} was chowned before the failure"
            );
            assert!(
                calls.contains(&Call::Chmod { n, mode: 0o660 }),
                "/dev/bpf{n} was chmodded before the failure"
            );
        }
        // The failing chown is the last call: no chmod of node 5, nothing on
        // node 6 or later, no member added, no receipt.
        assert_eq!(
            calls.last(),
            Some(&Call::Chown {
                n: 5,
                uid: 0,
                gid: 701
            })
        );
        assert!(!calls.contains(&Call::Chmod { n: 5, mode: 0o660 }));
        assert!(!calls
            .iter()
            .any(|c| matches!(c, Call::Chown { n, .. } | Call::Chmod { n, .. } if *n > 5)));
        assert_eq!(dseditgroup_calls(&calls), Vec::<Vec<String>>::new());
        assert!(!calls.iter().any(|c| matches!(c, Call::WriteReceipt(_))));
        assert!(sys.receipt.borrow().is_none());
    }

    #[test]
    fn tester_add_member_failure_leaves_no_receipt_so_the_next_run_retries() {
        let mut sys = Fake::new(all_nodes(), Some(701), Some(admin("matt")));
        sys.fail_dseditgroup_op = Some("edit");
        let err = apply(&sys, "0.5.9", 1_762_000_000_000).expect_err("a failed add stops the run");
        assert_eq!(err, "the fake refused the directory service change");
        let calls = sys.calls();
        assert_eq!(
            dseditgroup_calls(&calls),
            vec![argv(&[
                "/usr/sbin/dseditgroup",
                "-o",
                "edit",
                "-a",
                "matt",
                "-t",
                "user",
                "access_bpf",
            ])]
        );
        assert!(!calls.iter().any(|c| matches!(c, Call::WriteReceipt(_))));
        assert!(sys.receipt.borrow().is_none());
        // Every node was already set; the next launch finds no receipt and
        // plans the add again.
        assert_eq!(
            calls
                .iter()
                .filter(|c| matches!(c, Call::Chmod { mode: 0o660, .. }))
                .count(),
            256
        );
    }

    #[test]
    fn tester_create_group_failure_touches_no_node() {
        let mut sys = Fake::new(all_nodes(), None, Some(admin("matt")));
        sys.gid_after_create = Some(702);
        sys.fail_dseditgroup_op = Some("create");
        let err =
            apply(&sys, "0.5.9", 1_762_000_000_000).expect_err("a failed create stops the run");
        assert_eq!(err, "the fake refused the directory service change");
        let calls = sys.calls();
        assert_eq!(dseditgroup_calls(&calls).len(), 1);
        assert!(
            !calls.iter().any(|c| matches!(
                c,
                Call::Chown { .. } | Call::Chmod { .. } | Call::WriteReceipt(_)
            )),
            "{calls:?}"
        );
    }

    #[test]
    fn tester_create_group_without_a_gid_says_so_literally_and_stops_at_once() {
        let mut sys = Fake::new(all_nodes(), None, Some(admin("matt")));
        sys.gid_after_create = None;
        let err = apply(&sys, "0.5.9", 1_762_000_000_000).expect_err("no gid after create");
        assert_eq!(
            err,
            "group access_bpf was created but has no gid; no node was changed"
        );
        let calls = sys.calls();
        // The gid was read once before the plan and once after the create;
        // that re-read is the last call.
        assert_eq!(calls.iter().filter(|c| **c == Call::GroupGid).count(), 2);
        assert_eq!(calls.last(), Some(&Call::GroupGid));
    }

    #[test]
    fn tester_group_lookup_failure_stops_apply_before_any_node_change() {
        let mut sys = Fake::new(all_nodes(), Some(701), Some(admin("matt")));
        sys.group_gid_error = Some("could not look up group access_bpf: eServerError".to_string());
        assert_eq!(
            apply(&sys, "0.5.9", 1),
            Err("could not look up group access_bpf: eServerError".to_string())
        );
        assert!(!sys.calls().iter().any(is_mutation), "{:?}", sys.calls());
        // Likewise a console lookup failure (after the gid, before the plan).
        let mut sys = Fake::new(all_nodes(), Some(701), Some(admin("matt")));
        sys.console_error = Some("could not resolve console uid 501 to a name".to_string());
        assert_eq!(
            apply(&sys, "0.5.9", 1),
            Err("could not resolve console uid 501 to a name".to_string())
        );
        assert!(!sys.calls().iter().any(is_mutation), "{:?}", sys.calls());
    }

    #[test]
    fn tester_revert_with_a_schema_2_receipt_touches_nothing() {
        let sys = Fake::new(all_nodes(), Some(701), Some(admin("matt")));
        *sys.receipt.borrow_mut() = Some(br#"{"schema":2,"helper_version":"9.9.9"}"#.to_vec());
        let err = revert(&sys).expect_err("a newer receipt is refused");
        assert!(err.starts_with("existing receipt not readable: "), "{err}");
        assert!(err.contains("schema 2"), "{err}");
        assert_eq!(sys.calls(), vec![Call::ReceiptDirMeta, Call::ReadReceipt]);
        assert!(
            sys.receipt.borrow().is_some(),
            "the receipt stays for the newer helper that wrote it"
        );
    }

    #[test]
    fn tester_malformed_receipts_stop_both_modes_before_any_change() {
        for bad in [
            &b""[..],
            b"{",
            b"[]",
            b"null",
            br#"{"schema":"1"}"#,
            br#"{"schema":1}"#,
            b"\xff\xfe",
            b"{\"schema\":1,\"helper_version\":\"0.5.9\",\"applied_at\":1,\"group\":\"access_bpf\",\"gid\":701,\"nodes\":256,\"members_added\":\"matt\",\"errors\":[]}",
        ] {
            let sys = Fake::new(all_nodes(), Some(701), Some(admin("matt")));
            *sys.receipt.borrow_mut() = Some(bad.to_vec());
            let err = apply(&sys, "0.5.9", 1).expect_err("malformed refused by apply");
            assert!(err.starts_with("existing receipt not readable: "), "{bad:?}: {err}");
            assert_eq!(sys.calls(), vec![Call::ReceiptDirMeta, Call::ReadReceipt], "{bad:?}");

            let sys = Fake::new(all_nodes(), Some(701), None);
            *sys.receipt.borrow_mut() = Some(bad.to_vec());
            let err = revert(&sys).expect_err("malformed refused by revert");
            assert!(err.starts_with("existing receipt not readable: "), "{bad:?}: {err}");
            assert_eq!(sys.calls(), vec![Call::ReceiptDirMeta, Call::ReadReceipt], "{bad:?}");
        }
    }

    #[test]
    fn tester_remove_member_failure_keeps_the_receipt() {
        // A user the receipt names but the directory service will not remove
        // (left the group by other means, or the account is gone): the nodes
        // are already back to root:wheel, the run stops, and the receipt
        // stays so the next revert tries again instead of forgetting who was
        // added.
        let mut sys = Fake::new(all_nodes(), Some(701), None);
        *sys.receipt.borrow_mut() = Some(receipt(&["matt"]).to_json());
        sys.fail_dseditgroup_op = Some("edit");
        let err = revert(&sys).expect_err("a failed remove stops the run");
        assert_eq!(err, "the fake refused the directory service change");
        let calls = sys.calls();
        assert!(!calls.contains(&Call::DeleteReceipt), "{calls:?}");
        assert!(sys.receipt.borrow().is_some());
        assert_eq!(
            calls
                .iter()
                .filter(|c| matches!(c, Call::Chmod { mode: 0o600, .. }))
                .count(),
            256
        );
        assert_eq!(
            calls
                .iter()
                .filter(|c| matches!(c, Call::Chown { uid: 0, gid: 0, .. }))
                .count(),
            256
        );
    }

    #[test]
    fn tester_dry_runs_call_no_mutating_method_even_when_every_fact_is_missing() {
        // Missing directory, missing group, nobody at the console, four nodes.
        let nodes: Vec<NodeFacts> = (0..4).map(|n| node(n, BPF_MAJOR)).collect();
        let mut sys = Fake::new(nodes.clone(), None, None);
        sys.dir = None;
        let lines = dry_run_apply(&sys).expect("dry run");
        assert_eq!(
            sys.calls(),
            vec![
                Call::ReceiptDirMeta,
                Call::ListNodes,
                Call::GroupGid,
                Call::ConsoleUser
            ]
        );
        assert_eq!(
            lines[0],
            "receipt directory /Library/Application Support/Aitmproxy is missing; bpf-permissions would create it"
        );
        assert_eq!(
            lines[1],
            "4 of 256 nodes exist; bpf-permissions would create the rest first"
        );
        assert_eq!(lines[2], "create group access_bpf");
        assert_eq!(lines[3], "chown root:access_bpf /dev/bpf0");
        assert_eq!(lines.len(), 3 + 4 * 2 + 1);
        assert_eq!(
            lines.last().map(String::as_str),
            Some("write receipt /Library/Application Support/Aitmproxy/l4-helper.json")
        );

        let mut sys = Fake::new(nodes, None, None);
        sys.dir = None;
        let lines = dry_run_revert(&sys).expect("dry run");
        assert_eq!(sys.calls(), vec![Call::ReceiptDirMeta, Call::ListNodes]);
        assert_eq!(
            lines[0],
            "receipt directory /Library/Application Support/Aitmproxy is missing; there is no receipt to read"
        );
        assert_eq!(lines[1], "chown root:wheel /dev/bpf0");
        assert_eq!(lines.len(), 1 + 4 * 2 + 1);
        assert_eq!(
            lines.last().map(String::as_str),
            Some("delete receipt /Library/Application Support/Aitmproxy/l4-helper.json")
        );
    }

    #[test]
    fn tester_dry_run_turns_group_and_console_failures_into_lines_and_plans_conservatively() {
        // What the live dry run on a sandboxed Mac shows: dscl fails, so the
        // group is planned as absent; a console failure adds nobody.
        let mut sys = Fake::new(all_nodes(), Some(701), Some(admin("matt")));
        sys.group_gid_error = Some(
            "could not look up group access_bpf: Operation failed with error: eServerError"
                .to_string(),
        );
        sys.console_error = Some("could not resolve console uid 501 to a name".to_string());
        let lines = dry_run_apply(&sys).expect("dry run");
        assert_eq!(
            lines[0],
            "group access_bpf could not be looked up (could not look up group access_bpf: Operation failed with error: eServerError); planning as if it were absent"
        );
        assert_eq!(
            lines[1],
            "console user could not be determined (could not resolve console uid 501 to a name); planning as if nobody were logged in"
        );
        assert_eq!(lines[2], "create group access_bpf");
        assert_eq!(lines[3], "chown root:access_bpf /dev/bpf0");
        assert!(
            !lines.iter().any(|l| l.starts_with("add ")),
            "nobody is added when the console is unknown: {lines:?}"
        );
        assert_eq!(lines.len(), 3 + 256 * 2 + 1);
        assert!(!sys.calls().iter().any(touches_the_machine));
    }

    #[test]
    fn tester_apply_with_no_nodes_writes_a_zero_node_receipt() {
        // No /dev/bpf* at all (not a real macOS state): the planner refuses
        // nothing because there is nothing to judge, and the receipt records
        // 0 nodes, no error, and the member that was added. Pinned so a
        // change here is deliberate.
        let sys = Fake::new(Vec::new(), Some(701), Some(admin("matt")));
        let receipt = apply(&sys, "0.5.9", 1_762_000_000_000).expect("apply");
        assert_eq!(receipt.nodes, 0);
        assert_eq!(receipt.errors, Vec::<String>::new());
        assert_eq!(receipt.members_added, vec!["matt".to_string()]);
        assert!(!sys
            .calls()
            .iter()
            .any(|c| matches!(c, Call::Chown { .. } | Call::Chmod { .. })));
    }

    #[test]
    fn tester_every_node_refused_still_writes_the_receipt_with_every_error() {
        // /dev/bpf0 missing: every node refused, none set, 255 errors in the
        // receipt, and no chown or chmod at all. The admin is still added
        // (the plan does not condition AddMember on a node being set).
        let nodes: Vec<NodeFacts> = (1..256).map(|n| node(n, BPF_MAJOR)).collect();
        let sys = Fake::new(nodes, Some(701), Some(admin("matt")));
        let receipt = apply(&sys, "0.5.9", 1_762_000_000_000).expect("apply");
        assert_eq!(receipt.nodes, 0);
        assert_eq!(receipt.errors.len(), 255);
        assert_eq!(receipt.errors[0], "/dev/bpf1: /dev/bpf0 is missing");
        assert_eq!(receipt.errors[254], "/dev/bpf255: /dev/bpf0 is missing");
        assert_eq!(receipt.members_added, vec!["matt".to_string()]);
        let calls = sys.calls();
        assert!(!calls
            .iter()
            .any(|c| matches!(c, Call::Chown { .. } | Call::Chmod { .. })));
        assert_eq!(dseditgroup_calls(&calls).len(), 1);
    }

    #[test]
    fn tester_receipt_dir_refusals_are_literal_and_name_no_command() {
        let cases: [(DirMeta, &str); 5] = [
            (
                DirMeta {
                    is_dir: false,
                    is_symlink: true,
                    ..good_dir()
                },
                "/Library/Application Support/Aitmproxy is a symlink; nothing was changed",
            ),
            (
                DirMeta {
                    is_dir: false,
                    ..good_dir()
                },
                "/Library/Application Support/Aitmproxy is not a directory; nothing was changed",
            ),
            (
                DirMeta {
                    uid: 501,
                    ..good_dir()
                },
                "/Library/Application Support/Aitmproxy is owned by uid 501 gid 0 (expected root:wheel); nothing was changed",
            ),
            (
                DirMeta {
                    gid: 80,
                    ..good_dir()
                },
                "/Library/Application Support/Aitmproxy is owned by uid 0 gid 80 (expected root:wheel); nothing was changed",
            ),
            (
                DirMeta {
                    mode: 0o777,
                    ..good_dir()
                },
                "/Library/Application Support/Aitmproxy has mode 0777 (expected 0755); nothing was changed",
            ),
        ];
        let mut messages = Vec::new();
        for (dir, expected) in cases {
            let mut sys = Fake::new(all_nodes(), Some(701), None);
            sys.dir = Some(dir.clone());
            let err = apply(&sys, "0.5.9", 1).expect_err("refused by apply");
            assert_eq!(err, expected);
            assert_eq!(sys.calls(), vec![Call::ReceiptDirMeta]);
            messages.push(err);
            let mut sys = Fake::new(all_nodes(), Some(701), None);
            sys.dir = Some(dir);
            let err = revert(&sys).expect_err("refused by revert");
            assert_eq!(err, expected);
            assert_eq!(sys.calls(), vec![Call::ReceiptDirMeta]);
            messages.push(err);
        }
        // The executor's own messages (not the fake's) from the other stop
        // points, for the Rule 2 check.
        let mut sys = Fake::new(all_nodes(), None, None);
        sys.gid_after_create = None;
        messages.push(apply(&sys, "0.5.9", 1).expect_err("no gid"));
        let sys = Fake::new(all_nodes(), Some(701), None);
        *sys.receipt.borrow_mut() = Some(br#"{"schema":2}"#.to_vec());
        messages.push(apply(&sys, "0.5.9", 1).expect_err("schema 2"));
        let sys = Fake::new(all_nodes(), Some(701), None);
        *sys.receipt.borrow_mut() = Some(b"{".to_vec());
        messages.push(revert(&sys).expect_err("malformed"));
        assert_eq!(messages.len(), 13);
        for msg in &messages {
            assert_eq!(
                names_a_command(msg),
                None,
                "message {msg:?} names a command"
            );
        }
        assert_eq!(names_a_command("run dseditgroup now"), Some("dseditgroup"));
    }
}
