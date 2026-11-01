//! The macOS `/dev/bpf*` permission plan (spec §3.1, T2; AC6, AC14).
//!
//! Pure: given facts about the device nodes, the group, the prior receipt and
//! the console user, these functions return the list of steps the helper
//! would take. Nothing here touches the filesystem, the directory service or
//! any other system state; task P2.3's executor carries the steps out, and
//! `--dry-run` prints [`render`] and stops.

use aitm_proto_l4::privilege::contract::{Receipt, BPF_GROUP, RECEIPT_PATH};

/// Mode every valid node is given by `bpf-permissions` (owner and group may
/// read and write; nobody else).
const APPLY_MODE: u32 = 0o660;
/// Mode every valid node is returned to by `bpf-revert` (root only).
const REVERT_MODE: u32 = 0o600;
/// gid of `wheel`, the group `/dev/bpf*` ships with on macOS.
const WHEEL_GID: u32 = 0;

/// What the executor learned about one `/dev/bpfN` from `stat`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeFacts {
    /// The `N` in `/dev/bpfN`.
    pub n: u32,
    /// Whether the node is a character device.
    pub is_char: bool,
    /// The raw `st_rdev`; see [`bpf_major`].
    pub rdev: u64,
    /// Current owner uid.
    pub uid: u32,
    /// Current group gid.
    pub gid: u32,
    /// Current permission bits.
    pub mode: u32,
}

/// The macOS `major()` of a `dev_t`: bits 24 to 31 of `rdev`.
#[must_use]
pub fn bpf_major(rdev: u64) -> u32 {
    // The mask leaves at most eight bits, so the narrowing cannot lose any.
    ((rdev >> 24) & 0xff) as u32
}

/// The user logged in at the console (the owner of `/dev/console`) and
/// whether the directory service lists them in `admin`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsoleUser {
    /// Short account name.
    pub name: String,
    /// Member of the `admin` group.
    pub is_admin: bool,
}

/// One thing the helper will do, in order. Data only; the executor (task
/// P2.3) carries it out and `--dry-run` prints [`render`] instead.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Step {
    /// Create the [`BPF_GROUP`] group; planned first, only when it is absent.
    CreateGroup,
    /// Give `/dev/bpf{n}` owner root and the group `gid`.
    ///
    /// `gid` is `None` when the group does not exist yet at planning time:
    /// it means "the gid of the group the preceding [`Step::CreateGroup`]
    /// creates". The executor resolves it after creating the group and
    /// refuses to run a `Chown` whose `gid` is still `None` when the group
    /// does not exist. Keeping the planner pure this way lets `--dry-run` on a
    /// machine without the group print the whole plan. On revert `gid` is
    /// always `Some(0)`, i.e. `wheel`.
    Chown { n: u32, gid: Option<u32> },
    /// Set the permission bits of `/dev/bpf{n}`.
    Chmod { n: u32, mode: u32 },
    /// Leave `/dev/bpf{n}` untouched because it is not what a bpf node should
    /// be; `why` is the one-sentence reason, also carried into the receipt's
    /// `errors`.
    Refuse { n: u32, why: String },
    /// Add this user to [`BPF_GROUP`] (first run only, admin console user).
    AddMember(String),
    /// Remove this user from [`BPF_GROUP`] (only users the receipt says we added).
    RemoveMember(String),
    /// Write the receipt at [`RECEIPT_PATH`].
    WriteReceipt,
    /// Delete the receipt at [`RECEIPT_PATH`].
    DeleteReceipt,
}

/// Why no node can be trusted when `/dev/bpf0` gives no reference.
enum NoReference {
    Missing,
    NotChar,
}

impl NoReference {
    fn why(&self) -> String {
        match self {
            NoReference::Missing => "/dev/bpf0 is missing".to_string(),
            NoReference::NotChar => "/dev/bpf0 is not a character device".to_string(),
        }
    }
}

/// The verdict on one node against the reference `/dev/bpf0`.
enum Verdict {
    Valid,
    Refused(String),
}

/// Judge every node against `/dev/bpf0`: a node is valid only when it is a
/// character device with the same major number as `/dev/bpf0`. When
/// `/dev/bpf0` is absent or not a character device there is no reference and
/// every node is refused.
fn judge(nodes: &[NodeFacts]) -> Vec<(u32, Verdict)> {
    let reference = match nodes.iter().find(|node| node.n == 0) {
        None => Err(NoReference::Missing),
        Some(bpf0) if !bpf0.is_char => Err(NoReference::NotChar),
        Some(bpf0) => Ok(bpf_major(bpf0.rdev)),
    };
    nodes
        .iter()
        .map(|node| {
            let verdict = match &reference {
                Err(no_reference) => Verdict::Refused(no_reference.why()),
                Ok(_) if !node.is_char => Verdict::Refused("not a character device".to_string()),
                Ok(major0) => {
                    let major = bpf_major(node.rdev);
                    if major == *major0 {
                        Verdict::Valid
                    } else {
                        Verdict::Refused(format!(
                            "major {major} differs from /dev/bpf0's major {major0}"
                        ))
                    }
                }
            };
            (node.n, verdict)
        })
        .collect()
}

/// Push the per-node steps: `Chown` + `Chmod` for each valid node, `Refuse`
/// for the rest, in the order the nodes were given.
fn push_node_steps(steps: &mut Vec<Step>, nodes: &[NodeFacts], gid: Option<u32>, mode: u32) {
    for (n, verdict) in judge(nodes) {
        match verdict {
            Verdict::Valid => {
                steps.push(Step::Chown { n, gid });
                steps.push(Step::Chmod { n, mode });
            }
            Verdict::Refused(why) => steps.push(Step::Refuse { n, why }),
        }
    }
}

/// The plan for `bpf-permissions` (spec §3.1 steps 2 to 5).
///
/// `group_gid` is the gid of [`BPF_GROUP`] if it exists; `prior` is the
/// receipt from an earlier run, if any; `console` is the console user, if one
/// is logged in. `CreateGroup` comes first when the group is absent; each
/// node valid against `/dev/bpf0` gets `Chown` to the group and `Chmod` 0660,
/// others `Refuse`; the console user is added only on the first run (no
/// receipt) and only if they are an admin; `WriteReceipt` is last.
#[must_use]
pub fn plan_apply(
    nodes: &[NodeFacts],
    group_gid: Option<u32>,
    prior: Option<&Receipt>,
    console: Option<&ConsoleUser>,
) -> Vec<Step> {
    let mut steps = Vec::with_capacity(nodes.len() * 2 + 3);
    if group_gid.is_none() {
        steps.push(Step::CreateGroup);
    }
    push_node_steps(&mut steps, nodes, group_gid, APPLY_MODE);
    if prior.is_none() {
        if let Some(user) = console.filter(|user| user.is_admin) {
            steps.push(Step::AddMember(user.name.clone()));
        }
    }
    steps.push(Step::WriteReceipt);
    steps
}

/// The plan for `bpf-revert` (spec §3.1, last paragraph).
///
/// Each node valid against `/dev/bpf0` goes back to `root:wheel` 0600, others
/// are refused and left alone; exactly the users in `prior.members_added` are
/// removed from the group, in receipt order, and nobody else; `DeleteReceipt`
/// is last.
#[must_use]
pub fn plan_revert(nodes: &[NodeFacts], prior: Option<&Receipt>) -> Vec<Step> {
    let members = prior.map_or(&[][..], |receipt| receipt.members_added.as_slice());
    let mut steps = Vec::with_capacity(nodes.len() * 2 + members.len() + 1);
    push_node_steps(&mut steps, nodes, Some(WHEEL_GID), REVERT_MODE);
    for name in members {
        steps.push(Step::RemoveMember(name.clone()));
    }
    steps.push(Step::DeleteReceipt);
    steps
}

/// One line per step for `--dry-run`. The lines say what the helper itself
/// will do; they are not instructions to a person.
#[must_use]
pub fn render(steps: &[Step]) -> Vec<String> {
    steps
        .iter()
        .map(|step| match step {
            Step::CreateGroup => format!("create group {BPF_GROUP}"),
            Step::Chown { n, gid } => {
                // The planner only ever targets two groups: `wheel` on revert
                // and the bpf group otherwise (by gid or, before it exists, by
                // name).
                let group = if *gid == Some(WHEEL_GID) {
                    "wheel"
                } else {
                    BPF_GROUP
                };
                format!("chown root:{group} /dev/bpf{n}")
            }
            Step::Chmod { n, mode } => format!("chmod {mode:04o} /dev/bpf{n}"),
            Step::Refuse { n, why } => format!("refuse /dev/bpf{n}: {why}"),
            Step::AddMember(name) => format!("add {name} to {BPF_GROUP}"),
            Step::RemoveMember(name) => format!("remove {name} from {BPF_GROUP}"),
            Step::WriteReceipt => format!("write receipt {RECEIPT_PATH}"),
            Step::DeleteReceipt => format!("delete receipt {RECEIPT_PATH}"),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use aitm_proto_l4::privilege::contract::{Receipt, BPF_GROUP, RECEIPT_PATH, RECEIPT_SCHEMA};

    /// The major number macOS gives the bpf clone devices on a typical install.
    const BPF_MAJOR: u64 = 23;

    fn node(n: u32, is_char: bool, major: u64) -> NodeFacts {
        NodeFacts {
            n,
            is_char,
            rdev: (major << 24) | u64::from(n),
            uid: 0,
            gid: 0,
            mode: 0o600,
        }
    }

    fn receipt(members_added: &[&str]) -> Receipt {
        Receipt {
            schema: RECEIPT_SCHEMA,
            helper_version: "0.5.9".to_string(),
            applied_at: 1_762_000_000_000,
            group: BPF_GROUP.to_string(),
            gid: 504,
            nodes: 256,
            members_added: members_added.iter().map(|m| (*m).to_string()).collect(),
            errors: Vec::new(),
        }
    }

    fn admin(name: &str) -> ConsoleUser {
        ConsoleUser {
            name: name.to_string(),
            is_admin: true,
        }
    }

    #[test]
    fn bpf_major_extracts_bits_24_to_31() {
        assert_eq!(bpf_major((23 << 24) | 5), 23);
        assert_eq!(bpf_major((0xff << 24) | 0x00ff_ffff), 255);
        // Bits above 31 are not part of the major; macOS `dev_t` is 32 bits.
        assert_eq!(bpf_major((1 << 32) | (23 << 24)), 23);
        assert_eq!(bpf_major(0x12), 0);
        assert_eq!(bpf_major(0), 0);
    }

    #[test]
    fn create_group_comes_first_when_the_gid_is_absent() {
        let nodes = [node(0, true, BPF_MAJOR)];
        assert_eq!(
            plan_apply(&nodes, None, None, None),
            vec![
                Step::CreateGroup,
                Step::Chown { n: 0, gid: None },
                Step::Chmod { n: 0, mode: 0o660 },
                Step::WriteReceipt,
            ]
        );
        // With the group already present its gid rides on every Chown and no
        // CreateGroup is planned.
        assert_eq!(
            plan_apply(&nodes, Some(504), None, None),
            vec![
                Step::Chown {
                    n: 0,
                    gid: Some(504)
                },
                Step::Chmod { n: 0, mode: 0o660 },
                Step::WriteReceipt,
            ]
        );
    }

    #[test]
    fn foreign_major_is_refused() {
        let nodes = [
            node(0, true, BPF_MAJOR),
            node(1, true, BPF_MAJOR),
            node(3, true, 42),
        ];
        let steps = plan_apply(&nodes, Some(504), None, None);
        assert_eq!(
            steps,
            vec![
                Step::Chown {
                    n: 0,
                    gid: Some(504)
                },
                Step::Chmod { n: 0, mode: 0o660 },
                Step::Chown {
                    n: 1,
                    gid: Some(504)
                },
                Step::Chmod { n: 1, mode: 0o660 },
                Step::Refuse {
                    n: 3,
                    why: "major 42 differs from /dev/bpf0's major 23".to_string(),
                },
                Step::WriteReceipt,
            ]
        );
        assert!(
            !steps
                .iter()
                .any(|s| matches!(s, Step::Chown { n: 3, .. } | Step::Chmod { n: 3, .. })),
            "a refused node is never chowned or chmodded: {steps:?}"
        );
        // Revert leaves the foreign node alone too.
        assert_eq!(
            plan_revert(&nodes, None),
            vec![
                Step::Chown { n: 0, gid: Some(0) },
                Step::Chmod { n: 0, mode: 0o600 },
                Step::Chown { n: 1, gid: Some(0) },
                Step::Chmod { n: 1, mode: 0o600 },
                Step::Refuse {
                    n: 3,
                    why: "major 42 differs from /dev/bpf0's major 23".to_string(),
                },
                Step::DeleteReceipt,
            ]
        );
    }

    #[test]
    fn non_char_is_refused() {
        // A non-character node among valid ones is refused by itself.
        let nodes = [node(0, true, BPF_MAJOR), node(2, false, BPF_MAJOR)];
        assert_eq!(
            plan_apply(&nodes, Some(504), None, None),
            vec![
                Step::Chown {
                    n: 0,
                    gid: Some(504)
                },
                Step::Chmod { n: 0, mode: 0o660 },
                Step::Refuse {
                    n: 2,
                    why: "not a character device".to_string(),
                },
                Step::WriteReceipt,
            ]
        );
        // When /dev/bpf0 itself is not a character device there is no reference
        // major, so every node is refused and nothing is changed.
        let nodes = [node(0, false, BPF_MAJOR), node(1, true, BPF_MAJOR)];
        assert_eq!(
            plan_apply(&nodes, Some(504), None, None),
            vec![
                Step::Refuse {
                    n: 0,
                    why: "/dev/bpf0 is not a character device".to_string(),
                },
                Step::Refuse {
                    n: 1,
                    why: "/dev/bpf0 is not a character device".to_string(),
                },
                Step::WriteReceipt,
            ]
        );
        // Likewise when /dev/bpf0 is missing from the facts.
        let nodes = [node(1, true, BPF_MAJOR)];
        assert_eq!(
            plan_apply(&nodes, Some(504), None, None),
            vec![
                Step::Refuse {
                    n: 1,
                    why: "/dev/bpf0 is missing".to_string(),
                },
                Step::WriteReceipt,
            ]
        );
        assert_eq!(
            plan_revert(&nodes, None),
            vec![
                Step::Refuse {
                    n: 1,
                    why: "/dev/bpf0 is missing".to_string(),
                },
                Step::DeleteReceipt,
            ]
        );
    }

    #[test]
    fn receipt_present_adds_nobody() {
        let nodes = [node(0, true, BPF_MAJOR)];
        let prior = receipt(&["matt"]);
        let console = admin("matt");
        assert_eq!(
            plan_apply(&nodes, Some(504), Some(&prior), Some(&console)),
            vec![
                Step::Chown {
                    n: 0,
                    gid: Some(504)
                },
                Step::Chmod { n: 0, mode: 0o660 },
                Step::WriteReceipt,
            ]
        );
        // The first run (no receipt) with the same admin console user adds them.
        assert_eq!(
            plan_apply(&nodes, Some(504), None, Some(&console)),
            vec![
                Step::Chown {
                    n: 0,
                    gid: Some(504)
                },
                Step::Chmod { n: 0, mode: 0o660 },
                Step::AddMember("matt".to_string()),
                Step::WriteReceipt,
            ]
        );
    }

    #[test]
    fn non_admin_console_adds_nobody() {
        let nodes = [node(0, true, BPF_MAJOR)];
        let console = ConsoleUser {
            name: "guest".to_string(),
            is_admin: false,
        };
        let expected = vec![
            Step::Chown {
                n: 0,
                gid: Some(504),
            },
            Step::Chmod { n: 0, mode: 0o660 },
            Step::WriteReceipt,
        ];
        assert_eq!(
            plan_apply(&nodes, Some(504), None, Some(&console)),
            expected
        );
        // No console user at all (a boot-time run) adds nobody either.
        assert_eq!(plan_apply(&nodes, Some(504), None, None), expected);
    }

    #[test]
    fn revert_removes_only_members_added() {
        // The receipt says this helper added "matt". The group on the machine
        // also holds "wsuser" (added by a Wireshark install); the planner is
        // never told about group membership and plans from the receipt alone.
        let nodes = [node(0, true, BPF_MAJOR), node(1, true, BPF_MAJOR)];
        let prior = receipt(&["matt"]);
        let steps = plan_revert(&nodes, Some(&prior));
        assert_eq!(
            steps,
            vec![
                Step::Chown { n: 0, gid: Some(0) },
                Step::Chmod { n: 0, mode: 0o600 },
                Step::Chown { n: 1, gid: Some(0) },
                Step::Chmod { n: 1, mode: 0o600 },
                Step::RemoveMember("matt".to_string()),
                Step::DeleteReceipt,
            ]
        );
        let removed: Vec<&str> = steps
            .iter()
            .filter_map(|s| match s {
                Step::RemoveMember(name) => Some(name.as_str()),
                _ => None,
            })
            .collect();
        assert_eq!(removed, vec!["matt"]);
        assert!(!removed.contains(&"wsuser"));

        // Several members come out in receipt order; no receipt removes nobody.
        let prior = receipt(&["matt", "alice"]);
        assert_eq!(
            plan_revert(&nodes[..1], Some(&prior)),
            vec![
                Step::Chown { n: 0, gid: Some(0) },
                Step::Chmod { n: 0, mode: 0o600 },
                Step::RemoveMember("matt".to_string()),
                Step::RemoveMember("alice".to_string()),
                Step::DeleteReceipt,
            ]
        );
        assert_eq!(
            plan_revert(&nodes[..1], None),
            vec![
                Step::Chown { n: 0, gid: Some(0) },
                Step::Chmod { n: 0, mode: 0o600 },
                Step::DeleteReceipt,
            ]
        );
    }

    #[test]
    fn render_prints_the_literal_dry_run_lines() {
        let nodes = [node(0, true, BPF_MAJOR), node(1, true, BPF_MAJOR)];
        let console = admin("matt");
        assert_eq!(
            render(&plan_apply(&nodes, None, None, Some(&console))),
            vec![
                "create group access_bpf",
                "chown root:access_bpf /dev/bpf0",
                "chmod 0660 /dev/bpf0",
                "chown root:access_bpf /dev/bpf1",
                "chmod 0660 /dev/bpf1",
                "add matt to access_bpf",
                "write receipt /Library/Application Support/Aitmproxy/l4-helper.json",
            ]
        );
        assert_eq!(
            RECEIPT_PATH,
            "/Library/Application Support/Aitmproxy/l4-helper.json"
        );

        let nodes = [node(0, true, BPF_MAJOR), node(3, true, 42)];
        let prior = receipt(&["matt"]);
        assert_eq!(
            render(&plan_revert(&nodes, Some(&prior))),
            vec![
                "chown root:wheel /dev/bpf0",
                "chmod 0600 /dev/bpf0",
                "refuse /dev/bpf3: major 42 differs from /dev/bpf0's major 23",
                "remove matt from access_bpf",
                "delete receipt /Library/Application Support/Aitmproxy/l4-helper.json",
            ]
        );
    }
}
