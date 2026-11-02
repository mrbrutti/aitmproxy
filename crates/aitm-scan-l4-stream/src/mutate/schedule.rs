//! `Schedule`, `Case` and deterministic chain naming (spec S6.4).
//!
//! A [`Schedule`] is the whole mutation plan for one insertion point, as an
//! iterator. Stage 1 is every structure-aware case for the point's node
//! ([`crate::mutate::structure`]), in a fixed order and consuming no
//! randomness. Stage 2 stacks one to three byte-level mutators
//! ([`crate::mutate::bytes`]) on the node's bytes, re-renders with the
//! relations re-satisfied, and keeps going until `cases_planned` cases have
//! been handed out.
//!
//! The only source of randomness is a `ChaCha8Rng` seeded with `rng_seed`,
//! and stage 1 never touches it, so the same `(tree, spec, path, kind,
//! rng_seed, cases_planned, donors)` always yields byte-identical cases in
//! the same order (spec C5) — which is what makes a crash reproducible and a
//! finding replayable.
//!
//! A case that renders the seed itself, or a message an earlier case already
//! rendered, is dropped and does not count against the budget.

use std::collections::{HashSet, VecDeque};
use std::fmt;

use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha8Rng;

use crate::mutate::bytes::{self, ByteMutator, Donors, MAX_MESSAGE_BYTES};
use crate::mutate::structure::{structure_cases, Case};
use crate::spec::{GrammarKind, MessageSpec};
use crate::state::MAX_MESSAGE;
use crate::tree::{self, FieldPath, Tree};

/// The deepest stack of byte-level mutators one stage-2 case may use.
const MAX_STACK: usize = 3;

/// How many stage-2 attempts one `next()` makes before giving up. A point
/// whose field is a single byte runs out of distinct messages quickly; the
/// schedule must end rather than spin.
const STAGE2_ATTEMPTS: usize = 64;

/// The deterministic mutation plan for one insertion point.
///
/// Holds the seed message, so its `Debug` prints sizes only (spec S9).
pub struct Schedule {
    tree: Tree,
    path: FieldPath,
    donors: Vec<Vec<u8>>,
    rng: ChaCha8Rng,
    stage1: VecDeque<Case>,
    seen: HashSet<Vec<u8>>,
    emitted: u32,
    cases_planned: u32,
    stage2_applies: bool,
}

impl fmt::Debug for Schedule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Schedule")
            .field("path", &self.path)
            .field("donors", &Donors(&self.donors))
            .field("stage1_left", &self.stage1.len())
            .field("emitted", &self.emitted)
            .field("cases_planned", &self.cases_planned)
            .finish()
    }
}

impl Schedule {
    /// Plan the campaign for the node at `path`.
    ///
    /// `donors` are the other seeds of the same endpoint, which the
    /// `Crossover*` and `Splice` mutators draw from; an empty set simply
    /// skips those three.
    #[must_use]
    pub fn new(
        tree: Tree,
        spec: &MessageSpec,
        path: FieldPath,
        kind: GrammarKind,
        rng_seed: u64,
        cases_planned: u32,
        donors: Vec<Vec<u8>>,
    ) -> Schedule {
        let stage1 = structure_cases(&tree, spec, &path, kind)
            .into_iter()
            .collect();
        // Byte-level mutators rewrite a field's own bytes, so they apply to
        // a leaf; a container has none of its own.
        let stage2_applies = tree.get(&path).is_some_and(|node| node.children.is_empty());
        let mut seen = HashSet::new();
        seen.insert(tree::render(&tree));

        Schedule {
            tree,
            path,
            donors,
            rng: ChaCha8Rng::seed_from_u64(rng_seed),
            stage1,
            seen,
            emitted: 0,
            cases_planned,
            stage2_applies,
        }
    }

    /// How many cases have been handed out.
    #[must_use]
    pub fn emitted(&self) -> u32 {
        self.emitted
    }

    fn number(&mut self, mut case: Case) -> Case {
        case.index = self.emitted;
        self.emitted = self.emitted.saturating_add(1);
        case
    }

    /// One stage-2 case: a stack of one to three byte-level mutators over
    /// the node's bytes, re-rendered.
    fn stage2_case(&mut self) -> Option<Case> {
        let (mut buf, targets_relation) = {
            let node = self.tree.get(&self.path)?;
            (node.bytes.clone(), node.relation.is_some())
        };

        let depth = 1 + below(&mut self.rng, MAX_STACK);
        let mut chain = Vec::with_capacity(depth);
        for _ in 0..depth {
            let mutator = ByteMutator::ALL[below(&mut self.rng, ByteMutator::ALL.len())];
            let donors = Donors(&self.donors);
            if let Some(params) =
                bytes::apply(mutator, &mut buf, &mut self.rng, &donors, MAX_MESSAGE_BYTES)
            {
                chain.push(format!(
                    "{name}({path},{params})",
                    name = mutator.name(),
                    path = self.path
                ));
            }
        }
        if chain.is_empty() {
            return None;
        }

        let mut copy = self.tree.clone();
        copy.get_mut(&self.path)?.bytes = buf;
        // A byte-level mutator applied to a relation node is a desync too:
        // that node keeps what it was given (spec S6.4).
        let except = targets_relation.then(|| self.path.clone());
        tree::resatisfy(&mut copy, except.as_ref());

        let message = tree::render(&copy);
        if message.is_empty() || message.len() > MAX_MESSAGE {
            return None;
        }
        let field_bytes = copy
            .get(&self.path)
            .map(|node| node.bytes.clone())
            .unwrap_or_default();
        Some(Case {
            index: 0,
            bytes: message,
            chain,
            field_bytes,
        })
    }
}

impl Iterator for Schedule {
    type Item = Case;

    fn next(&mut self) -> Option<Case> {
        if self.emitted >= self.cases_planned {
            return None;
        }

        while let Some(case) = self.stage1.pop_front() {
            if self.seen.insert(case.bytes.clone()) {
                return Some(self.number(case));
            }
        }

        if !self.stage2_applies {
            return None;
        }
        for _ in 0..STAGE2_ATTEMPTS {
            if let Some(case) = self.stage2_case() {
                if self.seen.insert(case.bytes.clone()) {
                    return Some(self.number(case));
                }
            }
        }
        None
    }
}

/// The mutator that produced a chain entry: everything before the first `(`.
#[must_use]
pub fn mutator_name(chain_entry: &str) -> &str {
    match chain_entry.find('(') {
        Some(open) => chain_entry.get(..open).unwrap_or(chain_entry),
        None => chain_entry,
    }
}

/// A uniform index below `n`, matching `mutate::bytes`' own helper so the
/// two consume the generator the same way.
fn below(rng: &mut ChaCha8Rng, n: usize) -> usize {
    if n <= 1 {
        0
    } else {
        rng.random_range(0..n)
    }
}

#[cfg(test)]
mod tests {
    use crate::mutate::schedule::{mutator_name, Schedule};
    use crate::mutate::structure::structure_cases;
    use crate::mutate::structure::tests::{modbus_spec, modbus_tree, resp_spec, resp_tree};
    use crate::spec::GrammarKind;
    use crate::tree::{self, FieldPath};

    /// The structure-aware mutator names, to tell a stage-1 case from a
    /// stage-2 one in a schedule's output.
    const STRUCTURE: [&str; 11] = [
        "len_desync",
        "count_mismatch",
        "type_subst",
        "delim_remove",
        "delim_dup",
        "delim_inject",
        "long_string",
        "repeat_element",
        "checksum_invalid",
        "varint_overlong",
        "int_boundary",
    ];

    fn is_stage1(chain: &[String]) -> bool {
        chain
            .first()
            .is_some_and(|entry| STRUCTURE.contains(&mutator_name(entry)))
    }

    #[test]
    fn mutator_name_is_the_text_before_the_paren() {
        assert_eq!(mutator_name("len_desync(header.length,+1)"), "len_desync");
        assert_eq!(mutator_name("BitFlip(payload,@3)"), "BitFlip");
        assert_eq!(mutator_name("BytesInsert(payload,@2,+7)"), "BytesInsert");
        assert_eq!(mutator_name("delim_remove(command.crlf)"), "delim_remove");
        assert_eq!(mutator_name("no parens here"), "no parens here");
    }

    #[test]
    fn relations_resatisfied_unless_targeted() {
        let spec = modbus_spec();
        let tree = modbus_tree();

        // A byte-level mutation of a field that holds no relation: the
        // length follows the new PDU.
        let case = Schedule::new(
            tree.clone(),
            &spec,
            FieldPath::new("pdu.address"),
            GrammarKind::Modbus,
            1,
            400,
            Vec::new(),
        )
        .find(|case| {
            case.chain
                .first()
                .is_some_and(|entry| entry.starts_with("BytesInsert("))
        })
        .expect("seed 1 stacks a BytesInsert within 400 cases");
        assert!(case.bytes.len() > 12, "BytesInsert grew the message");
        let declared = u16::from_be_bytes([case.bytes[4], case.bytes[5]]);
        // The MBAP length counts unit_id and the PDU: everything after byte 6.
        assert_eq!(usize::from(declared), case.bytes.len() - 6);

        // A mutation that targets the relation itself: the PDU is untouched
        // and only the length is wrong.
        let cases = structure_cases(
            &tree,
            &spec,
            &FieldPath::new("header.length"),
            GrammarKind::Modbus,
        );
        let plus_one = cases
            .iter()
            .find(|case| case.chain.concat() == "len_desync(header.length,+1)")
            .expect("len_desync(+1) is in the schedule");
        assert_eq!(
            plus_one.bytes,
            vec![0x00, 0x01, 0x00, 0x00, 0x00, 0x07, 0x01, 0x03, 0x00, 0x00, 0x00, 0x01]
        );

        // RESP: a longer element re-satisfies its own length, not the count.
        let rspec = resp_spec();
        let rtree = resp_tree();
        let cases = structure_cases(
            &rtree,
            &rspec,
            &FieldPath::new("args[1].data"),
            GrammarKind::Resp,
        );
        let long = cases
            .iter()
            .find(|case| case.chain.concat() == "long_string(args[1].data,256)")
            .expect("long_string(256) is in the schedule");
        let mut expected = b"*2\r\n$4\r\nPING\r\n$256\r\n".to_vec();
        expected.extend(std::iter::repeat_n(b'A', 256));
        expected.extend_from_slice(b"\r\n");
        assert_eq!(long.bytes, expected);

        // count_mismatch targets the count: every element length survives.
        let cases = structure_cases(&rtree, &rspec, &FieldPath::new("count"), GrammarKind::Resp);
        let plus_one = cases
            .iter()
            .find(|case| case.chain.concat() == "count_mismatch(count,+1)")
            .expect("count_mismatch(+1) is in the schedule");
        assert_eq!(
            plus_one.bytes,
            b"*3\r\n$4\r\nPING\r\n$3\r\nabc\r\n".to_vec(),
            "the count lies; the elements do not"
        );
    }

    #[test]
    fn schedule_is_deterministic() {
        let spec = modbus_spec();
        let tree = modbus_tree();
        let path = FieldPath::new("pdu.address");
        let run = |seed: u64| -> Vec<(Vec<String>, Vec<u8>)> {
            Schedule::new(
                tree.clone(),
                &spec,
                path.clone(),
                GrammarKind::Modbus,
                seed,
                40,
                vec![b"donor".to_vec()],
            )
            .map(|case| (case.chain, case.bytes))
            .collect()
        };

        let first = run(1);
        assert_eq!(first, run(1), "the same inputs yield the same cases");
        assert_eq!(first.len(), 40);

        // pdu.address is `00 00`, so int_boundary's `0` renders the seed and
        // is dropped: three of the four stage-1 cases survive.
        let prefix = first
            .iter()
            .take_while(|(chain, _)| is_stage1(chain))
            .count();
        assert_eq!(prefix, 3);
        assert_eq!(
            first
                .iter()
                .take(prefix)
                .map(|(chain, _)| chain.concat())
                .collect::<Vec<String>>(),
            vec![
                "int_boundary(pdu.address,1)",
                "int_boundary(pdu.address,max)",
                "int_boundary(pdu.address,max-1)",
            ]
        );

        let second = run(2);
        assert_eq!(
            first[..prefix],
            second[..prefix],
            "stage 1 consumes no randomness"
        );
        assert_ne!(
            first[prefix..],
            second[prefix..],
            "stage 2 follows the seed"
        );

        // Indices are contiguous and no case repeats the seed or an earlier
        // case.
        let seed_bytes = tree::render(&tree);
        let mut seen = std::collections::HashSet::new();
        for (i, (_, bytes)) in first.iter().enumerate() {
            assert_ne!(*bytes, seed_bytes, "case {i} is the seed");
            assert!(
                seen.insert(bytes.clone()),
                "case {i} repeats an earlier one"
            );
        }
        let indices: Vec<u32> = Schedule::new(
            tree.clone(),
            &spec,
            path,
            GrammarKind::Modbus,
            1,
            40,
            vec![b"donor".to_vec()],
        )
        .map(|case| case.index)
        .collect();
        assert_eq!(indices, (0..40).collect::<Vec<u32>>());
    }
}
