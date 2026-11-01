//! The check registry: one container the whole catalogue is assembled in
//! (spec D9.3). Task 1 of the T1b plan owns this file.
//!
//! A thread-safe, lock-protected list of `Arc<dyn Check>` tagged by the source
//! that registered them — `"native"`, a lane crate's name, a script's path. It
//! performs no I/O and knows nothing about scheduling: the scripting tier fills
//! it as scripts load and reload, and the engine reads a [`CheckRegistry::snapshot`]
//! when it builds a job's catalogue.
//!
//! One id belongs to one source. A second source claiming an id is refused with
//! [`DuplicateCheck`] rather than silently shadowing the first, because a class
//! is single-sourced by design (spec D8.2: "a class is either native or Rhai,
//! never both"). The source that already owns an id may replace its own entry,
//! which is what a script reload does.

use std::fmt;
use std::sync::{Arc, RwLock};

use crate::traits::Check;

/// One registered check and the source that registered it.
struct Registered {
    /// Who registered it: `"native"`, a lane name, a script path.
    source: String,
    /// The check itself.
    check: Arc<dyn Check>,
}

/// The assembled check catalogue (spec D9.3).
///
/// Cheap to read and safe to share: the engine holds one `Arc<CheckRegistry>`
/// for the life of the process and takes a snapshot per job.
#[derive(Default)]
pub struct CheckRegistry {
    inner: RwLock<Vec<Registered>>,
}

/// A second source tried to register an id another source already owns.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DuplicateCheck {
    /// The check id that is already taken.
    pub id: String,
    /// The source that holds it.
    pub existing_source: String,
}

impl fmt::Display for DuplicateCheck {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "check `{}` is already registered by source `{}`",
            self.id, self.existing_source
        )
    }
}

impl std::error::Error for DuplicateCheck {}

impl CheckRegistry {
    /// An empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register `check` under `source`.
    ///
    /// Replaces the entry when `source` already registered that id (a script
    /// reload); refuses with [`DuplicateCheck`] when a *different* source owns
    /// it, leaving the registry untouched.
    pub fn add(&self, source: &str, check: Arc<dyn Check>) -> Result<(), DuplicateCheck> {
        let id = check.meta().id.clone();
        let mut entries = self.write();

        match entries.iter_mut().find(|e| e.check.meta().id == id) {
            Some(existing) if existing.source == source => {
                existing.check = check;
                Ok(())
            }
            Some(existing) => Err(DuplicateCheck {
                id,
                existing_source: existing.source.clone(),
            }),
            None => {
                entries.push(Registered {
                    source: source.to_string(),
                    check,
                });
                Ok(())
            }
        }
    }

    /// Make `checks` the complete set `source` provides, dropping whatever it
    /// registered before. The reload path for one script file.
    ///
    /// Entries from other sources are untouched. An incoming check whose id
    /// another source owns is **not** inserted — the same rule
    /// [`CheckRegistry::add`] applies — and is reported in the returned list,
    /// one [`DuplicateCheck`] per refused check, so a reload that silently lost
    /// a check cannot look like a clean one. Empty means every check went in.
    #[must_use = "a refused check vanishes from the catalogue; report or log the conflicts"]
    pub fn replace_source(&self, source: &str, checks: Vec<Arc<dyn Check>>) -> Vec<DuplicateCheck> {
        let mut entries = self.write();
        entries.retain(|e| e.source != source);

        let mut refused = Vec::new();
        for check in checks {
            let id = &check.meta().id;
            if let Some(existing) = entries.iter().find(|e| &e.check.meta().id == id) {
                refused.push(DuplicateCheck {
                    id: id.clone(),
                    existing_source: existing.source.clone(),
                });
                continue;
            }
            entries.push(Registered {
                source: source.to_string(),
                check,
            });
        }
        refused
    }

    /// Drop every check `source` registered, returning how many went.
    pub fn remove_source(&self, source: &str) -> usize {
        let mut entries = self.write();
        let before = entries.len();
        entries.retain(|e| e.source != source);
        before - entries.len()
    }

    /// Every registered check, sorted by id.
    ///
    /// Sorted so `scan.checks` and a job's catalogue are stable whatever order
    /// the scripts loaded in.
    pub fn snapshot(&self) -> Vec<Arc<dyn Check>> {
        let mut checks: Vec<Arc<dyn Check>> =
            self.read().iter().map(|e| Arc::clone(&e.check)).collect();
        checks.sort_by(|a, b| a.meta().id.cmp(&b.meta().id));
        checks
    }

    /// How many checks are registered.
    pub fn len(&self) -> usize {
        self.read().len()
    }

    /// Whether no check is registered.
    pub fn is_empty(&self) -> bool {
        self.read().is_empty()
    }

    /// Read the entries, recovering the list if a writer panicked: a poisoned
    /// lock must not take the catalogue — and with it every later scan — down.
    fn read(&self) -> std::sync::RwLockReadGuard<'_, Vec<Registered>> {
        self.inner.read().unwrap_or_else(|e| e.into_inner())
    }

    /// Write the entries, recovering a poisoned lock the same way.
    fn write(&self) -> std::sync::RwLockWriteGuard<'_, Vec<Registered>> {
        self.inner.write().unwrap_or_else(|e| e.into_inner())
    }
}

impl fmt::Debug for CheckRegistry {
    /// Prints the ids and their sources, never the checks themselves.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let entries = self.read();
        let mut listed: Vec<(&str, &str)> = entries
            .iter()
            .map(|e| (e.check.meta().id.as_str(), e.source.as_str()))
            .collect();
        listed.sort_unstable();
        f.debug_struct("CheckRegistry")
            .field("checks", &listed)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::testing::{null_meta, NullCheck};
    use crate::traits::Check;
    use crate::CheckMeta;

    /// A check with the given id, from nowhere in particular.
    fn check(id: &str) -> Arc<dyn Check> {
        Arc::new(NullCheck::new(null_meta(id)))
    }

    #[test]
    fn add_then_snapshot_sorted_by_id() {
        let registry = CheckRegistry::new();

        registry
            .add("s1", check("b-check"))
            .expect("b-check is new");
        registry
            .add("s2", check("a-check"))
            .expect("a-check is new");

        let ids: Vec<String> = registry
            .snapshot()
            .iter()
            .map(|c| c.meta().id.clone())
            .collect();
        assert_eq!(ids, vec!["a-check".to_string(), "b-check".to_string()]);
        assert_eq!(registry.len(), 2);
        assert!(!registry.is_empty());
    }

    #[test]
    fn duplicate_id_across_sources_is_refused() {
        let registry = CheckRegistry::new();
        registry
            .add("s1", check("b-check"))
            .expect("b-check is new");
        registry
            .add("s2", check("a-check"))
            .expect("a-check is new");

        let err = registry
            .add("s3", check("a-check"))
            .expect_err("a-check already belongs to s2");

        assert_eq!(
            err,
            DuplicateCheck {
                id: "a-check".to_string(),
                existing_source: "s2".to_string(),
            }
        );
        assert_eq!(
            err.to_string(),
            "check `a-check` is already registered by source `s2`"
        );
        assert_eq!(registry.len(), 2, "the refused add changed nothing");
    }

    #[test]
    fn same_source_replaces() {
        let registry = CheckRegistry::new();
        registry
            .add("s1", check("b-check"))
            .expect("b-check is new");
        registry
            .add("s2", check("a-check"))
            .expect("a-check is new");

        let mut replacement = null_meta("a-check");
        replacement.description = "the reloaded script".to_string();
        registry
            .add("s2", Arc::new(NullCheck::new(replacement)))
            .expect("the same source may replace its own check");

        assert_eq!(registry.len(), 2);
        let snapshot = registry.snapshot();
        assert_eq!(snapshot[0].meta().id, "a-check");
        assert_eq!(snapshot[0].meta().description, "the reloaded script");
    }

    #[test]
    fn replace_source_swaps_only_that_source() {
        let registry = CheckRegistry::new();
        registry
            .add("s1", check("b-check"))
            .expect("b-check is new");
        registry
            .add("s2", check("a-check"))
            .expect("a-check is new");

        let refused = registry.replace_source("s2", Vec::new());
        assert_eq!(refused, Vec::new(), "nothing to refuse in an empty set");

        let ids: Vec<String> = registry
            .snapshot()
            .iter()
            .map(|c| c.meta().id.clone())
            .collect();
        assert_eq!(ids, vec!["b-check".to_string()]);

        let refused = registry.replace_source("s2", vec![check("c-check"), check("d-check")]);
        assert_eq!(refused, Vec::new(), "c-check and d-check are new ids");
        let ids: Vec<String> = registry
            .snapshot()
            .iter()
            .map(|c| c.meta().id.clone())
            .collect();
        assert_eq!(
            ids,
            vec![
                "b-check".to_string(),
                "c-check".to_string(),
                "d-check".to_string()
            ]
        );
    }

    #[test]
    fn replace_source_reports_ids_another_source_owns() {
        let registry = CheckRegistry::new();
        registry
            .add("s1", check("b-check"))
            .expect("b-check is new");

        let refused = registry.replace_source("s2", vec![check("b-check"), check("c-check")]);

        assert_eq!(
            refused,
            vec![DuplicateCheck {
                id: "b-check".to_string(),
                existing_source: "s1".to_string(),
            }]
        );
        let ids: Vec<String> = registry
            .snapshot()
            .iter()
            .map(|c| c.meta().id.clone())
            .collect();
        assert_eq!(ids, vec!["b-check".to_string(), "c-check".to_string()]);
        assert_eq!(
            registry.len(),
            2,
            "s1 keeps b-check; only c-check joined from s2"
        );
    }

    #[test]
    fn remove_source_drops_only_its_checks_and_counts_them() {
        let registry = CheckRegistry::new();
        registry
            .add("s1", check("b-check"))
            .expect("b-check is new");
        registry
            .add("s2", check("a-check"))
            .expect("a-check is new");
        registry
            .add("s2", check("c-check"))
            .expect("c-check is new");

        assert_eq!(registry.remove_source("s2"), 2);
        assert_eq!(registry.remove_source("s2"), 0, "removing twice is a no-op");

        let ids: Vec<String> = registry
            .snapshot()
            .iter()
            .map(|c| c.meta().id.clone())
            .collect();
        assert_eq!(ids, vec!["b-check".to_string()]);
    }

    #[test]
    fn a_new_registry_is_empty() {
        let registry = CheckRegistry::default();
        assert_eq!(registry.len(), 0);
        assert!(registry.is_empty());
        assert!(registry.snapshot().is_empty());
    }

    /// Tester: `replace_source` documents that an incoming check whose id
    /// another source owns is skipped, never stolen — the single-source rule
    /// `add` enforces, reported back as a [`DuplicateCheck`]. Pinned so a
    /// reload of one script can never hijack a native check's id.
    #[test]
    fn replace_source_does_not_steal_an_id_another_source_owns() {
        let registry = CheckRegistry::new();
        let mut native = null_meta("a-check");
        native.description = "native".to_string();
        registry
            .add("native", Arc::new(NullCheck::new(native)))
            .expect("a-check is new");

        let refused =
            registry.replace_source("script.rhai", vec![check("a-check"), check("z-check")]);
        assert_eq!(
            refused,
            vec![DuplicateCheck {
                id: "a-check".to_string(),
                existing_source: "native".to_string(),
            }]
        );

        let snapshot = registry.snapshot();
        let ids: Vec<&str> = snapshot.iter().map(|c| c.meta().id.as_str()).collect();
        assert_eq!(ids, vec!["a-check", "z-check"]);
        assert_eq!(
            snapshot[0].meta().description,
            "native",
            "a-check still belongs to the native source"
        );
        assert_eq!(
            registry.remove_source("script.rhai"),
            1,
            "only z-check was the script's"
        );
    }

    /// Tester: two checks sharing one id inside a single `replace_source` batch
    /// keep the first; the registry never holds two entries for one id.
    #[test]
    fn replace_source_with_a_duplicate_id_in_one_batch_keeps_the_first() {
        let registry = CheckRegistry::new();
        let mut first = null_meta("dup");
        first.description = "first".to_string();
        let mut second = null_meta("dup");
        second.description = "second".to_string();

        let refused = registry.replace_source(
            "s",
            vec![
                Arc::new(NullCheck::new(first)),
                Arc::new(NullCheck::new(second)),
            ],
        );
        assert_eq!(
            refused,
            vec![DuplicateCheck {
                id: "dup".to_string(),
                existing_source: "s".to_string(),
            }],
            "the second copy is refused by the first, which the same batch owns"
        );

        assert_eq!(registry.len(), 1);
        assert_eq!(registry.snapshot()[0].meta().description, "first");
    }

    /// Tester: operations on a source that never registered are no-ops on an
    /// empty registry — no panic, no phantom entry.
    #[test]
    fn unknown_source_operations_are_no_ops() {
        let registry = CheckRegistry::new();
        assert_eq!(registry.replace_source("ghost", Vec::new()), Vec::new());
        assert_eq!(registry.remove_source("ghost"), 0);
        assert!(registry.is_empty());
        assert_eq!(registry.len(), 0);
    }

    /// Tester: `Debug` lists `(id, source)` pairs sorted, never the checks.
    #[test]
    fn debug_lists_ids_and_sources_sorted() {
        let registry = CheckRegistry::new();
        registry.add("s2", check("b-check")).expect("new");
        registry.add("s1", check("a-check")).expect("new");

        assert_eq!(
            format!("{registry:?}"),
            r#"CheckRegistry { checks: [("a-check", "s1"), ("b-check", "s2")] }"#
        );
    }

    /// Tester: the registry is one `Arc` shared by the scripting tier and the
    /// engine. Eight sources racing to register the same fifty ids end with
    /// exactly one entry per id, every cross-source duplicate refused, and a
    /// snapshot that is sorted and free of repeats.
    #[test]
    fn concurrent_adds_keep_one_entry_per_id() {
        let registry = Arc::new(CheckRegistry::new());
        let workers: Vec<_> = (0..8)
            .map(|t| {
                let registry = Arc::clone(&registry);
                std::thread::spawn(move || {
                    let source = format!("s{t}");
                    (0..50)
                        .filter(|i| registry.add(&source, check(&format!("c-{i:02}"))).is_err())
                        .count()
                })
            })
            .collect();
        let refused: usize = workers
            .into_iter()
            .map(|w| w.join().expect("worker thread"))
            .sum();

        assert_eq!(registry.len(), 50);
        assert_eq!(refused, 7 * 50, "every id was refused to the seven losers");
        let ids: Vec<String> = registry
            .snapshot()
            .iter()
            .map(|c| c.meta().id.clone())
            .collect();
        let mut expected = ids.clone();
        expected.sort();
        expected.dedup();
        assert_eq!(ids, expected, "snapshot is sorted with no repeat");
    }

    /// Tester: the module promises a poisoned lock does not take the catalogue
    /// down. A check whose `meta()` panics while the write lock is held poisons
    /// it; the next reader and writer recover rather than panicking too.
    #[test]
    fn a_poisoned_lock_is_recovered_not_propagated() {
        use std::panic::{catch_unwind, AssertUnwindSafe};
        use std::sync::atomic::{AtomicBool, Ordering};

        /// Panics from `meta()` while `armed`.
        struct Grenade {
            meta: CheckMeta,
            armed: Arc<AtomicBool>,
        }
        impl Check for Grenade {
            fn meta(&self) -> &CheckMeta {
                assert!(!self.armed.load(Ordering::SeqCst), "boom");
                &self.meta
            }
            fn run<'a>(
                &'a self,
                _point: &'a crate::point::InsertionPoint,
                _host: &'a dyn crate::traits::ProbeHost,
            ) -> futures::future::BoxFuture<'a, crate::check::Verdict> {
                unreachable!("never run")
            }
        }

        let armed = Arc::new(AtomicBool::new(false));
        let registry = CheckRegistry::new();
        registry
            .add(
                "s1",
                Arc::new(Grenade {
                    meta: null_meta("grenade"),
                    armed: Arc::clone(&armed),
                }),
            )
            .expect("disarmed, it registers");

        // Arm it: the next `add` scans existing entries under the write lock,
        // calls `meta()` on the grenade and panics with the lock held.
        armed.store(true, Ordering::SeqCst);
        let hook = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));
        let outcome = catch_unwind(AssertUnwindSafe(|| registry.add("s2", check("other"))));
        std::panic::set_hook(hook);
        assert!(outcome.is_err(), "the armed grenade panics under the lock");
        armed.store(false, Ordering::SeqCst);

        // Reader and writer both recover: the interrupted add left no entry.
        assert_eq!(registry.len(), 1);
        assert_eq!(
            registry.snapshot()[0].meta().id,
            "grenade",
            "the catalogue is still readable"
        );
        registry
            .add("s2", check("other"))
            .expect("the write lock is usable again");
        assert_eq!(registry.len(), 2);
    }
}
