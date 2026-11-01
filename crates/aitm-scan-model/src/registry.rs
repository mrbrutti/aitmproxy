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
    /// Entries from other sources are untouched, and an incoming check whose id
    /// another source owns is **not** inserted — the same rule [`CheckRegistry::add`]
    /// applies, with no error to return. A caller that must know which ids were
    /// refused adds them one by one.
    pub fn replace_source(&self, source: &str, checks: Vec<Arc<dyn Check>>) {
        let mut entries = self.write();
        entries.retain(|e| e.source != source);

        for check in checks {
            let id = &check.meta().id;
            if entries.iter().any(|e| &e.check.meta().id == id) {
                continue;
            }
            entries.push(Registered {
                source: source.to_string(),
                check,
            });
        }
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

        registry.replace_source("s2", Vec::new());

        let ids: Vec<String> = registry
            .snapshot()
            .iter()
            .map(|c| c.meta().id.clone())
            .collect();
        assert_eq!(ids, vec!["b-check".to_string()]);

        registry.replace_source("s2", vec![check("c-check"), check("d-check")]);
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
}
