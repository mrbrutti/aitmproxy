//! The shared TLS-passthrough host list.
//!
//! `PassthroughList` is an `Arc<RwLock<Vec<String>>>` newtype: the
//! `tls.passthrough.*` commands (this crate) mutate it and the
//! `PassthroughModule` (Task 11) reads it to decide, per TLS connection, whether
//! to tunnel a host byte-for-byte instead of decrypting it. Both hold clones of
//! the same `Arc`, so a command's edit is visible to the module immediately.

use std::sync::{Arc, RwLock};

/// A clonable handle to the shared passthrough list. Entries are a host
/// (`pinned.example`) or a leading-wildcard subdomain pattern (`*.example.com`);
/// matching is case-insensitive.
#[derive(Clone, Default)]
pub struct PassthroughList(Arc<RwLock<Vec<String>>>);

impl PassthroughList {
    /// A list seeded from config (`Config.tls.passthrough`). Entries are
    /// lowercased and de-duplicated, preserving first-seen order.
    pub fn new(seed: Vec<String>) -> Self {
        let list = Self::default();
        for host in seed {
            list.add(host);
        }
        list
    }

    /// Whether `host` is covered by some entry — an exact (case-insensitive)
    /// match, or a `*.suffix` entry whose suffix `host` ends with. This is the
    /// read the `PassthroughModule` makes against the `NextLayerHint` SNI.
    pub fn contains_host(&self, host: &str) -> bool {
        let host = host.to_ascii_lowercase();
        self.0
            .read()
            .expect("passthrough list lock poisoned")
            .iter()
            .any(|entry| entry_matches(entry, &host))
    }

    /// The current entries, in insertion order.
    pub fn hosts(&self) -> Vec<String> {
        self.0
            .read()
            .expect("passthrough list lock poisoned")
            .clone()
    }

    /// Add an entry (lowercased). A duplicate is ignored so the list stays a set.
    pub fn add(&self, host: String) {
        let host = host.trim().to_ascii_lowercase();
        if host.is_empty() {
            return;
        }
        let mut guard = self.0.write().expect("passthrough list lock poisoned");
        if !guard.iter().any(|h| h == &host) {
            guard.push(host);
        }
    }

    /// Remove an entry (matched case-insensitively). Returns whether one was
    /// removed, so the command layer can be idempotent like `scope.remove`.
    pub fn remove(&self, host: &str) -> bool {
        let host = host.trim().to_ascii_lowercase();
        let mut guard = self.0.write().expect("passthrough list lock poisoned");
        let before = guard.len();
        guard.retain(|h| h != &host);
        guard.len() != before
    }
}

/// Whether a stored `entry` covers `host` (both already lowercased for `host`;
/// `entry` is lowercased here since stored entries already are, this is defensive).
fn entry_matches(entry: &str, host: &str) -> bool {
    let entry = entry.to_ascii_lowercase();
    match entry.strip_prefix("*.") {
        // `*.example.com` covers `example.com` itself and any subdomain of it.
        Some(suffix) => host == suffix || host.ends_with(&format!(".{suffix}")),
        None => host == entry,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seed_lowercases_and_dedups() {
        let list = PassthroughList::new(vec![
            "Pinned.Example".into(),
            "pinned.example".into(),
            "other.test".into(),
        ]);
        assert_eq!(list.hosts(), vec!["pinned.example", "other.test"]);
    }

    #[test]
    fn exact_match_is_case_insensitive() {
        let list = PassthroughList::new(vec!["pinned.example".into()]);
        assert!(list.contains_host("PINNED.example"));
        assert!(!list.contains_host("other.example"));
    }

    #[test]
    fn wildcard_covers_subdomains_and_apex() {
        let list = PassthroughList::new(vec!["*.example.com".into()]);
        assert!(list.contains_host("api.example.com"));
        assert!(list.contains_host("deep.sub.example.com"));
        assert!(list.contains_host("example.com"));
        assert!(!list.contains_host("notexample.com"));
        assert!(!list.contains_host("example.com.evil.test"));
    }

    #[test]
    fn remove_reports_whether_present() {
        let list = PassthroughList::new(vec!["a.test".into()]);
        assert!(list.remove("A.test"));
        assert!(!list.remove("a.test"));
        assert!(list.hosts().is_empty());
    }
}
