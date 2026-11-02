/// Transport layer.
///
/// Responsibility: ship a completed bundle to the nest.
/// Implementations know nothing about what is inside the bundle —
/// they receive a directory path and a destination, and they deliver it.
use anyhow::Result;
use std::path::Path;

pub mod https;
pub mod local;
pub mod ssh;
pub mod tarball;

/// All transport backends implement this trait.
pub trait Transport {
    /// Ship the bundle at `bundle_root` to the configured destination.
    /// Must be atomic from the nest's perspective.
    /// Must retry at least once on transient failure.
    /// Must never block indefinitely — use a reasonable timeout.
    /// Must never panic; return Err on all failures.
    fn ship(&self, bundle_root: &Path) -> Result<()>;
}

/// Ship the bundle, retrying once on transient failure.
///
/// AGENTS.md requirement: "Retry at least once on transient failure before
/// giving up."  A second failure is returned to the caller unchanged.
pub fn ship_with_retry(transport: &dyn Transport, bundle_root: &Path) -> Result<()> {
    match transport.ship(bundle_root) {
        Ok(()) => Ok(()),
        Err(first_err) => {
            eprintln!("mina: ship attempt 1 failed ({first_err:#}), retrying…");
            transport.ship(bundle_root)
        }
    }
}

// ── Fake transport for tests ──────────────────────────────────────────────

#[cfg(test)]
pub mod fake {
    use super::*;
    use std::sync::{Arc, Mutex};

    /// Records every bundle path handed to it. Never fails unless told to.
    pub struct FakeTransport {
        pub shipped: Arc<Mutex<Vec<std::path::PathBuf>>>,
        pub should_fail: bool,
    }

    impl Default for FakeTransport {
        fn default() -> Self {
            Self::new()
        }
    }

    impl FakeTransport {
        pub fn new() -> Self {
            Self {
                shipped: Arc::new(Mutex::new(vec![])),
                should_fail: false,
            }
        }
    }

    impl Transport for FakeTransport {
        fn ship(&self, bundle_root: &Path) -> Result<()> {
            if self.should_fail {
                anyhow::bail!("FakeTransport: simulated failure");
            }
            self.shipped.lock().unwrap().push(bundle_root.to_owned());
            Ok(())
        }
    }
}
