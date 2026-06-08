/// Transport layer.
///
/// Responsibility: ship a completed bundle to the nest.
/// Implementations know nothing about what is inside the bundle —
/// they receive a directory path and a destination, and they deliver it.

use anyhow::Result;
use std::path::Path;

pub mod https;
pub mod ssh;

/// All transport backends implement this trait.
pub trait Transport {
    /// Ship the bundle at `bundle_root` to the configured destination.
    /// Must be atomic from the nest's perspective.
    /// Must retry at least once on transient failure.
    /// Must never block indefinitely — use a reasonable timeout.
    /// Must never panic; return Err on all failures.
    fn ship(&self, bundle_root: &Path) -> Result<()>;
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
