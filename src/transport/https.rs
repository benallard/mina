/// HTTPS transport.
///
/// Ships the bundle by POSTing a gzipped tarball to the nest endpoint.
/// TLS only — plain HTTP is rejected at config validation time.
///
/// TODO: implement using a minimal HTTP client (ureq or curl invocation).
///       Keeping this as a stub until the SSH transport is proven.
use anyhow::Result;
use std::path::Path;

use super::Transport;

pub struct HttpsTransport {
    /// e.g. "https://nest.example.com/ingest"
    pub endpoint: String,
}

impl Transport for HttpsTransport {
    fn ship(&self, _bundle_root: &Path) -> Result<()> {
        // TODO:
        // 1. tar -czf /tmp/mina-bundle-<uuid>.tar.gz -C bundle_root .
        // 2. POST the tarball to self.endpoint
        // 3. Verify 200 OK
        // 4. Clean up temp tarball
        anyhow::bail!("HTTPS transport not yet implemented")
    }
}
