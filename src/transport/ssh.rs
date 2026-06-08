/// SSH / rsync transport.
///
/// Ships the bundle by invoking rsync over SSH.
/// Requires a pre-deployed SSH key at /etc/mina/nest_key.
/// The nest's authorized_keys should restrict this key to rsync-only.
use anyhow::{Context, Result};
use std::path::Path;
use std::process::Command;

use super::Transport;

pub struct SshTransport {
    /// e.g. "mina@nest.example.com:/var/mina"
    pub destination: String,
    /// Path to the SSH private key. Default: /etc/mina/nest_key
    pub key_path: String,
}

impl Transport for SshTransport {
    fn ship(&self, bundle_root: &Path) -> Result<()> {
        // bundle_root is e.g. /tmp/mina-staging/web-prod-03/2025-06-01_14-32-05_alice/
        // We ship the host-level directory (one level up) so the nest layout is preserved.
        let host_dir = bundle_root.parent().context("bundle_root has no parent")?;

        let status = Command::new("rsync")
            .args([
                "-a",
                "--quiet",
                "-e",
                &format!(
                    "ssh -i {} -o StrictHostKeyChecking=accept-new",
                    self.key_path
                ),
                &format!("{}/", host_dir.display()),
                &self.destination,
            ])
            .status()
            .context("failed to invoke rsync")?;

        if !status.success() {
            anyhow::bail!("rsync exited with status {}", status);
        }

        Ok(())
    }
}
