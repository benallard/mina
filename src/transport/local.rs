/// Local filesystem transport.
///
/// Copies the bundle into a local destination directory, preserving the
/// canonical nest layout (`{hostname}/{timestamp}_{user}/`), then marks
/// every file read-only.  No network required.
///
/// Useful when the nest lives on the same machine, or during development
/// and testing when no SSH / HTTPS endpoint is available.
///
/// Atomicity: the bundle is copied to a temporary sibling directory first,
/// then renamed into its final position — so a partial copy never appears
/// at the destination.
use anyhow::{Context, Result};
use std::fs;
use std::path::{Path, PathBuf};

use super::Transport;

pub struct LocalTransport {
    /// Root of the local nest, e.g. "/var/mina".
    pub destination: PathBuf,
}

impl Transport for LocalTransport {
    fn ship(&self, bundle_root: &Path) -> Result<()> {
        // bundle_root  = /tmp/mina-staging/{host}/{timestamp}_{user}/
        // We want to reproduce the same two-level structure under destination.
        let host_name = bundle_root
            .parent()
            .and_then(|p| p.file_name())
            .context("bundle_root has no hostname parent directory")?;
        let bundle_name = bundle_root
            .file_name()
            .context("bundle_root has no final component")?;

        let dest_host_dir = self.destination.join(host_name);
        let final_dest = dest_host_dir.join(bundle_name);

        // Temporary name: same location, underscore-prefixed, so it is
        // invisible to readers that scan for the canonical pattern.
        let tmp_dest = dest_host_dir.join(format!(".tmp_{}", bundle_name.to_string_lossy()));

        fs::create_dir_all(&dest_host_dir)
            .with_context(|| format!("failed to create {}", dest_host_dir.display()))?;

        // 1. Copy into tmp location
        copy_dir_recursive(bundle_root, &tmp_dest).with_context(|| {
            format!(
                "failed to copy bundle from {} to {}",
                bundle_root.display(),
                tmp_dest.display()
            )
        })?;

        // 2. Set all files read-only before the rename so the bundle is
        //    already immutable the moment it becomes visible.
        set_readonly_recursive(&tmp_dest)
            .with_context(|| format!("failed to set read-only on {}", tmp_dest.display()))?;

        // 3. Atomic rename into final position
        fs::rename(&tmp_dest, &final_dest).with_context(|| {
            format!(
                "failed to rename {} → {}",
                tmp_dest.display(),
                final_dest.display()
            )
        })?;

        Ok(())
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────

/// Recursively copy a directory tree from `src` to `dst`.
/// `dst` must not already exist.
fn copy_dir_recursive(src: &Path, dst: &Path) -> Result<()> {
    fs::create_dir_all(dst)?;
    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let src_path = entry.path();
        let dst_path = dst.join(entry.file_name());
        if src_path.is_dir() {
            copy_dir_recursive(&src_path, &dst_path)?;
        } else {
            fs::copy(&src_path, &dst_path)
                .with_context(|| format!("copy {} → {}", src_path.display(), dst_path.display()))?;
        }
    }
    Ok(())
}

/// Recursively mark all files (not directories) as read-only.
fn set_readonly_recursive(dir: &Path) -> Result<()> {
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            set_readonly_recursive(&path)?;
        } else {
            let mut perms = fs::metadata(&path)
                .with_context(|| format!("metadata for {}", path.display()))?
                .permissions();
            perms.set_readonly(true);
            fs::set_permissions(&path, perms)
                .with_context(|| format!("set_permissions on {}", path.display()))?;
        }
    }
    Ok(())
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::TempDir;

    /// Build a minimal fake bundle tree:
    ///   staging/web-01/2025-06-01_12-00-00_alice/
    ///     session.json
    ///     commands.log
    fn make_fake_bundle(staging: &Path) -> PathBuf {
        let root = staging.join("web-01").join("2025-06-01_12-00-00_alice");
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("session.json"), b"{}").unwrap();
        fs::write(root.join("commands.log"), b"12:00:00\tls -la\n").unwrap();
        root
    }

    #[test]
    fn ships_bundle_to_destination() {
        let staging = TempDir::new().unwrap();
        let dest = TempDir::new().unwrap();
        let bundle_root = make_fake_bundle(staging.path());

        let transport = LocalTransport {
            destination: dest.path().to_owned(),
        };
        transport.ship(&bundle_root).unwrap();

        let final_path = dest.path().join("web-01").join("2025-06-01_12-00-00_alice");
        assert!(
            final_path.exists(),
            "bundle directory should exist at destination"
        );
        assert!(final_path.join("session.json").exists());
        assert!(final_path.join("commands.log").exists());
    }

    #[test]
    fn shipped_files_are_read_only() {
        let staging = TempDir::new().unwrap();
        let dest = TempDir::new().unwrap();
        let bundle_root = make_fake_bundle(staging.path());

        LocalTransport {
            destination: dest.path().to_owned(),
        }
        .ship(&bundle_root)
        .unwrap();

        let session_json = dest
            .path()
            .join("web-01")
            .join("2025-06-01_12-00-00_alice")
            .join("session.json");
        let perms = fs::metadata(&session_json).unwrap().permissions();
        assert!(
            perms.readonly(),
            "session.json should be read-only after shipping"
        );
    }

    #[test]
    fn no_partial_bundle_visible_at_final_path() {
        // Verify that the tmp directory is cleaned up and the final dir is present.
        let staging = TempDir::new().unwrap();
        let dest = TempDir::new().unwrap();
        let bundle_root = make_fake_bundle(staging.path());

        LocalTransport {
            destination: dest.path().to_owned(),
        }
        .ship(&bundle_root)
        .unwrap();

        let host_dir = dest.path().join("web-01");
        let entries: Vec<_> = fs::read_dir(&host_dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().to_string())
            .collect();
        // Only the final bundle dir should be present — no .tmp_ prefix
        assert!(
            entries.iter().all(|n| !n.starts_with(".tmp_")),
            "no temporary directories should remain: {entries:?}"
        );
        assert_eq!(entries.len(), 1);
    }
}
