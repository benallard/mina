/// Local filesystem transport.
///
/// Copies the bundle into a local destination directory, preserving the
/// canonical nest layout (`{hostname}/{timestamp}_{user}/`), then makes
/// it read-only and private to the owner: files `0400`, directories `0500`
/// (on unix). The bundle can hold copies of files only root may read.
/// No network required.
///
/// Useful when the nest lives on the same machine, or during development
/// and testing when no SSH / HTTPS endpoint is available.
///
/// Atomicity: the bundle is copied to a temporary sibling directory first,
/// then renamed into its final position — so a partial copy never appears
/// at the destination. The temporary directory is removed if any step
/// fails (after making its directories writable again).
///
/// If a bundle with the same name is already in the nest (two sessions of
/// the same user started in the same second), `_2`, `_3`, … is appended.
use anyhow::{bail, Context, Result};
use std::ffi::OsStr;
use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use super::Transport;

pub struct LocalTransport {
    /// Root of the local nest, e.g. "/var/mina".
    pub destination: PathBuf,
}

impl Transport for LocalTransport {
    fn ship(&self, bundle_root: &Path) -> Result<()> {
        // bundle_root  = /var/lib/mina/staging/{host}/{timestamp}_{user}/
        // We want to reproduce the same two-level structure under destination.
        let host_name = bundle_root
            .parent()
            .and_then(|p| p.file_name())
            .context("bundle_root has no hostname parent directory")?;
        let bundle_name = bundle_root
            .file_name()
            .context("bundle_root has no final component")?;

        let dest_host_dir = self.destination.join(host_name);
        fs::create_dir_all(&dest_host_dir)
            .with_context(|| format!("failed to create {}", dest_host_dir.display()))?;

        // Temporary name: same location, dot-prefixed, so it is invisible to
        // readers that scan for the canonical pattern. The process id keeps
        // two sessions closing at once from sharing it.
        let tmp_dest = dest_host_dir.join(format!(
            ".tmp_{}_{}",
            bundle_name.to_string_lossy(),
            std::process::id()
        ));
        create_private_dir(&tmp_dest)
            .with_context(|| format!("failed to create {}", tmp_dest.display()))?;

        let result = fill_and_publish(bundle_root, &tmp_dest, &dest_host_dir, bundle_name);
        if result.is_err() {
            // Best effort: the error being returned is the one that matters.
            remove_locked_tree(&tmp_dest);
        }
        result
    }
}

/// How many names `fill_and_publish` tries before giving up.
const MAX_NAME_ATTEMPTS: u32 = 100;

/// Copy the bundle into `tmp_dest`, lock it down and rename it to
/// `bundle_name` in `dest_host_dir` — or to `bundle_name_2`, `_3`, … if
/// that name is already taken. Never replaces an existing bundle.
fn fill_and_publish(
    bundle_root: &Path,
    tmp_dest: &Path,
    dest_host_dir: &Path,
    bundle_name: &OsStr,
) -> Result<()> {
    // 1. Copy into tmp location
    copy_dir_recursive(bundle_root, tmp_dest).with_context(|| {
        format!(
            "failed to copy bundle from {} to {}",
            bundle_root.display(),
            tmp_dest.display()
        )
    })?;

    // 2. Lock files and directories before the rename so the bundle is
    //    already immutable the moment it becomes visible. Renaming a
    //    directory within the same parent does not need write permission
    //    on the directory itself.
    lock_tree(tmp_dest).with_context(|| format!("failed to lock {}", tmp_dest.display()))?;

    // 3. Atomic rename into the first free final position
    for n in 1..=MAX_NAME_ATTEMPTS {
        let mut name = bundle_name.to_owned();
        if n > 1 {
            name.push(format!("_{n}"));
        }
        let final_dest = dest_host_dir.join(name);
        // rename() replaces an empty directory, so check first; the error
        // kinds below cover a bundle appearing in between.
        if final_dest.symlink_metadata().is_ok() {
            continue;
        }
        match fs::rename(tmp_dest, &final_dest) {
            Ok(()) => return Ok(()),
            Err(e)
                if matches!(
                    e.kind(),
                    ErrorKind::AlreadyExists | ErrorKind::DirectoryNotEmpty
                ) =>
            {
                continue
            }
            Err(e) => {
                return Err(e).with_context(|| {
                    format!(
                        "failed to rename {} → {}",
                        tmp_dest.display(),
                        final_dest.display()
                    )
                })
            }
        }
    }
    bail!(
        "no free name for bundle {} in {} after {MAX_NAME_ATTEMPTS} attempts",
        bundle_name.to_string_lossy(),
        dest_host_dir.display()
    )
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

/// Mode of every file in a shipped bundle.
const FILE_MODE: u32 = 0o400;
/// Mode of every directory in a shipped bundle.
const DIR_MODE: u32 = 0o500;

/// Create `dir`, accessible to its owner only.
fn create_private_dir(dir: &Path) -> std::io::Result<()> {
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(dir)
}

/// Recursively set files to `FILE_MODE` and directories, `dir` included,
/// to `DIR_MODE`. Symlinks are not followed.
fn lock_tree(dir: &Path) -> Result<()> {
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if entry.file_type()?.is_dir() {
            lock_tree(&path)?;
        } else {
            set_mode(&path, FILE_MODE)?;
        }
    }
    set_mode(dir, DIR_MODE)
}

/// Remove a tree that `lock_tree` may have locked: make its directories
/// writable again first, or the files in them could not be removed.
/// Best effort.
fn remove_locked_tree(dir: &Path) {
    unlock_dirs(dir);
    let _ = fs::remove_dir_all(dir);
}

fn unlock_dirs(dir: &Path) {
    let _ = set_mode(dir, 0o700);
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            if entry.file_type().is_ok_and(|t| t.is_dir()) {
                unlock_dirs(&entry.path());
            }
        }
    }
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .with_context(|| format!("set_permissions on {}", path.display()))
}

/// Without unix modes, only the owner-write bit means something: read-only.
#[cfg(not(unix))]
fn set_mode(path: &Path, mode: u32) -> Result<()> {
    let mut perms = fs::metadata(path)
        .with_context(|| format!("metadata for {}", path.display()))?
        .permissions();
    perms.set_readonly(mode & 0o200 == 0);
    fs::set_permissions(path, perms)
        .with_context(|| format!("set_permissions on {}", path.display()))
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    /// A temporary nest. Shipped bundles have `0500` directories, which
    /// `TempDir` cannot clean up unless the tests run as root.
    struct Nest(TempDir);

    impl Nest {
        fn new() -> Self {
            Nest(TempDir::new().unwrap())
        }

        fn path(&self) -> &Path {
            self.0.path()
        }
    }

    impl Drop for Nest {
        fn drop(&mut self) {
            unlock_dirs(self.0.path());
        }
    }

    /// Build a minimal fake bundle tree:
    ///   staging/web-01/2025-06-01_12-00-00_alice/
    ///     session.json
    ///     commands.log
    fn make_fake_bundle(staging: &Path) -> PathBuf {
        let root = staging.join("web-01").join("2025-06-01_12-00-00_alice");
        fs::create_dir_all(root.join("files/etc")).unwrap();
        fs::write(root.join("session.json"), b"{}").unwrap();
        fs::write(root.join("files/etc/shadow"), b"root:*:19000::::::\n").unwrap();
        fs::write(root.join("commands.log"), b"2025-06-01T12:00:00Z\tls -la\n").unwrap();
        root
    }

    #[test]
    fn ships_bundle_to_destination() {
        let staging = TempDir::new().unwrap();
        let dest = Nest::new();
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
        let dest = Nest::new();
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

    /// Mode bits, not access checks: the tests may run as root.
    #[cfg(unix)]
    fn mode_of(path: &Path) -> u32 {
        use std::os::unix::fs::PermissionsExt;
        fs::symlink_metadata(path).unwrap().permissions().mode() & 0o7777
    }

    #[cfg(unix)]
    #[test]
    fn shipped_bundle_is_private_to_owner() {
        let staging = TempDir::new().unwrap();
        let dest = Nest::new();
        let bundle_root = make_fake_bundle(staging.path());

        LocalTransport {
            destination: dest.path().to_owned(),
        }
        .ship(&bundle_root)
        .unwrap();

        let root = dest.path().join("web-01").join("2025-06-01_12-00-00_alice");
        for file in ["session.json", "commands.log", "files/etc/shadow"] {
            assert_eq!(mode_of(&root.join(file)), 0o400, "{file}");
        }
        for dir in ["", "files", "files/etc"] {
            assert_eq!(mode_of(&root.join(dir)), 0o500, "{dir:?}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn locked_tree_can_be_removed() {
        let tmp = TempDir::new().unwrap();
        let tree = tmp.path().join(".tmp_bundle");
        fs::create_dir_all(tree.join("files/etc")).unwrap();
        fs::write(tree.join("files/etc/shadow"), b"x").unwrap();
        lock_tree(&tree).unwrap();
        assert_eq!(mode_of(&tree.join("files/etc")), 0o500);

        remove_locked_tree(&tree);

        assert!(!tree.exists());
    }

    #[test]
    fn no_partial_bundle_visible_at_final_path() {
        // Verify that the tmp directory is cleaned up and the final dir is present.
        let staging = TempDir::new().unwrap();
        let dest = Nest::new();
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

    fn tmp_entries(host_dir: &Path) -> Vec<String> {
        fs::read_dir(host_dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().to_string())
            .filter(|n| n.starts_with(".tmp_"))
            .collect()
    }

    #[test]
    fn existing_bundle_with_the_same_name_is_kept() {
        let staging = TempDir::new().unwrap();
        let dest = Nest::new();
        let bundle_root = make_fake_bundle(staging.path());
        let host_dir = dest.path().join("web-01");
        let existing = host_dir.join("2025-06-01_12-00-00_alice");
        fs::create_dir_all(&existing).unwrap();
        fs::write(existing.join("session.json"), b"{\"first\": true}").unwrap();

        LocalTransport {
            destination: dest.path().to_owned(),
        }
        .ship(&bundle_root)
        .unwrap();

        assert_eq!(
            fs::read(existing.join("session.json")).unwrap(),
            b"{\"first\": true}"
        );
        let second = host_dir.join("2025-06-01_12-00-00_alice_2");
        assert_eq!(fs::read(second.join("session.json")).unwrap(), b"{}");
        assert!(second.join("commands.log").exists());
        assert!(tmp_entries(&host_dir).is_empty());
    }

    #[test]
    fn failed_rename_leaves_no_tmp_dir() {
        let staging = TempDir::new().unwrap();
        let dest = Nest::new();
        let bundle_root = make_fake_bundle(staging.path());
        let host_dir = dest.path().join("web-01");
        fs::create_dir_all(host_dir.join("2025-06-01_12-00-00_alice")).unwrap();
        for n in 2..=MAX_NAME_ATTEMPTS {
            fs::create_dir(host_dir.join(format!("2025-06-01_12-00-00_alice_{n}"))).unwrap();
        }

        let result = LocalTransport {
            destination: dest.path().to_owned(),
        }
        .ship(&bundle_root);

        assert!(result.is_err());
        assert!(tmp_entries(&host_dir).is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn failed_copy_leaves_no_tmp_dir() {
        let staging = TempDir::new().unwrap();
        let dest = Nest::new();
        let bundle_root = make_fake_bundle(staging.path());
        // A dangling symlink cannot be copied, whoever runs the test.
        std::os::unix::fs::symlink("/nonexistent/mina-test", bundle_root.join("broken")).unwrap();

        let result = LocalTransport {
            destination: dest.path().to_owned(),
        }
        .ship(&bundle_root);

        assert!(result.is_err());
        let host_dir = dest.path().join("web-01");
        assert!(tmp_entries(&host_dir).is_empty());
        assert!(!host_dir.join("2025-06-01_12-00-00_alice").exists());
    }
}
