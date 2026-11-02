/// Staging directory: where bundles are assembled before they are shipped.
///
/// Responsibility: make sure the staging directory is safe for root to
/// write into, and remove a staged bundle once it has been shipped.
/// Knows nothing about what is inside a bundle, and only the `Transport`
/// trait of the transport layer.
///
/// `session-close` runs as root and the staged bundle can contain copies of
/// files such as `/etc/shadow`. The staging directory must therefore be
/// owned by the user mina runs as (root), closed to group and other, and
/// not a symlink — otherwise another local user could read the copies, or
/// plant symlinks that make root write wherever they point.
use anyhow::{bail, Context, Result};
use std::path::Path;

use crate::transport::{ship_with_retry, Transport};

/// What `check_staging_dir` needs to know about the staging directory,
/// taken from `symlink_metadata` so a symlink is never followed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DirStat {
    pub is_symlink: bool,
    pub is_dir: bool,
    pub uid: u32,
    pub mode: u32,
}

/// Refuse a staging directory that is a symlink, not a directory, not
/// owned by `expected_uid`, or writable by group or other.
///
/// Pure function so it can be tested without root.
pub fn check_staging_dir(path: &Path, stat: DirStat, expected_uid: u32) -> Result<()> {
    if stat.is_symlink {
        bail!(
            "staging directory {} is a symlink; refusing to use it",
            path.display()
        );
    }
    if !stat.is_dir {
        bail!(
            "staging directory {} is not a directory; refusing to use it",
            path.display()
        );
    }
    if stat.uid != expected_uid {
        bail!(
            "staging directory {} is owned by uid {}, not {expected_uid}; refusing to use it",
            path.display(),
            stat.uid
        );
    }
    if stat.mode & 0o022 != 0 {
        bail!(
            "staging directory {} is writable by group or other (mode {:04o}); refusing to use it",
            path.display(),
            stat.mode & 0o7777
        );
    }
    Ok(())
}

/// Create the staging directory (and missing parents) with mode `0700`,
/// then check it with `check_staging_dir` against `expected_uid`.
///
/// An existing directory keeps its mode; it is only checked.
#[cfg(unix)]
pub fn prepare_staging_dir(path: &Path, expected_uid: u32) -> Result<()> {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt};

    if path.symlink_metadata().is_err() {
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(path)
            .with_context(|| format!("failed to create staging directory {}", path.display()))?;
    }
    let meta = path
        .symlink_metadata()
        .with_context(|| format!("failed to stat staging directory {}", path.display()))?;
    let stat = DirStat {
        is_symlink: meta.file_type().is_symlink(),
        is_dir: meta.is_dir(),
        uid: meta.uid(),
        mode: meta.mode(),
    };
    check_staging_dir(path, stat, expected_uid)
}

/// Without unix ownership and modes there is nothing to check: only create
/// the directory.
#[cfg(not(unix))]
pub fn prepare_staging_dir(path: &Path, _expected_uid: u32) -> Result<()> {
    std::fs::create_dir_all(path)
        .with_context(|| format!("failed to create staging directory {}", path.display()))
}

/// Ship the staged bundle (retrying once), then remove it from staging.
///
/// If shipping fails the staged bundle is the only copy: it is kept, and
/// the error says where.
pub fn ship_and_remove(transport: &dyn Transport, bundle_root: &Path) -> Result<()> {
    ship_with_retry(transport, bundle_root).with_context(|| {
        format!(
            "failed to ship bundle; kept in {} for manual recovery",
            bundle_root.display()
        )
    })?;
    std::fs::remove_dir_all(bundle_root).with_context(|| {
        format!(
            "bundle shipped, but could not remove staged copy {}",
            bundle_root.display()
        )
    })
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::fake::FakeTransport;
    use std::fs;
    use std::path::PathBuf;
    use tempfile::TempDir;

    fn ok_stat() -> DirStat {
        DirStat {
            is_symlink: false,
            is_dir: true,
            uid: 0,
            mode: 0o040700,
        }
    }

    fn check(stat: DirStat) -> Result<()> {
        check_staging_dir(Path::new("/var/lib/mina/staging"), stat, 0)
    }

    #[test]
    fn accepts_owned_private_dir() {
        assert!(check(ok_stat()).is_ok());
        assert!(check(DirStat {
            mode: 0o040755,
            ..ok_stat()
        })
        .is_ok());
    }

    #[test]
    fn refuses_symlink() {
        let err = check(DirStat {
            is_symlink: true,
            is_dir: false,
            ..ok_stat()
        })
        .unwrap_err();
        assert!(err.to_string().contains("symlink"), "{err}");
    }

    #[test]
    fn refuses_non_directory() {
        assert!(check(DirStat {
            is_dir: false,
            ..ok_stat()
        })
        .is_err());
    }

    #[test]
    fn refuses_other_owner() {
        let err = check(DirStat {
            uid: 1000,
            ..ok_stat()
        })
        .unwrap_err();
        assert!(err.to_string().contains("uid 1000"), "{err}");
    }

    #[test]
    fn refuses_group_or_other_writable() {
        for mode in [0o040770, 0o040707, 0o041777, 0o040720, 0o040702] {
            assert!(
                check(DirStat { mode, ..ok_stat() }).is_err(),
                "mode {mode:o} should be refused"
            );
        }
    }

    #[cfg(unix)]
    fn current_uid(path: &Path) -> u32 {
        use std::os::unix::fs::MetadataExt;
        fs::metadata(path).unwrap().uid()
    }

    #[cfg(unix)]
    #[test]
    fn creates_missing_staging_dir_0700() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = TempDir::new().unwrap();
        let staging = tmp.path().join("lib/mina/staging");

        prepare_staging_dir(&staging, current_uid(tmp.path())).unwrap();

        for dir in [tmp.path().join("lib/mina"), staging] {
            let mode = fs::metadata(&dir).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o700, "{}", dir.display());
        }
    }

    #[cfg(unix)]
    #[test]
    fn prepare_refuses_symlinked_staging_dir() {
        let tmp = TempDir::new().unwrap();
        let target = tmp.path().join("elsewhere");
        fs::create_dir(&target).unwrap();
        let link = tmp.path().join("staging");
        std::os::unix::fs::symlink(&target, &link).unwrap();

        assert!(prepare_staging_dir(&link, current_uid(tmp.path())).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn prepare_refuses_world_writable_staging_dir() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = TempDir::new().unwrap();
        let staging = tmp.path().join("staging");
        fs::create_dir(&staging).unwrap();
        fs::set_permissions(&staging, fs::Permissions::from_mode(0o1777)).unwrap();

        assert!(prepare_staging_dir(&staging, current_uid(tmp.path())).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn prepare_refuses_dir_owned_by_someone_else() {
        let tmp = TempDir::new().unwrap();
        let other_uid = current_uid(tmp.path()).wrapping_add(1);
        assert!(prepare_staging_dir(tmp.path(), other_uid).is_err());
    }

    fn make_staged_bundle(staging: &Path) -> PathBuf {
        let root = staging.join("web-01").join("2025-06-01_12-00-00_alice");
        fs::create_dir_all(root.join("files/etc")).unwrap();
        fs::write(root.join("session.json"), b"{}").unwrap();
        fs::write(root.join("files/etc/hostname"), b"web-01\n").unwrap();
        root
    }

    #[test]
    fn staged_bundle_removed_after_successful_ship() {
        let staging = TempDir::new().unwrap();
        let root = make_staged_bundle(staging.path());
        let transport = FakeTransport::new();

        ship_and_remove(&transport, &root).unwrap();

        assert_eq!(*transport.shipped.lock().unwrap(), vec![root.clone()]);
        assert!(!root.exists(), "staged bundle should be removed");
    }

    #[test]
    fn staged_bundle_kept_after_failed_ship() {
        let staging = TempDir::new().unwrap();
        let root = make_staged_bundle(staging.path());
        let transport = FakeTransport {
            should_fail: true,
            ..FakeTransport::new()
        };

        let err = ship_and_remove(&transport, &root).unwrap_err();

        assert!(format!("{err:#}").contains("kept in"), "{err:#}");
        assert!(root.join("session.json").exists());
        assert!(root.join("files/etc/hostname").exists());
    }
}
