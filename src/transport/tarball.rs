/// Bundle tarball for the HTTPS transport.
///
/// Packs a staged bundle into a gzip-compressed tar whose entries are
/// rooted at `{hostname}/{bundle_name}/` — the same two levels the local
/// transport writes into the nest. The archive is byte-reproducible (sorted
/// entries, normalised metadata, fixed gzip header), so a resend after a
/// retry carries the same digest and the nest can recognise it.
use anyhow::{bail, Context, Result};
use flate2::write::GzEncoder;
use flate2::Compression;
use sha2::{Digest, Sha256};
use std::fmt::Write as _;
use std::fs;
use std::path::Path;
use tar::{EntryType, Header, HeaderMode};

/// Build the gzip tar of `bundle_root`, rooted at `{hostname}/{bundle_name}/`
/// (the last two components of `bundle_root`). Only regular files and
/// directories are archived; anything else (a symlink, a device) is an
/// error, never followed.
pub fn build(bundle_root: &Path) -> Result<Vec<u8>> {
    let bundle_name = bundle_root
        .file_name()
        .context("bundle_root has no final component")?;
    let host_name = bundle_root
        .parent()
        .and_then(Path::file_name)
        .context("bundle_root has no hostname parent directory")?;
    let host = host_name.to_string_lossy();
    let prefix = format!("{host}/{}", bundle_name.to_string_lossy());

    // GzEncoder's default header carries no mtime and no file name.
    let mut tar = tar::Builder::new(GzEncoder::new(Vec::new(), Compression::default()));
    append_dir_entry(&mut tar, &host)?;
    append_tree(&mut tar, bundle_root, &prefix)?;
    let gz = tar
        .into_inner()
        .context("failed to finish bundle tarball")?;
    gz.finish().context("failed to finish bundle tarball")
}

/// `"sha256=" + 64 lowercase hex chars` of `body`.
pub fn digest(body: &[u8]) -> String {
    let mut out = String::from("sha256=");
    for byte in Sha256::digest(body) {
        // Writing to a String cannot fail.
        let _ = write!(out, "{byte:02x}");
    }
    out
}

type TarBuilder = tar::Builder<GzEncoder<Vec<u8>>>;

/// Append directory `dir` as `name/`, then its entries sorted by file name.
fn append_tree(tar: &mut TarBuilder, dir: &Path, name: &str) -> Result<()> {
    append_dir_entry(tar, name)?;
    let mut children = fs::read_dir(dir)
        .with_context(|| format!("failed to read {}", dir.display()))?
        .collect::<std::io::Result<Vec<_>>>()
        .with_context(|| format!("failed to read {}", dir.display()))?;
    children.sort_by_key(|e| e.file_name());
    for child in children {
        let path = child.path();
        let child_name = format!("{name}/{}", child.file_name().to_string_lossy());
        let meta = fs::symlink_metadata(&path)
            .with_context(|| format!("failed to stat {}", path.display()))?;
        if meta.is_dir() {
            append_tree(tar, &path, &child_name)?;
        } else if meta.is_file() {
            let mut header = Header::new_gnu();
            header.set_metadata_in_mode(&meta, HeaderMode::Deterministic);
            let file = fs::File::open(&path)
                .with_context(|| format!("failed to open {}", path.display()))?;
            tar.append_data(&mut header, &child_name, file)
                .with_context(|| format!("failed to archive {}", path.display()))?;
        } else {
            bail!(
                "{} is neither a regular file nor a directory; refusing to archive it",
                path.display()
            );
        }
    }
    Ok(())
}

/// Append an empty directory entry `name/` with deterministic metadata.
fn append_dir_entry(tar: &mut TarBuilder, name: &str) -> Result<()> {
    let mut header = Header::new_gnu();
    header.set_entry_type(EntryType::Directory);
    header.set_mode(0o755);
    header.set_size(0);
    header.set_mtime(0);
    tar.append_data(&mut header, format!("{name}/"), std::io::empty())
        .with_context(|| format!("failed to archive directory {name}"))
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::Read;
    use std::path::{Path, PathBuf};
    use tempfile::TempDir;

    const BUNDLE: &str = "2026-11-02_10-00-00_alice";

    /// `{tmp}/host1/{BUNDLE}/` with session.json, commands.log and
    /// files/etc/hosts. Returns the temp dir and the bundle root.
    fn bundle() -> (TempDir, PathBuf) {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path().join("host1").join(BUNDLE);
        fs::create_dir_all(root.join("files/etc")).unwrap();
        fs::write(root.join("session.json"), "{}\n").unwrap();
        fs::write(root.join("commands.log"), "echo one\n").unwrap();
        fs::write(root.join("files/etc/hosts"), "127.0.0.1 localhost\n").unwrap();
        (tmp, root)
    }

    /// (path, contents) of every entry, in archive order.
    fn entries(body: &[u8]) -> Vec<(String, Vec<u8>)> {
        let mut archive = tar::Archive::new(flate2::read::GzDecoder::new(body));
        archive
            .entries()
            .unwrap()
            .map(|e| {
                let mut e = e.unwrap();
                let path = e.path().unwrap().to_string_lossy().into_owned();
                let mut data = Vec::new();
                e.read_to_end(&mut data).unwrap();
                (path, data)
            })
            .collect()
    }

    fn under_bundle(rel: &str) -> String {
        format!("host1/{BUNDLE}/{rel}")
    }

    #[test]
    fn entries_are_rooted_at_host_and_bundle() {
        let (_tmp, root) = bundle();
        let paths: Vec<String> = entries(&build(&root).unwrap())
            .into_iter()
            .map(|(p, _)| p)
            .collect();
        assert_eq!(
            paths,
            [
                "host1/".to_owned(),
                format!("host1/{BUNDLE}/"),
                under_bundle("commands.log"),
                under_bundle("files/"),
                under_bundle("files/etc/"),
                under_bundle("files/etc/hosts"),
                under_bundle("session.json"),
            ]
        );
    }

    #[test]
    fn entry_contents_match_files() {
        let (_tmp, root) = bundle();
        let hosts = entries(&build(&root).unwrap())
            .into_iter()
            .find(|(p, _)| *p == under_bundle("files/etc/hosts"))
            .unwrap();
        assert_eq!(hosts.1, b"127.0.0.1 localhost\n");
    }

    #[test]
    fn building_twice_is_byte_identical() {
        let (_tmp, root) = bundle();
        let a = build(&root).unwrap();
        let log = fs::File::options()
            .write(true)
            .open(root.join("commands.log"))
            .unwrap();
        log.set_modified(std::time::SystemTime::UNIX_EPOCH).unwrap();
        let b = build(&root).unwrap();
        assert_eq!(a, b);
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlink_in_bundle() {
        let (_tmp, root) = bundle();
        let link = root.join("files/link");
        std::os::unix::fs::symlink("/etc/passwd", &link).unwrap();
        let e = format!("{:#}", build(&root).unwrap_err());
        assert!(e.contains(&link.display().to_string()), "{e}");
    }

    #[test]
    fn digest_of_empty_body() {
        assert_eq!(
            digest(b""),
            "sha256=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn bundle_root_needs_two_components() {
        assert!(build(Path::new("/")).is_err());
    }
}
