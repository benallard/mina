/// File capture.
///
/// Responsibility: extract candidate file paths from commands, detect
/// whether a file is text, snapshot its content.
/// This module does not know about sessions, bundles, or transport.

use anyhow::Result;
use std::path::{Path, PathBuf};


// ── Path extraction ───────────────────────────────────────────────────────

/// Verbs that strongly suggest their arguments are file paths.
/// This list is intentionally conservative — false negatives are
/// acceptable; false positives are not. See AGENTS.md.
const WRITE_VERBS: &[&str] = &[
    "vim", "vi", "nano", "emacs", "ed", "micro", "helix",
    "cp", "mv", "install",
    "cat", "tee",
    "sed", "awk", "perl", "python", "python3",
    "echo", "printf",
    "chmod", "chown", "chgrp",
    "ln", "truncate",
    "patch",
];

/// Extract candidate file paths from a shell command string.
///
/// Strategy:
/// 1. Tokenise on whitespace.
/// 2. Skip the first token (the verb) if it is in WRITE_VERBS — it is
///    still used as a hint but not itself a path.
/// 3. For remaining tokens: accept if they look like a path and don't
///    look like a flag.
pub fn extract_paths(command: &str) -> Vec<PathBuf> {
    let tokens: Vec<&str> = command.split_whitespace().collect();
    if tokens.is_empty() {
        return vec![];
    }

    let _verb = tokens[0];
    let args = &tokens[1..];

    args.iter()
        .filter(|t| looks_like_path(t))
        .map(|t| PathBuf::from(t))
        .collect()
}

fn looks_like_path(token: &str) -> bool {
    if token.starts_with('-') { return false; }  // flag
    // Reject tokens containing shell metacharacters — these are arguments
    // like 's/foo/bar/g', globs, or quoted strings, not file paths.
    if token.contains(|c| matches!(c, '\'' | '"' | '*' | '?' | '=' | ';' | '&' | '|')) {
        return false;
    }
    if token.starts_with('/') { return true; }   // absolute path
    if token.starts_with("./") || token.starts_with("../") { return true; }
    // Relative paths containing a slash but not starting with one
    if token.contains('/') { return true; }
    false
}

// ── Text detection ────────────────────────────────────────────────────────

const TEXT_PROBE_BYTES: usize = 8 * 1024; // 8KB

/// Returns true if the file looks like UTF-8 text.
/// Reads up to TEXT_PROBE_BYTES and checks for:
///   - Valid UTF-8
///   - No null bytes (strong binary indicator)
pub fn is_text_file(path: &Path) -> bool {
    match std::fs::read(path) {
        Err(_) => false,
        Ok(bytes) => {
            let probe = &bytes[..bytes.len().min(TEXT_PROBE_BYTES)];
            !probe.contains(&0u8) && std::str::from_utf8(probe).is_ok()
        }
    }
}

// ── Snapshot ──────────────────────────────────────────────────────────────

#[derive(Debug)]
pub enum CaptureOutcome {
    /// File content, as a String.
    Captured(String),
    /// File was skipped; reason is logged but not fatal.
    Skipped(SkipReason),
}

#[derive(Debug)]
pub enum SkipReason {
    NotFound,
    Binary,
    TooLarge { size_kb: u64, limit_kb: u64 },
    ReadError(String),
}

/// Attempt to snapshot a file.
/// Returns `CaptureOutcome` — callers decide what to do with skips.
pub fn snapshot(path: &Path, size_limit_kb: u64, skip_prefixes: &[PathBuf]) -> CaptureOutcome {
    // Respect skip_paths
    for prefix in skip_prefixes {
        if path.starts_with(prefix) {
            return CaptureOutcome::Skipped(SkipReason::NotFound);
        }
    }

    let metadata = match std::fs::metadata(path) {
        Err(_) => return CaptureOutcome::Skipped(SkipReason::NotFound),
        Ok(m) => m,
    };

    if !metadata.is_file() {
        return CaptureOutcome::Skipped(SkipReason::NotFound);
    }

    let size_kb = metadata.len() / 1024;
    if size_kb > size_limit_kb {
        return CaptureOutcome::Skipped(SkipReason::TooLarge { size_kb, limit_kb: size_limit_kb });
    }

    if !is_text_file(path) {
        return CaptureOutcome::Skipped(SkipReason::Binary);
    }

    match std::fs::read_to_string(path) {
        Ok(content) => CaptureOutcome::Captured(content),
        Err(e) => CaptureOutcome::Skipped(SkipReason::ReadError(e.to_string())),
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::TempDir;

    // ── extract_paths ──

    #[test]
    fn extracts_absolute_path_from_vim() {
        let paths = extract_paths("vim /etc/nginx/nginx.conf");
        assert_eq!(paths, vec![PathBuf::from("/etc/nginx/nginx.conf")]);
    }

    #[test]
    fn extracts_multiple_paths_from_cp() {
        let paths = extract_paths("cp /tmp/backup.conf /etc/nginx/nginx.conf");
        assert_eq!(paths.len(), 2);
    }

    #[test]
    fn ignores_flags() {
        let paths = extract_paths("sed -i 's/foo/bar/g' /etc/myapp/app.conf");
        assert_eq!(paths, vec![PathBuf::from("/etc/myapp/app.conf")]);
    }

    #[test]
    fn returns_empty_for_no_paths() {
        assert!(extract_paths("systemctl reload nginx").is_empty());
        assert!(extract_paths("ls -la").is_empty());
        assert!(extract_paths("").is_empty());
    }

    #[test]
    fn accepts_relative_paths() {
        let paths = extract_paths("vim ./config/settings.yml");
        assert_eq!(paths, vec![PathBuf::from("./config/settings.yml")]);
    }

    // ── is_text_file ──

    #[test]
    fn detects_text_file() {
        let dir = TempDir::new().unwrap();
        let p = dir.path().join("test.conf");
        std::fs::write(&p, "key = value\n").unwrap();
        assert!(is_text_file(&p));
    }

    #[test]
    fn detects_binary_file() {
        let dir = TempDir::new().unwrap();
        let p = dir.path().join("test.bin");
        std::fs::write(&p, b"\x00\x01\x02\x03binary").unwrap();
        assert!(!is_text_file(&p));
    }

    #[test]
    fn nonexistent_file_is_not_text() {
        assert!(!is_text_file(Path::new("/nonexistent/path/file.txt")));
    }

    // ── snapshot ──

    #[test]
    fn captures_small_text_file() {
        let dir = TempDir::new().unwrap();
        let p = dir.path().join("app.conf");
        std::fs::write(&p, "port = 8080\n").unwrap();
        match snapshot(&p, 512, &[]) {
            CaptureOutcome::Captured(content) => assert!(content.contains("8080")),
            other => panic!("Expected Captured, got {:?}", other),
        }
    }

    #[test]
    fn skips_binary_file() {
        let dir = TempDir::new().unwrap();
        let p = dir.path().join("binary");
        std::fs::write(&p, b"\x00\x01\x02").unwrap();
        assert!(matches!(snapshot(&p, 512, &[]), CaptureOutcome::Skipped(SkipReason::Binary)));
    }

    #[test]
    fn skips_file_over_size_limit() {
        let dir = TempDir::new().unwrap();
        let p = dir.path().join("big.log");
        // Write 2KB of text
        std::fs::write(&p, "x".repeat(2048)).unwrap();
        assert!(matches!(
            snapshot(&p, 1, &[]),
            CaptureOutcome::Skipped(SkipReason::TooLarge { .. })
        ));
    }

    #[test]
    fn skips_paths_under_excluded_prefix() {
        let dir = TempDir::new().unwrap();
        let p = dir.path().join("secret.conf");
        std::fs::write(&p, "password=hunter2\n").unwrap();
        let skips = vec![dir.path().to_owned()];
        assert!(matches!(snapshot(&p, 512, &skips), CaptureOutcome::Skipped(_)));
    }
}
