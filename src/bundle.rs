/// Bundle assembly.
///
/// Responsibility: take session metadata, command log, and captured files,
/// and write them into the canonical on-disk layout under a temp directory,
/// ready for the transport layer to ship.
///
/// Layout (see AGENTS.md):
///   {hostname}/{YYYY-MM-DD_HH-MM-SS}_{user}/
///     session.json
///     commands.log
///     files/{mirrored absolute path}

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

use crate::command_log::CommandEntry;
use crate::file_capture::{CaptureOutcome, SkipReason};
use crate::pam_hook::SessionMeta;

// ── Session report (session.json) ─────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize)]
pub struct SessionReport {
    #[serde(flatten)]
    pub meta: SessionMeta,
    pub commands_recorded: usize,
    pub files_captured: usize,
    pub files_skipped: Vec<SkippedFile>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SkippedFile {
    pub path: String,
    pub reason: String,
}

// ── Bundle ────────────────────────────────────────────────────────────────

pub struct Bundle {
    /// Root of the bundle directory, e.g.:
    /// /tmp/mina-staging/web-prod-03/2025-06-01_14-32-05_alice/
    pub root: PathBuf,
}

impl Bundle {
    /// Write the full bundle to disk under `staging_dir`.
    /// Returns the Bundle so the transport layer can locate and ship it.
    pub fn write(
        staging_dir: &Path,
        meta: SessionMeta,
        commands: Vec<CommandEntry>,
        captures: Vec<(PathBuf, CaptureOutcome)>,
    ) -> Result<Self> {
        let bundle_name = bundle_name(&meta);
        let root = staging_dir.join(&meta.host).join(&bundle_name);
        std::fs::create_dir_all(&root)?;

        // commands.log
        let commands_log = commands
            .iter()
            .map(|e| format!("{}\t{}", e.timestamp.format("%H:%M:%S"), e.command))
            .collect::<Vec<_>>()
            .join("\n");
        std::fs::write(root.join("commands.log"), commands_log)?;

        // files/
        let files_dir = root.join("files");
        let mut files_captured = 0usize;
        let mut files_skipped = Vec::new();

        for (path, outcome) in captures {
            match outcome {
                CaptureOutcome::Captured(content) => {
                    let dest = mirror_path(&files_dir, &path);
                    if let Some(parent) = dest.parent() {
                        std::fs::create_dir_all(parent)?;
                    }
                    std::fs::write(&dest, content)?;
                    files_captured += 1;
                }
                CaptureOutcome::Skipped(reason) => {
                    files_skipped.push(SkippedFile {
                        path: path.display().to_string(),
                        reason: describe_skip(&reason),
                    });
                }
            }
        }

        // session.json
        let report = SessionReport {
            meta,
            commands_recorded: commands.len(),
            files_captured,
            files_skipped,
        };
        let json = serde_json::to_string_pretty(&report)?;
        std::fs::write(root.join("session.json"), json)?;

        Ok(Bundle { root })
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────

/// e.g. "2025-06-01_14-32-05_alice"
fn bundle_name(meta: &SessionMeta) -> String {
    format!(
        "{}_{}", 
        meta.started_at.format("%Y-%m-%d_%H-%M-%S"),
        meta.user
    )
}

/// Strip the leading "/" from an absolute path so it can be joined
/// under files_dir without escaping.
fn mirror_path(files_dir: &Path, path: &Path) -> PathBuf {
    let stripped = path.strip_prefix("/").unwrap_or(path);
    files_dir.join(stripped)
}

fn describe_skip(reason: &SkipReason) -> String {
    match reason {
        SkipReason::NotFound      => "not found or not a file".into(),
        SkipReason::Binary        => "binary file".into(),
        SkipReason::TooLarge { size_kb, limit_kb }
            => format!("too large ({size_kb}KB > {limit_kb}KB limit)"),
        SkipReason::ReadError(e)  => format!("read error: {e}"),
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pam_hook::SessionMeta;
    use chrono::Utc;
    use tempfile::TempDir;

    fn fake_meta() -> SessionMeta {
        SessionMeta {
            host: "web-prod-03".into(),
            user: "alice".into(),
            source_ip: Some("10.0.1.42".into()),
            started_at: Utc::now(),
            ended_at: Some(Utc::now()),
        }
    }

    fn fake_commands() -> Vec<CommandEntry> {
        vec![
            CommandEntry::now("cd /etc/nginx"),
            CommandEntry::now("vim nginx.conf"),
        ]
    }

    #[test]
    fn bundle_creates_expected_files() {
        let staging = TempDir::new().unwrap();
        let meta = fake_meta();
        let captures = vec![
            (PathBuf::from("/etc/nginx/nginx.conf"),
             CaptureOutcome::Captured("worker_processes 1;\n".into())),
        ];

        let bundle = Bundle::write(staging.path(), meta, fake_commands(), captures).unwrap();

        assert!(bundle.root.join("session.json").exists());
        assert!(bundle.root.join("commands.log").exists());
        assert!(bundle.root.join("files/etc/nginx/nginx.conf").exists());
    }

    #[test]
    fn session_json_is_valid() {
        let staging = TempDir::new().unwrap();
        let bundle = Bundle::write(staging.path(), fake_meta(), fake_commands(), vec![]).unwrap();
        let json = std::fs::read_to_string(bundle.root.join("session.json")).unwrap();
        let report: SessionReport = serde_json::from_str(&json).unwrap();
        assert_eq!(report.meta.user, "alice");
        assert_eq!(report.commands_recorded, 2);
    }

    #[test]
    fn skipped_files_are_recorded_in_session_json() {
        let staging = TempDir::new().unwrap();
        let captures = vec![
            (PathBuf::from("/etc/ssl/private/key.pem"),
             CaptureOutcome::Skipped(SkipReason::Binary)),
        ];
        let bundle = Bundle::write(staging.path(), fake_meta(), vec![], captures).unwrap();
        let json = std::fs::read_to_string(bundle.root.join("session.json")).unwrap();
        let report: SessionReport = serde_json::from_str(&json).unwrap();
        assert_eq!(report.files_captured, 0);
        assert_eq!(report.files_skipped.len(), 1);
        assert!(report.files_skipped[0].reason.contains("binary"));
    }

    #[test]
    fn commands_log_contains_all_commands() {
        let staging = TempDir::new().unwrap();
        let bundle = Bundle::write(staging.path(), fake_meta(), fake_commands(), vec![]).unwrap();
        let log = std::fs::read_to_string(bundle.root.join("commands.log")).unwrap();
        assert!(log.contains("cd /etc/nginx"));
        assert!(log.contains("vim nginx.conf"));
    }
}
