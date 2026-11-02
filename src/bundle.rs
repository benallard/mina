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
///
/// If the bundle name is already taken (two sessions of the same user
/// started in the same second), `_2`, `_3`, … is appended to it.
///
/// `commands.log` has one line per command, each ending in a newline:
///
///   <timestamp>\t<command>
///
/// `<timestamp>` is ISO-8601 in UTC with second precision
/// (`2026-10-30T14:03:46Z`). A line break inside a command (a here-document
/// or multi-line loop, from a source that keeps it) is written as the two
/// characters `\n` (`\r` for a carriage return), so a line is always one
/// whole command. This is for reading and grepping: backslashes are not
/// escaped, so such a command cannot be told apart from one that contained
/// a literal `\n`.
use anyhow::{bail, Context, Result};
use chrono::SecondsFormat;
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
    /// Whether the shell hook attached to the session (a login shell loaded
    /// it), so that commands could be recorded. `false` for `ssh host cmd`,
    /// scp and sftp: no shell loads the hook, and `commands.log` is empty
    /// by design, not because recording failed. Missing in bundles from
    /// mina <= 0.2.
    #[serde(default)]
    pub shell_hook: bool,
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
    /// /var/lib/mina/staging/web-prod-03/2025-06-01_14-32-05_alice/
    pub root: PathBuf,
}

impl Bundle {
    /// Write the full bundle to disk under `staging_dir`.
    /// Returns the Bundle so the transport layer can locate and ship it.
    pub fn write(
        staging_dir: &Path,
        meta: SessionMeta,
        shell_hook: bool,
        commands: Vec<CommandEntry>,
        captures: Vec<(PathBuf, CaptureOutcome)>,
    ) -> Result<Self> {
        let host_dir = staging_dir.join(&meta.host);
        std::fs::create_dir_all(&host_dir)
            .with_context(|| format!("failed to create {}", host_dir.display()))?;
        let root = create_unique_dir(&host_dir, &bundle_name(&meta))?;

        // commands.log
        let commands_log: String = commands.iter().map(commands_log_line).collect();
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
                    if let Some(reason) = describe_skip(&reason) {
                        files_skipped.push(SkippedFile {
                            path: path.display().to_string(),
                            reason,
                        });
                    }
                }
            }
        }

        // session.json
        let report = SessionReport {
            meta,
            shell_hook,
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

/// How many names `create_unique_dir` tries before giving up.
const MAX_NAME_ATTEMPTS: u32 = 100;

/// Create `parent/name`, or `parent/name_2`, `parent/name_3`, … if that is
/// taken, and return the directory created. Never reuses an existing one.
fn create_unique_dir(parent: &Path, name: &str) -> Result<PathBuf> {
    for n in 1..=MAX_NAME_ATTEMPTS {
        let candidate = if n == 1 {
            parent.join(name)
        } else {
            parent.join(format!("{name}_{n}"))
        };
        match std::fs::create_dir(&candidate) {
            Ok(()) => return Ok(candidate),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => {
                return Err(e).with_context(|| format!("failed to create {}", candidate.display()))
            }
        }
    }
    bail!(
        "no free bundle name for {name} in {} after {MAX_NAME_ATTEMPTS} attempts",
        parent.display()
    )
}

/// Strip the leading "/" from an absolute path so it can be joined
/// under files_dir without escaping.
fn mirror_path(files_dir: &Path, path: &Path) -> PathBuf {
    let stripped = path.strip_prefix("/").unwrap_or(path);
    files_dir.join(stripped)
}

/// One `commands.log` line, newline included (see the module docs).
fn commands_log_line(entry: &CommandEntry) -> String {
    let command = entry.command.replace('\n', "\\n").replace('\r', "\\r");
    format!(
        "{}\t{}\n",
        entry.timestamp.to_rfc3339_opts(SecondsFormat::Secs, true),
        command
    )
}

/// The `files_skipped` reason for a skip, or `None` if the path is not
/// listed: excluded paths (`skip_paths`) and directories or other
/// non-regular files were never meant to be captured.
fn describe_skip(reason: &SkipReason) -> Option<String> {
    match reason {
        SkipReason::Excluded | SkipReason::NotAFile => None,
        SkipReason::NotFound => Some("not found".into()),
        SkipReason::Binary => Some("binary file".into()),
        SkipReason::TooLarge { size_kb, limit_kb } => {
            Some(format!("too large ({size_kb}KB > {limit_kb}KB limit)"))
        }
        SkipReason::ReadError(e) => Some(format!("read error: {e}")),
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pam_hook::SessionMeta;
    use chrono::{DateTime, Utc};
    use tempfile::TempDir;

    fn fake_meta() -> SessionMeta {
        SessionMeta {
            host: "web-prod-03".into(),
            user: "alice".into(),
            source_ip: Some("10.0.1.42".into()),
            tty: Some("ssh".into()),
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
        let captures = vec![(
            PathBuf::from("/etc/nginx/nginx.conf"),
            CaptureOutcome::Captured("worker_processes 1;\n".into()),
        )];

        let bundle = Bundle::write(staging.path(), meta, true, fake_commands(), captures).unwrap();

        assert!(bundle.root.join("session.json").exists());
        assert!(bundle.root.join("commands.log").exists());
        assert!(bundle.root.join("files/etc/nginx/nginx.conf").exists());
    }

    #[test]
    fn session_json_is_valid() {
        let staging = TempDir::new().unwrap();
        let bundle =
            Bundle::write(staging.path(), fake_meta(), true, fake_commands(), vec![]).unwrap();
        let json = std::fs::read_to_string(bundle.root.join("session.json")).unwrap();
        let report: SessionReport = serde_json::from_str(&json).unwrap();
        assert_eq!(report.meta.user, "alice");
        assert_eq!(report.commands_recorded, 2);
    }

    #[test]
    fn session_json_round_trips_tty_and_shell_hook() {
        let staging = TempDir::new().unwrap();
        let bundle = Bundle::write(staging.path(), fake_meta(), false, vec![], vec![]).unwrap();
        let json = std::fs::read_to_string(bundle.root.join("session.json")).unwrap();

        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(value["tty"], "ssh");
        assert_eq!(value["shell_hook"], false);
        assert_eq!(value["commands_recorded"], 0);

        let report: SessionReport = serde_json::from_str(&json).unwrap();
        assert_eq!(report.meta.tty.as_deref(), Some("ssh"));
        assert!(!report.shell_hook);
        let again = serde_json::to_string_pretty(&report).unwrap();
        assert_eq!(again, json);
    }

    #[test]
    fn session_json_without_new_fields_still_parses() {
        // A bundle written by mina <= 0.2.
        let json = r#"{"host":"db-01","user":"bob","source_ip":null,
            "started_at":"2026-10-30T14:03:46Z","ended_at":"2026-10-30T14:05:00Z",
            "commands_recorded":0,"files_captured":0,"files_skipped":[]}"#;
        let report: SessionReport = serde_json::from_str(json).unwrap();
        assert!(report.meta.tty.is_none());
        assert!(!report.shell_hook);
    }

    #[test]
    fn skipped_files_are_recorded_in_session_json() {
        let staging = TempDir::new().unwrap();
        let captures = vec![(
            PathBuf::from("/etc/ssl/private/key.pem"),
            CaptureOutcome::Skipped(SkipReason::Binary),
        )];
        let bundle = Bundle::write(staging.path(), fake_meta(), true, vec![], captures).unwrap();
        let json = std::fs::read_to_string(bundle.root.join("session.json")).unwrap();
        let report: SessionReport = serde_json::from_str(&json).unwrap();
        assert_eq!(report.files_captured, 0);
        assert_eq!(report.files_skipped.len(), 1);
        assert!(report.files_skipped[0].reason.contains("binary"));
    }

    #[test]
    fn commands_log_contains_all_commands() {
        let staging = TempDir::new().unwrap();
        let bundle =
            Bundle::write(staging.path(), fake_meta(), true, fake_commands(), vec![]).unwrap();
        let log = std::fs::read_to_string(bundle.root.join("commands.log")).unwrap();
        assert!(log.contains("cd /etc/nginx"));
        assert!(log.contains("vim nginx.conf"));
    }

    #[test]
    fn bundles_with_the_same_name_are_both_kept() {
        let staging = TempDir::new().unwrap();
        let meta = fake_meta();
        let name = bundle_name(&meta);
        let first = Bundle::write(
            staging.path(),
            meta.clone(),
            true,
            vec![CommandEntry::now("echo first")],
            vec![],
        )
        .unwrap();
        let second = Bundle::write(
            staging.path(),
            meta,
            true,
            vec![CommandEntry::now("echo second")],
            vec![],
        )
        .unwrap();

        let host_dir = staging.path().join("web-prod-03");
        assert_eq!(first.root, host_dir.join(&name));
        assert_eq!(second.root, host_dir.join(format!("{name}_2")));
        let first_log = std::fs::read_to_string(first.root.join("commands.log")).unwrap();
        let second_log = std::fs::read_to_string(second.root.join("commands.log")).unwrap();
        assert!(first_log.contains("echo first"));
        assert!(second_log.contains("echo second"));
    }

    #[test]
    fn unique_dir_gives_up_after_max_attempts() {
        let parent = TempDir::new().unwrap();
        std::fs::create_dir(parent.path().join("b")).unwrap();
        for n in 2..=MAX_NAME_ATTEMPTS {
            std::fs::create_dir(parent.path().join(format!("b_{n}"))).unwrap();
        }
        assert!(create_unique_dir(parent.path(), "b").is_err());
    }

    fn entry_at(rfc3339: &str, command: &str) -> CommandEntry {
        CommandEntry {
            timestamp: DateTime::parse_from_rfc3339(rfc3339)
                .unwrap()
                .with_timezone(&Utc),
            cwd: None,
            command: command.into(),
        }
    }

    fn read_log(commands: Vec<CommandEntry>) -> String {
        let staging = TempDir::new().unwrap();
        let bundle = Bundle::write(staging.path(), fake_meta(), true, commands, vec![]).unwrap();
        std::fs::read_to_string(bundle.root.join("commands.log")).unwrap()
    }

    #[test]
    fn commands_log_lines_have_utc_date_and_trailing_newline() {
        let log = read_log(vec![
            entry_at("2026-10-30T23:59:58.900Z", "systemctl status"),
            // Not UTC, and past midnight: written as UTC with its date.
            entry_at("2026-10-31T01:03:46.250+02:00", "printf 'a\tb'"),
        ]);
        assert_eq!(
            log,
            "2026-10-30T23:59:58Z\tsystemctl status\n\
             2026-10-30T23:03:46Z\tprintf 'a\tb'\n"
        );
    }

    #[test]
    fn empty_session_gives_empty_commands_log() {
        assert_eq!(read_log(vec![]), "");
    }

    #[test]
    fn newline_in_command_is_escaped() {
        let log = read_log(vec![
            entry_at("2026-10-30T14:03:46Z", "cat > /tmp/x <<EOF\nline a\r\nEOF"),
            entry_at("2026-10-30T14:03:50Z", "echo last"),
        ]);
        assert_eq!(
            log,
            "2026-10-30T14:03:46Z\tcat > /tmp/x <<EOF\\nline a\\r\\nEOF\n\
             2026-10-30T14:03:50Z\techo last\n"
        );
        assert_eq!(log.lines().count(), 2);
    }

    #[test]
    fn only_real_skips_are_listed() {
        let staging = TempDir::new().unwrap();
        let captures = vec![
            (
                PathBuf::from("/tmp/mina-staging/"),
                CaptureOutcome::Skipped(SkipReason::Excluded),
            ),
            (
                PathBuf::from("/etc/nginx"),
                CaptureOutcome::Skipped(SkipReason::NotAFile),
            ),
            (
                PathBuf::from("/etc/missing.conf"),
                CaptureOutcome::Skipped(SkipReason::NotFound),
            ),
            (
                PathBuf::from("/var/log/big.log"),
                CaptureOutcome::Skipped(SkipReason::TooLarge {
                    size_kb: 600,
                    limit_kb: 512,
                }),
            ),
            (
                PathBuf::from("/etc/shadow"),
                CaptureOutcome::Skipped(SkipReason::ReadError("Permission denied".into())),
            ),
        ];
        let bundle = Bundle::write(staging.path(), fake_meta(), true, vec![], captures).unwrap();
        let json = std::fs::read_to_string(bundle.root.join("session.json")).unwrap();
        let report: SessionReport = serde_json::from_str(&json).unwrap();
        let listed: Vec<(&str, &str)> = report
            .files_skipped
            .iter()
            .map(|s| (s.path.as_str(), s.reason.as_str()))
            .collect();
        assert_eq!(
            listed,
            vec![
                ("/etc/missing.conf", "not found"),
                ("/var/log/big.log", "too large (600KB > 512KB limit)"),
                ("/etc/shadow", "read error: Permission denied"),
            ]
        );
    }
}
