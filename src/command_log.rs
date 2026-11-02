/// Command stream capture.
///
/// Responsibility: collect the timestamped list of commands run during
/// a session. Two sources: shell hook (PROMPT_COMMAND) or auditd.
/// This module does not know about files, bundles, or transport.
pub mod audit_files;
pub mod auditd;

use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use audit_files::LogMark;
use auditd::Scope;

// ── Types ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandEntry {
    pub timestamp: DateTime<Utc>,
    /// Absolute working directory the command ran in, when the source
    /// records it. `None` for old-format hook lines: relative paths in such
    /// a command cannot be resolved and must not be guessed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cwd: Option<PathBuf>,
    pub command: String,
    /// Whether file paths may be taken from this command. Always for the
    /// shell hook (what a person typed). For auditd, only for the session's
    /// own commands: the shell and what it starts directly, not what runs
    /// deeper (package maintainer scripts, script internals). Not written
    /// to `commands.log`.
    #[serde(default = "yes", skip_serializing)]
    pub capture_paths: bool,
}

fn yes() -> bool {
    true
}

impl CommandEntry {
    pub fn now(command: impl Into<String>) -> Self {
        Self {
            timestamp: Utc::now(),
            cwd: None,
            command: command.into(),
            capture_paths: true,
        }
    }
}

// ── Where the commands came from (session.json) ───────────────────────────

/// The source a bundle's commands came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SourceKind {
    /// The shell hook attached: what a person typed at the prompt.
    ShellHook,
    /// Exec records from the audit log.
    Auditd,
    /// Nothing recorded the session's commands; `audit_status` says why.
    #[default]
    None,
}

/// The outcome of consulting the audit log at session close.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AuditStatus {
    /// All execs up to the session's end were read.
    Ok,
    /// Execs were read, but the start or the end may be missing.
    Incomplete,
    /// No exec of the session in the log: rules not loaded, or audit off.
    NotCapturing,
    /// mina's rules file is not installed (`mina install-audit`).
    RulesMissing,
    /// No auditd configuration or no local audit log.
    Unavailable,
    /// The login got no audit session id.
    NoSessionId,
    /// Reading the log failed.
    Error,
}

/// Where a bundle's commands came from, for session.json.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct CommandOrigin {
    /// Whether the shell hook attached to the session (a login shell loaded
    /// it). `false` for `ssh host cmd`, scp and sftp. Missing in bundles
    /// from mina <= 0.2.
    #[serde(default)]
    pub shell_hook: bool,
    /// Missing in bundles from mina <= 0.3.
    #[serde(default)]
    pub command_source: SourceKind,
    /// `None` when the audit log was not consulted (shell hook used).
    #[serde(default)]
    pub audit_status: Option<AuditStatus>,
    /// `[audit] max_commands` was reached; later commands were dropped.
    #[serde(default)]
    pub commands_truncated: bool,
}

/// Which source a session's commands come from. The shell hook wins when it
/// attached: it has the commands as typed, where auditd would give one line
/// per program (every pipe stage, `$(…)`, prompt helpers). Otherwise
/// auditd, if it read anything.
pub fn choose_source(hook_attached: bool, audit: Option<AuditStatus>) -> SourceKind {
    match (hook_attached, audit) {
        (true, _) => SourceKind::ShellHook,
        (false, Some(AuditStatus::Ok | AuditStatus::Incomplete)) => SourceKind::Auditd,
        _ => SourceKind::None,
    }
}

// ── Trait — mockable in tests ─────────────────────────────────────────────

/// Abstraction over a source of command entries for a session.
/// Real implementations: `ShellHookSource`, `AuditdSource`.
/// Test implementation: `FakeCommandSource`.
pub trait CommandSource {
    /// Return all commands recorded for the given session.
    /// `session_pid` is the PID of the login shell, used to scope
    /// auditd queries to this session's process tree.
    fn commands_for_session(&self, session_pid: u32) -> Result<Vec<CommandEntry>>;
}

// ── Shell hook source ─────────────────────────────────────────────────────

/// Reads commands from the per-session log file written by the shell hook
/// (PROMPT_COMMAND / preexec). The hook writes one line per command:
///
///   <unix_timestamp_ms>\t<cwd>\t<command>
///
/// `<cwd>` is the absolute working directory the command ran in. The
/// command itself may contain tabs, so a line is split into at most three
/// fields. Hooks from mina <= 0.2 wrote `<unix_timestamp_ms>\t<command>`;
/// such lines are still accepted: field 2 is only taken as the cwd if it is
/// an absolute path, otherwise everything after the timestamp is the command.
///
/// The file lives at /run/mina/<session_id>.cmds and is created by
/// mina's shell snippet injected via /etc/profile.d/mina.sh.
///
/// The shell hook resolves which session key to use at login time (handling
/// OpenSSH privsep by checking the grandparent PID), so by the time this
/// source is called the file is always named after the session key.
pub struct ShellHookSource {
    pub log_dir: std::path::PathBuf,
}

impl ShellHookSource {
    /// Whether the shell hook attached to the session: a login shell
    /// sourced it and created `<session_key>.cmds`. The hook creates the
    /// file before the first command, so it exists even when nothing was
    /// logged.
    ///
    /// `false` means no shell ever loaded the hook, as for `ssh host cmd`,
    /// scp and sftp: the session had no command stream to record.
    pub fn hook_attached(&self, session_key: u32) -> bool {
        self.log_dir.join(format!("{}.cmds", session_key)).is_file()
    }
}

impl CommandSource for ShellHookSource {
    fn commands_for_session(&self, session_pid: u32) -> Result<Vec<CommandEntry>> {
        let path = self.log_dir.join(format!("{}.cmds", session_pid));
        if !path.exists() {
            return Ok(vec![]);
        }
        let content = std::fs::read_to_string(&path)?;
        let mut entries = Vec::new();
        for line in content.lines() {
            if let Some(entry) = parse_shell_hook_line(line) {
                entries.push(entry);
            }
        }
        Ok(entries)
    }
}

fn parse_shell_hook_line(line: &str) -> Option<CommandEntry> {
    let (ts_str, rest) = line.split_once('\t')?;
    let ts_ms: i64 = ts_str.trim().parse().ok()?;
    let timestamp = DateTime::from_timestamp_millis(ts_ms)?;
    let (cwd, cmd) = match rest.split_once('\t') {
        Some((cwd, cmd)) if cwd.starts_with('/') => (Some(PathBuf::from(cwd)), cmd),
        _ => (None, rest),
    };
    Some(CommandEntry {
        timestamp,
        cwd,
        command: cmd.trim().to_owned(),
        capture_paths: true,
    })
}

// ── Auditd source ─────────────────────────────────────────────────────────

/// Reads the session's execs from the audit log written by auditd, scoped
/// by the audit session id. See docs/design/auditd-source.md.
pub struct AuditdSource {
    pub log_file: PathBuf,
    /// Log position at session open; `None` if session-open could not
    /// record it (the whole log is read, and the result is `Incomplete`).
    pub mark: Option<LogMark>,
    pub scope: Scope,
    /// How long to wait for auditd to write the close marker.
    pub wait: Duration,
}

/// What `AuditdSource::collect` found.
#[derive(Debug)]
pub struct AuditCommands {
    pub entries: Vec<CommandEntry>,
    pub status: AuditStatus,
    pub truncated: bool,
}

/// How often the log is re-read while waiting for the close marker.
const POLL: Duration = Duration::from_millis(50);

impl AuditdSource {
    /// Read the session's commands. auditd writes asynchronously, so the
    /// last execs may not be in the file yet: the log is re-read until the
    /// exec of the running `mina session-close` appears (everything before
    /// it has been written then), or until `wait` has passed.
    pub fn collect(&self) -> Result<AuditCommands> {
        let deadline = Instant::now() + self.wait;
        loop {
            let (text, start_found) = audit_files::read_since(&self.log_file, self.mark)?;
            let selected = auditd::select(&auditd::parse_events(&text), &self.scope);
            if selected.closed || Instant::now() >= deadline {
                let status = match (selected.closed, selected.any) {
                    (true, _) if start_found => AuditStatus::Ok,
                    (_, true) | (true, false) => AuditStatus::Incomplete,
                    (false, false) => AuditStatus::NotCapturing,
                };
                return Ok(AuditCommands {
                    entries: selected.entries,
                    status,
                    truncated: selected.truncated,
                });
            }
            std::thread::sleep(POLL);
        }
    }
}

impl CommandSource for AuditdSource {
    fn commands_for_session(&self, _session_pid: u32) -> Result<Vec<CommandEntry>> {
        Ok(self.collect()?.entries)
    }
}

/// Remove `<run_dir>/<session_key>.audit`, if any.
pub fn remove_log_mark(run_dir: &Path, session_key: u32) -> std::io::Result<()> {
    match std::fs::remove_file(LogMark::path(run_dir, session_key)) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e),
        _ => Ok(()),
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::TempDir;

    // Fake source for use in higher-level integration tests (tests/ tier 2)
    #[allow(dead_code)]
    pub struct FakeCommandSource(pub Vec<CommandEntry>);

    impl CommandSource for FakeCommandSource {
        fn commands_for_session(&self, _pid: u32) -> Result<Vec<CommandEntry>> {
            Ok(self.0.clone())
        }
    }

    #[test]
    fn shell_hook_wins_when_attached() {
        for audit in [None, Some(AuditStatus::Ok), Some(AuditStatus::Error)] {
            assert_eq!(choose_source(true, audit), SourceKind::ShellHook);
        }
    }

    #[test]
    fn auditd_when_it_read_something() {
        assert_eq!(
            choose_source(false, Some(AuditStatus::Ok)),
            SourceKind::Auditd
        );
        assert_eq!(
            choose_source(false, Some(AuditStatus::Incomplete)),
            SourceKind::Auditd
        );
    }

    #[test]
    fn none_otherwise() {
        for audit in [
            None,
            Some(AuditStatus::NotCapturing),
            Some(AuditStatus::RulesMissing),
            Some(AuditStatus::Unavailable),
            Some(AuditStatus::NoSessionId),
            Some(AuditStatus::Error),
        ] {
            assert_eq!(choose_source(false, audit), SourceKind::None, "{audit:?}");
        }
    }

    #[test]
    fn origin_serializes_in_kebab_case() {
        let origin = CommandOrigin {
            shell_hook: false,
            command_source: SourceKind::Auditd,
            audit_status: Some(AuditStatus::NotCapturing),
            commands_truncated: false,
        };
        let json = serde_json::to_value(origin).unwrap();
        assert_eq!(json["command_source"], "auditd");
        assert_eq!(json["audit_status"], "not-capturing");
        let shell = serde_json::to_value(SourceKind::ShellHook).unwrap();
        assert_eq!(shell, "shell-hook");
    }

    #[test]
    fn parses_valid_shell_hook_line() {
        let line = "1717200000000\tvim /etc/nginx/nginx.conf";
        let entry = parse_shell_hook_line(line).unwrap();
        assert_eq!(entry.command, "vim /etc/nginx/nginx.conf");
    }

    #[test]
    fn parses_line_with_cwd() {
        let line = "1717200000000\t/etc/nginx\tvim ./nginx.conf";
        let entry = parse_shell_hook_line(line).unwrap();
        assert_eq!(entry.cwd, Some(PathBuf::from("/etc/nginx")));
        assert_eq!(entry.command, "vim ./nginx.conf");
    }

    #[test]
    fn line_without_cwd_has_no_cwd() {
        let entry = parse_shell_hook_line("1717200000000\tvim ./nginx.conf").unwrap();
        assert_eq!(entry.cwd, None);
        assert_eq!(entry.command, "vim ./nginx.conf");
    }

    #[test]
    fn tab_inside_command_stays_in_command() {
        let line = "1717200000000\t/root\tprintf 'a\tb' > ./out";
        let entry = parse_shell_hook_line(line).unwrap();
        assert_eq!(entry.cwd, Some(PathBuf::from("/root")));
        assert_eq!(entry.command, "printf 'a\tb' > ./out");
    }

    #[test]
    fn old_format_with_tab_in_command_is_not_read_as_cwd() {
        // Field 2 is only a cwd if it is an absolute path.
        let line = "1717200000000\tprintf 'a\tb' > ./out";
        let entry = parse_shell_hook_line(line).unwrap();
        assert_eq!(entry.cwd, None);
        assert_eq!(entry.command, "printf 'a\tb' > ./out");
    }

    #[test]
    fn ignores_malformed_lines() {
        assert!(parse_shell_hook_line("not-a-timestamp\tcmd").is_none());
        assert!(parse_shell_hook_line("no-tab-at-all").is_none());
        assert!(parse_shell_hook_line("").is_none());
    }

    #[test]
    fn shell_hook_source_returns_empty_for_missing_file() {
        let dir = TempDir::new().unwrap();
        let source = ShellHookSource {
            log_dir: dir.path().to_owned(),
        };
        let entries = source.commands_for_session(99999).unwrap();
        assert!(entries.is_empty());
    }

    #[test]
    fn hook_attached_follows_the_log_file() {
        let dir = TempDir::new().unwrap();
        let source = ShellHookSource {
            log_dir: dir.path().to_owned(),
        };
        assert!(!source.hook_attached(1234));
        // An empty log: the hook attached but no command ran.
        std::fs::File::create(dir.path().join("1234.cmds")).unwrap();
        assert!(source.hook_attached(1234));
        assert!(!source.hook_attached(5678));
    }

    #[test]
    fn shell_hook_source_reads_log_file() {
        let dir = TempDir::new().unwrap();
        let mut f = std::fs::File::create(dir.path().join("1234.cmds")).unwrap();
        writeln!(f, "1717200000000\tcd /etc/nginx").unwrap();
        writeln!(f, "1717200005000\t/etc/nginx\tvim nginx.conf").unwrap();

        let source = ShellHookSource {
            log_dir: dir.path().to_owned(),
        };
        let entries = source.commands_for_session(1234).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[1].command, "vim nginx.conf");
        assert_eq!(entries[0].cwd, None);
        assert_eq!(entries[1].cwd, Some(PathBuf::from("/etc/nginx")));
    }
}
