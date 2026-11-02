/// Command stream capture.
///
/// Responsibility: collect the timestamped list of commands run during
/// a session. Two sources: shell hook (PROMPT_COMMAND) or auditd.
/// This module does not know about files, bundles, or transport.
use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

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
}

impl CommandEntry {
    pub fn now(command: impl Into<String>) -> Self {
        Self {
            timestamp: Utc::now(),
            cwd: None,
            command: command.into(),
        }
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
    })
}

// ── Auditd source ─────────────────────────────────────────────────────────

/// Reads commands from auditd logs, scoped to the session's process tree.
/// Requires auditd + pam_tty_audit to be configured.
///
/// TODO: implement ausearch integration or direct audit socket reading.
pub struct AuditdSource;

impl CommandSource for AuditdSource {
    fn commands_for_session(&self, _session_pid: u32) -> Result<Vec<CommandEntry>> {
        // TODO: invoke `ausearch --start session --pid <session_pid>`
        // and parse the TTY_INPUT records.
        anyhow::bail!("AuditdSource not yet implemented")
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
