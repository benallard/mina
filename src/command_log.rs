/// Command stream capture.
///
/// Responsibility: collect the timestamped list of commands run during
/// a session. Two sources: shell hook (PROMPT_COMMAND) or auditd.
/// This module does not know about files, bundles, or transport.
use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

// ── Types ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandEntry {
    pub timestamp: DateTime<Utc>,
    pub command: String,
}

impl CommandEntry {
    pub fn now(command: impl Into<String>) -> Self {
        Self {
            timestamp: Utc::now(),
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
/// (PROMPT_COMMAND / trap DEBUG). The hook writes one line per command:
///
///   <unix_timestamp_ms>\t<command>
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
    let (ts_str, cmd) = line.split_once('\t')?;
    let ts_ms: i64 = ts_str.trim().parse().ok()?;
    let timestamp = DateTime::from_timestamp_millis(ts_ms)?;
    Some(CommandEntry {
        timestamp,
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
    fn shell_hook_source_reads_log_file() {
        let dir = TempDir::new().unwrap();
        let mut f = std::fs::File::create(dir.path().join("1234.cmds")).unwrap();
        writeln!(f, "1717200000000\tcd /etc/nginx").unwrap();
        writeln!(f, "1717200005000\tvim nginx.conf").unwrap();

        let source = ShellHookSource {
            log_dir: dir.path().to_owned(),
        };
        let entries = source.commands_for_session(1234).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[1].command, "vim nginx.conf");
    }
}
