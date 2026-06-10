/// PAM session boundary handling.
///
/// Responsibility: record session open/close, user, source IP, timestamps.
/// Nothing else. This module does not touch files, parse commands, or
/// know about transport.
use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

// ── Trait — mockable in tests ─────────────────────────────────────────────

/// Abstraction over a PAM session event.
/// The real implementation reads PAM environment variables;
/// tests inject a `FakePamSession`.
pub trait PamSession {
    fn user(&self) -> &str;
    fn source_ip(&self) -> Option<&str>;
    fn hostname(&self) -> &str;
    fn opened_at(&self) -> SystemTime;
}

// ── Session metadata ──────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionMeta {
    pub host: String,
    pub user: String,
    pub source_ip: Option<String>,
    pub started_at: DateTime<Utc>,

    /// Filled in at session close.
    pub ended_at: Option<DateTime<Utc>>,
}

impl SessionMeta {
    pub fn open(session: &dyn PamSession) -> Self {
        Self {
            host: session.hostname().to_owned(),
            user: session.user().to_owned(),
            source_ip: session.source_ip().map(str::to_owned),
            started_at: session.opened_at().into(),
            ended_at: None,
        }
    }

    pub fn close(&mut self) {
        self.ended_at = Some(Utc::now());
    }

    pub fn duration_seconds(&self) -> Option<i64> {
        self.ended_at
            .map(|end| (end - self.started_at).num_seconds())
    }
}

// ── Real PAM implementation (reads environment) ───────────────────────────

/// Reads session context from the environment variables that PAM sets
/// when invoking `mina session-open` / `mina session-close` via pam_exec.
pub struct EnvPamSession {
    user: String,
    source_ip: Option<String>,
    hostname: String,
    opened_at: SystemTime,
}

impl EnvPamSession {
    pub fn from_env() -> Result<Self> {
        Ok(Self {
            user: std::env::var("PAM_USER").unwrap_or_else(|_| "unknown".into()),
            source_ip: std::env::var("PAM_RHOST").ok(),
            hostname: hostname()?,
            opened_at: SystemTime::now(),
        })
    }
}

impl PamSession for EnvPamSession {
    fn user(&self) -> &str {
        &self.user
    }
    fn source_ip(&self) -> Option<&str> {
        self.source_ip.as_deref()
    }
    fn hostname(&self) -> &str {
        &self.hostname
    }
    fn opened_at(&self) -> SystemTime {
        self.opened_at
    }
}

fn hostname() -> Result<String> {
    Ok(std::fs::read_to_string("/etc/hostname")
        .unwrap_or_else(|_| "unknown".into())
        .trim()
        .to_owned())
}

// ── Session state (persisted between session-open and session-close) ──────

/// Written to `/run/mina/<session_key>.session` by `mina session-open` and
/// read back by `mina session-close`.
///
/// **Session key** is the PPID of both `pam_exec` invocations (the sshd
/// child process that owns this connection).  It equals `$PPID` inside the
/// login shell, making it a stable identifier shared by all three processes.
#[derive(Debug, Serialize, Deserialize)]
pub struct SessionState {
    /// PID of the sshd child — the stable, shared session identifier.
    pub session_key: u32,
    pub meta: SessionMeta,
}

impl SessionState {
    pub fn new(session: &dyn PamSession, session_key: u32) -> Self {
        Self {
            session_key,
            meta: SessionMeta::open(session),
        }
    }

    /// Write state to `<run_dir>/<session_key>.session`.
    pub fn save(&self, run_dir: &Path) -> Result<()> {
        let path = Self::path(run_dir, self.session_key);
        let json = serde_json::to_string(self)?;
        std::fs::write(&path, json)
            .with_context(|| format!("failed to write session state to {}", path.display()))
    }

    /// Read state from `<run_dir>/<session_key>.session`.
    pub fn load(run_dir: &Path, session_key: u32) -> Result<Self> {
        let path = Self::path(run_dir, session_key);
        let json = std::fs::read_to_string(&path)
            .with_context(|| format!("failed to read session state from {}", path.display()))?;
        serde_json::from_str(&json)
            .with_context(|| format!("failed to parse session state from {}", path.display()))
    }

    /// Delete the state file once the bundle has been shipped.
    pub fn remove(&self, run_dir: &Path) -> Result<()> {
        let path = Self::path(run_dir, self.session_key);
        std::fs::remove_file(&path)
            .with_context(|| format!("failed to remove session state at {}", path.display()))
    }

    /// Canonical path for a given session key.
    pub fn path(run_dir: &Path, session_key: u32) -> PathBuf {
        run_dir.join(format!("{}.session", session_key))
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, SystemTime};
    use tempfile::TempDir;

    struct FakePamSession {
        user: &'static str,
        source_ip: Option<&'static str>,
        hostname: &'static str,
        opened_at: SystemTime,
    }

    impl PamSession for FakePamSession {
        fn user(&self) -> &str {
            self.user
        }
        fn source_ip(&self) -> Option<&str> {
            self.source_ip
        }
        fn hostname(&self) -> &str {
            self.hostname
        }
        fn opened_at(&self) -> SystemTime {
            self.opened_at
        }
    }

    fn fake_session() -> FakePamSession {
        FakePamSession {
            user: "alice",
            source_ip: Some("10.0.1.42"),
            hostname: "web-prod-03",
            opened_at: SystemTime::now() - Duration::from_secs(300),
        }
    }

    #[test]
    fn open_captures_metadata() {
        let s = fake_session();
        let meta = SessionMeta::open(&s);
        assert_eq!(meta.user, "alice");
        assert_eq!(meta.source_ip.as_deref(), Some("10.0.1.42"));
        assert_eq!(meta.host, "web-prod-03");
        assert!(meta.ended_at.is_none());
    }

    #[test]
    fn close_sets_ended_at_and_duration() {
        let s = fake_session();
        let mut meta = SessionMeta::open(&s);
        meta.close();
        assert!(meta.ended_at.is_some());
        // opened ~300s ago, so duration should be positive
        assert!(meta.duration_seconds().unwrap() > 0);
    }

    #[test]
    fn no_source_ip_is_allowed() {
        let s = FakePamSession {
            user: "bob",
            source_ip: None,
            hostname: "db-01",
            opened_at: SystemTime::now(),
        };
        let meta = SessionMeta::open(&s);
        assert!(meta.source_ip.is_none());
    }

    // ── SessionState ──

    fn fake_state(key: u32) -> SessionState {
        SessionState::new(&fake_session(), key)
    }

    #[test]
    fn session_state_round_trips_through_disk() {
        let dir = TempDir::new().unwrap();
        let state = fake_state(12345);
        state.save(dir.path()).unwrap();

        let loaded = SessionState::load(dir.path(), 12345).unwrap();
        assert_eq!(loaded.session_key, 12345);
        assert_eq!(loaded.meta.user, "alice");
        assert_eq!(loaded.meta.source_ip.as_deref(), Some("10.0.1.42"));
        assert!(loaded.meta.ended_at.is_none());
    }

    #[test]
    fn session_state_path_uses_session_key() {
        let path = SessionState::path(Path::new("/run/mina"), 9999);
        assert_eq!(path, PathBuf::from("/run/mina/9999.session"));
    }

    #[test]
    fn session_state_remove_deletes_file() {
        let dir = TempDir::new().unwrap();
        let state = fake_state(42);
        state.save(dir.path()).unwrap();
        assert!(SessionState::path(dir.path(), 42).exists());
        state.remove(dir.path()).unwrap();
        assert!(!SessionState::path(dir.path(), 42).exists());
    }

    #[test]
    fn load_missing_state_returns_error() {
        let dir = TempDir::new().unwrap();
        assert!(SessionState::load(dir.path(), 99999).is_err());
    }
}
