//! Tier 2: the auditd command source against audit logs in a temp dir.
//!
//! The fixtures in tests/fixtures/audit/ follow the documented record format
//! (see docs/design/auditd-source.md); they are to be replaced by recordings
//! from a test VM, anonymised, during the Tier-3 run. No auditd needed.

use std::path::Path;
use std::time::{Duration, Instant};

use mina_lib::command_log::audit_files::{read_since, LogMark};
use mina_lib::command_log::auditd::Scope;
use mina_lib::command_log::{AuditStatus, AuditdSource};
use tempfile::TempDir;

const SSH_CMD: &str = include_str!("fixtures/audit/ssh-cmd.log");
const SFTP: &str = include_str!("fixtures/audit/sftp.log");
const SUDO: &str = include_str!("fixtures/audit/sudo-apt.log");

/// Scope of the fixtures' session: ses 7, sshd's PAM process 4100,
/// `mina session-close` is pid 4999.
fn scope() -> Scope {
    Scope {
        ses: 7,
        session_key: 4100,
        drop_pam_children: true,
        own_exe: b"/usr/bin/mina".to_vec(),
        close_pid: 4999,
        close_since: 0,
        since: 0,
        max_commands: 10_000,
    }
}

/// Write `text` as a new audit log, with the mark taken before it.
fn marked_log(dir: &TempDir, text: &str) -> (std::path::PathBuf, LogMark) {
    let log = dir.path().join("audit.log");
    std::fs::write(&log, "").unwrap();
    let mark = LogMark::now(&log).unwrap();
    std::fs::write(&log, text).unwrap();
    (log, mark)
}

fn source(log: &Path, mark: Option<LogMark>, wait_ms: u64) -> AuditdSource {
    AuditdSource {
        log_file: log.to_owned(),
        mark,
        scope: scope(),
        wait: Duration::from_millis(wait_ms),
    }
}

fn commands(found: &mina_lib::command_log::AuditCommands) -> Vec<&str> {
    found.entries.iter().map(|e| e.command.as_str()).collect()
}

/// The fixture without its last exec (the close marker).
fn without_close_marker(text: &str) -> String {
    let marker = text
        .lines()
        .find(|l| l.contains("pid=4999 "))
        .and_then(|l| l.split("): ").next())
        .expect("fixture has a close marker")
        .split("msg=")
        .nth(1)
        .expect("stamp")
        .to_owned();
    text.lines()
        .filter(|l| !l.contains(&marker))
        .map(|l| format!("{l}\n"))
        .collect()
}

#[test]
fn ssh_command_session() {
    let dir = TempDir::new().unwrap();
    let log = dir.path().join("audit.log");
    std::fs::write(&log, SSH_CMD).unwrap();

    let found = source(&log, None, 0).collect().unwrap();
    // Read from the start (no mark): the start is not known.
    assert_eq!(found.status, AuditStatus::Incomplete);
    assert_eq!(
        commands(&found),
        ["bash -c 'cat /etc/hostname'", "cat /etc/hostname"]
    );
    // Without the session's start, the shell cannot be identified.
    assert!(found.entries.iter().all(|e| !e.capture_paths));

    let (log, mark) = marked_log(&dir, SSH_CMD);
    let found = source(&log, Some(mark), 0).collect().unwrap();
    assert_eq!(found.status, AuditStatus::Ok);
    assert!(found.entries.iter().all(|e| e.capture_paths));
}

#[test]
fn reads_only_what_came_after_the_mark() {
    let dir = TempDir::new().unwrap();
    let log = dir.path().join("audit.log");
    std::fs::write(&log, SFTP).unwrap();
    let mark = LogMark::now(&log).unwrap();
    std::fs::write(&log, format!("{SFTP}{SSH_CMD}")).unwrap();

    let found = source(&log, Some(mark), 0).collect().unwrap();
    assert_eq!(found.status, AuditStatus::Ok);
    assert_eq!(
        commands(&found),
        ["bash -c 'cat /etc/hostname'", "cat /etc/hostname"]
    );
}

#[test]
fn sftp_session_and_pam_helpers() {
    let dir = TempDir::new().unwrap();
    let log = dir.path().join("audit.log");
    std::fs::write(&log, SFTP).unwrap();
    let found = source(&log, None, 0).collect().unwrap();
    // motd's run-parts/uname and mina session-open are gone.
    assert_eq!(
        commands(&found),
        [
            "sh -c /usr/lib/openssh/sftp-server",
            "/usr/lib/openssh/sftp-server"
        ]
    );
}

#[test]
fn sudo_and_maintainer_scripts() {
    let dir = TempDir::new().unwrap();
    let (log, mark) = marked_log(&dir, SUDO);
    let found = source(&log, Some(mark), 0).collect().unwrap();
    let flags: Vec<(&str, bool)> = found
        .entries
        .iter()
        .map(|e| (e.command.as_str(), e.capture_paths))
        .collect();
    assert_eq!(
        flags,
        [
            ("bash -c 'sudo apt-get install -y nginx'", true),
            ("sudo apt-get install -y nginx", true),
            // sudo's pty monitor forked it and never exec'd: untraceable.
            ("apt-get install -y nginx", false),
            ("/usr/bin/dpkg --configure nginx", false),
            (
                "cp /usr/share/nginx/nginx.conf /etc/nginx/nginx.conf",
                false
            ),
        ]
    );
}

#[test]
fn rotation_between_open_and_close() {
    let dir = TempDir::new().unwrap();
    let log = dir.path().join("audit.log");
    std::fs::write(&log, "type=DAEMON_START msg=audit(1.000:1): op=start\n").unwrap();
    let mark = LogMark::now(&log).unwrap();
    // The session's first records go into the marked file, then auditd
    // rotates and writes the rest into a new audit.log.
    let (first, rest) = SSH_CMD.split_at(SSH_CMD.len() / 2);
    let cut = first.rfind('\n').unwrap() + 1;
    let (first, rest) = (&SSH_CMD[..cut], format!("{}{rest}", &first[cut..]));
    std::fs::OpenOptions::new()
        .append(true)
        .open(&log)
        .and_then(|mut f| std::io::Write::write_all(&mut f, first.as_bytes()))
        .unwrap();
    std::fs::rename(&log, dir.path().join("audit.log.1")).unwrap();
    std::fs::write(&log, rest).unwrap();

    let found = source(&log, Some(mark), 0).collect().unwrap();
    assert_eq!(found.status, AuditStatus::Ok);
    assert_eq!(commands(&found).len(), 2);
}

#[test]
fn marked_file_rotated_away_is_incomplete() {
    let dir = TempDir::new().unwrap();
    let log = dir.path().join("audit.log");
    std::fs::write(&log, "old\n").unwrap();
    let mark = LogMark::now(&log).unwrap();
    // Rotated past num_logs: no longer among audit.log{,.N}. It is moved,
    // not deleted, so the new file cannot reuse its inode.
    std::fs::rename(&log, dir.path().join("gone")).unwrap();
    std::fs::write(&log, SSH_CMD).unwrap();

    let (_, start_found) = read_since(&log, Some(&mark)).unwrap();
    // Unix: a new file has a new inode. Elsewhere the test is moot.
    if cfg!(unix) {
        assert!(!start_found);
        let found = source(&log, Some(mark), 0).collect().unwrap();
        assert_eq!(found.status, AuditStatus::Incomplete);
    }
}

#[test]
fn waits_for_the_close_marker() {
    let dir = TempDir::new().unwrap();
    let log = dir.path().join("audit.log");
    std::fs::write(&log, "").unwrap();
    let mark = LogMark::now(&log).unwrap();
    std::fs::write(&log, without_close_marker(SSH_CMD)).unwrap();

    let writer = {
        let log = log.clone();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(150));
            std::fs::write(&log, SSH_CMD).unwrap();
        })
    };
    let found = source(&log, Some(mark), 5000).collect().unwrap();
    writer.join().unwrap();
    assert_eq!(found.status, AuditStatus::Ok);
    assert_eq!(commands(&found).len(), 2);
}

#[test]
fn gives_up_after_the_wait() {
    let dir = TempDir::new().unwrap();
    let log = dir.path().join("audit.log");
    std::fs::write(&log, "").unwrap();
    let mark = LogMark::now(&log).unwrap();
    std::fs::write(&log, without_close_marker(SSH_CMD)).unwrap();

    let started = Instant::now();
    let found = source(&log, Some(mark), 200).collect().unwrap();
    assert!(started.elapsed() >= Duration::from_millis(200));
    assert!(started.elapsed() < Duration::from_secs(3));
    assert_eq!(found.status, AuditStatus::Incomplete);
    assert_eq!(commands(&found).len(), 2);
}

#[test]
fn nothing_of_the_session_is_not_capturing() {
    let dir = TempDir::new().unwrap();
    let log = dir.path().join("audit.log");
    std::fs::write(&log, "").unwrap();
    let mark = LogMark::now(&log).unwrap();
    std::fs::write(&log, "type=DAEMON_START msg=audit(1.000:1): op=start\n").unwrap();

    let found = source(&log, Some(mark), 100).collect().unwrap();
    assert_eq!(found.status, AuditStatus::NotCapturing);
    assert!(found.entries.is_empty());
}

#[test]
fn missing_log_finds_nothing() {
    let dir = TempDir::new().unwrap();
    let log = dir.path().join("audit.log");
    let found = source(&log, None, 0).collect().unwrap();
    // No files at all: nothing to read, nothing found.
    assert_eq!(found.status, AuditStatus::NotCapturing);
}

// ── Recordings from a Debian 13 test host (auditd 4.0.2, OpenSSH 10.0) ──
//
// `ausearch --session N --raw`, keeping only SYSCALL, EXECVE, CWD, PATH,
// PROCTITLE and EOE records (no addresses or host names). ENRICHED format.
// pam_exec runs mina twice at open and twice at close; pam_motd runs
// run-parts under the same session id.

fn recorded(ses: u32, session_key: u32, close_pid: u32) -> Scope {
    Scope {
        ses,
        session_key,
        close_pid,
        ..scope()
    }
}

fn collect_recorded(text: &str, scope: Scope) -> mina_lib::command_log::AuditCommands {
    let dir = TempDir::new().unwrap();
    let (log, mark) = marked_log(&dir, text);
    let source = AuditdSource {
        scope,
        ..source(&log, Some(mark), 0)
    };
    source.collect().unwrap()
}

#[test]
fn recorded_ssh_command() {
    let found = collect_recorded(
        include_str!("fixtures/audit/recorded/ssh-cmd.log"),
        recorded(56, 38424, 38485),
    );
    assert_eq!(
        commands(&found),
        ["bash -c 'cat /etc/hostname'", "cat /etc/hostname"]
    );
    assert!(found.entries.iter().all(|e| e.capture_paths));
    assert_eq!(found.entries[1].cwd, Some("/root".into()));
}

#[test]
fn recorded_scp_upload() {
    let found = collect_recorded(
        include_str!("fixtures/audit/recorded/scp.log"),
        recorded(26, 30103, 30116),
    );
    assert_eq!(
        commands(&found),
        [
            "bash -c /usr/lib/openssh/sftp-server",
            "/usr/lib/openssh/sftp-server"
        ]
    );
}

#[test]
fn recorded_sudo_and_apt() {
    let found = collect_recorded(
        include_str!("fixtures/audit/recorded/sudo-apt.log"),
        recorded(24, 29408, 29593),
    );
    assert_eq!(found.entries.len(), 41);
    // Only the shell and what it started directly; sudo's use_pty monitor
    // makes everything under sudo untraceable.
    let candidates: Vec<&str> = found
        .entries
        .iter()
        .filter(|e| e.capture_paths)
        .map(|e| e.command.as_str())
        .collect();
    assert_eq!(
        candidates,
        [
            "bash -c 'sudo -n cp /etc/hostname /etc/hostname.mina-test; sudo -n apt-get install -y -qq --reinstall nano >/dev/null 2>&1'",
            "sudo -n cp /etc/hostname /etc/hostname.mina-test",
            "sudo -n apt-get install -y -qq --reinstall nano",
        ]
    );
    // sudo's own PAM stack runs mina too (PAM_SERVICE=sudo): never a command.
    assert!(!found
        .entries
        .iter()
        .any(|e| e.command.starts_with("/usr/bin/mina")));
}
