/// Where the audit log is, how far it had got at session open, and the
/// rules that make the kernel record execs. See docs/design/auditd-source.md,
/// §2 and §3.
///
/// auditd rotates by renaming: `audit.log` → `audit.log.1` → … The inode
/// moves with the content, so the position recorded at session-open
/// (inode + offset) is found again at close even after a rotation.
use serde::{Deserialize, Serialize};
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

/// auditd's configuration file.
pub const AUDITD_CONF: &str = "/etc/audit/auditd.conf";
/// Where `mina install-audit` puts its rules.
pub const RULES_DIR: &str = "/etc/audit/rules.d";
pub const RULES_FILE: &str = "/etc/audit/rules.d/50-mina.rules";
/// The rules' key, as `auditctl -l` prints it.
pub const RULES_KEY: &str = "key=mina";

const DEFAULT_LOG_FILE: &str = "/var/log/audit/audit.log";
/// More rotated files than auditd's `num_logs` allows (999).
const MAX_ROTATED: u32 = 999;

// ── auditd.conf ───────────────────────────────────────────────────────────

/// The settings of auditd.conf mina needs.
#[derive(Debug, PartialEq, Eq)]
pub struct AuditdConf {
    pub log_file: PathBuf,
    /// `write_logs = no`: auditd writes nothing locally.
    pub write_logs: bool,
}

/// Parse auditd.conf (`key = value` lines, `#` comments).
pub fn parse_auditd_conf(text: &str) -> AuditdConf {
    let mut conf = AuditdConf {
        log_file: PathBuf::from(DEFAULT_LOG_FILE),
        write_logs: true,
    };
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        match key.trim() {
            "log_file" => conf.log_file = PathBuf::from(value.trim()),
            "write_logs" => conf.write_logs = !value.trim().eq_ignore_ascii_case("no"),
            _ => {}
        }
    }
    conf
}

// ── Position at session open ──────────────────────────────────────────────

/// How far the audit log had got at session open. Saved to
/// `<run_dir>/<session_key>.audit` by `session-open`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogMark {
    pub inode: u64,
    pub offset: u64,
}

impl LogMark {
    /// The current end of `log_file`.
    pub fn now(log_file: &Path) -> std::io::Result<Self> {
        let meta = std::fs::metadata(log_file)?;
        Ok(Self {
            inode: inode(&meta),
            offset: meta.len(),
        })
    }

    pub fn path(run_dir: &Path, session_key: u32) -> PathBuf {
        run_dir.join(format!("{session_key}.audit"))
    }

    pub fn save(&self, run_dir: &Path, session_key: u32) -> anyhow::Result<()> {
        std::fs::write(
            Self::path(run_dir, session_key),
            serde_json::to_string(self)?,
        )?;
        Ok(())
    }

    /// `None` when the file is missing or unreadable.
    pub fn load(run_dir: &Path, session_key: u32) -> Option<Self> {
        let text = std::fs::read_to_string(Self::path(run_dir, session_key)).ok()?;
        serde_json::from_str(&text).ok()
    }
}

#[cfg(unix)]
fn inode(meta: &std::fs::Metadata) -> u64 {
    std::os::unix::fs::MetadataExt::ino(meta)
}

#[cfg(not(unix))]
fn inode(_meta: &std::fs::Metadata) -> u64 {
    0
}

// ── Reading ───────────────────────────────────────────────────────────────

/// `log_file` and its rotated copies, oldest first: `….3`, `….2`, `….1`,
/// then `log_file`. Compressed copies (`.gz`) are not listed.
pub fn log_files(log_file: &Path) -> Vec<PathBuf> {
    let mut files: Vec<PathBuf> = (1..=MAX_ROTATED)
        .map(|n| PathBuf::from(format!("{}.{n}", log_file.display())))
        .take_while(|p| p.is_file())
        .collect();
    files.reverse();
    if log_file.is_file() {
        files.push(log_file.to_owned());
    }
    files
}

/// The log text written since `mark`, across rotations. The flag is `true`
/// when the start was found; without a mark, or when the marked file has
/// been rotated away, everything still there is returned with `false`.
pub fn read_since(log_file: &Path, mark: Option<LogMark>) -> std::io::Result<(String, bool)> {
    let files = log_files(log_file);
    let start = match mark {
        Some(m) => files
            .iter()
            .position(|f| std::fs::metadata(f).is_ok_and(|meta| inode(&meta) == m.inode))
            .map(|i| (i, m.offset)),
        None => None,
    };
    let (first, offset) = start.unwrap_or((0, 0));
    let mut bytes = Vec::new();
    for (i, file) in files.iter().enumerate().skip(first) {
        let mut f = std::fs::File::open(file)?;
        if i == first && offset > 0 {
            f.seek(SeekFrom::Start(offset))?;
        }
        f.read_to_end(&mut bytes)?;
    }
    Ok((
        String::from_utf8_lossy(&bytes).into_owned(),
        start.is_some(),
    ))
}

// ── Rules ─────────────────────────────────────────────────────────────────

/// The rules file for a kernel architecture (`uname -m`).
///
/// A line the kernel rejects stops `augenrules --load` and every rule after
/// it, so only the ABIs the kernel has are listed: 64- and 32-bit on x86_64
/// and aarch64, 64-bit on other 64-bit kernels, 32-bit on 32-bit ones.
pub fn rules_for_machine(machine: &str) -> String {
    let abis: &[&str] = match machine {
        "x86_64" | "aarch64" => &["b64", "b32"],
        m if m.contains("64") || m == "s390x" => &["b64"],
        _ => &["b32"],
    };
    let mut text = String::from(
        "## mina: record program executions of login sessions (mina(8)).\n\
         ## Installed by `mina install-audit`, removed by `mina uninstall-audit`.\n",
    );
    for abi in abis {
        text.push_str(&format!(
            "-a always,exit -F arch={abi} -S execve,execveat -F auid!=unset -F success=1 -k mina\n"
        ));
    }
    text
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auditd_conf_defaults() {
        let conf = parse_auditd_conf("");
        assert_eq!(conf.log_file, PathBuf::from("/var/log/audit/audit.log"));
        assert!(conf.write_logs);
    }

    #[test]
    fn auditd_conf_values() {
        let text =
            "# comment\nlog_file = /srv/audit/a.log\nwrite_logs = NO\nlog_format = ENRICHED\n";
        let conf = parse_auditd_conf(text);
        assert_eq!(conf.log_file, PathBuf::from("/srv/audit/a.log"));
        assert!(!conf.write_logs);
    }

    #[test]
    fn rules_per_architecture() {
        let amd64 = rules_for_machine("x86_64");
        assert!(amd64.contains("arch=b64") && amd64.contains("arch=b32"));
        assert!(amd64.contains("-S execve,execveat -F auid!=unset -F success=1 -k mina"));
        for m in ["ppc64le", "s390x", "riscv64"] {
            let r = rules_for_machine(m);
            assert!(r.contains("arch=b64") && !r.contains("arch=b32"), "{m}");
        }
        for m in ["armv7l", "i686"] {
            let r = rules_for_machine(m);
            assert!(!r.contains("arch=b64") && r.contains("arch=b32"), "{m}");
        }
    }

    #[test]
    fn rules_set_nothing_global() {
        let r = rules_for_machine("x86_64");
        for flag in ["-D", "-b ", "-f ", "-e ", "--backlog"] {
            assert!(!r.lines().any(|l| l.starts_with(flag)), "{flag}");
        }
    }
}
