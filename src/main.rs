use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use std::path::Path;

use mina_lib::pam_hook::{EnvPamSession, SessionState};

/// Directory where session state files and command logs are stored.
/// Created at boot by the tmpfiles.d entry installed by `mina install-pam`.
const RUN_DIR: &str = "/run/mina";

/// Mina — passive SSH session auditor.
///
/// Watches, records, and ships. It does not block, alert, or decide.
#[derive(Parser)]
#[command(
    name = "mina",
    version,
    about = "Passive SSH session auditor — watches, records, reports"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Install PAM hooks, shell profile snippet, and tmpfiles.d entry.
    ///
    /// Writes pam_exec lines into /etc/pam.d/sshd, deploys
    /// /etc/profile.d/mina.sh, creates /etc/mina/, and registers
    /// /run/mina with systemd-tmpfiles.
    InstallPam,

    /// Remove all PAM hooks and shell profile snippets installed by mina.
    ///
    /// Reverses every change made by install-pam. Safe to run multiple times.
    UninstallPam,

    /// Install auditd rules for command capture (alternative to shell hook).
    ///
    /// Adds an auditd rule that records execve calls and configures
    /// pam_tty_audit. Use when the shell hook is not reliable enough.
    InstallAudit,

    /// Record session open. Called by PAM via pam_exec at login.
    ///
    /// Persists session metadata (user, source IP, hostname, start time,
    /// shell PID) to /run/mina/<ppid>.session so that session-close can
    /// pick it up later.
    SessionOpen,

    /// Record session close and ship the bundle. Called by PAM via pam_exec at logout.
    ///
    /// Reads the persisted session state, harvests the command log,
    /// extracts and snapshots referenced files, assembles the bundle,
    /// ships it via the configured transport, and cleans up.
    SessionClose,
}

fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let cli = Cli::parse();

    match cli.command {
        Command::InstallPam => cmd_install_pam(),
        Command::UninstallPam => cmd_uninstall_pam(),
        Command::InstallAudit => cmd_install_audit(),
        Command::SessionOpen => cmd_session_open(),
        Command::SessionClose => cmd_session_close(),
    }
}

// ── Subcommand handlers ────────────────────────────────────────────────────
// Each lives in its own function so it can grow into a separate module
// (src/cmd/install_pam.rs etc.) without touching the dispatch table.

// ── Session key ───────────────────────────────────────────────────────────

/// Return the session key for the current process: the PPID read from
/// `/proc/self/stat`.
///
/// The session key is the PID of the sshd child process that owns this
/// connection.  It is the PPID of both `pam_exec` invocations (`session-open`
/// and `session-close`) and equals `$PPID` inside the login shell, giving all
/// three processes a stable shared identifier without any extra IPC.
#[cfg(target_os = "linux")]
fn session_key() -> Result<u32> {
    // /proc/self/stat: "pid (comm) state ppid ..."
    // `comm` may contain spaces and '(' / ')'; use rfind(')') to skip it.
    let stat =
        std::fs::read_to_string("/proc/self/stat").context("failed to read /proc/self/stat")?;
    let after_comm = stat
        .rfind(')')
        .context("unexpected format in /proc/self/stat")?;
    let mut fields = stat[after_comm + 1..].split_whitespace();
    let _state = fields
        .next()
        .context("missing state field in /proc/self/stat")?;
    fields
        .next()
        .context("missing ppid field in /proc/self/stat")?
        .parse::<u32>()
        .context("ppid in /proc/self/stat is not a valid u32")
}

#[cfg(not(target_os = "linux"))]
fn session_key() -> Result<u32> {
    bail!("session_key() is only supported on Linux")
}

fn cmd_install_pam() -> Result<()> {
    // TODO (Step 4):
    //   1. Write pam_exec lines to /etc/pam.d/sshd
    //   2. Copy mina.sh.profile to /etc/profile.d/mina.sh
    //   3. Write /usr/lib/tmpfiles.d/mina.conf  → "d /run/mina 0755 root root -"
    //   4. Write /etc/mina.toml from EXAMPLE_CONFIG if not already present
    //   5. Print a summary of changes made
    bail!("install-pam: not yet implemented (see STATUS.md Step 4)")
}

fn cmd_uninstall_pam() -> Result<()> {
    // TODO (Step 4):
    //   1. Remove pam_exec lines from /etc/pam.d/sshd
    //   2. Remove /etc/profile.d/mina.sh
    //   3. Remove /usr/lib/tmpfiles.d/mina.conf
    //   4. Leave /etc/mina.toml and /var/mina in place (data is precious)
    //   5. Print a summary of changes reverted
    bail!("uninstall-pam: not yet implemented (see STATUS.md Step 4)")
}

fn cmd_install_audit() -> Result<()> {
    // TODO (Step 11 / AuditdSource):
    //   1. Write an auditd rule: -a always,exit -F arch=b64 -S execve
    //   2. Configure pam_tty_audit in /etc/pam.d/sshd
    //   3. Reload auditd rules
    bail!("install-audit: not yet implemented (see STATUS.md Step 11)")
}

fn cmd_session_open() -> Result<()> {
    let run_dir = Path::new(RUN_DIR);
    if !run_dir.exists() {
        // /run/mina is created by tmpfiles.d at boot.
        // If it is missing we log and exit cleanly — never block login.
        eprintln!("mina: {RUN_DIR} does not exist; session will not be recorded");
        eprintln!("mina: run `mina install-pam` to configure tmpfiles.d");
        return Ok(());
    }

    let key = session_key().context("could not determine session key")?;
    let pam = EnvPamSession::from_env().context("could not read PAM environment")?;
    let state = SessionState::new(&pam, key);

    if let Err(e) = state.save(run_dir) {
        // Log the error but never propagate — never block login.
        eprintln!("mina: session-open failed to save state: {e}");
    }

    Ok(())
}

fn cmd_session_close() -> Result<()> {
    let run_dir = Path::new(RUN_DIR);

    let key = match session_key() {
        Ok(k) => k,
        Err(e) => {
            eprintln!("mina: session-close could not determine session key: {e}");
            return Ok(()); // Never block logout
        }
    };

    let mut state = match SessionState::load(run_dir, key) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("mina: session-close could not load session state: {e}");
            return Ok(()); // Never block logout
        }
    };

    state.meta.close(); // records ended_at = now

    // TODO (Step 3): full session-close orchestration
    //   1. Load /etc/mina.toml via Config::load()
    //   2. Read commands via ShellHookSource::commands_for_session(key)
    //   3. Extract candidate paths via file_capture::extract_paths()
    //   4. Snapshot each path via file_capture::snapshot()
    //   5. Assemble bundle via Bundle::write()
    //   6. Ship via SshTransport or HttpsTransport (with retry — Step 5)
    //   7. state.remove(run_dir)  — clean up state + cmds files
    //   8. On any failure: log to syslog but exit 0 (never block logout)

    Ok(())
}
