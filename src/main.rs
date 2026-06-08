use anyhow::{bail, Result};
use clap::{Parser, Subcommand};

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
        Command::InstallPam    => cmd_install_pam(),
        Command::UninstallPam  => cmd_uninstall_pam(),
        Command::InstallAudit  => cmd_install_audit(),
        Command::SessionOpen   => cmd_session_open(),
        Command::SessionClose  => cmd_session_close(),
    }
}

// ── Subcommand handlers ────────────────────────────────────────────────────
// Each lives in its own function so it can grow into a separate module
// (src/cmd/install_pam.rs etc.) without touching the dispatch table.

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
    // TODO (Step 2):
    //   1. Read PAM environment via EnvPamSession::from_env()
    //   2. Determine the login shell PID (PAM_TTY / $PPID)
    //   3. Serialise {user, source_ip, hostname, started_at, shell_pid}
    //      to /run/mina/<shell_pid>.session as JSON
    //   4. Ensure /run/mina exists (fail gracefully if not)
    bail!("session-open: not yet implemented (see STATUS.md Step 2)")
}

fn cmd_session_close() -> Result<()> {
    // TODO (Step 3):
    //   1. Determine shell PID ($PPID from PAM env or /proc)
    //   2. Load /run/mina/<shell_pid>.session
    //   3. Load /etc/mina.toml via Config::load()
    //   4. Read commands via ShellHookSource (or AuditdSource if configured)
    //   5. Extract candidate paths via file_capture::extract_paths()
    //   6. Snapshot each path via file_capture::snapshot()
    //   7. Assemble bundle via Bundle::write()
    //   8. Ship via SshTransport or HttpsTransport (with retry)
    //   9. Clean up /run/mina/<shell_pid>.{session,cmds}
    //  10. On any failure: log to syslog but exit 0 (never block logout)
    bail!("session-close: not yet implemented (see STATUS.md Step 3)")
}
