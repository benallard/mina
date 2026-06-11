use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use std::collections::HashSet;
use std::path::Path;

use mina_lib::bundle::Bundle;
use mina_lib::command_log::{CommandSource, ShellHookSource};
use mina_lib::config::{Config, TransportKind, DEFAULT_CONFIG_PATH};
use mina_lib::file_capture::{extract_paths, snapshot};
use mina_lib::pam_hook::{EnvPamSession, SessionState};
use mina_lib::transport::https::HttpsTransport;
use mina_lib::transport::local::LocalTransport;
use mina_lib::transport::ssh::SshTransport;
use mina_lib::transport::Transport;

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

    if let Err(e) = run_close_pipeline(&state, run_dir, key) {
        eprintln!("mina: session-close pipeline failed: {e:#}");
    }

    // Always clean up state and command log — even if the pipeline failed.
    if let Err(e) = state.remove(run_dir) {
        eprintln!("mina: failed to remove session state file: {e}");
    }
    let cmds_path = run_dir.join(format!("{key}.cmds"));
    if cmds_path.exists() {
        if let Err(e) = std::fs::remove_file(&cmds_path) {
            eprintln!("mina: failed to remove command log: {e}");
        }
    }

    Ok(())
}

/// The core pipeline run at session close.
///
/// All errors propagate upward; the caller (`cmd_session_close`) logs them
/// and ensures the user's shell exits regardless.
fn run_close_pipeline(state: &SessionState, run_dir: &Path, key: u32) -> Result<()> {
    // 1. Load config
    let config =
        Config::load(Path::new(DEFAULT_CONFIG_PATH)).context("failed to load /etc/mina.toml")?;

    // 2. Read commands recorded by the shell hook
    let source = ShellHookSource {
        log_dir: run_dir.to_owned(),
    };
    let commands = source
        .commands_for_session(key)
        .context("failed to read command log")?;

    // 3. Extract candidate file paths, deduplicated, first-seen order
    let mut seen = HashSet::new();
    let candidate_paths: Vec<_> = commands
        .iter()
        .flat_map(|e| extract_paths(&e.command))
        .filter(|p| seen.insert(p.clone()))
        .collect();

    // 4. Snapshot each candidate (text detection + size limit + skip list)
    let captures: Vec<_> = candidate_paths
        .into_iter()
        .map(|path| {
            let outcome = snapshot(
                &path,
                config.capture.text_size_limit_kb,
                &config.capture.skip_paths,
            );
            (path, outcome)
        })
        .collect();

    // 5. Assemble on-disk bundle
    let bundle = Bundle::write(&config.staging_dir, state.meta.clone(), commands, captures)
        .context("failed to assemble bundle")?;

    // 6. Build the configured transport and ship (retry once on failure)
    let transport = build_transport(&config)?;
    ship_with_retry(transport.as_ref(), &bundle.root).context("failed to ship bundle")?;

    Ok(())
}

/// Build a boxed `Transport` from the loaded config.
fn build_transport(config: &Config) -> Result<Box<dyn Transport>> {
    match config.nest.transport {
        TransportKind::Ssh => {
            let destination = config
                .nest
                .ssh_destination
                .clone()
                .context("nest.ssh_destination is required when transport = \"ssh\"")?;
            Ok(Box::new(SshTransport {
                destination,
                key_path: config.nest.ssh_key_path.clone(),
            }))
        }
        TransportKind::Https => {
            let endpoint = config
                .nest
                .https_endpoint
                .clone()
                .context("nest.https_endpoint is required when transport = \"https\"")?;
            Ok(Box::new(HttpsTransport { endpoint }))
        }
        TransportKind::Local => {
            let destination = config
                .nest
                .local_destination
                .clone()
                .context("nest.local_destination is required when transport = \"local\"")?;
            Ok(Box::new(LocalTransport {
                destination: destination.into(),
            }))
        }
    }
}

/// Ship the bundle, retrying once on transient failure.
///
/// AGENTS.md requirement: "Retry at least once on transient failure before
/// giving up."  A second failure is returned to the caller unchanged.
fn ship_with_retry(transport: &dyn Transport, bundle_root: &Path) -> Result<()> {
    match transport.ship(bundle_root) {
        Ok(()) => Ok(()),
        Err(first_err) => {
            eprintln!("mina: ship attempt 1 failed ({first_err:#}), retrying…");
            transport.ship(bundle_root)
        }
    }
}
