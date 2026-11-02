use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::time::Duration;

use mina_lib::bundle::Bundle;
use mina_lib::command_log::audit_files::{
    parse_auditd_conf, rules_for_machine, LogMark, AUDITD_CONF, RULES_DIR, RULES_FILE, RULES_KEY,
};
use mina_lib::command_log::auditd::Scope;
use mina_lib::command_log::{
    choose_source, remove_log_mark, AuditStatus, AuditdSource, CommandEntry, CommandOrigin,
    CommandSource, ShellHookSource, SourceKind,
};
use mina_lib::config::{AuditConfig, Config, SessionConfig, TransportKind, DEFAULT_CONFIG_PATH};
use mina_lib::file_capture::{extract_paths, extract_paths_for_audit, resolve_candidate, snapshot};
use mina_lib::pam_hook::{service_opens_session, EnvPamSession, SessionState};
use mina_lib::staging::{prepare_staging_dir, ship_and_remove};
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

    /// Install the audit rules that record the commands of sessions
    /// without a login shell (ssh host cmd, scp, sftp).
    ///
    /// Writes /etc/audit/rules.d/50-mina.rules for this kernel's
    /// architecture and loads it with augenrules. The rules record every
    /// program run by a logged-in user. If they fail to load, they are
    /// removed again. Needs auditd.
    InstallAudit,

    /// Remove the audit rules installed by install-audit.
    ///
    /// Safe to run multiple times.
    UninstallAudit,

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
        Command::UninstallAudit => cmd_uninstall_audit(),
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

// ── Process credentials ───────────────────────────────────────────────────

/// Set the process umask to `077`, so everything `session-close` writes
/// (staged bundles, nest directories) is private to root.
#[cfg(unix)]
fn restrict_umask() {
    // SAFETY: umask(2) only replaces the process file mode mask and cannot
    // fail; no pointers are involved.
    unsafe {
        libc::umask(0o077);
    }
}

#[cfg(not(unix))]
fn restrict_umask() {}

/// The effective uid of this process: the owner the staging directory
/// must have.
#[cfg(unix)]
fn effective_uid() -> u32 {
    // SAFETY: geteuid(2) takes no arguments, cannot fail and has no side
    // effects.
    unsafe { libc::geteuid() }
}

#[cfg(not(unix))]
fn effective_uid() -> u32 {
    0
}

// ── PAM / profile.d markers ───────────────────────────────────────────────

/// The lines written into /etc/pam.d/sshd, wrapped in guard comments so
/// `uninstall-pam` can find and remove exactly what was added.
const PAM_BLOCK_BEGIN: &str = "# BEGIN mina";
const PAM_BLOCK_END: &str = "# END mina";
const PAM_LINES: &str = "\
session optional pam_exec.so /usr/bin/mina session-open
session optional pam_exec.so /usr/bin/mina session-close";

const PAM_SSHD: &str = "/etc/pam.d/sshd";
const PROFILE_D_DEST: &str = "/etc/profile.d/mina.sh";
const PROFILE_D_SRC: &str = "/usr/share/mina/mina.sh.profile";
const TMPFILES_DEST: &str = "/usr/lib/tmpfiles.d/mina.conf";
const TMPFILES_LINE: &str = "d /run/mina 1777 root root -\n";

fn cmd_install_pam() -> Result<()> {
    let mut changed: Vec<&str> = vec![];

    // 1. /etc/mina.toml — write only if absent; data is precious
    let config_path = Path::new(DEFAULT_CONFIG_PATH);
    if !config_path.exists() {
        if let Some(parent) = config_path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("could not create {}", parent.display()))?;
        }
        std::fs::write(config_path, mina_lib::config::EXAMPLE_CONFIG)
            .with_context(|| format!("could not write {}", config_path.display()))?;
        changed.push(DEFAULT_CONFIG_PATH);
    } else {
        println!("  skip  {DEFAULT_CONFIG_PATH} (already exists — not overwritten)");
    }

    // 2. /etc/profile.d/mina.sh — shell hook
    //    Source is installed to /usr/share/mina/ by the package (or `make install`).
    //    Fall back to the binary's own location for manual installs.
    install_profile_d().context("could not install shell hook")?;
    changed.push(PROFILE_D_DEST);

    // 3. /usr/lib/tmpfiles.d/mina.conf — /run/mina at boot
    {
        let dest = Path::new(TMPFILES_DEST);
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("could not create {}", parent.display()))?;
        }
        std::fs::write(dest, TMPFILES_LINE)
            .with_context(|| format!("could not write {}", dest.display()))?;
        changed.push(TMPFILES_DEST);
    }

    // 4. /etc/pam.d/sshd — append pam_exec lines (idempotent)
    pam_install().context("could not update /etc/pam.d/sshd")?;
    changed.push(PAM_SSHD);

    println!("\nmina install-pam: done.");
    for f in &changed {
        println!("  wrote {f}");
    }
    println!("\nActivate /run/mina now (no reboot needed):");
    println!("  systemd-tmpfiles --create /usr/lib/tmpfiles.d/mina.conf");
    println!("  -- or --");
    println!("  mkdir -p /run/mina && chmod 1777 /run/mina");

    if !Path::new(RULES_FILE).exists() {
        println!("\nSessions without a login shell (ssh host cmd, scp, sftp) record");
        println!("commands only from the audit log. To enable that:");
        println!("  apt install auditd    # if not installed");
        println!("  mina install-audit");
    }

    Ok(())
}

fn cmd_uninstall_pam() -> Result<()> {
    let mut removed: Vec<&str> = vec![];
    let mut skipped: Vec<&str> = vec![];

    // 1. /etc/pam.d/sshd — remove only the mina block
    match pam_uninstall() {
        Ok(true) => removed.push(PAM_SSHD),
        Ok(false) => skipped.push(PAM_SSHD),
        Err(e) => eprintln!("  warn  could not update {PAM_SSHD}: {e}"),
    }

    // 2. /etc/profile.d/mina.sh
    match std::fs::remove_file(PROFILE_D_DEST) {
        Ok(()) => removed.push(PROFILE_D_DEST),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => skipped.push(PROFILE_D_DEST),
        Err(e) => eprintln!("  warn  could not remove {PROFILE_D_DEST}: {e}"),
    }

    // 3. /usr/lib/tmpfiles.d/mina.conf
    match std::fs::remove_file(TMPFILES_DEST) {
        Ok(()) => removed.push(TMPFILES_DEST),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => skipped.push(TMPFILES_DEST),
        Err(e) => eprintln!("  warn  could not remove {TMPFILES_DEST}: {e}"),
    }

    // 4. /etc/audit/rules.d/50-mina.rules
    match audit_uninstall() {
        Ok(true) => removed.push(RULES_FILE),
        Ok(false) => skipped.push(RULES_FILE),
        Err(e) => eprintln!("  warn  could not remove {RULES_FILE}: {e:#}"),
    }

    // /etc/mina.toml and /var/mina are deliberately left in place — data is precious.

    println!("\nmina uninstall-pam: done.");
    for f in &removed {
        println!("  removed {f}");
    }
    for f in &skipped {
        println!("  skip    {f} (not found — already uninstalled?)");
    }
    println!("\n  /etc/mina.toml and nest data directories were NOT removed.");
    println!("  Remove them manually if you no longer need the data.");

    Ok(())
}

// ── PAM block helpers ─────────────────────────────────────────────────────

/// Append the mina pam_exec block to /etc/pam.d/sshd if not already present.
fn pam_install() -> Result<()> {
    let path = Path::new(PAM_SSHD);
    let existing = std::fs::read_to_string(path)
        .with_context(|| format!("could not read {}", path.display()))?;

    if existing.contains(PAM_BLOCK_BEGIN) {
        println!("  skip  {PAM_SSHD} (mina block already present)");
        return Ok(());
    }

    let block = format!("\n{PAM_BLOCK_BEGIN}\n{PAM_LINES}\n{PAM_BLOCK_END}\n");
    let mut file = std::fs::OpenOptions::new()
        .append(true)
        .open(path)
        .with_context(|| format!("could not open {} for appending", path.display()))?;
    use std::io::Write;
    file.write_all(block.as_bytes())
        .with_context(|| format!("could not write to {}", path.display()))?;

    Ok(())
}

/// Remove the mina pam_exec block from /etc/pam.d/sshd.
/// Returns Ok(true) if the block was found and removed, Ok(false) if not present.
fn pam_uninstall() -> Result<bool> {
    let path = Path::new(PAM_SSHD);
    let existing = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(e).with_context(|| format!("could not read {}", path.display())),
    };

    if !existing.contains(PAM_BLOCK_BEGIN) {
        return Ok(false);
    }

    // Remove lines from PAM_BLOCK_BEGIN to PAM_BLOCK_END (inclusive)
    let mut in_block = false;
    let filtered: String = existing
        .lines()
        .filter(|line| {
            if line.trim() == PAM_BLOCK_BEGIN {
                in_block = true;
            }
            let keep = !in_block;
            if line.trim() == PAM_BLOCK_END {
                in_block = false;
            }
            keep
        })
        .collect::<Vec<_>>()
        .join("\n");

    // Preserve trailing newline
    let filtered = if existing.ends_with('\n') {
        format!("{filtered}\n")
    } else {
        filtered
    };

    std::fs::write(path, filtered)
        .with_context(|| format!("could not write {}", path.display()))?;

    Ok(true)
}

// ── profile.d installer ───────────────────────────────────────────────────

/// Copy the shell hook to /etc/profile.d/mina.sh.
///
/// Source search order (first found wins):
///   1. /usr/share/mina/mina.sh.profile  (package install)
///   2. Same directory as the running binary  (manual / dev install)
fn install_profile_d() -> Result<()> {
    let dest = Path::new(PROFILE_D_DEST);

    // Find the source file
    let src = if Path::new(PROFILE_D_SRC).exists() {
        std::path::PathBuf::from(PROFILE_D_SRC)
    } else {
        // Fall back: look next to the running binary
        let mut p = std::env::current_exe().context("could not determine binary path")?;
        p.pop();
        p.push("mina.sh.profile");
        if !p.exists() {
            bail!(
                "could not find mina.sh.profile — tried {} and {}",
                PROFILE_D_SRC,
                p.display()
            );
        }
        p
    };

    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("could not create {}", parent.display()))?;
    }

    std::fs::copy(&src, dest)
        .with_context(|| format!("could not copy {} -> {}", src.display(), dest.display()))?;

    Ok(())
}

// ── Audit rules ───────────────────────────────────────────────────────────

fn cmd_install_audit() -> Result<()> {
    if !Path::new(RULES_DIR).is_dir() {
        bail!("{RULES_DIR} does not exist: install auditd first (apt install auditd)");
    }
    let uname = tool_output("uname", &["-m"]).context("could not run uname -m")?;
    let machine = uname.trim();
    std::fs::write(RULES_FILE, rules_for_machine(machine))
        .with_context(|| format!("could not write {RULES_FILE}"))?;
    println!("  wrote {RULES_FILE} (for {machine})");

    match load_audit_rules() {
        Err(e) if is_not_found(&e) => {
            println!("\naugenrules not found: load the rules with `augenrules --load`");
            println!("or by restarting auditd.");
            return Ok(());
        }
        Err(e) => return Err(roll_back_rules(e)),
        Ok(()) => {}
    }
    let loaded = tool_output("auditctl", &["-l"]).context("could not run auditctl -l")?;
    if !loaded.contains(RULES_KEY) {
        return Err(roll_back_rules(anyhow::anyhow!(
            "auditctl -l does not list the mina rules after loading"
        )));
    }

    println!("\nmina install-audit: done. The kernel now records every program");
    println!("run by a logged-in user; mina reads those of its sessions at close.");
    Ok(())
}

/// Remove mina's rules again after they failed to load, and reload, so the
/// admin's other rules end up as before.
fn roll_back_rules(error: anyhow::Error) -> anyhow::Error {
    if let Err(e) = std::fs::remove_file(RULES_FILE) {
        eprintln!("  warn  could not remove {RULES_FILE}: {e}");
    } else if let Err(e) = load_audit_rules() {
        eprintln!("  warn  could not reload the audit rules: {e:#}");
    }
    error.context(format!(
        "the mina audit rules did not load; {RULES_FILE} was removed again"
    ))
}

fn cmd_uninstall_audit() -> Result<()> {
    if audit_uninstall()? {
        println!("  removed {RULES_FILE}");
    } else {
        println!("  skip    {RULES_FILE} (not found — already uninstalled?)");
    }
    Ok(())
}

/// Remove mina's rules file and reload the rules. `Ok(false)` if it was
/// not installed.
fn audit_uninstall() -> Result<bool> {
    match std::fs::remove_file(RULES_FILE) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(e).with_context(|| format!("could not remove {RULES_FILE}")),
    }
    if let Err(e) = load_audit_rules() {
        eprintln!("  warn  could not reload the audit rules ({e:#}); run `augenrules --load`");
    }
    Ok(true)
}

fn load_audit_rules() -> Result<()> {
    // augenrules prints auditctl's status block once per load step; only
    // its errors are of interest.
    let status = std::process::Command::new("augenrules")
        .arg("--load")
        .stdout(std::process::Stdio::null())
        .status()?;

    if !status.success() {
        bail!("augenrules --load failed ({status})");
    }
    Ok(())
}

fn is_not_found(e: &anyhow::Error) -> bool {
    e.downcast_ref::<std::io::Error>()
        .is_some_and(|io| io.kind() == std::io::ErrorKind::NotFound)
}

/// Run a tool and return its standard output.
fn tool_output(program: &str, args: &[&str]) -> Result<String> {
    let output = std::process::Command::new(program).args(args).output()?;
    if !output.status.success() {
        bail!("{program} failed ({})", output.status);
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

/// The audit log to read: `[audit] log_file`, else auditd.conf's. `None`
/// when auditd is not configured or writes no local log.
fn audit_log_file(audit: &AuditConfig) -> Option<PathBuf> {
    if let Some(file) = &audit.log_file {
        return Some(file.clone());
    }
    let conf = parse_auditd_conf(&std::fs::read_to_string(AUDITD_CONF).ok()?);
    conf.write_logs.then_some(conf.log_file)
}

/// Record how far the audit log had got, so session-close reads only what
/// the session added. Never fails the login.
fn record_audit_mark(run_dir: &Path, key: u32) {
    let audit = AuditConfig::load(Path::new(DEFAULT_CONFIG_PATH)).unwrap_or_default();
    let Some(log_file) = audit_log_file(&audit) else {
        return;
    };
    match LogMark::now(&log_file) {
        Ok(mark) => {
            if let Err(e) = mark.save(run_dir, key) {
                eprintln!("mina: session-open could not save the audit log position: {e}");
            }
        }
        // No log (yet): session-close reports why.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => eprintln!(
            "mina: session-open could not read {}: {e}",
            log_file.display()
        ),
    }
}

/// The session's commands from the audit log, with the reason when there
/// are none. See docs/design/auditd-source.md, §6.
fn audit_commands(
    state: &SessionState,
    run_dir: &Path,
    key: u32,
    audit: &AuditConfig,
) -> (Vec<CommandEntry>, AuditStatus, bool) {
    let Some(ses) = state.meta.audit_session else {
        return (vec![], AuditStatus::NoSessionId, false);
    };
    let Some(log_file) = audit_log_file(audit).filter(|f| f.is_file()) else {
        return (vec![], AuditStatus::Unavailable, false);
    };
    if !Path::new(RULES_FILE).is_file() {
        return (vec![], AuditStatus::RulesMissing, false);
    }
    let source = AuditdSource {
        log_file,
        mark: LogMark::load(run_dir, key),
        scope: Scope {
            ses,
            session_key: key,
            // sshd runs the shell from a separate process; login does not
            // (see the design, §1).
            drop_pam_children: std::env::var("PAM_SERVICE").as_deref() == Ok("sshd"),
            own_exe: own_exe(),
            close_pid: std::process::id(),
            // ended_at is now: the close marker is from this close phase.
            close_since: state.meta.ended_at.map_or(0, |t| t.timestamp()) - 2,
            since: state.meta.started_at.timestamp() - 1,
            max_commands: audit.max_commands,
        },
        wait: Duration::from_millis(audit.wait_ms),
    };
    match source.collect() {
        Ok(found) => (found.entries, found.status, found.truncated),
        Err(e) => {
            eprintln!("mina: could not read the audit log: {e:#}");
            (vec![], AuditStatus::Error, false)
        }
    }
}

/// The path of the running mina binary, as audit records name it.
fn own_exe() -> Vec<u8> {
    let path = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("/usr/bin/mina"));
    #[cfg(unix)]
    {
        std::os::unix::ffi::OsStrExt::as_bytes(path.as_os_str()).to_vec()
    }
    #[cfg(not(unix))]
    {
        path.to_string_lossy().into_owned().into_bytes()
    }
}

/// Whether the PAM service that called us (`PAM_SERVICE`) is one that opens
/// a session, per `[session] pam_services` in /etc/mina.toml.
///
/// Reads only the `[session]` table. A missing or unreadable config falls
/// back to the default allowlist (logged to stderr): this runs on every
/// login and logout and must never fail them.
fn pam_service_allowed() -> bool {
    let session = match SessionConfig::load(Path::new(DEFAULT_CONFIG_PATH)) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("mina: could not read [session] from {DEFAULT_CONFIG_PATH} ({e}); using default pam_services");
            SessionConfig::default()
        }
    };
    let service = std::env::var("PAM_SERVICE").ok();
    service_opens_session(service.as_deref(), &session.pam_services)
}

fn cmd_session_open() -> Result<()> {
    // pam_exec invokes every session module for *both* pam_open_session and
    // pam_close_session.  Guard against being called in the wrong phase so
    // that session-close (which runs in the same stack) does not immediately
    // consume and delete the state file we just wrote.
    //
    // PAM_TYPE is set by pam_exec:
    //   open_session  → we should act
    //   close_session → skip (session-close will handle it)
    if std::env::var("PAM_TYPE").as_deref() == Ok("close_session") {
        return Ok(());
    }

    // Only login services (sshd, login by default) open a session. cron,
    // su, sudo, systemd --user, ... return here without writing anything.
    if !pam_service_allowed() {
        return Ok(());
    }

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
    if state.meta.audit_session.is_some() {
        record_audit_mark(run_dir, key);
    }

    Ok(())
}

fn cmd_session_close() -> Result<()> {
    // pam_exec invokes every session module for *both* pam_open_session and
    // pam_close_session.  Guard against being called in the open phase so
    // that we do not consume the state file before the shell session starts.
    //
    // PAM_TYPE is set by pam_exec:
    //   close_session → we should act
    //   open_session  → skip (session-open already handled it)
    if std::env::var("PAM_TYPE").as_deref() == Ok("open_session") {
        return Ok(());
    }

    // The bundle holds copies of files root could read: never let it be
    // created readable by anyone else.
    restrict_umask();

    // Same filter as session-open: other services never had a session.
    if !pam_service_allowed() {
        return Ok(());
    }

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
    if let Err(e) = remove_log_mark(run_dir, key) {
        eprintln!("mina: failed to remove audit log position: {e}");
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

    // 2. Read the commands: from the shell hook if a login shell loaded it,
    //    otherwise from the audit log (ssh host cmd, scp, sftp)
    let hook = ShellHookSource {
        log_dir: run_dir.to_owned(),
    };
    let shell_hook = hook.hook_attached(key);
    let (commands, origin) = if shell_hook {
        let commands = hook
            .commands_for_session(key)
            .context("failed to read command log")?;
        let origin = CommandOrigin {
            shell_hook,
            command_source: SourceKind::ShellHook,
            ..CommandOrigin::default()
        };
        (commands, origin)
    } else {
        let (commands, status, truncated) = audit_commands(state, run_dir, key, &config.audit);
        let origin = CommandOrigin {
            shell_hook,
            command_source: choose_source(shell_hook, Some(status)),
            audit_status: Some(status),
            commands_truncated: truncated,
        };
        (commands, origin)
    };

    // 3. Extract candidate file paths, resolve relative ones against the
    //    directory the command ran in (dropped when unknown), deduplicated,
    //    first-seen order. From the audit log, only the session's own
    //    commands (`capture_paths`) of a few listed programs count.
    let from_audit = origin.command_source == SourceKind::Auditd;
    let mut seen = HashSet::new();
    let candidate_paths: Vec<_> = commands
        .iter()
        .filter(|e| e.capture_paths)
        .flat_map(|e| {
            let paths = if from_audit {
                extract_paths_for_audit(&e.command)
            } else {
                extract_paths(&e.command)
            };
            paths
                .into_iter()
                .filter_map(|p| resolve_candidate(&p, e.cwd.as_deref()))
        })
        .filter(|p| seen.insert(p.clone()))
        .collect();

    // 4. Build the effective skip list: user-configured paths plus any
    //    directories mina itself owns, so that it never snapshots its own
    //    artefacts (previous bundles, staging area) without the user needing
    //    to know about these paths.
    //
    //    - local_destination: the nest directory on this machine.  When a user
    //      browses past sessions during a session, mina would otherwise capture
    //      previous commands.log / session.json files into the new bundle.
    //    - staging_dir: the temporary assembly area.  Excluded defensively in
    //      case the user configured it outside /tmp.
    //    - run_dir (/run/mina): where live .session and .cmds files sit; never
    //      interesting to capture.
    let mut skip_paths = config.capture.skip_paths.clone();
    if config.nest.transport == TransportKind::Local {
        if let Some(ref dest) = config.nest.local_destination {
            skip_paths.push(std::path::PathBuf::from(dest));
        }
    }
    skip_paths.push(config.staging_dir.clone());
    skip_paths.push(run_dir.to_path_buf());

    // 5. Snapshot each candidate (text detection + size limit + skip list)
    let captures: Vec<_> = candidate_paths
        .into_iter()
        .map(|path| {
            let outcome = snapshot(&path, config.capture.text_size_limit_kb, &skip_paths);
            (path, outcome)
        })
        .collect();

    // 5. Assemble on-disk bundle, in a staging directory only root can use
    prepare_staging_dir(&config.staging_dir, effective_uid())
        .context("unsafe or unusable staging_dir")?;
    let bundle = Bundle::write(
        &config.staging_dir,
        state.meta.clone(),
        origin,
        commands,
        captures,
    )
    .context("failed to assemble bundle")?;

    // 6. Build the configured transport and ship (retry once on failure);
    //    the staged copy is removed once shipped, kept if shipping failed
    let transport = build_transport(&config)?;
    ship_and_remove(transport.as_ref(), &bundle.root)?;

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
        TransportKind::Https => Ok(Box::new(HttpsTransport {
            settings: config.nest.https_settings()?,
        })),
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
