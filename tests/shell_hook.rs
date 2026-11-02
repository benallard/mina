//! Tier 2: the bash shell hook (`mina.sh.profile`) driven by a real,
//! interactive `bash` with scripted input.
//!
//! The hook writes to the hard-coded `/run/mina`; the test runs a copy of
//! it with `_mina_log_dir` pointed at a temporary directory. The session
//! key is the shell's `$PPID`, which is this test process, so a fake
//! `<pid>.session` file in that directory makes the hook log.
//!
//! The hook is passed with `--rcfile`, like `/etc/profile.d` in a login
//! shell it is sourced before bash loads `$HISTFILE`. The rcfile also sets
//! `set -u` to check the hook works in such shells.
//!
//! Linux only (`/proc`, GNU `date +%s%3N`); skipped when bash is missing.
#![cfg(target_os = "linux")]

use std::fs;
use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

const LOG_DIR_LINE: &str = "_mina_log_dir=\"/run/mina\"";

fn have_bash() -> bool {
    Command::new("bash")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

/// Run `input` in an interactive bash with the hook loaded and return the
/// `(cwd, command)` pairs written to the `.cmds` file.
fn run_hook(dir: &Path, history: &str, env: &[(&str, &str)], input: &str) -> Vec<(String, String)> {
    let profile = fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/mina.sh.profile"))
        .expect("read mina.sh.profile");
    assert_eq!(
        profile.matches(LOG_DIR_LINE).count(),
        1,
        "log dir line not found in hook"
    );
    let hook = profile.replace(
        LOG_DIR_LINE,
        &format!("_mina_log_dir=\"{}\"", dir.display()),
    );
    fs::write(dir.join("hook.sh"), hook).unwrap();
    fs::write(
        dir.join("rc.sh"),
        format!("set -u\n. \"{}\"\n", dir.join("hook.sh").display()),
    )
    .unwrap();

    let key = std::process::id();
    fs::write(dir.join(format!("{key}.session")), "{}").unwrap();
    fs::write(dir.join("histfile"), history).unwrap();

    let mut child = Command::new("bash")
        .arg("--noprofile")
        .arg("--rcfile")
        .arg(dir.join("rc.sh"))
        .arg("-i")
        .env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("HOME", dir)
        .env("HISTFILE", dir.join("histfile"))
        .env("TERM", "dumb")
        .envs(env.iter().copied())
        .current_dir(dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn bash");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(input.as_bytes())
        .unwrap();
    let out = child.wait_with_output().unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stderr.contains("unbound variable") && !stderr.contains("_mina"),
        "hook error: {stderr}"
    );

    let cmds = fs::read_to_string(dir.join(format!("{key}.cmds"))).unwrap_or_default();
    cmds.lines()
        .map(|line| {
            let mut f = line.splitn(3, '\t');
            let ts = f.next().unwrap();
            assert!(ts.parse::<u64>().is_ok(), "bad timestamp in {line:?}");
            let cwd = f.next().expect("cwd").to_owned();
            let cmd = f.next().expect("command").to_owned();
            (cwd, cmd)
        })
        .collect()
}

fn pairs(expected: &[(&str, &str)]) -> Vec<(String, String)> {
    expected
        .iter()
        .map(|(c, m)| (c.to_string(), m.to_string()))
        .collect()
}

#[test]
fn logs_only_commands_that_ran() {
    if !have_bash() {
        eprintln!("bash not found, skipping");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().display().to_string();
    // Previous session's history must not show up; nor must the empty
    // line repeat `echo one`. A command repeated on purpose is logged twice.
    let got = run_hook(
        dir.path(),
        "systemctl status\n",
        &[],
        "echo one\n\n\ntrue\ntrue\ncd /\necho two\nexit\n",
    );
    assert_eq!(
        got,
        pairs(&[
            (&home, "echo one"),
            (&home, "true"),
            (&home, "true"),
            (&home, "cd /"),
            ("/", "echo two"),
        ])
    );
}

#[test]
fn histcontrol_ignoreboth_logs_nothing_false() {
    if !have_bash() {
        eprintln!("bash not found, skipping");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().display().to_string();
    // A repeated command and a space-prefixed one add no history entry:
    // they are not logged (missing them is accepted, inventing one is not).
    let got = run_hook(
        dir.path(),
        "systemctl status\n",
        &[("HISTCONTROL", "ignoreboth")],
        "echo one\necho one\n echo hidden\n\necho two\nexit\n",
    );
    assert_eq!(got, pairs(&[(&home, "echo one"), (&home, "echo two")]));
}

#[test]
fn history_disabled_logs_nothing() {
    if !have_bash() {
        eprintln!("bash not found, skipping");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let got = run_hook(
        dir.path(),
        "systemctl status\n",
        &[("HISTSIZE", "0")],
        "echo one\n\necho two\nexit\n",
    );
    assert_eq!(got, Vec::new());
}
