//! Tier 2: the bash shell hook (`mina.sh.profile`) driven by a real,
//! interactive `bash` with scripted input.
//!
//! The hook writes to the hard-coded `/run/mina`; the test runs a copy of
//! it with `_mina_log_dir` pointed at a temporary directory. The session
//! key is the nearest ancestor of the shell with a `<pid>.session` file
//! there. Usually that is this test process (bash's `$PPID`); some tests
//! start bash through intermediate `sh -c` processes, as `su -` or
//! `sudo -i` would sit between the login and the shell.
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

/// Wrapper that runs its arguments as a child (not `exec`), so it stays in
/// the process tree between its parent and bash.
const WRAP: &str = "\"$@\"; exit $?";

/// Run `input` in an interactive bash with the hook loaded, started as
/// `launch... bash ...`, and return its stderr.
fn run_bash(
    dir: &Path,
    history: &str,
    env: &[(&str, &str)],
    input: &str,
    launch: &[String],
) -> String {
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
    fs::write(dir.join("histfile"), history).unwrap();

    let rc = dir.join("rc.sh").display().to_string();
    let mut argv: Vec<String> = launch.to_vec();
    argv.extend(["bash", "--noprofile", "--rcfile", &rc, "-i"].map(String::from));
    let mut child = Command::new(&argv[0])
        .args(&argv[1..])
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
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(
        !stderr.contains("unbound variable") && !stderr.contains("_mina"),
        "hook error: {stderr}"
    );
    stderr
}

/// The `(cwd, command)` pairs in `<key>.cmds`.
fn read_cmds(dir: &Path, key: u32) -> Vec<(String, String)> {
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

fn write_session(dir: &Path, key: u32) {
    fs::write(dir.join(format!("{key}.session")), "{}").unwrap();
}

/// `sh -c` wrappers, `levels` deep, each a separate process.
fn sh_wrappers(levels: usize) -> Vec<String> {
    (0..levels)
        .flat_map(|_| ["sh", "-c", WRAP, "sh"].map(String::from))
        .collect()
}

/// Run `input` in an interactive bash with the hook loaded, the session on
/// this test process (bash's parent), and return the logged
/// `(cwd, command)` pairs.
fn run_hook(dir: &Path, history: &str, env: &[(&str, &str)], input: &str) -> Vec<(String, String)> {
    let key = std::process::id();
    write_session(dir, key);
    run_bash(dir, history, env, input, &[]);
    read_cmds(dir, key)
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

#[test]
fn finds_session_on_a_further_ancestor() {
    if !have_bash() {
        eprintln!("bash not found, skipping");
        return;
    }
    // Two processes between the session and bash, like sshd -> sudo -> bash.
    // One of them is named "x) (y z" so its /proc/<pid>/stat `comm` has
    // spaces and parens.
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().display().to_string();
    let odd = dir.path().join("x) (y z");
    fs::copy("/bin/sh", &odd).unwrap();
    let key = std::process::id();
    write_session(dir.path(), key);
    let mut launch = sh_wrappers(1);
    launch.extend([
        odd.display().to_string(),
        "-c".into(),
        WRAP.into(),
        "sh".into(),
    ]);
    run_bash(dir.path(), "", &[], "echo one\nexit\n", &launch);
    assert_eq!(read_cmds(dir.path(), key), pairs(&[(&home, "echo one")]));
}

#[test]
fn nearest_ancestor_session_wins() {
    if !have_bash() {
        eprintln!("bash not found, skipping");
        return;
    }
    // The test process and the intermediate sh both have a session file;
    // the sh one (closer to bash) gets the commands.
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().display().to_string();
    let outer = std::process::id();
    write_session(dir.path(), outer);
    let launch: Vec<String> = [
        "sh",
        "-c",
        "echo {} > \"$$.session\"; echo $$ > inner.pid; \"$@\"; exit $?",
        "sh",
    ]
    .map(String::from)
    .into();
    run_bash(dir.path(), "", &[], "echo one\nexit\n", &launch);
    let inner: u32 = fs::read_to_string(dir.path().join("inner.pid"))
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    assert_eq!(read_cmds(dir.path(), inner), pairs(&[(&home, "echo one")]));
    assert_eq!(read_cmds(dir.path(), outer), Vec::new());
}

#[test]
fn no_session_on_any_ancestor_logs_nothing() {
    if !have_bash() {
        eprintln!("bash not found, skipping");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let stderr = run_bash(dir.path(), "", &[], "echo one\nexit\n", &sh_wrappers(2));
    let cmds: Vec<_> = fs::read_dir(dir.path())
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|n| n.ends_with(".cmds"))
        .collect();
    assert_eq!(cmds, Vec::<String>::new());
    for needle in [
        "/proc",
        "No such file",
        "denied",
        "syntax error",
        "not found",
    ] {
        assert!(!stderr.contains(needle), "unexpected stderr: {stderr}");
    }
}
