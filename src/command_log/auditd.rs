/// Exec records from the kernel audit log, turned into command entries.
///
/// Pure functions only: text in, events out, events in, entries out. Finding
/// and reading the log files is `audit_files`; choosing the source is the
/// parent module. See docs/design/auditd-source.md, §3 and §5.
///
/// An exec is a group of records sharing `msg=audit(<sec>.<ms>:<serial>)`:
///
///   type=SYSCALL ... ppid=1201 pid=1240 auid=1000 ... ses=12 exe="/usr/bin/cat"
///   type=EXECVE ... argc=2 a0="cat" a1="/etc/hostname"
///   type=CWD ... cwd="/root"
///   type=PATH ..., type=PROCTITLE ..., type=EOE ...
///
/// Groups can interleave in the file (several CPUs), so they are collected
/// by stamp. Values are either quoted text or hex-encoded bytes. With
/// `log_format = ENRICHED` (Debian's default) a line carries an interpreted
/// copy after a 0x1D separator, which is ignored.
use chrono::DateTime;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::PathBuf;

use super::CommandEntry;

/// `(seconds, milliseconds, serial)` from `msg=audit(...)`. Orders events.
pub type Stamp = (i64, u32, u64);

/// One successful exec, assembled from its records.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecEvent {
    pub stamp: Stamp,
    pub pid: u32,
    pub ppid: u32,
    /// `None` when the record says the id is unset.
    pub ses: Option<u32>,
    pub exe: Option<Vec<u8>>,
    /// `None` when a part of argv is missing from the log.
    pub argv: Option<Vec<Vec<u8>>>,
    pub cwd: Option<Vec<u8>>,
}

/// What `select` needs to know about the session. See the design, §3
/// "Window".
#[derive(Debug, Clone)]
pub struct Scope {
    /// The audit session id of the login.
    pub ses: u32,
    /// PID of the process that runs the PAM stack (mina's parent).
    pub session_key: u32,
    /// Drop what the PAM stack started (sshd: motd helpers). Not for
    /// `login`, whose shell is itself a child of the session key.
    pub drop_pam_children: bool,
    /// Path of the mina binary: its execs are never commands.
    pub own_exe: Vec<u8>,
    /// PID of the running `mina session-close`: its exec ends the window.
    pub close_pid: u32,
    /// The close marker is not older than this (Unix seconds). The open
    /// phase also runs `mina session-close`, whose pid could come back.
    pub close_since: i64,
    /// Events before this (Unix seconds) are from an earlier boot or
    /// session that happened to have the same id.
    pub since: i64,
    /// Keep at most this many entries.
    pub max_commands: usize,
}

/// The result of `select`.
#[derive(Debug, Default)]
pub struct Selected {
    pub entries: Vec<CommandEntry>,
    /// The close marker was found: everything before it was written.
    pub closed: bool,
    /// At least one exec of this session was in the log.
    pub any: bool,
    /// More than `max_commands` execs; the rest were dropped.
    pub truncated: bool,
}

// ── Records ───────────────────────────────────────────────────────────────

/// One audit record line: its type, stamp and raw `key=value` fields.
#[derive(Debug, PartialEq, Eq)]
struct Record<'a> {
    kind: &'a str,
    stamp: Stamp,
    fields: Vec<(&'a str, &'a str)>,
}

fn parse_line(line: &str) -> Option<Record<'_>> {
    // ENRICHED: the interpreted part after 0x1D is not needed.
    let line = line.split('\x1d').next().unwrap_or(line);
    // `name_format` in auditd.conf may prefix `node=<name> `.
    let line = match line.strip_prefix("node=") {
        Some(rest) => rest.split_once(' ')?.1,
        None => line,
    };
    let rest = line.strip_prefix("type=")?;
    let (kind, rest) = rest.split_once(' ')?;
    let rest = rest.trim_start().strip_prefix("msg=audit(")?;
    let (stamp_text, rest) = rest.split_once("):")?;
    let (time, serial) = stamp_text.split_once(':')?;
    let (sec, ms) = time.split_once('.')?;
    let stamp = (sec.parse().ok()?, ms.parse().ok()?, serial.parse().ok()?);
    Some(Record {
        kind,
        stamp,
        fields: parse_fields(rest),
    })
}

/// Split `k=v k="quoted value" ...`. A quoted value runs to the next quote;
/// the kernel hex-encodes any value that contains one.
fn parse_fields(mut text: &str) -> Vec<(&str, &str)> {
    let mut fields = Vec::new();
    loop {
        text = text.trim_start();
        if text.is_empty() {
            return fields;
        }
        let Some((key, rest)) = text.split_once('=') else {
            return fields;
        };
        let end = if let Some(quoted) = rest.strip_prefix('"') {
            match quoted.find('"') {
                Some(i) => i + 2,
                None => rest.len(),
            }
        } else {
            rest.find(' ').unwrap_or(rest.len())
        };
        fields.push((key, &rest[..end]));
        text = &rest[end..];
    }
}

/// Decode a value: `"text"` is literal, `(null)` is nothing, anything else
/// is hex-encoded bytes. `None` for `(null)` or invalid hex.
pub fn decode_value(raw: &str) -> Option<Vec<u8>> {
    if let Some(inner) = raw.strip_prefix('"').and_then(|r| r.strip_suffix('"')) {
        return Some(inner.as_bytes().to_vec());
    }
    if raw.is_empty() || !raw.len().is_multiple_of(2) {
        return None;
    }
    (0..raw.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(raw.get(i..i + 2)?, 16).ok())
        .collect()
}

// ── Assembling events ─────────────────────────────────────────────────────

/// The SYSCALL record of an exec: pid, ppid, ses, exe.
struct Syscall(u32, u32, Option<u32>, Option<Vec<u8>>);

#[derive(Default)]
struct Partial {
    syscall: Option<Syscall>,
    failed: bool,
    has_execve: bool,
    argc: Option<usize>,
    args: BTreeMap<usize, Vec<u8>>,
    /// `aN[i]` chunks of a long argument.
    chunks: BTreeMap<usize, BTreeMap<usize, Vec<u8>>>,
    cwd: Option<Vec<u8>>,
}

/// Parse audit log text into the exec events it contains, ordered by stamp.
/// Lines that are not audit records, and records of other types, are
/// skipped. Failed execs (`success=no`) are dropped.
pub fn parse_events(text: &str) -> Vec<ExecEvent> {
    let mut groups: HashMap<Stamp, Partial> = HashMap::new();
    for record in text.lines().filter_map(parse_line) {
        match record.kind {
            "SYSCALL" | "EXECVE" | "CWD" => {}
            _ => continue,
        }
        let group = groups.entry(record.stamp).or_default();
        match record.kind {
            "SYSCALL" => add_syscall(group, &record.fields),
            "EXECVE" => add_execve(group, &record.fields),
            _ => {
                group.cwd = field(&record.fields, "cwd").and_then(decode_value);
            }
        }
    }
    let mut events: Vec<ExecEvent> = groups
        .into_iter()
        .filter_map(|(stamp, g)| finish(stamp, g))
        .collect();
    events.sort_by_key(|e| e.stamp);
    events
}

fn field<'a>(fields: &[(&str, &'a str)], key: &str) -> Option<&'a str> {
    fields.iter().find(|(k, _)| *k == key).map(|(_, v)| *v)
}

fn add_syscall(group: &mut Partial, fields: &[(&str, &str)]) {
    let num = |key| field(fields, key).and_then(|v| v.parse::<u32>().ok());
    let (Some(pid), Some(ppid)) = (num("pid"), num("ppid")) else {
        return;
    };
    let ses = num("ses").filter(|&s| s != u32::MAX);
    let exe = field(fields, "exe").and_then(decode_value);
    group.failed = field(fields, "success") == Some("no");
    group.syscall = Some(Syscall(pid, ppid, ses, exe));
}

fn add_execve(group: &mut Partial, fields: &[(&str, &str)]) {
    group.has_execve = true;
    for (key, value) in fields {
        if *key == "argc" {
            group.argc = value.parse().ok();
            continue;
        }
        let Some(rest) = key.strip_prefix('a') else {
            continue;
        };
        if let Some((index, chunk)) = rest.split_once('[') {
            // a1[0]=<hex>: one chunk of a long argument, always hex.
            let chunk = chunk.strip_suffix(']').and_then(|c| c.parse().ok());
            if let (Ok(index), Some(chunk), Some(bytes)) =
                (index.parse(), chunk, decode_value(value))
            {
                group.chunks.entry(index).or_default().insert(chunk, bytes);
            }
        } else if let Ok(index) = rest.parse::<usize>() {
            if let Some(bytes) = decode_value(value) {
                group.args.insert(index, bytes);
            }
        }
        // a1_len=<n> needs no handling: the chunks carry the content.
    }
}

fn finish(stamp: Stamp, g: Partial) -> Option<ExecEvent> {
    let Syscall(pid, ppid, ses, exe) = g.syscall?;
    if !g.has_execve || g.failed {
        return None;
    }
    let argv = g.argc.and_then(|argc| {
        (0..argc)
            .map(|i| match (g.args.get(&i), g.chunks.get(&i)) {
                (Some(arg), _) => Some(arg.clone()),
                (None, Some(chunks)) => contiguous(chunks),
                (None, None) => None,
            })
            .collect::<Option<Vec<_>>>()
    });
    Some(ExecEvent {
        stamp,
        pid,
        ppid,
        ses,
        exe,
        argv,
        cwd: g.cwd,
    })
}

/// Join chunks `0..n`, or `None` if one is missing.
fn contiguous(chunks: &BTreeMap<usize, Vec<u8>>) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    for (expected, (index, bytes)) in chunks.iter().enumerate() {
        if *index != expected {
            return None;
        }
        out.extend_from_slice(bytes);
    }
    Some(out)
}

// ── Selecting the session's commands ──────────────────────────────────────

/// Pick the session's commands from `events` (ordered by stamp), as
/// described in the design, §3 "Window" and §5.
///
/// Each entry is marked as a file-capture candidate only if it is at depth
/// 0 or 1 below the session's shell: depth 0 for an exec whose parent is
/// the process sshd forked for the session, depth n+1 for an exec whose
/// parent ran at depth n. An exec whose parent never exec'd (a forked
/// subshell, sudo's pty monitor) cannot be traced and is no candidate
/// either.
///
/// sshd's session process is the parent of the first exec whose parent
/// never execs itself. Not simply the first exec's parent: before it execs
/// the shell, sshd's session child may run `~/.ssh/rc`, `/etc/ssh/sshrc`
/// or `xauth` (X11 forwarding) through `sh`, as its own child.
pub fn select(events: &[ExecEvent], scope: &Scope) -> Selected {
    let mut out = Selected::default();
    let mut pam_children: HashSet<u32> = HashSet::new();
    let mut window: Vec<&ExecEvent> = Vec::new();

    for event in events {
        if event.ses != Some(scope.ses) || event.stamp.0 < scope.since {
            continue;
        }
        let is_mina = event.exe.as_deref() == Some(scope.own_exe.as_slice());
        // The open phase runs `mina session-close` too: only an exec from
        // the close phase can be this process (guards against pid reuse).
        if is_mina && event.pid == scope.close_pid && event.stamp.0 >= scope.close_since {
            out.closed = true;
            break;
        }
        if scope.drop_pam_children
            && (event.ppid == scope.session_key || pam_children.contains(&event.ppid))
        {
            pam_children.insert(event.pid);
            continue;
        }
        if is_mina {
            continue;
        }
        window.push(event);
    }
    out.any = !window.is_empty();

    let exec_pids: HashSet<u32> = window.iter().map(|e| e.pid).collect();
    let shell_parent = window
        .iter()
        .map(|e| e.ppid)
        .find(|ppid| !exec_pids.contains(ppid));
    let mut depth: HashMap<u32, u32> = HashMap::new();

    for event in window {
        let level = if Some(event.ppid) == shell_parent {
            Some(0)
        } else {
            depth.get(&event.ppid).map(|d| d + 1)
        };
        match level {
            Some(d) => depth.insert(event.pid, d),
            None => depth.remove(&event.pid),
        };

        if out.entries.len() >= scope.max_commands {
            out.truncated = true;
            continue;
        }
        out.entries
            .push(entry(event, level.is_some_and(|d| d <= 1)));
    }
    out
}

/// `parse_events`, limited to the exec events of audit session `ses`.
/// Records of other events are skipped before they are parsed, so a whole
/// busy log stays cheap to read.
pub fn parse_session_events(text: &str, ses: u32) -> Vec<ExecEvent> {
    let ses_field = format!(" ses={ses} ");
    let wanted: HashSet<&str> = text
        .lines()
        .filter(|l| l.contains("type=SYSCALL ") && l.contains(&ses_field))
        .filter_map(stamp_text)
        .collect();
    let lines: Vec<&str> = text
        .lines()
        .filter(|l| stamp_text(l).is_some_and(|s| wanted.contains(s)))
        .collect();
    parse_events(&lines.join("\n"))
}

/// The `<sec>.<ms>:<serial>` of a record line, unparsed.
fn stamp_text(line: &str) -> Option<&str> {
    let start = line.find("msg=audit(")? + "msg=audit(".len();
    let len = line[start..].find(')')?;
    Some(&line[start..start + len])
}

fn entry(event: &ExecEvent, near_shell: bool) -> CommandEntry {
    let (sec, ms, _) = event.stamp;
    let timestamp =
        DateTime::from_timestamp(sec, ms.saturating_mul(1_000_000)).unwrap_or(DateTime::UNIX_EPOCH);
    let cwd = event
        .cwd
        .as_deref()
        .and_then(|c| std::str::from_utf8(c).ok())
        .filter(|c| c.starts_with('/'))
        .map(PathBuf::from);
    let (command, utf8) = match &event.argv {
        Some(argv) => render_argv(argv),
        None => {
            let exe = event.exe.as_deref().unwrap_or(b"?");
            (
                format!("[argv incomplete] {}", String::from_utf8_lossy(exe)),
                false,
            )
        }
    };
    CommandEntry {
        timestamp,
        cwd,
        command,
        // A lossy path is not the path: no candidates from it.
        capture_paths: near_shell && utf8,
    }
}

/// Render argv as one shell-quoted line, so that it reads like what was
/// typed and can be pasted. Returns the line and whether argv was valid
/// UTF-8 (otherwise bytes are replaced by U+FFFD).
pub fn render_argv(argv: &[Vec<u8>]) -> (String, bool) {
    let mut utf8 = true;
    let words: Vec<String> = argv
        .iter()
        .map(|arg| {
            let text = match std::str::from_utf8(arg) {
                Ok(t) => t.to_owned(),
                Err(_) => {
                    utf8 = false;
                    String::from_utf8_lossy(arg).into_owned()
                }
            };
            shell_quote(&text)
        })
        .collect();
    (words.join(" "), utf8)
}

/// POSIX single-quote an argument unless it consists of safe characters only.
fn shell_quote(arg: &str) -> String {
    let safe = |c: char| c.is_ascii_alphanumeric() || "@%+=:,./_-".contains(c);
    if !arg.is_empty() && arg.chars().all(safe) {
        arg.to_owned()
    } else {
        format!("'{}'", arg.replace('\'', r"'\''"))
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// One exec as audit records: SYSCALL + EXECVE + CWD + EOE.
    fn exec(serial: u64, pid: u32, ppid: u32, ses: u32, exe: &str, args: &[&str]) -> String {
        let execve: Vec<String> = args
            .iter()
            .enumerate()
            .map(|(i, a)| format!("a{i}=\"{a}\""))
            .collect();
        let stamp = format!("msg=audit(1730550000.{:03}:{serial})", serial % 1000);
        format!(
            "type=SYSCALL {stamp}: arch=c000003e syscall=59 success=yes exit=0 ppid={ppid} pid={pid} auid=1000 uid=0 ses={ses} comm=\"x\" exe=\"{exe}\" key=\"mina\"\n\
             type=EXECVE {stamp}: argc={} {}\n\
             type=CWD {stamp}: cwd=\"/root\"\n\
             type=EOE {stamp}: \n",
            args.len(),
            execve.join(" ")
        )
    }

    fn scope() -> Scope {
        Scope {
            ses: 12,
            session_key: 100,
            drop_pam_children: true,
            own_exe: b"/usr/bin/mina".to_vec(),
            close_pid: 999,
            close_since: 0,
            since: 0,
            max_commands: 10_000,
        }
    }

    fn commands(sel: &Selected) -> Vec<&str> {
        sel.entries.iter().map(|e| e.command.as_str()).collect()
    }

    #[test]
    fn decodes_quoted_hex_and_null() {
        assert_eq!(decode_value("\"cat\""), Some(b"cat".to_vec()));
        assert_eq!(
            decode_value("2F746D702F61206220"),
            Some(b"/tmp/a b ".to_vec())
        );
        assert_eq!(decode_value("(null)"), None);
        assert_eq!(decode_value("ABC"), None);
        assert_eq!(decode_value("zz"), None);
    }

    #[test]
    fn enriched_suffix_is_ignored() {
        let line = "type=CWD msg=audit(1730550000.123:7): cwd=\"/root\"\x1dCWD=\"x y\"";
        let record = parse_line(line).unwrap();
        assert_eq!(record.kind, "CWD");
        assert_eq!(record.stamp, (1730550000, 123, 7));
        assert_eq!(record.fields, vec![("cwd", "\"/root\"")]);
    }

    #[test]
    fn non_records_are_skipped() {
        assert!(parse_line("").is_none());
        assert!(parse_line("garbage").is_none());
        assert!(parse_line("type=SYSCALL msg=audit(x): pid=1").is_none());
        assert!(parse_events("node=a\n\x00\x01\n").is_empty());
    }

    #[test]
    fn node_prefix_is_skipped() {
        let line = "node=web01 type=CWD msg=audit(1.000:7): cwd=\"/\"";
        assert_eq!(parse_line(line).unwrap().kind, "CWD");
    }

    #[test]
    fn assembles_one_exec() {
        let events = parse_events(&exec(
            1,
            200,
            150,
            12,
            "/usr/bin/cat",
            &["cat", "/etc/hostname"],
        ));
        assert_eq!(events.len(), 1);
        let e = &events[0];
        assert_eq!((e.pid, e.ppid, e.ses), (200, 150, Some(12)));
        assert_eq!(e.exe.as_deref(), Some(&b"/usr/bin/cat"[..]));
        assert_eq!(e.cwd.as_deref(), Some(&b"/root"[..]));
        assert_eq!(
            e.argv,
            Some(vec![b"cat".to_vec(), b"/etc/hostname".to_vec()])
        );
    }

    #[test]
    fn interleaved_records_are_grouped_by_stamp() {
        let a = exec(1, 200, 150, 12, "/usr/bin/cat", &["cat", "/etc/a"]);
        let b = exec(2, 300, 250, 13, "/usr/bin/ls", &["ls"]);
        let mut lines: Vec<&str> = Vec::new();
        for (x, y) in a.lines().zip(b.lines()) {
            lines.push(y);
            lines.push(x);
        }
        let events = parse_events(&lines.join("\n"));
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].ses, Some(12));
        assert_eq!(events[0].argv.as_ref().unwrap()[1], b"/etc/a");
        assert_eq!(events[1].ses, Some(13));
    }

    #[test]
    fn hex_argument_with_space_and_split_argument() {
        let text = "\
type=SYSCALL msg=audit(1.000:5): success=yes ppid=1 pid=2 ses=12 exe=\"/bin/bash\"
type=EXECVE msg=audit(1.000:5): argc=3 a0=\"bash\" a1=2D63 a2_len=6 a2[0]=656368 a2[1]=6F2061
";
        let events = parse_events(text);
        assert_eq!(
            events[0].argv,
            Some(vec![b"bash".to_vec(), b"-c".to_vec(), b"echo a".to_vec()])
        );
    }

    #[test]
    fn argv_across_several_execve_records() {
        let text = "\
type=SYSCALL msg=audit(1.000:5): success=yes ppid=1 pid=2 ses=12 exe=\"/bin/echo\"
type=EXECVE msg=audit(1.000:5): argc=3 a0=\"echo\" a1=\"x\"
type=EXECVE msg=audit(1.000:5): a2=\"y\"
";
        assert_eq!(
            parse_events(text)[0].argv,
            Some(vec![b"echo".to_vec(), b"x".to_vec(), b"y".to_vec()])
        );
    }

    #[test]
    fn missing_argument_or_chunk_makes_argv_incomplete() {
        let text = "\
type=SYSCALL msg=audit(1.000:5): success=yes ppid=1 pid=2 ses=12 exe=\"/bin/echo\"
type=EXECVE msg=audit(1.000:5): argc=3 a0=\"echo\" a2_len=4 a2[1]=6162
type=SYSCALL msg=audit(1.000:6): success=yes ppid=1 pid=3 ses=12 exe=\"/bin/echo\"
type=EXECVE msg=audit(1.000:6): argc=2 a0=\"echo\"
";
        let events = parse_events(text);
        assert_eq!(events.len(), 2);
        assert!(events.iter().all(|e| e.argv.is_none()));
        let sel = select(
            &events,
            &Scope {
                session_key: 0,
                ..scope()
            },
        );
        assert_eq!(commands(&sel), ["[argv incomplete] /bin/echo"; 2]);
        assert!(!sel.entries[0].capture_paths);
    }

    #[test]
    fn failed_execs_and_groups_without_execve_are_dropped() {
        let text = "\
type=SYSCALL msg=audit(1.000:5): success=no ppid=1 pid=2 ses=12 exe=\"/bin/x\"
type=EXECVE msg=audit(1.000:5): argc=1 a0=\"x\"
type=SYSCALL msg=audit(1.000:6): success=yes ppid=1 pid=2 ses=12 exe=\"/bin/x\"
type=PATH msg=audit(1.000:6): item=0 name=\"/etc/x\"
";
        assert!(parse_events(text).is_empty());
    }

    #[test]
    fn unset_session_id_is_none() {
        let events = parse_events(&exec(1, 2, 1, u32::MAX, "/bin/ls", &["ls"]));
        assert_eq!(events[0].ses, None);
    }

    #[test]
    fn other_sessions_are_dropped() {
        let text = exec(1, 200, 150, 13, "/usr/bin/cat", &["cat", "/etc/a"])
            + &exec(2, 201, 150, 12, "/usr/bin/cat", &["cat", "/etc/b"]);
        let sel = select(&parse_events(&text), &scope());
        assert_eq!(commands(&sel), ["cat /etc/b"]);
        assert!(sel.any);
    }

    #[test]
    fn pam_helpers_and_mina_are_dropped_for_sshd() {
        // 100 is the PAM process: motd's run-parts and its children, and
        // mina session-open, are its descendants.
        let text = exec(1, 101, 100, 12, "/usr/bin/mina", &["mina", "session-open"])
            + &exec(
                2,
                102,
                100,
                12,
                "/usr/bin/run-parts",
                &["run-parts", "/etc/update-motd.d"],
            )
            + &exec(
                3,
                103,
                102,
                12,
                "/bin/dash",
                &["sh", "/etc/update-motd.d/10-uname"],
            )
            + &exec(4, 104, 103, 12, "/usr/bin/uname", &["uname", "-snrvm"])
            + &exec(
                5,
                201,
                150,
                12,
                "/bin/bash",
                &["bash", "-c", "cat /etc/hostname"],
            )
            + &exec(6, 202, 201, 12, "/usr/bin/cat", &["cat", "/etc/hostname"]);
        let sel = select(&parse_events(&text), &scope());
        assert_eq!(
            commands(&sel),
            ["bash -c 'cat /etc/hostname'", "cat /etc/hostname"]
        );
    }

    #[test]
    fn pam_children_are_kept_when_not_asked_to_drop() {
        // login: the shell is a child of the session key.
        let text = exec(1, 101, 100, 12, "/bin/bash", &["-bash"]);
        let s = Scope {
            drop_pam_children: false,
            ..scope()
        };
        assert_eq!(commands(&select(&parse_events(&text), &s)), ["-bash"]);
    }

    #[test]
    fn close_marker_ends_the_window() {
        let text = exec(1, 201, 150, 12, "/bin/ls", &["ls"])
            + &exec(2, 999, 100, 12, "/usr/bin/mina", &["mina", "session-close"])
            + &exec(3, 1000, 999, 12, "/usr/bin/rsync", &["rsync"]);
        let sel = select(&parse_events(&text), &scope());
        assert!(sel.closed);
        assert_eq!(commands(&sel), ["ls"]);
    }

    #[test]
    fn without_close_marker_the_window_stays_open() {
        let text = exec(1, 201, 150, 12, "/bin/ls", &["ls"]);
        let sel = select(&parse_events(&text), &scope());
        assert!(!sel.closed);
        assert!(sel.any);
    }

    #[test]
    fn events_before_since_are_dropped() {
        let text = exec(1, 201, 150, 12, "/bin/ls", &["ls"]);
        let s = Scope {
            since: 1730550001,
            ..scope()
        };
        let sel = select(&parse_events(&text), &s);
        assert!(sel.entries.is_empty());
        assert!(!sel.any);
    }

    #[test]
    fn depth_decides_capture_candidates() {
        // sshd's session process is 150. bash (201) runs `sudo` in place;
        // sudo forks 202 which runs cp; cp is depth 1. apt (203, depth 1)
        // runs dpkg (204, depth 2) runs a maintainer script's chmod (205).
        let text = exec(1, 201, 150, 12, "/bin/bash", &["bash", "-c", "..."])
            + &exec(
                2,
                201,
                150,
                12,
                "/usr/bin/sudo",
                &["sudo", "cp", "a", "/etc/x"],
            )
            + &exec(3, 202, 201, 12, "/usr/bin/cp", &["cp", "a", "/etc/x"])
            + &exec(4, 203, 201, 12, "/usr/bin/apt", &["apt", "install", "x"])
            + &exec(5, 204, 203, 12, "/usr/bin/dpkg", &["dpkg", "-i"])
            + &exec(
                6,
                205,
                204,
                12,
                "/usr/bin/chmod",
                &["chmod", "600", "/etc/k"],
            );
        let sel = select(&parse_events(&text), &scope());
        let flags: Vec<bool> = sel.entries.iter().map(|e| e.capture_paths).collect();
        assert_eq!(flags, [true, true, true, true, false, false]);
    }

    #[test]
    fn rc_file_before_the_shell_does_not_shift_depth() {
        // ssh -X / ~/.ssh/rc: sshd's session child (160, forked from 150)
        // runs `sh -c xauth …` before it execs the shell itself.
        let text = exec(1, 161, 160, 12, "/bin/dash", &["sh", "-c", "xauth add"])
            + &exec(2, 162, 161, 12, "/usr/bin/xauth", &["xauth", "add"])
            + &exec(3, 160, 150, 12, "/bin/bash", &["bash", "-c", "./deploy.sh"])
            + &exec(4, 160, 150, 12, "/root/deploy.sh", &["./deploy.sh"])
            + &exec(5, 201, 160, 12, "/usr/bin/cp", &["cp", "a", "/etc/x"])
            + &exec(6, 202, 160, 12, "/root/helper.sh", &["./helper.sh"])
            + &exec(7, 203, 202, 12, "/usr/bin/cat", &["cat", "/etc/key"]);
        let sel = select(&parse_events(&text), &scope());
        let flags: Vec<bool> = sel.entries.iter().map(|e| e.capture_paths).collect();
        // xauth's sh ran before 160 exec'd: no depth. The shell and its
        // in-place exec: 0. cp, helper.sh: 1. helper's cat: 2.
        assert_eq!(flags, [false, false, true, true, true, true, false]);
    }

    #[test]
    fn open_phase_session_close_is_not_the_close_marker() {
        // pam_exec runs `mina session-close` at open too; its pid (999)
        // came back for the real close, much later.
        let text = exec(1, 999, 100, 12, "/usr/bin/mina", &["mina", "session-close"])
            + &exec(2, 201, 150, 12, "/bin/ls", &["ls"]);
        let s = Scope {
            close_since: 1730550001,
            ..scope()
        };
        let sel = select(&parse_events(&text), &s);
        assert!(!sel.closed);
        assert_eq!(commands(&sel), ["ls"]);
    }

    #[test]
    fn session_events_only() {
        let text = exec(1, 200, 150, 13, "/usr/bin/cat", &["cat", "/etc/a"])
            + &exec(2, 201, 150, 12, "/usr/bin/cat", &["cat", "/etc/b"])
            + &exec(3, 202, 150, 120, "/usr/bin/cat", &["cat", "/etc/c"]);
        let events = parse_session_events(&text, 12);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].pid, 201);
        assert_eq!(events, parse_events(&text)[1..2]);
    }

    #[test]
    fn untraceable_parent_is_no_candidate() {
        // 300 forked from bash but never exec'd (sudo's pty monitor).
        let text = exec(1, 201, 150, 12, "/bin/bash", &["bash", "-c", "..."])
            + &exec(2, 301, 300, 12, "/usr/bin/cp", &["cp", "a", "/etc/x"]);
        let sel = select(&parse_events(&text), &scope());
        assert!(sel.entries[0].capture_paths);
        assert!(!sel.entries[1].capture_paths);
    }

    #[test]
    fn max_commands_truncates_but_still_finds_close_marker() {
        let text = exec(1, 201, 150, 12, "/bin/a", &["a"])
            + &exec(2, 202, 150, 12, "/bin/b", &["b"])
            + &exec(3, 999, 100, 12, "/usr/bin/mina", &["mina"]);
        let s = Scope {
            max_commands: 1,
            ..scope()
        };
        let sel = select(&parse_events(&text), &s);
        assert_eq!(commands(&sel), ["a"]);
        assert!(sel.truncated);
        assert!(sel.closed);
    }

    #[test]
    fn entry_carries_time_and_cwd() {
        let text = exec(42, 201, 150, 12, "/bin/ls", &["ls"]);
        let sel = select(&parse_events(&text), &scope());
        let e = &sel.entries[0];
        assert_eq!(e.timestamp.timestamp(), 1730550000);
        assert_eq!(e.timestamp.timestamp_subsec_millis(), 42);
        assert_eq!(e.cwd, Some(PathBuf::from("/root")));
    }

    #[test]
    fn renders_shell_quoted() {
        let argv = [
            b"bash".to_vec(),
            b"-c".to_vec(),
            b"echo 'hi' > /etc/x".to_vec(),
            b"".to_vec(),
            b"a=b,c:d@e%f+g/h.i_j-k".to_vec(),
            b"$HOME".to_vec(),
        ];
        assert_eq!(
            render_argv(&argv),
            (
                r#"bash -c 'echo '\''hi'\'' > /etc/x' '' a=b,c:d@e%f+g/h.i_j-k '$HOME'"#.to_owned(),
                true
            )
        );
    }

    #[test]
    fn non_utf8_is_rendered_lossily_and_never_a_candidate() {
        let (line, utf8) = render_argv(&[b"cat".to_vec(), b"/etc/\xff".to_vec()]);
        assert_eq!(line, "cat '/etc/\u{fffd}'");
        assert!(!utf8);

        let text = "\
type=SYSCALL msg=audit(1.000:5): success=yes ppid=150 pid=201 ses=12 exe=\"/bin/cat\"
type=EXECVE msg=audit(1.000:5): argc=2 a0=\"cat\" a1=2F6574632FFF
";
        let sel = select(&parse_events(text), &scope());
        assert!(!sel.entries[0].capture_paths);
    }
}
