#!/bin/sh
# /etc/profile.d/mina.sh
# Injected by `mina install-pam`. Do not edit by hand.
#
# Logs each command to /run/mina/<session_key>.cmds, one line per command:
#   <unix_timestamp_ms>\t<cwd>\t<command>
#
# <cwd> is $PWD when the command started; mina resolves relative paths in
# the command against it. The command comes last because it may itself
# contain tabs. mina <= 0.2 wrote <unix_timestamp_ms>\t<command>; the
# parser still accepts that.
#
# Use `return` (not `exit`) — this file is sourced, not executed.
# `exit` would terminate the user's login shell.
#
# The file is harvested by `mina session-close` (via PAM) at logout.
# Supports bash and zsh. Other shells fall back silently (no logging).

_mina_log_dir="/run/mina"

[ -d "$_mina_log_dir" ] || return 0

# Resolve the session key — the PID written into /run/mina/<key>.session by
# `mina session-open`: the process that ran pam_exec for the login (sshd,
# login). It is an ancestor of this shell, but not always the parent: under
# OpenSSH privilege separation it is the grandparent, and a `su -` or
# `sudo -i` shell (which opens no session of its own) sits further down.
# Walk up /proc/<pid>/stat from $PPID to the nearest ancestor that has a
# .session file; stop at PID 1, after 16 steps, or on any read error.
# Builtins only (no fork per step).
_mina_session_key=""
_mina_pid=$PPID
_mina_depth=0
while [ "$_mina_depth" -lt 16 ]; do
    case $_mina_pid in
        '' | *[!0-9]* | 0 | 1) break ;;
    esac
    if [ -f "${_mina_log_dir}/${_mina_pid}.session" ]; then
        _mina_session_key=$_mina_pid
        break
    fi
    # "pid (comm) state ppid ...": comm may contain spaces and parens, so
    # cut at the last ')' and take the second field after it.
    _mina_stat=""
    read -r _mina_stat 2>/dev/null <"/proc/${_mina_pid}/stat" || break
    _mina_stat=${_mina_stat##*)}
    _mina_stat=${_mina_stat# }
    _mina_stat=${_mina_stat#* }
    _mina_pid=${_mina_stat%% *}
    _mina_depth=$((_mina_depth + 1))
done
unset _mina_pid _mina_depth _mina_stat

[ -n "$_mina_session_key" ] || return 0

_mina_log_file="${_mina_log_dir}/${_mina_session_key}.cmds"

# Create the log from the login shell, so it belongs to the session user:
# a nested `sudo -i` shell appending first would otherwise leave a file
# the user's own shell cannot write. A nested shell that cannot write it
# (`su - otheruser`) does not log.
[ -e "$_mina_log_file" ] || { true >>"$_mina_log_file"; } 2>/dev/null
[ -w "$_mina_log_file" ] || {
    unset _mina_session_key _mina_log_file
    return 0
}

if [ -n "$BASH_VERSION" ]; then
    # PROMPT_COMMAND runs after the command, when $PWD may already have
    # changed (`vim ./x && cd /`). The command started in the $PWD of the
    # previous prompt, so remember that one.
    _mina_cwd=$PWD
    # PROMPT_COMMAND also runs when no command was added to the history:
    # at the first prompt (where `history 1` is the last line of the
    # previous session's history file, loaded after this file is sourced),
    # after an empty line or Ctrl-C. Log only when the last history entry
    # (number and text) differs from the one seen at the previous prompt.
    # The first prompt only records it.
    # With HISTCONTROL=ignoredups/ignorespace (or erasedups repeating the
    # last command) a command adds no new entry and is not logged; with
    # history disabled (HISTSIZE=0, set +o history) nothing is logged.
    # _mina_hist stays unset until the first prompt (safe under `set -u`).
    unset _mina_hist
    _mina_log_command() {
        local cwd=$_mina_cwd
        _mina_cwd=$PWD
        local hist
        hist=$(history 1)
        if [ -z "${_mina_hist+set}" ] || [ "$hist" = "$_mina_hist" ]; then
            _mina_hist=$hist
            return
        fi
        _mina_hist=$hist
        local cmd
        cmd=$(printf '%s\n' "$hist" | sed 's/^[ ]*[0-9]*[ ]*//')
        [ -z "$cmd" ] && return
        local ts
        ts=$(date +%s%3N)
        printf '%s\t%s\t%s\n' "$ts" "$cwd" "$cmd" >> "$_mina_log_file"
    }
    # Prepend to PROMPT_COMMAND to avoid clobbering existing hooks
    PROMPT_COMMAND="_mina_log_command${PROMPT_COMMAND:+; $PROMPT_COMMAND}"

elif [ -n "$ZSH_VERSION" ]; then
    _mina_log_command() {
        local ts
        ts=$(date +%s%3N)
        printf '%s\t%s\t%s\n' "$ts" "$PWD" "$1" >> "$_mina_log_file"
    }
    # zsh: use preexec hook (fires with the command string as $1, before
    # the command runs, so $PWD is where it starts)
    autoload -Uz add-zsh-hook
    add-zsh-hook preexec _mina_log_command
fi
