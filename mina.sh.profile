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
# `mina session-open`.  Under modern OpenSSH with privilege separation,
# pam_exec runs in a monitor process (the shell's grandparent), not the
# direct parent.  We try $PPID first (simple case), then the parent of $PPID
# (privsep case).  One /proc read; no loop.
_mina_session_key=""
_mina_gppid=$(awk '{print $4}' "/proc/${PPID}/stat" 2>/dev/null)
for _mina_k in "$PPID" "$_mina_gppid"; do
    [ -n "$_mina_k" ] || continue
    [ -f "${_mina_log_dir}/${_mina_k}.session" ] || continue
    _mina_session_key="$_mina_k"
    break
done
unset _mina_gppid _mina_k

[ -n "$_mina_session_key" ] || return 0

_mina_log_file="${_mina_log_dir}/${_mina_session_key}.cmds"

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
