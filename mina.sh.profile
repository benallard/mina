#!/bin/sh
# /etc/profile.d/mina.sh
# Injected by `mina install-pam`. Do not edit by hand.
#
# Logs each command to /run/mina/<session_key>.cmds in the format:
#   <unix_timestamp_ms>\t<command>
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
    _mina_log_command() {
        local cmd
        cmd=$(history 1 | sed 's/^[ ]*[0-9]*[ ]*//')
        [ -z "$cmd" ] && return
        local ts
        ts=$(date +%s%3N)
        printf '%s\t%s\n' "$ts" "$cmd" >> "$_mina_log_file"
    }
    # Prepend to PROMPT_COMMAND to avoid clobbering existing hooks
    PROMPT_COMMAND="_mina_log_command${PROMPT_COMMAND:+; $PROMPT_COMMAND}"

elif [ -n "$ZSH_VERSION" ]; then
    _mina_log_command() {
        local ts
        ts=$(date +%s%3N)
        printf '%s\t%s\n' "$ts" "$1" >> "$_mina_log_file"
    }
    # zsh: use preexec hook (fires with the command string as $1)
    autoload -Uz add-zsh-hook
    add-zsh-hook preexec _mina_log_command
fi
