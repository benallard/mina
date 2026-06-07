#!/bin/sh
# /etc/profile.d/mina.sh
# Injected by `mina install-pam`. Do not edit by hand.
#
# Logs each command to /run/mina/<ppid>.cmds in the format:
#   <unix_timestamp_ms>\t<command>
#
# The file is harvested by `mina session-close` (via PAM) at logout.
# Supports bash and zsh. Other shells fall back silently (no logging).

_mina_log_dir="/run/mina"
_mina_log_file="${_mina_log_dir}/$$.cmds"

# Ensure the log directory exists (created by mina at boot via tmpfiles.d)
[ -d "$_mina_log_dir" ] || exit 0

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
