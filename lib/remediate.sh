#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 The Anzen contributors
# lib/remediate.sh — Generate executable remediation script from findings

# _remedy_manual_reason REMEDY — print why this command must not run
# unattended (nothing when it may). Such a remedy goes into the script as a
# comment: a reboot, a firewall switched on over SSH, or a change to who may
# log in can lock the admin out, and a batch script is the wrong place for it.
_remedy_manual_reason() {
    local cmd=${1%%  #*}     # remedies put their notes after "  # "
    local b='(^|[;&|({ ])'
    if [[ "$cmd" =~ ${b}(reboot|poweroff|halt|shutdown)([ ;&|]|$) ]]; then
        echo "restarts the machine"
    elif [[ "$cmd" =~ ${b}(kill|pkill|killall)[[:space:]] ]]; then
        echo "stops a process, look at it first"
    elif [[ "$cmd" =~ ufw[[:space:]]+(enable|default[[:space:]]+(deny|reject)) ]] \
      || [[ "$cmd" =~ ip6?tables[[:space:]]+-P[[:space:]]+(INPUT|FORWARD)[[:space:]]+(DROP|REJECT) ]] \
      || [[ "$cmd" =~ (enable|start)[[:space:]].*firewalld ]] \
      || [[ "$cmd" =~ nft[[:space:]].*policy[[:space:]]+drop ]]; then
        echo "turns on a firewall, which can cut your remote session"
    elif [[ "$cmd" == *sshd_config* ]] \
      && [[ "$cmd" =~ (Port[[:space:]]+[0-9]|PasswordAuthentication[[:space:]]+no|PermitRootLogin[[:space:]]+no|AllowUsers|AllowGroups|DenyUsers) ]]; then
        echo "changes who can log in over SSH, which can lock you out"
    fi
}

# _remedy_edited_files REMEDY — /etc files a remedy edits in place (sed -i, >>),
# one per line. Only plain path characters are matched, so the result is safe
# to print into the script unquoted.
_remedy_edited_files() {
    local cmd=${1%%  #*}
    [[ "$cmd" == *"sed -i"* || "$cmd" == *">>"* ]] || return 0
    printf '%s\n' "$cmd" | grep -oE '/etc/[A-Za-z0-9._/-]+' | sort -u
}

generate_remediate_script() {
    local output_file=$1
    local count=0
    local cur_section=""
    local reason f

    {
        cat <<HEADER
#!/bin/bash
# ============================================================
# Anzen Remediation Script
# Generated: $(date)
# Host:      $(_hostname)
# ⚠  Review each command carefully before running!
# ⚠  Run as root or with sudo
# ⚠  Steps marked MANUAL are NOT run: they can lock you out or
#    restart the machine. Run them yourself, one at a time.
# ============================================================
# Each command runs on its own: one that fails is reported and the rest
# still run (no set -e — many lines are checks that may find nothing)
set -uo pipefail
_failed=0
_manual=0
HEADER
        cat <<'PREAMBLE'
_bak_dir="/var/backups/anzen-remediate-$(date +%Y%m%d-%H%M%S)"

# Copy a file aside before the first command that edits it
_anzen_bak() {
    [ -f "$1" ] || return 0
    [ -e "$_bak_dir$1" ] && return 0
    ( umask 077; mkdir -p "$_bak_dir${1%/*}" ) && cp -p "$1" "$_bak_dir$1"
}

# After an sshd_config edit: a file sshd rejects must not stay on disk,
# or the next restart of sshd leaves the host without SSH
_anzen_sshd_check() {
    command -v sshd >/dev/null 2>&1 || return 0
    sshd -t 2>/dev/null && return 0
    if [ -f "$_bak_dir/etc/ssh/sshd_config" ]; then
        cp -p "$_bak_dir/etc/ssh/sshd_config" /etc/ssh/sshd_config
        echo "sshd_config was not valid after the last change: backup restored" >&2
    else
        echo "sshd_config is not valid: fix it before sshd restarts" >&2
    fi
}

PREAMBLE

        while IFS=$'\t' read -r level sec msg _id remedy; do
            [ -z "$remedy" ] && continue
            [ "$level" = "OK" ]   && continue
            [ "$level" = "INFO" ] && continue

            if [ "$sec" != "$cur_section" ]; then
                printf '\n# ── %s ─────────────────────────────\n\n' "$sec"
                cur_section="$sec"
            fi

            printf '# [%s] %s\n' "$level" "$msg"
            reason=""
            [[ "$remedy" == \#* ]] || reason=$(_remedy_manual_reason "$remedy")
            if [[ "$remedy" == \#* ]]; then
                # Advice only: nothing to run
                printf '%s\n\n' "$remedy"
            elif [ -n "$reason" ]; then
                printf '# MANUAL: %s. Not run by this script:\n#   %s\n_manual=$((_manual + 1))\n\n' \
                    "$reason" "$remedy"
            else
                while IFS= read -r f; do
                    [ -n "$f" ] && printf '_anzen_bak %s\n' "$f"
                done < <(_remedy_edited_files "$remedy")
                # Newline before "}": the remedy may end in a "# comment"
                printf '{ %s\n} || { echo "FAILED: %s" >&2; _failed=$((_failed + 1)); }\n' \
                    "$remedy" "$(printf '%s' "$msg" | sed 's/[\\"$`]/\\&/g')"
                [[ "${remedy%%  #*}" == *sshd_config* ]] && printf '_anzen_sshd_check\n'
                printf '\n'
            fi
            count=$((count + 1))
        done < "$FINDINGS_FILE"

        printf '# ── End of remediation (%s commands) ──\n' "$count"
        printf 'if [ -d "$_bak_dir" ]; then echo "Files as they were before: $_bak_dir"; fi\n'
        printf 'if [ "$_manual" -gt 0 ]; then echo "$_manual step(s) marked MANUAL were not run: read them in $0"; fi\n'
        printf 'if [ "$_failed" -gt 0 ]; then echo "Remediation finished: $_failed command(s) failed — see above."; exit 1; fi\n'
        printf 'echo "Remediation script complete."\n'

    } > "$output_file"

    # Root runs it and it lists what is wrong with the host: owner only
    chmod 700 "$output_file"
    echo "$count"
}
