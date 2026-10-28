#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 The Anzen contributors
# checks/files.sh — File system security checks

_KNOWN_SUID="ping$|ping6$|sudo$|sudoedit$|mount$|umount$|su$|passwd$|chsh$|chfn$|newgrp$|gpasswd$|pkexec$|Xorg$|ksu$|ssh-keysign$|crontab$|at$|wall$|write$|netstat$|traceroute$|traceroute6$|unix_chkpwd$|pam_timestamp_check$|pt_chown$|screen$|lockfile$"
_SYSTEM_PATHS="^/(bin|sbin|usr/bin|usr/sbin|usr/lib|usr/lib64|usr/libexec|usr/lib/openssh|usr/lib/ssh|usr/local/bin|snap|opt/homebrew)/"
# Exclude SUID bits inside container image layers (overlay/volumes — not live filesystem)
_CONTAINER_PATHS="containers/storage/overlay|/var/lib/docker/overlay|/var/lib/lxc"

run_files_check() {
    section "File Permissions"

    _check_perm() {
        local file=$1 expected=$2
        [ -f "$file" ] || return 0
        local actual perm
        actual=$(stat -c "%a %U:%G" "$file" 2>/dev/null)
        perm=$(echo "$actual" | awk '{print $1}')
        # Bits granted beyond the expected maximum; stricter is fine (RHEL
        # ships /etc/shadow as 000)
        local extra=$(( 8#$perm & ~8#$expected & 8#7777 ))
        if [ "$extra" -eq 0 ]; then
            ok "$file — $actual"
        elif [ $(( extra & 8#0007 )) -ne 0 ] || [ $(( extra & 8#0222 )) -ne 0 ]; then
            # Readable/writable by everyone, or writable beyond intent
            fail "$file — $actual (expected $expected or stricter)"
            remedy "chmod $expected $file"
        else
            warn "$file — $actual (expected $expected or stricter)"
            remedy "chmod $expected $file"
        fi
    }

    _check_perm /etc/passwd          644
    _check_perm /etc/shadow          640
    _check_perm /etc/group           644
    _check_perm /etc/gshadow         640
    _check_perm /etc/sudoers         440
    _check_perm /etc/ssh/sshd_config 600
    _check_perm /boot/grub/grub.cfg  600

    section "World-Writable Files"

    # Excluded trees are pruned, not filtered: "! -path" still walks them
    # (Docker image layers alone can hold 100k+ files). "dir/*" patterns —
    # built-in and EXCLUDE_PATHS alike — prune "dir"; other patterns filter.
    local excludes=(
        "/proc/*" "/sys/*" "/dev/*" "/run/*" "/tmp/*" "/var/tmp/*"
        "/var/lib/docker/*" "/var/lib/lxc/*"
        # App data dirs that legitimately use world-writable cache files
        "*/Plex Media Server/Plug-in Support/Data/*"
        "*/plex/*/cache/*"
        "*/jellyfin/*/cache/*"
        "*/transmission/*/incomplete/*"
    )
    # No "-false" to start the -o chain: BusyBox find (Alpine) rejects it, and
    # the error, hidden by 2>/dev/null, used to empty both scans
    local p prune_args=( \( -path /proc ) filter_args=()
    # shellcheck disable=SC2206  # EXCLUDE_PATHS is a space-separated glob list
    excludes+=( ${EXCLUDE_PATHS:-} )
    for p in "${excludes[@]}"; do
        if [[ "$p" == */\* ]]; then
            prune_args+=( -o -path "${p%/\*}" )
        else
            filter_args+=( ! -path "$p" )
        fi
    done
    prune_args+=( \) -prune -o )

    # One walk for both scans (a second walk doubled the run time on hosts with
    # large app-data trees); SUID/SGID paths are reported further down
    local f ww_list="" suid_list="" ww_seen=0
    local ww_cap=${WW_FILE_CAP:-50}   # configurable; default cap 50 findings
    while IFS= read -r f; do
        if [ -u "$f" ] || [ -g "$f" ]; then
            suid_list+="$f"$'\n'
            # Rare: SUID and world-writable at once
            (( 8#$(stat -c %a "$f" 2>/dev/null || echo 0) & 2 )) || continue
        fi
        ww_seen=$((ww_seen+1))
        [ "$ww_seen" -le "$ww_cap" ] && ww_list+="$f"$'\n'
    done < <(find / -xdev "${prune_args[@]}" -type f \
        \( -perm -o+w ! -perm /1000 -o -perm -4000 -o -perm -2000 \) \
        "${filter_args[@]}" -print 2>/dev/null)

    local ww_count=0
    while IFS= read -r f; do
        [ -n "$f" ] || continue
        fail "World-writable file: $f"
        remedy "chmod o-w $(_q "$f")"
        ww_count=$((ww_count+1))
    done <<< "$ww_list"
    if [ "$ww_seen" -gt "$ww_cap" ]; then
        warn "World-writable scan capped at $ww_cap — set WW_FILE_CAP in anzen.conf or add EXCLUDE_PATHS"
    fi

    [ "$ww_count" -eq 0 ] && ok "No world-writable files found"

    for d in /etc/cron.d /etc/cron.daily /etc/cron.weekly /etc/cron.monthly; do
        [ -d "$d" ] || continue
        # One finding per entry: a multi-line remedy would run the second
        # path as a command in remediate.sh
        while IFS= read -r f; do
            [ -n "$f" ] || continue
            fail "World-writable cron entry: $f"
            remedy "chmod o-w $(_q "$f")"
        done < <(find "$d" -perm -o+w 2>/dev/null)
    done

    section "SUID / SGID Binaries"

    SUID=$(printf '%s' "$suid_list" \
        | grep -vE "$_SYSTEM_PATHS" \
        | grep -vE "$_CONTAINER_PATHS" \
        | grep -vE "$_KNOWN_SUID")

    # Also allow paths from CUSTOM_SUID_WHITELIST config
    if [ -n "${CUSTOM_SUID_WHITELIST:-}" ]; then
        for entry in $CUSTOM_SUID_WHITELIST; do
            SUID=$(echo "$SUID" | grep -v "^${entry}$" || true)
        done
    fi

    if [ -n "$SUID" ]; then
        while IFS= read -r f; do
            warn "Unexpected SUID/SGID binary: $f"
            remedy "chmod -s $(_q "$f")  # verify this binary doesn't need SUID before removing"
        done <<< "$SUID"
    else
        ok "No unexpected SUID/SGID binaries found"
    fi
}
