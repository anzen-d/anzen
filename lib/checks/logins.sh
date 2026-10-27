#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 The Anzen contributors
# checks/logins.sh — Cron jobs and login history

run_logins_check() {
    section "Cron Jobs"

    ROOT_CRON=$(_priv crontab -l 2>/dev/null | grep -vE "^\s*(#|$)" || true)
    if [ -n "$ROOT_CRON" ]; then
        warn "Root crontab has active entries — review for unexpected jobs"
        while IFS= read -r line; do info "  $line"; done <<< "$ROOT_CRON"
    else
        ok "Root crontab is empty"
    fi

    for d in /etc/cron.d /etc/cron.daily /etc/cron.weekly /etc/cron.monthly; do
        [ -d "$d" ] || continue
        for f in "$d"/*; do
            [ -f "$f" ] || continue
            PERM_OCT=$(stat -c "%a" "$f" 2>/dev/null)
            if [ $((8#$PERM_OCT & 022)) -ne 0 ] 2>/dev/null; then
                warn "Cron file writable by group/other: $f ($PERM_OCT)"
                remedy "chmod 644 $f"
            fi
        done
    done

    CRON_USERS=$(ls /var/spool/cron/crontabs/ 2>/dev/null | tr '\n' ' ')
    [ -n "$CRON_USERS" ] && info "Users with crontabs: $CRON_USERS"

    section "Recent Logins"

    info "Last 10 successful logins:"
    last -n 10 2>/dev/null | grep -v "^wtmp\|^$" | while IFS= read -r line; do
        info "  $line"
    done

    # Failed logins with threshold-based severity
    FAIL_COUNT=0
    RAW=$(_priv lastb 2>/dev/null | grep -vc "^btmp\|^$" || true)
    if [ -n "$RAW" ] && [ "$RAW" != "0" ]; then
        FAIL_COUNT=$((10#$RAW))
    else
        J_COUNT=$(_priv journalctl -u ssh -u sshd --since "24 hours ago" 2>/dev/null \
            | grep -cE "Failed password|Invalid user" || true)
        FAIL_COUNT=$((10#$J_COUNT))
    fi

    if [ "$FAIL_COUNT" -ge "${FAIL_LOGIN_WARN:-50}" ]; then
        fail "Failed login attempts: $FAIL_COUNT — possible brute-force"
        remedy "# Install fail2ban: apt-get install -y fail2ban && systemctl enable --now fail2ban"
    elif [ "$FAIL_COUNT" -ge "${FAIL_LOGIN_OK:-10}" ]; then
        warn "Failed login attempts: $FAIL_COUNT — monitor closely"
    elif [ "$FAIL_COUNT" -gt 0 ]; then
        ok "Failed login attempts: $FAIL_COUNT (low)"
    else
        ok "No failed login attempts found"
    fi

    if [ "$FAIL_COUNT" -gt 0 ]; then
        _priv lastb -n 10 2>/dev/null | grep -v "^btmp\|^$" | while IFS= read -r line; do
            info "  $line"
        done
    fi

    section "Account Expiry"

    local no_expiry=""
    while IFS=: read -r uname _ uid _ _ _ shell; do
        [[ "$uid" =~ ^[0-9]+$ ]] || continue
        [ "$uid" -lt 1000 ] && continue
        echo "$shell" | grep -qE "(nologin|false|halt|sync|shutdown)$" && continue
        exp=$(_priv chage -l "$uname" 2>/dev/null | grep "Password expires" | cut -d: -f2 | xargs)
        if [ "$exp" = "never" ]; then
            no_expiry="$no_expiry $uname"
        fi
    done < /etc/passwd

    if [ -n "$no_expiry" ]; then
        warn "Accounts with password that never expires:$no_expiry"
        remedy "# For each account: chage -M 90 <username>"
    else
        ok "All human accounts have password expiry configured"
    fi
}
