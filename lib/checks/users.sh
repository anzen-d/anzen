#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 The Anzen contributors
# checks/users.sh — Users, sudo, and account security

run_users_check() {
    section "Users & Sudo"

    # Passwordless sudo
    if sudo -n -l 2>/dev/null | grep -q "NOPASSWD: ALL"; then
        fail "NOPASSWD: ALL — full root without a password prompt"
        remedy "visudo  # remove the NOPASSWD:ALL line for $(whoami)"
    elif sudo -n -l 2>/dev/null | grep -q "NOPASSWD"; then
        warn "NOPASSWD sudo rules found (not ALL — review)"
        remedy "visudo  # review and tighten NOPASSWD entries"
    else
        ok "No NOPASSWD sudo rules"
    fi

    # Sudo logging
    if grep -rqE "^\s*Defaults.*log_output|^\s*Defaults.*logfile|^\s*Defaults.*syslog" \
        /etc/sudoers /etc/sudoers.d/ 2>/dev/null; then
        ok "Sudo logging is configured"
    else
        warn "Sudo logging not configured"
        remedy "echo 'Defaults logfile=/var/log/sudo.log' | sudo EDITOR='tee -a' visudo"
    fi

    # UID 0
    UID0_USERS=$(awk -F: '$3==0 {print $1}' /etc/passwd | tr '\n' ' ')
    if [ "$UID0_USERS" = "root " ] || [ "$UID0_USERS" = "root" ]; then
        ok "Only root has UID 0"
    else
        fail "Multiple UID 0 accounts: $UID0_USERS"
        remedy "# For each non-root UID 0 account: usermod -u <new_uid> <username>"
    fi

    # Human accounts
    LOGIN_USERS=$(grep -vE '(nologin|false|sync|halt|shutdown)$' /etc/passwd \
        | awk -F: '$3>=1000 {print $1}' | tr '\n' ' ')
    info "Human accounts with login shells: $LOGIN_USERS"

    # Empty passwords — cross-reference /etc/passwd for UID (shadow $3 is lastchg, not UID)
    EMPTY_PASS=""
    while IFS=: read -r uname _ uid _; do
        [[ "$uid" =~ ^[0-9]+$ ]] || continue
        [ "$uid" -lt 1000 ] && continue
        shadow_pass=$(_priv awk -F: -v u="$uname" '$1==u{print $2}' /etc/shadow 2>/dev/null)
        if [ -z "$shadow_pass" ] || [ "$shadow_pass" = "!!" ] || [ "$shadow_pass" = "!" ]; then
            EMPTY_PASS="$EMPTY_PASS $uname"
        fi
    done < /etc/passwd
    EMPTY_PASS="${EMPTY_PASS# }"
    if [ -n "$EMPTY_PASS" ]; then
        fail "Human accounts with no/locked password: $EMPTY_PASS"
        remedy "# For each account: passwd -l <username>  OR  passwd <username>"
    else
        ok "No human accounts with empty passwords"
    fi

    # World-writable home dirs
    WW_HOMES=$(find /home /root -maxdepth 1 -perm -o+w -type d 2>/dev/null)
    if [ -n "$WW_HOMES" ]; then
        fail "World-writable home directories: $WW_HOMES"
        remedy "chmod 750 $(echo $WW_HOMES | tr '\n' ' ')"
    else
        ok "No world-writable home directories"
    fi

    # Legacy insecure files
    while IFS= read -r f; do
        warn "Insecure legacy file found: $f"
        remedy "rm -f $f"
    done < <(find /home /root -maxdepth 2 \
        \( -name ".rhosts" -o -name ".netrc" -o -name ".forward" \) 2>/dev/null)

    # Password aging
    if [ -f /etc/login.defs ]; then
        MAX_DAYS=$(grep "^PASS_MAX_DAYS" /etc/login.defs | awk '{print $2}')
        if [ -n "$MAX_DAYS" ] && [ "$((10#$MAX_DAYS))" -gt "${PASS_MAX_DAYS_WARN:-90}" ] 2>/dev/null; then
            warn "PASS_MAX_DAYS=$MAX_DAYS (recommended ≤ ${PASS_MAX_DAYS_WARN:-90})"
            remedy "sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS 90/' /etc/login.defs"
        elif [ -n "$MAX_DAYS" ]; then
            ok "PASS_MAX_DAYS=$MAX_DAYS"
        fi
    fi

    # pwquality
    if [ -f /etc/security/pwquality.conf ]; then
        MIN_LEN=$(grep -E "^\s*minlen\s*=" /etc/security/pwquality.conf 2>/dev/null \
            | awk -F= '{print $2}' | tr -d ' ' | head -1)
        if [ -n "$MIN_LEN" ] && [ "$((10#$MIN_LEN))" -ge 12 ] 2>/dev/null; then
            ok "Password minimum length: $MIN_LEN (pwquality)"
        elif [ -n "$MIN_LEN" ]; then
            warn "Password minimum length: $MIN_LEN — recommend ≥ 12"
            remedy "sed -i 's/^# *minlen.*/minlen = 12/' /etc/security/pwquality.conf"
        else
            warn "pwquality.conf found but minlen not set"
            remedy "echo 'minlen = 12' >> /etc/security/pwquality.conf"
        fi
    else
        warn "pwquality not configured (/etc/security/pwquality.conf missing)"
        remedy "apt-get install -y libpam-pwquality && echo 'minlen = 12' > /etc/security/pwquality.conf"
    fi

    section "PAM Account Lockout"

    local pam_lockout=false
    if [ -f /etc/security/faillock.conf ]; then
        DENY=$(grep -E "^\s*deny\s*=" /etc/security/faillock.conf 2>/dev/null | awk -F= '{print $2}' | tr -d ' ')
        if [ -n "$DENY" ] && [ "$((10#$DENY))" -gt 0 ] 2>/dev/null; then
            ok "pam_faillock configured (deny after $DENY failures)"
            pam_lockout=true
        fi
    fi
    if ! $pam_lockout && grep -rqE "pam_faillock|pam_tally2" /etc/pam.d/ 2>/dev/null; then
        ok "PAM account lockout configured (pam_faillock/pam_tally2)"
        pam_lockout=true
    fi
    if ! $pam_lockout; then
        warn "No PAM account lockout — brute force will not lock accounts"
        remedy "# On Ubuntu 22.04+: pam-auth-update --enable faillock"
    fi
}
