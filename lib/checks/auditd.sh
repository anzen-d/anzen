#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 The Anzen contributors
# checks/auditd.sh — Audit daemon, NTP time sync, TCP wrappers, rootkit scanners

run_auditd_check() {
    section "Audit Daemon"

    if command -v auditctl &>/dev/null || systemctl list-unit-files auditd.service &>/dev/null 2>&1; then
        local status
        status=$(systemctl is-active auditd 2>/dev/null || echo "inactive")
        if [ "$status" = "active" ]; then
            ok "auditd is running"
            local rule_count
            rule_count=$(_priv auditctl -l 2>/dev/null | grep -cve "^\s*$\|^No rules\|^-e" || true)
            if [ "$((10#$rule_count))" -gt 0 ]; then
                ok "Audit rules loaded: $rule_count"
            else
                warn "auditd running but no rules loaded"
                remedy "# Install a ruleset: apt-get install -y auditd audispd-plugins\n# Or copy: cp /usr/share/doc/auditd/examples/rules/30-stig.rules /etc/audit/rules.d/"
            fi
        else
            warn "auditd installed but not running"
            remedy "systemctl enable --now auditd"
        fi
    else
        warn "auditd not installed"
        remedy "apt-get install -y auditd audispd-plugins && systemctl enable --now auditd"
    fi

    section "Time Synchronization"

    local ntp_found=false

    if systemctl is-active systemd-timesyncd &>/dev/null; then
        local sync_info
        sync_info=$(timedatectl 2>/dev/null | grep -E "synchronized|NTP" | head -2 | sed 's/^ *//' | tr '\n' ' ' | xargs)
        ok "systemd-timesyncd active — $sync_info"
        ntp_found=true
    fi

    if command -v chronyc &>/dev/null; then
        if systemctl is-active chronyd &>/dev/null || systemctl is-active chrony &>/dev/null; then
            local tracking
            tracking=$(chronyc tracking 2>/dev/null | grep "System time" | head -1 | xargs || true)
            ok "chronyd active${tracking:+ — $tracking}"
            ntp_found=true
        else
            warn "chrony installed but not running"
            remedy "systemctl enable --now chronyd"
        fi
    fi

    if command -v ntpq &>/dev/null && ! $ntp_found; then
        if systemctl is-active ntp &>/dev/null || systemctl is-active ntpd &>/dev/null; then
            ok "ntpd active"; ntp_found=true
        else
            warn "ntpd installed but not running"
            remedy "systemctl enable --now ntp"
        fi
    fi

    if ! $ntp_found; then
        fail "No NTP service — clock drift corrupts log timestamps"
        remedy "apt-get install -y chrony && systemctl enable --now chronyd"
    fi

    section "TCP Wrappers"

    if [ -f /etc/hosts.deny ]; then
        local deny_count
        deny_count=$(grep -cvE "^\s*(#|$)" /etc/hosts.deny 2>/dev/null | tr -d '[:space:]' || true)
        if [ "${deny_count:-0}" -gt 0 ] 2>/dev/null; then
            ok "/etc/hosts.deny: $deny_count rule(s)"
        else
            warn "/etc/hosts.deny exists but empty — no deny rules"
            remedy "echo 'ALL: ALL' >> /etc/hosts.deny  # then whitelist in hosts.allow"
        fi
    else
        info "/etc/hosts.deny not present (acceptable if firewall is active)"
    fi

    if [ -f /etc/hosts.allow ]; then
        local allow_count
        allow_count=$(grep -cvE "^\s*(#|$)" /etc/hosts.allow 2>/dev/null | tr -d '[:space:]' || true)
        info "/etc/hosts.allow: $allow_count rule(s)"
    fi

    section "Rootkit Scanners"

    local scanner_found=false

    if command -v rkhunter &>/dev/null; then
        local rk_log
        rk_log=$(find /var/log -name "rkhunter.log" 2>/dev/null | head -1)
        if [ -n "$rk_log" ]; then
            local last_run
            last_run=$(stat -c "%y" "$rk_log" 2>/dev/null | cut -d. -f1)
            ok "rkhunter installed (last log: $last_run)"
        else
            warn "rkhunter installed but never run"
            remedy "rkhunter --update && rkhunter --check --skip-keypress"
        fi
        scanner_found=true
    fi

    if command -v chkrootkit &>/dev/null; then
        ok "chkrootkit installed"
        scanner_found=true
    fi

    if ! $scanner_found; then
        warn "No rootkit scanner installed"
        remedy "apt-get install -y rkhunter && rkhunter --update && rkhunter --check --skip-keypress"
    fi
}
