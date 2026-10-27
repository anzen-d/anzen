#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 The Anzen contributors
# checks/packages.sh — OS-aware package update checks

run_packages_check() {
    section "Package Updates"

    case "$OS_FAMILY" in
        debian)
            # Check list staleness without running apt-get update
            if [ -d /var/lib/apt/lists ]; then
                NEWEST=$(find /var/lib/apt/lists -maxdepth 1 -name "*Packages*" -printf '%T@\n' 2>/dev/null | sort -n | tail -1)
                if [ -n "$NEWEST" ]; then
                    AGE_H=$(( ($(date +%s) - ${NEWEST%.*}) / 3600 ))
                    if [ "$AGE_H" -gt 48 ]; then
                        warn "Package lists are stale (${AGE_H}h old)"
                        remedy "apt-get update"
                    else
                        info "Package lists last updated: ${AGE_H}h ago"
                    fi
                fi
            fi

            SECURITY_UPDATES=$(apt-get --just-print upgrade 2>/dev/null | grep -i security | grep "^Inst" | wc -l)
            ALL_UPDATES=$(apt-get --just-print upgrade 2>/dev/null | grep "^Inst" | wc -l)

            if [ "$SECURITY_UPDATES" -gt 0 ]; then
                fail "$SECURITY_UPDATES security updates pending ($ALL_UPDATES total)"
                remedy "apt-get upgrade -y"
            elif [ "$ALL_UPDATES" -gt 0 ]; then
                warn "$ALL_UPDATES package updates pending (none flagged as security)"
                remedy "apt-get upgrade -y"
            else
                ok "All packages up to date"
            fi

            if dpkg -l unattended-upgrades &>/dev/null 2>&1; then
                STATUS=$(systemctl is-active unattended-upgrades 2>/dev/null)
                if [ "$STATUS" = "active" ]; then
                    ok "unattended-upgrades is active"
                else
                    warn "unattended-upgrades installed but not active"
                    remedy "systemctl enable --now unattended-upgrades"
                fi
            else
                warn "unattended-upgrades not installed"
                remedy "apt-get install -y unattended-upgrades && dpkg-reconfigure -plow unattended-upgrades"
            fi
            ;;

        rhel)
            if command -v dnf &>/dev/null; then
                SECURITY_UPDATES=$(_priv dnf check-update --security -q 2>/dev/null | grep -v "^$\|^Last\|^Loaded" | wc -l)
                ALL_UPDATES=$(_priv dnf check-update -q 2>/dev/null | grep -v "^$\|^Last\|^Loaded" | wc -l)
                if [ "$SECURITY_UPDATES" -gt 0 ]; then
                    fail "$SECURITY_UPDATES security updates pending ($ALL_UPDATES total)"
                    remedy "dnf update --security -y"
                elif [ "$ALL_UPDATES" -gt 0 ]; then
                    warn "$ALL_UPDATES updates pending"
                    remedy "dnf update -y"
                else
                    ok "All packages up to date"
                fi
                if rpm -q dnf-automatic &>/dev/null; then
                    STATUS=$(systemctl is-active dnf-automatic.timer 2>/dev/null)
                    [ "$STATUS" = "active" ] && ok "dnf-automatic.timer active" \
                        || { warn "dnf-automatic timer not active"; remedy "systemctl enable --now dnf-automatic.timer"; }
                else
                    warn "dnf-automatic not installed"
                    remedy "dnf install -y dnf-automatic && systemctl enable --now dnf-automatic.timer"
                fi
            fi
            ;;

        arch)
            UPDATES=$(_priv pacman -Qu 2>/dev/null | wc -l)
            if [ "$UPDATES" -gt 0 ]; then
                warn "$UPDATES package updates available"
                remedy "pacman -Syu"
            else
                ok "All packages up to date"
            fi
            ;;

        alpine)
            UPDATES=$(_priv apk version 2>/dev/null | grep -c "<" || true)
            if [ "$UPDATES" -gt 0 ]; then
                warn "$UPDATES package updates available"
                remedy "apk upgrade"
            else
                ok "All packages up to date"
            fi
            ;;

        *)
            info "Package manager '$PKG_MGR' — manual update check required"
            ;;
    esac

    # ── CVE scan ──────────────────────────────────────────────────────────────
    # trivy scans run in the cve module; debsecan is the fallback without it
    if command -v trivy &>/dev/null; then
        return 0
    fi
    if command -v debsecan &>/dev/null && [ "${OS_FAMILY:-}" = "debian" ]; then
        local _suite _vuln_count
        _suite=$(lsb_release -cs 2>/dev/null || echo "")
        _vuln_count=$(debsecan ${_suite:+--suite "$_suite"} --format summary 2>/dev/null \
            | grep -c "^CVE" || true)
        if [ "$((10#${_vuln_count:-0}))" -gt 0 ]; then
            warn "$_vuln_count CVE(s) reported by debsecan"
            remedy "debsecan${_suite:+ --suite $_suite} --format detail | less"
        else
            ok "No known CVEs (debsecan)"
        fi
    else
        info "No CVE scanner found — install trivy (cve module) for vulnerability scanning"
    fi
}
