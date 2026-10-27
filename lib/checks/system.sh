#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 The Anzen contributors
# checks/system.sh — System information and resource health

run_system_check() {
    section "System Information"

    PUBLIC_IP=$(curl -sf --max-time 3 https://api.ipify.org 2>/dev/null \
        || curl -sf --max-time 3 https://ifconfig.me 2>/dev/null \
        || echo "unavailable")
    export ANZEN_PUBLIC_IP="$PUBLIC_IP"

    info "Hostname:   $(_hostname)"
    info "OS:         $OS_PRETTY"
    info "Family:     $OS_FAMILY / pkg: $PKG_MGR / init: $INIT_SYS"
    info "Kernel:     $(uname -r)"
    info "Arch:       $(uname -m)"
    info "Public IP:  $PUBLIC_IP"
    # /proc instead of uptime(1): procps is absent from minimal images
    local up_s; up_s=$(cut -d. -f1 /proc/uptime 2>/dev/null)
    [ -n "$up_s" ] && info "Uptime:     $((up_s / 86400)) days, $((up_s % 86400 / 3600)) hours"
    info "Date:       $(date)"

    # Reboot required
    if [ -f /var/run/reboot-required ]; then
        warn "System reboot required (pending kernel or package update)"
        remedy "shutdown -r +1 'Scheduled reboot for pending updates'  # or: reboot"
    else
        ok "No reboot required"
    fi

    # Kernel vs installed
    if [ "$OS_FAMILY" = "debian" ]; then
        INSTALLED_KERNEL=$(dpkg -l 2>/dev/null | grep "^ii.*linux-image" | awk '{print $3}' | sort -V | tail -1 || true)
        RUNNING_KERNEL=$(uname -r)
        if [ -n "$INSTALLED_KERNEL" ] && ! echo "$INSTALLED_KERNEL" | grep -q "$RUNNING_KERNEL"; then
            warn "Running kernel ($RUNNING_KERNEL) differs from latest installed — reboot needed"
            remedy "reboot"
        else
            ok "Running kernel is current"
        fi
    fi

    # /tmp sticky bit
    TMP_PERM=$(stat -c "%a" /tmp 2>/dev/null)
    if [ "$TMP_PERM" = "1777" ]; then
        ok "/tmp has sticky bit (1777)"
    else
        warn "/tmp permissions: $TMP_PERM (expected 1777)"
        remedy "chmod 1777 /tmp"
    fi

    # CPU usage — read /proc/stat twice
    if [ -r /proc/stat ]; then
        read -ra _s1 < /proc/stat
        sleep 0.4
        read -ra _s2 < /proc/stat
        _t1=0; for v in "${_s1[@]:1:7}"; do _t1=$((_t1+v)); done
        _t2=0; for v in "${_s2[@]:1:7}"; do _t2=$((_t2+v)); done
        _dt=$((_t2-_t1)); _di=$((_s2[4]-_s1[4]))
        if [ "$_dt" -gt 0 ]; then
            CPU_USED=$(( (_dt-_di)*100/_dt ))
            info "CPU usage: ${CPU_USED}%"
        fi
        unset _s1 _s2 _t1 _t2 _dt _di
    fi
    LOAD=$(awk '{print $1", "$2", "$3}' /proc/loadavg 2>/dev/null)
    [ -n "$LOAD" ] && info "Load avg:  $LOAD"

    # Memory
    MEM_INFO=$(free -m 2>/dev/null | awk '/^Mem:/ {printf "%d MB used / %d MB total (%.0f%%)", $3, $2, $3*100/$2}')
    if [ -n "$MEM_INFO" ]; then
        MEM_PCT=$(free 2>/dev/null | awk '/^Mem:/ {printf "%.0f", $3*100/$2}')
        if [ "$MEM_PCT" -ge "${MEM_FAIL_PCT:-90}" ] 2>/dev/null; then
            fail "Memory: $MEM_INFO"
            remedy "# Identify top consumers: ps aux --sort=-%mem | head -10"
        elif [ "$MEM_PCT" -ge "${MEM_WARN_PCT:-75}" ] 2>/dev/null; then
            warn "Memory: $MEM_INFO"
        else
            ok "Memory: $MEM_INFO"
        fi
    fi

    # Disk usage
    while read -r line; do
        usage=$(echo "$line" | awk '{print $5}' | tr -d '%')
        mount=$(echo "$line" | awk '{print $6}')
        size=$(echo "$line" | awk '{print $2}')
        used=$(echo "$line" | awk '{print $3}')
        if [ "$usage" -ge "${DISK_FAIL_PCT:-90}" ] 2>/dev/null; then
            fail "Disk $mount: ${usage}% used ($used / $size)"
            remedy "du -sh $mount/* 2>/dev/null | sort -rh | head -20  # find large files"
        elif [ "$usage" -ge "${DISK_WARN_PCT:-75}" ] 2>/dev/null; then
            warn "Disk $mount: ${usage}% used ($used / $size)"
        else
            ok "Disk $mount: ${usage}% used ($used / $size)"
        fi
    done < <(df -h --output=source,size,used,avail,pcent,target 2>/dev/null \
        | tail -n +2 | grep -v "tmpfs\|devtmpfs\|loop\|udev\|squashfs\|overlay" \
        | awk '!seen[$2 FS $3 FS $4]++')  # one line per volume: NFS exports/bind mounts of it repeat its numbers

    # Running services
    if command -v systemctl &>/dev/null; then
        SVC_COUNT=$(systemctl list-units --type=service --state=running 2>/dev/null | grep -c "\.service" || true)
        if [ "$SVC_COUNT" -ge "${SERVICE_COUNT_FAIL:-50}" ] 2>/dev/null; then
            fail "Running services: $SVC_COUNT (very high attack surface)"
            remedy "systemctl list-units --type=service --state=running | less  # disable unneeded services"
        elif [ "$SVC_COUNT" -ge "${SERVICE_COUNT_WARN:-30}" ] 2>/dev/null; then
            warn "Running services: $SVC_COUNT (high attack surface)"
        else
            ok "Running services: $SVC_COUNT"
        fi
    fi
}
