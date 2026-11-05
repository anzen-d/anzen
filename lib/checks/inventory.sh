#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 The Anzen contributors
# checks/inventory.sh — asset inventory (INFO only, no score): hardware,
# package database age, administrators, disk encryption, Secure Boot

# _inv_pkg_db — "PATH COUNT_COMMAND" for the package manager in use
_inv_pkg_db() {
    case "${PKG_MGR:-}" in
        apt)         echo "/var/lib/dpkg/status|dpkg-query -W -f=.\\n" ;;
        dnf|yum|zypper) for d in /var/lib/rpm /usr/lib/sysimage/rpm; do [ -d "$d" ] && { echo "$d|rpm -qa"; return; }; done ;;
        apk)         echo "/lib/apk/db/installed|apk info" ;;
        pacman)      echo "/var/lib/pacman/local|pacman -Qq" ;;
    esac
}

run_inventory_check() {
    section "Inventory"
    local v vendor model serial

    vendor=$(cat /sys/class/dmi/id/sys_vendor 2>/dev/null)
    model=$(cat /sys/class/dmi/id/product_name 2>/dev/null)
    [ -n "$vendor$model" ] && info "Hardware: ${vendor:-unknown} ${model:-}"
    # product_serial is root-only
    serial=$(_priv cat /sys/class/dmi/id/product_serial 2>/dev/null)
    [ -n "$serial" ] && info "Serial number: $serial"
    v=$(systemd-detect-virt 2>/dev/null)
    [ -n "$v" ] && [ "$v" != none ] && info "Virtualization: $v"

    v=$(awk -F': *' '/^model name/ { print $2; exit }' /proc/cpuinfo 2>/dev/null)
    [ -n "$v" ] && info "CPU: $v ($(nproc 2>/dev/null || echo '?') threads)"
    v=$(awk '/^MemTotal:/ { printf "%.1f", $2 / 1048576 }' /proc/meminfo 2>/dev/null)
    [ -n "$v" ] && info "Memory: $v GiB"

    local db path cmd mt n
    db=$(_inv_pkg_db)
    if [ -n "$db" ]; then
        path=${db%%|*}; cmd=${db#*|}
        mt=$(stat -c %Y "$path" 2>/dev/null)
        [ -n "$mt" ] && info "Package database last changed $(date -d "@$mt" +%Y-%m-%d 2>/dev/null) ($(( ($(date +%s) - mt) / 86400 )) days ago)"
        # shellcheck disable=SC2086  # cmd is a command with arguments
        n=$($cmd 2>/dev/null | wc -l)
        [ "${n:-0}" -gt 0 ] && info "Installed packages: $n"
    fi

    local admins="" g m
    for g in sudo wheel admin; do
        m=$(getent group "$g" 2>/dev/null | cut -d: -f4)
        [ -n "$m" ] && admins="$admins${admins:+,}$m"
    done
    [ -n "$admins" ] && info "Administrators (sudo/wheel/admin): $(printf '%s' "$admins" | tr ',' '\n' | sort -u | paste -sd, - | sed 's/,/, /g')"

    if command -v lsblk >/dev/null 2>&1; then
        if lsblk -rno TYPE 2>/dev/null | grep -qx crypt; then info "Disk encryption: dm-crypt/LUKS volumes present"
        else info "Disk encryption: no dm-crypt/LUKS volumes"; fi
    fi
    if command -v mokutil >/dev/null 2>&1; then
        v=$(mokutil --sb-state 2>/dev/null | head -1)
        [ -n "$v" ] && info "Secure Boot: ${v#SecureBoot }"
    elif [ -d /sys/firmware/efi ]; then
        info "Firmware: UEFI"
    else
        info "Firmware: BIOS (legacy boot)"
    fi
    return 0
}
