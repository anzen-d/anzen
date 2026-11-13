#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 The Anzen contributors
# checks/modules.sh — Kernel module security

# Modules behind the 2026 page-cache root exploits: Copy Fail (CVE-2026-31431,
# algif_aead), Dirty Frag (CVE-2026-43284 esp4/esp6, CVE-2026-43500 rxrpc) and
# Fragnesia (CVE-2026-46300, esp4/esp6). The kernel loads them on demand for
# an unprivileged user; hosts that do not use AF_ALG AEAD, AFS or IPsec lose
# nothing by blocking them, patched kernel or not. A "blacklist" line does not
# stop on-demand loading by name, only an "install" override does.
_modules_ondemand_check() {
    local proc="${ANZEN_PROC:-/proc}" dirs="${ANZEN_MODPROBE_DIRS:-/etc/modprobe.d /run/modprobe.d /usr/lib/modprobe.d /lib/modprobe.d}"
    command -v modinfo &>/dev/null || return 0
    [ -f /.dockerenv ] || [ -f /run/.containerenv ] && [ -z "${ANZEN_PROC:-}" ] && return 0
    [ "$(_sysctl kernel.modules_disabled 2>/dev/null)" = "1" ] && return 0
    local ipsec=false c
    for c in swanctl ipsec charon strongswan pluto; do command -v "$c" &>/dev/null && ipsec=true; done

    local m open=() pat file
    # shellcheck disable=SC2086
    for m in algif_aead esp4 esp6 rxrpc; do
        case $m in esp*) [ "$ipsec" = true ] && continue ;; esac
        grep -q "^$m " "$proc/modules" 2>/dev/null && continue       # in use
        file=$(modinfo -F filename "$m" 2>/dev/null) || continue      # not built
        case $file in /*) ;; *) continue ;; esac                      # built in: cannot be blocked
        pat="^[[:space:]]*install[[:space:]]+${m//_/[_-]}[[:space:]]"
        grep -rqsE "$pat" $dirs 2>/dev/null && continue
        open+=("$m")
    done
    if [ "${#open[@]}" -gt 0 ]; then
        warn "Kernel modules behind the 2026 page-cache root exploits (Copy Fail, Dirty Frag, Fragnesia) load on demand for any user: ${open[*]}"
        remedy "$(printf 'echo "install %s /bin/false" >> /etc/modprobe.d/anzen-blacklist.conf; ' "${open[@]}")# unused here; skip esp4/esp6 if you plan IPsec, rxrpc for AFS. Keep the kernel updated either way"
    else
        ok "Modules behind the 2026 page-cache root exploits are blocked, in use or not loadable"
    fi
}

run_modules_check() {
    section "Kernel Modules"

    # Check if kernel module loading is locked down
    local modules_disabled
    modules_disabled=$(_sysctl kernel.modules_disabled 2>/dev/null)
    if [ "${modules_disabled:-0}" -eq 1 ]; then
        ok "Kernel module loading disabled (modules_disabled=1)"
    else
        info "Kernel module loading allowed (modules_disabled=0)"
    fi

    # Check for risky/uncommon loaded modules
    local risky_modules=(
        "bluetooth"
        "btusb"
        "firewire_core"
        "thunderbolt"
        "dccp"
        "sctp"
        "rds"
        "tipc"
        "cramfs"
        "freevxfs"
        "jffs2"
        "hfs"
        "hfsplus"
        "squashfs"
        "udf"
        "usb_storage"
    )

    local loaded_risky=()
    if [ -r /proc/modules ]; then
        for mod in "${risky_modules[@]}"; do
            if grep -q "^${mod} " /proc/modules 2>/dev/null; then
                loaded_risky+=("$mod")
            fi
        done
    elif command -v lsmod &>/dev/null; then
        for mod in "${risky_modules[@]}"; do
            if lsmod 2>/dev/null | grep -q "^${mod} "; then
                loaded_risky+=("$mod")
            fi
        done
    fi

    if [ "${#loaded_risky[@]}" -gt 0 ]; then
        for mod in "${loaded_risky[@]}"; do
            warn "Potentially unneeded kernel module loaded: $mod"
            remedy "rmmod '$mod' && echo 'blacklist $mod' >> /etc/modprobe.d/anzen-blacklist.conf"
        done
    else
        ok "No risky kernel modules loaded"
    fi

    # Check module blacklist configuration
    local blacklist_dir="/etc/modprobe.d"
    if [ -d "$blacklist_dir" ]; then
        local blacklisted
        blacklisted=$(grep -rh "^blacklist" "$blacklist_dir" 2>/dev/null | awk '{print $2}' | sort -u | wc -l)
        info "Kernel module blacklist entries: $blacklisted"
    fi

    # Check if usb-storage is blacklisted (common hardening)
    if grep -rq "^blacklist usb.storage" /etc/modprobe.d/ 2>/dev/null; then
        ok "usb-storage module blacklisted"
    else
        warn "usb-storage not blacklisted (disable if USB storage not needed)"
        remedy "echo 'blacklist usb-storage' > /etc/modprobe.d/anzen-blacklist.conf && update-initramfs -u"
    fi

    # Check network protocol modules that are rarely needed
    local unused_proto_mods=()
    for mod in dccp sctp rds tipc; do
        if grep -rq "^blacklist $mod" /etc/modprobe.d/ 2>/dev/null; then
            continue
        fi
        unused_proto_mods+=("$mod")
    done

    if [ "${#unused_proto_mods[@]}" -gt 0 ]; then
        warn "Uncommon network protocols not blacklisted: ${unused_proto_mods[*]}"
        local bl_cmd
        bl_cmd=$(printf 'echo "blacklist %s" >> /etc/modprobe.d/anzen-blacklist.conf; ' "${unused_proto_mods[@]}")
        remedy "${bl_cmd}update-initramfs -u"
    else
        ok "Uncommon network protocol modules blacklisted"
    fi

    _modules_ondemand_check

    # Check kernel module signing
    local signing_pol
    signing_pol=$(cat /proc/sys/kernel/kexec_load_disabled 2>/dev/null)
    if [ "${signing_pol:-0}" -eq 1 ]; then
        ok "kexec loading disabled"
    else
        warn "kexec loading not disabled"
        remedy "sysctl -w kernel.kexec_load_disabled=1 && echo 'kernel.kexec_load_disabled=1' >> /etc/sysctl.d/99-anzen-hardening.conf"
    fi
}
