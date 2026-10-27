#!/bin/bash
# checks/modules.sh — Kernel module security

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
