#!/bin/bash
# checks/kernel.sh — Kernel hardening (sysctl) and MAC framework

_SYSCTL_CONF="/etc/sysctl.d/99-anzen-hardening.conf"

run_kernel_check() {
    section "Kernel Hardening (sysctl)"

    _sysctl_check() {
        local key=$1 expected=$2 label=${3:-$1} severity=${4:-warn}
        local val
        val=$(_sysctl "$key" 2>/dev/null)
        if [ -z "$val" ]; then
            info "$label: not available on this kernel"
            return
        fi
        if [ "$val" = "$expected" ]; then
            ok "$label: $val"
        else
            [ "$severity" = "fail" ] && fail "$label: $val (expected $expected)" \
                                     || warn "$label: $val (expected $expected)"
            remedy "sysctl -w ${key}=${expected} && echo '${key}=${expected}' >> $_SYSCTL_CONF"
        fi
    }

    _sysctl_check kernel.randomize_va_space       2 "ASLR"                       warn
    _sysctl_check kernel.dmesg_restrict           1 "dmesg_restrict"              warn
    _sysctl_check kernel.kptr_restrict            2 "kptr_restrict"               warn
    _sysctl_check net.ipv4.tcp_syncookies         1 "TCP SYN cookies"             warn
    _sysctl_check net.ipv4.conf.all.log_martians  1 "Log martian packets"         warn
    _sysctl_check net.ipv4.conf.all.rp_filter     1 "Reverse path filtering"      warn
    _sysctl_check net.ipv4.conf.all.accept_redirects   0 "ICMP redirects (IPv4)" warn
    _sysctl_check net.ipv6.conf.all.accept_redirects   0 "ICMP redirects (IPv6)" warn
    _sysctl_check net.ipv4.conf.all.accept_source_route 0 "Source routing (IPv4)" warn
    _sysctl_check net.ipv6.conf.all.accept_source_route 0 "Source routing (IPv6)" warn
    _sysctl_check net.ipv4.icmp_echo_ignore_broadcasts 1 "Ignore ICMP broadcasts" warn
    _sysctl_check fs.protected_symlinks  1 "Protected symlinks"  warn
    _sysctl_check fs.protected_hardlinks 1 "Protected hardlinks" warn

    local fwd
    fwd=$(_sysctl net.ipv4.ip_forward 2>/dev/null)
    if [ "$fwd" = "1" ]; then
        warn "IP forwarding enabled — verify intent (expected on routers/container hosts)"
    else
        ok "IP forwarding disabled"
    fi

    fwd=$(_sysctl net.ipv6.conf.all.forwarding 2>/dev/null)
    [ "$fwd" = "1" ] && warn "IPv6 forwarding enabled — verify intent" || ok "IPv6 forwarding disabled"

    local sr
    sr=$(_sysctl net.ipv4.conf.all.send_redirects 2>/dev/null)
    if [ "$sr" = "1" ]; then
        warn "Sending ICMP redirects enabled"
        remedy "sysctl -w net.ipv4.conf.all.send_redirects=0 && echo 'net.ipv4.conf.all.send_redirects=0' >> $_SYSCTL_CONF"
    else
        ok "Sending ICMP redirects disabled"
    fi

    local sd
    sd=$(_sysctl fs.suid_dumpable 2>/dev/null)
    if [ "$sd" = "0" ]; then
        ok "SUID core dumps disabled"
    elif [ -z "$sd" ]; then
        info "fs.suid_dumpable: not available on this kernel"
    else
        warn "fs.suid_dumpable=$sd (recommended: 0)"
        remedy "sysctl -w fs.suid_dumpable=0 && echo 'fs.suid_dumpable=0' >> $_SYSCTL_CONF"
    fi

    section "MAC Framework (AppArmor / SELinux)"

    local mac_found=false

    if command -v aa-status &>/dev/null || [ -d /sys/kernel/security/apparmor ]; then
        if aa-status --enabled 2>/dev/null; then
            local profiles enforcing
            profiles=$(aa-status 2>/dev/null | grep "profiles are loaded" | awk '{print $1}')
            enforcing=$(aa-status 2>/dev/null | grep "profiles are in enforce mode" | awk '{print $1}')
            ok "AppArmor enabled (${profiles:-?} profiles, ${enforcing:-?} enforcing)"
            mac_found=true
        else
            warn "AppArmor present but not enabled"
            remedy "aa-enforce /etc/apparmor.d/*  # enforce all profiles"
        fi
    fi

    if command -v getenforce &>/dev/null; then
        local se
        se=$(getenforce 2>/dev/null)
        case "$se" in
            Enforcing)  ok "SELinux: Enforcing"; mac_found=true ;;
            Permissive) warn "SELinux: Permissive — not enforcing"
                        remedy "setenforce 1 && sed -i 's/SELINUX=permissive/SELINUX=enforcing/' /etc/selinux/config" ;;
            Disabled)   warn "SELinux: Disabled"
                        remedy "sed -i 's/SELINUX=disabled/SELINUX=enforcing/' /etc/selinux/config && reboot" ;;
        esac
    fi

    $mac_found || warn "No MAC framework active (AppArmor or SELinux)"
}
