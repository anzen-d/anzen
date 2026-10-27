#!/bin/bash
# checks/network2.sh — Advanced network security checks

run_network2_check() {
    section "Network (Advanced)"

    # Promiscuous mode NICs
    local promisc_found=0
    while IFS= read -r iface; do
        iface="${iface%%:*}"
        FLAGS=$(ip link show "$iface" 2>/dev/null | grep -o 'PROMISC')
        if [ -n "$FLAGS" ]; then
            fail "Interface in promiscuous mode: $iface"
            remedy "ip link set $iface promisc off"
            promisc_found=$((promisc_found+1))
        fi
    done < <(ip -o link show 2>/dev/null | awk '{print $2}')
    [ "$promisc_found" -eq 0 ] && ok "No NICs in promiscuous mode"

    # IPv6 privacy extensions
    if [ -d /proc/sys/net/ipv6 ]; then
        local ipv6_priv
        ipv6_priv=$(_sysctl net.ipv6.conf.all.use_tempaddr 2>/dev/null)
        if [ "${ipv6_priv:-0}" -lt 2 ]; then
            warn "IPv6 privacy extensions not enabled (use_tempaddr=$ipv6_priv)"
            remedy "sysctl -w net.ipv6.conf.all.use_tempaddr=2 && echo 'net.ipv6.conf.all.use_tempaddr=2' >> /etc/sysctl.d/99-anzen-hardening.conf"
        else
            ok "IPv6 privacy extensions enabled"
        fi
    else
        info "IPv6 not available"
    fi

    # Tunnel/VPN interfaces (informational)
    local tunnels
    tunnels=$(ip -o link show 2>/dev/null | awk '{print $2}' | tr -d ':' \
        | grep -E '^(tun|tap|wg|vpn|ipsec|gre|vxlan|sit)' || true)
    if [ -n "$tunnels" ]; then
        while IFS= read -r t; do
            info "Tunnel/VPN interface detected: $t"
        done <<< "$tunnels"
    else
        ok "No tunnel interfaces detected"
    fi

    # IP forwarding
    local ip_fwd
    ip_fwd=$(_sysctl net.ipv4.ip_forward 2>/dev/null)
    if [ "${ip_fwd:-0}" -eq 1 ]; then
        warn "IPv4 forwarding enabled (net.ipv4.ip_forward=1)"
        remedy "sysctl -w net.ipv4.ip_forward=0 && echo 'net.ipv4.ip_forward=0' >> /etc/sysctl.d/99-anzen-hardening.conf"
    else
        ok "IPv4 forwarding disabled"
    fi

    # Source routing
    local src_rt
    src_rt=$(_sysctl net.ipv4.conf.all.accept_source_route 2>/dev/null)
    if [ "${src_rt:-1}" -ne 0 ]; then
        fail "IPv4 source routing accepted"
        remedy "sysctl -w net.ipv4.conf.all.accept_source_route=0 && echo 'net.ipv4.conf.all.accept_source_route=0' >> /etc/sysctl.d/99-anzen-hardening.conf"
    else
        ok "IPv4 source routing disabled"
    fi

    # ICMP redirect acceptance
    local icmp_redir
    icmp_redir=$(_sysctl net.ipv4.conf.all.accept_redirects 2>/dev/null)
    if [ "${icmp_redir:-1}" -ne 0 ]; then
        warn "ICMP redirects accepted"
        remedy "sysctl -w net.ipv4.conf.all.accept_redirects=0 && echo 'net.ipv4.conf.all.accept_redirects=0' >> /etc/sysctl.d/99-anzen-hardening.conf"
    else
        ok "ICMP redirects disabled"
    fi

    # Reverse path filtering
    local rp_filter
    rp_filter=$(_sysctl net.ipv4.conf.all.rp_filter 2>/dev/null)
    if [ "${rp_filter:-0}" -eq 0 ]; then
        warn "Reverse path filtering disabled"
        remedy "sysctl -w net.ipv4.conf.all.rp_filter=1 && echo 'net.ipv4.conf.all.rp_filter=1' >> /etc/sysctl.d/99-anzen-hardening.conf"
    else
        ok "Reverse path filtering enabled (rp_filter=$rp_filter)"
    fi

    # SYN cookies
    local syn_cookies
    syn_cookies=$(_sysctl net.ipv4.tcp_syncookies 2>/dev/null)
    if [ "${syn_cookies:-0}" -ne 1 ]; then
        fail "SYN cookies not enabled"
        remedy "sysctl -w net.ipv4.tcp_syncookies=1 && echo 'net.ipv4.tcp_syncookies=1' >> /etc/sysctl.d/99-anzen-hardening.conf"
    else
        ok "SYN cookies enabled"
    fi

    # Open ports listening on all interfaces (0.0.0.0 / ::)
    local open_all
    open_all=$(ss -tlnp 2>/dev/null | awk 'NR>1 && ($4 ~ /^0\.0\.0\.0:/ || $4 ~ /^\*:/ || $4 ~ /^:::/)' | awk '{print $4}' | sort -u)
    if [ -n "$open_all" ]; then
        while IFS= read -r addr; do
            warn "Service listening on all interfaces: $addr"
        done <<< "$open_all"
    else
        ok "No services unexpectedly listening on all interfaces"
    fi
}
