#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 The Anzen contributors
# checks/network.sh — Firewall and open ports

_port_name() {
    case $1 in
        21) echo "FTP" ;;     22) echo "SSH" ;;       23) echo "Telnet" ;;
        25) echo "SMTP" ;;    53) echo "DNS" ;;        80) echo "HTTP" ;;
        110) echo "POP3" ;;   111) echo "RPC" ;;       139) echo "NetBIOS" ;;
        143) echo "IMAP" ;;   443) echo "HTTPS" ;;     445) echo "SMB" ;;
        873) echo "rsync" ;;  3306) echo "MySQL" ;;    3389) echo "RDP" ;;
        5432) echo "PostgreSQL" ;; 5900) echo "VNC" ;; 6379) echo "Redis" ;;
        8080) echo "HTTP-alt" ;; 9200) echo "Elasticsearch" ;; 27017) echo "MongoDB" ;;
        512) echo "rexec" ;;  513) echo "rlogin" ;;    514) echo "rsh" ;;
        5984) echo "CouchDB" ;; 11211) echo "Memcached" ;;
        *) echo "" ;;
    esac
}

run_network_check() {
    section "Firewall"

    local fw_active=false

    if command -v ufw &>/dev/null; then
        UFW_STATUS=$(_priv ufw status 2>/dev/null | head -1)
        if echo "$UFW_STATUS" | grep -q "active"; then
            ok "UFW firewall is active"
            fw_active=true
        else
            fail "UFW installed but INACTIVE"
            remedy "ufw enable"
        fi
    fi

    if command -v firewall-cmd &>/dev/null; then
        if systemctl is-active --quiet firewalld 2>/dev/null; then
            ok "firewalld is active"
            fw_active=true
        else
            warn "firewalld installed but not running"
            remedy "systemctl enable --now firewalld"
        fi
    fi

    if command -v nft &>/dev/null; then
        NFT_RULES=$(_priv nft list ruleset 2>/dev/null | grep -c "chain\|rule" || true)
        if [ "$NFT_RULES" -gt 2 ]; then
            ok "nftables active ($NFT_RULES rules/chains)"
            fw_active=true
        fi
    fi

    if ! $fw_active && command -v iptables &>/dev/null; then
        RULES=$(_priv iptables -L INPUT -n 2>/dev/null | grep -c "^ACCEPT\|^DROP\|^REJECT" || true)
        if [ "$((10#$RULES))" -gt 2 ]; then
            ok "iptables INPUT has $RULES rules"
            fw_active=true
        else
            warn "iptables present but INPUT chain appears default-ACCEPT"
            remedy "iptables -P INPUT DROP && iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT && iptables -A INPUT -p tcp --dport 22 -j ACCEPT"
        fi
    fi

    if ! $fw_active; then
        fail "No active firewall detected (checked: ufw, firewalld, nftables, iptables)"
        remedy "apt-get install -y ufw && ufw allow ssh && ufw enable"
    fi

    section "Open Ports & Services"

    PUBLIC_COUNT=$(ss -tlnp 2>/dev/null | grep "LISTEN" | grep -vE "127\.|::1" | grep -c "." || true)
    if [ "$((10#$PUBLIC_COUNT))" -ge 30 ]; then
        warn "Large number of public listening ports: $PUBLIC_COUNT"
    else
        info "Public listening ports: $PUBLIC_COUNT"
    fi

    local port svc
    for port in 21 23 512 513 514 3306 3389 5900 5984 6379 9200 11211 27017; do
        svc=$(_port_name "$port")
        if _svc_public_tcp "$port"; then
            # HTTP datastores are recognisable: another app on the port is not one
            if ! _is_risky_service "$port"; then
                warn "Port ${port} open publicly (usual $svc port, but another service answers)"
                continue
            fi
            fail "High-risk port open publicly: ${port}/$svc"
            remedy "ufw deny $port  # or: systemctl stop ${svc,}"
        fi
    done

    info "Public listening ports:"
    while read -r addr; do
        port=$(echo "$addr" | rev | cut -d: -f1 | rev | tr -d '"]')
        name=$(_port_name "$port")
        [ -n "$name" ] && info "  :$port  ($name)" || info "  :$port"
    done < <(ss -tlnp 2>/dev/null | grep "LISTEN" | grep -vE "127\.|::1\b" \
             | awk '{print $4}' | sort -t: -k2 -n | uniq)

    if _svc_public_tcp 111; then
        warn "RPC portmapper (111) exposed — disable if NFS not needed"
        remedy "systemctl disable --now rpcbind && ufw deny 111"
    fi
}
