#!/bin/bash
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

    declare -A RISKY=( [23]="Telnet" [21]="FTP" [512]="rexec" [513]="rlogin" [514]="rsh"
                       [3306]="MySQL" [6379]="Redis" [9200]="Elasticsearch" [27017]="MongoDB"
                       [5900]="VNC" [3389]="RDP" [5984]="CouchDB" [11211]="Memcached" )
    for port in "${!RISKY[@]}"; do
        if ss -tlnp 2>/dev/null | grep "LISTEN" | grep -vE "127\.|::1\b" | grep -q ":${port}[[:space:]\"]"; then
            # HTTP datastores are recognisable: another app on the port is not one
            if ! _is_risky_service "$port"; then
                warn "Port ${port} open publicly (usual ${RISKY[$port]} port, but another service answers)"
                continue
            fi
            fail "High-risk port open publicly: ${port}/${RISKY[$port]}"
            remedy "ufw deny $port  # or: systemctl stop ${RISKY[$port],}"
        fi
    done

    info "Public listening ports:"
    while read -r addr; do
        port=$(echo "$addr" | rev | cut -d: -f1 | rev | tr -d '"]')
        name=$(_port_name "$port")
        [ -n "$name" ] && info "  :$port  ($name)" || info "  :$port"
    done < <(ss -tlnp 2>/dev/null | grep "LISTEN" | grep -vE "127\.|::1\b" \
             | awk '{print $4}' | sort -t: -k2 -n | uniq)

    if ss -tlnp 2>/dev/null | grep -v "127\." | grep -q ":111[[:space:]]"; then
        warn "RPC portmapper (111) exposed — disable if NFS not needed"
        remedy "systemctl disable --now rpcbind && ufw deny 111"
    fi
}
