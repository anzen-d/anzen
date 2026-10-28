#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 The Anzen contributors
# checks/services.sh — Containers, databases, brute-force protection, SMB

run_services_check() {
    section "Docker & Containers"

    local _u; _u=$(_invoking_user)
    if groups "$_u" 2>/dev/null | grep -qw docker; then
        fail "User '$_u' is in 'docker' group — equivalent to passwordless root"
        remedy "gpasswd -d $(_q "$_u") docker  # requires logout to take effect"
    fi
    if groups "$_u" 2>/dev/null | grep -qw microk8s; then
        warn "User '$_u' is in 'microk8s' group — verify cluster RBAC"
    fi

    if command -v docker &>/dev/null; then
        RUNNING=$(docker ps -q 2>/dev/null | wc -l)
        info "Running containers: $RUNNING"

        PRIV=$(docker ps --quiet 2>/dev/null \
            | xargs -I{} docker inspect {} \
                --format '{{.Name}} privileged={{.HostConfig.Privileged}}' 2>/dev/null \
            | grep "privileged=true" || true)
        if [ -n "$PRIV" ]; then
            fail "Privileged container(s): $PRIV"
            remedy "# Edit docker-compose.yml or run flags to remove privileged: true"
        else
            ok "No privileged containers"
        fi

        HOST_NET=$(docker ps --quiet 2>/dev/null \
            | xargs -I{} docker inspect {} \
                --format '{{.Name}} network={{.HostConfig.NetworkMode}}' 2>/dev/null \
            | grep "network=host" || true)
        [ -n "$HOST_NET" ] && warn "Container(s) using host network: $HOST_NET"

        if [ -S /var/run/docker.sock ]; then
            SOCK_PERM=$(stat -c "%a %U:%G" /var/run/docker.sock 2>/dev/null)
            info "Docker socket: $SOCK_PERM"
        fi
    fi

    section "Intrusion Prevention"

    IPS_FOUND=false

    if command -v fail2ban-client &>/dev/null; then
        STATUS=$(systemctl is-active fail2ban 2>/dev/null || echo "unknown")
        if [ "$STATUS" = "active" ]; then
            ok "fail2ban is active (native)"
            JAILS=$(_priv fail2ban-client status 2>/dev/null | grep "Jail list" | cut -d: -f2 | xargs)
            [ -n "$JAILS" ] && info "fail2ban jails: $JAILS"
            IPS_FOUND=true
        else
            warn "fail2ban installed but not running"
            remedy "systemctl enable --now fail2ban"
        fi
    fi

    if ! $IPS_FOUND && command -v docker &>/dev/null; then
        if docker ps 2>/dev/null | grep -qi "fail2ban"; then
            ok "fail2ban running in Docker"; IPS_FOUND=true
        fi
    fi

    if command -v cscli &>/dev/null; then
        STATUS=$(systemctl is-active crowdsec 2>/dev/null || echo "unknown")
        if [ "$STATUS" = "active" ]; then
            ok "CrowdSec is active (native)"; IPS_FOUND=true
        else
            warn "CrowdSec installed but not running"
            remedy "systemctl enable --now crowdsec"
        fi
    fi

    if ! $IPS_FOUND && command -v docker &>/dev/null; then
        if docker ps 2>/dev/null | grep -qi "crowdsec"; then
            ok "CrowdSec running in Docker"; IPS_FOUND=true
        fi
    fi

    if ! $IPS_FOUND; then
        fail "No intrusion prevention system (fail2ban or CrowdSec)"
        remedy "apt-get install -y fail2ban && systemctl enable --now fail2ban"
    fi

    section "Database Exposure"

    if ss -tlnp 2>/dev/null | grep -q ":5432[[:space:]]"; then
        if ss -tlnp 2>/dev/null | grep -v "127\." | grep -q ":5432[[:space:]]"; then
            warn "PostgreSQL listening on 0.0.0.0:5432"
            remedy "# In postgresql.conf: listen_addresses = 'localhost'\nsystemctl restart postgresql"
        else
            ok "PostgreSQL bound to localhost"
        fi
        PG_HBA=$(find /etc/postgresql /var/lib/postgresql -name pg_hba.conf 2>/dev/null | head -1)
        if [ -n "$PG_HBA" ]; then
            if grep -vE "^\s*(#|$)" "$PG_HBA" 2>/dev/null | grep -q "[[:space:]]trust$"; then
                fail "pg_hba.conf: 'trust' auth — passwordless DB access"
                remedy "# Replace 'trust' with 'scram-sha-256' or 'md5' in $PG_HBA"
            else
                ok "pg_hba.conf: no 'trust' auth"
            fi
        fi
    fi

    if ss -tlnp 2>/dev/null | grep -v "127\." | grep -q ":6379[[:space:]]"; then
        fail "Redis (6379) exposed on public interface"
        remedy "sed -i 's/^bind .*/bind 127.0.0.1/' /etc/redis/redis.conf && systemctl restart redis"
    fi

    if ss -tlnp 2>/dev/null | grep -v "127\." | grep -q ":3306[[:space:]]"; then
        warn "MySQL/MariaDB (3306) exposed on public interface"
        remedy "# In my.cnf: bind-address = 127.0.0.1\nsystemctl restart mysql"
    fi

    section "Samba / SMB"

    if ss -tlnp 2>/dev/null | grep -qE ":(139|445)[[:space:]]"; then
        warn "Samba (SMB) is listening — verify shares are locked down"
        if command -v testparm &>/dev/null; then
            GUEST=$(_priv testparm -s 2>/dev/null | grep -iE "guest ok|public" | grep -iv "no" | head -5 || true)
            if [ -n "$GUEST" ]; then
                fail "Samba guest/public share may be enabled: $GUEST"
                remedy "# In smb.conf under [global]: map to guest = never\nguest ok = no"
            else
                ok "No obvious guest shares in Samba config"
            fi
        fi
    fi
}
