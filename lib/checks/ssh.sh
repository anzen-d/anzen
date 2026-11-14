#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 The Anzen contributors
# checks/ssh.sh — SSH daemon hardening

# Use sshd -T (compiled effective config) — handles commented/defaulted settings correctly.
# Falls back to raw file parsing if sshd -T is unavailable.
_ssh_val() {
    if [ -z "$_SSHD_T_CACHE" ]; then
        _SSHD_T_CACHE=$(_priv sshd -T 2>/dev/null || true)
    fi
    if [ -n "$_SSHD_T_CACHE" ]; then
        echo "$_SSHD_T_CACHE" | grep -i "^${1} " | awk '{print $2}' | tail -1
    else
        local confd=()
        [ -d /etc/ssh/sshd_config.d ] && mapfile -t confd < <(ls /etc/ssh/sshd_config.d/*.conf 2>/dev/null)
        grep -Eih "^\s*${1}\s" /etc/ssh/sshd_config "${confd[@]}" 2>/dev/null \
            | tail -1 | awk '{print $2}' || true
    fi
}

# SSHole (CVE-2026-123158, November 2026): sshd on musl libc that checks
# passwords itself (no PAM) accepts any 257-1024 byte password for an account
# whose password field is "*", when another account has a $5$/$6$ hash.
# Fixed in OpenSSH 10.6p2; Alpine backported the fix to these package versions.
_SSHOLE_ALPINE_FIXED='10.6_p2-r0 10.3_p1-r2 10.2_p1-r1 10.0_p1-r11 9.9_p2-r1 9.7_p1-r6 9.6_p1-r3 9.3_p2-r4 9.1_p1-r7 9.0_p1-r6'

# The check runs against the host, or inside a running container when
# _SSHOLE_CTR (container ID) and _SSHOLE_RT (docker/podman/nerdctl) are set
_sx() {
    if [ -n "${_SSHOLE_CTR:-}" ]; then "$_SSHOLE_RT" exec -u 0 "$_SSHOLE_CTR" "$@"; else "$@"; fi
}
_sx_priv() {
    if [ -n "${_SSHOLE_CTR:-}" ]; then _sx "$@"; else _priv "$@"; fi
}
_sx_has() {
    if [ -n "${_SSHOLE_CTR:-}" ]; then _sx sh -c "command -v $1" &>/dev/null; else command -v "$1" &>/dev/null; fi
}
_sx_val() {
    if [ -n "${_SSHOLE_CTR:-}" ]; then
        grep -i "^${1} " <<< "$_SSHOLE_CFG" | awk '{print $2}' | tail -1
    else
        _ssh_val "$1"
    fi
}

# 0 = this sshd still has the bug, 1 = fixed. Sets _SSHOLE_VER for the remedy.
_ssh_sshole_unfixed() {
    local pkg fixed f v
    _SSHOLE_VER=""
    if _sx_has apk; then
        for pkg in openssh-server-pam openssh-server; do
            v=$(_sx apk info -e -v "$pkg" 2>/dev/null | head -1)
            [ -n "$v" ] && { _SSHOLE_VER=${v#"$pkg"-}; break; }
        done
    fi
    if [ -n "$_SSHOLE_VER" ]; then
        fixed=10.6_p2-r0
        for f in $_SSHOLE_ALPINE_FIXED; do
            [ "${f%-r*}" = "${_SSHOLE_VER%-r*}" ] && fixed=$f
        done
        [ "$(_sx apk version -t "$_SSHOLE_VER" "$fixed" 2>/dev/null)" = "<" ]
        return
    fi
    # Other musl systems: upstream version from "OpenSSH_10.6p2, OpenSSL ..."
    v=$(_sx sshd -V 2>&1 | grep -o 'OpenSSH_[0-9][0-9.]*p[0-9]*' | head -1)
    _SSHOLE_VER=${v#OpenSSH_}
    [ -n "$_SSHOLE_VER" ] || return 1
    local maj min pl
    maj=${_SSHOLE_VER%%.*}; min=${_SSHOLE_VER#*.}; min=${min%%p*}; min=${min%%.*}; pl=${_SSHOLE_VER##*p}
    [ $((10#$maj * 10000 + 10#$min * 100 + 10#${pl:-0})) -lt 100602 ]
}

# _ssh_sshole_check [CONTAINER_NAME] — messages get a "Container NAME: " prefix
_ssh_sshole_check() {
    local shadow="${ANZEN_SHADOW:-/etc/shadow}" logs="${ANZEN_AUTH_LOGS:-/var/log/messages /var/log/auth.log}"
    local pre="" bin
    if [ -n "${_SSHOLE_CTR:-}" ]; then
        pre="Container $1: "
        bin=$(_sx sh -c 'command -v sshd' 2>/dev/null) || return 0
        _SSHOLE_CFG=$(_sx sshd -T 2>/dev/null || true)
    else
        bin=$(command -v sshd 2>/dev/null) || return 0
    fi
    [ -n "$bin" ] || return 0
    _sx ldd "$bin" 2>&1 | grep -q musl || return 0
    [ "$(_sx_val UsePAM | tr 'A-Z' 'a-z')" = "yes" ] && return 0

    # Accounts with "*" as password field, and whether a $5$/$6$ hash exists
    local star=() hashed=false readable=false u h content
    content=$(_sx_priv cat "$shadow" 2>/dev/null)
    if [ -n "$content" ]; then
        readable=true
        while IFS=: read -r u h _; do
            case $h in
                '*') star+=("$u") ;;
                '$5$'*|'$6$'*) hashed=true ;;
            esac
        done <<< "$content"
    fi

    # Past exploitation: a password login for an account that has no password
    # (host only: containers log to the runtime, not to a file)
    local f hits=()
    if [ "${#star[@]}" -gt 0 ] && [ -z "${_SSHOLE_CTR:-}" ]; then
        for f in $logs; do
            _priv test -r "$f" 2>/dev/null || continue
            for u in "${star[@]}"; do
                _priv grep -qE "sshd.*Accepted password for $u from " "$f" 2>/dev/null && hits+=("$u")
            done
        done
    fi
    if [ "${#hits[@]}" -gt 0 ]; then
        fail "Password login accepted for accounts that have no password (${#hits[@]}) — sign of SSHole exploitation (CVE-2026-123158)"
        local who; who=$(printf '%s\n' "${hits[@]}" | sort -u | tr '\n' ' ')
        remedy "# accounts: ${who}— grep 'Accepted password for' $logs; treat the host as compromised unless every login is explained"
    fi

    local pw; pw=$(_sx_val PasswordAuthentication | tr 'A-Z' 'a-z')
    if ! _ssh_sshole_unfixed; then
        ok "${pre}OpenSSH has the SSHole fix (CVE-2026-123158)"
        return 0
    fi
    local fix
    fix="# update OpenSSH to 10.6p2 or a fixed distribution package (installed: $(_q "$_SSHOLE_VER")) and restart sshd"
    _sx_has apk && fix="apk upgrade -U openssh && rc-service sshd restart  # installed: $(_q "$_SSHOLE_VER"); the upgrade alone does not replace the running sshd"
    [ -n "${_SSHOLE_CTR:-}" ] && fix="# pull or rebuild the image of $(_q "$1") from a fixed base and recreate the container (installed: $(_q "$_SSHOLE_VER")); a fix made inside the container is lost on recreate"
    if [ "${pw:-yes}" != "yes" ]; then
        info "${pre}OpenSSH lacks the SSHole fix (CVE-2026-123158) — not reachable while PasswordAuthentication is off"
        remedy "$fix"
    elif [ "$readable" = true ] && { [ "${#star[@]}" -eq 0 ] || [ "$hashed" = false ]; }; then
        warn "${pre}OpenSSH lacks the SSHole fix (CVE-2026-123158) — not exploitable with the current accounts, one new password or key-only account changes that"
        remedy "$fix"
    else
        fail "${pre}OpenSSH password bypass SSHole (CVE-2026-123158): sshd on musl without PAM accepts an over-long password for accounts with no password set (${#star[@]})"
        remedy "$fix  # until then: PasswordAuthentication no. Accounts: ${star[*]:-unknown, /etc/shadow not readable}"
    fi
}

run_ssh_check() {
    section "SSH Configuration"

    if ! command -v sshd &>/dev/null && ! [ -f /etc/ssh/sshd_config ]; then
        info "SSH server not detected — skipping"
        return
    fi

    _sshd_reload() { echo "systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null"; }

    _SSHD_T_CACHE=""

    # Port
    SSH_PORT=$(_ssh_val "Port"); SSH_PORT=${SSH_PORT:-22}
    UNPRIV_START=$(_sysctl net.ipv4.ip_unprivileged_port_start 2>/dev/null || echo 1024)
    if [ "$SSH_PORT" = "22" ]; then
        warn "SSH on default port 22"
        remedy "sed -i 's/^#*Port.*/Port 2222/' /etc/ssh/sshd_config && $(_sshd_reload)"
    elif [ "$((10#$SSH_PORT))" -ge "$((10#$UNPRIV_START))" ] 2>/dev/null; then
        warn "SSH port $SSH_PORT is in unprivileged range (>= $UNPRIV_START)"
    else
        ok "SSH on non-default privileged port: $SSH_PORT"
    fi

    # PermitRootLogin
    VAL=$(_ssh_val "PermitRootLogin"); VAL=${VAL:-yes}
    if echo "$VAL" | grep -qi "^yes$"; then
        fail "PermitRootLogin: yes — direct root SSH login allowed"
        remedy "sed -i 's/^#*PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config && $(_sshd_reload)"
    elif echo "$VAL" | grep -qi "prohibit-password\|without-password"; then
        ok "PermitRootLogin: $VAL (key-only root)"
    else
        ok "PermitRootLogin: $VAL"
    fi

    # PasswordAuthentication
    VAL=$(_ssh_val "PasswordAuthentication"); VAL=${VAL:-yes}
    if echo "$VAL" | grep -qi "^yes$"; then
        warn "PasswordAuthentication: yes — password logins allowed (prefer keys)"
        remedy "sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config && $(_sshd_reload)"
    else
        ok "PasswordAuthentication: $VAL"
    fi

    # PermitEmptyPasswords
    VAL=$(_ssh_val "PermitEmptyPasswords"); VAL=${VAL:-no}
    if echo "$VAL" | grep -qi "^yes$"; then
        fail "PermitEmptyPasswords: yes"
        remedy "sed -i 's/^#*PermitEmptyPasswords.*/PermitEmptyPasswords no/' /etc/ssh/sshd_config && $(_sshd_reload)"
    else
        ok "PermitEmptyPasswords: $VAL"
    fi

    # X11Forwarding
    VAL=$(_ssh_val "X11Forwarding"); VAL=${VAL:-no}
    if echo "$VAL" | grep -qi "^yes$"; then
        warn "X11Forwarding: yes — disable unless needed"
        remedy "sed -i 's/^#*X11Forwarding.*/X11Forwarding no/' /etc/ssh/sshd_config && $(_sshd_reload)"
    else
        ok "X11Forwarding: $VAL"
    fi

    # AllowTcpForwarding — port forwarding turns any SSH account into a tunnel
    # past the firewall (to internal services, or back out with -R)
    VAL=$(_ssh_val "AllowTcpForwarding"); VAL=${VAL:-yes}
    if echo "$VAL" | grep -qiE "^(yes|all|remote)$"; then
        warn "AllowTcpForwarding: $VAL — SSH users can tunnel past the firewall"
        remedy "echo 'AllowTcpForwarding no' >> /etc/ssh/sshd_config && $(_sshd_reload)  # or Match User <admin> to keep it for one user"
    else
        ok "AllowTcpForwarding: $VAL"
    fi

    # PermitTunnel — tun/tap devices give a full layer-3/2 VPN over SSH
    VAL=$(_ssh_val "PermitTunnel"); VAL=${VAL:-no}
    if echo "$VAL" | grep -qi "^no$"; then
        ok "PermitTunnel: no"
    else
        warn "PermitTunnel: $VAL — SSH users can create a VPN tunnel into this network"
        remedy "sed -i 's/^#*PermitTunnel.*/PermitTunnel no/' /etc/ssh/sshd_config && $(_sshd_reload)"
    fi

    # GatewayPorts — remote forwards bound to all interfaces publish services
    # from the SSH client's side to the whole network
    VAL=$(_ssh_val "GatewayPorts"); VAL=${VAL:-no}
    if echo "$VAL" | grep -qiE "^(yes|clientspecified)$"; then
        warn "GatewayPorts: $VAL — remote port forwards can listen on all interfaces"
        remedy "sed -i 's/^#*GatewayPorts.*/GatewayPorts no/' /etc/ssh/sshd_config && $(_sshd_reload)"
    else
        ok "GatewayPorts: $VAL"
    fi

    # PermitUserEnvironment — ~/.ssh/environment can set LD_PRELOAD and get
    # around ForceCommand and restricted shells
    VAL=$(_ssh_val "PermitUserEnvironment"); VAL=${VAL:-no}
    if echo "$VAL" | grep -qi "^no$"; then
        ok "PermitUserEnvironment: no"
    else
        warn "PermitUserEnvironment: $VAL — users can set LD_PRELOAD and other variables for sshd sessions"
        remedy "sed -i 's/^#*PermitUserEnvironment.*/PermitUserEnvironment no/' /etc/ssh/sshd_config && $(_sshd_reload)"
    fi

    # AllowAgentForwarding — root (or an attacker as root) on this host can use
    # every forwarded agent while its session is open. A policy choice: INFO
    VAL=$(_ssh_val "AllowAgentForwarding"); VAL=${VAL:-yes}
    if echo "$VAL" | grep -qi "^no$"; then
        ok "AllowAgentForwarding: no"
    else
        info "AllowAgentForwarding: $VAL — forwarded agents of logged-in users are usable by root here"
    fi

    # Host-based and rhosts trust: a login is accepted because of the client
    # host name, so one compromised host opens every host that trusts it
    VAL=$(_ssh_val "HostbasedAuthentication"); VAL=${VAL:-no}
    if echo "$VAL" | grep -qi "^yes$"; then
        warn "HostbasedAuthentication: yes — logins are trusted by client host instead of a user key"
        remedy "sed -i 's/^#*HostbasedAuthentication.*/HostbasedAuthentication no/' /etc/ssh/sshd_config && $(_sshd_reload)"
    else
        ok "HostbasedAuthentication: no"
    fi
    VAL=$(_ssh_val "IgnoreRhosts"); VAL=${VAL:-yes}
    if echo "$VAL" | grep -qi "^no$"; then
        warn "IgnoreRhosts: no — ~/.rhosts and ~/.shosts files are honoured"
        remedy "sed -i 's/^#*IgnoreRhosts.*/IgnoreRhosts yes/' /etc/ssh/sshd_config && $(_sshd_reload)"
    else
        ok "IgnoreRhosts: $VAL"
    fi

    # MaxAuthTries
    VAL=$(_ssh_val "MaxAuthTries"); VAL=${VAL:-6}
    if [ "$VAL" -gt 4 ] 2>/dev/null; then
        warn "MaxAuthTries: $VAL (recommended: 3)"
        remedy "sed -i 's/^#*MaxAuthTries.*/MaxAuthTries 3/' /etc/ssh/sshd_config && $(_sshd_reload)"
    else
        ok "MaxAuthTries: $VAL"
    fi

    # Protocol
    VAL=$(_ssh_val "Protocol")
    if [ "$VAL" = "1" ]; then
        fail "SSH Protocol 1 enabled — insecure"
        remedy "sed -i 's/^Protocol.*/Protocol 2/' /etc/ssh/sshd_config && $(_sshd_reload)"
    else
        ok "SSH Protocol: ${VAL:-2 (default)}"
    fi

    # ClientAliveInterval
    VAL=$(_ssh_val "ClientAliveInterval"); VAL=${VAL:-0}
    if [ "$((10#$VAL))" -eq 0 ] 2>/dev/null; then
        warn "ClientAliveInterval: 0 — idle sessions never time out"
        remedy "echo 'ClientAliveInterval 300' >> /etc/ssh/sshd_config && echo 'ClientAliveCountMax 2' >> /etc/ssh/sshd_config && $(_sshd_reload)"
    elif [ "$((10#$VAL))" -le 300 ] 2>/dev/null; then
        ok "ClientAliveInterval: ${VAL}s"
    else
        warn "ClientAliveInterval: ${VAL}s (consider ≤ 300)"
    fi

    # LoginGraceTime
    VAL=$(_ssh_val "LoginGraceTime"); VAL=${VAL:-120}
    if [ "$((10#$VAL))" -gt 60 ] 2>/dev/null; then
        warn "LoginGraceTime: ${VAL}s (recommended ≤ 60)"
        remedy "sed -i 's/^#*LoginGraceTime.*/LoginGraceTime 30/' /etc/ssh/sshd_config && $(_sshd_reload)"
    else
        ok "LoginGraceTime: ${VAL}s"
    fi

    # UseDNS
    VAL=$(_ssh_val "UseDNS"); VAL=${VAL:-yes}
    if echo "$VAL" | grep -qi "^yes$"; then
        warn "UseDNS: yes — can slow logins"
        remedy "echo 'UseDNS no' >> /etc/ssh/sshd_config && $(_sshd_reload)"
    else
        ok "UseDNS: $VAL"
    fi

    # AllowUsers / AllowGroups
    ALLOW_USERS=$(_ssh_val "AllowUsers")
    ALLOW_GROUPS=$(_ssh_val "AllowGroups")
    if [ -n "$ALLOW_USERS" ]; then
        ok "AllowUsers: $ALLOW_USERS"
    elif [ -n "$ALLOW_GROUPS" ]; then
        ok "AllowGroups: $ALLOW_GROUPS"
    else
        warn "AllowUsers/AllowGroups not set — all system users can attempt SSH"
        # Never suggest "AllowUsers root": with PermitRootLogin no it locks everyone out
        local _u; _u=$(_invoking_user)
        if [ "$_u" = root ]; then
            remedy "# echo 'AllowUsers <your-admin-user>' >> /etc/ssh/sshd_config && $(_sshd_reload)"
        else
            remedy "echo 'AllowUsers $_u' >> /etc/ssh/sshd_config && $(_sshd_reload)"
        fi
    fi

    # Cipher/MAC hardening
    CIPHERS=$(_ssh_val "Ciphers")
    MACS=$(_ssh_val "MACs")
    KEXALGS=$(_ssh_val "KexAlgorithms")
    if [ -n "$CIPHERS" ] && [ -n "$MACS" ] && [ -n "$KEXALGS" ]; then
        ok "Ciphers/MACs/KexAlgorithms explicitly configured"
        if echo "$CIPHERS" | grep -qiE "arcfour|3des|blowfish|cast|rc4"; then
            fail "Weak ciphers in SSH config: $CIPHERS"
            remedy "sed -i 's/^Ciphers.*/Ciphers aes256-gcm@openssh.com,chacha20-poly1305@openssh.com,aes128-gcm@openssh.com/' /etc/ssh/sshd_config && $(_sshd_reload)"
        fi
        if echo "$MACS" | grep -qiE "md5|sha1$|umac-64@"; then
            warn "Potentially weak MACs: $MACS"
        fi
    else
        warn "Ciphers/MACs/KexAlgorithms not explicitly set — using OpenSSH defaults"
        # One line: remediate.sh prints remedies verbatim, so a "\n" heredoc
        # never ended and swallowed every later command into sshd_config
        remedy "echo 'Ciphers aes256-gcm@openssh.com,chacha20-poly1305@openssh.com' >> /etc/ssh/sshd_config && echo 'MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com' >> /etc/ssh/sshd_config && echo 'KexAlgorithms curve25519-sha256,diffie-hellman-group16-sha512' >> /etc/ssh/sshd_config && $(_sshd_reload)"
    fi

    # Authorized keys
    KEY_COUNT=0
    for f in /root/.ssh/authorized_keys /home/*/.ssh/authorized_keys; do
        [ -f "$f" ] || continue
        COUNT=$(wc -l < "$f")
        info "Authorized keys: $f ($COUNT key(s))"
        KEY_COUNT=$((KEY_COUNT + COUNT))
        PERM=$(stat -c "%a" "$f" 2>/dev/null)
        if [ "$PERM" != "600" ] && [ "$PERM" != "644" ]; then
            warn "Loose permissions on $f: $PERM"
            remedy "chmod 600 $(_q "$f")"
        fi
    done
    [ "$KEY_COUNT" -eq 0 ] && info "No authorized_keys files found"

    _ssh_sshole_check ""
}
