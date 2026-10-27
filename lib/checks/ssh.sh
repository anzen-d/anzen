#!/bin/bash
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
        remedy "echo 'AllowUsers $(whoami)' >> /etc/ssh/sshd_config && $(_sshd_reload)"
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
        remedy "cat >> /etc/ssh/sshd_config <<'EOF'\nCiphers aes256-gcm@openssh.com,chacha20-poly1305@openssh.com\nMACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com\nKexAlgorithms curve25519-sha256,diffie-hellman-group16-sha512\nEOF\n$(_sshd_reload)"
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
            remedy "chmod 600 $f"
        fi
    done
    [ "$KEY_COUNT" -eq 0 ] && info "No authorized_keys files found"
}
