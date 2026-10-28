#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 The Anzen contributors
# checks/secrets.sh — Secrets and credential exposure

# _key_files — private-key files writable by group or accessible by others
# (group read is how Debian's ssl-cert group works). Permissions are filtered
# first — a host can hold 100k+ properly locked keys — then id_* and .p12
# count by name, .pem/.key only with a PRIVATE KEY block: certificates and
# chains share those extensions. Dependency trees and test fixtures are pruned
# so find does not walk them at all.
_key_files() {
    local -a skip=( \( -name node_modules -o -name vendor -o -name testdata -o -name fixtures
                     -o -name site-packages -o -name .cache -o -path "*/go/pkg/mod"
                     -o -path "*/containers/storage/overlay" -o -path "*/docker/overlay2"
                     -o -path "*/ca-trust" -o -path "*/ca-certificates" \) -prune -o )
    local roots=(/home /root /etc/ssl /opt /srv)
    # One walk: by-name matches print directly, .pem/.key go to batched grep
    find "${roots[@]}" -xdev "${skip[@]}" -type f -perm /027 \
        \( \( -name "id_rsa" -o -name "id_ecdsa" -o -name "id_ed25519" -o -name "*.p12" \) -print \
        -o \( -name "*.pem" -o -name "*.key" \) \
        -exec grep -lE -- '-----BEGIN ([A-Z]+ )?PRIVATE KEY-----' {} + \) 2>/dev/null
}

run_secrets_check() {
    section "Secrets & Credentials"
    local key_files; key_files=$(_key_files)

    # Private key files with loose permissions
    local loose_keys=0
    while IFS= read -r f; do
        fail "Private key with loose permissions: $f ($(stat -c "%a" "$f" 2>/dev/null))"
        remedy "chmod 600 $(_q "$f")"
        loose_keys=$((loose_keys+1))
    done < <(head -30 <<< "$key_files" | grep .)
    [ "$loose_keys" -eq 0 ] && ok "No private keys with loose permissions found"

    # World-readable private keys
    local world_keys
    world_keys=$(while IFS= read -r f; do
        [ -n "$f" ] && [ $((8#$(stat -c %a "$f") & 8#004)) -ne 0 ] && echo "$f"
    done <<< "$key_files" | head -10)
    if [ -n "$world_keys" ]; then
        while IFS= read -r f; do
            fail "World-readable private key: $f"
            remedy "chmod 600 $(_q "$f")"
        done <<< "$world_keys"
    fi

    # .env files readable by current user
    local env_count=0
    while IFS= read -r f; do
        warn ".env file found: $f"
        env_count=$((env_count+1))
        [ "$env_count" -ge 5 ] && break
    done < <(find /home /root /opt /srv /var/www /etc -xdev -name ".env" -type f 2>/dev/null | head -10)
    [ "$env_count" -eq 0 ] && ok "No .env files found in common locations"

    # AWS credentials
    for f in /root/.aws/credentials /home/*/.aws/credentials; do
        [ -f "$f" ] || continue
        PERM=$(stat -c "%a" "$f" 2>/dev/null)
        if [ "$PERM" != "600" ]; then
            fail "AWS credentials file loose permissions: $f ($PERM)"
            remedy "chmod 600 $(_q "$f")"
        else
            ok "AWS credentials protected: $f"
        fi
    done

    # .netrc files
    for f in /root/.netrc /home/*/.netrc; do
        [ -f "$f" ] || continue
        warn ".netrc file found (may contain plaintext credentials): $f"
        remedy "rm -f $(_q "$f")  # move to ~/.ssh/config or use credential helpers"
    done

    # Hardcoded secrets in config files
    local secret_count=0
    local secret_patterns='password\s*=\s*[^$][^\s]{3,}|secret\s*=\s*[^$][^\s]{3,}|api_key\s*=\s*[^$][^\s]{3,}|AWS_SECRET|token\s*=\s*[^$][^\s]{3,}'
    while IFS= read -r f; do
        [ -f "$f" ] || continue
        # Skip binary files
        file "$f" 2>/dev/null | grep -q "text" || continue
        if grep -qEi "$secret_patterns" "$f" 2>/dev/null; then
            warn "Possible hardcoded secret in: $f"
            secret_count=$((secret_count+1))
            [ "$secret_count" -ge 5 ] && break
        fi
    done < <(find /etc /opt /srv /var/www -xdev -type f \
        \( -name "*.conf" -o -name "*.cfg" -o -name "*.ini" -o -name "*.yml" -o -name "*.yaml" -o -name "*.env" \) \
        ! -path "*/\.*" 2>/dev/null | head -50)
    [ "$secret_count" -eq 0 ] && ok "No obvious hardcoded secrets in config files"

    # SSH agent socket
    if [ -n "${SSH_AUTH_SOCK:-}" ] && [ -S "${SSH_AUTH_SOCK:-}" ]; then
        SOCK_PERM=$(stat -c "%a %U" "$SSH_AUTH_SOCK" 2>/dev/null)
        info "SSH agent socket: $SSH_AUTH_SOCK ($SOCK_PERM)"
    fi
}
