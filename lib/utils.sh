#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 The Anzen contributors
# lib/utils.sh — Shared utility functions (sourced early by anzen.sh)

# Succeed only if FILE is owned by the current user (or root) and not world-writable
_trusted_file() {
    local f="$1" owner perms
    owner=$(stat -c '%U' "$f" 2>/dev/null) || { echo "ERROR: Cannot stat $f" >&2; return 1; }
    perms=$(stat -c '%a' "$f" 2>/dev/null)
    if [ "$owner" != "$(id -un)" ] && [ "$owner" != "root" ]; then
        echo "ERROR: '$f' owned by '$owner' — refusing to use it" >&2; return 1
    fi
    if (( 8#$perms & 2 )); then
        echo "ERROR: '$f' is world-writable — refusing to use it" >&2; return 1
    fi
}

# Source a config file only if _trusted_file accepts it
_safe_source_config() {
    _trusted_file "$1" || return 1
    # shellcheck source=/dev/null
    source "$1"
}

# _invoking_user — the person behind the audit: SUDO_USER under sudo, so
# user-level checks (sudo rules, docker group, AllowUsers) are not about root
_invoking_user() { echo "${SUDO_USER:-$(id -un)}"; }

# Run a command with root privileges without ever prompting: directly when
# already root, via passwordless sudo otherwise, else unprivileged (the caller
# then sees whatever partial output a normal user gets)
_priv() {
    if [ "$EUID" -eq 0 ]; then
        "$@"
    elif command -v sudo &>/dev/null && sudo -n true 2>/dev/null; then
        sudo -n "$@"
    else
        "$@"
    fi
}

# _svc_listen_addrs PORT — local addresses with a TCP listener on PORT
_svc_listen_addrs() {
    ss -tln 2>/dev/null | awk 'NR>1{print $4}' | grep -E ":$1\$" | sed -E "s/:$1\$//; s/^\[//; s/\]\$//; s/%.*//"
}

# _svc_public_tcp PORT — true if PORT listens on a non-loopback address
_svc_public_tcp() {
    _svc_listen_addrs "$1" | grep -qvE '^(127\.|::1$)'
}

# _svc_probe_addr PORT — address to connect to for a local probe of PORT
_svc_probe_addr() {
    local a
    a=$(_svc_listen_addrs "$1" | head -1)
    case "$a" in
        "") ;;
        0.0.0.0|\*|::) echo 127.0.0.1 ;;
        *) echo "$a" ;;
    esac
}

# _svc_probe ADDR PORT PAYLOAD — send PAYLOAD (printf format) and print the
# first bytes of the reply; local connections only, 2 s timeout
_svc_probe() {
    command -v timeout &>/dev/null || return 1
    # shellcheck disable=SC2016
    timeout 2 bash -c 'exec 3<>"/dev/tcp/$1/$2" || exit 1; printf "$3" >&3; head -c 64 <&3' _ "$1" "$2" "$3" 2>/dev/null
}
