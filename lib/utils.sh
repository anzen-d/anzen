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
