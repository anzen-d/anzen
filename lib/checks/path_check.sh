#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 The Anzen contributors
# checks/path_check.sh — PATH security checks

run_path_check_check() {
    section "PATH Security"

    # Check root's PATH for world-writable directories
    local root_path
    root_path=$(sudo -n bash -c 'echo $PATH' 2>/dev/null || echo "$PATH")
    local ww_path=0

    IFS=':' read -ra path_dirs <<< "$root_path"
    for dir in "${path_dirs[@]}"; do
        [ -z "$dir" ] && {
            fail "Empty entry (relative path) in PATH"
            remedy "# Remove empty entries from PATH in /root/.bashrc or /etc/environment"
            ww_path=$((ww_path+1))
            continue
        }
        [ "$dir" = "." ] && {
            fail "Current directory '.' in PATH"
            remedy "# Remove '.' from PATH in /root/.bashrc or /etc/profile"
            ww_path=$((ww_path+1))
            continue
        }
        if [ -d "$dir" ]; then
            # stat -L: /bin -> usr/bin symlinks are lrwxrwxrwx themselves
            DPERM=$(stat -L -c "%a %U" "$dir" 2>/dev/null)
            DMODE=$(echo "$DPERM" | awk '{print $1}')
            DOWNER=$(echo "$DPERM" | awk '{print $2}')
            # World-writable
            if [ $((8#${DMODE:-0} & 8#002)) -ne 0 ]; then
                fail "World-writable directory in PATH: $dir"
                remedy "chmod o-w '$dir'"
                ww_path=$((ww_path+1))
            # Group-writable by non-root
            elif [ $((8#${DMODE:-0} & 8#020)) -ne 0 ] && [ "$DOWNER" != "root" ]; then
                warn "Group-writable non-root PATH dir: $dir (owner: $DOWNER)"
                remedy "chmod g-w '$dir'  # or chown root '$dir'"
                ww_path=$((ww_path+1))
            fi
        fi
    done

    [ "$ww_path" -eq 0 ] && ok "No world-writable or unsafe directories in PATH"

    # Check for PATH manipulation in /etc/environment or /etc/profile.d
    local path_inject=0
    while IFS= read -r f; do
        if grep -qE '(export PATH=.*:\.|export PATH=\.|PATH=.*:\.|PATH=\.)' "$f" 2>/dev/null; then
            warn "Potential PATH injection in: $f"
            path_inject=$((path_inject+1))
        fi
    done < <(find /etc/profile.d /etc/environment /etc/bash.bashrc \
        -type f 2>/dev/null)

    [ "$path_inject" -eq 0 ] && ok "No PATH manipulation in /etc/profile.d or /etc/environment"

    # Check LD_PRELOAD
    if [ -n "${LD_PRELOAD:-}" ]; then
        fail "LD_PRELOAD is set: $LD_PRELOAD"
        remedy "unset LD_PRELOAD  # and remove from shell profiles"
    else
        ok "LD_PRELOAD not set"
    fi

    # Check LD_LIBRARY_PATH
    if [ -n "${LD_LIBRARY_PATH:-}" ]; then
        warn "LD_LIBRARY_PATH is set: $LD_LIBRARY_PATH"
        remedy "unset LD_LIBRARY_PATH  # can be abused for library hijacking"
    else
        ok "LD_LIBRARY_PATH not set"
    fi

    # Check /etc/ld.so.preload
    if [ -f /etc/ld.so.preload ] && [ -s /etc/ld.so.preload ]; then
        fail "/etc/ld.so.preload exists and is non-empty (rootkit indicator)"
        remedy "cat /etc/ld.so.preload  # investigate before removing"
    else
        ok "/etc/ld.so.preload not in use"
    fi

    # Writeable files in PATH dirs (non-root owned binaries)
    local writable_bins=0
    for dir in "${path_dirs[@]}"; do
        [ -d "$dir" ] || continue
        while IFS= read -r f; do
            FOWNER=$(stat -c "%U" "$f" 2>/dev/null)
            [ "$FOWNER" = "root" ] && continue
            warn "Non-root owned binary in PATH: $f (owner: $FOWNER)"
            remedy "chown root:root '$f' && chmod 755 '$f'"
            writable_bins=$((writable_bins+1))
            [ "$writable_bins" -ge 5 ] && break 2
        done < <(find "$dir" -maxdepth 1 -type f 2>/dev/null)
    done

    [ "$writable_bins" -eq 0 ] && ok "All binaries in PATH are root-owned"
}
