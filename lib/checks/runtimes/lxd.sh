#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 The Anzen contributors
# runtimes/lxd.sh — LXD and legacy LXC checks

_lxd_checks() {
    local containers
    containers=$(lxc list --format csv -c ns 2>/dev/null | grep "RUNNING" | cut -d, -f1)
    [ -z "$containers" ] && { info "[lxd] No running containers"; return; }

    while IFS= read -r cname; do
        [ -z "$cname" ] && continue

        local priv
        priv=$(lxc config get "$cname" security.privileged 2>/dev/null)
        [ "$priv" = "true" ] && {
            fail "[lxd] Privileged container: $cname"
            remedy "lxc config set $cname security.privileged false"; }

        local nesting
        nesting=$(lxc config get "$cname" security.nesting 2>/dev/null)
        [ "$nesting" = "true" ] && {
            warn "[lxd] Nesting enabled: $cname"
            remedy "lxc config set $cname security.nesting false"; }

        local idmap
        idmap=$(lxc config get "$cname" raw.idmap 2>/dev/null)
        [ -n "$idmap" ] && info "[lxd] Custom idmap on $cname: $idmap"

    done <<< "$containers"
}

_lxc_checks() {
    local containers
    containers=$(lxc-ls --running 2>/dev/null)
    [ -z "$containers" ] && { info "[lxc] No running containers"; return; }

    for cname in $containers; do
        local cfg="/var/lib/lxc/$cname/config"
        if [ -f "$cfg" ]; then
            grep -q "lxc.apparmor.profile\|lxc.aa_profile" "$cfg" 2>/dev/null \
                && ok "[lxc] AppArmor profile set: $cname" \
                || { warn "[lxc] No AppArmor profile: $cname"
                     remedy "# Add 'lxc.apparmor.profile = generated' to $cfg"; }

            grep -q "lxc.idmap\|lxc.id_map" "$cfg" 2>/dev/null \
                && ok "[lxc] UID/GID mapping configured: $cname" \
                || { warn "[lxc] No UID/GID mapping (unprivileged): $cname"
                     remedy "# Add lxc.idmap lines to $cfg for unprivileged containers"; }
        fi
    done
}
