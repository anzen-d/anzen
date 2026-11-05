#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 The Anzen contributors
# plugins/nginx_proxy_manager.sh — Nginx Proxy Manager proxy hosts
#
# Reads the nginx files NPM generates (DATA/nginx/proxy_host/*.conf), so it
# needs no API token and works while NPM is down.
#
# Settings (anzen.conf):
#   NPM_DATA_DIR=/opt/npm/data            the directory mounted at /data
#   NPM_PUBLIC_HOSTS="example.com *.example.org"
#                                         hosts meant to be public (globs);
#                                         they are not flagged for missing
#                                         access control
#
# Access control = an NPM access list, "deny all", basic auth or auth_request
# (Authelia, Authentik, oauth2-proxy). A host without any is open to anyone
# who can reach the proxy.

_npm_is_public() {
    local h=$1 p
    for p in ${NPM_PUBLIC_HOSTS:-}; do
        # shellcheck disable=SC2053
        [[ "$h" == $p ]] && return 0
    done
    return 1
}

run_nginx_proxy_manager_check() {
    section "Nginx Proxy Manager"

    local dir="${NPM_DATA_DIR:-}"
    if [ -z "$dir" ]; then
        info "NPM_DATA_DIR not set — nothing to check"
        return
    fi
    if ! _priv test -d "$dir/nginx/proxy_host"; then
        warn "No proxy hosts under $dir/nginx/proxy_host — is NPM_DATA_DIR the directory mounted at /data?"
        return
    fi

    local f conf name hosts=0 open=0 public=0
    while IFS= read -r f; do
        conf=$(_priv cat "$f" 2>/dev/null) || continue
        # NPM writes "server_name a.example b.example;" — the first name labels the host
        name=$(echo "$conf" | awk '/^[[:space:]]*server_name/{gsub(";","");print $2; exit}')
        [ -n "$name" ] || continue
        hosts=$((hosts + 1))
        local id; id=$(basename "$f" .conf)

        if ! echo "$conf" | grep -qE '^[[:space:]]*(deny all;|auth_basic[[:space:]]+[^o]|auth_request[[:space:]]|include[[:space:]].*(authelia|authentik|oauth2))'; then
            if _npm_is_public "$name"; then
                public=$((public + 1))
            else
                open=$((open + 1))
                warn "Proxy host $name has no access list or authentication"
                remedy "# NPM → Proxy Host $id → Access List, or add $name to NPM_PUBLIC_HOSTS if it is meant to be public"
            fi
        fi

        if ! echo "$conf" | grep -qE '^[[:space:]]*listen[[:space:]].*443'; then
            warn "Proxy host $name serves plain HTTP only"
            remedy "# NPM → Proxy Host $id → SSL: request a certificate and enable Force SSL"
        elif ! echo "$conf" | grep -q 'include conf.d/include/force-ssl.conf'; then
            warn "Proxy host $name does not force HTTPS"
            remedy "# NPM → Proxy Host $id → SSL → Force SSL"
        fi
    done < <(_priv find "$dir/nginx/proxy_host" -maxdepth 1 -name '*.conf' -type f 2>/dev/null | sort -V)

    info "NPM: $hosts proxy hosts, $public public by NPM_PUBLIC_HOSTS, $open without access control"
    [ "$open" -eq 0 ] && ok "Every non-public proxy host has access control"

    # The admin UI (port 81) should not be reachable from outside
    # A LAN address is fine; only wildcard binds reach every interface
    if _svc_listen_addrs 81 | grep -qxE '0\.0\.0\.0|\*|::'; then
        warn "NPM admin UI port 81 listens on all interfaces"
        remedy "# publish it as 127.0.0.1:81:81 (or a LAN address) in the NPM compose file"
    fi
}
