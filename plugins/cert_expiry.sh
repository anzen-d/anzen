#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 The Anzen contributors
# plugins/cert_expiry.sh — expiry of TLS certificates served by other hosts
#
# The built-in tls module checks certificates on this host. This plugin
# connects to the endpoints you list (with SNI), so it also covers sites behind
# a reverse proxy, a NAS, a router, or anything else on the network.
#
# Settings (anzen.conf):
#   CERT_EXPIRY_HOSTS="example.com nas.lan:5001 [2001:db8::1]:443"
#   TLS_WARN_DAYS=30  TLS_FAIL_DAYS=7   shared with the tls module
#   CERT_EXPIRY_TIMEOUT=5               seconds per endpoint
#
# Makes network connections: skipped with --offline.

run_cert_expiry_check() {
    section "Certificate Expiry (remote)"

    if [ -z "${CERT_EXPIRY_HOSTS:-}" ]; then
        info "CERT_EXPIRY_HOSTS not set — nothing to check"
        return
    fi
    if [ "${OFFLINE:-false}" = true ]; then
        info "--offline: remote certificate checks skipped"
        return
    fi
    if ! command -v openssl &>/dev/null; then
        info "openssl not available — skipping"
        return
    fi

    local warn_days="${TLS_WARN_DAYS:-30}" fail_days="${TLS_FAIL_DAYS:-7}"
    local t="${CERT_EXPIRY_TIMEOUT:-5}" ep host port end end_epoch days
    for ep in $CERT_EXPIRY_HOSTS; do
        if [[ "$ep" == \[*\]:* ]]; then        # [IPv6]:port
            host=${ep%]:*}; host=${host#[}; port=${ep##*]:}
        elif [[ "$ep" == \[*\] ]]; then
            host=${ep#[}; host=${host%]}; port=443
        elif [[ "$ep" == *:* ]]; then
            host=${ep%:*}; port=${ep##*:}
        else
            host=$ep; port=443
        fi
        local connect="$host:$port"
        [[ "$host" == *:* ]] && connect="[$host]:$port"

        end=$(echo | timeout "$t" openssl s_client -connect "$connect" \
                -servername "$host" 2>/dev/null \
            | openssl x509 -noout -enddate 2>/dev/null | cut -d= -f2-)
        if [ -z "$end" ]; then
            warn "No TLS certificate from $host:$port (unreachable or not TLS)"
            continue
        fi
        end_epoch=$(date -d "$end" +%s 2>/dev/null) || continue
        days=$(( (end_epoch - $(date +%s)) / 86400 ))
        if [ "$days" -lt 0 ]; then
            fail "Certificate of $host:$port EXPIRED"
            remedy "# renew the certificate served by $host:$port"
        elif [ "$days" -le "$fail_days" ]; then
            fail "Certificate of $host:$port expires in $days days"
            remedy "# renew the certificate served by $host:$port; check that auto-renewal runs"
        elif [ "$days" -le "$warn_days" ]; then
            warn "Certificate of $host:$port expires in $days days"
            remedy "# renew the certificate served by $host:$port; check that auto-renewal runs"
        else
            ok "Certificate of $host:$port valid for $days days"
        fi
    done
}
