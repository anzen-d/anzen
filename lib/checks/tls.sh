#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 The Anzen contributors
# checks/tls.sh — TLS certificate expiry and configuration checks

run_tls_check() {
    section "TLS Certificates"

    if ! command -v openssl &>/dev/null; then
        info "openssl not available — skipping TLS checks"
        return
    fi

    local warn_days="${TLS_WARN_DAYS:-30}"
    local fail_days="${TLS_FAIL_DAYS:-7}"

    # Check listening HTTPS ports
    local https_ports
    https_ports=$(ss -tlnp 2>/dev/null | awk 'NR>1{print $4}' \
        | grep -oE ':[0-9]+$' | tr -d ':' \
        | sort -un \
        | grep -E '^(443|8443|4443|8080|9443)$' || true)

    # Also check common local cert files
    local cert_files=()
    while IFS= read -r f; do
        cert_files+=("$f")
    done < <(find /etc/ssl /etc/nginx /etc/apache2 /etc/letsencrypt /opt \
        -type f \( -name "*.crt" -o -name "*.pem" -o -name "fullchain.pem" \) \
        ! -name "*ca*" ! -name "*chain*" \
        2>/dev/null | head -20)

    local checked=0

    # Check cert files directly
    for cert in "${cert_files[@]}"; do
        # Skip if not a certificate (e.g., private key PEMs)
        openssl x509 -in "$cert" -noout 2>/dev/null || continue
        local expiry
        expiry=$(openssl x509 -in "$cert" -noout -enddate 2>/dev/null | cut -d= -f2-)
        [ -z "$expiry" ] && continue
        local expiry_epoch
        expiry_epoch=$(date -d "$expiry" +%s 2>/dev/null) || continue
        local now_epoch
        now_epoch=$(date +%s)
        local days_left=$(( (expiry_epoch - now_epoch) / 86400 ))
        local subject
        subject=$(openssl x509 -in "$cert" -noout -subject 2>/dev/null | sed 's/subject=//')

        if [ "$days_left" -le 0 ]; then
            fail "Certificate EXPIRED: $cert ($subject)"
            remedy "certbot renew --force-renewal  # or replace cert at $cert"
        elif [ "$days_left" -le "$fail_days" ]; then
            fail "Certificate expires in ${days_left}d: $cert ($subject)"
            remedy "certbot renew  # expires in ${days_left} days: $cert"
        elif [ "$days_left" -le "$warn_days" ]; then
            warn "Certificate expires in ${days_left}d: $cert ($subject)"
            remedy "certbot renew  # expires in ${days_left} days: $cert"
        else
            ok "Certificate valid ${days_left}d: $(basename "$cert")"
        fi
        checked=$((checked+1))
    done

    # Check live HTTPS ports on localhost
    for port in $https_ports; do
        local expiry
        expiry=$(echo Q | openssl s_client -connect "127.0.0.1:$port" \
            -servername localhost 2>/dev/null \
            | openssl x509 -noout -enddate 2>/dev/null | cut -d= -f2-) || continue
        [ -z "$expiry" ] && continue
        local expiry_epoch
        expiry_epoch=$(date -d "$expiry" +%s 2>/dev/null) || continue
        local now_epoch
        now_epoch=$(date +%s)
        local days_left=$(( (expiry_epoch - now_epoch) / 86400 ))

        if [ "$days_left" -le 0 ]; then
            fail "TLS cert EXPIRED on port $port"
            remedy "certbot renew --force-renewal  # port $port cert expired"
        elif [ "$days_left" -le "$fail_days" ]; then
            fail "TLS cert on port $port expires in ${days_left}d"
            remedy "certbot renew  # port $port cert expires in ${days_left} days"
        elif [ "$days_left" -le "$warn_days" ]; then
            warn "TLS cert on port $port expires in ${days_left}d"
            remedy "certbot renew"
        else
            ok "TLS cert on port $port valid ${days_left}d"
        fi
        checked=$((checked+1))
    done

    # Check weak TLS protocols only on ports that responded with a valid cert above
    for port in $https_ports; do
        # Skip if port didn't respond with a cert during the expiry check
        local test_cert
        test_cert=$(echo Q | openssl s_client -connect "127.0.0.1:$port" \
            -servername localhost 2>/dev/null | openssl x509 -noout 2>/dev/null && echo yes || echo no)
        [ "$test_cert" = "yes" ] || continue

        local tls1_ok
        tls1_ok=$(echo Q | openssl s_client -connect "127.0.0.1:$port" \
            -tls1 2>&1 | grep "Cipher is" | grep -vc "(NONE)" || true)
        if [ "${tls1_ok:-0}" -gt 0 ]; then
            fail "TLSv1.0 accepted on port $port (deprecated)"
            remedy "# Disable TLSv1.0/1.1 in your server config (nginx: ssl_protocols TLSv1.2 TLSv1.3)"
        fi
    done

    [ "$checked" -eq 0 ] && info "No TLS certificates found to check"
}
