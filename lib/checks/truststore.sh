#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 The Anzen contributors
# checks/truststore.sh — Distrusted CA certificates in trust stores
#
# Compares every certificate in the system CA bundles, Java cacerts, Python
# certifi, locally added anchors and the CA bundles of running containers
# against lib/data/distrusted-certs.tsv (compromised or distrusted CAs, e.g.
# the eMudhra intermediates of October 2026). Fingerprints are the SHA-256 of
# the DER certificate, computed with base64 + sha256sum — no OpenSSL needed.

# _pem_fingerprints — read PEM text on stdin, print one SHA-256 (upper-case hex)
# per certificate
_pem_fingerprints() {
    awk '/-----BEGIN CERTIFICATE-----/ { b64 = ""; on = 1; next }
         /-----END CERTIFICATE-----/   { if (on) print b64; on = 0; next }
         on { gsub(/[ \r\t]/, ""); b64 = b64 $0 }' \
    | while IFS= read -r b64; do
          printf '%s' "$b64" | base64 -d 2>/dev/null | sha256sum | awk '{ print toupper($1) }'
      done
}

# Fingerprints per bundle content: containers built from the same base image
# ship byte-identical bundles, so each distinct bundle is fingerprinted once.
# _bundle_cache PEM sets _TS_KEY; call it in the current shell (not a pipe)
declare -gA _TS_CACHE=()
_TS_KEY=""
_bundle_cache() {
    _TS_KEY=$(printf '%s' "$1" | sha256sum | cut -c1-64)
    [ -n "${_TS_CACHE[$_TS_KEY]+x}" ] || _TS_CACHE[$_TS_KEY]=$(_pem_fingerprints <<< "$1")
}

# _distrusted_list — "SHA256<TAB>SEVERITY<TAB>INCIDENT<TAB>NAME<TAB>REF" from the
# bundled list plus DISTRUSTED_CERTS_FILE (site additions)
_distrusted_list() {
    local f
    for f in "$ANZEN_DIR/lib/data/distrusted-certs.tsv" ${DISTRUSTED_CERTS_FILE:-}; do
        [ -f "$f" ] && grep -vE '^\s*(#|$)' "$f"
    done
}

# _truststore_scan LABEL REMEDY — fingerprints on stdin; report every listed
# certificate found. Call with "< <(...)", not a pipe: the counters must
# survive in the current shell
_TS_CHECKED=0
_TS_FOUND=0
_truststore_scan() {
    local label=$1 fix=$2 fps hits
    fps=$(cat)
    [ -n "$fps" ] || return 1
    _TS_CHECKED=$(( _TS_CHECKED + $(grep -c . <<< "$fps") ))
    hits=$(awk -F'\t' 'NR == FNR { bad[$1] = $0; next } $1 in bad { print bad[$1] }' \
               <(_distrusted_list) - <<< "$fps" | sort -u)
    [ -n "$hits" ] || return 0
    local _fp sev inc name ref
    while IFS=$'\t' read -r _fp sev inc name ref; do
        if [ "$sev" = "WARN" ]; then
            warn "Distrusted certificate in $label: $name [$inc]"
        else
            fail "Distrusted certificate in $label: $name [$inc]"
        fi
        remedy "$fix  # $ref"
    done <<< "$hits"
    _TS_FOUND=1
}

run_truststore_check() {
    section "Trust Stores"
    _TS_CHECKED=0; _TS_FOUND=0
    if ! command -v sha256sum &>/dev/null || ! command -v base64 &>/dev/null; then
        info "sha256sum/base64 not available — skipping"
        return 0
    fi
    info "Distrusted certificate list: $(_distrusted_list | grep -c .) entries"

    # System bundles (Debian/Ubuntu/Alpine/Arch, RHEL/Fedora, openSUSE); several
    # paths are often symlinks to one file, so each real file is read once
    local upd="update the ca-certificates package (apt/dnf/zypper/apk/pacman upgrade ca-certificates)"
    local f real
    local -A seen=()
    for f in /etc/ssl/certs/ca-certificates.crt /etc/pki/tls/certs/ca-bundle.crt \
             /etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem /etc/ssl/ca-bundle.pem /etc/ssl/cert.pem; do
        [ -f "$f" ] || continue
        real=$(readlink -f "$f")
        [ -n "${seen[$real]+x}" ] && continue
        seen[$real]=1
        _truststore_scan "$f" "$upd" < <(_pem_fingerprints < "$f")
    done

    # Locally added anchors, merged into the bundle by update-ca-certificates
    for f in /usr/local/share/ca-certificates /etc/pki/ca-trust/source/anchors /etc/ca-certificates/trust-source/anchors; do
        [ -d "$f" ] || continue
        _truststore_scan "$f" "remove the certificate from $f, then run update-ca-certificates / update-ca-trust" \
            < <(find "$f" -type f \( -name '*.crt' -o -name '*.pem' \) -exec cat {} + 2>/dev/null | _pem_fingerprints)
    done

    # Java ships its own cacerts keystore, independent of the OS bundle
    if command -v keytool &>/dev/null; then
        _truststore_scan "Java cacerts" "update the JDK, or remove the alias: keytool -delete -cacerts -alias <alias>" \
            < <(keytool -list -rfc -cacerts -storepass changeit 2>/dev/null | _pem_fingerprints)
    fi

    # Python certifi (bundled by pip, requests and many tools)
    local py
    for py in python3 python; do
        command -v "$py" &>/dev/null || continue
        f=$("$py" -c 'import certifi; print(certifi.where())' 2>/dev/null) || continue
        [ -f "$f" ] && _truststore_scan "Python certifi ($f)" "pip install -U certifi" < <(_pem_fingerprints < "$f")
        break
    done

    # Running containers carry their own CA bundle — a patched host does not
    # fix an image built earlier
    if [ "${TRUSTSTORE_SCAN_CONTAINERS:-true}" = "true" ] && command -v docker &>/dev/null && docker info &>/dev/null; then
        local id name image bundle pem
        while IFS=$'\t' read -r id name image; do
            for bundle in /etc/ssl/certs/ca-certificates.crt /etc/pki/tls/certs/ca-bundle.crt /etc/ssl/cert.pem; do
                # First bundle that exists in the container is the one it uses
                pem=$(docker cp -L "$id:$bundle" - 2>/dev/null | tar -xO 2>/dev/null)
                [ -n "$pem" ] || continue
                _bundle_cache "$pem"
                _truststore_scan "container $name ($image)" \
                    "pull/rebuild $image with updated ca-certificates, then recreate $name" \
                    <<< "${_TS_CACHE[$_TS_KEY]}"
                break
            done
        done < <(docker ps --format '{{.ID}}{{"\t"}}{{.Names}}{{"\t"}}{{.Image}}' 2>/dev/null)
    fi

    if [ "$_TS_CHECKED" -eq 0 ]; then
        info "No CA bundles found to check"
    elif [ "$_TS_FOUND" -eq 0 ]; then
        ok "No distrusted CA certificates found ($_TS_CHECKED certificates checked)"
    fi
}
