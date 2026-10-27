#!/usr/bin/env bats
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 The Anzen contributors
# tests/test_checks_truststore.bats — distrusted CA detection (real certificates)

setup() {
    ANZEN_DIR="$(cd "$(dirname "$BATS_TEST_FILENAME")/.." && pwd)"
    FX="$ANZEN_DIR/tests/fixtures"
    FINDINGS_FILE="$(mktemp)"
    NO_COLOR=true QUIET=true
    export ANZEN_DIR FINDINGS_FILE NO_COLOR QUIET
    # shellcheck disable=SC1091
    source "$ANZEN_DIR/lib/output.sh"
    # shellcheck disable=SC1091
    source "$ANZEN_DIR/lib/checks/truststore.sh"
    section "Trust Stores"
}

teardown() { rm -f "$FINDINGS_FILE" "${FINDINGS_FILE}.tmp"; }

@test "_pem_fingerprints() matches openssl's SHA-256 fingerprint" {
    command -v openssl >/dev/null || skip "no openssl"
    expected=$(openssl x509 -in "$FX/emudhra-dv-g3b.pem" -noout -fingerprint -sha256 | cut -d= -f2 | tr -d :)
    [ "$(_pem_fingerprints < "$FX/emudhra-dv-g3b.pem")" = "$expected" ]
}

@test "_pem_fingerprints() handles a multi-certificate bundle" {
    n=$(cat "$FX/isrg-root-x1.pem" "$FX/emudhra-dv-g3b.pem" | _pem_fingerprints | grep -c .)
    [ "$n" -eq 2 ]
}

@test "compromised eMudhra intermediate is a FAIL" {
    _truststore_scan "test bundle" "fix" < <(cat "$FX/isrg-root-x1.pem" "$FX/emudhra-dv-g3b.pem" | _pem_fingerprints)
    grep -q $'^FAIL\t.*Distrusted certificate in test bundle: EM DV TLS CA - G3B' "$FINDINGS_FILE"
    [ "$_TS_FOUND" -eq 1 ]
    [ "$_TS_CHECKED" -eq 2 ]
}

@test "AAA Certificate Services (cross-signer) is a WARN" {
    _truststore_scan "test bundle" "fix" < <(_pem_fingerprints < "$FX/aaa-certificate-services.pem")
    grep -q $'^WARN\t.*AAA Certificate Services' "$FINDINGS_FILE"
}

@test "a clean bundle produces no findings" {
    _truststore_scan "test bundle" "fix" < <(_pem_fingerprints < "$FX/isrg-root-x1.pem")
    [ ! -s "$FINDINGS_FILE" ]
    [ "$_TS_FOUND" -eq 0 ]
}

@test "DISTRUSTED_CERTS_FILE adds site entries" {
    fp=$(_pem_fingerprints < "$FX/isrg-root-x1.pem")
    printf '%s\tWARN\tlocal-test\tMy distrusted CA\thttps://example.com\n' "$fp" > "$BATS_TEST_TMPDIR/extra.tsv"
    DISTRUSTED_CERTS_FILE="$BATS_TEST_TMPDIR/extra.tsv"
    _truststore_scan "test bundle" "fix" < <(_pem_fingerprints < "$FX/isrg-root-x1.pem")
    grep -q $'^WARN\t.*My distrusted CA \\[local-test\\]' "$FINDINGS_FILE"
}

@test "every list entry is a 64-hex fingerprint with FAIL or WARN" {
    run awk -F'\t' '!/^[[:space:]]*(#|$)/ && ($1 !~ /^[0-9A-F]{64}$/ || ($2 != "FAIL" && $2 != "WARN") || NF < 4) { print NR": "$0 }' \
        "$ANZEN_DIR/lib/data/distrusted-certs.tsv"
    [ -z "$output" ]
}
