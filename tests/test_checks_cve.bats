#!/usr/bin/env bats
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 The Anzen contributors
# tests/test_checks_cve.bats — Tests for lib/checks/cve.sh grouping

setup() {
    ANZEN_DIR="$(cd "$(dirname "$BATS_TEST_FILENAME")/.." && pwd)"
    FINDINGS_FILE="$(mktemp)"
    NO_COLOR=true QUIET=true
    export ANZEN_DIR FINDINGS_FILE NO_COLOR QUIET
    # shellcheck disable=SC1091
    source "$ANZEN_DIR/lib/output.sh"
    # shellcheck disable=SC1091
    source "$ANZEN_DIR/lib/checks/cve.sh"
    section "Vulnerabilities (host)"
}

teardown() { rm -f "$FINDINGS_FILE" "${FINDINGS_FILE}.tmp"; }

rows() {
    printf '%s\t%s\t%s\t%s\t%s\t%s\n' \
        "img (debian 12)" openssl 3.0.2 "3.0.13, 3.1.5" HIGH CVE-2024-0001 \
        "img (debian 12)" openssl 3.0.2 "3.0.13" CRITICAL CVE-2024-0002 \
        "img (debian 12)" openssl 3.0.2 "3.0.13" HIGH CVE-2024-0003 \
        "img (debian 12)" openssl 3.0.2 "3.0.13" HIGH CVE-2024-0004 \
        "img (debian 12)" openssl 3.0.2 "3.0.13" HIGH CVE-2024-0004 \
        "Node.js" undici 6.28.0 "6.29.1" HIGH CVE-2026-1
}

@test "_cve_report() emits one finding per package version" {
    rows | _cve_report "host" "apt-get install --only-upgrade %s" >/dev/null
    [ "$(grep -c . "$FINDINGS_FILE")" -eq 2 ]
}

@test "_cve_report() is FAIL with any CRITICAL, WARN otherwise" {
    rows | _cve_report "host" "x %s" >/dev/null
    grep -q $'^FAIL\t.*openssl 3.0.2 in host: 1 CRITICAL, 3 HIGH' "$FINDINGS_FILE"
    grep -q $'^WARN\t.*undici 6.28.0 in host Node.js: 1 HIGH' "$FINDINGS_FILE"
}

@test "_cve_report() lists three CVEs, counts duplicates once, names the fix" {
    rows | _cve_report "host" "apt-get install --only-upgrade %s" >/dev/null
    line=$(grep openssl "$FINDINGS_FILE")
    [[ "$line" == *"CVE-2024-0001 CVE-2024-0002 CVE-2024-0003 +1 more"* ]]
    [[ "$line" == *"apt-get install --only-upgrade openssl  # fixed in 3.0.13" ]]
}

@test "run_cve_check() says so when trivy is missing" {
    command -v trivy >/dev/null && skip "trivy is installed"
    run_cve_check
    grep -q "trivy not installed" "$FINDINGS_FILE"
}

@test "_cve_report() names the binary or path for non-OS packages" {
    printf '%s\t%s\t%s\t%s\t%s\t%s\n' usr/local/bin/terraform stdlib v1.23.4 1.24 CRITICAL CVE-9 \
        | _cve_report "host" "x %s" >/dev/null
    grep -q 'stdlib v1.23.4 in host /usr/local/bin/terraform: 1 CRITICAL' "$FINDINGS_FILE"
}

kev_rows() {
    # KEV CVE at MEDIUM without a fix, a non-KEV MEDIUM, and a fresh HIGH
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "img (debian 12)" sudo 1.9.5 "" MEDIUM CVE-2025-1111 2025-03-01T00:00:00Z \
        "img (debian 12)" sudo 1.9.5 "1.9.6" MEDIUM CVE-2025-2222 2025-03-01T00:00:00Z \
        "img (debian 12)" curl 8.0.0 "8.0.1" HIGH CVE-2026-3333 "$(date -u +%F)T00:00:00Z"
}

@test "_cve_report() makes a CISA KEV CVE a FAIL at any severity, even unfixed" {
    _KEV_FILE=$(mktemp)
    printf 'CVE-2025-1111\t2025-04-01\t2025-04-22\tKnown\n' > "$_KEV_FILE"
    _cve_report "host" "x %s" < <(kev_rows) >/dev/null
    grep -q $'^FAIL\t.*sudo 1.9.5 in host: ACTIVELY EXPLOITED CVE-2025-1111 (CISA KEV, due 2025-04-22, used by ransomware) — 1 MEDIUM' "$FINDINGS_FILE"
    # The non-KEV MEDIUM is below CVE_SEVERITY and stays out
    ! grep -q CVE-2025-2222 "$FINDINGS_FILE"
    [ "$_CVE_N" -eq 2 ]
    rm -f "$_KEV_FILE"
}

@test "_cve_report() lists CVEs published in the last CVE_NEW_DAYS as INFO" {
    _KEV_FILE=""
    kev_rows | _cve_report "host" "x %s" >/dev/null
    grep -q $'^INFO\t.*Published in the last 7 days (1): CVE-2026-3333 (curl)' "$FINDINGS_FILE"
}

@test "_kev_load() parses the CISA feed and refuses a truncated one" {
    feed=$(mktemp); export KEV_CACHE_DIR=$(mktemp -d)
    { echo '{"vulnerabilities": ['
      for i in $(seq 1 600); do
          printf '{"cveID": "CVE-2024-%d", "dateAdded": "2024-01-01", "dueDate": "2024-01-22", "knownRansomwareCampaignUse": "Unknown"},\n' "$i"
      done; echo '{"cveID": "not-a-cve; rm -rf /"}]}'; } > "$feed"
    KEV_URL="file://$feed" _kev_load
    [ "$(wc -l < "$_KEV_FILE")" -eq 600 ]
    grep -q $'^CVE-2024-7\t2024-01-01\t2024-01-22\tUnknown$' "$_KEV_FILE"
    # Truncated feed: keep the previous list instead of replacing it
    echo '{"cveID": "CVE-2024-1"}' > "$feed"; touch -d '2 days ago' "$KEV_CACHE_DIR/kev.tsv"
    KEV_URL="file://$feed" _kev_load
    [ "$(wc -l < "$_KEV_FILE")" -eq 600 ]
    rm -rf "$feed" "$KEV_CACHE_DIR"
}

@test "_cve_report() ignores kernel packages inside container images" {
    _KEV_FILE=""
    printf '%s\t%s\t%s\t%s\t%s\t%s\n' "img (debian 12)" linux-libc-dev 6.1.1 6.1.2 CRITICAL CVE-2026-5 \
        > "$BATS_TEST_TMPDIR/r"
    _cve_report "img [c]" "x %s" image < "$BATS_TEST_TMPDIR/r" >/dev/null
    [ "$_CVE_N" -eq 0 ]
    _cve_report "host" "x %s" < "$BATS_TEST_TMPDIR/r" >/dev/null
    [ "$_CVE_N" -eq 1 ]
}
