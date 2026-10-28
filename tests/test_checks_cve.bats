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

fix_first_findings() {
    local k=$'\t'
    {
    echo "FAIL${k}Vulnerabilities (host)${k}linux-modules-6.8.0-142-generic 6.8.0-142.142 in host: ACTIVELY EXPLOITED CVE-2026-53266 (CISA KEV, due 2026-08-30) — 1 HIGH${k}id1${k}x  # fixed in 6.8.0-147.147"
    echo "FAIL${k}Vulnerabilities (containers)${k}apache2-utils 2.4.46-r3 in old:latest [speedtest]: ACTIVELY EXPLOITED CVE-2021-41773 (CISA KEV, due 2021-11-17, used by ransomware) — 1 HIGH${k}id2${k}x  # fixed in 2.4.48"
    echo "FAIL${k}Vulnerabilities (containers)${k}brotli-libs 1.1.0 in a:1 [a]: ACTIVELY EXPLOITED CVE-2026-1 (CISA KEV, due 2026-11-10) — 1 MEDIUM${k}id3${k}x  # fixed in 1.1.1"
    echo "FAIL${k}Vulnerabilities (containers)${k}libbrotli1 1.0.9 in b:2 [b]: ACTIVELY EXPLOITED CVE-2026-1 (CISA KEV, due 2026-11-10) — 1 MEDIUM${k}id4${k}x"
    echo "FAIL${k}Vulnerabilities (containers)${k}starlette 0.47 in b:2 [b] Python: ACTIVELY EXPLOITED CVE-2026-2 (CISA KEV, due 2026-09-16) — 1 HIGH${k}id5${k}x  # fixed in 0.49"
    } > "$FINDINGS_FILE"
}

@test "_cve_fix_first() ranks targets, groups CVEs and suggests a reboot" {
    fix_first_findings
    _KEV_FILE=/dev/null
    boot=$(mktemp -d); touch "$boot/vmlinuz-6.8.0-142-generic" "$boot/vmlinuz-6.8.0-147-generic"
    ANZEN_BOOT_DIR=$boot ANZEN_RUNNING_KERNEL=6.8.0-142-generic _cve_fix_first >/dev/null
    info=$(grep $'^INFO\tExploited CVEs' "$FINDINGS_FILE" | cut -f3)
    [[ "$info" == *"Reboot into 6.8.0-147-generic (installed; running 6.8.0-142-generic) — fixes actively exploited kernel CVEs: CVE-2026-53266"* ]]
    # Ransomware first; an image's OS and Python findings are one target
    [ "$(sed -n 2p <<< "$info")" = "old:latest [speedtest]: 1 actively exploited CVE (CVE-2021-41773), used by ransomware" ]
    [[ "$info" == *"b:2 [b]: 2 actively exploited CVEs (CVE-2026-1 CVE-2026-2) — no fix for some yet"* ]]
    [[ "$info" == *"CVE-2026-1 (brotli-libs, libbrotli1): 2 targets, 1 with a fix available"* ]]
    rm -rf "$boot"
}

@test "_cve_fix_first() suggests no reboot when the installed kernel is not newer than the fix" {
    fix_first_findings
    _KEV_FILE=/dev/null
    boot=$(mktemp -d); touch "$boot/vmlinuz-6.8.0-142-generic" "$boot/vmlinuz-6.8.0-145-generic"
    ANZEN_BOOT_DIR=$boot ANZEN_RUNNING_KERNEL=6.8.0-142-generic _cve_fix_first >/dev/null
    ! grep -q "Reboot into" "$FINDINGS_FILE"
    rm -rf "$boot"
}
