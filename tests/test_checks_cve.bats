#!/usr/bin/env bats
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
