#!/usr/bin/env bats
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 The Anzen contributors
# tests/test_plugins.bats — plugins/ catalogue

setup() {
    ANZEN_DIR="$(cd "$(dirname "$BATS_TEST_FILENAME")/.." && pwd)"
    FINDINGS_FILE="$(mktemp)"
    NO_COLOR=true QUIET=true
    export ANZEN_DIR FINDINGS_FILE NO_COLOR QUIET
    # shellcheck disable=SC1091
    source "$ANZEN_DIR/lib/output.sh"
    # shellcheck disable=SC1091
    source "$ANZEN_DIR/lib/utils.sh"
    T="$BATS_TEST_TMPDIR"
}

teardown() { rm -f "$FINDINGS_FILE" "${FINDINGS_FILE}.tmp"; }

@test "every plugin defines run_<name>_check and is quiet without settings" {
    for f in "$ANZEN_DIR"/plugins/*.sh; do
        name=$(basename "$f" .sh)
        bash -n "$f"
        (
            # shellcheck disable=SC1090
            source "$f"
            declare -f "run_${name}_check" > /dev/null
            "run_${name}_check" > /dev/null
        )
    done
    ! grep -qE "^(FAIL|WARN)	" "$FINDINGS_FILE"
}

@test "backup_age: fresh, stale, missing and malformed entries" {
    # shellcheck disable=SC1091
    source "$ANZEN_DIR/plugins/backup_age.sh"
    mkdir -p "$T/fresh/snapshots" "$T/stale" "$T/empty"
    touch "$T/fresh/snapshots/a"
    touch -d '5 days ago' "$T/stale/old"
    BACKUP_AGE_PATHS="$T/fresh/snapshots:1 $T/stale:2 $T/missing:1 $T/empty:1 nonsense" \
        run_backup_age_check > /dev/null
    grep -q "^OK	Backup Age	Newest backup in $T/fresh/snapshots is 0 hours old" "$FINDINGS_FILE"
    grep -q "^FAIL	Backup Age	Newest backup in $T/stale is 1[12][0-9] hours old (limit 2 days)" "$FINDINGS_FILE"
    grep -q "^FAIL	Backup Age	Backup location missing: $T/missing" "$FINDINGS_FILE"
    grep -q "^FAIL	Backup Age	No backup files in $T/empty" "$FINDINGS_FILE"
    grep -q "^WARN	Backup Age	.*'nonsense' is not PATH:MAX_DAYS" "$FINDINGS_FILE"
}

@test "backup_age: the finding ID does not change as the backup ages" {
    a=$(_finding_id "Backup Age" "Newest backup in /b is 50 hours old (limit 2 days)")
    b=$(_finding_id "Backup Age" "Newest backup in /b is 73 hours old (limit 2 days)")
    [ "$a" = "$b" ]
}

@test "cert_expiry: skipped with --offline; endpoint parsing; unreachable is a WARN" {
    # shellcheck disable=SC1091
    source "$ANZEN_DIR/plugins/cert_expiry.sh"
    CERT_EXPIRY_HOSTS="example.com" OFFLINE=true run_cert_expiry_check > /dev/null
    grep -q "^INFO	.*--offline" "$FINDINGS_FILE"
    command -v openssl >/dev/null || skip "openssl not installed"
    : > "$FINDINGS_FILE"
    # Port 1 on loopback: nothing listens there
    CERT_EXPIRY_HOSTS="127.0.0.1:1 [::1]:1" CERT_EXPIRY_TIMEOUT=2 run_cert_expiry_check > /dev/null
    grep -q "^WARN	.*No TLS certificate from 127.0.0.1:1" "$FINDINGS_FILE"
    grep -q "^WARN	.*No TLS certificate from ::1:1" "$FINDINGS_FILE"
}

@test "cert_expiry: a local TLS server's certificate expiry is reported" {
    command -v openssl >/dev/null || skip "openssl not installed"
    # shellcheck disable=SC1091
    source "$ANZEN_DIR/plugins/cert_expiry.sh"
    openssl req -x509 -newkey rsa:2048 -nodes -keyout "$T/k" -out "$T/c" -subj /CN=localhost -days 5 2>/dev/null
    port=$(( 20000 + RANDOM % 20000 ))
    openssl s_server -quiet -accept "$port" -cert "$T/c" -key "$T/k" -www < /dev/null > /dev/null 2>&1 &
    srv=$!
    sleep 1
    CERT_EXPIRY_HOSTS="localhost:$port" run_cert_expiry_check > /dev/null
    kill "$srv" 2>/dev/null || true
    grep -qE "^FAIL	.*Certificate of localhost:$port expires in [45] days" "$FINDINGS_FILE"
}

_npm_host() {
    # _npm_host ID NAME BODY — write a proxy host file like NPM generates
    mkdir -p "$T/npm/nginx/proxy_host"
    printf '# %s\nserver {\n  listen 80;\n%s\n  server_name %s;\n}\n' "$2" "$3" "$2" > "$T/npm/nginx/proxy_host/$1.conf"
}

@test "nginx_proxy_manager: open, protected, public and plain-HTTP hosts" {
    # shellcheck disable=SC1091
    source "$ANZEN_DIR/plugins/nginx_proxy_manager.sh"
    ss() { printf 'h\nLISTEN 0 0 0.0.0.0:81 0.0.0.0:*\n'; }
    _npm_host 1 open.lan.example $'listen 443 ssl;\n    include conf.d/include/force-ssl.conf;'
    _npm_host 2 acl.lan.example $'listen 443 ssl;\n    include conf.d/include/force-ssl.conf;\n    # Access Rules: 1 total\n    allow 10.0.0.0/8;\n    deny all;'
    _npm_host 3 sso.lan.example $'listen 443 ssl;\n    include conf.d/include/force-ssl.conf;\ninclude /data/nginx/snippets/authelia-location.conf;'
    _npm_host 4 www.example.com $'listen 443 ssl;\n    include conf.d/include/force-ssl.conf;'
    _npm_host 5 nossl.lan.example $'    auth_basic "Authorization required";'
    _npm_host 6 noforce.lan.example $'listen 443 ssl;\n  deny all;'
    _npm_host 7 off.lan.example $'listen 443 ssl;\n    include conf.d/include/force-ssl.conf;\n  auth_basic off;\n  #deny all;'
    NPM_DATA_DIR="$T/npm" NPM_PUBLIC_HOSTS="*.example.com" run_nginx_proxy_manager_check > /dev/null
    grep -q "^WARN	.*Proxy host open.lan.example has no access list" "$FINDINGS_FILE"
    grep -q "^WARN	.*Proxy host off.lan.example has no access list" "$FINDINGS_FILE"
    ! grep -qE "(acl|sso|nossl|noforce).lan.example has no access" "$FINDINGS_FILE"
    ! grep -q "www.example.com" "$FINDINGS_FILE"
    grep -q "^WARN	.*nossl.lan.example serves plain HTTP only" "$FINDINGS_FILE"
    grep -q "^WARN	.*noforce.lan.example does not force HTTPS" "$FINDINGS_FILE"
    grep -q "^INFO	.*7 proxy hosts, 1 public by NPM_PUBLIC_HOSTS, 2 without access control" "$FINDINGS_FILE"
    grep -q "^WARN	.*admin UI port 81" "$FINDINGS_FILE"
}

@test "nginx_proxy_manager: wrong NPM_DATA_DIR is a WARN" {
    # shellcheck disable=SC1091
    source "$ANZEN_DIR/plugins/nginx_proxy_manager.sh"
    NPM_DATA_DIR="$T/nope" run_nginx_proxy_manager_check > /dev/null
    grep -q "^WARN	.*No proxy hosts under $T/nope" "$FINDINGS_FILE"
}
