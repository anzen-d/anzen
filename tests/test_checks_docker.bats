#!/usr/bin/env bats
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 The Anzen contributors
# tests/test_checks_docker.bats — container checks against a stubbed docker CLI

setup() {
    ANZEN_DIR="$(cd "$(dirname "$BATS_TEST_FILENAME")/.." && pwd)"
    FINDINGS_FILE="$(mktemp)"
    NO_COLOR=true QUIET=true
    export ANZEN_DIR FINDINGS_FILE NO_COLOR QUIET
    # shellcheck disable=SC1091
    source "$ANZEN_DIR/lib/output.sh"
    # shellcheck disable=SC1091
    source "$ANZEN_DIR/lib/checks/runtimes/oci.sh"
    mkdir -p "$BATS_TEST_TMPDIR/bin"
    # docker stub: one container; answers each inspect format by what it asks for
    cat > "$BATS_TEST_TMPDIR/bin/docker" <<'SH'
#!/bin/bash
case "$1" in
  ps) echo "c1 web" ;;
  inspect)
    case "$*" in
      *cap=*) printf 'cap=CAP_SYS_ADMIN\npid=host\nipc=\nsec=seccomp=unconfined\nenv=PATH=/usr/bin\nenv=POSTGRES_PASSWORD=hunter2\nenv=DB_PASSWORD_FILE=/run/secrets/db\nenv=TOKENIZERS_PARALLELISM=false\nport=0.0.0.0 8080/tcp\nport=:: 8080/tcp\nport=127.0.0.1 9000/tcp\n' ;;
      *Privileged*) echo false ;;
      *Config.User*) echo app ;;
      *NetworkMode*) echo bridge ;;
      *Mounts*) echo "" ;;
      *Memory*) echo 268435456 ;;
    esac ;;
esac
SH
    # No ufw/firewalld/iptables on the test PATH
    printf '#!/bin/sh\nexit 1\n' > "$BATS_TEST_TMPDIR/bin/ufw"
    chmod +x "$BATS_TEST_TMPDIR/bin/docker" "$BATS_TEST_TMPDIR/bin/ufw"
    PATH="$BATS_TEST_TMPDIR/bin:$PATH"
}

teardown() { rm -f "$FINDINGS_FILE" "${FINDINGS_FILE}.tmp"; }

@test "docker: capabilities, host PID, seccomp, env secrets (names only), published ports" {
    _oci_container_checks docker >/dev/null
    grep -q $'^FAIL\t.*web adds capabilities that allow escaping to the host: SYS_ADMIN' "$FINDINGS_FILE"
    grep -q $'^FAIL\t.*web shares the host PID namespace' "$FINDINGS_FILE"
    grep -q $'^WARN\t.*web runs without a seccomp profile' "$FINDINGS_FILE"
    grep -q $'^WARN\t.*Secrets in environment variables of web: POSTGRES_PASSWORD (readable' "$FINDINGS_FILE"
    ! grep -q 'hunter2\|TOKENIZERS\|DB_PASSWORD_FILE' "$FINDINGS_FILE"
    # Without an active host firewall: INFO, loopback-bound port not listed
    grep -q $'^INFO\t.*web publishes 8080/tcp on all interfaces' "$FINDINGS_FILE"
    ! grep -q '9000/tcp' "$FINDINGS_FILE"
}

@test "docker: published port with ufw active is a WARN about the bypass" {
    printf '#!/bin/sh\necho "Status: active"\n' > "$BATS_TEST_TMPDIR/bin/ufw"
    _oci_container_checks docker >/dev/null
    grep -q $'^WARN\t.*web publishes 8080/tcp on all interfaces — Docker.s rules bypass ufw' "$FINDINGS_FILE"
}
