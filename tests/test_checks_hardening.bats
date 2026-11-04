#!/usr/bin/env bats
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 The Anzen contributors
# tests/test_checks_hardening.bats — SSH forwarding, eBPF/ptrace, exposed
# Redis/Memcached/MongoDB, weak TLS certificates, NO_COLOR

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

_sshd_t() {
    # shellcheck disable=SC2329
    sshd() { printf '%s\n' "$SSHD_T"; }
    _priv() { "$@"; }
    # shellcheck disable=SC1091
    source "$ANZEN_DIR/lib/checks/ssh.sh"
    run_ssh_check > /dev/null
}

@test "ssh: default AllowTcpForwarding yes is a WARN, PermitTunnel no is OK" {
    SSHD_T=$'port 2222\npermitrootlogin no\nallowtcpforwarding yes\npermittunnel no'
    _sshd_t
    grep -q "^WARN	SSH Configuration	AllowTcpForwarding: yes" "$FINDINGS_FILE"
    grep -q "^OK	SSH Configuration	PermitTunnel: no" "$FINDINGS_FILE"
}

@test "ssh: AllowTcpForwarding no is OK, PermitTunnel yes is a WARN" {
    SSHD_T=$'port 2222\nallowtcpforwarding no\npermittunnel yes'
    _sshd_t
    grep -q "^OK	SSH Configuration	AllowTcpForwarding: no" "$FINDINGS_FILE"
    grep -q "^WARN	SSH Configuration	PermitTunnel: yes" "$FINDINGS_FILE"
}

@test "kernel: unprivileged eBPF and ptrace_scope 0 are WARNs; 2 and 1 pass" {
    # shellcheck disable=SC1091
    source "$ANZEN_DIR/lib/checks/kernel.sh"
    _sysctl() { case $1 in kernel.unprivileged_bpf_disabled) echo "$BPF" ;; kernel.yama.ptrace_scope) echo "$PT" ;; esac; }
    BPF=0 PT=0 run_kernel_check > /dev/null
    grep -q "^WARN	.*kernel.unprivileged_bpf_disabled=0" "$FINDINGS_FILE"
    grep -q "^WARN	.*kernel.yama.ptrace_scope=0" "$FINDINGS_FILE"
    : > "$FINDINGS_FILE"
    BPF=2 PT=1 run_kernel_check > /dev/null
    grep -q "^OK	.*Unprivileged eBPF disabled (2)" "$FINDINGS_FILE"
    grep -q "^OK	.*ptrace restricted" "$FINDINGS_FILE"
}

# Source services.sh first, then stub _svc_probe, then call _services
_services() {
    # shellcheck disable=SC2329
    ss() {
        case "$1" in
            -tln|-tlnp) printf 'State Recv-Q Send-Q Local Peer\n'; printf '%s\n' "${SS_TCP[@]}" ;;
            -ulnp)      printf 'State Recv-Q Send-Q Local Peer\n'; printf '%s\n' "${SS_UDP[@]}" ;;
        esac
    }
    run_services_check > /dev/null 2>&1 || true
}

@test "services: listener address parsing (IPv4, IPv6, wildcard, loopback)" {
    # shellcheck disable=SC1091
    source "$ANZEN_DIR/lib/checks/services.sh"
    ss() { printf 'h\n'; printf 'LISTEN 0 0 %s *:*\n' "[::1]:6379" "127.0.0.1:6379"; }
    ! _svc_public_tcp 6379
    [ "$(_svc_probe_addr 6379)" = "::1" ]
    ss() { printf 'h\n'; printf 'LISTEN 0 0 %s *:*\n' "0.0.0.0:11211" "[::]:11211"; }
    _svc_public_tcp 11211
    [ "$(_svc_probe_addr 11211)" = "127.0.0.1" ]
    ss() { printf 'h\n'; printf 'LISTEN 0 0 %s *:*\n' "*:27017"; }
    _svc_public_tcp 27017
}

@test "services: Redis without a password, public Memcached TCP+UDP, MongoDB" {
    SS_TCP=("LISTEN 0 0 0.0.0.0:6379 0.0.0.0:*" "LISTEN 0 0 0.0.0.0:11211 0.0.0.0:*" "LISTEN 0 0 [::]:27017 [::]:*")
    SS_UDP=("UNCONN 0 0 0.0.0.0:11211 0.0.0.0:*")
    # shellcheck disable=SC1091
    source "$ANZEN_DIR/lib/checks/services.sh"
    _svc_probe() { [ "$2" = 6379 ] && printf '+PONG\r\n'; }
    _services
    grep -q "^FAIL	.*Redis on 127.0.0.1:6379 accepts commands without a password" "$FINDINGS_FILE"
    grep -q "^FAIL	.*Memcached (11211) exposed" "$FINDINGS_FILE"
    grep -q "^FAIL	.*Memcached UDP (11211)" "$FINDINGS_FILE"
    grep -q "^FAIL	.*MongoDB (27017) exposed.*authorization not confirmed" "$FINDINGS_FILE"
}

@test "services: Redis with a password and local-only Memcached are quiet" {
    SS_TCP=("LISTEN 0 0 127.0.0.1:6379 0.0.0.0:*" "LISTEN 0 0 127.0.0.1:11211 0.0.0.0:*")
    SS_UDP=()
    # shellcheck disable=SC1091
    source "$ANZEN_DIR/lib/checks/services.sh"
    _svc_probe() { printf -- '-NOAUTH Authentication required.\r\n'; }
    _services
    ! grep -qE "Redis|Memcached|MongoDB" "$FINDINGS_FILE"
}

@test "tls: 1024-bit RSA is a FAIL, SHA-1 signed leaf a WARN, good cert quiet" {
    command -v openssl >/dev/null || skip "openssl not installed"
    # shellcheck disable=SC1091
    source "$ANZEN_DIR/lib/checks/tls.sh"
    openssl req -x509 -newkey rsa:1024 -nodes -keyout "$T/k1" -out "$T/weak.pem" -subj /CN=weak -days 30 2>/dev/null
    openssl req -x509 -newkey rsa:2048 -nodes -keyout "$T/ca.key" -out "$T/ca.pem" -subj /CN=ca -days 30 2>/dev/null
    openssl req -newkey rsa:2048 -nodes -keyout "$T/l.key" -out "$T/l.csr" -subj /CN=leaf 2>/dev/null
    openssl x509 -req -in "$T/l.csr" -CA "$T/ca.pem" -CAkey "$T/ca.key" -CAcreateserial -sha1 -days 30 -out "$T/sha1.pem" 2>/dev/null \
        || skip "this openssl refuses SHA-1 signing"
    _tls_weak_cert weak < "$T/weak.pem"
    _tls_weak_cert sha1leaf < "$T/sha1.pem"
    _tls_weak_cert good < "$T/ca.pem"
    grep -q "^FAIL	.*1024-bit RSA key: weak" "$FINDINGS_FILE"
    grep -q "^WARN	.*signed with sha1WithRSAEncryption: sha1leaf" "$FINDINGS_FILE"
    ! grep -q "good" "$FINDINGS_FILE"
}

@test "NO_COLOR in the environment disables colour like --no-color" {
    run grep -c 'if \[ -n "${NO_COLOR:-}" \] && \[ "$NO_COLOR" != false \]; then NO_COLOR=true' "$ANZEN_DIR/anzen.sh"
    [ "$output" = 1 ]
    run env NO_COLOR=1 bash "$ANZEN_DIR/anzen.sh" --version
    [ "$status" -eq 0 ]
}

@test "services: Redis and PostgreSQL on 127.0.0.1 + [::1] are not 'exposed'" {
    # Debian/Ubuntu defaults: bind 127.0.0.1 -::1 / listen_addresses = localhost
    SS_TCP=("LISTEN 0 0 127.0.0.1:6379 0.0.0.0:*" "LISTEN 0 0 [::1]:6379 [::]:*"
            "LISTEN 0 0 127.0.0.1:5432 0.0.0.0:*" "LISTEN 0 0 [::1]:5432 [::]:*")
    SS_UDP=()
    # shellcheck disable=SC1091
    source "$ANZEN_DIR/lib/checks/services.sh"
    _svc_probe() { printf -- '-NOAUTH\r\n'; }
    _services
    ! grep -q "Redis (6379) exposed" "$FINDINGS_FILE"
    ! grep -q "PostgreSQL listening on 0.0.0.0" "$FINDINGS_FILE"
    grep -q "^OK	.*PostgreSQL bound to localhost" "$FINDINGS_FILE"
}

@test "system: a mount point with shell syntax is quoted in the disk remedy" {
    # shellcheck disable=SC1091
    source "$ANZEN_DIR/lib/checks/system.sh"
    mnt='/media/u/x$(touch '"$T"'/pwned)'
    df() { printf 'Filesystem Size Used Avail Use%% Mounted\n/dev/sdb1 1G 1G 0 99%% %s\n' "$mnt"; }
    run_system_check > /dev/null 2>&1 || true
    r=$(grep "^FAIL	.*Disk /media/u/x" "$FINDINGS_FILE" | cut -f5)
    [ -n "$r" ]
    bash -c "$r" 2>/dev/null || true
    [ ! -e "$T/pwned" ]
}

@test "notify: ntfy token and heartbeat URL never appear in curl's arguments" {
    # shellcheck disable=SC1091
    source "$ANZEN_DIR/lib/notify.sh"
    curl() { printf 'ARGS %s\n' "$*" >> "$T/curl"; printf 'STDIN %s\n' "$(cat)" >> "$T/curl"; }
    NOTIFY_NTFY_URL="https://ntfy.example/topic" NOTIFY_NTFY_TOKEN="tk_secret" _notify 1 80 "" h
    HEARTBEAT_URL="https://kuma.example/api/push/pushsecret" heartbeat
    ! grep "^ARGS" "$T/curl" | grep -qE "tk_secret|pushsecret"
    grep -q '^STDIN url = "https://ntfy.example/topic"' "$T/curl"
    grep -q 'header = "Authorization: Bearer tk_secret"' "$T/curl"
    grep -q 'url = "https://kuma.example/api/push/pushsecret"' "$T/curl"
}
