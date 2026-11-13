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

@test "ssh: GatewayPorts and PermitUserEnvironment are WARNs, agent forwarding INFO" {
    SSHD_T=$'port 2222\ngatewayports clientspecified\npermituserenvironment yes\nallowagentforwarding yes'
    _sshd_t
    grep -q "^WARN	SSH Configuration	GatewayPorts: clientspecified" "$FINDINGS_FILE"
    grep -q "^WARN	SSH Configuration	PermitUserEnvironment: yes" "$FINDINGS_FILE"
    grep -q "^INFO	SSH Configuration	AllowAgentForwarding: yes" "$FINDINGS_FILE"
    : > "$FINDINGS_FILE"
    SSHD_T=$'port 2222\ngatewayports no\npermituserenvironment no\nallowagentforwarding no'
    _sshd_t
    grep -q "^OK	SSH Configuration	GatewayPorts: no" "$FINDINGS_FILE"
    grep -q "^OK	SSH Configuration	PermitUserEnvironment: no" "$FINDINGS_FILE"
    grep -q "^OK	SSH Configuration	AllowAgentForwarding: no" "$FINDINGS_FILE"
}

@test "ssh: host-based and rhosts trust are WARNs" {
    SSHD_T=$'port 2222\nhostbasedauthentication yes\nignorerhosts no'
    _sshd_t
    grep -q "^WARN	SSH Configuration	HostbasedAuthentication: yes" "$FINDINGS_FILE"
    grep -q "^WARN	SSH Configuration	IgnoreRhosts: no" "$FINDINGS_FILE"
    : > "$FINDINGS_FILE"
    SSHD_T=$'port 2222\nhostbasedauthentication no\nignorerhosts yes'
    _sshd_t
    grep -q "^OK	SSH Configuration	HostbasedAuthentication: no" "$FINDINGS_FILE"
    grep -q "^OK	SSH Configuration	IgnoreRhosts: yes" "$FINDINGS_FILE"
}

@test "kernel: ldisc autoload is a WARN, kexec loading INFO" {
    # shellcheck disable=SC1091
    source "$ANZEN_DIR/lib/checks/kernel.sh"
    _sysctl() { case $1 in dev.tty.ldisc_autoload) echo "$LD" ;; kernel.kexec_load_disabled) echo "$KX" ;; esac; }
    LD=1 KX=0 run_kernel_check > /dev/null
    grep -q "^WARN	.*dev.tty.ldisc_autoload=1" "$FINDINGS_FILE"
    grep -q "^INFO	.*kernel.kexec_load_disabled=0" "$FINDINGS_FILE"
    : > "$FINDINGS_FILE"
    LD=0 KX=1 run_kernel_check > /dev/null
    grep -q "^OK	.*TTY line-discipline autoload disabled" "$FINDINGS_FILE"
    grep -q "^OK	.*kexec loading disabled" "$FINDINGS_FILE"
}

@test "services: Elasticsearch, CouchDB and etcd without authentication" {
    SS_TCP=("LISTEN 0 0 0.0.0.0:9200 0.0.0.0:*" "LISTEN 0 0 127.0.0.1:5984 0.0.0.0:*" "LISTEN 0 0 [::1]:2379 [::]:*")
    SS_UDP=()
    # shellcheck disable=SC1091
    source "$ANZEN_DIR/lib/checks/services.sh"
    _svc_probe() { :; }
    _svc_http() {
        echo "$1 $2 $3 ${4:-}" >> "$T/http.log"
        case $2 in
            9200) printf '200\t{ "name" : "n1", "cluster_name" : "prod" }\n' ;;
            5984) printf '200\t["_users","orders"]\n' ;;
            2379) printf '200\t{"header":{"cluster_id":"1"},"count":"0"}\n' ;;
        esac
    }
    _services
    grep -q "^FAIL	.*Elasticsearch on 127.0.0.1:9200 answers without authentication" "$FINDINGS_FILE"
    grep -q "^WARN	.*CouchDB on 127.0.0.1:5984 answers without authentication (local only)" "$FINDINGS_FILE"
    grep -q "^WARN	.*etcd on ::1:2379 answers without authentication (local only)" "$FINDINGS_FILE"
    grep -q '^::1 2379 /v3/kv/range {"key":"AA==","limit":1}$' "$T/http.log"
    # With authentication: 401, or 200 with an error body
    : > "$FINDINGS_FILE"
    _svc_http() { case $2 in 9200) printf '401\t{"error":"security_exception"}\n' ;; 5984) printf '401\t{"error":"unauthorized"}\n' ;; 2379) printf '200\t{"error":"etcdserver: user name is empty"}\n' ;; esac; }
    _services
    ! grep -qE "Elasticsearch|CouchDB|etcd" "$FINDINGS_FILE"
}

@test "services: Kafka serving metadata without authentication" {
    SS_TCP=("LISTEN 0 0 127.0.0.1:9092 0.0.0.0:*")
    SS_UDP=()
    # shellcheck disable=SC1091
    source "$ANZEN_DIR/lib/checks/services.sh"
    _svc_http() { :; }
    _svc_probe() {
        [ "$2" = 9092 ] || return 0
        printf '%s' "$3" > "$T/kafka.req"
        printf '\x00\x00\x00\x30\x00\x00\x00\x01\x00\x00\x00\x01'
    }
    _services
    grep -q "^WARN	.*Kafka on 127.0.0.1:9092 answers without authentication (local only)" "$FINDINGS_FILE"
    [ "$(printf "$(cat "$T/kafka.req")" | od -An -tx1 | tr -d ' \n')" = 0000000e0003000000000001ffff00000000 ]
    : > "$FINDINGS_FILE"
    _svc_probe() { :; }
    _services
    ! grep -q Kafka "$FINDINGS_FILE"
}

@test "services: ZooKeeper answering four-letter commands" {
    SS_TCP=("LISTEN 0 0 *:2181 *:*")
    SS_UDP=()
    # shellcheck disable=SC1091
    source "$ANZEN_DIR/lib/checks/services.sh"
    _svc_http() { :; }
    _svc_probe() { [ "$2" = 2181 ] && [ "$3" = srvr ] && printf 'Zookeeper version: 3.8.4-9316c2a7\nLatency min/avg/max: 0/0.0/0\n'; }
    _services
    grep -q "^FAIL	.*ZooKeeper on 127.0.0.1:2181 answers without authentication" "$FINDINGS_FILE"
    : > "$FINDINGS_FILE"
    _svc_probe() { printf 'srvr is not executed because it is not in the whitelist.\n'; }
    _services
    ! grep -q ZooKeeper "$FINDINGS_FILE"
}

@test "services: Solr without authentication, RabbitMQ with the guest login" {
    SS_TCP=("LISTEN 0 0 0.0.0.0:8983 0.0.0.0:*" "LISTEN 0 0 127.0.0.1:15672 0.0.0.0:*")
    SS_UDP=()
    # shellcheck disable=SC1091
    source "$ANZEN_DIR/lib/checks/services.sh"
    _svc_probe() { :; }
    _svc_http() {
        echo "$2 ${5:-}" >> "$T/http.log"
        case $2 in
            8983) printf '200\t{"responseHeader":{"status":0},"solr_home":"/var/solr/data"}\n' ;;
            15672) [ "${5:-}" = guest:guest ] && printf '200\t{"name":"guest","tags":["administrator"]}\n' ;;
        esac
    }
    _services
    grep -q "^FAIL	.*Solr on 127.0.0.1:8983 answers without authentication" "$FINDINGS_FILE"
    grep -q "^WARN	.*RabbitMQ on 127.0.0.1:15672 accepts the default guest login (local only)" "$FINDINGS_FILE"
    grep -q "^15672 guest:guest$" "$T/http.log"
    : > "$FINDINGS_FILE"
    _svc_http() { case $2 in 8983) printf '401\t\n' ;; 15672) printf '401\t{"error":"not_authorised"}\n' ;; esac; }
    _services
    ! grep -qE "Solr|RabbitMQ" "$FINDINGS_FILE"
}

@test "_svc_http returns status and body, brackets IPv6" {
    curl() { echo "$*" > "$T/curl.args"; printf 'line1\nline2\n404'; }
    run _svc_http ::1 2379 /version
    [ "$output" = "404	line1 line2" ]
    grep -q 'http://\[::1\]:2379/version' "$T/curl.args"
}

@test "_svc_http sends basic auth only when asked" {
    curl() { echo "$*" > "$T/curl.args"; printf 'ok\n200'; }
    _svc_http 127.0.0.1 15672 /api/whoami "" guest:guest > /dev/null
    grep -q -- '-u guest:guest' "$T/curl.args"
    _svc_http 127.0.0.1 15672 /api/whoami > /dev/null
    ! grep -q -- '-u' "$T/curl.args"
}

@test "tls: CA-issued leaf without SAN is a WARN, with SAN quiet" {
    command -v openssl >/dev/null || skip "openssl not installed"
    # shellcheck disable=SC1091
    source "$ANZEN_DIR/lib/checks/tls.sh"
    openssl req -x509 -newkey rsa:2048 -nodes -keyout "$T/ca.key" -out "$T/ca.pem" -subj /CN=ca -days 30 2>/dev/null
    openssl req -newkey rsa:2048 -nodes -keyout "$T/l.key" -out "$T/l.csr" -subj /CN=leaf.example.com 2>/dev/null
    openssl x509 -req -in "$T/l.csr" -CA "$T/ca.pem" -CAkey "$T/ca.key" -CAcreateserial -days 30 -out "$T/nosan.pem" 2>/dev/null
    printf 'subjectAltName=DNS:leaf.example.com\n' > "$T/ext"
    openssl x509 -req -in "$T/l.csr" -CA "$T/ca.pem" -CAkey "$T/ca.key" -CAcreateserial -days 30 -extfile "$T/ext" -out "$T/san.pem" 2>/dev/null
    _tls_weak_cert nosan < "$T/nosan.pem"
    _tls_weak_cert withsan < "$T/san.pem"
    _tls_weak_cert theca < "$T/ca.pem"
    grep -q "^WARN	.*without a Subject Alternative Name: nosan" "$FINDINGS_FILE"
    ! grep -qE "withsan|theca" "$FINDINGS_FILE"
}

# ── modules: on-demand modules behind Copy Fail / Dirty Frag / Fragnesia ─────
_ondemand() {
    # shellcheck disable=SC1091
    source "$ANZEN_DIR/lib/checks/modules.sh"
    mkdir -p "$T/proc" "$T/modprobe.d"
    printf '%s\n' "$1" > "$T/proc/modules"
    # shellcheck disable=SC2329
    modinfo() {
        case $3 in
            algif_aead|esp4|rxrpc) echo "/lib/modules/6.8.0/kernel/x/$3.ko.zst" ;;
            esp6) echo "(builtin)" ;;
            *) return 1 ;;
        esac
    }
    # shellcheck disable=SC2329
    _sysctl() { echo "${MODDIS:-0}"; }
    section "Kernel Modules" > /dev/null
    ANZEN_PROC="$T/proc" ANZEN_MODPROBE_DIRS="$T/modprobe.d" _modules_ondemand_check
}

@test "modules: unblocked on-demand exploit modules are a WARN; loaded and built-in ones are left out" {
    mkdir -p "$T/modprobe.d"
    echo "blacklist rxrpc" > "$T/modprobe.d/bl.conf"      # blacklist does not stop on-demand loading
    _ondemand "esp4 16384 0 - Live 0x0"
    grep -q $'^WARN\tKernel Modules\t.*load on demand for any user: algif_aead rxrpc\t' "$FINDINGS_FILE"
    grep -q 'echo "install algif_aead /bin/false" >> /etc/modprobe.d/anzen-blacklist.conf; echo "install rxrpc /bin/false"' "$FINDINGS_FILE"
}

@test "modules: install overrides or modules_disabled make the on-demand check quiet" {
    mkdir -p "$T/modprobe.d"
    printf 'install algif-aead /bin/false\ninstall esp4 /bin/false\n  install rxrpc /bin/true\n' > "$T/modprobe.d/x.conf"
    _ondemand ""
    grep -q $'^OK\t.*page-cache root exploits are blocked' "$FINDINGS_FILE"
    : > "$FINDINGS_FILE"; rm "$T/modprobe.d/x.conf"
    MODDIS=1 _ondemand ""
    [ ! -s "$FINDINGS_FILE" ]
}
