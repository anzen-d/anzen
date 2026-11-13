#!/usr/bin/env bats
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 The Anzen contributors
# tests/test_checks_ssh.bats — Tests for lib/checks/ssh.sh
# run_ssh_check runs for real; only `sshd -T` (the effective config) is faked

setup() {
    ANZEN_DIR="$(cd "$(dirname "$BATS_TEST_FILENAME")/.." && pwd)"
    FINDINGS_FILE="$(mktemp)"
    NO_COLOR=true QUIET=true
    export ANZEN_DIR FINDINGS_FILE NO_COLOR QUIET
    # shellcheck disable=SC1091
    source "$ANZEN_DIR/lib/output.sh"
    # shellcheck disable=SC1091
    source "$ANZEN_DIR/lib/utils.sh"
    # shellcheck disable=SC1091
    source "$ANZEN_DIR/lib/checks/ssh.sh"
    # A hardened effective config; each test changes one line
    SAFE=$'port 2222\npermitrootlogin no\npasswordauthentication no\npermitemptypasswords no
x11forwarding no\nmaxauthtries 3\nallowtcpforwarding no\npermittunnel no\nlogingracetime 30
clientaliveinterval 300\nusedns no\nallowusers alice'
}

teardown() { rm -f "$FINDINGS_FILE" "${FINDINGS_FILE}.tmp"; }

# _check "key value" — run the real module with SAFE plus one changed line
_check() {
    local key=${1%% *}
    SSHD_T=$(grep -v "^$key " <<< "$SAFE"; echo "$1")
    # shellcheck disable=SC2329
    sshd() { printf '%s\n' "$SSHD_T"; }
    _priv() { "$@"; }
    run_ssh_check > /dev/null
}

@test "ssh: the hardened config has no FAIL" {
    _check "port 2222"
    ! grep -q "^FAIL" "$FINDINGS_FILE"
}

@test "ssh: PermitRootLogin yes is a FAIL, prohibit-password is OK" {
    _check "permitrootlogin yes"
    grep -q "^FAIL	SSH Configuration	PermitRootLogin: yes" "$FINDINGS_FILE"
    : > "$FINDINGS_FILE"
    _check "permitrootlogin prohibit-password"
    grep -q "^OK	SSH Configuration	PermitRootLogin: prohibit-password (key-only root)" "$FINDINGS_FILE"
}

@test "ssh: PasswordAuthentication yes is a WARN with a remedy" {
    _check "passwordauthentication yes"
    grep -q "^WARN	SSH Configuration	PasswordAuthentication: yes.*PasswordAuthentication no" "$FINDINGS_FILE"
}

@test "ssh: PermitEmptyPasswords yes is a FAIL" {
    _check "permitemptypasswords yes"
    grep -q "^FAIL	SSH Configuration	PermitEmptyPasswords: yes" "$FINDINGS_FILE"
}

@test "ssh: MaxAuthTries above 4 is a WARN, 3 is OK" {
    _check "maxauthtries 6"
    grep -q "^WARN	SSH Configuration	MaxAuthTries: 6" "$FINDINGS_FILE"
    : > "$FINDINGS_FILE"
    _check "maxauthtries 3"
    grep -q "^OK	SSH Configuration	MaxAuthTries: 3" "$FINDINGS_FILE"
}

@test "ssh: X11Forwarding yes is a WARN" {
    _check "x11forwarding yes"
    grep -q "^WARN	SSH Configuration	X11Forwarding: yes" "$FINDINGS_FILE"
}

@test "ssh: weak ciphers are a FAIL" {
    SAFE+=$'\nmacs hmac-sha2-256\nkexalgorithms curve25519-sha256'
    _check "ciphers aes128-ctr,3des-cbc"
    grep -q "^FAIL	SSH Configuration	Weak ciphers in SSH config" "$FINDINGS_FILE"
}

@test "_ssh_val uses sshd -T over raw file when available" {
    # sshd -T correctly reflects effective defaults even for commented settings
    # This test verifies _ssh_val prefers compiled output
    run bash -c "
        ANZEN_DIR='$ANZEN_DIR' FINDINGS_FILE='$FINDINGS_FILE'
        NO_COLOR=true QUIET=true
        export ANZEN_DIR FINDINGS_FILE NO_COLOR QUIET
        source '$ANZEN_DIR/lib/output.sh'
        source '$ANZEN_DIR/lib/utils.sh'
        source '$ANZEN_DIR/lib/checks/ssh.sh'
        # Simulate sshd -T returning 'permitrootlogin prohibit-password'
        _priv() { echo 'permitrootlogin prohibit-password'; }
        val=\$(_ssh_val PermitRootLogin)
        echo \"\$val\"
    "
    [[ "$output" == *"prohibit-password"* ]]
}

@test "AllowUsers remedy never suggests root (would lock everyone out)" {
    for who in root alice; do
        : > "$FINDINGS_FILE"
        SUDO_USER=$who bash -c "
            ANZEN_DIR='$ANZEN_DIR' FINDINGS_FILE='$FINDINGS_FILE' NO_COLOR=true QUIET=true
            source '$ANZEN_DIR/lib/output.sh'; source '$ANZEN_DIR/lib/utils.sh'
            source '$ANZEN_DIR/lib/checks/ssh.sh'
            # sshd -T with no AllowUsers/AllowGroups; sshd itself 'installed'
            _priv() { printf 'permitrootlogin no\npasswordauthentication no\n'; }
            command() { [ \"\$2\" = sshd ] && return 0; builtin command \"\$@\"; }
            run_ssh_check >/dev/null
        "
        line=$(grep "AllowUsers/AllowGroups not set" "$FINDINGS_FILE")
        if [ "$who" = root ]; then [[ "$line" == *"# echo 'AllowUsers <your-admin-user>'"* ]]
        else [[ "$line" == *"echo 'AllowUsers alice'"* ]]; fi
    done
}

# ── SSHole (CVE-2026-123158) ──────────────────────────────────────────────────
# _sshole PKGVER "sshd -T lines" "shadow lines" — musl sshd with an Alpine package
_sshole() {
    APKVER=$1 SSHD_T=$2
    printf '%s\n' "$3" > "$BATS_TEST_TMPDIR/shadow"
    : > "$BATS_TEST_TMPDIR/log"
    [ -n "${4:-}" ] && printf '%s\n' "$4" > "$BATS_TEST_TMPDIR/log"
    # shellcheck disable=SC2329
    sshd() { printf '%s\n' "$SSHD_T"; }
    # shellcheck disable=SC2329
    ldd() { echo "	/lib/ld-musl-x86_64.so.1 (0x7e53e7187000)"; }
    # shellcheck disable=SC2329
    apk() {
        case "$1 $2" in
            "info -e") [ "$4" = openssh-server ] && echo "openssh-server-$APKVER" ;;
            "version -t") [ "$(printf '%s\n' "$3" "$4" | sort -V | head -1)" = "$3" ] && [ "$3" != "$4" ] && echo "<" || echo ">" ;;
        esac
    }
    _priv() { "$@"; }
    _SSHD_T_CACHE=""
    section "SSH Configuration" > /dev/null
    ANZEN_SHADOW="$BATS_TEST_TMPDIR/shadow" ANZEN_AUTH_LOGS="$BATS_TEST_TMPDIR/log" _ssh_sshole_check
}

@test "ssh: SSHole is a FAIL on an unfixed musl sshd with a passwordless and a hashed account" {
    _sshole 10.0_p1-r10 "passwordauthentication yes" $'root:*::0:::::\nalice:$6$salt$hash:1::::::\nbob:!:1::::::'
    grep -q $'^FAIL\tSSH Configuration\tOpenSSH password bypass SSHole (CVE-2026-123158).*no password set (1)' "$FINDINGS_FILE"
    grep -q 'apk upgrade -U openssh && rc-service sshd restart' "$FINDINGS_FILE"
}

@test "ssh: SSHole fixed package, PAM, password logins off and harmless accounts are not a FAIL" {
    _sshole 10.0_p1-r11 "passwordauthentication yes" $'root:*::0:::::\nalice:$6$salt$hash:1::::::'
    grep -q $'^OK\t.*OpenSSH has the SSHole fix' "$FINDINGS_FILE"
    : > "$FINDINGS_FILE"
    _sshole 10.0_p1-r10 $'usepam yes\npasswordauthentication yes' $'root:*::0:::::\nalice:$6$salt$hash:1::::::'
    [ ! -s "$FINDINGS_FILE" ]
    _sshole 10.0_p1-r10 "passwordauthentication no" $'root:*::0:::::\nalice:$6$salt$hash:1::::::'
    grep -q $'^INFO\t.*lacks the SSHole fix.*PasswordAuthentication is off' "$FINDINGS_FILE"
    : > "$FINDINGS_FILE"
    # Locked with "!" only, no "*" account
    _sshole 9.7_p1-r5 "passwordauthentication yes" $'root:!::0:::::\nalice:$6$salt$hash:1::::::'
    grep -q $'^WARN\t.*lacks the SSHole fix.*not exploitable with the current accounts' "$FINDINGS_FILE"
    ! grep -q "^FAIL" "$FINDINGS_FILE"
}

@test "ssh: SSHole exploitation sign in the auth log is a FAIL even after the fix" {
    _sshole 10.0_p1-r11 "passwordauthentication yes" $'root:*::0:::::\nalice:$6$salt$hash:1::::::' \
        $'Nov  6 03:12:01 box auth.info sshd-session[4242]: Accepted password for root from 203.0.113.7 port 51234 ssh2\nNov  6 03:13:01 box auth.info sshd-session[4250]: Accepted password for alice from 203.0.113.7 port 51240 ssh2'
    grep -q $'^FAIL\t.*Password login accepted for accounts that have no password (1)' "$FINDINGS_FILE"
    grep -q 'accounts: root —' "$FINDINGS_FILE"
}

@test "ssh: SSHole on musl without apk compares the upstream version; glibc is skipped" {
    printf 'root:*::0:::::\nalice:$6$salt$hash:1::::::\n' > "$BATS_TEST_TMPDIR/shadow"
    # shellcheck disable=SC2329
    sshd() { [ "$1" = "-V" ] && echo "OpenSSH_${SSHV}, OpenSSL 3.5.9" >&2; echo "passwordauthentication yes"; }
    # shellcheck disable=SC2329
    ldd() { echo "	/lib/ld-musl-aarch64.so.1 (0x1)"; }
    _priv() { "$@"; }
    command -v apk && skip "apk on this machine"
    _go() { : > "$FINDINGS_FILE"; _SSHD_T_CACHE=""; ANZEN_SHADOW="$BATS_TEST_TMPDIR/shadow" ANZEN_AUTH_LOGS=/nonexistent _ssh_sshole_check; }
    SSHV=10.6p1 _go; grep -q "^FAIL" "$FINDINGS_FILE"
    SSHV=9.9p2  _go; grep -q "^FAIL" "$FINDINGS_FILE"
    SSHV=10.6p2 _go; grep -q "^OK" "$FINDINGS_FILE"
    SSHV=11.0p1 _go; grep -q "^OK" "$FINDINGS_FILE"
    # shellcheck disable=SC2329
    ldd() { echo "	libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x1)"; }
    SSHV=9.6p1 _go; [ ! -s "$FINDINGS_FILE" ]
}
