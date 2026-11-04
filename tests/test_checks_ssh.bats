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
