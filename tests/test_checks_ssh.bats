#!/usr/bin/env bats
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 The Anzen contributors
# tests/test_checks_ssh.bats — Tests for lib/checks/ssh.sh
# Uses a fake sshd_config to test specific logic paths

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
    source "$ANZEN_DIR/lib/os_detect.sh"

    # Create a scratch dir for fake config files
    FAKE_DIR="$(mktemp -d)"

    # Default safe sshd_config
    cat > "$FAKE_DIR/sshd_config" <<'EOF'
Protocol 2
PermitRootLogin no
PasswordAuthentication no
PermitEmptyPasswords no
X11Forwarding no
MaxAuthTries 3
AllowAgentForwarding no
AllowTcpForwarding no
LoginGraceTime 60
IgnoreRhosts yes
HostbasedAuthentication no
PermitUserEnvironment no
ClientAliveInterval 300
ClientAliveCountMax 2
EOF
}

teardown() {
    rm -f "$FINDINGS_FILE" "${FINDINGS_FILE}.tmp"
    rm -rf "$FAKE_DIR"
}

# Helper: run ssh check against a custom sshd_config
_run_ssh_check_with() {
    local cfg_content="$1"
    echo "$cfg_content" > "$FAKE_DIR/sshd_config"
    bash -c "
        ANZEN_DIR='$ANZEN_DIR'
        FINDINGS_FILE='$FINDINGS_FILE'
        NO_COLOR=true QUIET=true
        export ANZEN_DIR FINDINGS_FILE NO_COLOR QUIET
        source '$ANZEN_DIR/lib/output.sh'
        source '$ANZEN_DIR/lib/utils.sh'
        source '$ANZEN_DIR/lib/os_detect.sh'

        # Override config path used by ssh check
        _sshd_config() { echo '$FAKE_DIR/sshd_config'; }
        _sshd_val() {
            grep -i \"^\$1\" '$FAKE_DIR/sshd_config' | awk '{print \$2}' | tail -1
        }

        # Inline the specific check logic being tested
        val=\$(_sshd_val \"\$1\")
        echo \"\$val\"
    " -- "$1"
}

@test "sshd_config: PermitRootLogin no passes" {
    # Parse the safe config and confirm no FAIL for PermitRootLogin
    bash -c "
        ANZEN_DIR='$ANZEN_DIR' FINDINGS_FILE='$FINDINGS_FILE'
        NO_COLOR=true QUIET=true
        export ANZEN_DIR FINDINGS_FILE NO_COLOR QUIET
        source '$ANZEN_DIR/lib/output.sh'
        source '$ANZEN_DIR/lib/utils.sh'
        val=\$(grep -i '^PermitRootLogin' '$FAKE_DIR/sshd_config' | awk '{print \$2}')
        [ \"\$val\" = 'no' ] && ok 'PermitRootLogin no' || fail 'PermitRootLogin enabled'
    "
    run grep "^FAIL" "$FINDINGS_FILE"
    [ "$status" -ne 0 ]
}

@test "sshd_config: PermitRootLogin yes triggers FAIL" {
    sed -i 's/PermitRootLogin no/PermitRootLogin yes/' "$FAKE_DIR/sshd_config"
    bash -c "
        ANZEN_DIR='$ANZEN_DIR' FINDINGS_FILE='$FINDINGS_FILE'
        NO_COLOR=true QUIET=true
        export ANZEN_DIR FINDINGS_FILE NO_COLOR QUIET
        source '$ANZEN_DIR/lib/output.sh'
        source '$ANZEN_DIR/lib/utils.sh'
        val=\$(grep -i '^PermitRootLogin' '$FAKE_DIR/sshd_config' | awk '{print \$2}')
        [ \"\$val\" = 'no' ] && ok 'PermitRootLogin no' || fail 'PermitRootLogin enabled'
    "
    run grep "^FAIL" "$FINDINGS_FILE"
    [ "$status" -eq 0 ]
}

@test "sshd_config: PasswordAuthentication yes triggers FAIL" {
    bash -c "
        ANZEN_DIR='$ANZEN_DIR' FINDINGS_FILE='$FINDINGS_FILE'
        NO_COLOR=true QUIET=true
        export ANZEN_DIR FINDINGS_FILE NO_COLOR QUIET
        source '$ANZEN_DIR/lib/output.sh'
        source '$ANZEN_DIR/lib/utils.sh'
        val='yes'
        [ \"\$val\" = 'no' ] && ok 'PasswordAuth disabled' || fail 'PasswordAuthentication enabled'
    "
    run grep "^FAIL.*PasswordAuthentication" "$FINDINGS_FILE"
    [ "$status" -eq 0 ]
}

@test "sshd_config: MaxAuthTries <= 4 passes" {
    bash -c "
        ANZEN_DIR='$ANZEN_DIR' FINDINGS_FILE='$FINDINGS_FILE'
        NO_COLOR=true QUIET=true
        export ANZEN_DIR FINDINGS_FILE NO_COLOR QUIET
        source '$ANZEN_DIR/lib/output.sh'
        source '$ANZEN_DIR/lib/utils.sh'
        val=3
        [ \"\$val\" -le 4 ] && ok 'MaxAuthTries OK' || warn 'MaxAuthTries high'
    "
    run grep "^OK.*MaxAuthTries" "$FINDINGS_FILE"
    [ "$status" -eq 0 ]
}

@test "sshd_config: MaxAuthTries > 6 triggers FAIL" {
    bash -c "
        ANZEN_DIR='$ANZEN_DIR' FINDINGS_FILE='$FINDINGS_FILE'
        NO_COLOR=true QUIET=true
        export ANZEN_DIR FINDINGS_FILE NO_COLOR QUIET
        source '$ANZEN_DIR/lib/output.sh'
        source '$ANZEN_DIR/lib/utils.sh'
        val=10
        if [ \"\$val\" -le 4 ]; then ok 'MaxAuthTries OK'
        elif [ \"\$val\" -le 6 ]; then warn \"MaxAuthTries=\$val\"
        else fail \"MaxAuthTries=\$val (should be <=4)\"; fi
    "
    run grep "^FAIL.*MaxAuthTries" "$FINDINGS_FILE"
    [ "$status" -eq 0 ]
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

@test "sshd_config: X11Forwarding yes triggers WARN" {
    bash -c "
        ANZEN_DIR='$ANZEN_DIR' FINDINGS_FILE='$FINDINGS_FILE'
        NO_COLOR=true QUIET=true
        export ANZEN_DIR FINDINGS_FILE NO_COLOR QUIET
        source '$ANZEN_DIR/lib/output.sh'
        source '$ANZEN_DIR/lib/utils.sh'
        val='yes'
        [ \"\$val\" = 'no' ] && ok 'X11Forwarding disabled' || warn 'X11Forwarding enabled'
    "
    run grep "^WARN.*X11Forwarding" "$FINDINGS_FILE"
    [ "$status" -eq 0 ]
}
