#!/usr/bin/env bats
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 The Anzen contributors
# tests/test_macos.bats — macOS edition against stub macOS commands. CI also runs
# this file under Bash 3.2 (the version macOS ships) and the script for real on
# a macOS runner.

setup() {
    ANZEN_DIR="$(cd "$(dirname "$BATS_TEST_FILENAME")/.." && pwd)"
    STUBS="$ANZEN_DIR/tests/macos/stubs"
    export STUB_FIXTURES="$ANZEN_DIR/tests/fixtures"
    export ANZEN_SOCKETFILTERFW="$STUBS/socketfilterfw"
    export PATH="$STUBS:$PATH" NO_COLOR=1
    # Test keychain path must exist for the System Roots check
    export HOME="$BATS_TEST_TMPDIR"
}

mac() { run bash "$ANZEN_DIR/macos/anzen-macos.sh" "$@"; }

@test "macos: --version and --list" {
    mac --version
    [[ "$output" == "anzen-macos "* ]]
    mac --list
    [[ "$output" == *truststore* ]]
}

@test "macos: unknown module is rejected" {
    mac --check=nope
    [ "$status" -eq 1 ]
    [[ "$output" == *"Unknown module: nope"* ]]
}

@test "macos: insecure test Mac produces the expected FAILs" {
    mac --check=filevault --check=sip --check=gatekeeper --check=accounts --check=updates
    [ "$status" -eq 1 ]
    [[ "$output" == *"[FAIL] FileVault is off"* ]]
    [[ "$output" == *"[FAIL] System Integrity Protection disabled"* ]]
    [[ "$output" == *"[FAIL] Gatekeeper disabled"* ]]
    [[ "$output" == *"[FAIL] Automatic login enabled for 'demo'"* ]]
    [[ "$output" == *"[WARN] Guest account enabled"* ]]
    [[ "$output" == *"[FAIL] CriticalUpdateInstall disabled"* ]]
    [[ "$output" == *"[WARN] 2 recommended update(s) available"* ]]
    [[ "$output" == *"[WARN] 3 administrator accounts"* ]]
}

@test "macos: secure settings are OK" {
    STUB_FILEVAULT=On STUB_SIP=enabled STUB_GATEKEEPER=enabled mac --check=filevault --check=sip --check=gatekeeper
    [ "$status" -eq 0 ]
    [[ "$output" == *"[ OK ] FileVault is on"* ]]
    [[ "$output" == *"[ OK ] System Integrity Protection enabled"* ]]
}

@test "macos: firewall and sharing services" {
    mac --check=firewall --check=sharing
    [[ "$output" == *"[WARN] Application firewall disabled"* ]]
    [[ "$output" == *"[WARN] Stealth mode disabled"* ]]
    [[ "$output" == *"Remote Login (SSH) is listening on all interfaces (port 22)"* ]]
    [[ "$output" == *"Screen Sharing / Remote Management (VNC) is listening"* ]]
    [[ "$output" != *"Printer Sharing"* ]]   # 631 only on 127.0.0.1
}

@test "macos: uptime is read from the sec field of kern.boottime" {
    mac --check=system
    [[ "$output" == *"Uptime: 50 days"* ]]
    [[ "$output" == *"[WARN] System not restarted for 50 days"* ]]
}

@test "macos: the sealed system volume is skipped, the Data volume is checked" {
    mac --check=system
    [[ "$output" == *"[FAIL] Disk /System/Volumes/Data: 97% used"* ]]
    [[ "$output" != *"Disk /: "* ]]
    [[ "$output" != *"System/Volumes/VM"* ]]
}

# Fake keychain file and an up-to-date cert.pem (only ISRG) unless a test overrides it
ts_env() {
    touch "$BATS_TEST_TMPDIR/SystemRoots.keychain"
    export ANZEN_SYSTEM_ROOTS_KEYCHAIN="$BATS_TEST_TMPDIR/SystemRoots.keychain"
    cp "$STUB_FIXTURES/isrg-root-x1.pem" "$BATS_TEST_TMPDIR/cert.pem"
    export ANZEN_CERT_PEM="$BATS_TEST_TMPDIR/cert.pem"
    # Hermetic on a real Mac too: no Homebrew bundles, certifi or Java
    export ANZEN_HOMEBREW_BUNDLES="" ANZEN_CHECK_RUNTIMES=0
    # and no real System keychain: point HOME at the temp dir (done in setup)
}

@test "macos: distrusted root in the keychain but blocked by Apple is OK, not FAIL" {
    ts_env
    mac --check=truststore
    [ "$status" -eq 0 ]
    [[ "$output" == *"[ OK ] emSign ECC Root CA - G3 (distrusted root) is in SystemRoots.keychain but blocked by macOS trust evaluation"* ]]
    [[ "$output" == *"[INFO] AAA Certificate Services"*"legitimate root; Apple blocks the affected intermediates"* ]]
    [[ "$output" != *"[FAIL]"* ]]
}

@test "macos: distrusted root still trusted by macOS is a FAIL" {
    ts_env
    STUB_TRUSTED=1 mac --check=truststore
    [ "$status" -eq 1 ]
    [[ "$output" == *"[FAIL] Distrusted certificate still trusted by macOS: emSign ECC Root CA - G3"* ]]
}

@test "macos: /etc/ssl/cert.pem with the distrusted roots is FAIL/WARN (curl, git, openssl)" {
    ts_env
    cat "$STUB_FIXTURES/emsign-ecc-root-g3.pem" "$STUB_FIXTURES/aaa-certificate-services.pem" >> "$ANZEN_CERT_PEM"
    mac --check=truststore
    [ "$status" -eq 1 ]
    [[ "$output" == *"[FAIL] Distrusted certificate in $ANZEN_CERT_PEM (used by curl, git, openssl): emSign ECC Root CA - G3"* ]]
    [[ "$output" == *"[WARN] Distrusted certificate in $ANZEN_CERT_PEM (used by curl, git, openssl): AAA Certificate Services"* ]]
}

@test "macos: JSON report has the shared layout and IDs match the Linux edition" {
    mac --check=filevault --output="$BATS_TEST_TMPDIR/r.json"
    grep -q '^  "summary": {"fail": 1, ' "$BATS_TEST_TMPDIR/r.json"
    line=$(grep '"level": "FAIL"' "$BATS_TEST_TMPDIR/r.json")
    id=$(sed -E 's/.*"id": "([^"]+)".*/\1/' <<< "$line")
    # Same ID as lib/output.sh computes for the same section and message
    msg="FileVault is off — the disk is readable by anyone with physical access"
    expected=$(bash -c "source '$ANZEN_DIR/lib/output.sh' 2>/dev/null; _finding_id 'FileVault' '$msg'")
    [ "$id" = "$expected" ]
}

@test "macos: accepted risk turns the FAIL into INFO" {
    expected=$(bash -c "source '$ANZEN_DIR/lib/output.sh' 2>/dev/null; _finding_id 'Gatekeeper' 'Gatekeeper disabled — unsigned apps run without checks'")
    printf '%s 2999-01-01 lab machine\n' "$expected" > "$BATS_TEST_TMPDIR/accept"
    mac --check=gatekeeper --accept="$BATS_TEST_TMPDIR/accept"
    [ "$status" -eq 0 ]
    [[ "$output" == *"accepted until 2999-01-01: lab machine"* ]]
}
