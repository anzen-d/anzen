#!/usr/bin/env bats
# tests/test_checks_secrets.bats — Tests for lib/checks/secrets.sh logic
# Creates fake files to trigger each detection path

setup() {
    ANZEN_DIR="$(cd "$(dirname "$BATS_TEST_FILENAME")/.." && pwd)"
    FINDINGS_FILE="$(mktemp)"
    NO_COLOR=true QUIET=true
    export ANZEN_DIR FINDINGS_FILE NO_COLOR QUIET
    # shellcheck disable=SC1091
    source "$ANZEN_DIR/lib/output.sh"

    FAKE_DIR="$(mktemp -d)"
    export FAKE_DIR
}

teardown() {
    rm -f "$FINDINGS_FILE" "${FINDINGS_FILE}.tmp"
    rm -rf "$FAKE_DIR"
}

# Helper: run a snippet that mimics a secrets check on FAKE_DIR
_check_snippet() {
    bash -c "
        ANZEN_DIR='$ANZEN_DIR' FINDINGS_FILE='$FINDINGS_FILE'
        NO_COLOR=true QUIET=true FAKE_DIR='$FAKE_DIR'
        export ANZEN_DIR FINDINGS_FILE NO_COLOR QUIET
        source '$ANZEN_DIR/lib/output.sh'
        $1
    "
}

@test "secrets: world-readable private key triggers FAIL" {
    local keyfile="$FAKE_DIR/id_rsa"
    echo "-----BEGIN RSA PRIVATE KEY-----" > "$keyfile"
    chmod 644 "$keyfile"

    _check_snippet "
        f='$keyfile'
        perm=\$(stat -c '%a' \"\$f\" 2>/dev/null)
        if [ \$((8#\${perm:-600} & 8#044)) -ne 0 ]; then
            fail \"World/group readable private key: \$f\"
        else
            ok \"Private key permissions OK: \$f\"
        fi
    "
    run grep "^FAIL" "$FINDINGS_FILE"
    [ "$status" -eq 0 ]
    [[ "$output" == *"private key"* ]]
}

@test "secrets: private key with 600 permissions passes" {
    local keyfile="$FAKE_DIR/id_rsa"
    echo "-----BEGIN RSA PRIVATE KEY-----" > "$keyfile"
    chmod 600 "$keyfile"

    _check_snippet "
        f='$keyfile'
        perm=\$(stat -c '%a' \"\$f\" 2>/dev/null)
        if [ \$((8#\${perm:-600} & 8#044)) -ne 0 ]; then
            fail \"World/group readable private key: \$f\"
        else
            ok \"Private key permissions OK: \$f\"
        fi
    "
    run grep "^FAIL" "$FINDINGS_FILE"
    [ "$status" -ne 0 ]
}

@test "secrets: .env file with world-readable perms triggers WARN" {
    local envfile="$FAKE_DIR/.env"
    echo "DB_PASSWORD=secret123" > "$envfile"
    chmod 644 "$envfile"

    _check_snippet "
        f='$envfile'
        perm=\$(stat -c '%a' \"\$f\" 2>/dev/null)
        if [ \$((8#\${perm:-600} & 8#004)) -ne 0 ]; then
            warn \"World-readable .env file: \$f\"
        else
            ok \".env permissions OK: \$f\"
        fi
    "
    run grep "^WARN.*\.env" "$FINDINGS_FILE"
    [ "$status" -eq 0 ]
}

@test "secrets: AWS credentials file triggers FAIL" {
    mkdir -p "$FAKE_DIR/.aws"
    local credfile="$FAKE_DIR/.aws/credentials"
    cat > "$credfile" <<'EOF'
[default]
aws_access_key_id = AKIAIOSFODNN7EXAMPLE
aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
EOF
    chmod 644 "$credfile"

    _check_snippet "
        f='$credfile'
        if [ -f \"\$f\" ]; then
            perm=\$(stat -c '%a' \"\$f\" 2>/dev/null)
            if [ \$((8#\${perm:-600} & 8#044)) -ne 0 ]; then
                fail \"AWS credentials file readable by others: \$f\"
            else
                ok \"AWS credentials permissions OK\"
            fi
        fi
    "
    run grep "^FAIL.*AWS" "$FINDINGS_FILE"
    [ "$status" -eq 0 ]
}

@test "secrets: hardcoded password pattern in config triggers WARN" {
    local cfgfile="$FAKE_DIR/app.conf"
    echo 'db_password = "supersecret123"' > "$cfgfile"

    _check_snippet "
        f='$cfgfile'
        if grep -qiE '(password|passwd|secret|api_key)\s*=\s*[\"'\''][^\"'\'']{4,}' \"\$f\" 2>/dev/null; then
            warn \"Possible hardcoded secret in: \$f\"
        fi
    "
    run grep "^WARN.*hardcoded\|^WARN.*secret\|^WARN.*Possible" "$FINDINGS_FILE"
    [ "$status" -eq 0 ]
}

@test "secrets: .netrc file with loose permissions triggers FAIL" {
    local netrc="$FAKE_DIR/.netrc"
    echo "machine example.com login user password pass" > "$netrc"
    chmod 644 "$netrc"

    _check_snippet "
        f='$netrc'
        if [ -f \"\$f\" ]; then
            perm=\$(stat -c '%a' \"\$f\" 2>/dev/null)
            if [ \$((8#\${perm:-600} & 8#044)) -ne 0 ]; then
                fail \".netrc is world/group readable: \$f\"
            fi
        fi
    "
    run grep "^FAIL.*netrc" "$FINDINGS_FILE"
    [ "$status" -eq 0 ]
}

@test "_key_files() ignores certificates and keeps real keys" {
    # shellcheck disable=SC1091
    source "$ANZEN_DIR/lib/checks/secrets.sh"
    d=$(mktemp -d /home/anzen-test.XXXXXX 2>/dev/null) || skip "cannot write under /home"
    printf -- '-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n' > "$d/cert.pem"
    printf -- '-----BEGIN PRIVATE KEY-----\nMIIE\n-----END PRIVATE KEY-----\n' > "$d/privkey.pem"
    printf -- '-----BEGIN EC PRIVATE KEY-----\nMHc\n-----END EC PRIVATE KEY-----\n' > "$d/tls.key"
    run _key_files
    rm -rf "$d"
    [[ "$output" == *"$d/privkey.pem"* ]]
    [[ "$output" == *"$d/tls.key"* ]]
    [[ "$output" != *"$d/cert.pem"* ]]
}
