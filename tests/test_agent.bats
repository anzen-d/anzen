#!/usr/bin/env bats
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 The Anzen contributors
# tests/test_agent.bats — push agent: enrol, approve, signed upload, receiver

setup() {
    ANZEN_DIR="$(cd "$(dirname "$BATS_TEST_FILENAME")/.." && pwd)"
    T="$(mktemp -d)"
    PORT=$((20000 + RANDOM % 20000))
    URL="http://127.0.0.1:$PORT"
    ADMIN="http://127.0.0.1:$((PORT + 1))"
    # One conf for both roles: the controller's state and history, the host's key dir
    cat > "$T/c.conf" <<CONF
HISTORY_DIR=$T/hist
DASHBOARD_FILE=$T/dash.html
AGENT_STATE_DIR=$T/state
AGENT_DIR=$T/agent
AGENT_PUBLIC_URL=$URL
AGENT_LISTEN=127.0.0.1:$PORT
AGENT_ADMIN_LISTEN=127.0.0.1:$((PORT + 1))
CONF
    chmod 600 "$T/c.conf"
    A=("$ANZEN_DIR/anzen.sh" --config="$T/c.conf")
    # 3>&-: bats waits for every holder of its fd 3
    "${A[@]}" --receiver > "$T/recv.log" 2>&1 3>&- &
    RECV=$!
    for _ in $(seq 50); do curl -fs -o /dev/null "$URL/enrol" && break; sleep 0.2; done
}

teardown() {
    kill "$RECV" 2>/dev/null
    rm -rf "$T"
}

# The host's own run; --history= makes a --check run count as a full one
_host_run() { "${A[@]}" --check=kernel --history="$T/hosthist" --quiet --no-color; }
_code() { "${A[@]}" --agent-list | awk '$1 == "pending" { print $2 }'; }
# _post BODY_FILE [KEY] [PATH] — send BODY signed with KEY; prints the HTTP
# status, and before it the answer when PATH is not "report"
_post() {
    local key=${2:-$T/agent/key.pem} path=${3:-report} id out=/dev/null
    [ "$path" = report ] || out=-
    id=$(openssl pkey -in "$key" -pubout -outform DER | openssl dgst -sha256 -r | cut -d' ' -f1)
    curl -s -o "$out" -w '%{http_code}' -H "X-Anzen-Agent: $id" \
        -H "X-Anzen-Signature: $(openssl dgst -sha256 -sign "$key" "$1" | base64 | tr -d '\n')" \
        --data-binary @"$1" "$URL/$path"
}
# Web controller: _login stores the session cookie, _api ACTION JSON prints the answer
_login() {
    curl -s -o /dev/null -c "$T/jar" --data-urlencode "token=$(cat "$T/state/admin.token")" "$ADMIN/login"
    CSRF=$(curl -s -b "$T/jar" "$ADMIN/" | sed -n 's/.*data-csrf="\([0-9a-f]*\)".*/\1/p')
}
_api() {
    curl -s -b "$T/jar" -H "X-Anzen-Csrf: ${3-$CSRF}" -H 'Content-Type: application/json' \
        -d "$2" -w '\n%{http_code}' "$ADMIN/api/$1"
}

@test "agent: --enrol refuses a plain http controller" {
    run "${A[@]}" --enrol=http://controller.example.com
    [ "$status" -ne 0 ]
    [[ "$output" == *"https://"* ]]
    [ ! -e "$T/agent/key.pem" ]
}

@test "agent: nothing is stored before approval, the approved name wins afterwards" {
    run "${A[@]}" --enrol="$URL"
    [ "$status" -eq 0 ]
    [[ "$output" =~ Code:\ [0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4} ]]
    [ "$(stat -c %a "$T/agent/key.pem")" = 600 ]
    code=$(_code)
    [[ "$output" == *"$code"* ]]

    run _host_run
    [[ "$output" == *"Push agent: upload"*"failed"* ]]
    [ ! -d "$T/hist" ] || [ -z "$(ls -A "$T/hist")" ]

    run "${A[@]}" --agent-approve="$code:web1"
    [ "$status" -eq 0 ]
    run _host_run
    [[ "$output" == *"Pushed"* ]]
    f=$(ls "$T"/hist/web1/*.json)
    grep -qx '  "hostname": "web1",' "$f"
    [ "$(grep -c '^  "hostname": ' "$f")" -eq 1 ]
    grep -q '"web1"' "$T/dash.html"
    "${A[@]}" --agent-list | grep -Eq '^approved +[0-9a-f-]+ +web1 +20[0-9-]+T'
}

@test "agent: replay, changed report, wrong key and junk are refused" {
    "${A[@]}" --enrol="$URL"
    "${A[@]}" --agent-approve="$(_code):web1"
    _host_run || true
    f=$(ls "$T"/hist/web1/*.json)
    cp "$f" "$T/again.json"
    # Same report again: its date is not newer
    [ "$(_post "$T/again.json")" = 400 ]
    [ "$(ls "$T"/hist/web1/*.json | wc -l)" -eq 1 ]

    # A newer report from a key nobody approved
    sed 's/^  "date": .*/  "date": "2099-01-01T00:00:00Z",/' "$f" > "$T/new.json"
    openssl ecparam -genkey -name prime256v1 -noout -out "$T/other.pem"
    [ "$(_post "$T/new.json" "$T/other.pem")" = 403 ]

    # Good key, signature of another body
    id=$(openssl pkey -in "$T/agent/key.pem" -pubout -outform DER | openssl dgst -sha256 -r | cut -d' ' -f1)
    sig=$(openssl dgst -sha256 -sign "$T/agent/key.pem" "$T/again.json" | base64 | tr -d '\n')
    [ "$(curl -s -o /dev/null -w '%{http_code}' -H "X-Anzen-Agent: $id" -H "X-Anzen-Signature: $sig" \
         --data-binary @"$T/new.json" "$URL/report")" = 403 ]

    # Signed by the approved key, but markup where a finding should be
    sed 's|^  "findings": \[|&\n    <script>alert(1)</script>,|' "$T/new.json" > "$T/junk.json"
    [ "$(_post "$T/junk.json")" = 400 ]
    [ "$(ls "$T"/hist/web1/*.json | wc -l)" -eq 1 ]

    # The untouched newer report is fine
    [ "$(_post "$T/new.json")" = 200 ]
    [ "$(ls "$T"/hist/web1/*.json | wc -l)" -eq 2 ]
}

@test "agent: a revoked host is refused" {
    "${A[@]}" --enrol="$URL"
    "${A[@]}" --agent-approve="$(_code):web1"
    run "${A[@]}" --agent-revoke=web1
    [ "$status" -eq 0 ]
    run _host_run
    [[ "$output" == *"Push agent: upload"*"failed"* ]]
    [ ! -d "$T/hist/web1" ]
}

@test "agent: approval needs the whole code, a free name and no foreign history" {
    "${A[@]}" --enrol="$URL"
    code=$(_code)
    run "${A[@]}" --agent-approve="${code%%-*}:web1"
    [ "$status" -ne 0 ]
    run "${A[@]}" --agent-approve="$code:../etc"
    [ "$status" -ne 0 ]
    # The name the host suggested already has history: the admin must say so
    hint=$(awk '$1 == "pending" { print $3 }' <("${A[@]}" --agent-list))
    mkdir -p "$T/hist/$hint"
    run "${A[@]}" --agent-approve="$code"
    [ "$status" -ne 0 ]
    [[ "$output" == *"already exists"* ]]
    "${A[@]}" --agent-approve="$code:web1"

    # A second host cannot take the same name
    sed "s|^AGENT_DIR=.*|AGENT_DIR=$T/agent2|" "$T/c.conf" > "$T/c2.conf"
    chmod 600 "$T/c2.conf"
    "$ANZEN_DIR/anzen.sh" --config="$T/c2.conf" --enrol="$URL"
    run "${A[@]}" --agent-approve="$(_code):web1"
    [ "$status" -ne 0 ]
    [[ "$output" == *"already called"* ]]
}

@test "agent: the pending list is capped" {
    for i in 1 2; do
        openssl ecparam -genkey -name prime256v1 -noout | openssl pkey -pubout -out "$T/k$i.pub"
    done
    source "$ANZEN_DIR/lib/agent.sh"
    AGENT_STATE_DIR="$T/state" AGENT_MAX_PENDING=1
    run agent_enrol_receive "$T/k1.pub" "host.example.com"
    [ "$output" = pending ]
    [ "$(cat "$T"/state/pending/*.name)" = host ]
    run agent_enrol_receive "$T/k2.pub" x
    [ "$status" -eq 2 ]
    echo "not a key" > "$T/bad.pub"
    run agent_enrol_receive "$T/bad.pub" x
    [ "$status" -eq 1 ]
}

@test "agent: the receiver serves the bootstrap script and this anzen" {
    curl -fsS "$URL/enrol" > "$T/boot.sh"
    sh -n "$T/boot.sh"
    grep -q -- "--enrol=\"$URL\"" "$T/boot.sh"
    curl -fsS "$URL/anzen.tar.gz" | tar -tzvf - > "$T/list"
    grep -q ' \./anzen\.sh$' "$T/list"
    grep -q ' \./lib/agent\.sh$' "$T/list"
    # Root-owned in the archive, whoever owns the controller's copy
    ! awk '{ print $2 }' "$T/list" | grep -vq '^0/0$\|^root/root$'
    [ "$(curl -s -o /dev/null -w '%{http_code}' "$URL/nothing")" = 404 ]
    # No key header: refused before the body is read
    [ "$(curl -s -o /dev/null -w '%{http_code}' --data-binary @"$T/boot.sh" "$URL/report")" = 403 ]
}

@test "web: no token, no cookie or no CSRF value means no access" {
    [ "$(stat -c %a "$T/state/admin.token")" = 600 ]
    [ "$(curl -s -o /dev/null -w '%{http_code}' "$ADMIN/api/state")" = 401 ]
    [ "$(curl -s -o "$T/page" -w '%{http_code}' -d token=wrong "$ADMIN/login")" = 401 ]
    grep -q 'data-view="login" data-csrf=""' "$T/page"
    ! grep -q "$(cat "$T/state/admin.token")" "$T/page"
    curl -s -D "$T/head" -o /dev/null "$ADMIN/"
    grep -qi "^content-security-policy: default-src 'none'; script-src 'nonce-" "$T/head"

    "${A[@]}" --enrol="$URL"
    _login
    [ -n "$CSRF" ]
    # The cookie alone (a request another site could trigger) changes nothing
    run _api approve "{\"code\": \"$(_code)\", \"name\": \"web1\"}" ""
    [[ "$output" == *403 ]]
    "${A[@]}" --agent-list | grep -q '^pending'
    grep -q 'sign-in.*failed' "$T/state/audit.log"
}

@test "web: approve, rename, scan now, revoke; each one is in the audit log" {
    "${A[@]}" --enrol="$URL"
    code=$(_code)
    _login
    curl -s -b "$T/jar" "$ADMIN/api/state" | grep -q "\"state\": \"pending\", \"code\": \"$code\""

    # Only the expected shapes are passed on
    run _api approve "{\"code\": \"$code\", \"name\": \"../etc\"}"
    [[ "$output" == *400 ]]
    run _api approve "{\"code\": \"$code\", \"name\": \"web1 --agent-revoke=x\"}"
    [[ "$output" == *400 ]]
    run _api approve "{\"code\": \"$code\", \"name\": \"web1\"}"
    [[ "$output" == *'"ok": true'*200 ]]
    _host_run || true
    [ -n "$(ls "$T"/hist/web1/*.json)" ]

    run _api rename '{"name": "web1", "new": "shop"}'
    [[ "$output" == *200 ]]
    grep -qx '  "hostname": "shop",' "$T"/hist/shop/*.json
    [ ! -e "$T/hist/web1" ]

    # Scan now: the host's next signed poll gets "scan", exactly once
    printf 'poll %s\n' "$(date +%s)" > "$T/poll"
    [ "$(_post "$T/poll" "" poll)" = idle200 ]
    run _api scan '{"name": "shop"}'
    [[ "$output" == *200 ]]
    curl -s -b "$T/jar" "$ADMIN/api/state" | grep -q '"name": "shop".*"scan": true'
    [ "$(_post "$T/poll" "" poll)" = scan200 ]
    [ "$(_post "$T/poll" "" poll)" = idle200 ]
    # A poll signed long ago, or by a stranger, gets nothing
    echo "poll 1000000000" > "$T/old"
    [ "$(_post "$T/old" "" poll)" = 400 ]
    openssl ecparam -genkey -name prime256v1 -noout -out "$T/other.pem"
    [ "$(_post "$T/poll" "$T/other.pem" poll)" = 403 ]

    run _api revoke '{"name": "shop"}'
    [[ "$output" == *200 ]]
    [ "$(_post "$T/poll" "" poll)" = 403 ]
    [ -d "$T/hist/shop" ]
    for a in approve rename scan revoke; do grep -q "	$a	.*	ok$" "$T/state/audit.log"; done
}
