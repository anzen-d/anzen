#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 The Anzen contributors
# lib/agent.sh — Push agent: hosts upload their own report to a controller
#
# Host:       anzen --enrol=URL makes a key pair in AGENT_DIR and sends the
#             public key. After that every full run uploads its JSON report,
#             signed with the private key. Outbound HTTPS only.
# Controller: anzen --receiver takes the uploads (lib/receiver.py, which only
#             moves bytes and calls back into the functions below). A key
#             counts only after the admin has run --agent-approve=CODE with the
#             code the host printed.
#
# The controller never sends a command to a host. What a host sends is checked
# three times before it is stored: approved key, signature, exact report shape.

# Settings (defaults in lib/config.sh): AGENT_DIR, AGENT_STATE_DIR,
# AGENT_PUBLIC_URL, AGENT_LISTEN, AGENT_ADMIN_LISTEN

# _agent_url_ok URL — https only; plain http is for a local test receiver
_agent_url_ok() {
    [[ $1 =~ ^https://[A-Za-z0-9.-]+(:[0-9]+)?(/[A-Za-z0-9._/-]*)?$ ]] ||
        [[ $1 =~ ^http://(127\.0\.0\.1|localhost)(:[0-9]+)?(/[A-Za-z0-9._/-]*)?$ ]]
}

# _agent_key_id PUBKEY_PEM — SHA-256 of the DER public key (64 hex characters)
_agent_key_id() {
    ( set -o pipefail
      openssl pkey -pubin -in "$1" -outform DER 2>/dev/null | openssl dgst -sha256 -r | cut -d' ' -f1 )
}

# _agent_code ID — what the admin compares: host screen against --agent-list
_agent_code() { echo "${1:0:4}-${1:4:4}-${1:8:4}"; }

# ── Host side ────────────────────────────────────────────────────────────────

# agent_enrolled — this host has a key and a controller URL
agent_enrolled() { [ -s "$AGENT_DIR/key.pem" ] && [ -s "$AGENT_DIR/url" ]; }

# agent_enrol URL — make the key pair (kept when it exists), send the public key
agent_enrol() {
    local url=${1%/} d=$AGENT_DIR id reply c
    if ! _agent_url_ok "$url"; then
        echo "ERROR: --enrol needs an https:// URL (plain http only for localhost)" >&2
        return 1
    fi
    for c in openssl curl; do
        command -v "$c" >/dev/null || { echo "ERROR: --enrol needs $c" >&2; return 1; }
    done
    (umask 077; mkdir -p "$d") || { echo "ERROR: cannot create $d (run as root)" >&2; return 1; }
    if [ ! -s "$d/key.pem" ]; then
        (umask 077; openssl ecparam -genkey -name prime256v1 -noout -out "$d/key.pem") 2>/dev/null ||
            { echo "ERROR: could not create a key in $d" >&2; return 1; }
    fi
    openssl pkey -in "$d/key.pem" -pubout -out "$d/pub.pem" 2>/dev/null && id=$(_agent_key_id "$d/pub.pem") ||
        { echo "ERROR: $d/key.pem is not a usable key" >&2; return 1; }
    reply=$(curl -fsS -m 30 -H "X-Anzen-Name: $(_hostname | tr -cd 'A-Za-z0-9._-')" \
                 --data-binary @"$d/pub.pem" "$url/enrol") ||
        { echo "ERROR: enrolment request to $url failed" >&2; return 1; }
    printf '%s\n' "$url" > "$d/url"
    if [ "$reply" = approved ]; then
        echo "This host is already approved on $url."
    else
        echo "Enrolment sent to $url."
        echo "  Code: $(_agent_code "$id")"
        echo "On the controller, compare the code and approve it:"
        echo "  anzen --agent-list"
        echo "  anzen --agent-approve=$(_agent_code "$id")"
    fi
    echo "Every full run on this host now uploads its report (not with --offline or --check)."
}

# _agent_post PATH FILE — send FILE to the controller, signed with this host's
# key; prints the answer
_agent_post() {
    local d=$AGENT_DIR url id sig
    url=$(head -1 "$d/url" 2>/dev/null)
    _agent_url_ok "$url" || { echo "[WARN] Push agent: bad URL in $d/url" >&2; return 1; }
    id=$(_agent_key_id "$d/pub.pem") || return 1
    sig=$(openssl dgst -sha256 -sign "$d/key.pem" "$2" 2>/dev/null | base64 | tr -d '\n')
    [ -n "$sig" ] || { echo "[WARN] Push agent: could not sign with $d/key.pem" >&2; return 1; }
    curl -fsS -m 120 -H 'Expect:' -H "X-Anzen-Agent: $id" -H "X-Anzen-Signature: $sig" \
         --data-binary @"$2" "$url/$1"
}

# agent_push JSON — upload a report; prints the controller URL
agent_push() {
    _agent_post report "$1" >/dev/null ||
        { echo "[WARN] Push agent: upload failed (not approved yet?)" >&2; return 1; }
    head -1 "$AGENT_DIR/url"
}

# agent_poll — ask the controller whether the admin pressed "Scan now"; when
# so, run a full audit now (which uploads its report). Meant for a cron line
# every few minutes. The answer is one word: the controller cannot name a command
agent_poll() {
    agent_enrolled || { echo "ERROR: this host is not enrolled (--enrol=URL)" >&2; return 1; }
    local body reply
    body=$(umask 077; mktemp) || return 1
    printf 'poll %s\n' "$(date +%s)" > "$body"
    reply=$(_agent_post poll "$body" 2>/dev/null)
    rm -f "$body"
    [ "$reply" = scan ] || return 0
    local -a cmd=(bash "$ANZEN_DIR/anzen.sh" --quiet)
    [ -n "${CONFIG_FILE:-}" ] && cmd+=("--config=$(realpath "$CONFIG_FILE")")
    # Not next to a run that is already going (the weekly one, or the last request)
    if command -v flock >/dev/null; then
        flock -n "$AGENT_DIR/run.lock" "${cmd[@]}"
    else
        "${cmd[@]}"
    fi
}

# ── Controller side ──────────────────────────────────────────────────────────

# agent_enrol_receive PUBKEY_FILE [NAME_HINT] — park a key as pending; prints
# "pending" or "approved". Returns 2 when the pending list is full
agent_enrol_receive() {
    local st=$AGENT_STATE_DIR id name
    [ -f "$1" ] && [ "$(wc -c < "$1")" -le 2048 ] || return 1
    id=$(_agent_key_id "$1") && [[ $id =~ ^[0-9a-f]{64}$ ]] || return 1
    [ -f "$st/approved/$id.pem" ] && { echo approved; return 0; }
    (umask 077; mkdir -p "$st/pending") || return 1
    # Anyone who reaches the receiver can ask: old requests go, the list is capped
    find "$st/pending" -type f -mmin +1440 -delete 2>/dev/null
    if [ ! -f "$st/pending/$id.pem" ]; then
        if [ "$(find "$st/pending" -name '*.pem' | wc -l)" -ge "${AGENT_MAX_PENDING:-20}" ]; then
            echo "ERROR: too many pending enrolments (see --agent-list)" >&2
            return 2
        fi
        # Store what openssl parsed, never the uploaded bytes
        (umask 077; openssl pkey -pubin -in "$1" -pubout -out "$st/pending/$id.pem") 2>/dev/null || return 1
    fi
    name=${2:-}; name=$(printf '%s' "${name%%.*}" | tr -cd 'A-Za-z0-9_-' | cut -c1-40)
    (umask 077; printf '%s\n' "$name" > "$st/pending/$id.name")
    echo pending
}

# agent_list — pending and approved agents
agent_list() {
    local st=$AGENT_STATE_DIR f id
    printf '%-9s %-15s %-24s %s\n' STATE CODE NAME "LAST REPORT"
    for f in "$st"/pending/*.pem "$st"/approved/*.pem; do
        [ -f "$f" ] || continue
        id=$(basename "$f" .pem)
        printf '%-9s %-15s %-24s %s\n' "$(basename "$(dirname "$f")")" "$(_agent_code "$id")" \
            "$(cat "${f%.pem}.name" 2>/dev/null)" "$(cat "${f%.pem}.last" 2>/dev/null || echo -)"
    done
}

# _agent_pending CODE — the one pending key file a code stands for
_agent_pending() {
    local code; code=$(printf '%s' "$1" | tr 'A-F' 'a-f' | tr -cd '0-9a-f')
    if [ "${#code}" -lt 12 ]; then
        echo "ERROR: give the whole code, like 1a2b-3c4d-5e6f" >&2; return 1
    fi
    local -a m=("$AGENT_STATE_DIR/pending/$code"*.pem)
    if [ "${#m[@]}" -ne 1 ] || [ ! -f "${m[0]}" ]; then
        echo "ERROR: no single pending enrolment with code $1 (see --agent-list)" >&2; return 1
    fi
    echo "${m[0]}"
}

# agent_approve CODE[:NAME] — accept a pending key. NAME is the history
# directory and the name on the dashboard; the host cannot change it later
agent_approve() {
    local st=$AGENT_STATE_DIR spec=$1 name="" given=false f id n
    [[ $spec == *:* ]] && { name=${spec#*:}; given=true; }
    f=$(_agent_pending "${spec%%:*}") || return 1
    id=$(basename "$f" .pem)
    $given || name=$(cat "${f%.pem}.name" 2>/dev/null)
    if [[ ! $name =~ ^[A-Za-z0-9_-]{1,40}$ ]]; then
        echo "ERROR: name must be letters, digits, _ or -: --agent-approve=CODE:name" >&2; return 1
    fi
    for n in "$st"/approved/*.name; do
        [ -f "$n" ] && [ "$(cat "$n")" = "$name" ] || continue
        echo "ERROR: another agent is already called '$name' (revoke it or pick another name)" >&2
        return 1
    done
    # A new key must not slip into the history of an existing host by its own word
    if ! $given && [ -n "${HISTORY_DIR:-}" ] && [ -d "$HISTORY_DIR/$name" ]; then
        echo "ERROR: history for '$name' already exists. To continue it: --agent-approve=${spec}:$name" >&2
        return 1
    fi
    (umask 077; mkdir -p "$st/approved") && mv "$f" "$st/approved/$id.pem" || return 1
    (umask 077; printf '%s\n' "$name" > "$st/approved/$id.name")
    rm -f "${f%.pem}.name"
    echo "Approved: $name ($(_agent_code "$id")). Its reports go to ${HISTORY_DIR:-HISTORY_DIR}/$name/"
}

# agent_revoke NAME|CODE — drop an approved agent by name or a pending one by code
agent_revoke() {
    local st=$AGENT_STATE_DIR n f
    for n in "$st"/approved/*.name; do
        [ -f "$n" ] && [ "$(cat "$n")" = "$1" ] || continue
        rm -f "${n%.name}.pem" "${n%.name}.last" "${n%.name}.seen" "${n%.name}.scan" "$n"
        echo "Revoked: $1 (its history stays)"
        return 0
    done
    f=$(_agent_pending "$1" 2>/dev/null) || { echo "ERROR: no agent named '$1' and no pending code $1" >&2; return 1; }
    rm -f "$f" "${f%.pem}.name"
    echo "Removed pending enrolment $1"
}

# agent_report_receive ID SIG_FILE JSON — verify and store one uploaded report.
# Returns 3 for an unknown key or bad signature, 4 for a bad report, 5 when the
# controller cannot store it
agent_report_receive() {
    local st=$AGENT_STATE_DIR id=$1 sig=$2 json=$3 name date last tmp prev new="" nf score
    if [[ ! $id =~ ^[0-9a-f]{64}$ ]] || [ ! -f "$st/approved/$id.pem" ]; then
        echo "ERROR: report from a key that is not approved" >&2; return 3
    fi
    if ! openssl dgst -sha256 -verify "$st/approved/$id.pem" -signature "$sig" "$json" >/dev/null 2>&1; then
        echo "ERROR: bad signature on a report for key $(_agent_code "$id")" >&2; return 3
    fi
    name=$(cat "$st/approved/$id.name" 2>/dev/null)
    [[ $name =~ ^[A-Za-z0-9_-]{1,40}$ ]] || { echo "ERROR: agent $(_agent_code "$id") has no valid name" >&2; return 5; }
    if ! _dashboard_run_obj "$json" 0 >/dev/null; then
        echo "ERROR: $name sent something that is not an anzen report" >&2; return 4
    fi
    date=$(sed -n 's/^  "date": "\(.*\)",\{0,1\}$/\1/p' "$json" | tail -1)
    if [[ ! $date =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$ ]]; then
        echo "ERROR: $name sent a report without a valid date" >&2; return 4
    fi
    # The date is inside the signed report: an old upload cannot be sent again
    last=$(cat "$st/approved/$id.last" 2>/dev/null)
    if [[ ! $date > $last ]]; then
        echo "ERROR: report from $name is not newer than its last one ($last)" >&2; return 4
    fi
    [ -n "${HISTORY_DIR:-}" ] || { echo "ERROR: HISTORY_DIR is not set on the controller" >&2; return 5; }

    # The approved name wins over the hostname the report claims
    tmp=$(umask 077; mktemp) || return 5
    sed 's/^  "hostname": .*/  "hostname": "'"$name"'",/' "$json" > "$tmp"
    prev=$(history_latest "$HISTORY_DIR" "$name")
    [ -n "$prev" ] && new=$(history_new_fails_json "$prev" "$tmp")
    history_store "$HISTORY_DIR" "$name" "$tmp" >/dev/null || { rm -f "$tmp"; return 5; }
    (umask 077; printf '%s\n' "$date" > "$st/approved/$id.last")
    nf=$(sed -n 's/^  "summary": {"fail": \([0-9]*\),.*/\1/p' "$tmp" | head -1)
    score=$(sed -n 's/.*"score": \([0-9]*\)}.*/\1/p' "$tmp" | head -1)
    rm -f "$tmp"
    notify_run "${nf:-0}" "${score:-0}" "$new" "$name"
    [ -n "${DASHBOARD_FILE:-}" ] && generate_dashboard "$HISTORY_DIR" "$DASHBOARD_FILE"
    return 0
}

# agent_poll_receive ID SIG_FILE BODY — a host's signed "poll <unix time>";
# prints "scan" (once per request) or "idle". Returns 3 / 4 like a report
agent_poll_receive() {
    local st=$AGENT_STATE_DIR id=$1 t now
    if [[ ! $id =~ ^[0-9a-f]{64}$ ]] || [ ! -f "$st/approved/$id.pem" ]; then
        return 3
    fi
    openssl dgst -sha256 -verify "$st/approved/$id.pem" -signature "$2" "$3" >/dev/null 2>&1 || return 3
    t=$(head -c 64 "$3")
    [[ $t =~ ^poll\ ([0-9]{9,11})$ ]] || return 4
    t=${BASH_REMATCH[1]}; now=$(date +%s)
    # Signed time must be current: a recorded poll is useless five minutes later
    [ "$((now - t))" -le 300 ] && [ "$((t - now))" -le 300 ] || return 4
    (umask 077; date -u +%Y-%m-%dT%H:%M:%SZ > "$st/approved/$id.seen")
    if [ -f "$st/approved/$id.scan" ]; then
        rm -f "$st/approved/$id.scan"
        echo scan
    else
        echo idle
    fi
}

# _agent_by_name NAME — path of the approved agent's .name file
_agent_by_name() {
    local n
    for n in "$AGENT_STATE_DIR"/approved/*.name; do
        [ -f "$n" ] && [ "$(cat "$n")" = "$1" ] && { echo "$n"; return 0; }
    done
    return 1
}

# agent_scan_request NAME — the host runs a full audit at its next poll
agent_scan_request() {
    local n; n=$(_agent_by_name "$1") || { echo "ERROR: no agent named '$1'" >&2; return 1; }
    (umask 077; : > "${n%.name}.scan")
    echo "Scan requested for $1 (starts at the host's next poll)"
}

# agent_rename OLD NEW — new name for an approved agent and its history
agent_rename() {
    local n new=$2 f
    n=$(_agent_by_name "$1") || { echo "ERROR: no agent named '$1'" >&2; return 1; }
    [[ $new =~ ^[A-Za-z0-9_-]{1,40}$ ]] || { echo "ERROR: name must be letters, digits, _ or -" >&2; return 1; }
    if _agent_by_name "$new" >/dev/null || { [ -n "${HISTORY_DIR:-}" ] && [ -e "$HISTORY_DIR/$new" ]; }; then
        echo "ERROR: the name '$new' is taken" >&2; return 1
    fi
    if [ -n "${HISTORY_DIR:-}" ] && [ -d "$HISTORY_DIR/$1" ] && [ ! -L "$HISTORY_DIR/$1" ]; then
        mv "$HISTORY_DIR/$1" "$HISTORY_DIR/$new" || return 1
        for f in "$HISTORY_DIR/$new"/*.json; do
            [ -f "$f" ] && sed -i 's/^  "hostname": .*/  "hostname": "'"$new"'",/' "$f"
        done
        [ -n "${DASHBOARD_FILE:-}" ] && generate_dashboard "$HISTORY_DIR" "$DASHBOARD_FILE"
    fi
    printf '%s\n' "$new" > "$n"
    echo "Renamed: $1 is now $new"
}

# agent_state — one line per agent for the web controller:
# STATE CODE NAME LAST_REPORT LAST_POLL SCAN_PENDING SCORE FAILS WARNS (tab-separated;
# pending agents carry the request time as LAST_REPORT)
agent_state() {
    local st=$AGENT_STATE_DIR f b id name latest sum
    for f in "$st"/pending/*.pem; do
        [ -f "$f" ] || continue
        id=$(basename "$f" .pem)
        printf 'pending\t%s\t%s\t%s\t\t0\t\t\t\n' "$(_agent_code "$id")" "$(cat "${f%.pem}.name" 2>/dev/null)" \
            "$(date -u -r "$f" +%Y-%m-%dT%H:%M:%SZ)"
    done
    for f in "$st"/approved/*.pem; do
        [ -f "$f" ] || continue
        b=${f%.pem}; id=$(basename "$b"); name=$(cat "$b.name" 2>/dev/null); sum=$'\t\t'
        latest=$( [ -n "${HISTORY_DIR:-}" ] && history_latest "$HISTORY_DIR" "$name" )
        [ -n "$latest" ] && sum=$(sed -n 's/^  "summary": {"fail": \([0-9]*\), "warn": \([0-9]*\),.*"score": \([0-9]*\)},\{0,1\}$/\3\t\1\t\2/p' "$latest" | head -1)
        printf 'approved\t%s\t%s\t%s\t%s\t%s\t%s\n' "$(_agent_code "$id")" "$name" "$(cat "$b.last" 2>/dev/null)" \
            "$(cat "$b.seen" 2>/dev/null)" "$( [ -f "$b.scan" ] && echo 1 || echo 0 )" "${sum:-$'\t\t'}"
    done
}

# agent_tarball — this anzen as a tar.gz for new hosts, all files owned by root
agent_tarball() {
    tar -czf - -C "$ANZEN_DIR" --owner=0 --group=0 --exclude=./reports --exclude=./anzen.conf \
        --exclude=./anzen.accept --exclude=./.git --exclude=./tests .
}

# agent_enrol_script — the script behind "curl -fsSL URL/enrol | sudo sh":
# install this controller's anzen, enrol, schedule a weekly run
agent_enrol_script() {
    local url=${AGENT_PUBLIC_URL%/}
    _agent_url_ok "$url" || { echo "ERROR: AGENT_PUBLIC_URL is not set to an https:// URL" >&2; return 1; }
    cat <<EOF
#!/bin/sh
# anzen push agent: install from $url, enrol, schedule
set -eu
# All in one function: a download cut short runs nothing
main() {
    [ "\$(id -u)" -eq 0 ] || { echo "Run as root: curl -fsSL $url/enrol | sudo sh" >&2; exit 1; }
    for c in bash curl tar openssl; do
        command -v "\$c" >/dev/null || { echo "anzen agent needs \$c" >&2; exit 1; }
    done
    d=/usr/local/lib/anzen
    mkdir -p "\$d"
    curl -fsSL "$url/anzen.tar.gz" | tar -xzof - -C "\$d"
    printf '#!/bin/bash\nexec bash %s/anzen.sh "\$@"\n' "\$d" > /usr/local/bin/anzen
    chmod 755 /usr/local/bin/anzen
    bash "\$d/anzen.sh" --enrol="$url"
    crontab -l 2>/dev/null | grep -q '# anzen:local' || bash "\$d/anzen.sh" --schedule=weekly ||
        echo "No cron entry made: schedule 'anzen --quiet' yourself" >&2
    # "Scan now" on the controller reaches this host at its next poll
    { crontab -l 2>/dev/null | grep -v '# anzen:poll' || true
      echo "*/5 * * * * \$d/anzen.sh --agent-poll >/dev/null 2>&1 # anzen:poll"; } | crontab - ||
        echo "No poll entry made: 'Scan now' will not reach this host" >&2
}
main
EOF
}

# agent_receiver — start the HTTP receiver in the foreground
agent_receiver() {
    command -v python3 >/dev/null || { echo "ERROR: --receiver needs python3" >&2; return 1; }
    [ -n "${HISTORY_DIR:-}" ] || { echo "ERROR: --receiver needs HISTORY_DIR" >&2; return 1; }
    if ! _agent_url_ok "$AGENT_PUBLIC_URL"; then
        echo "ERROR: set AGENT_PUBLIC_URL to the https:// URL the hosts use to reach this receiver" >&2
        return 1
    fi
    [[ $AGENT_LISTEN =~ ^[0-9A-Za-z.:-]+:[0-9]+$ ]] || { echo "ERROR: AGENT_LISTEN must be ADDRESS:PORT" >&2; return 1; }
    echo "anzen receiver on $AGENT_LISTEN for $AGENT_PUBLIC_URL (plain HTTP: put a TLS proxy in front)"
    echo "New host: curl -fsSL ${AGENT_PUBLIC_URL%/}/enrol | sudo sh"
    # The web controller has one secret: who holds it may approve hosts
    local token="$AGENT_STATE_DIR/admin.token"
    if [ -n "$AGENT_ADMIN_LISTEN" ]; then
        [[ $AGENT_ADMIN_LISTEN =~ ^[0-9A-Za-z.:-]+:[0-9]+$ ]] ||
            { echo "ERROR: AGENT_ADMIN_LISTEN must be ADDRESS:PORT (empty turns the web controller off)" >&2; return 1; }
        (umask 077; mkdir -p "$AGENT_STATE_DIR") || return 1
        [ -s "$token" ] || (umask 077; openssl rand -hex 32 > "$token") ||
            { echo "ERROR: could not write $token" >&2; return 1; }
        chmod 600 "$token"
        echo "Web controller on $AGENT_ADMIN_LISTEN, sign in with the token in $token"
    fi
    ANZEN_SH="$ANZEN_DIR/anzen.sh" ANZEN_CONF="${CONFIG_FILE:+$(realpath "$CONFIG_FILE")}" \
    AGENT_STATE_DIR="$AGENT_STATE_DIR" AGENT_LISTEN="$AGENT_LISTEN" \
    AGENT_ADMIN_LISTEN="$AGENT_ADMIN_LISTEN" AGENT_ADMIN_TOKEN_FILE="$token" \
    AGENT_PUBLIC_URL="${AGENT_PUBLIC_URL%/}" \
        exec python3 "$ANZEN_DIR/lib/receiver.py"
}
