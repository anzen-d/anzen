#!/bin/bash
# lib/http_probe.sh — HTTP probing shared by the pentest modules: status/body
# fetches, a catch-all baseline (SPAs answer 200 for every path) and a secret
# scanner that decides whether a 200 response really exposes something.
#
# _CURL_RESOLVE_FLAGS may be set by pentest_external (--resolve-to).
_CURL_RESOLVE_FLAGS="${_CURL_RESOLVE_FLAGS:-}"

_http_code() {
    local url=$1
    # shellcheck disable=SC2086
    curl -sk -o /dev/null -w '%{http_code}' \
        --max-time 6 --connect-timeout 4 ${_CURL_RESOLVE_FLAGS} "$url" 2>/dev/null
}

_http_body_size() {
    local url=$1
    # shellcheck disable=SC2086
    curl -sk -o /dev/null -w '%{size_download}' \
        --max-time 6 --connect-timeout 4 ${_CURL_RESOLVE_FLAGS} "$url" 2>/dev/null
}

_http_body() {
    local url=$1
    # shellcheck disable=SC2086
    curl -sk --max-time 6 --connect-timeout 4 ${_CURL_RESOLVE_FLAGS} "$url" 2>/dev/null
}

# Establish a catch-all baseline for the web app.
# Sets globals: _CATCHALL=true/false  _CANARY_SIZE=N  _CANARY_CODE=NNN
_establish_baseline() {
    local base=$1
    local rand
    rand=$(cat /proc/sys/kernel/random/uuid 2>/dev/null || printf '%s' "$RANDOM$RANDOM$RANDOM")
    local canary_url="${base}/anzen-canary-${rand:0:16}"
    _CANARY_CODE=$(_http_code "$canary_url")
    _CANARY_SIZE=$(_http_body_size "$canary_url")
    if [ "$_CANARY_CODE" = "200" ]; then
        _CATCHALL=true
        info "Catch-all route detected (canary → HTTP 200, ${_CANARY_SIZE}B) — enabling content verification"
    else
        _CATCHALL=false
    fi
}

# Scan body for actual secret content.
# Returns 0 (found secrets) and prints matched patterns to stdout.
# Returns 1 if no secrets found.
_scan_secrets() {
    local body=$1
    local found=false

    # Each rule: "label" "pattern"
    local -a rules=(
        # Private keys
        "Private key"                    "BEGIN (RSA|EC|DSA|OPENSSH|PGP) PRIVATE KEY"
        # Credentials in key=value form (env files, config files)
        "Password field"                 "(password|passwd|pwd|secret|token|api[_-]?key|auth[_-]?key|access[_-]?key|client[_-]?secret)[[:space:]]*[=:][[:space:]]*['\"]?[^'\"\$\{][^'\"]{4,}"
        # DB connection strings
        "DB connection string"           "(mysql|postgres|postgresql|mongodb|redis|amqp|jdbc)://[^[:space:]'\"]+"
        # AWS credentials
        "AWS access key"                 "AKIA[0-9A-Z]{16}"
        "AWS secret"                     "aws[_-]?secret[_-]?access[_-]?key[[:space:]]*=[[:space:]]*[A-Za-z0-9/+]{40}"
        # Generic high-entropy tokens (bearer, basic auth)
        "Bearer token"                   "Bearer [A-Za-z0-9+/=_-]{20,}"
        "Basic auth header"              "Authorization:[[:space:]]*Basic [A-Za-z0-9+/=]{10,}"
        # JWT
        "JWT token"                      "eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"
        # Known secret variable names with non-empty values
        "Secret variable"                "(SECRET_KEY|DJANGO_SECRET|APP_SECRET|ENCRYPTION_KEY|SIGNING_KEY|PRIVATE_KEY|MASTER_KEY)[[:space:]]*=[[:space:]]*[^\$\{][^[:space:]]{6,}"
        # htpasswd hash formats
        "htpasswd hash"                  "^[^:]{1,64}:(\\\$apr1\\\$|\\\$2[ayb]\\\$|\\\{SHA\\\}|[a-zA-Z0-9./]{13}$)"
        # PHP config patterns
        "PHP DB credential"              "define\(['\"]DB_(PASSWORD|USER|HOST|NAME)['\"]"
        # Git credential helpers with embedded creds
        "Git embedded credential"        "https?://[^:@[:space:]]+:[^@[:space:]]+@"
        # Spring Boot actuator sensitive data
        "Actuator secret value"          "\"value\":\"[^*\"\$\{][^\"]{4,}\""
        # Slack/GitHub/Generic tokens
        "Slack token"                    "xox[baprs]-[0-9A-Za-z-]{10,}"
        "GitHub token"                   "gh[pousr]_[A-Za-z0-9]{36,}"
        "Generic secret token"           "(secret|token)['\"]?[[:space:]]*:[[:space:]]*['\"][A-Za-z0-9+/=_-]{16,}['\"]"
    )

    local i=0
    while [ $i -lt "${#rules[@]}" ]; do
        local label="${rules[$i]}"
        local pattern="${rules[$((i+1))]}"
        local match
        match=$(echo "$body" | grep -oiE -- "$pattern" 2>/dev/null | head -1 | sed 's/./&/;s/.\{60\}.*/.../')
        if [ -n "$match" ]; then
            echo "$label: $match"
            found=true
        fi
        (( i += 2 ))
    done

    $found && return 0 || return 1
}

# Check a response against the baseline, then secret-scan any unique response.
# Returns:
#   0 = real hit with secrets  (FAIL)
#   2 = unique response, no secrets found  (WARN — distinct but benign)
#   1 = catch-all false positive  (skip)
# Sets global _HIT_SECRETS with matched patterns (space-separated lines).
_HIT_SECRETS=""
_classify_hit() {
    local _path=$1 body=$2 size=$3

    # Gate 1: no catch-all → treat every 200 as noteworthy
    if [ "$_CATCHALL" != "true" ]; then
        _HIT_SECRETS=$(_scan_secrets "$body")
        [ -n "$_HIT_SECRETS" ] && return 0 || return 2
    fi

    # Gate 2: size gate — same size as canary → almost certainly catch-all
    if [ -n "$_CANARY_SIZE" ] && [ "$_CANARY_SIZE" -gt 0 ]; then
        local delta=$(( size - _CANARY_SIZE ))
        delta=${delta#-}
        local threshold=$(( _CANARY_SIZE / 20 + 50 ))
        if [ "$delta" -lt "$threshold" ]; then
            return 1  # indistinguishable from catch-all
        fi
    fi

    # Gate 3: unique response — run secret scanner to decide severity
    _HIT_SECRETS=$(_scan_secrets "$body")
    [ -n "$_HIT_SECRETS" ] && return 0 || return 2
}

# _is_risky_service PORT — false only when an HTTP datastore port provably
# serves something else; other ports cannot be fingerprinted this cheaply
_is_risky_service() {
    local body
    case $1 in 9200|5984) ;; *) return 0 ;; esac
    body=$(curl -s --max-time 3 "http://127.0.0.1:$1/" 2>/dev/null)
    [ -z "$body" ] && body=$(curl -sk --max-time 3 "https://127.0.0.1:$1/" 2>/dev/null)
    [ -z "$body" ] && return 0
    case $1 in
        9200) [[ "$body" == *'"cluster_name"'* || "$body" == *"security_exception"* ]] ;;
        5984) [[ "$body" == *'"couchdb"'* || "$body" == *"unauthorized"* ]] ;;
    esac
}
