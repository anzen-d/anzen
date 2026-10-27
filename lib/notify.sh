#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 The Anzen contributors
# lib/notify.sh — Post-audit notification hook

# Called with: _notify <fail_count> <score> [new_fail_messages] [host]
# Respects: NOTIFY_CMD, NOTIFY_NTFY_URL (NOTIFY_ON is applied by notify_run)
_notify() {
    local fails=$1 score=$2 new=${3:-} host=${4:-$(_hostname)}
    local n_new=0
    [ -n "$new" ] && n_new=$(grep -c . <<< "$new")

    # Generic command hook — ANZEN_FAILS, ANZEN_SCORE, ANZEN_NEW_FAILS (count)
    # and ANZEN_NEW_FAIL_LIST (newline-separated messages) are available
    if [ -n "${NOTIFY_CMD:-}" ]; then
        ANZEN_FAILS="$fails" ANZEN_SCORE="$score" ANZEN_NEW_FAILS="$n_new" \
            ANZEN_NEW_FAIL_LIST="$new" bash -c "$NOTIFY_CMD" || true
        return
    fi

    # ntfy push notification
    if [ -n "${NOTIFY_NTFY_URL:-}" ]; then
        local title priority body
        body="Score: ${score}% | $(date -u +%Y-%m-%dT%H:%M:%SZ)"
        if [ "$n_new" -gt 0 ]; then
            title="Anzen: $n_new new FAIL(s) on $host"
            priority="high"
            body+=$'\n'"$(head -5 <<< "$new" | sed 's/^/+ /')"
            [ "$n_new" -gt 5 ] && body+=$'\n'"… and $((n_new - 5)) more"
        elif [ "$fails" -gt 0 ]; then
            title="Anzen: $fails FAIL(s) on $host"
            priority="high"
        else
            title="Anzen: Clean audit on $host"
            priority="default"
        fi
        local auth=()
        [ -n "${NOTIFY_NTFY_TOKEN:-}" ] && auth=(-H "Authorization: Bearer ${NOTIFY_NTFY_TOKEN}")
        curl -sfS -X POST "${NOTIFY_NTFY_URL}" "${auth[@]}" \
            -H "Title: ${title}" \
            -H "Priority: ${priority}" \
            --data-raw "$body" \
            >/dev/null 2>&1 || true
    fi
}

# notify_run FAILS SCORE NEW_FAILS [HOST] — apply NOTIFY_ON, then _notify
notify_run() {
    [ -n "${NOTIFY_CMD:-}" ] || [ -n "${NOTIFY_NTFY_URL:-}" ] || return 0
    local on="${NOTIFY_ON:-always}"
    [ "${NOTIFY_ON_FAIL_ONLY:-false}" = "true" ] && on=fail
    case "$on" in
        always)     _notify "$@" ;;
        fail)       [ "$1" -gt 0 ] && _notify "$@" ;;
        regression) [ -n "$3" ] && _notify "$@" ;;
        *)          echo "[WARN] Unknown NOTIFY_ON='$on' (always|fail|regression)" >&2 ;;
    esac
    return 0
}

# heartbeat — fetch HEARTBEAT_URL (dead-man switch: Uptime Kuma push, healthchecks.io, ...)
heartbeat() {
    [ -n "${HEARTBEAT_URL:-}" ] || return 0
    curl -fsS -m 10 -o /dev/null "$HEARTBEAT_URL" || echo "[WARN] Heartbeat to HEARTBEAT_URL failed" >&2
}
