#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 The Anzen contributors
# Anzen (安全) — Linux Security Audit Tool
# Usage: ./anzen.sh [OPTIONS]

set -uo pipefail

ANZEN_VERSION="0.11.1"
ANZEN_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPORT_DIR="$ANZEN_DIR/reports"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# ── Argument parsing ──────────────────────────────────────────────────────────
GENERATE_HTML=false
GENERATE_TXT=false
GENERATE_JSON=false
GENERATE_SARIF=false
GENERATE_REMEDIATE=false
PARALLEL=false
BASELINE=false
DIFF=false
STRICT=false
OUTPUT_FILE=""
CONFIG_FILE=""
REMOTE_HOST=""
SCHEDULE=""
CHECKS=()
QUIET=false
NO_COLOR=false
PENTEST_TARGET=""
PENTEST_WAN=false
PENTEST_RESOLVE_IP=""
PENTEST_REMOTE_HOST=""
HISTORY_ARG=""
DASHBOARD_ONLY=""

for arg in "$@"; do
    case $arg in
        --html)          GENERATE_HTML=true ;;
        --txt)           GENERATE_TXT=true ;;
        --json)          GENERATE_JSON=true ;;
        --sarif)         GENERATE_SARIF=true ;;
        --remediate)     GENERATE_REMEDIATE=true ;;
        --parallel|-p)   PARALLEL=true ;;
        --baseline)      BASELINE=true ;;
        --diff)          DIFF=true ;;
        --strict)        STRICT=true ;;
        --quiet|-q)      QUIET=true ;;
        --no-color)      NO_COLOR=true ;;
        --version|-v)    echo "anzen $ANZEN_VERSION"; exit 0 ;;
        --output=*)      OUTPUT_FILE="${arg#*=}" ;;
        --config=*)      CONFIG_FILE="${arg#*=}" ;;
        --check=*)       CHECKS+=("${arg#*=}") ;;
        --remote=*)      REMOTE_HOST="${arg#*=}" ;;
        --target=*)       PENTEST_TARGET="${arg#*=}" ;;
        --wan)            PENTEST_WAN=true ;;
        --resolve-to=*)   PENTEST_RESOLVE_IP="${arg#*=}" ;;
        --remote-pentest=*) PENTEST_REMOTE_HOST="${arg#*=}" ;;
        --schedule=*)    SCHEDULE="${arg#*=}" ;;
        --history=*)     HISTORY_ARG="${arg#*=}" ;;
        --dashboard=*)   DASHBOARD_ONLY="${arg#*=}" ;;
        --help|-h)
            cat <<EOF
Anzen $ANZEN_VERSION — Linux Security Audit Tool

Usage: $0 [OPTIONS]

Output:
  --html               HTML report (reports/anzen_TIMESTAMP.html)
  --txt                Plain text report (reports/anzen_TIMESTAMP.txt)
  --json               JSON report (reports/anzen_TIMESTAMP.json)
  --sarif              SARIF 2.1.0 report for GitHub/GitLab code scanning
  --remediate          Generate remediate.sh from current findings
  --output=FILE        Override output path; with several formats, the extension
                       is replaced per format (out.html, out.txt, out.json, ...)

Filtering:
  --check=MODULE       Run only specific module(s) — repeatable
  --quiet, -q          Suppress INFO lines (show FAIL/WARN/OK only)
  --no-color           Disable ANSI colour output
  --strict             Exit non-zero on WARN in addition to FAIL

Modules:
  system users ssh network network2 packages files secrets
  systemd_hardening tls compiler path_check modules
  services docker_security images logins kernel auditd cve truststore
  pentest              Active local self-pentest (ports, banners, HTTP)
  pentest_external     Active external endpoint pentest (requires --target)

Baseline & Diff:
  --baseline           Save current run as baseline (reports/.baseline.json)
  --diff               Compare to baseline — exits 2 on regressions

Advanced:
  --config=FILE        Load config from FILE instead of anzen.conf
  --parallel, -p       Run check modules in parallel
  --remote=HOSTS       Audit remote host(s) over SSH: [user@]host[,[user@]host...];
                       results go to HISTORY_DIR/<host>/ like local runs
  --target=HOST/URL    External endpoint to pentest (own systems only)
  --wan                Also scan WAN/public IP for internet-exposed ports
  --resolve-to=IP      Force all HTTP + port scan to this IP (simulates internet view)
  --remote-pentest=USER@HOST  Run the pentest module from a remote host via SSH
  --schedule=FREQ      Install cron job: daily|weekly|monthly (append :HH:MM for custom time)

History & dashboard:
  --history=DIR        Save this run to DIR/<host>/ (default: HISTORY_DIR in anzen.conf)
  --dashboard=FILE     Build a static HTML dashboard from the history dir and exit
  --version, -v        Print version and exit

Examples:
  ./anzen.sh --html --txt
  ./anzen.sh --html --remediate
  ./anzen.sh --check=ssh --check=kernel --quiet
  ./anzen.sh --json --sarif --diff
  ./anzen.sh --remote=root@10.0.0.5 --html --output=/tmp/remote.html
  ./anzen.sh --schedule=daily:02:30
  ./anzen.sh --strict --json
  ./anzen.sh --check=pentest
  ./anzen.sh --check=pentest_external --target=https://mysite.example.com
EOF
            exit 0
            ;;
        *)
            echo "Unknown option: $arg  (try --help)" >&2
            exit 1
            ;;
    esac
done

export QUIET NO_COLOR PENTEST_TARGET PENTEST_WAN PENTEST_RESOLVE_IP

ALL_MODULES=(system users ssh network network2 packages files secrets
             systemd_hardening tls compiler path_check modules
             services docker_security images logins kernel auditd cve truststore
             pentest pentest_external)


# ── Shared utilities (defines _safe_source_config) ───────────────────────────
source "$ANZEN_DIR/lib/utils.sh"

# ── Remote pentest mode ───────────────────────────────────────────────────────
# Runs only pentest_external from a remote SSH host — true internet perspective.
if [ -n "$PENTEST_REMOTE_HOST" ]; then
    if [ -z "$PENTEST_TARGET" ]; then
        echo "ERROR: --remote-pentest requires --target=HOST" >&2; exit 1
    fi
    echo "Pushing anzen to $PENTEST_REMOTE_HOST for internet-perspective pentest..."
    RPEN_TMPDIR=$(ssh "$PENTEST_REMOTE_HOST" "mktemp -d /tmp/anzen.XXXXXX" 2>/dev/null)
    if [ -z "$RPEN_TMPDIR" ]; then
        echo "ERROR: could not create temp dir on $PENTEST_REMOTE_HOST" >&2; exit 1
    fi
    tar -czf - -C "$ANZEN_DIR" . | ssh "$PENTEST_REMOTE_HOST" "tar -xzf - -C $RPEN_TMPDIR"
    # Build args: only pentest_external + target, strip remote-pentest flag
    RPEN_ARGS=("--check=pentest_external" "--target=${PENTEST_TARGET}")
    [ -n "$OUTPUT_FILE" ] && RPEN_ARGS+=("--output=$OUTPUT_FILE")
    $GENERATE_HTML  && RPEN_ARGS+=("--html")
    $GENERATE_JSON  && RPEN_ARGS+=("--json")
    $GENERATE_TXT   && RPEN_ARGS+=("--txt")
    $QUIET          && RPEN_ARGS+=("--quiet")
    echo "Running pentest from $PENTEST_REMOTE_HOST → $PENTEST_TARGET ..."
    ssh "$PENTEST_REMOTE_HOST" "bash $RPEN_TMPDIR/anzen.sh ${RPEN_ARGS[*]}"
    ssh "$PENTEST_REMOTE_HOST" "rm -rf $RPEN_TMPDIR"
    exit $?
fi

# ── Schedule mode ─────────────────────────────────────────────────────────────
if [ -n "$SCHEDULE" ]; then
    SCHED_FREQ="${SCHEDULE%%:*}"
    SCHED_TIME="${SCHEDULE#*:}"
    if [[ "$SCHED_TIME" != "$SCHED_FREQ" ]] && [[ "$SCHED_TIME" =~ ^([0-9]{1,2}):([0-9]{2})$ ]]; then
        CRON_HOUR="${BASH_REMATCH[1]}"
        CRON_MIN="${BASH_REMATCH[2]}"
    else
        CRON_HOUR=6; CRON_MIN=0
    fi
    case "$SCHED_FREQ" in
        daily)   CRON_TIME="$CRON_MIN $CRON_HOUR * * *" ;;
        weekly)  CRON_TIME="$CRON_MIN $CRON_HOUR * * 1" ;;
        monthly) CRON_TIME="$CRON_MIN $CRON_HOUR 1 * *" ;;
        *)       echo "Invalid schedule: $SCHEDULE (use daily|weekly|monthly, optionally :HH:MM)" >&2; exit 1 ;;
    esac
    _cfg=""
    [ -n "$CONFIG_FILE" ] && _cfg=" --config=$(printf '%q' "$(realpath "$CONFIG_FILE")")"
    [ -n "$HISTORY_ARG" ] && _cfg+=" --history=$(printf '%q' "$(realpath -m "$HISTORY_ARG")")"
    $PARALLEL && _cfg+=" --parallel"
    [ -n "$REMOTE_HOST" ] && _cfg+=" --remote=$(printf '%q' "$REMOTE_HOST")"
    # One entry per target set: the local audit and each fleet keep their own line
    _mark="# anzen:${REMOTE_HOST:-local}"
    CRON_CMD="$CRON_TIME $ANZEN_DIR/anzen.sh --quiet --txt --json$_cfg 2>&1 | logger -t anzen $_mark"
    # Replace the entry with the same marker; for the local audit also drop a
    # legacy entry from before markers existed (anzen.sh, no "# anzen:" tag)
    ( crontab -l 2>/dev/null | awk -v mark="$_mark" -v is_local="${REMOTE_HOST:+0}" '
          index($0, mark) { next }
          is_local != "0" && /anzen\.sh/ && !/# anzen:/ { next }
          { print }'
      echo "$CRON_CMD" ) | crontab -
    echo "Scheduled ($SCHEDULE): $CRON_CMD"
    exit 0
fi

# ── Load config ───────────────────────────────────────────────────────────────
if [ -n "$CONFIG_FILE" ]; then
    if [ -f "$CONFIG_FILE" ]; then
        _safe_source_config "$CONFIG_FILE" || exit 1
    else
        echo "Config not found: $CONFIG_FILE" >&2; exit 1
    fi
fi
source "$ANZEN_DIR/lib/config.sh"

# ── Privilege check ───────────────────────────────────────────────────────────
if [ "$EUID" -ne 0 ] && ! sudo -n true 2>/dev/null; then
    echo "[WARN] Not running as root and no passwordless sudo — some checks may be incomplete."
fi

# ── Findings temp file ────────────────────────────────────────────────────────
FINDINGS_FILE=$(umask 077; mktemp /tmp/anzen_findings.XXXXXX)
export FINDINGS_FILE
trap 'rm -f "$FINDINGS_FILE" "${FINDINGS_FILE}.tmp"' EXIT

# ── Load libraries ────────────────────────────────────────────────────────────
source "$ANZEN_DIR/lib/os_detect.sh"
source "$ANZEN_DIR/lib/http_probe.sh"
source "$ANZEN_DIR/lib/output.sh"
source "$ANZEN_DIR/lib/report_html.sh"
source "$ANZEN_DIR/lib/report_txt.sh"
source "$ANZEN_DIR/lib/report_json.sh"
source "$ANZEN_DIR/lib/report_sarif.sh"
source "$ANZEN_DIR/lib/baseline.sh"
source "$ANZEN_DIR/lib/remediate.sh"
source "$ANZEN_DIR/lib/notify.sh"
source "$ANZEN_DIR/lib/history.sh"

[ -n "$HISTORY_ARG" ] && HISTORY_DIR="$HISTORY_ARG"

# ── Dashboard mode (reads history, runs no checks) ────────────────────────────
if [ -n "$DASHBOARD_ONLY" ]; then
    if [ -z "${HISTORY_DIR:-}" ] || [ ! -d "$HISTORY_DIR" ]; then
        echo "ERROR: --dashboard needs an existing history dir (--history=DIR or HISTORY_DIR)" >&2
        exit 1
    fi
    generate_dashboard "$HISTORY_DIR" "$DASHBOARD_ONLY" || exit 1
    echo "Dashboard: $DASHBOARD_ONLY"
    exit 0
fi

# ── Remote / fleet mode (--remote=host1,host2) ────────────────────────────────
if [ -n "$REMOTE_HOST" ]; then
    source "$ANZEN_DIR/lib/fleet.sh"
    # Only scan-shaping flags travel; reports/history/notify stay local
    _fleet_args=()
    for arg in "$@"; do
        case $arg in
            --check=*|--parallel|-p|--strict|--quiet|-q|--no-color|--target=*|--wan|--resolve-to=*)
                _fleet_args+=("$arg") ;;
        esac
    done
    run_fleet "$REMOTE_HOST" "${_fleet_args[@]}"
    exit $?
fi

# ── Accepted risks ────────────────────────────────────────────────────────────
if [ -f "$ACCEPT_FILE" ]; then
    _trusted_file "$ACCEPT_FILE" || exit 1
    load_accepted "$ACCEPT_FILE"
fi

for check_file in "$ANZEN_DIR"/lib/checks/*.sh; do
    if ! bash -n "$check_file" 2>/dev/null; then
        echo "[WARN] Syntax error in $check_file — skipping" >&2
        continue
    fi
    # shellcheck source=/dev/null
    source "$check_file"
done

# ── Custom checks (site-specific modules kept outside this repo) ─────────────
# Each CUSTOM_CHECKS_DIR/<name>.sh must define run_<name>_check. They run as
# root, so the same ownership/world-writable rule as anzen.conf applies.
if [ -n "${CUSTOM_CHECKS_DIR:-}" ]; then
    for check_file in "$CUSTOM_CHECKS_DIR"/*.sh; do
        [ -f "$check_file" ] || continue
        _trusted_file "$check_file" || continue
        if ! bash -n "$check_file" 2>/dev/null; then
            echo "[WARN] Syntax error in $check_file — skipping" >&2
            continue
        fi
        # shellcheck source=/dev/null
        source "$check_file"
        ALL_MODULES+=("$(basename "$check_file" .sh)")
    done
fi

# Reject unknown --check values instead of silently running nothing
for _c in "${CHECKS[@]}"; do
    [[ " ${ALL_MODULES[*]} " == *" $_c "* ]] && continue
    echo "Unknown module: $_c  (valid: ${ALL_MODULES[*]})" >&2
    exit 1
done
unset _c

# ── Banner ────────────────────────────────────────────────────────────────────
if [ "$QUIET" = "false" ]; then
    echo -e "\n\033[1m\033[36m   安全  Anzen $ANZEN_VERSION — Linux Security Audit\033[0m"
    echo -e "\033[36m   Host: $(_hostname)  |  OS: $OS_PRETTY\033[0m"
    echo -e "\033[36m   $(date)\033[0m\n"
fi

# ── Module runner ─────────────────────────────────────────────────────────────
# Warn about any module whose run function failed to load
_missing_mods=()
for _m in "${ALL_MODULES[@]}"; do
    declare -f "run_${_m}_check" &>/dev/null || _missing_mods+=("$_m")
done
if [ "${#_missing_mods[@]}" -gt 0 ]; then
    echo "[WARN] Modules missing run function (load failed?): ${_missing_mods[*]}" >&2
fi
unset _missing_mods _m

_should_run() {
    for ex in ${EXCLUDE_CHECKS:-}; do [ "$ex" = "$1" ] && return 1; done
    [ "${#CHECKS[@]}" -eq 0 ] && return 0
    for c in "${CHECKS[@]}"; do [ "$c" = "$1" ] && return 0; done
    return 1
}

_run_module() {
    local name=$1
    local func="run_${name}_check"
    command -v "$func" &>/dev/null && _should_run "$name" && $func
    return 0
}

# ── Run checks ────────────────────────────────────────────────────────────────
if $PARALLEL; then
    PARALLEL_DIR=$(umask 077; mktemp -d /tmp/anzen_parallel.XXXXXX)
    trap 'rm -rf "$PARALLEL_DIR" "$FINDINGS_FILE" "${FINDINGS_FILE}.tmp"' EXIT

    for mod in "${ALL_MODULES[@]}"; do
        _should_run "$mod" || continue
        (
            # shellcheck disable=SC2030
            FINDINGS_FILE="$PARALLEL_DIR/${mod}.findings"
            touch "$FINDINGS_FILE"
            export FINDINGS_FILE
            _run_module "$mod" > "$PARALLEL_DIR/${mod}.out" 2>&1
        ) &
    done
    wait

    for mod in "${ALL_MODULES[@]}"; do
        [ -f "$PARALLEL_DIR/${mod}.out" ] && cat "$PARALLEL_DIR/${mod}.out"
        # shellcheck disable=SC2031
        [ -f "$PARALLEL_DIR/${mod}.findings" ] && cat "$PARALLEL_DIR/${mod}.findings" >> "$FINDINGS_FILE"
    done
else
    for mod in "${ALL_MODULES[@]}"; do
        _run_module "$mod"
    done
fi

# ── Summary ───────────────────────────────────────────────────────────────────
print_summary

# ── History ───────────────────────────────────────────────────────────────────
NEW_FAILS=""
if [ -n "${HISTORY_DIR:-}" ]; then
    # First run for this host: nothing to compare with, so nothing is "new"
    _prev=$(history_latest "$HISTORY_DIR")
    [ -n "$_prev" ] && NEW_FAILS=$(history_new_fails "$_prev")
    unset _prev
    _hf=$(history_save "$HISTORY_DIR") && echo -e "\033[1m\033[36m  History   : $_hf\033[0m"
    unset _hf
    if [ -n "${DASHBOARD_FILE:-}" ]; then
        generate_dashboard "$HISTORY_DIR" "$DASHBOARD_FILE" && \
            echo -e "\033[1m\033[36m  Dashboard : $DASHBOARD_FILE\033[0m"
    fi
fi

# ── Notify + heartbeat ────────────────────────────────────────────────────────
_nf=$(grep -c "^FAIL	" "$FINDINGS_FILE" 2>/dev/null) || _nf=0
notify_run "$_nf" "$(_overall_score)" "$NEW_FAILS"
unset _nf
heartbeat

mkdir -p "$REPORT_DIR"

# Count enabled formats so --output= can be split across several of them
_n_formats=0
for _f in $GENERATE_HTML $GENERATE_TXT $GENERATE_JSON $GENERATE_SARIF; do
    $_f && _n_formats=$((_n_formats + 1))
done

# _report_path EXT — OUTPUT_FILE as-is for a single format, OUTPUT_FILE with
# its extension swapped for EXT when several are enabled, else the default
_report_path() {
    local ext=$1
    if [ -z "$OUTPUT_FILE" ]; then
        echo "$REPORT_DIR/anzen_${TIMESTAMP}.$ext"
    elif [ "$_n_formats" -le 1 ]; then
        echo "$OUTPUT_FILE"
    else
        local base=$OUTPUT_FILE
        [[ "$(basename "$base")" == *.* ]] && base="${base%.*}"
        [[ "$base" == *.sarif ]] && base="${base%.sarif}"
        echo "$base.$ext"
    fi
}

# ── HTML ──────────────────────────────────────────────────────────────────────
if $GENERATE_HTML; then
    HTML_FILE=$(_report_path html)
    generate_html_report "$HTML_FILE"
    echo -e "\033[1m\033[36m  HTML      : $HTML_FILE\033[0m"
fi

# ── Text ──────────────────────────────────────────────────────────────────────
if $GENERATE_TXT; then
    TXT_FILE=$(_report_path txt)
    generate_txt_report "$TXT_FILE"
    echo -e "\033[1m\033[36m  Text      : $TXT_FILE\033[0m"
fi

# ── JSON ──────────────────────────────────────────────────────────────────────
if $GENERATE_JSON; then
    JSON_FILE=$(_report_path json)
    generate_json_report "$JSON_FILE"
    echo -e "\033[1m\033[36m  JSON      : $JSON_FILE\033[0m"
fi

# ── SARIF ─────────────────────────────────────────────────────────────────────
if $GENERATE_SARIF; then
    SARIF_FILE=$(_report_path sarif.json)
    generate_sarif_report "$SARIF_FILE"
    echo -e "\033[1m\033[36m  SARIF     : $SARIF_FILE\033[0m"
fi

# ── Remediate ─────────────────────────────────────────────────────────────────
if $GENERATE_REMEDIATE; then
    REMEDIATE_FILE="$REPORT_DIR/remediate_${TIMESTAMP}.sh"
    REMEDY_COUNT=$(generate_remediate_script "$REMEDIATE_FILE")
    echo -e "\033[1m\033[36m  Remediate : $REMEDIATE_FILE ($REMEDY_COUNT commands)\033[0m"
fi

# ── Baseline ──────────────────────────────────────────────────────────────────
if $BASELINE; then
    save_baseline
fi

# ── Diff ──────────────────────────────────────────────────────────────────────
DIFF_EXIT=0
if $DIFF; then
    diff_baseline || DIFF_EXIT=1
fi

echo ""

# ── Exit code ─────────────────────────────────────────────────────────────────
# shellcheck disable=SC2031
FAIL_COUNT=$(grep -c "^FAIL	" "$FINDINGS_FILE" 2>/dev/null) || FAIL_COUNT=0
WARN_COUNT=$(grep -c "^WARN	" "$FINDINGS_FILE" 2>/dev/null) || WARN_COUNT=0
[ "$((10#${FAIL_COUNT:-0}))" -gt 0 ] && exit 1
[ "$STRICT" = "true" ] && [ "$((10#${WARN_COUNT:-0}))" -gt 0 ] && exit 1
[ "$DIFF_EXIT" -gt 0 ] && exit 2
exit 0
