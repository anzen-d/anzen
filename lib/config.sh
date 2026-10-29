#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 The Anzen contributors
# lib/config.sh — Load user config and set defaults for all thresholds

# _safe_source_config is defined in lib/utils.sh and loaded by anzen.sh before
# this file is sourced. Guard for direct/test invocations.
if ! declare -f _safe_source_config &>/dev/null; then
    # shellcheck source=lib/utils.sh
    source "${ANZEN_DIR}/lib/utils.sh"
fi

# Disk usage thresholds (%)
DISK_WARN_PCT="${DISK_WARN_PCT:-75}"
DISK_FAIL_PCT="${DISK_FAIL_PCT:-90}"

# Memory usage thresholds (%)
MEM_WARN_PCT="${MEM_WARN_PCT:-75}"
MEM_FAIL_PCT="${MEM_FAIL_PCT:-90}"

# Failed login thresholds
FAIL_LOGIN_OK="${FAIL_LOGIN_OK:-10}"
FAIL_LOGIN_WARN="${FAIL_LOGIN_WARN:-50}"

# Running service count thresholds
SERVICE_COUNT_WARN="${SERVICE_COUNT_WARN:-30}"
SERVICE_COUNT_FAIL="${SERVICE_COUNT_FAIL:-50}"

# Password max age warning (days)
PASS_MAX_DAYS_WARN="${PASS_MAX_DAYS_WARN:-90}"

# TLS certificate expiry thresholds (days)
TLS_WARN_DAYS="${TLS_WARN_DAYS:-30}"
TLS_FAIL_DAYS="${TLS_FAIL_DAYS:-7}"

# Score penalty weights
SCORE_FAIL_PENALTY="${SCORE_FAIL_PENALTY:-10}"
SCORE_WARN_PENALTY="${SCORE_WARN_PENALTY:-3}"

# Checks to exclude (space-separated module names)
EXCLUDE_CHECKS="${EXCLUDE_CHECKS:-}"

# Additional SUID paths to whitelist (space-separated)
CUSTOM_SUID_WHITELIST="${CUSTOM_SUID_WHITELIST:-}"

# World-writable scan: max findings before capping (prevents runaway on media dirs)
WW_FILE_CAP="${WW_FILE_CAP:-50}"

# Path globs to exclude from world-writable scan (space-separated)
EXCLUDE_PATHS="${EXCLUDE_PATHS:-}"

# Downgrade specific FAIL findings to WARN (space-separated substrings to match)
FAIL_AS_WARN="${FAIL_AS_WARN:-}"

# Accepted risks: "ID YYYY-MM-DD reason" per line (see anzen.accept.example)
ACCEPT_FILE="${ACCEPT_FILE:-${ANZEN_DIR}/anzen.accept}"

# Notifications — set NOTIFY_NTFY_URL or NOTIFY_CMD (mutually exclusive)
NOTIFY_NTFY_URL="${NOTIFY_NTFY_URL:-}"
NOTIFY_CMD="${NOTIFY_CMD:-}"
NOTIFY_ON_FAIL_ONLY="${NOTIFY_ON_FAIL_ONLY:-false}"
NOTIFY_ON="${NOTIFY_ON:-always}"
NOTIFY_NTFY_TOKEN="${NOTIFY_NTFY_TOKEN:-}"

# Run history (one JSON per run under HISTORY_DIR/<host>/) and retention
HISTORY_DIR="${HISTORY_DIR:-}"
HISTORY_KEEP="${HISTORY_KEEP:-52}"
# Rebuild this static dashboard after every run saved to HISTORY_DIR
DASHBOARD_FILE="${DASHBOARD_FILE:-}"
# URL fetched after every run (dead-man switch, e.g. Uptime Kuma push)
HEARTBEAT_URL="${HEARTBEAT_URL:-}"

# Container image freshness (images module)
IMAGE_MAX_AGE_DAYS="${IMAGE_MAX_AGE_DAYS:-180}"
IMAGE_CHECK_UPDATES="${IMAGE_CHECK_UPDATES:-true}"
IMAGE_WARN_LATEST="${IMAGE_WARN_LATEST:-true}"

# Distrusted CA certificates (truststore module)
# Extra list in the same format as lib/data/distrusted-certs.tsv
DISTRUSTED_CERTS_FILE="${DISTRUSTED_CERTS_FILE:-}"
TRUSTSTORE_SCAN_CONTAINERS="${TRUSTSTORE_SCAN_CONTAINERS:-true}"

# CVE scanning (cve module, needs trivy)
CVE_SEVERITY="${CVE_SEVERITY:-CRITICAL,HIGH}"
CVE_IGNORE_UNFIXED="${CVE_IGNORE_UNFIXED:-true}"
CVE_SCAN_IMAGES="${CVE_SCAN_IMAGES:-true}"
CVE_TIMEOUT="${CVE_TIMEOUT:-60m}"
# CVEs published within this many days are listed as new (INFO)
CVE_NEW_DAYS="${CVE_NEW_DAYS:-7}"
# CISA Known Exploited Vulnerabilities: exploited CVEs are FAIL at any severity
KEV_CHECK="${KEV_CHECK:-true}"
KEV_URL="${KEV_URL:-https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json}"
KEV_CACHE_DIR="${KEV_CACHE_DIR:-}"   # default: /var/cache/anzen (root) or ~/.cache/anzen
CVE_SKIP_DIRS="${CVE_SKIP_DIRS:-/proc /sys /dev /run /tmp /var/tmp /var/lib/docker /var/lib/containerd /var/lib/containers /snap}"

# Drift module state (what the previous full run saw)
DRIFT_STATE_DIR="${DRIFT_STATE_DIR:-/var/lib/anzen/state}"

# Directory of site-specific check modules (<name>.sh defining run_<name>_check)
CUSTOM_CHECKS_DIR="${CUSTOM_CHECKS_DIR:-}"

# Load user config if present (overrides defaults above)
_conf="${ANZEN_DIR}/anzen.conf"
[ -f "$_conf" ] && _safe_source_config "$_conf"
unset _conf

export DISK_WARN_PCT DISK_FAIL_PCT MEM_WARN_PCT MEM_FAIL_PCT
export FAIL_LOGIN_OK FAIL_LOGIN_WARN SERVICE_COUNT_WARN SERVICE_COUNT_FAIL
export PASS_MAX_DAYS_WARN TLS_WARN_DAYS TLS_FAIL_DAYS
export SCORE_FAIL_PENALTY SCORE_WARN_PENALTY
export EXCLUDE_CHECKS CUSTOM_SUID_WHITELIST EXCLUDE_PATHS WW_FILE_CAP
export FAIL_AS_WARN ACCEPT_FILE
export NOTIFY_NTFY_URL NOTIFY_CMD NOTIFY_ON_FAIL_ONLY NOTIFY_ON NOTIFY_NTFY_TOKEN
export IMAGE_MAX_AGE_DAYS IMAGE_CHECK_UPDATES IMAGE_WARN_LATEST
export DISTRUSTED_CERTS_FILE TRUSTSTORE_SCAN_CONTAINERS
export CVE_SEVERITY CVE_IGNORE_UNFIXED CVE_SCAN_IMAGES CVE_TIMEOUT CVE_SKIP_DIRS
export CVE_NEW_DAYS KEV_CHECK KEV_URL KEV_CACHE_DIR
export DRIFT_STATE_DIR
export HISTORY_DIR HISTORY_KEEP CUSTOM_CHECKS_DIR DASHBOARD_FILE HEARTBEAT_URL
