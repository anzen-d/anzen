#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 The Anzen contributors
# lib/output.sh — Terminal output and findings collection

# Honour NO_COLOR (https://no-color.org) and --no-color flag; no colour when
# stdout is not a terminal (cron | logger, redirects)
if { [ -n "${NO_COLOR:-}" ] && [ "$NO_COLOR" != false ]; } || [ ! -t 1 ]; then
    RED='' YELLOW='' GREEN='' CYAN='' BOLD='' NC=''
else
    RED='\033[0;31m'
    YELLOW='\033[1;33m'
    GREEN='\033[0;32m'
    CYAN='\033[0;36m'
    BOLD='\033[1m'
    NC='\033[0m'
fi

CURRENT_SECTION="General"

# _sysctl KEY — value of a kernel parameter; reads /proc/sys directly when the
# sysctl binary (procps) is missing, as in minimal images
_sysctl() {
    if command -v sysctl &>/dev/null; then
        sysctl -n "$1" 2>/dev/null
    else
        cat "/proc/sys/${1//.//}" 2>/dev/null
    fi
}

# _hostname — minimal images (Fedora, Arch containers) have no hostname binary
_hostname() { hostname 2>/dev/null || uname -n; }
# FINDINGS_FILE must be set by anzen.sh before sourcing checks
#
# Findings TSV, one line per finding:
#   LEVEL<TAB>SECTION<TAB>MESSAGE<TAB>ID<TAB>REMEDY
# REMEDY stays last: it is often empty, and read with IFS=$'\t' collapses
# empty fields in the middle of a line

# _finding_id SECTION MESSAGE — stable ID: section slug + hash of the message
# with volatile parts (percentages, sizes, durations, counts) normalised away,
# so "Disk / at 81%" and "Disk / at 86%" share an ID across runs
_finding_id() {
    local slug norm
    slug=$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]' | tr -cs 'a-z0-9' '-')
    slug="${slug#-}"; slug="${slug%-}"
    norm=$(printf '%s' "$2" | tr '[:upper:]\t\n' '[:lower:]  ' | sed -E \
        -e 's/[0-9]+(\.[0-9]+)? ?(%|[kmgtp]i?b?\b|days?\b|hours?\b|minutes?\b|seconds?\b|ms\b)/#\2/g' \
        -e 's/\(([0-9]+)( [a-z]+)*\)/(#)/g' \
        -e 's/\b[0-9]+ (found|files?|entries|items|packages?|updates?|failed|attempts?|services?|containers?|users?|accounts?|rules?|processes|connections?)\b/# \1/g' \
        -e 's/[[:space:]]+/ /g')
    printf '%s-%s' "$slug" "$(printf '%s' "$norm" | md5sum | cut -c1-8)"
}

# Accepted risks, loaded by load_accepted from ACCEPT_FILE:
#   ID  YYYY-MM-DD  reason...
declare -gA ACCEPTED_UNTIL=() ACCEPTED_REASON=()

load_accepted() {
    local f=$1 id until reason
    [ -f "$f" ] || return 0
    while read -r id until reason; do
        [[ -z "$id" || "$id" == \#* ]] && continue
        if ! [[ "$until" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]]; then
            echo "[WARN] $f: '$id' needs an expiry date (YYYY-MM-DD) — ignored" >&2
            continue
        fi
        ACCEPTED_UNTIL[$id]=$until
        ACCEPTED_REASON[$id]=${reason:-no reason given}
    done < "$f"
}

_record() { _record_as "$1" "$2" "$2"; }

# _accepted MESSAGE — succeeds when the finding is accepted and not expired;
# sets _ACCEPT_NOTE either way when an entry exists
_accepted() {
    local id; id=$(_finding_id "$CURRENT_SECTION" "$1")
    _ACCEPT_NOTE=""
    [ -n "${ACCEPTED_UNTIL[$id]+x}" ] || return 1
    if [[ "${ACCEPTED_UNTIL[$id]}" < "$(date +%F)" ]]; then
        _ACCEPT_NOTE=" [acceptance expired ${ACCEPTED_UNTIL[$id]}: ${ACCEPTED_REASON[$id]}]"
        return 1
    fi
    _ACCEPT_NOTE="[accepted until ${ACCEPTED_UNTIL[$id]}: ${ACCEPTED_REASON[$id]}]"
}

# _record_as LEVEL ID_MESSAGE SHOWN_MESSAGE — keep the ID of the original
# message when the recorded text gets an acceptance note appended
_record_as() {
    local id msg=$3
    id=$(_finding_id "$CURRENT_SECTION" "$2")
    # Strip tabs and newlines that would break TSV parsing downstream
    msg="${msg//$'\t'/ }"
    msg="${msg//$'\n'/ }"
    [ -n "$FINDINGS_FILE" ] && printf '%s\t%s\t%s\t%s\t\n' "$1" "$CURRENT_SECTION" "$msg" "$id" >> "$FINDINGS_FILE"
}

# _q VALUE — shell-quote a value for a remedy command. Use it for every name
# taken from the system (file names, users): remediate.sh runs as root, and a
# file named "x'; cmd #" must not become a command
_q() { printf '%q' "$1"; }

# Append a remediation command to the most recent finding (amends last line)
remedy() {
    [ -s "$FINDINGS_FILE" ] || return 0
    # Passed via ENVIRON: awk -v would expand backslash escapes in the command
    ANZEN_REMEDY=$1 awk 'BEGIN{FS=OFS="\t"; r=ENVIRON["ANZEN_REMEDY"]} NR>1{print prev} {prev=$0} END{
        # Fill the 5th (remedy) field of the last finding
        split(prev, f, "\t")
        print f[1], f[2], f[3], f[4], r
    }' "$FINDINGS_FILE" > "${FINDINGS_FILE}.tmp" && mv "${FINDINGS_FILE}.tmp" "$FINDINGS_FILE"
}

ok()   { echo -e "${GREEN}[ OK ]${NC} $1"; _record "OK"   "$1"; }

# Accepted findings are recorded as INFO (no score penalty, kept in reports)
_accepted_info() {
    [ "${QUIET:-false}" = "true" ] || echo -e "${CYAN}[ACPT]${NC} $1 $_ACCEPT_NOTE"
    _record_as "INFO" "$1" "$1 $_ACCEPT_NOTE"
}

warn() {
    if _accepted "$1"; then _accepted_info "$1"; return; fi
    echo -e "${YELLOW}[WARN]${NC} $1$_ACCEPT_NOTE"
    _record_as "WARN" "$1" "$1$_ACCEPT_NOTE"
}
fail() {
    local _msg="$1"
    if _accepted "$_msg"; then _accepted_info "$_msg"; return; fi
    # FAIL_AS_WARN: space-separated substrings; matching findings are downgraded to WARN
    local _pat
    for _pat in ${FAIL_AS_WARN:-}; do
        if [[ "$_msg" == *"$_pat"* ]]; then
            warn "$_msg"
            return
        fi
    done
    echo -e "${RED}[FAIL]${NC} $_msg$_ACCEPT_NOTE"
    _record_as "FAIL" "$_msg" "$_msg$_ACCEPT_NOTE"
}
info() {
    _record "INFO" "$1"
    [ "${QUIET:-false}" = "true" ] && return
    echo -e "${CYAN}[INFO]${NC} $1"
}

section() {
    CURRENT_SECTION="$1"
    [ "${QUIET:-false}" = "true" ] && return
    echo -e "\n${BOLD}${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BOLD}${CYAN}  $1${NC}"
    echo -e "${BOLD}${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
}

# _section_scores — one line per section with WARN/FAIL/OK findings:
#   SECTION<TAB>FAIL<TAB>WARN<TAB>OK<TAB>SCORE
# Section score = 100 - FAIL*penalty - WARN*penalty, floored at 0
_section_scores() {
    awk -F'\t' -v fp="${SCORE_FAIL_PENALTY:-10}" -v wp="${SCORE_WARN_PENALTY:-3}" '
        $1 == "FAIL" || $1 == "WARN" || $1 == "OK" {
            if (!($2 in seen)) { seen[$2] = 1; order[++n] = $2 }
            c[$2, $1]++
        }
        END {
            for (i = 1; i <= n; i++) {
                s = order[i]
                sc = 100 - c[s, "FAIL"] * fp - c[s, "WARN"] * wp
                if (sc < 0) sc = 0
                printf "%s\t%d\t%d\t%d\t%d\n", s, c[s, "FAIL"], c[s, "WARN"], c[s, "OK"], sc
            }
        }' "$FINDINGS_FILE"
}

# _overall_score — mean of section scores, so one noisy section (e.g. 150
# container warnings) cannot drag the whole host to 0; 100 with no findings
_overall_score() {
    _section_scores | awk -F'\t' '{ t += $5; n++ } END { print (n ? int(t / n + 0.5) : 100) }'
}

# _repeated_findings [MIN] — "COUNT<TAB>LEVEL<TAB>PREFIX" for message prefixes
# (text before the first ": ") shared by at least MIN WARN/FAIL findings
_repeated_findings() {
    awk -F'\t' -v min="${1:-3}" '
        $1 == "FAIL" || $1 == "WARN" {
            # Prefix before ": " — a bare ":" also occurs in versions and ports
            p = $3; i = index(p, ": "); if (i > 0) p = substr(p, 1, i - 1)
            if (p == "" || p == $3) next
            k = $1 "\t" p; if (!(k in c)) order[++n] = k; c[k]++
        }
        END { for (i = 1; i <= n; i++) if (c[order[i]] >= min) printf "%d\t%s\n", c[order[i]], order[i] }
    ' "$FINDINGS_FILE" | sort -t$'\t' -k1,1nr
}

# _format_secs SECONDS — "42s" or "9m 05s"
_format_secs() {
    if [ "$1" -ge 60 ]; then printf '%dm %02ds' $(( $1 / 60 )) $(( $1 % 60 )); else printf '%ds' "$1"; fi
}

print_summary() {
    local fails warns oks score
    fails=$(grep -c "^FAIL	" "$FINDINGS_FILE" 2>/dev/null) || fails=0
    warns=$(grep -c "^WARN	" "$FINDINGS_FILE" 2>/dev/null) || warns=0
    oks=$(grep -c   "^OK	"   "$FINDINGS_FILE" 2>/dev/null) || oks=0
    score=$(_overall_score)

    echo -e "\n${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BOLD}  SUMMARY${NC}"
    echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    local sec f w _o sc
    while IFS=$'\t' read -r sec f w _o sc; do
        [ "$f" -eq 0 ] && [ "$w" -eq 0 ] && continue
        printf "  %-36s %3s%%   FAIL %-3s WARN %s\n" "$sec" "$sc" "$f" "$w"
    done < <(_section_scores)
    local reps; reps=$(_repeated_findings 3)
    if [ -n "$reps" ]; then
        echo -e "\n  ${BOLD}Repeated:${NC}"
        local n lvl prefix
        while IFS=$'\t' read -r n lvl prefix; do
            printf "  %4s× %-4s %s\n" "$n" "$lvl" "$prefix"
        done <<< "$reps"
    fi
    # Slowest modules, so a long run points at what to exclude (EXCLUDE_PATHS)
    if [ -s "${TIMES_FILE:-}" ]; then
        local slow mod secs
        slow=$(sort -t$'\t' -k2,2nr "$TIMES_FILE" | awk -F'\t' '$2 >= 10' | head -3)
        if [ -n "$slow" ]; then
            echo -e "\n  ${BOLD}Slowest:${NC}"
            while IFS=$'\t' read -r mod secs; do
                printf "  %8s  %s\n" "$(_format_secs "$secs")" "$mod"
            done <<< "$slow"
        fi
    fi
    echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "  ${RED}${BOLD}FAIL: $fails${NC}   ${YELLOW}${BOLD}WARN: $warns${NC}   ${GREEN}${BOLD}OK: $oks${NC}   Score: ${BOLD}${score}%${NC}"
    echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}\n"
}
