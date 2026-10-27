#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 The Anzen contributors
# anzen-tui.sh — Interactive TUI for Anzen (安全)
# Requires: whiptail (apt install whiptail) or dialog (apt install dialog)
# Requires: bash 4.0+
#
# Usage: ./anzen-tui.sh [OPTIONS]
#   -h          Show this help
#   -v          Print version
#   -n          Non-interactive (plain select menu, no whiptail/dialog)
#   -t SECONDS  Timeout for "Press Enter" prompts (default: 30)

set -uo pipefail

ANZEN_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ANZEN_VERSION=$(grep 'ANZEN_VERSION=' "$ANZEN_DIR/anzen.sh" | head -1 | cut -d'"' -f2)

# ── Ch.14: getopts — parse TUI-level flags ────────────────────────────────────
FORCE_PLAIN=false
PROMPT_TIMEOUT=30

while getopts ':hvnt:' opt; do
    case "$opt" in
        h)  cat <<'EOF'
Usage: ./anzen-tui.sh [OPTIONS]
  -h          Show this help
  -v          Print version
  -n          Non-interactive (plain select menu, no whiptail/dialog)
  -t SECONDS  Timeout for "Press Enter" prompts (default: 30)
EOF
            exit 0 ;;
        v)  printf 'anzen-tui %s\n' "$ANZEN_VERSION"; exit 0 ;;
        n)  FORCE_PLAIN=true ;;
        t)  PROMPT_TIMEOUT="$OPTARG"
            [[ "$PROMPT_TIMEOUT" =~ ^[0-9]+$ ]] || { printf 'Error: -t requires a number\n' >&2; exit 1; } ;;
        :)  printf 'Error: -%s requires an argument\n' "$OPTARG" >&2; exit 1 ;;
        \?) printf 'Error: unknown option -%s  (try -h)\n' "$OPTARG" >&2; exit 1 ;;
    esac
done
shift $(( OPTIND - 1 ))

# ── tput-based color variables (Ch.15 / portable terminal caps) ───────────────
if [[ -t 1 ]] && command -v tput &>/dev/null; then
    C_RED=$(tput setaf 1 2>/dev/null) || C_RED=''
    C_GRN=$(tput setaf 2 2>/dev/null) || C_GRN=''
    C_YEL=$(tput setaf 3 2>/dev/null) || C_YEL=''
    C_CYN=$(tput setaf 6 2>/dev/null) || C_CYN=''
    C_BLD=$(tput bold    2>/dev/null) || C_BLD=''
    C_RST=$(tput sgr0    2>/dev/null) || C_RST=''
else
    C_RED='' C_GRN='' C_YEL='' C_CYN='' C_BLD='' C_RST=''
fi

# ── Ch.16: cleanup + proper SIGINT re-raise ───────────────────────────────────
_cleanup() { tput cnorm 2>/dev/null; tput rmcup 2>/dev/null || clear 2>/dev/null; }
trap '_cleanup'                               EXIT TERM
trap '_cleanup; trap - INT; kill -s INT "$$"' INT

# ── Detect dialog utility ─────────────────────────────────────────────────────
if command -v whiptail &>/dev/null; then
    DLG=whiptail
elif command -v dialog &>/dev/null; then
    DLG=dialog
else
    printf '%sError:%s whiptail or dialog is required for the TUI.\n' "$C_RED" "$C_RST"
    printf 'Install: apt install whiptail   |   yum install newt\n'
    exit 1
fi

# ── Capture dialog output (swaps stdout/stderr) ───────────────────────────────
dlg() { "$DLG" "$@" 3>&1 1>&2 2>&3; }

# ── Modules with descriptions ─────────────────────────────────────────────────
ALL_MODULES=(
    system            "CPU, memory, OS info"
    users             "User accounts and privileges"
    ssh               "SSH daemon configuration"
    network           "Network interfaces and open ports"
    network2          "Advanced network security checks"
    packages          "Package updates"
    files             "Sensitive file permissions"
    secrets           "Exposed secrets and private keys"
    systemd_hardening "Systemd unit hardening"
    tls               "TLS/SSL certificates"
    compiler          "Compiler tools exposure"
    path_check        "PATH variable safety"
    modules           "Kernel module restrictions"
    services          "Running services audit"
    logins            "Login history and activity"
    kernel            "Kernel parameters (sysctl)"
    auditd            "Audit daemon configuration"
    images            "Container image age, pinning, updates"
    cve               "Known CVEs: host + container images (trivy)"
    docker_security   "Container / Docker security"
)

MODULE_NAMES=()
for (( i=0; i<${#ALL_MODULES[@]}; i+=2 )); do
    MODULE_NAMES+=("${ALL_MODULES[$i]}")
done

# ── State ─────────────────────────────────────────────────────────────────────
declare -A MOD_STATE FMT_STATE OPT_STATE

for m in "${MODULE_NAMES[@]}"; do MOD_STATE[$m]=ON; done
for f in html txt json;         do FMT_STATE[$f]=OFF; done
for o in quiet no-color parallel remediate baseline diff; do OPT_STATE[$o]=OFF; done

OUTPUT_FILE=""
REMOTE_HOST=""
CONFIG_FILE=""
SCHEDULE=""
declare -a BUILT_ARGS

# ── Dynamic dialog dimensions ─────────────────────────────────────────────────
_dims() {
    local th tw
    th=$(tput lines 2>/dev/null || echo 24)
    tw=$(tput cols  2>/dev/null || echo 80)
    DH=$(( th - 3 )); DW=$(( tw > 82 ? 80 : tw - 2 ))
}

# ── Ch.14: read with timeout — wraps `read -t` ────────────────────────────────
# Usage: _pause "message"   returns 0 on Enter, 1 on timeout
_pause() {
    printf '\n  %s (auto-continue in %ss) ' "${1:-Press Enter to continue...}" "$PROMPT_TIMEOUT"
    read -r -t "$PROMPT_TIMEOUT" || true
}

# ── Ch.18: --separate-output + mapfile for clean checklist parsing ────────────
# bash 4.0 compatible — avoids local -n nameref (requires 4.3+)
_read_checklist() {
    # $1 = variable name to populate, $2 = raw dialog output (one item per line)
    local _varname=$1 _raw=$2 _item
    local _filtered=()
    local _lines=()
    mapfile -t _lines <<< "$_raw"
    for _item in "${_lines[@]}"; do [[ -n "$_item" ]] && _filtered+=("$_item"); done
    eval "${_varname}=(\"\${_filtered[@]}\")"
}

# ── Select modules ────────────────────────────────────────────────────────────
select_modules() {
    _dims
    local list_h=$(( DH - 9 ))
    (( list_h >= 5 )) || list_h=5

    if [[ "$DLG" == "whiptail" ]]; then
        local pre
        pre=$(dlg --title " Modules " \
            --cancel-button "Back" \
            --menu "Quick select or pick individually:" \
            11 52 3 \
            "custom" "Pick modules individually (checklist)" \
            "all"    "Enable all modules" \
            "none"   "Disable all modules") || return 0
        if [[ "$pre" == "all" ]];  then
            for m in "${MODULE_NAMES[@]}"; do MOD_STATE[$m]=ON;  done; return 0
        fi
        if [[ "$pre" == "none" ]]; then
            for m in "${MODULE_NAMES[@]}"; do MOD_STATE[$m]=OFF; done; return 0
        fi
    fi

    while true; do
        local items=()
        for (( i=0; i<${#ALL_MODULES[@]}; i+=2 )); do
            local name="${ALL_MODULES[$i]}" desc="${ALL_MODULES[$i+1]}"
            items+=("$name" "$desc" "${MOD_STATE[$name]}")
        done

        local result rc
        if [[ "$DLG" == "dialog" ]]; then
            result=$(dlg --title " Modules " \
                --extra-button --extra-label "All On" \
                --help-button  --help-label  "All Off" \
                --cancel-button "Done" \
                --separate-output \
                --checklist "Space = toggle   Tab = buttons" \
                "$DH" "$DW" "$list_h" "${items[@]}")
            rc=$?
            if [[ $rc -eq 3 ]]; then
                for m in "${MODULE_NAMES[@]}"; do MOD_STATE[$m]=ON;  done; continue
            fi
            if [[ $rc -eq 2 ]]; then
                for m in "${MODULE_NAMES[@]}"; do MOD_STATE[$m]=OFF; done; continue
            fi
        else
            result=$(dlg --title " Modules " \
                --cancel-button "Done" \
                --separate-output \
                --checklist "Space = toggle   Tab = buttons" \
                "$DH" "$DW" "$list_h" "${items[@]}")
            rc=$?
        fi

        [[ $rc -ne 0 ]] && return 0

        for m in "${MODULE_NAMES[@]}"; do MOD_STATE[$m]=OFF; done
        local selected=()
        _read_checklist selected "$result"
        for m in "${selected[@]}"; do
            [[ -v MOD_STATE[$m] ]] && MOD_STATE[$m]=ON
        done
        return 0
    done
}

# ── Select output formats ─────────────────────────────────────────────────────
select_formats() {
    _dims
    local result
    result=$(dlg --title " Output Formats " \
        --separate-output \
        --checklist "Select report formats to generate:" \
        13 "$DW" 3 \
        html "HTML report (reports/anzen_TIMESTAMP.html)" "${FMT_STATE[html]}" \
        txt  "Plain text  (reports/anzen_TIMESTAMP.txt)"  "${FMT_STATE[txt]}" \
        json "JSON report (reports/anzen_TIMESTAMP.json)" "${FMT_STATE[json]}") || return 0

    for f in html txt json; do FMT_STATE[$f]=OFF; done
    local selected=()
    _read_checklist selected "$result"
    for f in "${selected[@]}"; do
        [[ -v FMT_STATE[$f] ]] && FMT_STATE[$f]=ON
    done
}

# ── Select options ────────────────────────────────────────────────────────────
select_options() {
    _dims
    local result
    result=$(dlg --title " Options " \
        --separate-output \
        --checklist "Select run-time options:" \
        17 "$DW" 6 \
        quiet      "Suppress INFO lines (FAIL/WARN/OK only)"  "${OPT_STATE[quiet]}" \
        no-color   "Disable ANSI colour output"               "${OPT_STATE[no-color]}" \
        parallel   "Run all modules in parallel"              "${OPT_STATE[parallel]}" \
        remediate  "Generate remediation script after run"    "${OPT_STATE[remediate]}" \
        baseline   "Save this run as the new baseline"        "${OPT_STATE[baseline]}" \
        diff       "Compare results against saved baseline"   "${OPT_STATE[diff]}") || return 0

    for o in quiet no-color parallel remediate baseline diff; do OPT_STATE[$o]=OFF; done
    local selected=()
    _read_checklist selected "$result"
    for o in "${selected[@]}"; do
        [[ -v OPT_STATE[$o] ]] && OPT_STATE[$o]=ON
    done
}

# ── Advanced settings submenu ─────────────────────────────────────────────────
advanced_settings() {
    while true; do
        _dims
        local out_label="${OUTPUT_FILE:-(auto)}"
        local host_label="${REMOTE_HOST:-(local)}"
        local cfg_label="${CONFIG_FILE:-(default)}"
        local sched_label="${SCHEDULE:-(none)}"

        local sub
        sub=$(dlg --title " Advanced Settings " \
            --cancel-button "Back" \
            --menu "Current: output=$out_label  host=$host_label  config=$cfg_label  schedule=$sched_label" \
            15 "$DW" 4 \
            "file"     "Output file path        [$out_label]" \
            "remote"   "Remote SSH host         [$host_label]" \
            "config"   "Config file             [$cfg_label]" \
            "schedule" "Install cron schedule   [$sched_label]") || return 0

        case "$sub" in
            file)
                while true; do
                    local result
                    result=$(dlg --title " Output File " \
                        --inputbox "Override output path (blank = default timestamped file):" \
                        9 "$DW" "$OUTPUT_FILE") || break
                    if [[ -z "$result" ]]; then OUTPUT_FILE=""; break; fi
                    local parent_dir; parent_dir="$(dirname "$result")"
                    if [[ ! -d "$parent_dir" ]]; then
                        dlg --title " Error " --msgbox "Directory does not exist: $parent_dir" 7 60; continue
                    elif [[ ! -w "$parent_dir" ]]; then
                        dlg --title " Error " --msgbox "Directory not writable: $parent_dir"    7 60; continue
                    fi
                    OUTPUT_FILE="$result"; break
                done
                ;;
            remote)
                while true; do
                    local result
                    result=$(dlg --title " Remote Host " \
                        --inputbox "Run audit on a remote host via SSH (blank = local):"$'\n'"Format: user@host" \
                        10 "$DW" "$REMOTE_HOST") || break
                    if [[ -z "$result" ]]; then REMOTE_HOST=""; break; fi
                    if [[ ! "$result" =~ ^[A-Za-z0-9._-]+@[A-Za-z0-9._:-]+$ ]]; then
                        dlg --title " Error " --msgbox "Invalid format. Expected: user@host" 7 52; continue
                    fi
                    REMOTE_HOST="$result"; break
                done
                ;;
            config)
                while true; do
                    local result
                    result=$(dlg --title " Config File " \
                        --inputbox "Path to anzen.conf to load (blank = built-in defaults):" \
                        9 "$DW" "$CONFIG_FILE") || break
                    if [[ -z "$result" ]]; then CONFIG_FILE=""; break; fi
                    local resolved; resolved=$(realpath -e "$result" 2>/dev/null) || resolved=""
                    if [[ -z "$resolved" ]]; then
                        dlg --title " Error " --msgbox "File not found: $result" 7 52; continue
                    fi
                    CONFIG_FILE="$resolved"; break
                done
                ;;
            schedule)
                local result
                result=$(dlg --title " Schedule " \
                    --cancel-button "Clear" \
                    --menu "Install a cron job to run anzen automatically:" \
                    12 52 3 \
                    "daily"   "Every day at 06:00" \
                    "weekly"  "Every Monday at 06:00" \
                    "monthly" "1st of month at 06:00")
                local src=$?
                [[ $src -eq 0 ]] && SCHEDULE="$result"
                [[ $src -eq 1 ]] && SCHEDULE=""
                ;;
        esac
    done
}

# ── Build args array ──────────────────────────────────────────────────────────
build_args() {
    BUILT_ARGS=()

    local all_on=true
    for m in "${MODULE_NAMES[@]}"; do
        [[ "${MOD_STATE[$m]}" == "OFF" ]] && all_on=false && break
    done
    if [[ "$all_on" == false ]]; then
        for m in "${MODULE_NAMES[@]}"; do
            [[ "${MOD_STATE[$m]}" == "ON" ]] && BUILT_ARGS+=("--check=$m")
        done
    fi

    [[ "${FMT_STATE[html]}"      == "ON" ]] && BUILT_ARGS+=("--html")
    [[ "${FMT_STATE[txt]}"       == "ON" ]] && BUILT_ARGS+=("--txt")
    [[ "${FMT_STATE[json]}"      == "ON" ]] && BUILT_ARGS+=("--json")
    [[ "${OPT_STATE[quiet]}"     == "ON" ]] && BUILT_ARGS+=("--quiet")
    [[ "${OPT_STATE[no-color]}"  == "ON" ]] && BUILT_ARGS+=("--no-color")
    [[ "${OPT_STATE[parallel]}"  == "ON" ]] && BUILT_ARGS+=("--parallel")
    [[ "${OPT_STATE[remediate]}" == "ON" ]] && BUILT_ARGS+=("--remediate")
    [[ "${OPT_STATE[baseline]}"  == "ON" ]] && BUILT_ARGS+=("--baseline")
    [[ "${OPT_STATE[diff]}"      == "ON" ]] && BUILT_ARGS+=("--diff")
    [[ -n "$REMOTE_HOST" ]]                 && BUILT_ARGS+=("--remote=$REMOTE_HOST")
    [[ -n "$CONFIG_FILE" ]]                 && BUILT_ARGS+=("--config=$CONFIG_FILE")
    [[ -n "$SCHEDULE" ]]                    && BUILT_ARGS+=("--schedule=$SCHEDULE")
    [[ -n "$OUTPUT_FILE" ]]                 && BUILT_ARGS+=("--output=$OUTPUT_FILE")
}

# ── Ch.15: latest report via glob array (not ls|head) ─────────────────────────
_latest_report() {
    local pattern=$1 _old; _old=$(shopt -p nullglob)
    shopt -s nullglob
    # shellcheck disable=SC2206  # intentional glob expansion without quoting
    local matches=( $pattern )
    eval "$_old"
    [[ "${#matches[@]}" -gt 0 ]] && printf '%s' "${matches[-1]}"
}

# ── Post-run: offer to view generated reports ─────────────────────────────────
_offer_view_reports() {
    local candidates=()
    if [[ -n "$OUTPUT_FILE" && -f "$OUTPUT_FILE" ]]; then
        candidates+=("$OUTPUT_FILE")
    else
        local f
        f=$(_latest_report "$ANZEN_DIR/reports/anzen_*.txt");  [[ -n "$f" && "${FMT_STATE[txt]}"  == "ON" ]] && candidates+=("$f")
        f=$(_latest_report "$ANZEN_DIR/reports/anzen_*.json"); [[ -n "$f" && "${FMT_STATE[json]}" == "ON" ]] && candidates+=("$f")
        f=$(_latest_report "$ANZEN_DIR/reports/anzen_*.html"); [[ -n "$f" && "${FMT_STATE[html]}" == "ON" ]] && candidates+=("$f")
    fi
    [[ "${#candidates[@]}" -eq 0 ]] && return 0

    local items=()
    local r; for r in "${candidates[@]}"; do items+=("$r" "$(basename "$r")"); done

    _dims
    local chosen
    chosen=$(dlg --title " View Report " \
        --cancel-button "Skip" \
        --menu "Open a report file?" \
        $(( ${#candidates[@]} + 8 )) "$DW" "${#candidates[@]}" \
        "${items[@]}") || return 0

    local ext="${chosen##*.}"
    if [[ "$ext" == "html" ]] && command -v xdg-open &>/dev/null; then
        xdg-open "$chosen" &
    elif command -v less &>/dev/null; then
        clear; less "$chosen"
    else
        clear; cat "$chosen"; _pause "Press Enter to continue..."
    fi
}

# ── Ch.15+18: run audit, stream output live through dialog or terminal ─────────
#
# dialog supports --progressbox (pipes stdin into a scrolling widget — Ch.18).
# whiptail has no equivalent; we fall back to a clear + direct terminal output.
# Ch.15: mktemp + tee preserves output for post-run view regardless of mode.
# Ch.16: PIPESTATUS captures exit code across the pipe; `wait` for background.
_run_with_output() {
    local -a args=("$@")
    # Ch.15: temp file captures full output for later report viewing / logging
    local tmp; tmp=$(mktemp /tmp/anzen_run.XXXXXX)
    trap 'rm -f "$tmp"' RETURN

    _dims
    local rc=0
    if [[ "$DLG" == "dialog" ]]; then
        # Ch.18: --progressbox — live scrolling output inside a dialog widget
        # Pipe: anzen → tee (file) → progressbox
        # PIPESTATUS[0] gives anzen's exit code after the pipe finishes
        "$ANZEN_DIR/anzen.sh" "${args[@]}" 2>&1 \
            | tee "$tmp" \
            | dialog --title " Running Audit — 安全 Anzen $ANZEN_VERSION " \
                     --progressbox "Streaming live output…" \
                     "$DH" "$DW"
        rc="${PIPESTATUS[0]}"
    else
        # whiptail fallback: plain terminal output, still tee'd to tmp file
        clear
        "$ANZEN_DIR/anzen.sh" "${args[@]}" 2>&1 | tee "$tmp"
        rc="${PIPESTATUS[0]}"
    fi

    # Ch.15: log session summary to syslog if logger is available
    if command -v logger &>/dev/null; then
        local host_tag="${REMOTE_HOST:-local}"
        logger -t anzen-tui "audit finished: host=$host_tag exit=$rc args=${args[*]:-none}"
    fi

    # Parse finding counts from captured output (strip ANSI codes first)
    local plain; plain=$(sed 's/\x1B\[[0-9;]*[mK]//g' "$tmp" 2>/dev/null)
    local n_fail n_warn n_ok
    n_fail=$(printf '%s\n' "$plain" | grep -c '^\[FAIL\]' 2>/dev/null) || n_fail=0
    n_warn=$(printf '%s\n' "$plain" | grep -c '^\[WARN\]' 2>/dev/null) || n_warn=0
    n_ok=$(printf '%s\n'   "$plain" | grep -c '^\[ OK \]' 2>/dev/null) || n_ok=0

    printf '\n'
    if [[ $rc -eq 0 ]]; then
        printf '%s  Audit complete — %d OK  %d WARN  0 FAIL%s\n' \
            "$C_GRN" "$n_ok" "$n_warn" "$C_RST"
    elif [[ $rc -eq 1 ]]; then
        printf '%s  Audit complete — %d FAIL  %d WARN  %d OK  (review findings above)%s\n' \
            "$C_RED" "$n_fail" "$n_warn" "$n_ok" "$C_RST"
    elif [[ $rc -eq 2 ]]; then
        printf '%s  Audit complete — baseline regressions detected  %d FAIL  %d WARN%s\n' \
            "$C_YEL" "$n_fail" "$n_warn" "$C_RST"
    else
        printf '%s  Audit exited with unexpected code %d%s\n' "$C_YEL" "$rc" "$C_RST"
    fi

    # Ch.14: `read -t` — auto-continue after PROMPT_TIMEOUT seconds
    _pause "Press Enter to return to menu..."

    _offer_view_reports
    return "$rc"
}

# ── About dialog (ABS: heredoc for multi-line formatted output) ───────────────
show_about() {
    _dims
    local os_info; os_info=$(uname -srm 2>/dev/null || echo "unknown")
    local hostname; hostname=$(hostname 2>/dev/null || echo "unknown")
    # ABS §19: heredoc to compose multi-line string without echo -e chains
    local body
    body=$(cat <<EOF
  安全 Anzen $ANZEN_VERSION — Linux Security Audit Tool

  Host    : $hostname
  OS      : $os_info
  Script  : $ANZEN_DIR/anzen.sh
  TUI     : $ANZEN_DIR/anzen-tui.sh
  Dialog  : $DLG

  Modules available : ${#MODULE_NAMES[@]}
  Reports directory : $ANZEN_DIR/reports/
EOF
)
    dlg --title " About Anzen " --msgbox "$body" 16 60
}

# ── Run audit ─────────────────────────────────────────────────────────────────
run_audit() {
    _dims

    if [[ -n "$SCHEDULE" ]]; then
        dlg --title " Confirm " \
            --yesno "Install a $SCHEDULE cron job for anzen?" \
            7 52 || return 0
        clear
        "$ANZEN_DIR/anzen.sh" "--schedule=$SCHEDULE"
        _pause "Press Enter to return to menu..."
        return 0
    fi

    # Guard: block run if no modules are selected
    local mod_on=0 m
    for m in "${MODULE_NAMES[@]}"; do
        [[ "${MOD_STATE[$m]}" == "ON" ]] && mod_on=$(( mod_on + 1 ))
    done
    if [[ $mod_on -eq 0 ]]; then
        dlg --title " Error " \
            --msgbox "No modules selected.\n\nEnable at least one module before running." \
            9 52
        return 0
    fi

    build_args

    local display="anzen.sh"
    local a; for a in "${BUILT_ARGS[@]}"; do display+=" $a"; done

    local wrap_lines=$(( (${#display} / (DW - 6)) + 1 ))
    local confirm_h=$(( wrap_lines + 7 ))
    (( confirm_h >= 9  )) || confirm_h=9
    (( confirm_h <= DH )) || confirm_h=$DH

    dlg --title " Confirm " \
        --yesno "Run the following command?"$'\n\n'"  $display" \
        "$confirm_h" "$DW" || return 0

    _run_with_output "${BUILT_ARGS[@]}"
}

# ── Status line for menu ──────────────────────────────────────────────────────
menu_status() {
    local mod_on=0 m
    for m in "${MODULE_NAMES[@]}"; do
        [[ "${MOD_STATE[$m]}" == "ON" ]] && mod_on=$(( mod_on + 1 ))
    done

    local fmts="" opts=""
    [[ "${FMT_STATE[html]}" == "ON" ]] && fmts+="HTML "
    [[ "${FMT_STATE[txt]}"  == "ON" ]] && fmts+="TXT "
    [[ "${FMT_STATE[json]}" == "ON" ]] && fmts+="JSON"
    [[ -z "$fmts" ]] && fmts="(none)"

    [[ "${OPT_STATE[quiet]}"     == "ON" ]] && opts+="quiet "
    [[ "${OPT_STATE[parallel]}"  == "ON" ]] && opts+="parallel "
    [[ "${OPT_STATE[no-color]}"  == "ON" ]] && opts+="no-color "
    [[ "${OPT_STATE[remediate]}" == "ON" ]] && opts+="remediate "
    [[ "${OPT_STATE[baseline]}"  == "ON" ]] && opts+="baseline "
    [[ "${OPT_STATE[diff]}"      == "ON" ]] && opts+="diff"
    [[ -z "$opts" ]] && opts="(none)"

    local adv=""
    [[ -n "$OUTPUT_FILE" ]] && adv+="out=${OUTPUT_FILE##*/} "
    [[ -n "$REMOTE_HOST" ]] && adv+="remote=$REMOTE_HOST "
    [[ -n "$CONFIG_FILE" ]] && adv+="cfg=${CONFIG_FILE##*/} "
    [[ -n "$SCHEDULE"    ]] && adv+="schedule=$SCHEDULE"
    [[ -z "$adv" ]] && adv="(none)"

    printf 'Modules: %d/%d   Formats: %s\nOptions: %s\nAdvanced: %s' \
        "$mod_on" "${#MODULE_NAMES[@]}" "$fmts" "$opts" "$adv"
}

# ── Ch.13: select — plain-text fallback menu (non-TTY / -n flag) ──────────────
_plain_menu() {
    printf '\n%s安全  Anzen %s — Linux Security Audit (plain mode)%s\n\n' \
        "$C_CYN$C_BLD" "$ANZEN_VERSION" "$C_RST"

    PS3="  Select option [#]: "
    local choice
    select choice in \
        "Run audit — all modules" \
        "Run audit — select modules" \
        "Show version" \
        "Exit"
    do
        case "$REPLY" in
            1)
                printf '\nRunning full audit...\n\n'
                _run_with_output
                ;;
            2)
                printf '\nAvailable modules:\n'
                local i=1 m
                for m in "${MODULE_NAMES[@]}"; do printf '  %2d) %s\n' "$i" "$m"; i=$(( i + 1 )); done
                printf '\nEnter module names (space-separated): '
                local input; read -r input
                local args=()
                local input_arr=()
                read -ra input_arr <<< "$input"
                for m in "${input_arr[@]}"; do
                    [[ -v MOD_STATE[$m] ]] && args+=("--check=$m")
                done
                if [[ "${#args[@]}" -eq 0 ]]; then printf 'No valid modules given.\n'; continue; fi
                _run_with_output "${args[@]}"
                ;;
            3) printf 'anzen %s\n' "$ANZEN_VERSION" ;;
            4) exit 0 ;;
            *) printf 'Invalid option.\n' ;;
        esac
    done
}

# ── Main menu loop ────────────────────────────────────────────────────────────
main_menu() {
    while true; do
        _dims
        local status choice
        status=$(menu_status)
        choice=$(dlg \
            --title "  安全  Anzen $ANZEN_VERSION — Linux Security Audit  " \
            --cancel-button "Exit" \
            --menu "$status" \
            "$DH" "$DW" 7 \
            "1" "  Select Modules       (toggle individual checks)" \
            "2" "  Output Formats       (HTML / TXT / JSON)" \
            "3" "  Options              (quiet, parallel, baseline …)" \
            "4" "  Advanced             (output file, remote, config, schedule)" \
            "5" "  View Reports         (browse reports/ directory)" \
            "6" "  About" \
            "7" "  Run Audit") || exit 0

        case "$choice" in
            1) select_modules    ;;
            2) select_formats    ;;
            3) select_options    ;;
            4) advanced_settings ;;
            5) _offer_view_reports ;;
            6) show_about        ;;
            7) run_audit         ;;
        esac
    done
}

# ── Entry point ───────────────────────────────────────────────────────────────
if [[ "$FORCE_PLAIN" == true || ! -t 0 || ! -t 1 ]]; then
    _plain_menu
else
    main_menu
fi
