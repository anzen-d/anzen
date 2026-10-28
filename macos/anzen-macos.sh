#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 The Anzen contributors
#
# Anzen (安全) for macOS — security audit with the same report format as anzen.sh.
#
# Runs with the Bash 3.2 that ships with macOS (no Homebrew needed). Reports use
# the same finding IDs, accept-file format, JSON layout and history layout as
# the Linux and Windows editions, so one anzen dashboard covers all three.
#
#   sudo ./macos/anzen-macos.sh            # audit this Mac
#   sudo ./macos/anzen-macos.sh --json     # + reports/anzen_<timestamp>.json
#   ./macos/anzen-macos.sh --help
#
# Root gives complete results (sharing services, admin settings); without it the
# script still runs and says which checks were limited.

set -u

ANZEN_VERSION="0.11.5"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
FAIL_PENALTY=10
WARN_PENALTY=3
SOCKETFILTERFW="${ANZEN_SOCKETFILTERFW:-/usr/libexec/ApplicationFirewall/socketfilterfw}"
# Overridable for tests
SYSTEM_ROOTS_KEYCHAIN="${ANZEN_SYSTEM_ROOTS_KEYCHAIN:-/System/Library/Keychains/SystemRootCertificates.keychain}"
SYSTEM_KEYCHAIN="${ANZEN_SYSTEM_KEYCHAIN:-/Library/Keychains/System.keychain}"
CERT_PEM="${ANZEN_CERT_PEM:-/etc/ssl/cert.pem}"
HOMEBREW_BUNDLES="${ANZEN_HOMEBREW_BUNDLES-/opt/homebrew/etc/ca-certificates/cert.pem /usr/local/etc/ca-certificates/cert.pem /opt/homebrew/etc/openssl@3/cert.pem /usr/local/etc/openssl@3/cert.pem}"
CHECK_RUNTIMES="${ANZEN_CHECK_RUNTIMES:-1}"   # Python certifi, Java cacerts

MODULES="system updates filevault sip gatekeeper firewall sharing accounts ssh truststore"

usage() {
    cat <<EOF
Anzen $ANZEN_VERSION — macOS Security Audit

Usage: $0 [options]

  --check=MODULE     Run only this module (repeatable). Modules:
                     $MODULES
  --json             Write a JSON report (reports/anzen_<timestamp>.json, or --output)
  --output=FILE      Path for the JSON report
  --history=DIR      Save the run as DIR/<host>/<UTC timestamp>.json (anzen history layout)
  --accept=FILE      Accepted risks: "ID YYYY-MM-DD reason" per line (default: anzen.accept)
  --quiet, -q        Hide INFO lines and section banners
  --no-color         Plain output (NO_COLOR is honoured too)
  --strict           Exit 1 on WARN as well as FAIL
  --list             List modules
  --version, -v      Print version
  --help, -h         This help
EOF
}

# ── Arguments ────────────────────────────────────────────────────────────────
CHECKS=""; JSON=false; OUTPUT=""; HISTORY=""; ACCEPT_FILE="$ROOT_DIR/anzen.accept"
QUIET=false; STRICT=false; COLOR=true
[ -n "${NO_COLOR:-}" ] && COLOR=false
for arg in "$@"; do
    case $arg in
        --check=*)   CHECKS="$CHECKS ${arg#*=}" ;;
        --json)      JSON=true ;;
        --output=*)  OUTPUT="${arg#*=}"; JSON=true ;;
        --history=*) HISTORY="${arg#*=}" ;;
        --accept=*)  ACCEPT_FILE="${arg#*=}" ;;
        --quiet|-q)  QUIET=true ;;
        --no-color)  COLOR=false ;;
        --strict)    STRICT=true ;;
        --list)      for m in $MODULES; do echo "$m"; done; exit 0 ;;
        --version|-v) echo "anzen-macos $ANZEN_VERSION"; exit 0 ;;
        --help|-h)   usage; exit 0 ;;
        *)           echo "Unknown option: $arg  (try --help)" >&2; exit 1 ;;
    esac
done
for c in $CHECKS; do
    case " $MODULES " in *" $c "*) ;; *) echo "Unknown module: $c  (valid: $MODULES)" >&2; exit 1 ;; esac
done

if $COLOR; then
    RED=$'\033[0;31m'; YELLOW=$'\033[1;33m'; GREEN=$'\033[0;32m'; CYAN=$'\033[0;36m'; BOLD=$'\033[1m'; NC=$'\033[0m'
else
    RED=''; YELLOW=''; GREEN=''; CYAN=''; BOLD=''; NC=''
fi

FINDINGS=$(mktemp "${TMPDIR:-/tmp}/anzen-macos.XXXXXX")
trap 'rm -f "$FINDINGS" "$FINDINGS.tmp"' EXIT
SECTION="General"

# ── Finding IDs (same scheme as lib/output.sh _finding_id) ───────────────────
# Section slug + first 8 hex of the MD5 of the lower-cased message with
# volatile numbers normalised. GNU sed spells the word boundary \b; macOS
# (BSD) sed has [[:<:]] and [[:>:]] instead.
if sed --version >/dev/null 2>&1; then _WB_END='\b'; _WB_START='\b'; else _WB_END='[[:>:]]'; _WB_START='[[:<:]]'; fi

_md5() { if command -v md5sum >/dev/null 2>&1; then md5sum | cut -c1-8; else md5 -q | cut -c1-8; fi; }

_finding_id() {
    local slug norm
    slug=$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]' | tr -cs 'a-z0-9' '-')
    slug="${slug#-}"; slug="${slug%-}"
    norm=$(printf '%s' "$2" | tr '[:upper:]\t\n' '[:lower:]  ' | sed -E \
        -e "s/[0-9]+(\\.[0-9]+)? ?(%|[kmgtp]i?b?${_WB_END}|days?${_WB_END}|hours?${_WB_END}|minutes?${_WB_END}|seconds?${_WB_END}|ms${_WB_END})/#\\2/g" \
        -e 's/\(([0-9]+)( [a-z]+)*\)/(#)/g' \
        -e "s/${_WB_START}[0-9]+ (found|files?|entries|items|packages?|updates?|failed|attempts?|services?|containers?|users?|accounts?|rules?|processes|connections?)${_WB_END}/# \\1/g" \
        -e 's/[[:space:]]+/ /g')
    printf '%s-%s' "$slug" "$(printf '%s' "$norm" | _md5)"
}

# Tests source the script for its functions only (tests/macos/check-ids.sh)
if [ "${ANZEN_SOURCE_ONLY:-}" = 1 ]; then return 0 2>/dev/null || exit 0; fi

# ── Accepted risks ───────────────────────────────────────────────────────────
ACCEPTED=""   # "ID<TAB>UNTIL<TAB>REASON" lines
if [ -f "$ACCEPT_FILE" ]; then
    while read -r id until reason; do
        case $id in ''|\#*) continue ;; esac
        case $until in
            [0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]) ACCEPTED="$ACCEPTED$id	$until	${reason:-no reason given}
" ;;
            *) echo "[WARN] $ACCEPT_FILE: '$id' needs an expiry date (YYYY-MM-DD) — ignored" >&2 ;;
        esac
    done < "$ACCEPT_FILE"
fi

# ── Output ───────────────────────────────────────────────────────────────────
section() {
    SECTION=$1
    $QUIET && return 0
    printf '\n%s━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━%s\n%s  %s%s\n%s━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━%s\n' \
        "$BOLD$CYAN" "$NC" "$BOLD$CYAN" "$1" "$NC" "$BOLD$CYAN" "$NC"
}

# _add LEVEL MESSAGE [REMEDY]
_add() {
    local level=$1 msg remedy=${3:-} id note="" acc until reason
    msg=$(printf '%s' "$2" | tr '\t\n' '  ')
    id=$(_finding_id "$SECTION" "$msg")
    if [ "$level" = FAIL ] || [ "$level" = WARN ]; then
        acc=$(printf '%s' "$ACCEPTED" | awk -F'\t' -v id="$id" '$1 == id { print $2 "\t" $3; exit }')
        if [ -n "$acc" ]; then
            until=${acc%%	*}; reason=${acc#*	}
            if [ "$until" \> "$(date +%Y-%m-%d)" ] || [ "$until" = "$(date +%Y-%m-%d)" ]; then
                level=INFO; note=" [accepted until $until: $reason]"
            else
                note=" [acceptance expired $until: $reason]"
            fi
        fi
    fi
    printf '%s\t%s\t%s\t%s\t%s\n' "$level" "$SECTION" "$msg$note" "$id" "$(printf '%s' "$remedy" | tr '\t\n' '  ')" >> "$FINDINGS"
    case $level in
        FAIL) printf '%s[FAIL]%s %s\n' "$RED" "$NC" "$msg$note" ;;
        WARN) printf '%s[WARN]%s %s\n' "$YELLOW" "$NC" "$msg$note" ;;
        OK)   printf '%s[ OK ]%s %s\n' "$GREEN" "$NC" "$msg$note" ;;
        INFO) $QUIET || printf '%s[INFO]%s %s\n' "$CYAN" "$NC" "$msg$note" ;;
    esac
}
ok()   { _add OK "$1"; }
info() { _add INFO "$1"; }
warn() { _add WARN "$1" "${2:-}"; }
fail() { _add FAIL "$1" "${2:-}"; }

IS_ROOT=false; [ "$(id -u)" -eq 0 ] && IS_ROOT=true
_defaults() { defaults read "$1" "$2" 2>/dev/null; }

# ── Checks ───────────────────────────────────────────────────────────────────
check_system() {
    section "System Information"
    info "macOS $(sw_vers -productVersion 2>/dev/null) (build $(sw_vers -buildVersion 2>/dev/null)) on $(uname -m)"
    local boot now days
    # "{ sec = 1730000000, usec = 123 } …" — anchor on "{ sec", ".*sec" would hit usec
    boot=$(sysctl -n kern.boottime 2>/dev/null | sed -nE 's/^[{] *sec = ([0-9]+).*/\1/p')
    now=$(date +%s)
    if [ -n "$boot" ] && [ "$boot" -gt 0 ] 2>/dev/null; then
        days=$(( (now - boot) / 86400 ))
        info "Uptime: $days days"
        [ "$days" -gt 45 ] && warn "System not restarted for $days days — installed updates may be waiting for a restart" "sudo shutdown -r now"
    fi
    local line pct mount
    # Since macOS 11, / is the sealed read-only system volume; user data lives on
    # /System/Volumes/Data, which is the one that fills up
    local skip_root=0; df -P -l 2>/dev/null | awk '$6 == "/System/Volumes/Data"' | grep -q . && skip_root=1
    df -P -l 2>/dev/null | awk -v sr="$skip_root" 'NR > 1 && !(sr && $6 == "/") && $6 !~ "^/(System/Volumes/(VM|Preboot|Update|xarts|iSCPreboot|Hardware)|dev)"' \
        | while read -r line; do
              pct=$(echo "$line" | awk '{ sub(/%/, "", $5); print $5 }')
              mount=$(echo "$line" | awk '{ print $6 }')
              [ -n "$pct" ] || continue
              if [ "$pct" -ge 90 ]; then echo "FAIL|Disk $mount: $pct% used"
              elif [ "$pct" -ge 75 ]; then echo "WARN|Disk $mount: $pct% used"
              else echo "OK|Disk $mount: $pct% used"; fi
          done > "$FINDINGS.tmp"
    while IFS='|' read -r lvl msg; do
        case $lvl in FAIL) fail "$msg" "Storage settings → Manage, or: du -sh ~/* | sort -h" ;; WARN) warn "$msg" ;; OK) ok "$msg" ;; esac
    done < "$FINDINGS.tmp"
}

check_updates() {
    section "Software Update"
    local p=/Library/Preferences/com.apple.SoftwareUpdate key val
    for key in AutomaticCheckEnabled AutomaticDownload CriticalUpdateInstall ConfigDataInstall; do
        val=$(_defaults "$p" "$key")
        case "$key:$val" in
            *:1) ok "$key enabled" ;;
            CriticalUpdateInstall:0|ConfigDataInstall:0)
                fail "$key disabled — security responses and XProtect/Gatekeeper data are not installed" "sudo defaults write $p $key -bool true" ;;
            *:0) warn "$key disabled" "sudo defaults write $p $key -bool true" ;;
            *:)  info "$key not set (macOS default applies)" ;;
        esac
    done
    local n
    n=$(_defaults "$p" LastRecommendedUpdatesAvailable)
    if [ -n "$n" ] && [ "$n" -gt 0 ] 2>/dev/null; then
        warn "$n recommended update(s) available" "softwareupdate --install --all --restart"
    elif [ -n "$n" ]; then
        ok "No recommended updates pending"
    fi
}

check_filevault() {
    section "FileVault"
    local s; s=$(fdesetup status 2>/dev/null)
    case $s in
        *"FileVault is On"*)  ok "FileVault is on" ;;
        *"FileVault is Off"*) fail "FileVault is off — the disk is readable by anyone with physical access" "sudo fdesetup enable" ;;
        *"in progress"*)      info "FileVault encryption in progress" ;;
        *) info "FileVault status unavailable" ;;
    esac
}

check_sip() {
    section "System Integrity Protection"
    local s; s=$(csrutil status 2>/dev/null)
    case $s in
        *"status: enabled"*)  ok "System Integrity Protection enabled" ;;
        *"status: disabled"*) fail "System Integrity Protection disabled" "Boot into Recovery, then: csrutil enable" ;;
        *"Custom Configuration"*|*"unknown"*) warn "System Integrity Protection in a custom/partial configuration" "Boot into Recovery, then: csrutil enable" ;;
        *) info "SIP status unavailable" ;;
    esac
}

check_gatekeeper() {
    section "Gatekeeper"
    local s; s=$(spctl --status 2>/dev/null)
    case $s in
        *"assessments enabled"*)  ok "Gatekeeper enabled" ;;
        *"assessments disabled"*) fail "Gatekeeper disabled — unsigned apps run without checks" "sudo spctl --master-enable" ;;
        *) info "Gatekeeper status unavailable" ;;
    esac
}

check_firewall() {
    section "Application Firewall"
    if [ ! -x "$SOCKETFILTERFW" ]; then info "socketfilterfw not found"; return 0; fi
    local s; s=$("$SOCKETFILTERFW" --getglobalstate 2>/dev/null)
    case $s in
        *"enabled"*|*"State = 1"*|*"State = 2"*) ok "Application firewall enabled" ;;
        *"disabled"*|*"State = 0"*) warn "Application firewall disabled" "sudo $SOCKETFILTERFW --setglobalstate on" ;;
        *) info "Firewall state unavailable" ;;
    esac
    case $("$SOCKETFILTERFW" --getstealthmode 2>/dev/null) in
        *"enabled"*|*"is on"*) ok "Stealth mode enabled" ;;
        *"disabled"*|*"is off"*) warn "Stealth mode disabled (Mac answers pings and port probes)" "sudo $SOCKETFILTERFW --setstealthmode on" ;;
    esac
}

check_sharing() {
    section "Sharing Services"
    # Listening TCP ports on all interfaces, from netstat (works without root)
    local ports; ports=$(netstat -an -p tcp 2>/dev/null | awk '$NF == "LISTEN" && ($4 ~ /^\*\./ || $4 ~ /^0\.0\.0\.0\./) { n = split($4, a, "."); print a[n] }' | sort -un)
    local found=false port name fix
    for spec in "22|Remote Login (SSH)|sudo systemsetup -setremotelogin off" \
                "5900|Screen Sharing / Remote Management (VNC)|System Settings → General → Sharing → Screen Sharing off" \
                "3283|Apple Remote Desktop|System Settings → General → Sharing → Remote Management off" \
                "445|File Sharing (SMB)|System Settings → General → Sharing → File Sharing off" \
                "548|File Sharing (AFP)|System Settings → General → Sharing → File Sharing off" \
                "3389|Remote Desktop (RDP)|stop the RDP server" \
                "631|Printer Sharing|System Settings → General → Sharing → Printer Sharing off"; do
        port=${spec%%|*}; name=${spec#*|}; fix=${name#*|}; name=${name%%|*}
        if printf '%s\n' "$ports" | grep -qx "$port"; then
            warn "$name is listening on all interfaces (port $port)" "$fix"
            found=true
        fi
    done
    $found || ok "No remote access or file sharing services listening"
    [ -n "$ports" ] && info "TCP ports listening on all interfaces: $(printf '%s' "$ports" | tr '\n' ' ')"
}

check_accounts() {
    section "Accounts"
    local p=/Library/Preferences/com.apple.loginwindow v
    v=$(_defaults "$p" autoLoginUser)
    if [ -n "$v" ]; then
        fail "Automatic login enabled for '$v'" "sudo defaults delete $p autoLoginUser; sudo rm -f /etc/kcpassword"
    else
        ok "Automatic login disabled"
    fi
    [ -f /etc/kcpassword ] && fail "/etc/kcpassword exists (stored auto-login password)" "sudo rm -f /etc/kcpassword"
    v=$(_defaults "$p" GuestEnabled)
    if [ "$v" = 1 ]; then warn "Guest account enabled" "sudo defaults write $p GuestEnabled -bool false"
    else ok "Guest account disabled"; fi
    local admins n
    admins=$(dscl . -read /Groups/admin GroupMembership 2>/dev/null | sed 's/^GroupMembership: *//')
    if [ -n "$admins" ]; then
        n=$(printf '%s\n' $admins | grep -vc '^root$')
        info "Administrators: $admins"
        [ "$n" -gt 2 ] && warn "$n administrator accounts — use a standard account for daily work" "System Settings → Users & Groups"
    fi
    v=$(_defaults /Library/Preferences/com.apple.screensaver askForPassword)
    [ "$v" = 0 ] && warn "Password not required after screen saver / sleep (system default)" "System Settings → Lock Screen → Require password immediately"
}

check_ssh() {
    section "SSH Configuration"
    local cfg=/etc/ssh/sshd_config v
    if ! netstat -an -p tcp 2>/dev/null | awk '$NF == "LISTEN"' | grep -qE '[.:]22 '; then
        info "Remote Login (SSH) not listening — skipping"
        return 0
    fi
    v=$( { cat "$cfg" /etc/ssh/sshd_config.d/*.conf 2>/dev/null; } | awk 'tolower($1) == "permitrootlogin" { print tolower($2); exit }')
    case $v in
        yes) fail "PermitRootLogin yes — direct root login allowed" "echo 'PermitRootLogin no' | sudo tee /etc/ssh/sshd_config.d/100-anzen.conf" ;;
        *) ok "Root login over SSH not allowed (${v:-default})" ;;
    esac
    v=$( { cat /etc/ssh/sshd_config.d/*.conf "$cfg" 2>/dev/null; } | awk 'tolower($1) == "passwordauthentication" { print tolower($2); exit }')
    case $v in
        no) ok "SSH password authentication disabled" ;;
        *)  warn "SSH password authentication enabled — prefer keys" "echo 'PasswordAuthentication no' | sudo tee /etc/ssh/sshd_config.d/100-anzen.conf" ;;
    esac
}

# Distrusted CA certificates: same list and fingerprint scheme as the Linux
# truststore module (SHA-256 of the DER certificate)
_sha256() { if command -v sha256sum >/dev/null 2>&1; then sha256sum; else shasum -a 256; fi; }
_sha1() { if command -v sha1sum >/dev/null 2>&1; then sha1sum; else shasum -a 1; fi; }

# _pem_certs — PEM on stdin → "FINGERPRINT<TAB>BASE64" per certificate
_pem_certs() {
    awk '/-----BEGIN CERTIFICATE-----/ { b64 = ""; on = 1; next }
         /-----END CERTIFICATE-----/   { if (on) print b64; on = 0; next }
         on { gsub(/[ \r\t]/, ""); b64 = b64 $0 }' \
    | while IFS= read -r b64; do
          printf '%s\t%s\n' "$(printf '%s' "$b64" | base64 --decode 2>/dev/null | _sha256 | awk '{ print toupper($1) }')" "$b64"
      done
}

# _ts_hits CERTS — "FINGERPRINT<TAB>BASE64" lines → matching list entries, each
# as "SEV<TAB>INCIDENT<TAB>NAME<TAB>REF<TAB>BASE64". Runs in a command
# substitution, so callers count certificates themselves (_ts_count)
TS_CHECKED=0; TS_FOUND=0
_ts_count() { [ -n "$1" ] && TS_CHECKED=$(( TS_CHECKED + $(printf '%s\n' "$1" | grep -c .) )); return 0; }
_ts_hits() {
    [ -n "$1" ] || return 0
    grep -vE '^[[:space:]]*(#|$)' "$ROOT_DIR/lib/data/distrusted-certs.tsv" \
        | awk -F'\t' 'NR == FNR { bad[$1] = $2 "\t" $3 "\t" $4 "\t" $5; next } $1 in bad { print bad[$1] "\t" $2 }' \
              - <(printf '%s\n' "$1") | sort -u
}

# _ts_report LABEL REMEDY — plain file bundles: every listed certificate counts
_ts_report() {
    local certs hits sev inc name ref _b64
    certs=$(cat)
    _ts_count "$certs"
    hits=$(_ts_hits "$certs")
    [ -n "$hits" ] || return 0
    while IFS='	' read -r sev inc name ref _b64; do
        if [ "$sev" = WARN ]; then warn "Distrusted certificate in $1: $name [$inc]" "$2  # $ref"
        else fail "Distrusted certificate in $1: $name [$inc]" "$2  # $ref"; fi
    done <<< "$hits"
    TS_FOUND=1
}

# _ts_keychain KEYCHAIN — Apple blocks distrusted CAs in TLS trust evaluation
# while the certificate stays in SystemRootCertificates.keychain (confirmed on
# macOS 26.6.2: connections fail with -1202, yet `security verify-cert -p basic`
# still says trusted, so no local command shows the block). A match there is
# INFO; one in a keychain the user or an admin added it to is a FAIL
_ts_keychain() {
    local kc=$1 certs hits sev inc name ref b64 sha1
    certs=$(security find-certificate -a -p "$kc" 2>/dev/null | _pem_certs)
    _ts_count "$certs"
    hits=$(_ts_hits "$certs")
    [ -n "$hits" ] || return 0
    while IFS='	' read -r sev inc name ref b64; do
        if [ "$kc" = "$SYSTEM_ROOTS_KEYCHAIN" ]; then
            info "$name is in $(basename "$kc") — Apple blocks the compromised chain in TLS; keep macOS updated [$inc]"
        else
            sha1=$(printf '%s' "$b64" | base64 --decode 2>/dev/null | _sha1 | awk '{ print toupper($1) }')
            fail "Distrusted certificate added to $(basename "$kc"): $name [$inc]" "sudo security delete-certificate -Z $sha1 \"$kc\"  # $ref"
            TS_FOUND=1
        fi
    done <<< "$hits"
}

check_truststore() {
    section "Trust Stores"
    if [ ! -f "$ROOT_DIR/lib/data/distrusted-certs.tsv" ]; then info "Distrusted certificate list not found"; return 0; fi
    info "Distrusted certificate list: $(grep -vcE '^[[:space:]]*(#|$)' "$ROOT_DIR/lib/data/distrusted-certs.tsv") entries"
    TS_CHECKED=0; TS_FOUND=0
    local kc f
    for kc in "$SYSTEM_ROOTS_KEYCHAIN" "$SYSTEM_KEYCHAIN" \
              "$HOME/Library/Keychains/login.keychain-db"; do
        [ -f "$kc" ] && _ts_keychain "$kc"
    done

    # Command-line tools (curl, git, openssl, Homebrew's OpenSSL) read PEM
    # bundles directly and do not apply Apple's blocks
    # shellcheck disable=SC2086  # space-separated path list
    for f in "$CERT_PEM" $HOMEBREW_BUNDLES; do
        [ -f "$f" ] || continue
        case $f in
            "$CERT_PEM") _ts_report "$f (used by curl, git, openssl)" \
                "sudo cp /etc/ssl/cert.pem /etc/ssl/cert.pem.bak, then remove the listed root from /etc/ssl/cert.pem (Apple's interim guidance; a macOS update may restore it)" \
                < <(_pem_certs < "$f") ;;
            *) _ts_report "$f (Homebrew)" "brew upgrade ca-certificates openssl@3" < <(_pem_certs < "$f") ;;
        esac
    done

    [ "$CHECK_RUNTIMES" = 1 ] || { _ts_summary; return 0; }
    if command -v python3 >/dev/null 2>&1 && f=$(python3 -c 'import certifi; print(certifi.where())' 2>/dev/null) && [ -f "$f" ]; then
        _ts_report "Python certifi ($f)" "pip3 install -U certifi" < <(_pem_certs < "$f")
    fi
    if /usr/libexec/java_home >/dev/null 2>&1 && command -v keytool >/dev/null 2>&1; then
        _ts_report "Java cacerts" "update the JDK" < <(keytool -list -rfc -cacerts -storepass changeit 2>/dev/null | _pem_certs)
    fi
    _ts_summary
}

_ts_summary() {
    if [ "$TS_CHECKED" -eq 0 ]; then info "No certificate stores found to check"
    elif [ "$TS_FOUND" -eq 0 ]; then ok "No distrusted CA certificates trusted ($TS_CHECKED certificates checked)"; fi
}

# ── Run ──────────────────────────────────────────────────────────────────────
if ! $QUIET; then
    printf '\n%s   安全  Anzen %s — macOS Security Audit%s\n' "$BOLD$CYAN" "$ANZEN_VERSION" "$NC"
    printf '%s   Host: %s  |  %s%s\n' "$CYAN" "$(hostname -s 2>/dev/null || hostname)" "$(date)" "$NC"
fi
$IS_ROOT || echo "[WARN] Not running as root — some checks will be incomplete." >&2

for m in $MODULES; do
    if [ -n "$CHECKS" ]; then case " $CHECKS " in *" $m "*) ;; *) continue ;; esac; fi
    "check_$m"
done

# ── Summary and report ───────────────────────────────────────────────────────
SECTIONS=$(awk -F'\t' -v fp="$FAIL_PENALTY" -v wp="$WARN_PENALTY" '
    $1 == "FAIL" || $1 == "WARN" || $1 == "OK" { if (!($2 in seen)) { seen[$2] = 1; o[++n] = $2 } c[$2, $1]++ }
    END { for (i = 1; i <= n; i++) { s = o[i]; sc = 100 - c[s, "FAIL"] * fp - c[s, "WARN"] * wp; if (sc < 0) sc = 0
          printf "%s\t%d\t%d\t%d\t%d\n", s, c[s, "FAIL"], c[s, "WARN"], c[s, "OK"], sc } }' "$FINDINGS")
SCORE=$(printf '%s\n' "$SECTIONS" | awk -F'\t' 'NF { t += $5; n++ } END { print (n ? int(t / n + 0.5) : 100) }')
count() { awk -F'\t' -v l="$1" '$1 == l { n++ } END { print n + 0 }' "$FINDINGS"; }
N_FAIL=$(count FAIL); N_WARN=$(count WARN); N_OK=$(count OK); N_INFO=$(count INFO)

printf '\n%s━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━%s\n%s  SUMMARY%s\n%s━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━%s\n' "$BOLD" "$NC" "$BOLD" "$NC" "$BOLD" "$NC"
printf '%s\n' "$SECTIONS" | awk -F'\t' 'NF && ($2 || $3) { printf "  %-36s %3s%%   FAIL %-3s WARN %s\n", $1, $5, $2, $3 }'
printf '%s━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━%s\n' "$BOLD" "$NC"
printf '  %sFAIL: %s%s   %sWARN: %s%s   %sOK: %s%s   Score: %s%%\n' "$RED" "$N_FAIL" "$NC" "$YELLOW" "$N_WARN" "$NC" "$GREEN" "$N_OK" "$NC" "$SCORE"
printf '%s━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━%s\n' "$BOLD" "$NC"

# Same line layout as lib/report_json.sh — the history/dashboard parsers rely on it
json_escape() { sed -e 's/\\/\\\\/g' -e 's/"/\\"/g'; }
write_json() {
    local out=$1 host
    host=$(hostname -s 2>/dev/null || hostname)
    mkdir -p "$(dirname "$out")"
    {
        printf '{\n'
        printf '  "hostname": "%s",\n' "$(printf '%s' "$host" | tr '[:upper:]' '[:lower:]' | json_escape)"
        printf '  "os": "%s",\n' "$(printf 'macOS %s' "$(sw_vers -productVersion 2>/dev/null)" | json_escape)"
        printf '  "kernel": "%s",\n' "$(uname -r | json_escape)"
        printf '  "arch": "%s",\n' "$(uname -m)"
        printf '  "public_ip": "",\n'
        printf '  "audited_by": "%s",\n' "$(id -un | json_escape)"
        printf '  "version": "%s",\n' "$ANZEN_VERSION"
        printf '  "date": "%s",\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
        printf '  "summary": {"fail": %d, "warn": %d, "ok": %d, "info": %d, "score": %d},\n' "$N_FAIL" "$N_WARN" "$N_OK" "$N_INFO" "$SCORE"
        printf '  "sections": ['
        printf '%s\n' "$SECTIONS" | awk -F'\t' 'NF { gsub(/\\/, "&&", $1); gsub(/"/, "\\\"", $1)
            printf "%s\n    {\"name\": \"%s\", \"fail\": %d, \"warn\": %d, \"ok\": %d, \"score\": %d}", (n++ ? "," : ""), $1, $2, $3, $4, $5 }'
        printf '\n  ],\n  "findings": [\n'
        awk -F'\t' 'function esc(v) { gsub(/\\/, "&&", v); gsub(/"/, "\\\"", v); gsub(/[\001-\037]/, "", v); return v }
            { if (NR > 1) printf ",\n"
              printf "    {\"id\": \"%s\", \"level\": \"%s\", \"section\": \"%s\", \"message\": \"%s\", \"remedy\": \"%s\"}", esc($4), esc($1), esc($2), esc($3), esc($5) }' "$FINDINGS"
        printf '\n  ]\n}\n'
    } > "$out"
}

if $JSON; then
    [ -n "$OUTPUT" ] || OUTPUT="$ROOT_DIR/reports/anzen_$(date +%Y%m%d_%H%M%S).json"
    write_json "$OUTPUT"
    printf '%s  JSON      : %s%s\n' "$BOLD$CYAN" "$OUTPUT" "$NC"
fi
if [ -n "$HISTORY" ]; then
    h=$(hostname -s 2>/dev/null || hostname | cut -d. -f1)
    h=$(printf '%s' "$h" | tr '[:upper:]' '[:lower:]')
    f="$HISTORY/$h/$(date -u +%Y%m%dT%H%M%SZ).json"
    (umask 077; write_json "$f")
    printf '%s  History   : %s%s\n' "$BOLD$CYAN" "$f" "$NC"
fi

[ "$N_FAIL" -gt 0 ] && exit 1
$STRICT && [ "$N_WARN" -gt 0 ] && exit 1
exit 0
