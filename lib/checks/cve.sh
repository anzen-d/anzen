#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 The Anzen contributors
# checks/cve.sh — Known vulnerabilities (CVEs) in host packages and container images
# Uses trivy (https://trivy.dev); its vulnerability database updates itself.
# One finding per vulnerable package: CRITICAL → FAIL, HIGH → WARN.
# CVEs in the CISA Known Exploited Vulnerabilities catalog (KEV_CHECK) are a
# FAIL at any severity, fix or no fix: they are being exploited right now.

# Tab-separated rows: target, package, installed, fixed, severity, CVE, published
_CVE_TEMPLATE='{{range .}}{{$t:=.Target}}{{range .Vulnerabilities}}{{$t}}{{"\t"}}{{.PkgName}}{{"\t"}}{{.InstalledVersion}}{{"\t"}}{{.FixedVersion}}{{"\t"}}{{.Severity}}{{"\t"}}{{.VulnerabilityID}}{{"\t"}}{{.PublishedDate}}{{"\n"}}{{end}}{{end}}'

# With the KEV list loaded, trivy reports every severity, fixed or not, and
# _cve_report applies CVE_SEVERITY / CVE_IGNORE_UNFIXED to non-KEV CVEs only
_cve_trivy_args() {
    local args=(--quiet --scanners vuln --timeout "${CVE_TIMEOUT:-60m}"
                --format template --template "$_CVE_TEMPLATE")
    if [ -n "$_KEV_FILE" ]; then
        args+=(--severity "UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL")
    else
        args+=(--severity "${CVE_SEVERITY:-CRITICAL,HIGH}")
        [ "${CVE_IGNORE_UNFIXED:-true}" = "true" ] && args+=(--ignore-unfixed)
    fi
    printf '%s\n' "${args[@]}"
}

# _kev_load — set _KEV_FILE to the cached KEV list ("CVE<TAB>ADDED<TAB>DUE<TAB>
# RANSOMWARE"), refreshed when older than a day; empty when unavailable
_KEV_FILE=""
_kev_load() {
    _KEV_FILE=""
    [ "${KEV_CHECK:-true}" = "true" ] || return 0
    local dir="${KEV_CACHE_DIR:-}"
    if [ -z "$dir" ]; then
        if [ "$EUID" -eq 0 ]; then dir=/var/cache/anzen; else dir="${XDG_CACHE_HOME:-$HOME/.cache}/anzen"; fi
    fi
    local cache="$dir/kev.tsv" tmp n
    if [ -s "$cache" ] && [ -n "$(find "$cache" -mmin -1440 2>/dev/null)" ]; then
        _KEV_FILE=$cache; return 0
    fi
    if command -v curl &>/dev/null && (umask 077; mkdir -p "$dir") 2>/dev/null; then
        tmp=$(mktemp "$dir/kev.XXXXXX")
        # Token per field, whatever the JSON layout; IDs validated before use
        curl -fsSL -m 60 "${KEV_URL:-https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json}" 2>/dev/null \
            | grep -oE '"(cveID|dateAdded|dueDate|knownRansomwareCampaignUse)": *"[^"]*"' \
            | awk -F'"' '$2 == "cveID" { if (id != "") print id "\t" a "\t" d "\t" r; id = $4; a = d = r = "" }
                         $2 == "dateAdded" { a = $4 } $2 == "dueDate" { d = $4 }
                         $2 == "knownRansomwareCampaignUse" { r = $4 }
                         END { if (id != "") print id "\t" a "\t" d "\t" r }' \
            | grep -E "^CVE-[0-9]{4}-[0-9]+"$'\t' > "$tmp"
        n=$(wc -l < "$tmp")
        # The catalog has well over a thousand entries; less means a broken download
        if [ "$n" -ge 500 ]; then mv "$tmp" "$cache"; _KEV_FILE=$cache; return 0; fi
        rm -f "$tmp"
    fi
    if [ -s "$cache" ]; then
        info "CISA KEV list could not be refreshed — using the cached copy from $(date -r "$cache" +%F 2>/dev/null)"
        _KEV_FILE=$cache
    else
        info "CISA KEV list unavailable (no network?) — exploited-CVE check skipped"
    fi
    return 0
}

# _cve_report WHERE REMEDY_FMT [image] — read trivy rows on stdin, emit one finding
# per package+version: counts, up to three CVE IDs (exploited ones first) and
# the fixed version; CVEs published in the last CVE_NEW_DAYS as one INFO line.
# Sets _CVE_N to the number of findings
_CVE_N=0
_cve_report() {
    local where=$1 remedy_fmt=$2 in_image=${3:-} level pkg msg fix cutoff
    _CVE_N=0
    cutoff=$(date -u -d "@$(( $(date +%s) - ${CVE_NEW_DAYS:-7} * 86400 ))" +%F 2>/dev/null)
    while IFS=$'\t' read -r level pkg msg fix; do
        if [ "$level" = "NEW" ]; then info "$msg"; continue; fi
        if [ "$level" = "FAIL" ]; then fail "$msg"; else warn "$msg"; fi
        # shellcheck disable=SC2059  # the format is ours, %s is the package
        remedy "$(printf "$remedy_fmt" "$pkg")${fix:+  # fixed in $fix}"
        _CVE_N=$((_CVE_N + 1))
    done < <(awk -F'\t' -v where="$where" -v in_image="$in_image" -v sevs=",${CVE_SEVERITY:-CRITICAL,HIGH}," \
                 -v unfixed="${CVE_IGNORE_UNFIXED:-true}" -v cutoff="$cutoff" -v newdays="${CVE_NEW_DAYS:-7}" '
        FILENAME == ARGV[1] { kev[$1] = 1; due[$1] = $3; rw[$1] = ($4 == "Known"); next }
        {
            # Containers run on the host kernel: kernel packages in an image
            # (linux-libc-dev headers and the like) are never the running kernel
            if (in_image != "" && $2 ~ /^(linux-(libc-dev|headers|image|modules|tools)|kernel(-headers|-devel)?$)/) next
            # Without KEV, trivy already filtered; with it, filter here except KEV
            if (!($6 in kev) && (index(sevs, "," $5 ",") == 0 || (unfixed == "true" && $4 == ""))) next
            # OS package targets look like "name (ubuntu 24.04)"; anything else
            # (a binary, jar or lockfile path, "Node.js"…) is named in the finding
            loc = ($1 ~ / \([a-z]+ [0-9.]+\)$/) ? "" : $1
            if (loc ~ /\//) loc = "/" loc
            k = $2 "\t" $3 "\t" loc
            if (!(k in seen)) { seen[k] = 1; order[++n] = k; fixed[k] = $4 }
            # A CVE can be listed once per target/file: count it once
            if ((k, $6) in cve) next
            cve[k, $6] = 1
            nsev[k, $5]++; cnt[k]++
            if ($6 in kev) {
                nkev[k]++; kids[k] = kids[k] (kids[k] == "" ? "" : " ") $6
                if (kdue[k] == "" || due[$6] < kdue[k]) kdue[k] = due[$6]
                if (rw[$6]) krw[k] = 1
            } else if (++oth[k] <= 3) ids[k] = ids[k] (ids[k] == "" ? "" : " ") $6
            # PublishedDate is ISO 8601: the date prefix compares as a string
            if (cutoff != "" && substr($7, 1, 10) >= cutoff && !(($6) in newseen)) {
                newseen[$6] = 1; newlist = newlist (newlist == "" ? "" : ", ") $6 " (" $2 ")"; nnew++
            }
        }
        END {
            split("CRITICAL HIGH MEDIUM LOW UNKNOWN", lv, " ")
            for (i = 1; i <= n; i++) {
                k = order[i]; split(k, p, "\t")
                sev = ""
                for (j = 1; j <= 5; j++) if (nsev[k, lv[j]]) sev = sev (sev == "" ? "" : ", ") nsev[k, lv[j]] " " lv[j]
                list = ids[k]; more = cnt[k] - nkev[k] - (oth[k] > 3 ? 3 : oth[k])
                if (more > 0) list = list " +" more " more"
                expl = ""
                if (nkev[k]) expl = "ACTIVELY EXPLOITED " kids[k] " (CISA KEV, due " kdue[k] (krw[k] ? ", used by ransomware" : "") ") — "
                fx = fixed[k]; sub(/,.*/, "", fx)
                printf "%s\t%s\t%s %s in %s%s: %s%s%s\t%s\n", (nsev[k, "CRITICAL"] || nkev[k] ? "FAIL" : "WARN"), p[1], \
                    p[1], p[2], where, (p[3] == "" ? "" : " " p[3]), expl, sev, (list == "" ? "" : " — " list), fx
            }
            # "-", not an empty field: read with IFS=tab collapses empty fields
            if (nnew) printf "NEW\t-\tPublished in the last %d days (%d): %s\t\n", newdays, nnew, newlist
        }' "${_KEV_FILE:-/dev/null}" -)
}

# _cve_scan KIND TARGET OUT — trivy rows into OUT; on failure sets _CVE_ERR
# (a failed scan must not read as "no CVEs"). Skip dirs apply to rootfs only.
_CVE_ERR=""
_cve_scan() {
    local kind=$1 target=$2 out=$3 err rc extra=()
    [ "$kind" = "rootfs" ] && extra=("${skip[@]}")
    err=$(mktemp)
    trivy "$kind" "${args[@]}" "${extra[@]}" "$target" >"$out" 2>"$err"
    rc=$?
    _CVE_ERR=""
    [ "$rc" -ne 0 ] && _CVE_ERR=$(grep -m1 -iE 'fatal|error' "$err" | cut -f3- | cut -c1-200)
    rm -f "$err"
    return "$rc"
}

run_cve_check() {
    section "Vulnerabilities (host)"

    if ! command -v trivy &>/dev/null; then
        info "trivy not installed — no CVE scan (https://trivy.dev; debsecan is used by the packages module as a fallback)"
        return 0
    fi

    _kev_load
    [ -n "$_KEV_FILE" ] && info "CISA KEV: $(wc -l < "$_KEV_FILE") actively exploited CVEs (list of $(date -r "$_KEV_FILE" +%F 2>/dev/null))"
    local -a args skip=()
    mapfile -t args < <(_cve_trivy_args)
    local d
    for d in ${CVE_SKIP_DIRS:-/proc /sys /dev /run /tmp /var/tmp /var/lib/docker /var/lib/containerd /var/lib/containers /snap}; do  # see config.sh
        skip+=(--skip-dirs "$d")
    done

    # Host: OS packages plus installed language packages (jars, node_modules, wheels…)
    local rows; rows=$(mktemp)
    # shellcheck disable=SC2064  # expand now: rows is local
    trap "rm -f '$rows'" RETURN
    if ! _cve_scan rootfs / "$rows"; then
        warn "Host CVE scan failed: ${_CVE_ERR:-trivy exited non-zero}"
    else
        _cve_report "host" "apt-get install --only-upgrade %s  # OS package; otherwise update the app that ships it" < "$rows"
        [ "$_CVE_N" -eq 0 ] && ok "No ${CVE_SEVERITY:-CRITICAL,HIGH} CVEs with a fix available on the host${_KEV_FILE:+, none actively exploited}"
    fi

    [ "${CVE_SCAN_IMAGES:-true}" = "true" ] || return 0
    local rt=""
    command -v docker &>/dev/null && docker info &>/dev/null && rt=docker
    [ -z "$rt" ] && command -v podman &>/dev/null && rt=podman
    [ -z "$rt" ] && return 0

    section "Vulnerabilities (containers)"
    # One scan per running image; each finding names the containers using it
    local image names clean=0 scanned=0
    while IFS=$'\t' read -r image names; do
        scanned=$((scanned + 1))
        if ! _cve_scan image "$image" "$rows"; then
            warn "CVE scan failed for $image: ${_CVE_ERR:-trivy exited non-zero}"
        else
            _cve_report "$image [$names]" "$rt pull ${image//%/%%} && recreate ${names//%/%%}  # %s" image < "$rows"
            [ "$_CVE_N" -eq 0 ] && clean=$((clean + 1))
        fi
    done < <("$rt" ps --format '{{.Image}}\t{{.Names}}' 2>/dev/null \
             | awk -F'\t' '{ if (!($1 in n)) order[++c] = $1; n[$1] = (n[$1] ? n[$1] "," : "") $2 }
                           END { for (i = 1; i <= c; i++) print order[i] "\t" n[order[i]] }')
    info "$scanned running image(s) scanned, $clean without ${CVE_SEVERITY:-CRITICAL,HIGH} CVEs that have a fix"
}
