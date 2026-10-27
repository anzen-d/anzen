#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 The Anzen contributors
# checks/cve.sh — Known vulnerabilities (CVEs) in host packages and container images
# Uses trivy (https://trivy.dev); its vulnerability database updates itself.
# One finding per vulnerable package: CRITICAL → FAIL, HIGH → WARN.

# Tab-separated rows: target, package, installed, fixed, severity, CVE
_CVE_TEMPLATE='{{range .}}{{$t:=.Target}}{{range .Vulnerabilities}}{{$t}}{{"\t"}}{{.PkgName}}{{"\t"}}{{.InstalledVersion}}{{"\t"}}{{.FixedVersion}}{{"\t"}}{{.Severity}}{{"\t"}}{{.VulnerabilityID}}{{"\n"}}{{end}}{{end}}'

_cve_trivy_args() {
    local args=(--quiet --scanners vuln --severity "${CVE_SEVERITY:-CRITICAL,HIGH}"
                --timeout "${CVE_TIMEOUT:-60m}"
                --format template --template "$_CVE_TEMPLATE")
    [ "${CVE_IGNORE_UNFIXED:-true}" = "true" ] && args+=(--ignore-unfixed)
    printf '%s\n' "${args[@]}"
}

# _cve_report WHERE REMEDY_FMT — read trivy rows on stdin, emit one finding
# per package+version: counts, up to three CVE IDs and the fixed version
_cve_report() {
    local where=$1 remedy_fmt=$2 level pkg msg fix
    while IFS=$'\t' read -r level pkg msg fix; do
        if [ "$level" = "FAIL" ]; then fail "$msg"; else warn "$msg"; fi
        # shellcheck disable=SC2059  # the format is ours, %s is the package
        remedy "$(printf "$remedy_fmt" "$pkg")${fix:+  # fixed in $fix}"
    done < <(awk -F'\t' -v where="$where" '
        {
            # OS package targets look like "name (ubuntu 24.04)"; anything else
            # (a binary, jar or lockfile path, "Node.js"…) is named in the finding
            loc = ($1 ~ / \([a-z]+ [0-9.]+\)$/) ? "" : $1
            if (loc ~ /\//) loc = "/" loc
            k = $2 "\t" $3 "\t" loc
            if (!(k in seen)) { seen[k] = 1; order[++n] = k; fixed[k] = $4 }
            # A CVE can be listed once per target/file: count it once
            if ((k, $6) in cve) next
            cve[k, $6] = 1
            if ($5 == "CRITICAL") crit[k]++; else high[k]++
            if (++cnt[k] <= 3) ids[k] = ids[k] (ids[k] == "" ? "" : " ") $6
        }
        END {
            for (i = 1; i <= n; i++) {
                k = order[i]; split(k, p, "\t")
                sev = (crit[k] ? crit[k] " CRITICAL" : "") (crit[k] && high[k] ? ", " : "") (high[k] ? high[k] " HIGH" : "")
                more = cnt[k] > 3 ? " +" (cnt[k] - 3) " more" : ""
                fx = fixed[k]; sub(/,.*/, "", fx)
                printf "%s\t%s\t%s %s in %s%s: %s — %s%s\t%s\n", (crit[k] ? "FAIL" : "WARN"), p[1], \
                    p[1], p[2], where, (p[3] == "" ? "" : " " p[3]), sev, ids[k], more, fx
            }
        }')
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
    elif [ -s "$rows" ]; then
        _cve_report "host" "apt-get install --only-upgrade %s  # OS package; otherwise update the app that ships it" < "$rows"
    else
        ok "No ${CVE_SEVERITY:-CRITICAL,HIGH} CVEs with a fix available on the host"
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
        elif [ -s "$rows" ]; then
            _cve_report "$image [$names]" "$rt pull ${image//%/%%} && recreate ${names//%/%%}  # %s" < "$rows"
        else
            clean=$((clean + 1))
        fi
    done < <("$rt" ps --format '{{.Image}}\t{{.Names}}' 2>/dev/null \
             | awk -F'\t' '{ if (!($1 in n)) order[++c] = $1; n[$1] = (n[$1] ? n[$1] "," : "") $2 }
                           END { for (i = 1; i <= c; i++) print order[i] "\t" n[order[i]] }')
    info "$scanned running image(s) scanned, $clean without ${CVE_SEVERITY:-CRITICAL,HIGH} CVEs that have a fix"
}
