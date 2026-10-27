#!/bin/bash
# tests/distro-matrix.sh — run anzen inside minimal containers of each supported
# distro family and fail on shell-level errors (missing commands, bad
# arithmetic, unbound variables, syntax errors). Findings themselves do not
# matter here: a minimal container is "insecure" in many ways. What matters is
# that every module degrades gracefully when a tool or service is absent.
#
# Usage: tests/distro-matrix.sh [image ...]     (needs docker)
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Official images via mirrors that do not count against Docker Hub pull limits
IMAGES=(
    public.ecr.aws/docker/library/debian:12
    public.ecr.aws/docker/library/ubuntu:24.04
    quay.io/fedora/fedora:41
    quay.io/rockylinux/rockylinux:9
    public.ecr.aws/docker/library/alpine:3.20
    public.ecr.aws/docker/library/archlinux:latest
    registry.opensuse.org/opensuse/leap:15.6
)
[ "$#" -gt 0 ] && IMAGES=("$@")

# Every passive module; the active pentest modules probe the network
MODULES=$(sed -n '/^ALL_MODULES=(/,/)/p' "$ROOT/anzen.sh" | tr -d '()' | sed 's/ALL_MODULES=//' \
          | tr -s ' \n' '\n' | grep -vE '^(pentest|pentest_external)?$' | sed 's/^/--check=/' | tr '\n' ' ')

# Shell errors, never legitimate output
ERRORS='command not found|unbound variable|syntax error|integer expression expected|bad substitution|unexpected EOF|No such file or directory.*\.sh|division by 0|invalid arithmetic|ambiguous redirect'

# GitHub shows ::error lines as annotations, readable without log access
_annotate() { [ -n "${GITHUB_ACTIONS:-}" ] && echo "::error title=distro-matrix $1::$2"; return 0; }

fail=0
failed=()
for img in "${IMAGES[@]}"; do
    # Pull first: docker create would print pull progress next to the ID
    if ! perr=$(docker pull -q "$img" 2>&1); then
        echo "FAIL  $img (pull)"; _annotate "${img##*/}" "docker pull failed: $(tail -2 <<< "$perr" | tr '\n' ' ')"
        fail=1; failed+=("${img##*/}"); continue
    fi
    # docker cp, not a tar pipe: some minimal images (openSUSE) ship no tar
    if ! cid=$(docker create -i --entrypoint sh "$img" -c "
            command -v bash >/dev/null 2>&1 || apk add -q bash >/dev/null 2>&1
            cd /anzen && bash ./anzen.sh --no-color $MODULES 2>&1
            echo \"__EXIT=\$?\"" 2>/tmp/anzen-matrix-create.err); then
        echo "FAIL  $img (docker create)"; _annotate "${img##*/}" "docker create failed: $(tr '\n' ' ' < /tmp/anzen-matrix-create.err)"
        fail=1; failed+=("${img##*/}"); continue
    fi
    if ! cperr=$(docker cp "$ROOT/." "$cid:/anzen" 2>&1 >/dev/null); then
        echo "FAIL  $img (docker cp)"; _annotate "${img##*/}" "docker cp failed: $cperr"
        docker rm -f "$cid" >/dev/null 2>&1; fail=1; failed+=("${img##*/}"); continue
    fi
    out=$(timeout 600 docker start -a "$cid" 2>&1)
    docker rm -f "$cid" >/dev/null 2>&1
    rc=$(sed -n 's/^__EXIT=//p' <<< "$out")
    errs=$(grep -E "$ERRORS" <<< "$out" | sort | uniq -c | sort -rn)
    os=$(sed -n 's/.*OS: \(.*\)$/\1/p' <<< "$out" | sed 's/\x1b\[[0-9;]*m//g' | head -1)
    if [ -n "$errs" ] || [[ ! "$rc" =~ ^[01]$ ]]; then
        printf 'FAIL  %-48s exit=%s  %s\n' "$img" "${rc:-?}" "$os"
        sed 's/^/      /' <<< "$errs" | head -25
        _annotate "${img##*/}" "exit=${rc:-?} $(head -5 <<< "$errs" | tr '\n' ';' | cut -c1-500) | tail: $(tail -4 <<< "$out" | tr '\n' ';' | cut -c1-400)"
        fail=1; failed+=("${img##*/}")
    else
        printf 'ok    %-48s exit=%s  %s\n' "$img" "$rc" "$os"
    fi
done
[ "$fail" -ne 0 ] && _annotate summary "failed: ${failed[*]}"
exit "$fail"
