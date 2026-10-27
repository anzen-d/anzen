#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 The Anzen contributors
# tests/macos/check-ids.sh — the macOS edition must compute the same finding IDs
# as the Linux edition. tests/fixtures/id-corpus.tsv holds SECTION, MESSAGE and
# the ID lib/output.sh computes; run on a Mac (BSD sed) in CI.
set -u
root="$(cd "$(dirname "$0")/../.." && pwd)"
ANZEN_SOURCE_ONLY=1 . "$root/macos/anzen-macos.sh"
fail=0; n=0
while IFS='	' read -r section message expected; do
    n=$((n + 1))
    got=$(_finding_id "$section" "$message")
    if [ "$got" != "$expected" ]; then
        echo "MISMATCH: [$section] $message: got $got, expected $expected"
        fail=1
    fi
done < "$root/tests/fixtures/id-corpus.tsv"
echo "$n IDs checked, $( [ $fail -eq 0 ] && echo 'all match' || echo 'mismatches found')"
exit $fail
