#!/usr/bin/env bats
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 The Anzen contributors
# tests/test_checks_files.bats — world-writable and SUID/SGID scan

setup() {
    ANZEN_DIR="$(cd "$(dirname "$BATS_TEST_FILENAME")/.." && pwd)"
    FINDINGS_FILE="$(mktemp)"
    NO_COLOR=true QUIET=true
    export ANZEN_DIR FINDINGS_FILE NO_COLOR QUIET
    # shellcheck disable=SC1091
    source "$ANZEN_DIR/lib/output.sh"
    # shellcheck disable=SC1091
    source "$ANZEN_DIR/lib/utils.sh"
    T="$BATS_TEST_TMPDIR"
}

teardown() { rm -f "$FINDINGS_FILE" "${FINDINGS_FILE}.tmp"; }

@test "files: image layers of containerd are pruned and never a SUID finding" {
    local layer="$T/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/1/fs/usr/bin"
    local k3s="$T/var/lib/rancher/k3s/agent/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/1/fs/bin"
    mkdir -p "$layer" "$k3s" "$T/opt"
    touch "$layer/su" "$k3s/tool" "$T/opt/tool"
    chmod 4755 "$layer/su" "$k3s/tool" "$T/opt/tool"
    # shellcheck disable=SC1091
    source "$ANZEN_DIR/lib/checks/files.sh"
    # The walk itself is stubbed: the walk of / records its arguments and returns the three files
    # shellcheck disable=SC2329
    find() {
        [ "$1" = / ] || return 0   # the cron directory scans find nothing
        printf '%s\n' "$@" > "$T/find.args"; printf '%s\n' "$layer/su" "$k3s/tool" "$T/opt/tool"
    }
    run_files_check > /dev/null
    grep -q "^WARN	SUID / SGID Binaries	Unexpected SUID/SGID binary: $T/opt/tool	" "$FINDINGS_FILE"
    [ "$(grep -c containerd "$FINDINGS_FILE")" -eq 0 ]
    grep -qx "/var/lib/containerd" "$T/find.args"
    grep -qx "/var/lib/rancher/k3s/agent/containerd" "$T/find.args"
}
