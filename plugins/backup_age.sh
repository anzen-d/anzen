#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 The Anzen contributors
# plugins/backup_age.sh — fail when the newest backup is too old
#
# Settings (anzen.conf):
#   BACKUP_AGE_PATHS="PATH:MAX_DAYS ..."   e.g. "/srv/restic/snapshots:2 /var/backups/db:1"
#   BACKUP_AGE_DEPTH=2                     how deep to look for the newest file
#
# Point a restic repository at its snapshots/ directory (one small file per
# snapshot), Borg at the repository root, file-based backups at their folder.

run_backup_age_check() {
    section "Backup Age"

    if [ -z "${BACKUP_AGE_PATHS:-}" ]; then
        info "BACKUP_AGE_PATHS not set — nothing to check"
        return
    fi

    local entry path max newest now age_h
    now=$(date +%s)
    for entry in $BACKUP_AGE_PATHS; do
        path=${entry%:*}
        max=${entry##*:}
        if [ "$path" = "$entry" ] || ! [[ "$max" =~ ^[0-9]+$ ]]; then
            warn "BACKUP_AGE_PATHS entry '$entry' is not PATH:MAX_DAYS"
            continue
        fi
        if ! _priv test -e "$path"; then
            fail "Backup location missing: $path"
            remedy "# check that $(_q "$path") is mounted and the backup job runs"
            continue
        fi
        newest=$(_priv find "$path" -maxdepth "${BACKUP_AGE_DEPTH:-2}" -type f \
            -exec stat -c %Y {} + 2>/dev/null | sort -n | tail -1)
        if [ -z "$newest" ]; then
            fail "No backup files in $path"
            continue
        fi
        age_h=$(( (now - newest) / 3600 ))
        if [ "$age_h" -gt $((max * 24)) ]; then
            fail "Newest backup in $path is $age_h hours old (limit $max days)"
            remedy "# check the backup job that writes to $(_q "$path") and its logs"
        else
            ok "Newest backup in $path is $age_h hours old (limit $max days)"
        fi
    done
}
