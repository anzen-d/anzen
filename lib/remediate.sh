#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 The Anzen contributors
# lib/remediate.sh — Generate executable remediation script from findings

generate_remediate_script() {
    local output_file=$1
    local count=0
    local cur_section=""

    {
        cat <<HEADER
#!/bin/bash
# ============================================================
# Anzen Remediation Script
# Generated: $(date)
# Host:      $(_hostname)
# ⚠  Review each command carefully before running!
# ⚠  Run as root or with sudo
# ============================================================
# Each command runs on its own: one that fails is reported and the rest
# still run (no set -e — many lines are checks that may find nothing)
set -uo pipefail
_failed=0

HEADER

        while IFS=$'\t' read -r level sec msg _id remedy; do
            [ -z "$remedy" ] && continue
            [ "$level" = "OK" ]   && continue
            [ "$level" = "INFO" ] && continue

            if [ "$sec" != "$cur_section" ]; then
                printf '\n# ── %s ─────────────────────────────\n\n' "$sec"
                cur_section="$sec"
            fi

            printf '# [%s] %s\n' "$level" "$msg"
            if [[ "$remedy" == \#* ]]; then
                # Advice only: nothing to run
                printf '%s\n\n' "$remedy"
            else
                # Newline before "}": the remedy may end in a "# comment"
                printf '{ %s\n} || { echo "FAILED: %s" >&2; _failed=$((_failed + 1)); }\n\n' \
                    "$remedy" "$(printf '%s' "$msg" | sed 's/[\\"$`]/\\&/g')"
            fi
            count=$((count + 1))
        done < "$FINDINGS_FILE"

        printf '# ── End of remediation (%s commands) ──\n' "$count"
        printf 'if [ "$_failed" -gt 0 ]; then echo "Remediation finished: $_failed command(s) failed — see above."; exit 1; fi\n'
        printf 'echo "Remediation script complete."\n'

    } > "$output_file"

    chmod +x "$output_file"
    echo "$count"
}
