#!/bin/bash
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
set -euo pipefail

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
            printf '%s\n\n' "$remedy"
            count=$((count + 1))
        done < "$FINDINGS_FILE"

        printf '# ── End of remediation (%s commands) ──\n' "$count"
        printf 'echo "Remediation script complete."\n'

    } > "$output_file"

    chmod +x "$output_file"
    echo "$count"
}
