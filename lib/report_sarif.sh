#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 The Anzen contributors
# lib/report_sarif.sh — SARIF 2.1.0 output (GitHub/GitLab code-scanning compatible)

_sarif_escape() {
    sed 's/\\/\\\\/g; s/"/\\"/g' <<< "$1"
}

generate_sarif_report() {
    local output_file=$1
    declare -A _seen_rules
    local rules_json="" results_json=""
    local first_rule=true first_result=true

    while IFS=$'\t' read -r level sec msg id _remedy; do
        [ "$level" = "OK"   ] && continue
        [ "$level" = "INFO" ] && continue

        local sarif_level
        case "$level" in
            FAIL) sarif_level="error"   ;;
            WARN) sarif_level="warning" ;;
            *)    sarif_level="note"    ;;
        esac

        local rule_id
        rule_id=$(printf '%s' "$sec" | tr '[:upper:] /' '[:lower:]--' | tr -cd 'a-z0-9-')

        if [ -z "${_seen_rules[$rule_id]+x}" ]; then
            _seen_rules[$rule_id]=1
            $first_rule || rules_json+=','
            rules_json+=$(printf '{"id":"%s","name":"%s","defaultConfiguration":{"level":"%s"},"help":{"text":"Anzen check: %s"}}' \
                "$rule_id" "$(_sarif_escape "$sec")" "$sarif_level" "$(_sarif_escape "$sec")")
            first_rule=false
        fi

        $first_result || results_json+=','
        results_json+=$(printf '{"ruleId":"%s","level":"%s","message":{"text":"%s"},"partialFingerprints":{"anzenFindingId/v1":"%s"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"///%s"}}}]}' \
            "$rule_id" "$sarif_level" "$(_sarif_escape "$msg")" "$id" "$(_sarif_escape "$(_hostname)")")
        first_result=false
    done < "$FINDINGS_FILE"

    {
        printf '{\n'
        printf '  "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.5.json",\n'
        printf '  "version": "2.1.0",\n'
        printf '  "runs": [{\n'
        printf '    "tool": {"driver": {"name": "anzen", "version": "%s", "rules": [%s]}},\n' \
            "$ANZEN_VERSION" "$rules_json"
        printf '    "results": [%s]\n' "$results_json"
        printf '  }]\n'
        printf '}\n'
    } > "$output_file"

    unset _seen_rules
}
