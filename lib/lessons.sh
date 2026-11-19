#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 The Anzen contributors
# lib/lessons.sh — attach a short lesson to a finding (lib/data/lessons.tsv).
# Bash 3.2 safe: the macOS edition reads the same report code.

# _findings_lessons — one line per line of FINDINGS_FILE: the lesson of the
# first matching line as TITLE<TAB>WHY<TAB>BEFORE_YOU_CHANGE<TAB>VERIFY, or an
# empty line. Read it next to the findings on another file descriptor.
_findings_lessons() {
    _findings_map "${ANZEN_LESSONS_FILE:-${ANZEN_DIR:-${ROOT_DIR:-.}}/lib/data/lessons.tsv}" 6
}
