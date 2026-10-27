#!/bin/bash
# docs/demo/build.sh OUT_DIR — build the live demo site: the dashboard from the
# demo history (dates shifted so the newest run is today) and the sample report.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$here/../.."
out=${1:?usage: build.sh OUT_DIR}
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

cp -r "$here/history" "$work/history"
# Shift every run by the same number of days so the newest one is today
newest=$(grep -ho '"date": "[0-9-]*' "$work"/history/*/*.json | cut -d'"' -f4 | sort | tail -1)
shift_days=$(( ( $(date -u +%s) - $(date -u -d "$newest" +%s) ) / 86400 ))
for f in "$work"/history/*/*.json; do
    d=$(grep -om1 '"date": "[0-9-]*' "$f" | cut -d'"' -f4)
    nd=$(date -u -d "$d + $shift_days days" +%F)
    sed -i "s/\"date\": \"$d/\"date\": \"$nd/" "$f"
    # Accepted-risk expiry dates move with the runs, so "expiring soon" stays true
    for until in $(grep -o 'accepted until [0-9-]*' "$f" | awk '{print $3}' | sort -u); do
        sed -i "s/accepted until $until/accepted until $(date -u -d "$until + $shift_days days" +%F)/g" "$f"
    done
done

mkdir -p "$out"
"$root/anzen.sh" --history="$work/history" --dashboard="$out/index.html"
cp "$here/report.html" "$out/report.html"
echo "Demo site: $out"
