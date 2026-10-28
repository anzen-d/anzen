#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 The Anzen contributors
# lib/history.sh — Run history, regression detection and the static dashboard
#
# History layout: $HISTORY_DIR/<host>/<YYYYmmddTHHMMSSZ>.json, each file a
# normal JSON report (report_json.sh). Its one-entry-per-line layout is what the
# sed/awk parsing below relies on.

# _history_host_dir DIR [HOST] — per-host history dir (default: this host)
_history_host_dir() {
    local host=${2:-$(_hostname)}
    echo "$1/${host%%.*}"
}

# history_latest DIR [HOST] — newest history file for the host, empty if none
history_latest() {
    local d; d=$(_history_host_dir "$1" "${2:-}")
    ls -1 "$d"/*.json 2>/dev/null | sort | tail -1
}

# _history_fail_entries FILE — "ID<TAB>MESSAGE" for each FAIL in a JSON report
_history_fail_entries() {
    sed -n 's/^    {"id": "\([^"]*\)", "level": "FAIL", "section": "[^"]*", "message": "\(.*\)", "remedy": ".*"},\{0,1\}$/\1\t\2/p' "$1" \
        | sed 's/\\"/"/g; s/\\\\/\\/g'
}

# history_new_fails PREV_FILE — messages of current FAILs (FINDINGS_FILE) whose
# ID was not a FAIL in PREV_FILE; every current FAIL when there is no previous run
history_new_fails() {
    local prev=$1
    # FILENAME, not NR == FNR: the previous-run input may be empty
    awk -F'\t' 'FILENAME == ARGV[1] { seen[$1] = 1; next }
                 $1 == "FAIL" && !($4 in seen) { print $3 }' \
        <( [ -n "$prev" ] && [ -f "$prev" ] && _history_fail_entries "$prev" ) "$FINDINGS_FILE"
}

# history_new_fails_json PREV CUR — same comparison between two JSON reports
# (remote hosts, whose findings exist only as their JSON report)
history_new_fails_json() {
    awk -F'\t' 'FILENAME == ARGV[1] { seen[$1] = 1; next } !($1 in seen) { print $2 }' \
        <( [ -n "$1" ] && [ -f "$1" ] && _history_fail_entries "$1" ) <(_history_fail_entries "$2")
}

# history_store DIR HOST JSON — copy a JSON report into the host's history,
# keep the newest HISTORY_KEEP runs, print the stored path
history_store() {
    local d; d=$(_history_host_dir "$1" "$2")
    (umask 077; mkdir -p "$d") || return 1
    if [ -L "$1" ] || [ -L "$d" ]; then
        echo "ERROR: History path '$d' involves a symlink — refusing to write" >&2
        return 1
    fi
    local base out n=1
    base="$d/$(date -u +%Y%m%dT%H%M%SZ)"; out="$base.json"
    # Two runs in the same second must not overwrite each other
    while [ -e "$out" ]; do out="$base-$n.json"; n=$((n + 1)); done
    cp "$3" "$out" && chmod 600 "$out" || return 1

    # HISTORY_KEEP=0 keeps everything ("head -n -0" would list every run)
    local keep="${HISTORY_KEEP:-52}"
    [ "$keep" -gt 0 ] 2>/dev/null && \
        ls -1 "$d"/*.json 2>/dev/null | sort | head -n "-$keep" | xargs -r rm -f --
    echo "$out"
}

# history_save DIR — write this run as a JSON report into this host's history
history_save() {
    local tmp out; tmp=$(umask 077; mktemp)
    generate_json_report "$tmp"
    out=$(history_store "$1" "" "$tmp")
    local rc=$?
    rm -f "$tmp"
    [ "$rc" -eq 0 ] && echo "$out"
    return "$rc"
}

# _dashboard_runs DIR — JS array literal: one object per history file with
# host, date, summary and sections; findings only for each host's two newest
_dashboard_runs() {
    local dir=$1 host_dir f first=true n i files
    printf '['
    for host_dir in "$dir"/*/; do
        [ -d "$host_dir" ] || continue
        mapfile -t files < <(ls -1 "$host_dir"*.json 2>/dev/null | sort)
        n=${#files[@]}
        for (( i = 0; i < n; i++ )); do
            f=${files[$i]}
            $first || printf ','
            first=false
            awk -v full="$(( i >= n - 2 ))" '
                /^  "hostname": /  { sub(/,$/, ""); host = $0 }
                /^  "date": /      { sub(/,$/, ""); date = $0 }
                /^  "version": /   { sub(/,$/, ""); ver = $0 }
                /^  "summary": /   { sub(/,$/, ""); summ = $0 }
                /^  "sections": \[/ { in_s = 1; next }
                /^  "findings": \[/ { in_f = 1; next }
                /^  \]/            { in_s = 0; in_f = 0; next }
                in_s { sub(/,$/, ""); secs = secs (secs == "" ? "" : ",") $0 }
                in_f && full == 1 && $0 !~ /"level": "OK"/ {
                    sub(/,$/, ""); fnd = fnd (fnd == "" ? "" : ",") $0
                }
                END {
                    printf "{%s,%s,%s,%s,\"sections\":[%s],\"findings\":%s}\n", \
                        host, date, (ver == "" ? "\"version\": \"\"" : ver), summ, secs, \
                        (full == 1 ? "[" fnd "]" : "null")
                }' "$f"
        done
    done
    printf ']'
}

# generate_dashboard HISTORY_DIR OUTPUT — self-contained HTML, no network access
generate_dashboard() {
    local dir=$1 out=$2
    local runs; runs=$(_dashboard_runs "$dir")
    # Neutralise "</script>" inside messages so the data cannot end the block
    runs=${runs//<\//<\\/}

    cat > "$out" <<'HTML'
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Anzen dashboard</title>
<style>
:root {
  --bg: #f6f7f9; --surface: #ffffff; --border: #e3e6eb; --text: #1b1f24; --muted: #5f6b7a;
  --fail: #c62828; --warn: #b26a00; --ok: #2e7d32; --info: #1565c0; --line: #3b6fd8;
  --mono: ui-monospace, "SF Mono", "Fira Code", monospace;
}
@media (prefers-color-scheme: dark) {
  :root:not([data-theme="light"]) {
    --bg: #0f1216; --surface: #171b21; --border: #262c35; --text: #e6e9ee; --muted: #8e99a8;
    --fail: #ef5350; --warn: #ffb74d; --ok: #66bb6a; --info: #64b5f6; --line: #7aa2ff;
  }
}
:root[data-theme="dark"] {
  --bg: #0f1216; --surface: #171b21; --border: #262c35; --text: #e6e9ee; --muted: #8e99a8;
  --fail: #ef5350; --warn: #ffb74d; --ok: #66bb6a; --info: #64b5f6; --line: #7aa2ff;
}
* { box-sizing: border-box; }
body { margin: 0; background: var(--bg); color: var(--text);
       font: 14px/1.5 system-ui, -apple-system, "Segoe UI", sans-serif; }
header { display: flex; align-items: center; justify-content: space-between; gap: 1rem;
         padding: 1.25rem 1rem; max-width: 1200px; margin: 0 auto; flex-wrap: wrap; }
header h1 { margin: 0; font-size: 1.25rem; }
header .meta { color: var(--muted); font-size: .85rem; display: block; }
main { max-width: 1200px; margin: 0 auto; padding: 0 1rem 3rem; }
h2 { font-size: 1rem; margin: 2rem 0 .75rem; }
.hosts { display: grid; grid-template-columns: repeat(auto-fill, minmax(260px, 1fr)); gap: .75rem; }
.host { background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: .9rem 1rem;
        cursor: pointer; text-align: left; color: inherit; font: inherit; }
.host[aria-pressed="true"] { outline: 2px solid var(--line); }
.host .name { font-weight: 600; }
.host .score { font-size: 2rem; font-weight: 700; font-variant-numeric: tabular-nums; }
.host .delta { font-size: .85rem; margin-left: .4rem; }
.host .counts, .host .when { color: var(--muted); font-size: .8rem; }
.stale { color: var(--warn) !important; }
.up { color: var(--ok); } .down { color: var(--fail); }
.panel { background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 1rem; overflow-x: auto; }
svg text { fill: var(--muted); font-size: 11px; }
table { width: 100%; border-collapse: collapse; }
th, td { text-align: left; padding: .4rem .5rem; border-bottom: 1px solid var(--border); vertical-align: top; }
th { color: var(--muted); font-weight: 500; font-size: .8rem; }
td.num { text-align: right; font-variant-numeric: tabular-nums; white-space: nowrap; }
.lvl { font-family: var(--mono); font-size: .75rem; font-weight: 700; }
.lvl.FAIL { color: var(--fail); } .lvl.WARN { color: var(--warn); } .lvl.INFO { color: var(--info); }
.msg { word-break: break-word; }
.id { font-family: var(--mono); font-size: .75rem; color: var(--muted); }
.grid2 { display: grid; grid-template-columns: 1fr 1fr; gap: .75rem; }
@media (max-width: 760px) { .grid2 { grid-template-columns: 1fr; } }
.list { margin: 0; padding-left: 1.1rem; }
.list li { margin: .2rem 0; word-break: break-word; }
.hosttag { display: inline-block; font-size: .75rem; font-weight: 600; padding: 0 .4rem; margin-right: .3rem;
           border: 1px solid var(--border); border-radius: 4px; color: var(--muted); }
.empty { color: var(--muted); }
.filters { display: flex; gap: .5rem; flex-wrap: wrap; margin-bottom: .75rem; }
.filters input, .filters select, button.theme { background: var(--surface); color: var(--text);
  border: 1px solid var(--border); border-radius: 6px; padding: .35rem .5rem; font: inherit; }
.filters input { flex: 1; min-width: 180px; }
.bar { height: 6px; border-radius: 3px; background: var(--border); min-width: 60px; }
.bar > span { display: block; height: 100%; border-radius: 3px; }
@media (max-width: 600px) { .barcol { display: none; } }
</style>
</head>
<body>
<header>
  <div><h1>安全 Anzen</h1><span class="meta" id="meta"></span></div>
  <button class="theme" id="theme" type="button">Theme</button>
</header>
<main>
  <section><h2>Hosts</h2><div class="hosts" id="hosts"></div></section>
  <div id="attention"></div>
  <div id="detail"></div>
</main>
<script>
HTML
    printf 'const RUNS = %s;\n' "$runs" >> "$out"
    cat >> "$out" <<'HTML'
const STALE_DAYS = 8, EXPIRY_DAYS = 30;
const $ = s => document.querySelector(s);
const esc = s => String(s ?? "").replace(/[&<>"]/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]));
const days = d => (Date.now() - new Date(d)) / 864e5;
const fmt = d => new Date(d).toLocaleString(undefined, {dateStyle: "medium", timeStyle: "short"});

const byHost = {};
for (const r of RUNS) (byHost[r.hostname] ||= []).push(r);
for (const h in byHost) byHost[h].sort((a, b) => a.date.localeCompare(b.date));
const hosts = Object.keys(byHost).sort();
// Open on the host that needs attention most: lowest latest score
let current = [...hosts].sort((a, b) => byHost[a].at(-1).summary.score - byHost[b].at(-1).summary.score)[0];

function trend(runs, w, h = 160) {
  if (runs.length < 2) return '<p class="empty">Trend appears after the second run.</p>';
  const p = 28, xs = (w - 2 * p) / (runs.length - 1);
  const y = s => h - p - (s / 100) * (h - 2 * p);
  const pts = runs.map((r, i) => [p + i * xs, y(r.summary.score)]);
  const grid = [0, 50, 100].map(v =>
    `<line x1="${p}" x2="${w - p}" y1="${y(v)}" y2="${y(v)}" stroke="var(--border)"/>` +
    `<text x="2" y="${y(v) + 4}">${v}</text>`).join("");
  const dots = pts.map(([x, yy], i) =>
    `<circle cx="${x}" cy="${yy}" r="3" fill="var(--line)"><title>${fmt(runs[i].date)}: ${runs[i].summary.score}%</title></circle>`).join("");
  return `<svg viewBox="0 0 ${w} ${h}" width="${w}" height="${h}" role="img" aria-label="Score trend">${grid}
    <polyline fill="none" stroke="var(--line)" stroke-width="2" points="${pts.map(q => q.join(",")).join(" ")}"/>${dots}
    <text x="${p}" y="${h - 6}">${esc(fmt(runs[0].date))}</text>
    <text x="${w - p}" y="${h - 6}" text-anchor="end">${esc(fmt(runs.at(-1).date))}</text></svg>`;
}

function renderHosts() {
  $("#hosts").innerHTML = hosts.map(h => {
    const runs = byHost[h], last = runs.at(-1), prev = runs.at(-2);
    const d = prev ? last.summary.score - prev.summary.score : 0;
    const age = days(last.date);
    return `<button class="host" type="button" data-host="${esc(h)}" aria-pressed="${h === current}">
      <div class="name">${esc(h)}</div>
      <div><span class="score">${last.summary.score}%</span>${prev && d ? `<span class="delta ${d > 0 ? "up" : "down"}">${d > 0 ? "+" : ""}${d}</span>` : ""}</div>
      <div class="counts">FAIL ${last.summary.fail} · WARN ${last.summary.warn} · ${runs.length} run${runs.length > 1 ? "s" : ""}</div>
      <div class="when ${age > STALE_DAYS ? "stale" : ""}">Last run ${esc(fmt(last.date))}${age > STALE_DAYS ? " — stale" : ""}</div>
    </button>`;
  }).join("") || '<p class="empty">No history yet.</p>';
  document.querySelectorAll(".host").forEach(b => b.onclick = () => { current = b.dataset.host; render(); });
}

// Per host: FAILs new/fixed vs the previous run, accepted risks expiring soon
function changes(h) {
  const runs = byHost[h], last = runs.at(-1), prev = runs.at(-2);
  const fails = r => (r?.findings || []).filter(f => f.level === "FAIL");
  const prevIds = new Set(fails(prev).map(f => f.id)), curIds = new Set(fails(last).map(f => f.id));
  const expiring = (last.findings || []).flatMap(f => {
    const m = /\[accepted until (\d{4}-\d{2}-\d{2}): ([^\]]*)\]/.exec(f.message);
    return m && -days(m[1]) < EXPIRY_DAYS ? [{...f, until: m[1], reason: m[2]}] : [];
  });
  return {
    hasPrev: !!prev,
    newF: prev ? fails(last).filter(f => !prevIds.has(f.id)) : [],
    fixed: prev ? fails(prev).filter(f => !curIds.has(f.id)) : [],
    expiring,
  };
}

const li = (arr, f) => arr.length ? `<ul class="list">${arr.map(f).join("")}</ul>` : '<p class="empty">None.</p>';
const hostTag = h => `<span class="hosttag">${esc(h)}</span>`;
const stripAccept = m => m.replace(/\s*\[accepted until.*\]$/, "");

// Fleet-wide: what changed since each host's previous run, and what expires soon
function renderAttention() {
  const all = hosts.map(h => [h, changes(h)]);
  const flat = key => all.flatMap(([h, c]) => c[key].map(f => ({...f, host: h})));
  const newF = flat("newF"), fixed = flat("fixed"), expiring = flat("expiring").sort((a, b) => a.until.localeCompare(b.until));
  $("#attention").innerHTML = `
    <div class="grid2">
      <section><h2>New FAILs since previous run</h2><div class="panel">${li(newF, f => `<li>${hostTag(f.host)} ${esc(f.message)} <span class="id">${esc(f.id)}</span></li>`)}</div></section>
      <section><h2>Fixed since previous run</h2><div class="panel">${li(fixed, f => `<li>${hostTag(f.host)} ${esc(f.message)}</li>`)}</div></section>
    </div>
    <section><h2>Accepted risks expiring within ${EXPIRY_DAYS} days</h2><div class="panel">${li(expiring, f => `<li>${hostTag(f.host)} <b>${esc(f.until)}</b> — ${esc(stripAccept(f.message))} <span class="id">${esc(f.reason)}</span></li>`)}</div></section>`;
}

function renderDetail() {
  if (!current) { $("#detail").innerHTML = ""; return; }
  const runs = byHost[current], last = runs.at(-1), prev = runs.at(-2);
  const issues = (last.findings || []).filter(f => f.level === "FAIL" || f.level === "WARN");
  const prevSec = Object.fromEntries((prev?.sections || []).map(s => [s.name, s.score]));
  $("#detail").innerHTML = `
    <h2>${esc(current)} — score trend</h2><div class="panel" id="trend"></div>
    <section><h2>Sections</h2><div class="panel"><table>
      <thead><tr><th>Section</th><th class="num">Score</th><th class="barcol"></th><th class="num">Δ</th><th class="num">FAIL</th><th class="num">WARN</th></tr></thead>
      <tbody>${[...last.sections].sort((a, b) => a.score - b.score).map(s => {
        const d = s.name in prevSec ? s.score - prevSec[s.name] : null;
        const c = s.score >= 80 ? "var(--ok)" : s.score >= 50 ? "var(--warn)" : "var(--fail)";
        return `<tr><td>${esc(s.name)}</td><td class="num">${s.score}%</td>
          <td class="barcol"><div class="bar"><span style="width:${s.score}%;background:${c}"></span></div></td>
          <td class="num ${d > 0 ? "up" : d < 0 ? "down" : ""}">${d ? (d > 0 ? "+" : "") + d : ""}</td>
          <td class="num">${s.fail}</td><td class="num">${s.warn}</td></tr>`;
      }).join("")}</tbody></table></div></section>
    <section><h2>Findings (latest run)</h2><div class="panel">
      <div class="filters">
        <input id="q" type="search" placeholder="Filter by text, section or ID" aria-label="Filter findings">
        <select id="lvl" aria-label="Level"><option value="">FAIL + WARN</option><option>FAIL</option><option>WARN</option></select>
      </div>
      <table><thead><tr><th>Level</th><th>Section</th><th>Finding</th></tr></thead><tbody id="rows"></tbody></table>
    </div></section>`;

  const rows = () => {
    const q = $("#q").value.toLowerCase(), l = $("#lvl").value;
    $("#rows").innerHTML = issues
      .filter(f => (!l || f.level === l) && (!q || `${f.message} ${f.section} ${f.id}`.toLowerCase().includes(q)))
      .sort((a, b) => (a.level === b.level ? 0 : a.level === "FAIL" ? -1 : 1))
      .map(f => `<tr><td class="lvl ${f.level}">${f.level}</td><td>${esc(f.section)}</td>
        <td class="msg">${esc(f.message)}<div class="id">${esc(f.id)}</div></td></tr>`).join("")
      || '<tr><td colspan="3" class="empty">No matching findings.</td></tr>';
  };
  drawTrend();
  $("#q").oninput = rows; $("#lvl").onchange = rows; rows();
}

// Drawn at the panel's real pixel width so labels keep their font size
function drawTrend() {
  const el = $("#trend");
  if (el) el.innerHTML = trend(byHost[current], Math.max(280, el.clientWidth - 34));
}
addEventListener("resize", drawTrend);

function render() { renderHosts(); renderAttention(); renderDetail(); }

const root = document.documentElement;
try { const t = localStorage.getItem("anzen-theme"); if (t) root.dataset.theme = t; } catch (e) {}
$("#theme").onclick = () => {
  const dark = root.dataset.theme ? root.dataset.theme === "dark" : matchMedia("(prefers-color-scheme: dark)").matches;
  root.dataset.theme = dark ? "light" : "dark";
  try { localStorage.setItem("anzen-theme", root.dataset.theme); } catch (e) {}
};
$("#meta").textContent = `${hosts.length} host${hosts.length === 1 ? "" : "s"} · ${RUNS.length} runs · generated ${fmt(new Date())}`;
render();
</script>
</body>
</html>
HTML
}
