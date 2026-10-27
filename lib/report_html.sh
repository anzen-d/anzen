#!/bin/bash
# lib/report_html.sh — Generate HTML security report

_html_escape() {
    sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g; s/"/\&quot;/g' <<< "$1"
}

generate_html_report() {
    local output_file=$1
    local fails warns oks infos

    fails=$(grep -c "^FAIL	" "$FINDINGS_FILE" 2>/dev/null) || fails=0
    warns=$(grep -c "^WARN	" "$FINDINGS_FILE" 2>/dev/null) || warns=0
    oks=$(grep -c   "^OK	"   "$FINDINGS_FILE" 2>/dev/null) || oks=0
    infos=$(grep -c "^INFO	" "$FINDINGS_FILE" 2>/dev/null) || infos=0

    local total=$(( fails + warns + oks )); : "$total"  # used in template below
    local score; score=$(_overall_score)

    local score_color="#059669"
    [ "$score" -lt 80 ] && score_color="#d97706"
    [ "$score" -lt 50 ] && score_color="#dc2626"

    cat > "$output_file" <<HTML
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Anzen — $(_hostname) — $(date +"%Y-%m-%d")</title>
<style>
:root {
    --bg: #0f172a; --surface: #1e293b; --surface2: #263548;
    --border: #334155; --text: #e2e8f0; --text-muted: #64748b;
    --fail-bg: #1c0a0a; --fail-border: #7f1d1d; --fail-text: #ef4444; --fail-label: #f87171;
    --warn-bg: #1c1400; --warn-border: #78350f; --warn-text: #f59e0b; --warn-label: #fbbf24;
    --ok-bg:   #021c0e; --ok-border:   #14532d; --ok-text:   #10b981; --ok-label:   #34d399;
    --info-bg: #0c1221; --info-border: #1e3a5f; --info-text: #3b82f6; --info-label: #93c5fd;
    --score-color: ${score_color};
}
body.light {
    --bg: #f1f5f9; --surface: #ffffff; --surface2: #f8fafc;
    --border: #e2e8f0; --text: #0f172a; --text-muted: #64748b;
    --fail-bg: #fef2f2; --fail-border: #fca5a5; --fail-text: #dc2626; --fail-label: #dc2626;
    --warn-bg: #fffbeb; --warn-border: #fcd34d; --warn-text: #d97706; --warn-label: #d97706;
    --ok-bg:   #f0fdf4; --ok-border:   #86efac; --ok-text:   #16a34a; --ok-label:   #16a34a;
    --info-bg: #eff6ff; --info-border: #93c5fd; --info-text: #2563eb; --info-label: #2563eb;
}
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
       background: var(--bg); color: var(--text); min-height: 100vh; transition: background .2s, color .2s; }

/* Header */
.header { background: var(--surface); border-bottom: 1px solid var(--border); padding: 1.5rem 2rem; }
.header-top { display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 1.25rem; }
.logo { font-size: 1.75rem; font-weight: 800; letter-spacing: -1px; color: #38bdf8; }
.logo span { color: var(--text); }
.tagline { color: var(--text-muted); font-size: 0.8rem; margin-top: 3px; }
.header-actions { display: flex; gap: 0.5rem; }
.btn { padding: 0.4rem 0.9rem; border-radius: 6px; font-size: 0.8rem; font-weight: 600;
       cursor: pointer; border: 1px solid var(--border); background: var(--surface2);
       color: var(--text); transition: all .15s; }
.btn:hover { border-color: #38bdf8; color: #38bdf8; }
.header-meta { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 0.75rem; }
.meta-item { background: var(--bg); border: 1px solid var(--border); border-radius: 8px; padding: 0.6rem 1rem; }
.meta-label { font-size: 0.65rem; text-transform: uppercase; letter-spacing: .06em; color: var(--text-muted); margin-bottom: 2px; }
.meta-value { font-size: 0.85rem; color: var(--text); font-family: monospace; }

/* Summary cards */
.summary { display: grid; grid-template-columns: repeat(4, 1fr); gap: 1rem; padding: 1.25rem 2rem;
           background: var(--bg); border-bottom: 1px solid var(--border); }
.card { border-radius: 10px; padding: 1rem 1.25rem; text-align: center; border: 1px solid; }
.card-label { font-size: 0.7rem; text-transform: uppercase; letter-spacing: .08em; font-weight: 600; margin-bottom: .4rem; }
.card-count { font-size: 2.5rem; font-weight: 800; line-height: 1; }
.card.fail  { background: var(--fail-bg);  border-color: var(--fail-border); }
.card.fail  .card-label { color: var(--fail-label); }  .card.fail  .card-count { color: var(--fail-text); }
.card.warn  { background: var(--warn-bg);  border-color: var(--warn-border); }
.card.warn  .card-label { color: var(--warn-label); }  .card.warn  .card-count { color: var(--warn-text); }
.card.ok    { background: var(--ok-bg);    border-color: var(--ok-border); }
.card.ok    .card-label { color: var(--ok-label); }    .card.ok    .card-count { color: var(--ok-text); }
.card.score { background: var(--surface);  border-color: var(--border); }
.card.score .card-label { color: var(--text-muted); }  .card.score .card-count { color: var(--score-color); }

/* Filters */
.filters { display: flex; gap: 0.5rem; padding: 1rem 2rem 0; flex-wrap: wrap; }
.filter-btn { padding: 0.3rem 0.8rem; border-radius: 999px; font-size: 0.75rem; font-weight: 600;
              cursor: pointer; border: 1px solid var(--border); background: var(--surface2);
              color: var(--text-muted); transition: all .15s; }
.filter-btn:hover, .filter-btn.active { border-color: transparent; color: #fff; }
.filter-btn[data-filter="ALL"].active  { background: #475569; }
.filter-btn[data-filter="FAIL"].active { background: var(--fail-text); }
.filter-btn[data-filter="WARN"].active { background: var(--warn-text); }
.filter-btn[data-filter="OK"].active   { background: var(--ok-text); }
.filter-btn[data-filter="INFO"].active { background: var(--info-text); }

/* Sections */
.content { padding: 1rem 2rem 2rem; }
details { background: var(--surface); border: 1px solid var(--border); border-radius: 10px;
          margin-bottom: 0.75rem; overflow: hidden; transition: border-color .2s; }
details[open] { border-color: #38bdf840; }
summary { padding: 0.9rem 1.25rem; cursor: pointer; display: flex; justify-content: space-between;
          align-items: center; user-select: none; list-style: none; }
summary::-webkit-details-marker { display: none; }
summary:hover { background: var(--surface2); }
.section-title { font-weight: 600; font-size: 0.9rem; color: var(--text); }
.section-badges { display: flex; gap: 0.35rem; align-items: center; }
.mini-badge { font-size: 0.65rem; font-weight: 700; padding: 2px 7px; border-radius: 999px; }
.mini-badge.fail { background: var(--fail-border); color: var(--fail-label); }
.mini-badge.warn { background: var(--warn-border); color: var(--warn-label); }
.mini-badge.ok   { background: var(--ok-border);   color: var(--ok-label); }
.chevron { color: var(--text-muted); font-size: 0.7rem; transition: transform .2s; margin-left: .5rem; }
details[open] .chevron { transform: rotate(180deg); }

/* Findings */
.findings { border-top: 1px solid var(--border); }
.finding { padding: 0.6rem 1.25rem; border-bottom: 1px solid var(--surface2);
           display: flex; gap: 0.75rem; align-items: flex-start; font-size: 0.85rem; }
.finding:last-child { border-bottom: none; }
.finding:hover { background: var(--surface2); }
.finding-body { flex: 1; min-width: 0; }
.badge { padding: 2px 8px; border-radius: 4px; font-size: 0.68rem; font-weight: 700;
         white-space: nowrap; letter-spacing: .03em; margin-top: 1px; flex-shrink: 0; }
.badge.FAIL { background: var(--fail-border); color: var(--fail-label); }
.badge.WARN { background: var(--warn-border); color: var(--warn-label); }
.badge.OK   { background: var(--ok-border);   color: var(--ok-label); }
.badge.INFO { background: var(--info-border); color: var(--info-label); }
.finding-msg { font-family: "SF Mono","Fira Code",monospace; color: var(--text); word-break: break-word; }
.finding-id { font-family: "SF Mono","Fira Code",monospace; font-size: 0.68rem; color: var(--text-muted); }
.remedy { margin-top: 0.35rem; display: flex; align-items: flex-start; gap: 0.4rem; }
.remedy-label { font-size: 0.65rem; color: var(--text-muted); white-space: nowrap; padding-top: 2px; }
.remedy-cmd { font-family: "SF Mono","Fira Code",monospace; font-size: 0.78rem;
              color: #38bdf8; background: var(--bg); border: 1px solid var(--border);
              border-radius: 4px; padding: 2px 6px; word-break: break-all; cursor: pointer; }
.remedy-cmd:hover { border-color: #38bdf8; }
.remedy-copied { font-size: 0.65rem; color: var(--ok-text); margin-left: 4px; opacity: 0; transition: opacity .3s; }

.footer { text-align: center; padding: 1.5rem; color: var(--text-muted); font-size: 0.75rem;
          border-top: 1px solid var(--border); }
.footer a { color: #38bdf8; text-decoration: none; }

@media print {
    body { background: white; color: #000; }
    .header-actions, .filters, .btn { display: none; }
    details { border: 1px solid #ccc; break-inside: avoid; }
    details:not([open]) { display: none; }
    .finding { break-inside: avoid; }
    .remedy-cmd { color: #0369a1; background: #f0f9ff; border-color: #bae6fd; }
}
</style>
</head>
<body>

<div class="header">
  <div class="header-top">
    <div>
      <div class="logo">安<span>zen</span></div>
      <div class="tagline">Linux Security Audit</div>
    </div>
    <div class="header-actions">
      <button class="btn" onclick="toggleTheme()">☀ / ☾</button>
      <button class="btn" onclick="window.print()">⎙ Print</button>
    </div>
  </div>
  <div class="header-meta">
    <div class="meta-item"><div class="meta-label">Hostname</div><div class="meta-value">$(_hostname)</div></div>
    <div class="meta-item"><div class="meta-label">OS</div><div class="meta-value">$(_html_escape "$OS_PRETTY")</div></div>
    <div class="meta-item"><div class="meta-label">Kernel</div><div class="meta-value">$(uname -r)</div></div>
    <div class="meta-item"><div class="meta-label">Public IP</div><div class="meta-value">${ANZEN_PUBLIC_IP:-unavailable}</div></div>
    <div class="meta-item"><div class="meta-label">Audited By</div><div class="meta-value">$(whoami)</div></div>
    <div class="meta-item"><div class="meta-label">Date</div><div class="meta-value">$(date "+%Y-%m-%d %H:%M %Z")</div></div>
  </div>
</div>

<div class="summary">
  <div class="card fail">  <div class="card-label">Failed</div>   <div class="card-count">$fails</div></div>
  <div class="card warn">  <div class="card-label">Warnings</div> <div class="card-count">$warns</div></div>
  <div class="card ok">    <div class="card-label">Passed</div>   <div class="card-count">$oks</div></div>
  <div class="card score"> <div class="card-label">Score</div>    <div class="card-count">${score}%</div></div>
</div>

<div class="filters">
  <button class="filter-btn active" data-filter="ALL"  onclick="filterFindings('ALL')">All</button>
  <button class="filter-btn"        data-filter="FAIL" onclick="filterFindings('FAIL')">FAIL ($fails)</button>
  <button class="filter-btn"        data-filter="WARN" onclick="filterFindings('WARN')">WARN ($warns)</button>
  <button class="filter-btn"        data-filter="OK"   onclick="filterFindings('OK')">OK ($oks)</button>
  <button class="filter-btn"        data-filter="INFO" onclick="filterFindings('INFO')">INFO ($infos)</button>
</div>

<div class="content" id="main-content">
HTML

    # Build sections
    local -A section_score=()
    local _s _f _w _o _sc
    while IFS=$'\t' read -r _s _f _w _o _sc; do section_score[$_s]=$_sc; done < <(_section_scores)
    local prev_section="" section_fail=0 section_warn=0 section_ok=0 section_html=""

    _flush_section() {
        [ -z "$prev_section" ] && return
        local badges=""
        [ "$section_fail" -gt 0 ] && badges+="<span class=\"mini-badge fail\">${section_fail} FAIL</span>"
        [ "$section_warn" -gt 0 ] && badges+="<span class=\"mini-badge warn\">${section_warn} WARN</span>"
        [ "$section_ok"   -gt 0 ] && badges+="<span class=\"mini-badge ok\">${section_ok} OK</span>"
        [ -n "${section_score[$prev_section]:-}" ] && badges+="<span class=\"mini-badge\">${section_score[$prev_section]}%</span>"
        local open_attr=""
        [ "$section_fail" -gt 0 ] && open_attr=" open"

        cat >> "$output_file" <<SECTION
  <details${open_attr}>
    <summary>
      <span class="section-title">$(_html_escape "$prev_section")</span>
      <span style="display:flex;align-items:center"><span class="section-badges">$badges</span><span class="chevron">▼</span></span>
    </summary>
    <div class="findings">
$(printf '%s' "$section_html")
    </div>
  </details>
SECTION
        section_html=""
        section_fail=0; section_warn=0; section_ok=0
    }

    while IFS=$'\t' read -r level sec msg id remedy; do
        if [ "$sec" != "$prev_section" ]; then
            _flush_section
            prev_section="$sec"
        fi
        local escaped_msg escaped_remedy
        escaped_msg=$(_html_escape "$msg")
        escaped_remedy=$(_html_escape "${remedy:-}")

        local remedy_html=""
        if [ -n "$remedy" ] && [ "$level" != "OK" ] && [ "$level" != "INFO" ]; then
            remedy_html="<div class=\"remedy\"><span class=\"remedy-label\">Fix:</span><code class=\"remedy-cmd\" onclick=\"copyRemedyInline(this)\" title=\"Click to copy\">$escaped_remedy</code><span class=\"remedy-copied\">✓ copied</span></div>"
        fi

        section_html+="      <div class=\"finding\" data-level=\"$level\"><span class=\"badge $level\">$level</span><div class=\"finding-body\"><div class=\"finding-msg\">$escaped_msg</div><div class=\"finding-id\">$id</div>$remedy_html</div></div>"$'\n'

        case "$level" in
            FAIL) section_fail=$((section_fail+1)) ;;
            WARN) section_warn=$((section_warn+1)) ;;
            OK)   section_ok=$((section_ok+1)) ;;
        esac
    done < "$FINDINGS_FILE"

    _flush_section

    cat >> "$output_file" <<HTML
</div>

<div class="footer">
  Generated by <strong>Anzen ${ANZEN_VERSION:-}</strong> &mdash; $(date "+%Y-%m-%d %H:%M:%S")
</div>

<script>
// Theme toggle
function toggleTheme() {
    document.body.classList.toggle('light');
    localStorage.setItem('anzen-theme', document.body.classList.contains('light') ? 'light' : 'dark');
}
if (localStorage.getItem('anzen-theme') === 'light') document.body.classList.add('light');

// Filter findings
function filterFindings(level) {
    document.querySelectorAll('.finding').forEach(el => {
        el.style.display = (level === 'ALL' || el.dataset.level === level) ? '' : 'none';
    });
    // Hide sections where all findings are hidden
    document.querySelectorAll('details').forEach(details => {
        const visible = [...details.querySelectorAll('.finding')].some(el => el.style.display !== 'none');
        details.style.display = visible ? '' : 'none';
    });
    document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
    document.querySelector('[data-filter="' + level + '"]').classList.add('active');
}

// Copy remedy command inline
function copyRemedyInline(el) {
    navigator.clipboard.writeText(el.textContent).then(() => {
        const copied = el.nextElementSibling;
        if (copied) { copied.style.opacity = 1; setTimeout(() => copied.style.opacity = 0, 1500); }
    }).catch(() => {
        const range = document.createRange();
        range.selectNode(el);
        window.getSelection().removeAllRanges();
        window.getSelection().addRange(range);
    });
}
</script>
</body>
</html>
HTML
}
