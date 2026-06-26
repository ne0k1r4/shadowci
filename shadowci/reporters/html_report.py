"""
HTML report generator — professional self-contained HTML report.
No external dependencies. Pure inline CSS + JS.
"""
# TODO: add a dark mode toggle, the white bg hurts now
import os
import json
from datetime import datetime
from typing import List
from ..models import Finding, calculate_risk_score, SEVERITY_ORDER

SEVERITY_COLORS = {
    "CRITICAL": "#ef4444",
    "HIGH":     "#f97316",
    "MEDIUM":   "#f59e0b",
    "LOW":      "#10b981",
    "INFO":     "#3b82f6",
}
SEVERITY_BG = {
    "CRITICAL": "rgba(239, 68, 68, 0.05)",
    "HIGH":     "rgba(249, 115, 22, 0.05)",
    "MEDIUM":   "rgba(245, 158, 11, 0.05)",
    "LOW":      "rgba(16, 185, 129, 0.05)",
    "INFO":     "rgba(59, 130, 246, 0.05)",
}
SEVERITY_GLYPHS = {
    "CRITICAL": "●",
    "HIGH":     "●",
    "MEDIUM":   "●",
    "LOW":      "●",
    "INFO":     "●",
}


def _esc(s: str) -> str:
    return (s.replace('&','&amp;').replace('<','&lt;')
             .replace('>','&gt;').replace('"','&quot;'))


def generate_html_report(findings: List[Finding], target_path: str,
                         output_path: str = "shadowci_report.html") -> str:
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    total = len(findings)
    risk_score = calculate_risk_score(findings)
    abs_target = os.path.abspath(target_path)

    counts = {s: 0 for s in SEVERITY_ORDER}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    has_critical = counts.get("CRITICAL", 0) > 0
    has_high     = counts.get("HIGH", 0) > 0
    if has_critical or has_high:
        verdict = "FAIL"
        verdict_col = "#ef4444"
    elif counts.get("MEDIUM", 0) > 0:
        verdict = "WARNING"
        verdict_col = "#f59e0b"
    else:
        verdict = "PASS"
        verdict_col = "#10b981"

    # Group by severity
    by_sev = {}
    for f in findings:
        by_sev.setdefault(f.severity, []).append(f)

    # Build findings HTML
    findings_html = ""
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        group = by_sev.get(sev, [])
        if not group:
            continue
        col = SEVERITY_COLORS.get(sev, "#fff")
        bg = SEVERITY_BG.get(sev, "rgba(255,255,255,0.02)")
        glyph = SEVERITY_GLYPHS.get(sev, "·")
        cnt = len(group)

        cards = ""
        for f in group:
            loc = _esc(f.file) + (f":{f.line}" if f.line else "")
            det = f'<div class="detail">{_esc(f.detail)}</div>' if f.detail else ""
            rem = f'<div class="remediation"><span class="rem-label">Fix:</span> {_esc(f.remediation)}</div>' if f.remediation else ""
            cards += f"""
            <div class="finding-card" style="border-left:4px solid {col}; background:{bg};">
              <div class="finding-header">
                <span class="finding-msg">{_esc(f.message)}</span>
                <span class="finding-scanner">{_esc(f.scanner)}</span>
              </div>
              <div class="finding-loc">↳ <code>{loc}</code></div>
              {det}{rem}
            </div>"""

        findings_html += f"""
        <div class="sev-section" data-severity="{sev}">
          <div class="sev-header" style="border-color:{col}33; color:{col};"
               onclick="toggleSection(this)">
            <span>{glyph} {sev} <span class="sev-count">({cnt})</span></span>
            <span class="toggle-arrow">▼</span>
          </div>
          <div class="sev-body">{cards}</div>
        </div>"""

    # Filter Bar HTML
    filter_buttons_html = f"""
    <div class="filter-container">
      <span class="filter-label">Filter Severity:</span>
      <button class="filter-btn active" data-severity="ALL" onclick="filterFindings('ALL')" style="--btn-color: #f1f3f5;">
        All <span class="filter-count">({total})</span>
      </button>
    """
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        c = counts.get(sev, 0)
        col = SEVERITY_COLORS.get(sev, "#fff")
        disabled_attr = 'disabled style="opacity: 0.25; cursor: not-allowed;"' if c == 0 else f'style="--btn-color: {col};"'
        filter_buttons_html += f"""
      <button class="filter-btn" data-severity="{sev}" onclick="filterFindings('{sev}')" {disabled_attr}>
        {sev} <span class="filter-count">({c})</span>
      </button>"""
    filter_buttons_html += "\n    </div>"

    # Summary bars
    bar_html = ""
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        c = counts.get(sev, 0)
        if c == 0:
            continue
        col = SEVERITY_COLORS.get(sev, "#fff")
        pct = min(c * 5, 100)
        bar_html += f"""
        <div class="bar-row">
          <span class="bar-label" style="color:{col};">{SEVERITY_GLYPHS.get(sev,'·')} {sev}</span>
          <div class="bar-track">
            <div class="bar-fill" style="width:{pct}%; background:{col};"></div>
          </div>
          <span class="bar-count" style="color:{col};">{c}</span>
        </div>"""

    risk_col = "#ef4444" if risk_score >= 80 else "#f97316" if risk_score >= 50 else "#f59e0b" if risk_score >= 25 else "#10b981"
    risk_pct = risk_score

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>ShadowCI Report — {_esc(os.path.basename(abs_target))}</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500;700&display=swap');

  *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}

  :root {{
    --bg:           #07080a;
    --surface:      #0f1117;
    --surface2:     #161a22;
    --surface-card: #12141a;
    --border:       #20242d;
    --border-hover: #2e3543;
    --text:         #f1f3f5;
    --muted:        #858e9d;
    --mono:         'JetBrains Mono', monospace;
    --sans:         'Inter', system-ui, -apple-system, sans-serif;
    --low:          #10b981;
    --info:         #3b82f6;
  }}

  html {{ scroll-behavior: smooth; }}
  body {{
    background: var(--bg);
    color: var(--text);
    font-family: var(--sans);
    font-size: 15px;
    line-height: 1.6;
    -webkit-font-smoothing: antialiased;
    -moz-osx-font-smoothing: grayscale;
  }}

  /* ── Header ─────────────────────────────────────────────────── */
  .header {{
    background: linear-gradient(180deg, #0e1118 0%, #07080a 100%);
    border-bottom: 1px solid var(--border);
    padding: 64px 32px 48px;
    text-align: center;
    position: relative;
    overflow: hidden;
  }}
  .header::before {{
    content: '';
    position: absolute; inset: 0;
    background: radial-gradient(ellipse at 50% 0%, rgba(59,130,246,0.08) 0%, transparent 75%);
    pointer-events: none;
  }}
  .header-rule {{
    font-family: var(--mono);
    font-size: 11px;
    color: var(--muted);
    letter-spacing: 2px;
    text-transform: uppercase;
    margin-bottom: 12px;
  }}
  .header h1 {{
    font-family: var(--sans);
    font-size: clamp(24px, 5vw, 44px);
    font-weight: 800;
    background: linear-gradient(135deg, #ffffff 0%, #a5b4fc 100%);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    letter-spacing: -0.03em;
    margin-bottom: 8px;
  }}
  .header .subtitle {{
    font-family: var(--sans);
    font-weight: 500;
    color: var(--muted);
    font-size: 14px;
  }}

  /* ── Layout ──────────────────────────────────────────────────── */
  .container {{ max-width: 1100px; margin: 0 auto; padding: 32px 24px; }}

  /* ── Meta card ───────────────────────────────────────────────── */
  .meta-grid {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 16px;
    margin-bottom: 32px;
  }}
  .meta-card {{
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 20px;
    transition: transform 0.2s ease, border-color 0.2s ease;
  }}
  .meta-card:hover {{
    border-color: var(--border-hover);
    transform: translateY(-1px);
  }}
  .meta-card .label {{
    font-family: var(--mono);
    font-size: 11px;
    letter-spacing: 1px;
    text-transform: uppercase;
    color: var(--muted);
    margin-bottom: 8px;
  }}
  .meta-card .value {{
    font-family: var(--mono);
    font-size: 14px;
    color: var(--text);
    word-break: break-all;
  }}
  .verdict-card {{
    text-align: center;
    border-color: {verdict_col}44;
  }}
  .verdict-text {{
    font-family: var(--sans);
    font-size: 24px;
    font-weight: 700;
    color: {verdict_col};
    text-shadow: 0 0 20px {verdict_col}22;
  }}

  /* ── Risk score ──────────────────────────────────────────────── */
  .risk-section {{
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 24px;
    margin-bottom: 32px;
  }}
  .risk-section h2 {{
    font-family: var(--mono);
    font-size: 11px;
    letter-spacing: 2px;
    text-transform: uppercase;
    color: var(--muted);
    margin-bottom: 20px;
  }}
  .risk-score-row {{
    display: flex;
    align-items: center;
    gap: 24px;
    margin-bottom: 24px;
  }}
  .risk-number {{
    font-family: var(--mono);
    font-size: 56px;
    font-weight: 700;
    color: {risk_col};
    line-height: 1;
    text-shadow: 0 0 30px {risk_col}33;
    min-width: 90px;
  }}
  .risk-track {{
    flex: 1;
    height: 12px;
    background: #14161d;
    border-radius: 6px;
    overflow: hidden;
    border: 1px solid var(--border);
  }}
  .risk-fill {{
    height: 100%;
    width: {risk_pct}%;
    background: linear-gradient(90deg, {risk_col}bb, {risk_col});
    border-radius: 6px;
    transition: width 1.2s cubic-bezier(0.16, 1, 0.3, 1);
  }}
  .bar-row {{
    display: flex;
    align-items: center;
    gap: 16px;
    margin-bottom: 12px;
  }}
  .bar-label {{
    font-family: var(--mono);
    font-size: 11px;
    width: 90px;
    flex-shrink: 0;
    letter-spacing: 0.5px;
  }}
  .bar-track {{
    flex: 1;
    height: 8px;
    background: #14161d;
    border-radius: 4px;
    overflow: hidden;
    border: 1px solid var(--border);
  }}
  .bar-fill {{
    height: 100%;
    border-radius: 4px;
  }}
  .bar-count {{
    font-family: var(--mono);
    font-size: 12px;
    font-weight: 700;
    width: 30px;
    text-align: right;
  }}

  /* ── Filter Bar ──────────────────────────────────────────────── */
  .filter-container {{
    margin-bottom: 24px;
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 12px;
    background: var(--surface);
    border: 1px solid var(--border);
    padding: 12px 16px;
    border-radius: 8px;
  }}
  .filter-label {{
    font-family: var(--mono);
    font-size: 11px;
    color: var(--muted);
    text-transform: uppercase;
    letter-spacing: 1px;
    margin-right: 8px;
  }}
  .filter-btn {{
    font-family: var(--mono);
    font-size: 12px;
    background: rgba(255, 255, 255, 0.03);
    border: 1px solid var(--border);
    color: var(--text);
    padding: 6px 14px;
    border-radius: 6px;
    cursor: pointer;
    transition: all 0.2s ease;
    display: flex;
    align-items: center;
    gap: 6px;
  }}
  .filter-btn:hover:not(:disabled) {{
    background: rgba(255, 255, 255, 0.08);
    border-color: var(--border-hover);
  }}
  .filter-btn.active {{
    background: var(--btn-color, var(--text));
    color: #07080a;
    border-color: var(--btn-color, var(--text));
    font-weight: 600;
  }}

  /* ── Findings ────────────────────────────────────────────────── */
  .findings-section h2 {{
    font-family: var(--mono);
    font-size: 11px;
    letter-spacing: 2px;
    text-transform: uppercase;
    color: var(--muted);
  }}
  .sev-section {{ margin-bottom: 16px; }}
  .sev-header {{
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 14px 20px;
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 8px;
    cursor: pointer;
    font-family: var(--mono);
    font-weight: 700;
    font-size: 13px;
    letter-spacing: 1px;
    user-select: none;
    transition: background 0.2s, border-color 0.2s;
  }}
  .sev-header:hover {{
    background: var(--surface2);
    border-color: var(--border-hover);
  }}
  .sev-count {{ font-weight: 500; opacity: 0.6; margin-left: 6px; }}
  .toggle-arrow {{ font-size: 10px; transition: transform 0.2s ease; }}
  .sev-header.collapsed .toggle-arrow {{ transform: rotate(-90deg); }}
  .sev-body {{ padding: 12px 0 0; display: flex; flex-direction: column; gap: 12px; }}
  .sev-body.hidden {{ display: none; }}

  .finding-card {{
    background: var(--surface-card);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 18px 24px;
    border-left-width: 4px;
    border-left-style: solid;
    transition: transform 0.2s cubic-bezier(0.16, 1, 0.3, 1), box-shadow 0.2s ease, border-color 0.2s ease;
  }}
  .finding-card:hover {{
    transform: translateY(-2px);
    border-color: var(--border-hover);
    box-shadow: 0 8px 30px rgba(0, 0, 0, 0.3);
  }}
  .finding-header {{
    display: flex;
    justify-content: space-between;
    align-items: flex-start;
    gap: 16px;
    margin-bottom: 8px;
  }}
  .finding-msg {{
    font-family: var(--sans);
    font-size: 15px;
    font-weight: 600;
    color: var(--text);
    flex: 1;
    line-height: 1.5;
  }}
  .finding-scanner {{
    font-family: var(--mono);
    font-size: 10px;
    background: rgba(255, 255, 255, 0.05);
    border: 1px solid var(--border);
    padding: 3px 8px;
    border-radius: 4px;
    color: var(--muted);
    flex-shrink: 0;
    white-space: nowrap;
  }}
  .finding-loc {{
    font-family: var(--mono);
    font-size: 12px;
    color: var(--muted);
    margin-bottom: 12px;
  }}
  .finding-loc code {{
    color: #60a5fa;
    background: rgba(59, 130, 246, 0.08);
    padding: 2px 8px;
    border-radius: 4px;
    border: 1px solid rgba(59, 130, 246, 0.15);
  }}
  .detail {{
    font-family: var(--sans);
    font-size: 13px;
    color: var(--muted);
    border-top: 1px solid var(--border);
    padding-top: 12px;
    margin-top: 12px;
    line-height: 1.6;
  }}
  .remediation {{
    font-family: var(--sans);
    font-size: 13px;
    color: #a7f3d0;
    border-top: 1px solid rgba(16, 185, 129, 0.1);
    padding-top: 12px;
    margin-top: 12px;
    background: rgba(16, 185, 129, 0.02);
    padding: 8px 12px;
    border-radius: 4px;
  }}
  .rem-label {{
    font-family: var(--mono);
    font-size: 10px;
    letter-spacing: 1px;
    text-transform: uppercase;
    color: #34d399;
    font-weight: 700;
    margin-right: 6px;
  }}

  /* ── Action Buttons ──────────────────────────────────────────── */
  .action-btn {{
    font-family: var(--mono);
    font-size: 10px;
    background: transparent;
    border: 1px solid var(--border);
    color: var(--muted);
    padding: 4px 8px;
    border-radius: 4px;
    cursor: pointer;
    transition: all 0.2s ease;
  }}
  .action-btn:hover {{
    color: var(--text);
    border-color: var(--border-hover);
    background: rgba(255,255,255,0.03);
  }}

  /* ── Empty State ─────────────────────────────────────────────── */
  .empty-state {{
    text-align: center;
    padding: 64px 32px;
    background: var(--surface);
    border: 1px dashed var(--border);
    border-radius: 8px;
    margin: 20px 0;
  }}
  .empty-icon {{
    font-size: 32px;
    color: var(--low);
    background: rgba(16, 185, 129, 0.1);
    width: 64px;
    height: 64px;
    line-height: 64px;
    border-radius: 50%;
    margin: 0 auto 16px;
    display: flex;
    align-items: center;
    justify-content: center;
    box-shadow: 0 0 20px rgba(16, 185, 129, 0.2);
  }}
  .empty-title {{
    font-family: var(--sans);
    font-size: 18px;
    font-weight: 600;
    color: var(--text);
    margin-bottom: 8px;
  }}
  .empty-desc {{
    font-family: var(--sans);
    font-size: 14px;
    color: var(--muted);
    max-width: 400px;
    margin: 0 auto;
  }}

  /* ── Footer ──────────────────────────────────────────────────── */
  .footer {{
    border-top: 1px solid var(--border);
    padding: 40px 24px;
    text-align: center;
    margin-top: 64px;
  }}
  .footer .dn-rule {{
    font-family: var(--mono);
    font-size: 11px;
    color: var(--muted);
    letter-spacing: 2px;
    text-transform: uppercase;
    margin-bottom: 12px;
  }}
  .footer p {{
    font-family: var(--sans);
    color: var(--muted);
    font-size: 13px;
  }}

  /* ── Sticky nav ──────────────────────────────────────────────── */
  .sticky-bar {{
    position: sticky;
    top: 0;
    z-index: 100;
    background: rgba(7, 8, 10, 0.9);
    backdrop-filter: blur(8px);
    border-bottom: 1px solid var(--border);
    padding: 12px 24px;
    display: flex;
    align-items: center;
    gap: 20px;
    font-family: var(--mono);
    font-size: 11px;
  }}
  .sticky-logo {{
    color: var(--text);
    font-weight: 800;
    letter-spacing: 2px;
    margin-right: auto;
    font-family: var(--sans);
  }}
  .sticky-logo span {{
    color: var(--info);
  }}
  .sticky-stat {{ color: var(--muted); display: flex; align-items: center; gap: 4px; }}
  .sticky-stat span {{ font-weight: 700; }}
</style>
</head>
<body>

<div class="header">
  <div class="header-rule">— Security Scan Report —</div>
  <h1>ShadowCI</h1>
  <div class="subtitle">v2.0.0 · by ne0k1ra</div>
</div>

<div class="sticky-bar">
  <span class="sticky-logo">SHADOW<span>CI</span></span>
  <span class="sticky-stat">CRITICAL <span style="color:#ef4444">{counts.get('CRITICAL',0)}</span></span>
  <span class="sticky-stat">HIGH <span style="color:#f97316">{counts.get('HIGH',0)}</span></span>
  <span class="sticky-stat">MEDIUM <span style="color:#f59e0b">{counts.get('MEDIUM',0)}</span></span>
  <span class="sticky-stat">RISK <span style="color:{risk_col}">{risk_score}/100</span></span>
  <span class="sticky-stat" style="color:{verdict_col}; font-weight:700">{verdict}</span>
</div>

<div class="container">

  <div class="meta-grid">
    <div class="meta-card">
      <div class="label">Target</div>
      <div class="value">{_esc(abs_target)}</div>
    </div>
    <div class="meta-card">
      <div class="label">Scan Time</div>
      <div class="value">{now}</div>
    </div>
    <div class="meta-card">
      <div class="label">Total Findings</div>
      <div class="value" style="font-size:28px; font-weight:700; color:var(--text)">{total}</div>
    </div>
    <div class="meta-card verdict-card">
      <div class="label">Verdict</div>
      <div class="verdict-text">{verdict}</div>
    </div>
  </div>

  <div class="risk-section">
    <h2>Risk Assessment</h2>
    <div class="risk-score-row">
      <div class="risk-number">{risk_score}</div>
      <div style="flex:1">
        <div style="font-family:var(--mono);font-size:11px;color:var(--muted);margin-bottom:6px;">RISK SCORE / 100</div>
        <div class="risk-track"><div class="risk-fill"></div></div>
      </div>
    </div>
    {bar_html}
  </div>

  {filter_buttons_html}

  <div class="findings-section">
    <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:20px;">
      <h2>Findings</h2>
      <div style="display:flex; gap:10px;">
        <button class="action-btn" onclick="toggleAll(false)">Collapse All</button>
        <button class="action-btn" onclick="toggleAll(true)">Expand All</button>
      </div>
    </div>
    {findings_html if findings_html else f'''
    <div class="empty-state">
      <div class="empty-icon">✓</div>
      <div class="empty-title">All Checks Passed</div>
      <div class="empty-desc">No security vulnerabilities or configuration issues were detected in this repository.</div>
    </div>'''}
  </div>

</div>

<div class="footer">
  <div class="dn-rule">— end of report —</div>
  <p style="margin-top:8px;font-size:11px;">Generated by ShadowCI · {now}</p>
</div>

<script>
function toggleSection(header) {{
  const body = header.nextElementSibling;
  const isCollapsed = body.classList.contains('hidden');
  body.classList.toggle('hidden');
  header.classList.toggle('collapsed');
}}

function toggleAll(expand) {{
  document.querySelectorAll('.sev-section').forEach(section => {{
    const header = section.querySelector('.sev-header');
    const body = section.querySelector('.sev-body');
    if (expand) {{
      body.classList.remove('hidden');
      header.classList.remove('collapsed');
    }} else {{
      body.classList.add('hidden');
      header.classList.add('collapsed');
    }}
  }});
}}

function filterFindings(severity) {{
  // Update active state of buttons
  document.querySelectorAll('.filter-btn').forEach(btn => {{
    if (btn.getAttribute('data-severity') === severity) {{
      btn.classList.add('active');
    }} else {{
      btn.classList.remove('active');
    }}
  }});

  // Filter sections
  document.querySelectorAll('.sev-section').forEach(section => {{
    const sectionSev = section.getAttribute('data-severity');
    if (severity === 'ALL' || sectionSev === severity) {{
      section.style.display = 'block';
    }} else {{
      section.style.display = 'none';
    }}
  }});
}}

// Auto-collapse LOW and INFO sections
document.addEventListener('DOMContentLoaded', function() {{
  document.querySelectorAll('.sev-header').forEach(function(h) {{
    if (h.textContent.includes('LOW') || h.textContent.includes('INFO')) {{
      h.nextElementSibling.classList.add('hidden');
      h.classList.add('collapsed');
    }}
  }});
}});
</script>
</body>
</html>"""

    with open(output_path, 'w', encoding='utf-8') as fp:
        fp.write(html)

    return output_path
