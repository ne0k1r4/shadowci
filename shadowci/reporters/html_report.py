"""
HTML report generator — Death Note themed self-contained HTML report.
No external dependencies. Pure inline CSS + JS.
"""
import os
import json
from datetime import datetime
from typing import List
from ..models import Finding, calculate_risk_score, SEVERITY_ORDER

SEVERITY_COLORS = {
    "CRITICAL": "#dc2626",
    "HIGH":     "#ea580c",
    "MEDIUM":   "#ca8a04",
    "LOW":      "#16a34a",
    "INFO":     "#2563eb",
}
SEVERITY_BG = {
    "CRITICAL": "#1c0a0a",
    "HIGH":     "#1c0f08",
    "MEDIUM":   "#1c1808",
    "LOW":      "#081c0a",
    "INFO":     "#080f1c",
}
SEVERITY_GLYPHS = {
    "CRITICAL": "†",
    "HIGH":     "⚠",
    "MEDIUM":   "◈",
    "LOW":      "◇",
    "INFO":     "○",
}


def _esc(s: str) -> str:
    return (s.replace('&','&amp;').replace('<','&lt;')
             .replace('>','&gt;').replace('"','&quot;'))


def generate_html_report(findings: List[Finding], target_path: str,
                         output_path: str = "shadowci_report.html") -> str:
    now          = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    total        = len(findings)
    risk_score   = calculate_risk_score(findings)
    abs_target   = os.path.abspath(target_path)

    counts = {s: 0 for s in SEVERITY_ORDER}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    has_critical = counts.get("CRITICAL", 0) > 0
    has_high     = counts.get("HIGH", 0) > 0
    if has_critical:
        verdict     = "† CONDEMNED †"
        verdict_col = "#dc2626"
    elif has_high:
        verdict     = "⚠ JUDGMENT PENDING"
        verdict_col = "#ea580c"
    elif counts.get("MEDIUM", 0) > 0:
        verdict     = "◈ UNDER SCRUTINY"
        verdict_col = "#ca8a04"
    else:
        verdict     = "◇ ABSOLVED"
        verdict_col = "#16a34a"

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
        col   = SEVERITY_COLORS.get(sev, "#fff")
        bg    = SEVERITY_BG.get(sev, "#111")
        glyph = SEVERITY_GLYPHS.get(sev, "·")
        cnt   = len(group)

        cards = ""
        for f in group:
            loc = _esc(f.file) + (f":{f.line}" if f.line else "")
            det = f'<div class="detail">{_esc(f.detail)}</div>' if f.detail else ""
            rem = f'<div class="remediation"><span class="rem-label">Fix:</span> {_esc(f.remediation)}</div>' if f.remediation else ""
            cards += f"""
            <div class="finding-card" style="border-left:3px solid {col}; background:{bg};">
              <div class="finding-header">
                <span class="finding-msg">{_esc(f.message)}</span>
                <span class="finding-scanner">{_esc(f.scanner)}</span>
              </div>
              <div class="finding-loc">↳ <code>{loc}</code></div>
              {det}{rem}
            </div>"""

        findings_html += f"""
        <div class="sev-section">
          <div class="sev-header" style="border-color:{col}; color:{col};"
               onclick="toggleSection(this)">
            <span>{glyph} {sev} <span class="sev-count">({cnt})</span></span>
            <span class="toggle-arrow">▼</span>
          </div>
          <div class="sev-body">{cards}</div>
        </div>"""

    # Summary bars
    bar_html = ""
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        c = counts.get(sev, 0)
        if c == 0:
            continue
        col  = SEVERITY_COLORS.get(sev, "#fff")
        pct  = min(c * 3, 100)
        bar_html += f"""
        <div class="bar-row">
          <span class="bar-label" style="color:{col};">{SEVERITY_GLYPHS.get(sev,'·')} {sev}</span>
          <div class="bar-track">
            <div class="bar-fill" style="width:{pct}%; background:{col};"></div>
          </div>
          <span class="bar-count" style="color:{col};">{c}</span>
        </div>"""

    risk_col = "#dc2626" if risk_score >= 80 else "#ea580c" if risk_score >= 50 else "#ca8a04" if risk_score >= 25 else "#16a34a"
    risk_pct = risk_score

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>ShadowCI Report — {_esc(os.path.basename(abs_target))}</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=Crimson+Pro:ital,wght@0,400;0,600;1,400&family=JetBrains+Mono:wght@400;700&display=swap');

  *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}

  :root {{
    --bg:       #0a0a0a;
    --surface:  #111111;
    --surface2: #181818;
    --border:   #2a2a2a;
    --text:     #e8e8e8;
    --muted:    #666;
    --crimson:  #dc2626;
    --gold:     #d4a017;
    --bone:     #f5f0e8;
    --mono:     'JetBrains Mono', monospace;
    --serif:    'Crimson Pro', Georgia, serif;
  }}

  html {{ scroll-behavior: smooth; }}
  body {{ background: var(--bg); color: var(--text); font-family: var(--serif); font-size: 16px; line-height: 1.6; }}

  /* ── Header ─────────────────────────────────────────────────── */
  .header {{
    background: linear-gradient(180deg, #0f0000 0%, #0a0a0a 100%);
    border-bottom: 1px solid #2a0000;
    padding: 48px 32px 32px;
    text-align: center;
    position: relative;
    overflow: hidden;
  }}
  .header::before {{
    content: '';
    position: absolute; inset: 0;
    background: radial-gradient(ellipse at 50% 0%, rgba(220,38,38,0.08) 0%, transparent 70%);
    pointer-events: none;
  }}
  .header-rule {{
    font-family: var(--mono);
    font-size: 10px;
    color: #3a0000;
    letter-spacing: 4px;
    text-transform: uppercase;
    margin-bottom: 16px;
  }}
  .header h1 {{
    font-family: var(--mono);
    font-size: clamp(22px, 4vw, 40px);
    font-weight: 700;
    color: var(--crimson);
    letter-spacing: 6px;
    text-transform: uppercase;
    text-shadow: 0 0 40px rgba(220,38,38,0.4);
    margin-bottom: 8px;
  }}
  .header .subtitle {{
    font-family: var(--serif);
    font-style: italic;
    color: var(--gold);
    font-size: 14px;
    margin-bottom: 24px;
  }}
  .header .quote {{
    font-family: var(--serif);
    font-style: italic;
    color: #555;
    font-size: 13px;
    max-width: 500px;
    margin: 0 auto;
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
    border-radius: 6px;
    padding: 20px;
  }}
  .meta-card .label {{
    font-family: var(--mono);
    font-size: 10px;
    letter-spacing: 2px;
    text-transform: uppercase;
    color: var(--muted);
    margin-bottom: 8px;
  }}
  .meta-card .value {{
    font-family: var(--mono);
    font-size: 13px;
    color: var(--bone);
    word-break: break-all;
  }}
  .verdict-card {{
    text-align: center;
    border-color: {verdict_col}44;
  }}
  .verdict-text {{
    font-family: var(--serif);
    font-size: 22px;
    font-weight: 600;
    color: {verdict_col};
    text-shadow: 0 0 20px {verdict_col}44;
  }}

  /* ── Risk score ──────────────────────────────────────────────── */
  .risk-section {{
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 24px;
    margin-bottom: 32px;
  }}
  .risk-section h2 {{
    font-family: var(--mono);
    font-size: 11px;
    letter-spacing: 3px;
    text-transform: uppercase;
    color: var(--muted);
    margin-bottom: 20px;
  }}
  .risk-score-row {{
    display: flex;
    align-items: center;
    gap: 20px;
    margin-bottom: 20px;
  }}
  .risk-number {{
    font-family: var(--mono);
    font-size: 48px;
    font-weight: 700;
    color: {risk_col};
    line-height: 1;
    text-shadow: 0 0 30px {risk_col}55;
    min-width: 80px;
  }}
  .risk-track {{
    flex: 1;
    height: 12px;
    background: #1a1a1a;
    border-radius: 6px;
    overflow: hidden;
    border: 1px solid var(--border);
  }}
  .risk-fill {{
    height: 100%;
    width: {risk_pct}%;
    background: linear-gradient(90deg, {risk_col}88, {risk_col});
    border-radius: 6px;
    transition: width 1s ease;
  }}
  .bar-row {{
    display: flex;
    align-items: center;
    gap: 12px;
    margin-bottom: 10px;
  }}
  .bar-label {{
    font-family: var(--mono);
    font-size: 11px;
    width: 90px;
    flex-shrink: 0;
  }}
  .bar-track {{
    flex: 1;
    height: 6px;
    background: #1a1a1a;
    border-radius: 3px;
    overflow: hidden;
  }}
  .bar-fill {{
    height: 100%;
    border-radius: 3px;
  }}
  .bar-count {{
    font-family: var(--mono);
    font-size: 12px;
    font-weight: 700;
    width: 30px;
    text-align: right;
  }}

  /* ── Findings ────────────────────────────────────────────────── */
  .findings-section h2 {{
    font-family: var(--mono);
    font-size: 11px;
    letter-spacing: 3px;
    text-transform: uppercase;
    color: var(--muted);
    margin-bottom: 20px;
  }}
  .sev-section {{ margin-bottom: 16px; }}
  .sev-header {{
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 14px 20px;
    background: var(--surface);
    border: 1px solid;
    border-radius: 6px;
    cursor: pointer;
    font-family: var(--mono);
    font-weight: 700;
    font-size: 14px;
    letter-spacing: 2px;
    user-select: none;
    transition: background 0.2s;
  }}
  .sev-header:hover {{ background: var(--surface2); }}
  .sev-count {{ font-weight: 400; opacity: 0.7; }}
  .toggle-arrow {{ font-size: 10px; transition: transform 0.2s; }}
  .sev-header.collapsed .toggle-arrow {{ transform: rotate(-90deg); }}
  .sev-body {{ padding: 12px 0 0; display: flex; flex-direction: column; gap: 8px; }}
  .sev-body.hidden {{ display: none; }}

  .finding-card {{
    border-radius: 4px;
    padding: 16px 20px;
    border-left-width: 3px;
    border-left-style: solid;
  }}
  .finding-header {{
    display: flex;
    justify-content: space-between;
    align-items: flex-start;
    gap: 12px;
    margin-bottom: 8px;
  }}
  .finding-msg {{
    font-family: var(--serif);
    font-size: 15px;
    font-weight: 600;
    color: var(--bone);
    flex: 1;
  }}
  .finding-scanner {{
    font-family: var(--mono);
    font-size: 10px;
    background: #ffffff11;
    border: 1px solid #ffffff22;
    padding: 2px 8px;
    border-radius: 3px;
    color: var(--muted);
    flex-shrink: 0;
    white-space: nowrap;
  }}
  .finding-loc {{
    font-family: var(--mono);
    font-size: 12px;
    color: var(--muted);
    margin-bottom: 8px;
  }}
  .finding-loc code {{
    color: #8ab4f8;
    background: #0a1628;
    padding: 1px 6px;
    border-radius: 3px;
  }}
  .detail {{
    font-family: var(--serif);
    font-size: 13px;
    color: #999;
    border-top: 1px solid #ffffff0a;
    padding-top: 8px;
    margin-top: 8px;
  }}
  .remediation {{
    font-family: var(--serif);
    font-size: 13px;
    color: #6ee7b7;
    border-top: 1px solid #6ee7b711;
    padding-top: 8px;
    margin-top: 8px;
  }}
  .rem-label {{
    font-family: var(--mono);
    font-size: 10px;
    letter-spacing: 1px;
    text-transform: uppercase;
    color: #34d399;
    font-weight: 700;
  }}

  /* ── Footer ──────────────────────────────────────────────────── */
  .footer {{
    border-top: 1px solid #1a0000;
    padding: 32px 24px;
    text-align: center;
    margin-top: 64px;
  }}
  .footer .dn-rule {{
    font-family: var(--mono);
    font-size: 10px;
    color: #2a0000;
    letter-spacing: 4px;
    text-transform: uppercase;
    margin-bottom: 12px;
  }}
  .footer p {{
    font-family: var(--serif);
    font-style: italic;
    color: var(--muted);
    font-size: 13px;
  }}

  /* ── Sticky nav ──────────────────────────────────────────────── */
  .sticky-bar {{
    position: sticky;
    top: 0;
    z-index: 100;
    background: #0a0a0aee;
    backdrop-filter: blur(8px);
    border-bottom: 1px solid var(--border);
    padding: 8px 24px;
    display: flex;
    align-items: center;
    gap: 20px;
    font-family: var(--mono);
    font-size: 11px;
  }}
  .sticky-logo {{ color: var(--crimson); font-weight: 700; letter-spacing: 2px; margin-right: auto; }}
  .sticky-stat {{ color: var(--muted); }}
  .sticky-stat span {{ font-weight: 700; }}
</style>
</head>
<body>

<div class="header">
  <div class="header-rule">— Repository Security Intelligence —</div>
  <h1>ShadowCI</h1>
  <div class="subtitle">Death Note Edition · v1.2.0 · by ne0k1ra</div>
  <div class="quote">「 If you can see it — you can judge it. 」</div>
</div>

<div class="sticky-bar">
  <span class="sticky-logo">† SHADOWCI</span>
  <span class="sticky-stat">CRITICAL <span style="color:#dc2626">{counts.get('CRITICAL',0)}</span></span>
  <span class="sticky-stat">HIGH <span style="color:#ea580c">{counts.get('HIGH',0)}</span></span>
  <span class="sticky-stat">MEDIUM <span style="color:#ca8a04">{counts.get('MEDIUM',0)}</span></span>
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
      <div class="value" style="font-size:28px; color:var(--bone)">{total}</div>
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

  <div class="findings-section">
    <h2>Findings</h2>
    {findings_html if findings_html else '<div style="color:var(--muted);font-style:italic;padding:32px 0;">◇ No findings detected. Ryuk is disappointed.</div>'}
  </div>

</div>

<div class="footer">
  <div class="dn-rule">— end of judgment —</div>
  <p>「 The names have been written. There is no going back. 」</p>
  <p style="margin-top:8px;font-size:11px;">Generated by ShadowCI · {now}</p>
</div>

<script>
function toggleSection(header) {{
  const body = header.nextElementSibling;
  const isCollapsed = body.classList.contains('hidden');
  body.classList.toggle('hidden');
  header.classList.toggle('collapsed');
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
