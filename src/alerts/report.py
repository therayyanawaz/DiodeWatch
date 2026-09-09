"""Human-readable incident report for one alert or a time window.

Two surfaces, one set of facts: `write_report` returns a self-contained HTML
file (no external assets, no JS dependencies — print-ready for PDF via the
browser's "Save as PDF"), and `render_report_page` returns the page the
mission-control console serves at /report/{alert_id} on its own stylesheet.
Both render the full evidence trail — envelope, ATT&CK mapping, the flow
5-tuple, every evidence item with observed value vs threshold, and the
advisory triage verdict — so an analyst can audit a detection without
re-running the detector.

    from src.alerts.store import AlertStore
    from src.alerts.report import write_report

    store = AlertStore("alerts.db")
    alerts = store.between("2026-09-04T00:00:00", "2026-09-04T01:00:00")
    write_report(alerts, "incident.html", title="Morning incident window")
"""
from __future__ import annotations

import html
from collections.abc import Iterable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .schema import Alert, display_class

_SEV_COLOR = {
    "critical": "#b3261e",
    "high": "#d97706",
    "medium": "#d4a017",
    "low": "#4c8c4a",
}

_CSS = """
:root { color-scheme: light dark; }
body { font-family: system-ui, -apple-system, "Segoe UI", sans-serif;
       margin: 0 auto; max-width: 960px; padding: 24px; line-height: 1.45; }
header.report h1 { font-size: 1.4rem; margin-bottom: 4px; }
header.report p { color: #777; margin: 2px 0; font-size: .9rem; }
table { border-collapse: collapse; width: 100%; margin: 8px 0; }
th, td { border: 1px solid #ddd; padding: 6px 8px; text-align: left;
         font-size: .85rem; vertical-align: top; }
th { background: #f2f2f2; }
.alert { border: 1px solid #ccc; border-radius: 8px; margin: 14px 0;
         padding: 12px 16px; page-break-inside: avoid; }
.alert h2 { margin: 0 0 6px; font-size: 1rem; display: flex; gap: 8px;
            align-items: center; flex-wrap: wrap; }
.badge { border-radius: 10px; padding: 1px 9px; font-size: .72rem;
         color: #fff; font-weight: 600; }
.meta { color: #666; font-size: .82rem; margin: 2px 0; }
.attck { font-family: ui-monospace, monospace; font-size: .82rem; }
.summary th, .summary td { font-size: .8rem; }
footer { margin-top: 24px; color: #999; font-size: .75rem; }
code { background: #f2f2f2; padding: 0 3px; border-radius: 3px; }
@media print { body { max-width: none; } .alert { break-inside: avoid; } }
"""


def _esc(v) -> str:
    if v is None:
        return ""
    return html.escape(str(v))


def _sev_badge(sev: str | None) -> str:
    sev = sev or "medium"
    color = _SEV_COLOR.get(sev, "#666")
    return f'<span class="badge" style="background:{color}">{_esc(sev.upper())}</span>'


def _conf(a: Alert) -> str:
    try:
        return f"{float(a.confidence) * 100:.1f}%"
    except (TypeError, ValueError):
        return _esc(a.confidence)


def _generated() -> str:
    """Rendered both as `generated {this} UTC`, so no offset belongs in it."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


# label -> key in the verdict envelope (src/triage/questions.answer_summary).
# Both renderers read the verdict through this one table, so a renamed engine
# key fails the report tests instead of silently printing a placeholder.
_TRIAGE_FIELDS = (("disposition", "recommended"),
                  ("urgency", "urgency"),
                  ("P(false-positive)", "p_false_positive"))


def triage_line(verdict: dict[str, Any]) -> str:
    """The one sentence this project prints about a verdict: both report
    renderers and the wall's evidence API share it rather than each rewording it.
    """
    return " · ".join(f"{label} {verdict[key]}"
                      for label, key in _TRIAGE_FIELDS
                      if verdict.get(key) is not None)


def _five_tuple(a: Alert) -> str:
    """The endpoints this detector actually observed, or an em dash.

    Fan-in and sweep alerts key on one endpoint, so the other is genuinely
    absent; printing empty octets around the arrow read as a broken record.
    Returned unescaped — callers render it through `_esc` like any field.
    """
    def ep(ip, port):
        if not ip:
            return None
        return f"{ip}:{port}" if port not in (None, "") else str(ip)

    src, dst = ep(a.src_ip, a.src_port), ep(a.dst_ip, a.dst_port)
    if src and dst:
        line = f"{src} → {dst}"
    elif src or dst:
        line = f"{'src' if src else 'dst'} {src or dst}"
    else:
        return "—"
    return f"{line} ({a.proto})" if a.proto else line


def _alert_block(a: Alert) -> str:
    rows = [
        ("alert_id", a.alert_id),
        ("timestamp", a.timestamp),
        ("window", f"{a.window_start} — {a.window_end}" if a.window_start and a.window_end else None),
        ("detector", a.detector),
        ("key (entity)", a.key),
        ("flow", a.flow_id),
        ("5-tuple", _five_tuple(a) if (a.src_ip or a.dst_ip) else None),
        ("confidence", _conf(a)),
    ]
    flow_rows = "".join(f"<tr><th>{_esc(k)}</th><td>{_esc(v)}</td></tr>"
                        for k, v in rows if v not in (None, ""))
    ev_rows = "".join(
        f"<tr><td><code>{_esc(e.condition)}</code></td>"
        f"<td>{_esc(e.observed)} {_esc(e.operator)} {_esc(e.threshold)}</td>"
        f"<td>{_esc(e.description)}</td><td>{_esc(e.unit)}</td></tr>"
        for e in a.evidence)
    attck = (f'<span class="attck">{_esc(a.attack_technique)} · '
             f'{_esc(a.attack_tactic)}</span>' if a.attack_technique else "—")
    verdict = _esc(triage_line(a.triage)) if a.triage else ""
    triage = (f'<p class="meta">TRIAGE — ADVISORY (NEVER MUTATES THE '
              f'DETECTION): {verdict}</p>' if verdict else "")
    return f"""
<div class="alert">
  <h2><span>Alert {_esc(display_class(a.threat_class))}</span>{_sev_badge(a.severity)}</h2>
  <p class="meta">ATT&CK: {attck}</p>
  <table>{flow_rows}</table>
  <table>
    <tr><th style="width:22%">Evidence condition</th>
        <th style="width:30%">observed vs threshold</th>
        <th>what it means</th><th style="width:9%">unit</th></tr>
    {ev_rows}
  </table>
  {triage}
</div>"""


def write_report(alerts: Iterable[Alert], out_path: str | Path,
                 title: str = "DiodeWatch incident report") -> Path:
    """Render alerts to a self-contained HTML report; returns the path."""
    alerts = sorted(alerts, key=lambda a: (a.timestamp or "", a.alert_id or ""))
    p = Path(out_path)
    p.parent.mkdir(parents=True, exist_ok=True)

    by_class: dict[str, int] = {}
    by_sev: dict[str, int] = {}
    for a in alerts:
        name = display_class(a.threat_class)
        by_class[name] = by_class.get(name, 0) + 1
        sev = a.severity or "medium"
        by_sev[sev] = by_sev.get(sev, 0) + 1

    summary_rows = "".join(
        f"<tr><td>{_esc(k)}</td><td>{v}</td></tr>"
        for k, v in sorted(by_class.items()))
    sev_rows = "".join(
        f"<tr><td>{_esc(k)}</td><td>{v}</td></tr>"
        for k, v in sorted(by_sev.items(), key=lambda kv: -kv[1]))
    generated = _generated()
    window = ""
    if alerts:
        first, last = alerts[0].timestamp, alerts[-1].timestamp
        # The wall's report route exports exactly one alert, so the degenerate
        # `X — X` range is what a judge printing that page actually sees.
        span = _esc(first) if first == last else f"{_esc(first)} — {_esc(last)}"
        window = f"<p>window: {span}</p>"

    body = "\n".join(_alert_block(a) for a in alerts)
    empty = ("" if alerts else "<p><strong>No alerts in the selected "
             "range.</strong></p>")
    html_doc = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>{_esc(title)}</title>
<style>{_CSS}</style></head>
<body>
<header class="report">
  <h1>{_esc(title)}</h1>
  <p>{len(alerts)} alert(s) · generated {generated} UTC</p>
  {window}
</header>
<table class="summary"><tr><td valign="top" style="width:50%">
  <table><tr><th colspan="2">By threat class</th></tr>{summary_rows}</table>
</td><td valign="top">
  <table><tr><th colspan="2">By severity</th></tr>{sev_rows}</table>
</td></tr></table>
{empty}
{body}
<footer>DiodeWatch · passive AI threat detection on unidirectional IP traffic ·
alert evidence store export</footer>
</body></html>"""
    p.write_text(html_doc, encoding="utf-8")
    return p


_REPORT_FAVICON = (
    "data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' "
    "viewBox='0 0 32 32'%3E%3Crect width='32' height='32' fill='%23fafafa'/%3E"
    "3Cpath d='M16 5 27 25H5L16 5Z' fill='%23171717'/%3E%3C/svg%3E")


def render_report_page(alerts: Iterable[Alert],
                       title: str = "DiodeWatch incident report") -> str:
    """Render alerts as an in-site page on the mission-control design system.

    Links the console's own stylesheet (same origin — still fully offline,
    no CDN) so the report inherits the design tokens and follows the
    light/dark theme chosen on the console (localStorage key `sih-theme`).
    Returned as an HTMLResponse by the /report/{alert_id} route.
    """
    alerts = sorted(alerts, key=lambda a: (a.timestamp or "", a.alert_id or ""))
    generated = _generated()

    def _sev_tag(sev: str | None) -> str:
        s = (sev or "medium").lower()
        cls = ("ev-tag--red" if s in ("critical", "high")
               else "ev-tag--amber" if s == "medium" else "ev-tag--green")
        return f'<span class="ev-tag {cls}">{_esc(s.upper())}</span>'

    blocks = []
    for a in alerts:
        tags = [_sev_tag(a.severity),
                f'<span class="ev-tag ev-tag--cyan">CONF {_esc(_conf(a))}</span>']
        if a.attack_technique:
            tags.append(f'<span class="ev-tag ev-tag--cyan">'
                        f'{_esc(a.attack_technique)}</span>')
        if a.attack_tactic:
            tags.append(f'<span class="ev-tag ev-tag--green">'
                        f'{_esc(a.attack_tactic)}</span>')
        if a.window_seconds:
            tags.append(f'<span class="ev-tag ev-tag--cyan">'
                        f'{_esc(a.window_seconds)}s WINDOW</span>')
        five = _esc(_five_tuple(a))
        ev_rows = "".join(
            f"<tr><td>{_esc(e.condition)}</td>"
            f"<td class=\"ev-obs\">{_esc(e.observed)}</td>"
            f"<td class=\"ev-op\">{_esc(e.operator)}</td>"
            f"<td>{_esc(e.threshold)}"
            + (f" <span class=\"ev-desc\">{_esc(e.unit)}</span>" if e.unit else "")
            + f"</td><td class=\"ev-desc\">{_esc(e.description)}</td></tr>"
            for e in a.evidence)
        verdict = _esc(triage_line(a.triage)) if a.triage else ""
        triage = (
            '<div class="ev-block"><p class="ev-block-title">'
            'TRIAGE — ADVISORY (NEVER MUTATES THE DETECTION)</p>'
            f'<div class="ev-tuple">{verdict}</div></div>') if verdict else ""
        blocks.append(f"""
    <section class="card">
      <div class="card-head"><b>{_esc(display_class(a.threat_class))}</b>
        <span class="muted">{_esc(a.detector or "detector")}</span></div>
      <div class="ev-tags ev-block">{"".join(tags)}</div>
      <div class="ev-block">
        <p class="ev-block-title">FLOW 5-TUPLE</p>
        <div class="ev-tuple">{five}<br>
          <span class="muted">entity {_esc(a.key or "—")} · flow
            {_esc(a.flow_id or "—")}</span><br>
          <span class="muted">{_esc(a.timestamp or "")} · window
            {_esc(a.window_start or "—")} → {_esc(a.window_end or "—")}</span>
        </div>
      </div>
      <div class="ev-block">
        <p class="ev-block-title">EVIDENCE — OBSERVED VS THRESHOLD</p>
        <table class="ev-table">
          <thead><tr><th>CONDITION</th><th>OBSERVED</th><th></th>
            <th>THRESHOLD</th><th>NOTES</th></tr></thead>
          <tbody>{ev_rows or '<tr><td colspan="5" class="muted">no evidence items</td></tr>'}</tbody>
        </table>
      </div>
      {triage}
    </section>""")

    body = "".join(blocks) or ('<section class="card"><p class="muted">'
                               "no alerts in the selected range</p></section>")
    return f"""<!DOCTYPE html>
<html lang="en" data-theme="">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light dark">
<title>{_esc(title)}</title>
<link rel="icon" href="{_REPORT_FAVICON}">
<link rel="stylesheet" href="/css/app.css">
<script>
try {{ var _t = localStorage.getItem("sih-theme");
  document.documentElement.dataset.theme = _t === "dark" ? "dark" : "";
}} catch (e) {{ }}
</script>
</head>
<body>
<header class="topbar report-topbar">
  <a class="brand" href="/">
    <svg class="brand-mark tri" aria-hidden="true" viewBox="0 0 24 24"><path fill="currentColor" stroke="none" d="M12 3.5 21.5 20h-19L12 3.5Z"/></svg>
    <span>DiodeWatch</span>
  </a>
  <span class="pill">Incident Report</span>
  <div class="top-right">
    <span class="sys-clock">generated {generated} UTC</span>
  </div>
</header>
<main class="content report-page">
  <section class="greeting">
    <h1>{_esc(title)}</h1>
    <p>{len(alerts)} alert(s) · full evidence trail — observed vs threshold,
       auditable without re-running the detector.</p>
  </section>
  {body}
  <footer class="foot">
    <span>DiodeWatch · passive AI threat detection on unidirectional IP traffic</span>
    <span class="foot-sep">·</span>
    <span>offline, zero external calls</span>
  </footer>
</main>
</body>
</html>"""
