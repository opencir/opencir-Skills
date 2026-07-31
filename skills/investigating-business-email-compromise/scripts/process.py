#!/usr/bin/env python3
"""
BEC Investigation Report Engine

Renders a Business Email Compromise case file into a single self-contained HTML
incident report with seven sections, and validates case files before rendering.

The output has no external stylesheets, scripts, fonts, or images - it renders
offline, prints to PDF, and is safe to attach to a ticket. All interpolated values
are HTML-escaped; all indicators are defanged so a circulated report cannot be
clicked into a live threat.

Usage:
    python process.py report   --case case.json --out bec-report.html
    python process.py validate --case case.json

Requirements:
    Python 3.8+ standard library only - nothing to install.
"""

import argparse
import html
import json
import re
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone

UNKNOWN = "UNKNOWN"

# Severity -> accent colour, matching the palette used across this repository's
# HTML-reporting skills.
SEVERITY_COLORS = {
    "critical": "#e74c3c",
    "high": "#e67e22",
    "medium": "#f1c40f",
    "low": "#3498db",
    "info": "#95a5a6",
    UNKNOWN: "#95a5a6",
}

VERDICT_COLORS = {
    "malicious": "#e74c3c",
    "suspicious": "#e67e22",
    "deviation": "#e74c3c",
    "match": "#27ae60",
    "clean": "#27ae60",
    "benign": "#27ae60",
    "not checked": "#95a5a6",
    UNKNOWN: "#95a5a6",
}

# Sections required in a well-formed case file.
REQUIRED_TOP_LEVEL = [
    "case", "asset", "baseline", "observed", "phishing_email",
    "ioc_enrichment", "exfiltration", "graph_activity", "timeline",
    "root_cause", "recommendations",
]

# Fields compared between the legitimate baseline and observed activity.
BASELINE_FIELDS = [
    ("asn", "ASN"),
    ("isp", "ISP"),
    ("country", "Country"),
    ("city", "City"),
    ("device_type", "Device type"),
    ("os", "Operating system"),
    ("browser", "Browser"),
    ("browser_version", "Browser version"),
]

_IPV4 = re.compile(r"\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b")


@dataclass
class RenderStats:
    """Counters surfaced in the executive summary KPI row."""
    severity: str = UNKNOWN
    dwell_time: str = UNKNOWN
    ioc_hits: int = 0
    ioc_checked: int = 0
    files_downloaded: int = 0
    files_viewed: int = 0
    deviations: int = 0
    baseline_compared: int = 0
    timeline_events: int = 0
    open_actions: int = 0
    warnings: list = field(default_factory=list)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def defang(value):
    """Neutralise indicators so the rendered report cannot be clicked into a threat.

    Defangs URL schemes, every dot in a URL's authority component (TLD-agnostic, so
    an unusual TLD is still neutralised), IPv4 addresses, bare domains on a known
    TLD, and the @ in a bare email address. Prose is left readable - a sentence
    containing a full stop is not a domain.
    """
    if not isinstance(value, str) or not value.strip():
        return value
    out = value
    out = re.sub(r"(?i)\bhttps://", "hxxps://", out)
    out = re.sub(r"(?i)\bhttp://", "hxxp://", out)
    out = re.sub(r"(?i)\bftp://", "fxp://", out)

    # Defang the host of any (already scheme-neutralised) URL, whatever its TLD.
    # The lookarounds make this idempotent - analysts often paste IOCs that are
    # already defanged, and [.] must not become [[.]].
    def _host(match):
        return match.group(1) + re.sub(r"(?<!\[)\.(?!\])", "[.]", match.group(2))

    out = re.sub(r"(?i)\b(hxxps?://|fxp://)([^/\s?#]+)", _host, out)

    out = _IPV4.sub(lambda m: "{}.{}.{}[.]{}".format(*m.groups()), out)
    # Bare hostnames: only where they clearly look like a domain, not prose.
    out = re.sub(r"(?i)\b([a-z0-9-]+)\.(com|net|org|io|ru|cn|top|xyz|info|biz|co)\b",
                 r"\1[.]\2", out)
    out = out.replace("@", "[at]") if "@" in out and " " not in out else out
    return out


def esc(value, do_defang=False):
    """HTML-escape any value. Case data contains attacker-controlled strings."""
    if value is None:
        return UNKNOWN
    if isinstance(value, (list, tuple)):
        value = ", ".join(str(v) for v in value) if value else "None"
    if isinstance(value, bool):
        value = "Yes" if value else "No"
    text = str(value)
    if not text.strip():
        return UNKNOWN
    if do_defang:
        text = defang(text)
    return html.escape(text, quote=True)


def is_unknown(value):
    return value is None or str(value).strip().upper() == UNKNOWN or not str(value).strip()


def strip_comments(obj):
    """Drop _comment keys, and drop list rows that carry one.

    A dict inside a list that has a _comment key is a template example row - the
    shipped case-template.json marks every one of them. Removing them here means a
    half-filled template never leaks placeholder rows into the report, even if the
    analyst forgot to delete them.
    """
    if isinstance(obj, dict):
        return {k: strip_comments(v) for k, v in obj.items() if k != "_comment"}
    if isinstance(obj, list):
        return [
            strip_comments(i) for i in obj
            if not (isinstance(i, dict) and "_comment" in i)
        ]
    return obj


def parse_utc(value):
    """Parse an ISO-8601 UTC timestamp, tolerating a trailing Z. None if unparseable."""
    if is_unknown(value):
        return None
    text = str(value).strip().replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def format_duration(start, end):
    """Human-readable gap between two datetimes."""
    if not start or not end:
        return UNKNOWN
    delta = end - start
    if delta.total_seconds() < 0:
        return UNKNOWN
    days = delta.days
    hours, rem = divmod(delta.seconds, 3600)
    minutes = rem // 60
    if days:
        return f"{days}d {hours}h {minutes}m"
    if hours:
        return f"{hours}h {minutes}m"
    return f"{minutes}m"


def color_for(value, table, default="#95a5a6"):
    return table.get(str(value).strip().lower(), default)


def real_rows(rows):
    """Template example rows carry only UNKNOWN values; drop them from the report."""
    out = []
    for row in rows or []:
        if not isinstance(row, dict):
            continue
        values = [v for k, v in row.items() if k != "_comment"]
        if any(not is_unknown(v) for v in values if not isinstance(v, (list, dict))):
            out.append(row)
    return out


# ---------------------------------------------------------------------------
# Analysis
# ---------------------------------------------------------------------------

def compare_baseline(case):
    """Diff observed activity against the analyst-supplied legitimate baseline."""
    baseline = case.get("baseline", {})
    observed = case.get("observed", {})
    rows = []
    for key, label in BASELINE_FIELDS:
        b_val = baseline.get(key, UNKNOWN)
        o_val = observed.get(key, UNKNOWN)
        if is_unknown(b_val) or is_unknown(o_val):
            verdict = UNKNOWN
        elif str(b_val).strip().lower() == str(o_val).strip().lower():
            verdict = "MATCH"
        else:
            verdict = "DEVIATION"
        rows.append({"label": label, "baseline": b_val, "observed": o_val, "verdict": verdict})
    return rows


def compute_stats(case, baseline_rows):
    """Derive the KPI figures shown in the executive summary."""
    stats = RenderStats()
    stats.severity = case.get("case", {}).get("severity", UNKNOWN)

    metrics = case.get("metrics", {})
    stats.dwell_time = format_duration(
        parse_utc(metrics.get("initial_compromise_utc")),
        parse_utc(metrics.get("detection_utc")),
    )

    iocs = real_rows(case.get("ioc_enrichment"))
    stats.ioc_checked = len(iocs)
    stats.ioc_hits = sum(
        1 for i in iocs
        if str(i.get("verdict", "")).strip().lower() in ("malicious", "suspicious")
    )

    exfil = case.get("exfiltration", {})
    stats.files_downloaded = len(real_rows(exfil.get("files_downloaded")))
    stats.files_viewed = len(real_rows(exfil.get("files_viewed")))

    stats.deviations = sum(1 for r in baseline_rows if r["verdict"] == "DEVIATION")
    stats.baseline_compared = sum(1 for r in baseline_rows if r["verdict"] != UNKNOWN)
    stats.timeline_events = len(real_rows(case.get("timeline")))
    stats.open_actions = sum(
        1 for r in real_rows(case.get("recommendations"))
        if str(r.get("status", "")).strip().lower() != "closed"
    )

    if stats.baseline_compared == 0:
        stats.warnings.append(
            "No baseline comparison was possible - neither the legitimate baseline nor the "
            "observed values were supplied. Section 2 cannot distinguish normal from anomalous."
        )
    if stats.ioc_checked == 0:
        stats.warnings.append(
            "No IOC enrichment was recorded. Indicators were not checked against threat "
            "intelligence - this is not the same as the indicators being clean."
        )
    if is_unknown(metrics.get("initial_compromise_utc")):
        stats.warnings.append(
            "Initial compromise time is UNKNOWN, so dwell time cannot be calculated."
        )
    return stats


def compute_metrics_table(case):
    """Response metrics derived from the timeline, with their targets."""
    m = case.get("metrics", {})
    compromise = parse_utc(m.get("initial_compromise_utc"))
    detection = parse_utc(m.get("detection_utc"))
    triage = parse_utc(m.get("triage_complete_utc"))
    containment = parse_utc(m.get("containment_utc"))
    recovery = parse_utc(m.get("recovery_utc"))
    return [
        ("Dwell time", "Initial compromise to detection",
         format_duration(compromise, detection), "< 24 hours"),
        ("MTTD", "Detection to triage complete",
         format_duration(detection, triage), "< 30 minutes"),
        ("MTTC", "Detection to containment",
         format_duration(detection, containment), "< 4 hours"),
        ("MTTR", "Detection to recovery",
         format_duration(detection, recovery), "< 48 hours"),
    ]


# ---------------------------------------------------------------------------
# HTML building blocks
# ---------------------------------------------------------------------------

def table(headers, rows, empty_msg="No data recorded.", defang_cols=None):
    """Render a table, or an empty-state note when there are no rows."""
    if not rows:
        return f'<p class="empty">{esc(empty_msg)}</p>'
    defang_cols = defang_cols or set()
    head = "".join(f"<th>{esc(h)}</th>" for h in headers)
    body = []
    for row in rows:
        cells = []
        for idx, cell in enumerate(row):
            cells.append(f"<td>{esc(cell, do_defang=idx in defang_cols)}</td>")
        body.append(f"<tr>{''.join(cells)}</tr>")
    return (
        '<div class="table-wrap"><table>'
        f"<thead><tr>{head}</tr></thead>"
        f"<tbody>{''.join(body)}</tbody>"
        "</table></div>"
    )


def badge(text, color):
    return f'<span class="badge" style="background:{color}">{esc(text)}</span>'


def kpi_card(value, label, color):
    return (
        f'<div class="card" style="border-top-color:{color}">'
        f"<h3>{esc(value)}</h3><p>{esc(label)}</p></div>"
    )


def field_table(pairs, defang_keys=None):
    """Two-column label/value table for metadata blocks."""
    defang_keys = defang_keys or set()
    rows = "".join(
        f"<tr><th>{esc(k)}</th><td>{esc(v, do_defang=k in defang_keys)}</td></tr>"
        for k, v in pairs
    )
    return f'<div class="table-wrap"><table class="kv">{rows}</table></div>'


CSS = """
* { box-sizing: border-box; }
body { font-family: Arial, Helvetica, sans-serif; margin: 0; padding: 24px;
       background: #f5f5f5; color: #222; line-height: 1.5; }
.wrap { max-width: 1200px; margin: 0 auto; }
.header { background: #1a1a2e; color: #fff; padding: 24px 28px; border-radius: 8px; }
.header h1 { margin: 0 0 6px; font-size: 1.6em; }
.header .sub { opacity: .82; font-size: .9em; margin: 2px 0; }
.header .cls { display: inline-block; margin-top: 12px; padding: 4px 10px;
               border: 1px solid rgba(255,255,255,.35); border-radius: 4px;
               font-size: .75em; letter-spacing: .06em; text-transform: uppercase; }
.asset { background: #fff; border-radius: 8px; padding: 18px 22px; margin: 18px 0;
         box-shadow: 0 2px 4px rgba(0,0,0,.1); border-left: 5px solid #1a1a2e; }
.asset h2 { margin: 0 0 10px; font-size: 1em; text-transform: uppercase;
            letter-spacing: .05em; color: #555; }
nav.toc { background: #fff; border-radius: 8px; padding: 14px 22px; margin: 18px 0;
          box-shadow: 0 2px 4px rgba(0,0,0,.1);
          display: flex; flex-wrap: wrap; gap: 8px 20px; }
nav.toc a { color: #2c3e50; text-decoration: none; font-size: .9em;
            white-space: nowrap; }
nav.toc a:hover { text-decoration: underline; }
section { background: #fff; border-radius: 8px; padding: 22px 26px; margin: 18px 0;
          box-shadow: 0 2px 4px rgba(0,0,0,.1); }
section > h2 { margin: 0 0 4px; font-size: 1.15em; color: #1a1a2e;
               border-bottom: 2px solid #eee; padding-bottom: 10px; }
section > h2 .num { color: #7f8c8d; font-weight: normal; margin-right: 8px; }
h3 { font-size: .95em; color: #2c3e50; margin: 20px 0 8px; }
.summary { display: flex; gap: 14px; flex-wrap: wrap; margin: 18px 0; }
.card { background: #fff; border: 1px solid #eee; border-top: 4px solid #95a5a6;
        border-radius: 8px; padding: 16px 20px; flex: 1 1 150px; text-align: center; }
.card h3 { margin: 0; font-size: 1.7em; color: #1a1a2e; }
.card p { margin: 4px 0 0; font-size: .8em; color: #666; }
.table-wrap { overflow-x: auto; margin: 10px 0; }
table { width: 100%; border-collapse: collapse; font-size: .88em; min-width: 760px; }
th { background: #2c3e50; color: #fff; padding: 10px 12px; text-align: left;
     font-weight: 600; white-space: nowrap; }
/* overflow-wrap breaks only strings that cannot fit (long URLs, user agents);
   ordinary words such as "Bucharest" stay intact, unlike word-break. */
td { padding: 9px 12px; border-bottom: 1px solid #eee; vertical-align: top;
     overflow-wrap: break-word; }
tr:last-child td { border-bottom: none; }
tbody tr:hover { background: #f8f9fa; }
table.kv { min-width: 0; }
table.kv th { background: #f4f6f8; color: #2c3e50; width: 220px;
              border-bottom: 1px solid #eee; }
.badge { display: inline-block; padding: 3px 9px; border-radius: 3px; color: #fff;
         font-size: .78em; font-weight: 600; letter-spacing: .02em; }
.empty { color: #888; font-style: italic; font-size: .9em; margin: 10px 0; }
.note { border-left: 4px solid #f1c40f; background: #fffdf3; padding: 12px 16px;
        margin: 14px 0; font-size: .88em; border-radius: 0 4px 4px 0; }
.note.crit { border-left-color: #e74c3c; background: #fdf3f2; }
.rc { background: #1a1a2e; color: #fff; padding: 16px 20px; border-radius: 6px;
      margin: 16px 0; }
.rc .lbl { font-size: .75em; text-transform: uppercase; letter-spacing: .08em;
           opacity: .7; }
.rc .val { font-size: 1.05em; margin-top: 5px; }
.prose { white-space: pre-wrap; }
footer { text-align: center; color: #888; font-size: .8em; padding: 24px 0; }
@media print {
  body { background: #fff; padding: 0; }
  section, .asset, nav.toc { box-shadow: none; border: 1px solid #ddd;
                             page-break-inside: avoid; }
  nav.toc { display: none; }
}
@media (max-width: 640px) {
  body { padding: 12px; }
  .card { flex: 1 1 100%; }
}
"""


# ---------------------------------------------------------------------------
# Section renderers
# ---------------------------------------------------------------------------

def sec1_summary(case, stats):
    sev_color = color_for(stats.severity, SEVERITY_COLORS)
    cards = "".join([
        kpi_card(stats.severity, "Severity", sev_color),
        kpi_card(stats.dwell_time, "Dwell time", "#e67e22"),
        kpi_card(f"{stats.ioc_hits}/{stats.ioc_checked}", "IOC hits / checked", "#e74c3c"),
        kpi_card(stats.files_downloaded, "Files downloaded", "#3498db"),
        kpi_card(stats.files_viewed, "Files viewed", "#f1c40f"),
        kpi_card(f"{stats.deviations}/{stats.baseline_compared}",
                 "Baseline deviations", "#e74c3c"),
    ])
    summary = case.get("executive_summary", UNKNOWN)
    body = (
        f'<p class="prose">{esc(summary)}</p>' if not is_unknown(summary)
        else '<p class="empty">No executive summary recorded.</p>'
    )
    warnings = "".join(
        f'<div class="note">{esc(w)}</div>' for w in stats.warnings
    )
    return section(1, "Executive Summary",
                   f'<div class="summary">{cards}</div>{body}{warnings}')


def sec2_indicators(case, baseline_rows):
    # Baseline comparison
    rows = [
        (r["label"], r["baseline"], r["observed"], r["verdict"])
        for r in baseline_rows
    ]
    cmp_table = table(
        ["Field", "Legitimate baseline", "Observed", "Verdict"], rows,
        "No baseline or observed values supplied.",
    )
    dev = sum(1 for r in baseline_rows if r["verdict"] == "DEVIATION")
    known = sum(1 for r in baseline_rows if r["verdict"] != UNKNOWN)
    if known:
        note = (
            f'<div class="note{" crit" if dev >= 3 else ""}">'
            f"{dev} of {known} comparable fields deviate from the user's known-good baseline. "
            "A single deviation is weak evidence; several within a short window is a "
            "compromise signal.</div>"
        )
    else:
        note = ""

    # ASN assessment
    asn = case.get("asn_assessment", {})
    asn_block = field_table([
        ("Observed ASN", asn.get("observed_asn", UNKNOWN)),
        ("Usage type", asn.get("usage_type", UNKNOWN)),
        ("Category", asn.get("category", UNKNOWN)),
        ("Risk", asn.get("risk", UNKNOWN)),
        ("Rationale", asn.get("rationale", UNKNOWN)),
    ])

    # Sign-ins
    signin_rows = [
        (s.get("timestamp_utc"), s.get("ip"), s.get("asn"), s.get("isp"),
         s.get("country"), s.get("city"), s.get("os"), s.get("browser"),
         s.get("result"), s.get("mfa"), s.get("assessment"))
        for s in real_rows(case.get("signins"))
    ]
    signins = table(
        ["Time (UTC)", "IP", "ASN", "ISP", "Country", "City", "OS", "Browser",
         "Result", "MFA", "Assessment"],
        signin_rows, "No sign-in records recorded.", defang_cols={1},
    )

    # Observed user agent / IPs
    obs = case.get("observed", {})
    obs_block = field_table([
        ("User agent", obs.get("user_agent", UNKNOWN)),
        ("IP addresses", obs.get("ip_addresses", UNKNOWN)),
    ], defang_keys={"IP addresses"})

    # Phishing email
    mail = case.get("phishing_email", {})
    auth = mail.get("auth_results", {}) or {}
    mail_block = field_table([
        ("Sender", mail.get("sender", UNKNOWN)),
        ("Display name", mail.get("sender_display_name", UNKNOWN)),
        ("Subject", mail.get("subject", UNKNOWN)),
        ("URL", mail.get("url", UNKNOWN)),
        ("Received (UTC)", mail.get("received_utc", UNKNOWN)),
        ("Clicked (UTC)", mail.get("clicked_utc", UNKNOWN)),
        ("Recipients", mail.get("recipient_count", UNKNOWN)),
        ("Delivery action", mail.get("delivery_action", UNKNOWN)),
        ("SPF", auth.get("spf", UNKNOWN)),
        ("DKIM", auth.get("dkim", UNKNOWN)),
        ("DMARC", auth.get("dmarc", UNKNOWN)),
        ("Analysis", mail.get("analysis", UNKNOWN)),
    ], defang_keys={"Sender", "URL"})

    # IOC enrichment
    ioc_rows = []
    for i in real_rows(case.get("ioc_enrichment")):
        verdict = i.get("verdict", UNKNOWN)
        ioc_rows.append((
            i.get("indicator"), i.get("type"), i.get("tool"),
            verdict, i.get("sources"), i.get("detail"),
        ))
    iocs = table(
        ["Indicator", "Type", "MCP tool", "Verdict", "Sources", "Detail"],
        ioc_rows,
        "No IOC enrichment recorded. Indicators were not checked - this is not the "
        "same as the indicators being clean.",
        defang_cols={0},
    )

    # Mailbox persistence
    persist_rows = [
        (p.get("timestamp_utc"), p.get("type"), p.get("name"), p.get("detail"),
         p.get("source_ip"), p.get("assessment"))
        for p in real_rows(case.get("mailbox_persistence"))
    ]
    persist = table(
        ["Time (UTC)", "Type", "Name", "Detail", "Source IP", "Assessment"],
        persist_rows, "No mailbox persistence artefacts recorded.", defang_cols={4},
    )

    content = (
        "<h3>Legitimate baseline vs observed</h3>" + cmp_table + note +
        "<h3>Observed client</h3>" + obs_block +
        "<h3>ASN / ISP assessment</h3>" + asn_block +
        '<div class="note">ASN classification is analyst judgement against the criteria in '
        "<code>references/standards.md</code>. The threat-intel MCP server has no dedicated "
        "ASN lookup tool - <code>isp</code> and <code>usageType</code> come from AbuseIPDB and "
        "GreyNoise metadata returned inside <code>threatintel_lookup_ip</code>.</div>" +
        "<h3>Sign-in activity</h3>" + signins +
        "<h3>Phishing email analysis</h3>" + mail_block +
        "<h3>Threat intelligence enrichment (MCP)</h3>" + iocs +
        "<h3>Mailbox persistence</h3>" + persist
    )
    return section(2, "Suspicious ASN/ISP, OS, User Agent, Geography, IPs &amp; "
                      "Phishing Email Analysis", content)


def sec3_exfiltration(case):
    ex = case.get("exfiltration", {})
    summary = field_table([
        (f"Baseline daily mean ({ex.get('baseline_window_days', 30)}-day)",
         ex.get("baseline_daily_mean", UNKNOWN)),
        ("Incident-window downloads", ex.get("incident_downloads", UNKNOWN)),
        ("Incident window (hours)", ex.get("incident_window_hours", UNKNOWN)),
        ("Spike ratio", ex.get("spike_ratio", UNKNOWN)),
        ("Sites affected", ex.get("sites_affected", UNKNOWN)),
        ("Sensitivity labels", ex.get("sensitivity_labels", UNKNOWN)),
    ])
    dl_rows = [
        (f.get("timestamp_utc"), f.get("file"), f.get("site"),
         f.get("operation"), f.get("ip"))
        for f in real_rows(ex.get("files_downloaded"))
    ]
    downloaded = table(
        ["Time (UTC)", "File", "Site", "Operation", "IP"], dl_rows,
        "No file downloads recorded.", defang_cols={4},
    )
    view_rows = [
        (f.get("timestamp_utc"), f.get("file"), f.get("site"),
         f.get("operation"), f.get("ip"))
        for f in real_rows(ex.get("files_viewed"))
    ]
    viewed = table(
        ["Time (UTC)", "File", "Site", "Operation", "IP"], view_rows,
        "No file views recorded.", defang_cols={4},
    )
    content = (
        "<h3>Download spike against the user's own baseline</h3>" + summary +
        '<div class="note">Report the ratio, not the raw count. Files merely <em>viewed</em> '
        "still represent exposure and may carry notification obligations, but they are "
        "distinct from bulk download.</div>"
        "<h3>Files downloaded</h3>" + downloaded +
        "<h3>Files viewed (not downloaded)</h3>" + viewed
    )
    return section(3, "SharePoint / OneDrive Download Spike &amp; Files Viewed", content)


def sec4_graph(case):
    rows = [
        (g.get("timestamp_utc"), g.get("app_id"), g.get("app_name"), g.get("operation"),
         g.get("scopes"), g.get("ip"), g.get("call_count"), g.get("assessment"))
        for g in real_rows(case.get("graph_activity"))
    ]
    content = table(
        ["Time (UTC)", "App ID", "App name", "Operation", "Scopes", "IP",
         "Calls", "Assessment"],
        rows, "No suspicious Graph API activity recorded.", defang_cols={5},
    )
    content += (
        '<div class="note crit">An illicit OAuth consent grant survives both session '
        "revocation and password reset. If one is present, credential reset alone will "
        "<strong>not</strong> evict the attacker - the grant must be revoked and any "
        "attacker service principal disabled.</div>"
    )
    return section(4, "Suspicious Microsoft Graph API Activity", content)


def sec5_timeline(case):
    events = real_rows(case.get("timeline"))
    events.sort(key=lambda e: (parse_utc(e.get("timestamp_utc")) or datetime.max.replace(
        tzinfo=timezone.utc)))
    rows = [
        (e.get("timestamp_utc"), e.get("event"), e.get("actor"), e.get("source"))
        for e in events
    ]
    tl = table(["Time (UTC)", "Event", "Actor", "Source"], rows,
               "No timeline events recorded.")
    metric_rows = [
        (name, definition, value, target)
        for name, definition, value, target in compute_metrics_table(case)
    ]
    metrics = table(["Metric", "Definition", "Value", "Target"], metric_rows)
    content = (
        tl +
        '<div class="note">All timestamps are UTC. Times that cannot be evidenced are left '
        "UNKNOWN rather than estimated - an estimated initial-compromise time silently "
        "changes the dwell-time headline.</div>"
        "<h3>Response metrics</h3>" + metrics
    )
    return section(5, "Incident Timeline", content)


def sec6_rca(case):
    rc = case.get("root_cause", {})
    whys = [
        (w.get("level"), w.get("question"), w.get("answer"), w.get("evidence"))
        for w in real_rows(rc.get("five_whys"))
    ]
    whys_table = table(["Level", "Question", "Answer", "Evidence"], whys,
                       "No 5 Whys analysis recorded.")
    root = rc.get("root_cause", UNKNOWN)
    block = (
        f'<div class="rc"><div class="lbl">Root cause</div>'
        f'<div class="val">{esc(root)}</div></div>'
    )
    conf = field_table([
        ("Confidence", rc.get("confidence", UNKNOWN)),
        ("Rationale", rc.get("confidence_rationale", UNKNOWN)),
    ])
    content = (
        whys_table + block + "<h3>Confidence</h3>" + conf +
        '<div class="note">A root cause must be a systemic gap the organisation can fix. '
        '"User clicked a link" is a symptom; the absent control that would have made the '
        "click survivable is the cause.</div>"
    )
    return section(6, "Root Cause Analysis", content)


def sec7_recommendations(case):
    recs = real_rows(case.get("recommendations"))
    order = {"immediate": 0, "short-term": 1, "long-term": 2}
    recs.sort(key=lambda r: order.get(str(r.get("horizon", "")).strip().lower(), 9))
    rows = [
        (r.get("id"), r.get("horizon"), r.get("action"), r.get("owner"),
         r.get("priority"), r.get("deadline"), r.get("category"), r.get("status"))
        for r in recs
    ]
    content = table(
        ["ID", "Horizon", "Action", "Owner", "Priority", "Deadline", "Category", "Status"],
        rows, "No recommendations recorded.",
    )
    content += (
        '<div class="note">Every recommendation carries an owner and a deadline. A row '
        "without both will not get done.</div>"
    )
    notes = case.get("evidence_notes") or []
    notes = [n for n in notes if isinstance(n, str) and n.strip()]
    if notes:
        items = "".join(f"<li>{esc(n)}</li>" for n in notes)
        content += f"<h3>Evidence notes &amp; limitations</h3><ul>{items}</ul>"
    return section(7, "Recommendations", content)


def section(num, title, content):
    return (
        f'<section id="section-{num}">'
        f'<h2><span class="num">{num}.</span>{title}</h2>'
        f"{content}</section>"
    )


# ---------------------------------------------------------------------------
# Document
# ---------------------------------------------------------------------------

SECTION_TITLES = [
    "Executive Summary",
    "Indicators &amp; Phishing Analysis",
    "Exfiltration",
    "Graph API Activity",
    "Timeline",
    "Root Cause",
    "Recommendations",
]


def render(case):
    """Render the full case file into one self-contained HTML document."""
    case = strip_comments(case)
    meta = case.get("case", {})
    asset = case.get("asset", {})
    baseline_rows = compare_baseline(case)
    stats = compute_stats(case, baseline_rows)

    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    title = meta.get("title", "Business Email Compromise Investigation")

    toc = "".join(
        f'<a href="#section-{i + 1}">{i + 1}. {t}</a>'
        for i, t in enumerate(SECTION_TITLES)
    )

    asset_block = field_table([
        ("Username / UPN", asset.get("username", UNKNOWN)),
        ("Display name", asset.get("display_name", UNKNOWN)),
        ("Department", asset.get("department", UNKNOWN)),
        ("Role", asset.get("role", UNKNOWN)),
        ("VIP / privileged", asset.get("vip", UNKNOWN)),
        ("Manager", asset.get("manager", UNKNOWN)),
    ])

    sections = "".join([
        sec1_summary(case, stats),
        sec2_indicators(case, baseline_rows),
        sec3_exfiltration(case),
        sec4_graph(case),
        sec5_timeline(case),
        sec6_rca(case),
        sec7_recommendations(case),
    ])

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{esc(title)}</title>
<style>{CSS}</style>
</head>
<body>
<div class="wrap">

  <div class="header">
    <h1>{esc(title)}</h1>
    <p class="sub">Investigation ID: {esc(meta.get('investigation_id', UNKNOWN))}
       &middot; Analyst: {esc(meta.get('analyst', UNKNOWN))}
       &middot; Opened: {esc(meta.get('date_utc', UNKNOWN))}</p>
    <p class="sub">Status: {esc(meta.get('status', UNKNOWN))}
       &middot; Severity: {esc(meta.get('severity', UNKNOWN))}
       &middot; Report generated: {esc(generated)}</p>
    <span class="cls">{esc(meta.get('classification', 'CONFIDENTIAL'))}</span>
  </div>

  <div class="asset">
    <h2>Asset under investigation</h2>
    {asset_block}
  </div>

  <nav class="toc">{toc}</nav>

  {sections}

  <footer>
    Generated by the <strong>investigating-business-email-compromise</strong> skill &middot;
    Opencir Skills &middot; {esc(generated)}<br>
    Indicators in this report are defanged. Handle according to your evidence and
    data-protection policy.
  </footer>

</div>
</body>
</html>
"""


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

def load_case(path):
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except FileNotFoundError:
        sys.exit(f"ERROR: case file not found: {path}")
    except json.JSONDecodeError as exc:
        sys.exit(f"ERROR: case file is not valid JSON: {exc}")


def cmd_validate(args):
    case = strip_comments(load_case(args.case))
    errors, warnings = [], []

    for key in REQUIRED_TOP_LEVEL:
        if key not in case:
            errors.append(f"Missing required top-level section: {key}")

    meta = case.get("case", {})
    for key in ("title", "investigation_id", "analyst", "date_utc", "severity"):
        if is_unknown(meta.get(key)):
            warnings.append(f"case.{key} is UNKNOWN")

    if is_unknown(case.get("asset", {}).get("username")):
        errors.append("asset.username is UNKNOWN - the report needs an asset to be about")

    baseline_rows = compare_baseline(case)
    if not any(r["verdict"] != UNKNOWN for r in baseline_rows):
        warnings.append(
            "No baseline comparison possible - baseline and observed are both empty")

    for name in ("ioc_enrichment", "timeline", "recommendations"):
        if not real_rows(case.get(name)):
            warnings.append(f"{name} contains no real entries (template rows only)")

    for entry in real_rows(case.get("timeline")):
        if parse_utc(entry.get("timestamp_utc")) is None and not is_unknown(
                entry.get("timestamp_utc")):
            warnings.append(
                f"Unparseable timeline timestamp: {entry.get('timestamp_utc')!r} "
                "(expected ISO-8601 UTC, e.g. 2026-07-20T14:32:11Z)")

    for w in warnings:
        print(f"WARN  {w}")
    for e in errors:
        print(f"ERROR {e}")
    print(f"\n{len(errors)} error(s), {len(warnings)} warning(s)")
    return 1 if errors else 0


def cmd_report(args):
    case = load_case(args.case)
    output = render(case)
    try:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(output)
    except IOError as exc:
        sys.exit(f"ERROR: could not write report: {exc}")
    print(f"Report written to {args.out} ({len(output):,} bytes)")
    return 0


def main():
    parser = argparse.ArgumentParser(
        description="BEC investigation report engine")
    sub = parser.add_subparsers(dest="command", required=True)

    p_report = sub.add_parser("report", help="Render the HTML incident report")
    p_report.add_argument("--case", required=True, help="Path to the case JSON file")
    p_report.add_argument("--out", required=True, help="Output HTML path")
    p_report.set_defaults(func=cmd_report)

    p_val = sub.add_parser("validate", help="Check a case file before rendering")
    p_val.add_argument("--case", required=True, help="Path to the case JSON file")
    p_val.set_defaults(func=cmd_validate)

    args = parser.parse_args()
    sys.exit(args.func(args))


if __name__ == "__main__":
    main()
