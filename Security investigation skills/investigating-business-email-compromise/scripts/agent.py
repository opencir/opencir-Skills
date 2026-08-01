#!/usr/bin/env python3
"""BEC baseline-deviation and exfiltration-spike scorer.

Reads a BEC case file and computes the two judgements that drive report section 2
and section 3: how far observed sign-in activity departs from the user's known-good
baseline, and how far the incident-window download volume departs from the user's
own 30-day rate.

Scoring weights deviation *combinations*, not single fields - one anomaly is travel
or a new phone, several within a window is a compromise signal.

Usage:
    python agent.py --case case.json
    python agent.py --case case.json --quiet     # risk_level only
"""

import argparse
import json
import sys

UNKNOWN = "UNKNOWN"

# Field -> weight. Geography and network identity carry more signal than a browser
# minor-version bump, which changes on its own with every update.
FIELD_WEIGHTS = {
    "asn": 25,
    "isp": 15,
    "country": 25,
    "city": 10,
    "device_type": 15,
    "os": 10,
    "browser": 8,
    "browser_version": 2,
}

FIELD_LABELS = {
    "asn": "ASN",
    "isp": "ISP",
    "country": "Country",
    "city": "City",
    "device_type": "Device type",
    "os": "Operating system",
    "browser": "Browser",
    "browser_version": "Browser version",
}

# usageType values that indicate a machine, not a person's home or office.
HOSTING_MARKERS = (
    "data center", "datacenter", "web hosting", "transit", "hosting",
    "vpn", "proxy", "tor", "cloud",
)


def is_unknown(value):
    return value is None or str(value).strip().upper() == UNKNOWN or not str(value).strip()


def compare_baseline(case):
    """Diff observed against the analyst-supplied legitimate baseline."""
    baseline = case.get("baseline", {}) or {}
    observed = case.get("observed", {}) or {}
    results = []
    for key, weight in FIELD_WEIGHTS.items():
        b_val, o_val = baseline.get(key), observed.get(key)
        if is_unknown(b_val) or is_unknown(o_val):
            verdict = UNKNOWN
        elif str(b_val).strip().lower() == str(o_val).strip().lower():
            verdict = "MATCH"
        else:
            verdict = "DEVIATION"
        results.append({
            "field": FIELD_LABELS[key],
            "baseline": b_val if not is_unknown(b_val) else UNKNOWN,
            "observed": o_val if not is_unknown(o_val) else UNKNOWN,
            "verdict": verdict,
            "weight": weight,
        })
    return results


def score_asn(case):
    """Score the observed ASN's usage type. Analyst-supplied, not a tool verdict."""
    asn = case.get("asn_assessment", {}) or {}
    usage = str(asn.get("usage_type", "")).lower()
    category = str(asn.get("category", "")).lower()
    haystack = usage + " " + category
    if any(marker in haystack for marker in HOSTING_MARKERS):
        return 30, ("Observed ASN is hosting/VPN/proxy infrastructure - humans do not "
                    "normally read corporate mail from a datacenter")
    if "bulletproof" in haystack:
        return 40, "Observed ASN is abuse-tolerant hosting"
    if is_unknown(asn.get("usage_type")) and is_unknown(asn.get("category")):
        return 0, "ASN usage type not assessed"
    return 0, "Observed ASN category is consistent with normal user access"


def score_exfiltration(case):
    """Compare incident-window downloads against the user's own daily baseline."""
    ex = case.get("exfiltration", {}) or {}
    mean = ex.get("baseline_daily_mean")
    count = ex.get("incident_downloads")
    try:
        mean = float(mean)
        count = float(count)
    except (TypeError, ValueError):
        return 0, None, "Download baseline or incident count not recorded"

    if mean <= 0:
        return 0, None, "Baseline daily mean is zero - ratio undefined"

    ratio = count / mean
    if ratio >= 50:
        return 30, ratio, f"Download volume is {ratio:.0f}x the user's daily baseline"
    if ratio >= 10:
        return 20, ratio, f"Download volume is {ratio:.0f}x the user's daily baseline"
    if ratio >= 3:
        return 10, ratio, f"Download volume is {ratio:.1f}x the user's daily baseline"
    return 0, ratio, f"Download volume is {ratio:.1f}x baseline - within normal variation"


def score_persistence(case):
    """Persistence artefacts are decisive regardless of geography."""
    score, findings = 0, []
    for row in case.get("mailbox_persistence") or []:
        if not isinstance(row, dict) or "_comment" in row:
            continue
        if any(not is_unknown(v) for v in row.values()):
            score += 20
            findings.append(
                f"Mailbox persistence: {row.get('type', 'artefact')} - "
                f"{row.get('detail', UNKNOWN)}")

    for row in case.get("graph_activity") or []:
        if not isinstance(row, dict) or "_comment" in row:
            continue
        op = str(row.get("operation", "")).lower()
        if "consent" in op or "service principal" in op:
            score += 25
            findings.append(
                "Illicit OAuth consent or service principal - survives password reset "
                "and session revocation, must be revoked separately")
    return min(score, 45), findings


def score_iocs(case):
    """Count malicious/suspicious enrichment verdicts."""
    hits, checked = 0, 0
    for row in case.get("ioc_enrichment") or []:
        if not isinstance(row, dict) or "_comment" in row:
            continue
        verdict = str(row.get("verdict", "")).strip().lower()
        if not verdict or verdict == "not checked":
            continue
        checked += 1
        if verdict in ("malicious", "suspicious"):
            hits += 1
    score = min(hits * 12, 30)
    return score, hits, checked


def risk_level(score):
    if score >= 75:
        return "CRITICAL"
    if score >= 50:
        return "HIGH"
    if score >= 25:
        return "MEDIUM"
    return "LOW"


def analyse(case):
    baseline = compare_baseline(case)
    deviations = [b for b in baseline if b["verdict"] == "DEVIATION"]
    comparable = [b for b in baseline if b["verdict"] != UNKNOWN]
    unknown_fields = [b["field"] for b in baseline if b["verdict"] == UNKNOWN]

    deviation_score = sum(d["weight"] for d in deviations)
    asn_score, asn_note = score_asn(case)
    exfil_score, ratio, exfil_note = score_exfiltration(case)
    persist_score, persist_findings = score_persistence(case)
    ioc_score, ioc_hits, ioc_checked = score_iocs(case)

    total = min(
        deviation_score + asn_score + exfil_score + persist_score + ioc_score, 100)

    findings = []
    if len(deviations) >= 3:
        findings.append(
            f"{len(deviations)} of {len(comparable)} comparable fields deviate from "
            "baseline - deviation stacking indicates compromise, not travel")
    elif deviations:
        findings.append(
            f"{len(deviations)} of {len(comparable)} comparable fields deviate from "
            "baseline - verify with the user before concluding")
    if asn_score:
        findings.append(asn_note)
    if exfil_note and exfil_score:
        findings.append(exfil_note)
    findings.extend(persist_findings)
    if ioc_hits:
        findings.append(
            f"{ioc_hits} of {ioc_checked} enriched indicators returned "
            "malicious or suspicious")

    caveats = []
    if not comparable:
        caveats.append(
            "No baseline comparison was possible - both baseline and observed are "
            "empty. The score reflects other evidence only.")
    if unknown_fields:
        caveats.append(
            "Not compared (UNKNOWN on one side): " + ", ".join(unknown_fields))
    if ioc_checked == 0:
        caveats.append(
            "No indicators were enriched - absence of IOC hits here does not mean "
            "the indicators are clean.")

    return {
        "asset": (case.get("asset", {}) or {}).get("username", UNKNOWN),
        "investigation_id": (case.get("case", {}) or {}).get("investigation_id", UNKNOWN),
        "baseline_comparison": baseline,
        "deviation_count": len(deviations),
        "comparable_fields": len(comparable),
        "download_spike_ratio": round(ratio, 1) if ratio is not None else UNKNOWN,
        "ioc_hits": ioc_hits,
        "ioc_checked": ioc_checked,
        "score_breakdown": {
            "baseline_deviation": deviation_score,
            "asn_usage_type": asn_score,
            "download_spike": exfil_score,
            "persistence": persist_score,
            "ioc_enrichment": ioc_score,
        },
        "risk_score": total,
        "risk_level": risk_level(total),
        "findings": findings,
        "caveats": caveats,
    }


def main():
    parser = argparse.ArgumentParser(
        description="Score BEC baseline deviations and exfiltration spike")
    parser.add_argument("--case", required=True, help="Path to the case JSON file")
    parser.add_argument("--quiet", action="store_true",
                        help="Print only the risk level")
    args = parser.parse_args()

    try:
        with open(args.case, encoding="utf-8") as fh:
            case = json.load(fh)
    except FileNotFoundError:
        sys.exit(f"ERROR: case file not found: {args.case}")
    except json.JSONDecodeError as exc:
        sys.exit(f"ERROR: case file is not valid JSON: {exc}")

    result = analyse(case)
    if args.quiet:
        print(result["risk_level"])
    else:
        print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
