"""
Risk Score Calculator for RISK CHECKER.
Transparent, rule-based cybersecurity posture scoring engine (0-100 scale).
Incorporates severity weights, category caps, and deduplication.
"""

from typing import List, Dict, Any, Tuple


# Severity point weights
SEVERITY_WEIGHTS = {
    "CRITICAL": 35,
    "HIGH": 20,
    "MEDIUM": 10,
    "LOW": 4
}

# Maximum contribution caps per security domain to prevent disproportionate skewing
CATEGORY_CAPS = {
    "SSL/TLS Security": 45,
    "Transport Security": 35,
    "Port & Service Exposure": 35,
    "Injection Prevention": 25,
    "Cookie Security": 20,
    "Clickjacking": 15,
    "Information Disclosure": 12,
    "Device Feature Security": 10,
    "MIME Sniffing": 8,
    "General": 20
}


def classify_risk_level(score: int) -> str:
    """Classify 0-100 numerical score into risk bands."""
    if score >= 70:
        return "CRITICAL"
    elif score >= 40:
        return "HIGH"
    elif score >= 20:
        return "MEDIUM"
    else:
        return "LOW"


def deduplicate_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Deduplicates findings based on category and title.
    If duplicates occur, keeps the instance with higher severity.
    """
    severity_rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
    seen: Dict[Tuple[str, str], Dict[str, Any]] = {}

    for f in findings:
        cat = f.get("category", "General").strip()
        title = f.get("title", "").strip()
        key = (cat, title)

        if key not in seen:
            seen[key] = f
        else:
            current_rank = severity_rank.get(seen[key].get("severity", "LOW"), 1)
            new_rank = severity_rank.get(f.get("severity", "LOW"), 1)
            if new_rank > current_rank:
                seen[key] = f

    return list(seen.values())


def calculate_risk_score(
    findings: List[Dict[str, Any]],
    web_data: Dict[str, Any] = None,
    ssl_data: Dict[str, Any] = None,
    port_data: Dict[str, Any] = None
) -> Dict[str, Any]:
    """
    Calculates the overall configuration risk score (0-100).
    Returns total score, risk level, breakdown by category, and processed findings.
    """
    unique_findings = deduplicate_findings(findings)

    # Accumulate points grouped by category
    category_points: Dict[str, int] = {}
    severity_breakdown = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}

    for f in unique_findings:
        sev = f.get("severity", "LOW").upper()
        cat = f.get("category", "General")
        weight = SEVERITY_WEIGHTS.get(sev, 4)

        severity_breakdown[sev] = severity_breakdown.get(sev, 0) + 1
        category_points[cat] = category_points.get(cat, 0) + weight

    # Apply category caps to avoid single-domain inflation
    total_capped_score = 0
    category_summary = {}

    for cat, raw_pts in category_points.items():
        cap = CATEGORY_CAPS.get(cat, 30)
        effective_pts = min(raw_pts, cap)
        category_summary[cat] = {
            "raw_points": raw_pts,
            "capped_points": effective_pts,
            "max_cap": cap
        }
        total_capped_score += effective_pts

    # Clamp overall score between 0 and 100
    final_score = min(max(int(round(total_capped_score)), 0), 100)
    risk_level = classify_risk_level(final_score)

    # Sort findings by severity (Critical down to Low)
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    sorted_findings = sorted(
        unique_findings,
        key=lambda x: severity_order.get(x.get("severity", "LOW").upper(), 4)
    )

    return {
        "risk_score": final_score,
        "risk_level": risk_level,
        "severity_breakdown": severity_breakdown,
        "total_findings": len(sorted_findings),
        "category_summary": category_summary,
        "findings": sorted_findings,
        "scoring_methodology": {
            "scale": "0 - 100",
            "weights": SEVERITY_WEIGHTS,
            "caps": CATEGORY_CAPS,
            "disclaimer": "This score is an estimated defensive configuration risk score, not a comprehensive penetration test or vulnerability exploitation guarantee."
        }
    }
