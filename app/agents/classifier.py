from __future__ import annotations

from typing import Dict, Any, List
from app.mcp.mitre_client import get_technique_by_id

# --- MITRE mapping ---
MITRE_ID_MAP = {
    "ATO": ["T1078"],
    "EXPLOIT_PRIVESC": ["T1190", "T1068"],
    "RANSOMWARE": ["T1486", "T1490"],
    "EXFIL": ["T1041", "T1567"],
    "THIRD_PARTY": ["T1199", "T1078"],
}


def _risk_level_from_score(score: int) -> str:
    # Simple thresholds
    if score >= 200:
        return "High"
    if score >= 120:
        return "Med"
    return "Low"


def _score_from_category(category: str, telemetry: Dict[str, bool]) -> Dict[str, Any]:
    """
    Implements the scoring table we agreed:
    risk_score = impact * likelihood * 10
    """
    # Defaults
    impact = 3
    likelihood = 3

    if category == "ATO":
        impact = 5
        likelihood = 5 if telemetry.get("idp") else 4
        risk_rationale = (
            "High impact (account takeover enables broad access and can lead to escalation) and high likelihood "
            "given credential abuse prevalence; visibility improves with IdP telemetry."
        )

    elif category == "EXPLOIT_PRIVESC":
        impact = 5
        likelihood = 5 if telemetry.get("cloud") else 4
        risk_rationale = (
            "High impact (privileged access can compromise the environment) and increasing likelihood as exploitation "
            "is a common initial access vector; cloud audit telemetry improves detection confidence."
        )

    elif category == "RANSOMWARE":
        impact = 5
        likelihood = 5 if telemetry.get("edr") else 4
        risk_rationale = (
            "Very high impact due to business disruption and potential data loss/extortion; likelihood increases "
            "when EDR telemetry enables early behavioral signals."
        )

    elif category == "EXFIL":
        impact = 5
        likelihood = 5 if (telemetry.get("proxy") or telemetry.get("db")) else 4
        risk_rationale = (
            "High impact due to potential sensitive data leakage and regulatory exposure; likelihood increases when "
            "network/database telemetry enables correlation between export activity and outbound traffic."
        )

    elif category == "THIRD_PARTY":
        impact = 4
        likelihood = 4 if telemetry.get("idp") else 3
        risk_rationale = (
            "Moderate-to-high impact depending on accessed systems; likelihood increases with identity visibility "
            "into vendor behavior and access patterns."
        )

    else:
        risk_rationale = "Default scoring applied due to unknown category."

    risk_score = impact * likelihood * 10
    risk_level = _risk_level_from_score(risk_score)

    return {
        "impact": impact,
        "likelihood": likelihood,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "risk_rationale": risk_rationale,
    }


def run(session_id: str, analyzer_out: Dict[str, Any]) -> Dict[str, Any]:    
    # Soporta ambos formatos:
    # - analyzer_out crudo: {"detectors": [...]}
    # - analyzer_out envelope: {"payload": {"detectors": [...]}}
    detectors = analyzer_out.get("detectors")
    if detectors is None:
        detectors = (analyzer_out.get("payload") or {}).get("detectors", [])
    if detectors is None:
        detectors = []

    classified: List[Dict[str, Any]] = []

    for d in detectors:
        category = d.get("category_hint", "UNKNOWN")
        telemetry = d.get("telemetry_flags", {}) or {}

        scoring = _score_from_category(category, telemetry)

        # MITRE lookup vía MCP (con fallback)
        mitre: List[Dict[str, str]] = []
        for tid in MITRE_ID_MAP.get(category, []):
            info = get_technique_by_id(tid)

            if not info:
                mitre.append({"technique": tid, "name": "Unknown (MCP lookup failed)"})
                continue

            name = (
                info.get("name")
                or info.get("technique_name")
                or info.get("title")
                or "Unknown"
            )

            mitre.append({"technique": tid, "name": name})

        classified.append({
            "name": d.get("name"),
            "category": category,
            "mitre": mitre,
            **scoring,
        })

    # Orden por risk_score final
    classified.sort(key=lambda x: x.get("risk_score", 0), reverse=True)

    return {
        "message": "classifier ok",
        "session_id_seen": session_id,
        "classified_detectors": classified,
    }
