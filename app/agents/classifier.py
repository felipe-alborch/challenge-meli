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
    if score >= 200:
        return "High"
    if score >= 120:
        return "Medium"
    return "Low"


def _score_from_category(category: str, telemetry: Dict[str, bool]) -> Dict[str, Any]:
    # Base por categoría (criterio de negocio/amenaza)
    # Ajustado para que haya priorización.
    base = {
        "RANSOMWARE":      (5, 5),  
        "ATO":             (5, 5),  
        "EXFIL":           (5, 4),
        "EXPLOIT_PRIVESC": (5, 4),
        "THIRD_PARTY":     (4, 3), 
    }

    impact, likelihood = base.get(category, (3, 3))

    bonus = 0
    if category == "ATO" and telemetry.get("idp"):
        bonus = 0 
    elif category == "RANSOMWARE" and telemetry.get("edr"):
        bonus = 0
    elif category == "EXFIL" and (telemetry.get("proxy") or telemetry.get("db")):
        bonus = 1
    elif category == "EXPLOIT_PRIVESC" and telemetry.get("cloud"):
        bonus = 1
    elif category == "THIRD_PARTY" and telemetry.get("idp"):
        bonus = 1

    likelihood = min(5, likelihood + bonus)

    if category == "RANSOMWARE":
        risk_rationale = (
            "Critical availability impact aligned with DBIR system intrusion patterns. "
            "Ransomware remains one of the most disruptive and prevalent attack outcomes."
        )
    elif category == "ATO":
        risk_rationale = (
            "High-impact credential abuse scenario aligned with DBIR credential-based breaches. "
            "MFA fatigue and valid account misuse remain highly prevalent initial access vectors."
        )
    elif category == "EXFIL":
        risk_rationale = (
            "High data exposure impact aligned with DBIR data breach outcomes. "
            "Exfiltration following abnormal export activity represents elevated business risk."
        )
    elif category == "EXPLOIT_PRIVESC":
        risk_rationale = (
            "Privilege escalation following vulnerability exploitation reflects DBIR system intrusion trends. "
            "Administrative access compromise significantly increases blast radius."
        )
    elif category == "THIRD_PARTY":
        risk_rationale = (
            "Third-party access abuse reflects DBIR supply chain and partner risk trends. "
            "Impact depends on privilege scope and monitoring maturity."
        )
    else:
        risk_rationale = (
            "Default scoring applied due to unknown category."
        )

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
