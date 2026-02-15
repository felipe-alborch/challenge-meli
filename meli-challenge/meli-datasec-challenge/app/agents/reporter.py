from __future__ import annotations

from typing import Dict, Any, List
from pathlib import Path


def _index_by_name(items: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    idx: Dict[str, Dict[str, Any]] = {}
    for it in items:
        name = it.get("name")
        if name:
            idx[name] = it
    return idx


def run(
    session_id: str,
    analyzer_out: Dict[str, Any],
    classifier_out: Dict[str, Any],
) -> Dict[str, Any]:

    project_root = Path(__file__).resolve().parents[2]
    runs_dir = project_root / "runs" / session_id
    runs_dir.mkdir(parents=True, exist_ok=True)

    detectors = analyzer_out.get("detectors", [])
    classified = classifier_out.get("classified_detectors", [])

    classified_by_name = _index_by_name(classified)
    detectors_by_name = _index_by_name(detectors)

    # Prefer ordering by classifier score (already sorted)
    ordered_names = [c.get("name") for c in classified if c.get("name")]
    ordered_detectors = [detectors_by_name[n] for n in ordered_names if n in detectors_by_name]

    report_path = runs_dir / "report.md"

    with report_path.open("w", encoding="utf-8") as f:
        f.write("# UEBA Detection Proposal\n\n")
        f.write(f"**Session ID:** `{session_id}`\n\n")

        f.write("## Summary\n\n")
        f.write(
            "This report summarizes detection proposals (Analyzer) and their enrichment "
            "(Classifier: MITRE mapping + risk scoring), aligned with DBIR 2025 themes.\n\n"
        )

        f.write("> Detectors are ordered by classifier risk_score (descending).\n\n")

        f.write("## Proposed Detectors\n\n")

        for i, d in enumerate(ordered_detectors, 1):
            name = d.get("name")
            c = classified_by_name.get(name, {})

            f.write(f"### {i}. {name}\n\n")

            # Risk from classifier
            f.write(f"**Risk Level:** {c.get('risk_level', 'unknown')}\n\n")

            score = c.get("risk_score")
            impact = c.get("impact")
            likelihood = c.get("likelihood")
            if score is not None:
                line = f"**Risk Score:** {score}"
                if impact is not None and likelihood is not None:
                    line += f" (Impact {impact}/5 × Likelihood {likelihood}/5)"
                f.write(line + "\n\n")

            rr = c.get("risk_rationale")
            if rr:
                f.write("**Risk Rationale:**\n")
                f.write(f"{rr}\n\n")

            # MITRE from classifier
            mitre = c.get("mitre", [])
            if mitre:
                f.write("**MITRE ATT&CK Mapping:**\n")
                for m in mitre:
                    tech = m.get("technique", "")
                    nm = m.get("name", "")
                    if tech or nm:
                        f.write(f"- {tech} — {nm}\n")
                f.write("\n")

            # Details from analyzer
            f.write(f"**Goal:** {d.get('goal')}\n\n")

            f.write("**Data Needed:**\n")
            for item in d.get("data_needed", []):
                f.write(f"- {item}\n")
            f.write("\n")

            f.write("**Detection Logic:**\n")
            f.write(f"{d.get('detection_logic')}\n\n")

            f.write("**Expected False Positives:**\n")
            f.write(f"{d.get('expected_false_positives')}\n\n")

            f.write("**Tuning Ideas:**\n")
            f.write(f"{d.get('tuning_ideas')}\n\n")

            f.write("**Rationale (Analyzer):**\n")
            f.write(f"{d.get('rationale')}\n\n")

            f.write("---\n\n")

    return {
        "message": "report generated",
        "report_path": str(report_path),
        "session_id_seen": session_id,
    }
