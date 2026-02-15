from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Dict, Any


@dataclass
class Detector:
    name: str
    goal: str
    data_needed: List[str]
    detection_logic: str
    expected_false_positives: str
    tuning_ideas: str
    rationale: str
    telemetry_flags: Dict[str, bool]
    category_hint: str


class AnalyzerAgent:
    """
    Agent 1 (Analyzer):
    - reads the user input template (filled by user)
    - reads dbir_2025_subset.txt
    - proposes up to 5 detectors with preliminary risk + rationale
    """

    def __init__(self, project_root: Optional[Path] = None):
        # app/agents/analyzer.py -> parents[2] == repo_root
        self.project_root = project_root or Path(__file__).resolve().parents[2]
        self.inputs_dir = self.project_root / "inputs"
        self.data_dir = self.project_root / "data"

    def read_text_file(self, path: Path) -> str:
        if not path.exists():
            raise FileNotFoundError(f"Missing file: {path}")
        return path.read_text(encoding="utf-8", errors="replace")

    def propose_detectors(
        self,
        user_input_path: str = "template_input.txt",
        dbir_path: str = "dbir_2025_subset.txt",
        max_detectors: int = 5,
    ) -> List[Detector]:

        user_input = self.read_text_file(self.inputs_dir / user_input_path)
        _dbir_subset = self.read_text_file(self.data_dir / dbir_path)

        telemetry = self._infer_telemetry_flags(user_input)

        candidates: List[Detector] = []

        candidates.append(Detector(
            name="Suspicious sign-in chain (new geo/device + MFA fatigue + success)",
            goal="Detect account takeover patterns leveraging stolen credentials and MFA prompt bombing.",
            data_needed=["IdP sign-in logs", "MFA events", "Conditional Access / risk events (if available)"],
            detection_logic=(
                "Trigger when a user exhibits a deviation from their 30-day behavioral baseline in authentication patterns, "
                "including: (1) repeated MFA push prompts or denials within a short window (possible MFA fatigue), "
                "followed by (2) a successful sign-in from a new geographic location or previously unseen device fingerprint. "
                "Increase risk score if the login occurs outside the user’s typical working hours or differs significantly "
                "from their historical geo/device profile and peer group behavior."
            ),
            expected_false_positives="Users traveling or changing devices; noisy MFA prompts from misconfigured apps.",
            tuning_ideas="Whitelist known travel patterns; require 'new device' AND 'new geo'; add user baseline hours.",
            rationale=(
                "Aligned with DBIR themes: credential abuse + MFA fatigue. "
                f"Telemetry check: IdP logs={'yes' if telemetry['idp'] else 'no/unknown'}."
            ),
            telemetry_flags=telemetry,
            category_hint="ATO"
        ))

        candidates.append(Detector(
            name="Potential vulnerability exploitation leading to privileged session",
            goal="Detect suspicious privileged access shortly after unusual external access and sensitive changes.",
            data_needed=["Cloud audit logs or server logs", "IdP logs", "EDR process telemetry (if available)"],
            detection_logic=(
                "Trigger when an administrative interface or cloud management plane is accessed from a source/IP "
                "that deviates from the entity’s historical access profile (new ASN, geo, or IP reputation anomaly), "
                "followed within 30–60 minutes by privilege-escalating actions (role assignment, new admin creation, API key issuance). "
                "Elevate risk if the access pattern differs from the user’s or service account’s normal operational baseline "
                "and falls outside peer group change frequency."
            ),
            expected_false_positives="Legitimate admin work from new IPs; responders; new VPN exit nodes.",
            tuning_ideas="Require correlation with change events; whitelist corporate VPN; add geo/device baseline.",
            rationale=(
                "Aligned with DBIR theme: increased initial access via vulnerability exploitation. "
                f"Telemetry check: cloud_audit={'yes' if telemetry['cloud'] else 'no/unknown'}."
            ),
            telemetry_flags=telemetry,
            category_hint="EXPLOIT_PRIVESC"
        ))

        candidates.append(Detector(
            name="Ransomware early behavior (mass file ops + recovery tampering)",
            goal="Detect early ransomware-like behavior before widespread encryption impact.",
            data_needed=["EDR process + file telemetry", "Windows Security logs (optional)"],
            detection_logic=(
                "Trigger when endpoint telemetry shows file modification or rename rates significantly exceeding "
                "the host’s historical baseline (e.g., sudden spike across multiple directories), "
                "combined with behaviors associated with recovery tampering such as shadow copy deletion, "
                "backup service termination, or abnormal process tree lineage. "
                "Increase confidence if the process lineage deviates from typical administrative or backup tool behavior "
                "observed in the last 30 days."
            ),
            expected_false_positives="Backup/restore tools; mass updates; IT scripts.",
            tuning_ideas="Allowlist known agents; require combination of mass file ops + recovery tampering.",
            rationale=(
                "Aligned with DBIR theme: ransomware prevalence in system intrusion patterns. "
                f"Telemetry check: edr={'yes' if telemetry['edr'] else 'no/unknown'}."
            ),
            telemetry_flags=telemetry,
            category_hint="RANSOMWARE"
        ))

        candidates.append(Detector(
            name="Mass data export + unusual egress destination",
            goal="Detect potential data theft via abnormal export followed by outbound transfer.",
            data_needed=["App audit logs or DB audit logs", "Proxy logs or Firewall logs", "DNS logs (optional)"],
            detection_logic=(
                "Trigger when a user or service account performs a data export or query whose volume (rows/bytes) "
                "significantly exceeds their 30-day historical average and deviates from their peer group’s normal behavior, "
                "followed within 15–60 minutes by outbound network communication to a new or low-prevalence external domain. "
                "Increase risk score if the destination has no prior communication history for that user or host."
            ),
            expected_false_positives="Reporting periods; migrations; BI jobs.",
            tuning_ideas="Baseline per role; require 'new destination' + 'large export' correlation; add time windows.",
            rationale=(
                "Aligned with DBIR themes: credential abuse/insider + exfil outcomes. "
                f"Telemetry check: proxy={'yes' if telemetry['proxy'] else 'no/unknown'}, db_logs={'yes' if telemetry['db'] else 'no/unknown'}."
            ),
            telemetry_flags=telemetry,
            category_hint="EXFIL"
        ))

        candidates.append(Detector(
            name="Third-party access anomaly (vendor account deviates from normal patterns)",
            goal="Detect risky vendor/partner access outside expected time/systems.", 
            data_needed=["IdP logs", "VPN logs (if used)", "App audit logs"],
            detection_logic=(
                "Trigger when a vendor or third-party account deviates from its established behavioral profile, "
                "including access to new critical systems, authentication outside historically observed time windows, "
                "or privilege modification attempts. "
                "Increase anomaly score if the access pattern differs from both the account’s 30-day baseline "
                "and from the standard behavior of other vendor accounts within the same peer group."
            ),
            expected_false_positives="Planned maintenance; emergency support windows.",
            tuning_ideas="Define vendor allowlist; enforce time windows; require step-up auth for exceptions.",
            rationale=(
                "Aligned with DBIR theme: increased third-party involvement. "
                f"Telemetry check: idp={'yes' if telemetry['idp'] else 'no/unknown'}."
            ),
            telemetry_flags=telemetry,
            category_hint="THIRD_PARTY"
        ))

        return candidates[:max_detectors]


    def _infer_telemetry_flags(self, user_input: str) -> dict:
        text = user_input.lower()

        def has_any(*keywords: str) -> bool:
            return any(k.lower() in text for k in keywords)

        return {
            "idp": has_any("idp", "sign-in", "sso", "azure ad", "okta"),
            "edr": has_any("edr", "endpoint", "process telemetry"),
            "cloud": has_any("cloud audit", "cloudtrail", "azure activity", "gcp audit"),
            "dns": has_any("dns"),
            "proxy": has_any("proxy"),
            "db": has_any("db audit", "database", "db logs"),
        }

    def _tailor_by_telemetry(self, detectors: List[Detector], telemetry: dict) -> List[Detector]:
        tailored: List[Detector] = []
        for d in detectors:
            risk = d.risk
            needed = " ".join(d.data_needed).lower()

            if "edr" in needed and not telemetry["edr"]:
                risk = "Med"
            if ("proxy" in needed or "dns" in needed) and not (telemetry["proxy"] or telemetry["dns"]):
                risk = "Med"
            if "cloud" in needed and not telemetry["cloud"]:
                risk = "Med"

            tailored.append(Detector(**{**d.__dict__, "risk": risk}))
        return tailored


# --- Compatibility layer ---
# Your scaffold likely calls analyzer.run(session_id, text).
# We'll keep it to avoid breaking main/orchestrator.
def run(session_id: str, text: str) -> Dict[str, Any]:
    agent = AnalyzerAgent()
    # Si main.py te pasa un texto con el input, lo usamos.
    # Si viene vacío/corto, caemos al archivo template_input.txt
    if text and len(text.strip()) > 50:
        # guardamos temporalmente el input recibido
        tmp_path = agent.inputs_dir / "runtime_input.txt"
        tmp_path.write_text(text, encoding="utf-8")
        user_input_path = "runtime_input.txt"
    else:
        user_input_path = "template_input.txt"

    detectors = agent.propose_detectors(
        user_input_path=user_input_path,
        dbir_path="dbir_2025_subset.txt",
        max_detectors=5,
    )


    return {
        "message": "analyzer ok",
        "session_id_seen": session_id,
        "input_chars": len(text),
        "detectors": [d.__dict__ for d in detectors],
    }
