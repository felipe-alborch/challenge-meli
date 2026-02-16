# UEBA Detection Proposal

**Session ID:** `1e1b57a826f04a0e8f66b567b385778e`

## Summary

This report summarizes detection proposals (Analyzer) and their enrichment (Classifier: MITRE mapping + risk scoring), aligned with DBIR 2025 themes.

> Detectors are ordered by classifier risk_score (descending).

## Proposed Detectors

### 1. Suspicious sign-in chain (new geo/device + MFA fatigue + success)

**Risk Level:** High

**Risk Score:** 250 (Impact 5/5 × Likelihood 5/5)

**Risk Rationale:**
Alto impacto por abuso de cuentas válidas; muy probable por credential abuse y MFA fatigue.

**MITRE ATT&CK Mapping:**
- T1078 — Valid Accounts

**Goal:** Detect account takeover patterns leveraging stolen credentials and MFA prompt bombing.

**Data Needed:**
- IdP sign-in logs
- MFA events
- Conditional Access / risk events (if available)

**Detection Logic:**
Trigger when a user exhibits a deviation from their 30-day behavioral baseline in authentication patterns, including: (1) repeated MFA push prompts or denials within a short window (possible MFA fatigue), followed by (2) a successful sign-in from a new geographic location or previously unseen device fingerprint. Increase risk score if the login occurs outside the user’s typical working hours or differs significantly from their historical geo/device profile and peer group behavior.

**Expected False Positives:**
Users traveling or changing devices; noisy MFA prompts from misconfigured apps.

**Tuning Ideas:**
Whitelist known travel patterns; require 'new device' AND 'new geo'; add user baseline hours.

**Rationale (Analyzer):**
Aligned with DBIR themes: credential abuse + MFA fatigue. Telemetry check: IdP logs=yes.

---

### 2. Potential vulnerability exploitation leading to privileged session

**Risk Level:** High

**Risk Score:** 250 (Impact 5/5 × Likelihood 5/5)

**Risk Rationale:**
Alto impacto por escalamiento/acciones admin; probabilidad alta cuando hay exposición de superficie y cambios privilegiados.

**MITRE ATT&CK Mapping:**
- T1190 — Exploit Public-Facing Application
- T1068 — Exploitation for Privilege Escalation

**Goal:** Detect suspicious privileged access shortly after unusual external access and sensitive changes.

**Data Needed:**
- Cloud audit logs or server logs
- IdP logs
- EDR process telemetry (if available)

**Detection Logic:**
Trigger when an administrative interface or cloud management plane is accessed from a source/IP that deviates from the entity’s historical access profile (new ASN, geo, or IP reputation anomaly), followed within 30–60 minutes by privilege-escalating actions (role assignment, new admin creation, API key issuance). Elevate risk if the access pattern differs from the user’s or service account’s normal operational baseline and falls outside peer group change frequency.

**Expected False Positives:**
Legitimate admin work from new IPs; responders; new VPN exit nodes.

**Tuning Ideas:**
Require correlation with change events; whitelist corporate VPN; add geo/device baseline.

**Rationale (Analyzer):**
Aligned with DBIR theme: increased initial access via vulnerability exploitation. Telemetry check: cloud_audit=yes.

---

### 3. Ransomware early behavior (mass file ops + recovery tampering)

**Risk Level:** High

**Risk Score:** 250 (Impact 5/5 × Likelihood 5/5)

**Risk Rationale:**
Impacto crítico por interrupción del negocio + extorsión; alta prevalencia en intrusiones.

**MITRE ATT&CK Mapping:**
- T1486 — Data Encrypted for Impact
- T1490 — Inhibit System Recovery

**Goal:** Detect early ransomware-like behavior before widespread encryption impact.

**Data Needed:**
- EDR process + file telemetry
- Windows Security logs (optional)

**Detection Logic:**
Trigger when endpoint telemetry shows file modification or rename rates significantly exceeding the host’s historical baseline (e.g., sudden spike across multiple directories), combined with behaviors associated with recovery tampering such as shadow copy deletion, backup service termination, or abnormal process tree lineage. Increase confidence if the process lineage deviates from typical administrative or backup tool behavior observed in the last 30 days.

**Expected False Positives:**
Backup/restore tools; mass updates; IT scripts.

**Tuning Ideas:**
Allowlist known agents; require combination of mass file ops + recovery tampering.

**Rationale (Analyzer):**
Aligned with DBIR theme: ransomware prevalence in system intrusion patterns. Telemetry check: edr=yes.

---

### 4. Mass data export + unusual egress destination

**Risk Level:** High

**Risk Score:** 250 (Impact 5/5 × Likelihood 5/5)

**Risk Rationale:**
Alto impacto por fuga de datos y exposición regulatoria; probabilidad alta si hay señales de export + egress.

**MITRE ATT&CK Mapping:**
- T1041 — Exfiltration Over C2 Channel
- T1567 — Exfiltration Over Web Service

**Goal:** Detect potential data theft via abnormal export followed by outbound transfer.

**Data Needed:**
- App audit logs or DB audit logs
- Proxy logs or Firewall logs
- DNS logs (optional)

**Detection Logic:**
Trigger when a user or service account performs a data export or query whose volume (rows/bytes) significantly exceeds their 30-day historical average and deviates from their peer group’s normal behavior, followed within 15–60 minutes by outbound network communication to a new or low-prevalence external domain. Increase risk score if the destination has no prior communication history for that user or host.

**Expected False Positives:**
Reporting periods; migrations; BI jobs.

**Tuning Ideas:**
Baseline per role; require 'new destination' + 'large export' correlation; add time windows.

**Rationale (Analyzer):**
Aligned with DBIR themes: credential abuse/insider + exfil outcomes. Telemetry check: proxy=yes, db_logs=yes.

---

### 5. Third-party access anomaly (vendor account deviates from normal patterns)

**Risk Level:** Medium

**Risk Score:** 160 (Impact 4/5 × Likelihood 4/5)

**Risk Rationale:**
Riesgo relevante por accesos de terceros; probabilidad media y depende de controles/visibilidad.

**MITRE ATT&CK Mapping:**
- T1199 — Trusted Relationship
- T1078 — Valid Accounts

**Goal:** Detect risky vendor/partner access outside expected time/systems.

**Data Needed:**
- IdP logs
- VPN logs (if used)
- App audit logs

**Detection Logic:**
Trigger when a vendor or third-party account deviates from its established behavioral profile, including access to new critical systems, authentication outside historically observed time windows, or privilege modification attempts. Increase anomaly score if the access pattern differs from both the account’s 30-day baseline and from the standard behavior of other vendor accounts within the same peer group.

**Expected False Positives:**
Planned maintenance; emergency support windows.

**Tuning Ideas:**
Define vendor allowlist; enforce time windows; require step-up auth for exceptions.

**Rationale (Analyzer):**
Aligned with DBIR theme: increased third-party involvement. Telemetry check: idp=yes.

---

