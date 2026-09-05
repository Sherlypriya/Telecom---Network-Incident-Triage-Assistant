"""
Orchestrates the full triage pipeline:
  alerts -> correlate into incidents/noise -> prioritize -> match runbook or escalate
"""
from datetime import datetime
from typing import List
from collections import Counter

from app.models.schemas import Alert, Incident, IncidentStatus, TriageSnapshot
from app.correlation import correlate, explain_grouping
from app.prioritization import score_incident, tier_for_score
from app.runbook_engine import match_runbook
from app.escalation import build_escalation_context


def _incident_title(alerts: List[Alert]) -> str:
    type_counts = Counter(a.alert_type.value for a in alerts)
    dominant_type, _ = type_counts.most_common(1)[0]
    devices = sorted(set(a.source_device for a in alerts))
    lead_device = devices[0]
    label = dominant_type.replace("_", " ").title()
    if len(devices) > 1:
        return f"{label} — {lead_device} + {len(devices) - 1} more device(s)"
    return f"{label} — {lead_device}"


def run_triage(alerts: List[Alert]) -> TriageSnapshot:
    now = datetime.utcnow()
    incident_groups, noise = correlate(alerts)

    incidents: List[Incident] = []
    for group in incident_groups:
        group_sorted = sorted(group, key=lambda a: a.timestamp)
        reason = explain_grouping(group_sorted)
        score = score_incident(group_sorted)
        tier = tier_for_score(score)
        type_counts = Counter(a.alert_type.value for a in group_sorted)
        dominant_type = type_counts.most_common(1)[0][0]
        duplicate_count = sum(max(count - 1, 0) for count in Counter((a.source_device, a.alert_type.value, a.raw_message) for a in group_sorted).values())
        devices = sorted(set(a.source_device for a in group_sorted))
        severity_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        max_severity = max((a.severity.value for a in group_sorted), key=severity_rank.get)
        impact_explanation = [
            f"+{min(len(devices), 8) * 5} {len(devices)} affected device(s)",
            f"+{min(len(group_sorted), 10) * 2} {len(group_sorted)} correlated alert(s)",
        ]
        if max_severity == "critical":
            impact_explanation.insert(0, "+40 critical-severity signal")
        elif max_severity == "high":
            impact_explanation.insert(0, "+25 high-severity signal")
        if any(device.startswith(("core-", "aaa-", "dns-")) for device in devices):
            impact_explanation.append("+15 core or shared-service infrastructure")

        runbook_match = match_runbook(group_sorted)

        incident = Incident(
            title=_incident_title(group_sorted),
            created_at=min(a.timestamp for a in group_sorted),
            updated_at=max(a.timestamp for a in group_sorted),
            alert_ids=[a.id for a in group_sorted],
            affected_devices=sorted(set(a.source_device for a in group_sorted)),
            dominant_alert_type=dominant_type,
            priority_score=score,
            priority_tier=tier,
            correlation_reason=reason,
            duplicate_count=duplicate_count,
            impact_explanation=impact_explanation,
            decision_trace=[
                "Alert validated",
                f"{len(group_sorted)} alert(s) correlated",
                f"{duplicate_count} duplicate alert(s) grouped" if duplicate_count else "No duplicate alerts detected",
                f"{len(devices)} device(s) affected",
                f"Impact score calculated: {score:g}",
            ],
        )

        if runbook_match:
            incident.runbook_match = runbook_match
            incident.status = IncidentStatus.OPEN
        else:
            incident.status = IncidentStatus.ESCALATED
            incident.escalation_context = build_escalation_context(
                group_sorted, reason, near_miss_runbook=None
            )
            incident.decision_trace.extend(["Runbooks searched", "No suitable runbook found", "Escalation required"])
        if incident.runbook_match:
            incident.decision_trace.extend([
                f"Runbook matched: {incident.runbook_match.runbook_id}",
                "Recommendation grounded in runbook steps",
            ])

        # attach incident_id back onto alerts for traceability
        for a in group_sorted:
            a.incident_id = incident.id

        incidents.append(incident)

    incidents.sort(key=lambda i: i.priority_score, reverse=True)

    return TriageSnapshot(
        incidents=incidents,
        noise_alerts=noise,
        all_alerts_processed=len(alerts),
        generated_at=now,
    )
