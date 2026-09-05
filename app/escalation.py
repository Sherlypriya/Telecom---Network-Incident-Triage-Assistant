"""
Builds a rich escalation context when an incident has no matching runbook,
so the receiving team starts from evidence, not from scratch.
"""
from typing import List, Dict, Any, Optional
from app.models.schemas import Alert, RunbookMatch


def build_escalation_context(
    alerts: List[Alert],
    correlation_reason: str,
    near_miss_runbook: Optional[RunbookMatch] = None,
) -> Dict[str, Any]:
    devices = sorted(set(a.source_device for a in alerts))
    regions = sorted(set(a.region for a in alerts if a.region))
    types = sorted(set(a.alert_type.value for a in alerts))
    timeline = [
        {
            "time": a.timestamp.isoformat(),
            "device": a.source_device,
            "type": a.alert_type.value,
            "severity": a.severity.value,
            "message": a.raw_message,
        }
        for a in sorted(alerts, key=lambda x: x.timestamp)
    ]

    context = {
        "what_happened": (
            f"{len(alerts)} alert(s) across {len(devices)} device(s) "
            f"({', '.join(devices)}) in region(s) {', '.join(regions) or 'n/a'}, "
            f"spanning alert types: {', '.join(types)}."
        ),
        "why_grouped": correlation_reason,
        "timeline": timeline,
        "runbooks_considered": (
            f"Closest match was '{near_miss_runbook.title}' "
            f"(confidence {near_miss_runbook.confidence}) but it fell below the "
            f"confidence threshold, so no automatic recommendation was made."
            if near_miss_runbook else
            "No runbook in the current library covers this alert-type combination."
        ),
        "suggested_next_step": (
            "No existing runbook confidently matches this pattern. Recommend a "
            "human engineer investigate using the timeline above, and if resolved, "
            "consider authoring a new runbook for this alert-type combination."
        ),
    }
    return context
