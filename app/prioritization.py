"""
Scores and tiers incidents by likely impact.

Score factors (transparent, weighted sum — tune weights as needed):
  - severity_score: highest severity among alerts in the incident
  - fanout_score: number of distinct devices affected (blast radius)
  - volume_score: number of alerts in the group (bigger storm = bigger problem)
  - criticality_score: whether "core" infrastructure devices are involved
"""
from typing import List
from app.models.schemas import Alert, PriorityTier

SEVERITY_WEIGHTS = {"critical": 40, "high": 25, "medium": 12, "low": 5}
CORE_DEVICE_HINTS = ("core-", "aaa-", "dns-")


def _criticality_bonus(devices: List[str]) -> int:
    return 15 if any(d.startswith(CORE_DEVICE_HINTS) for d in devices) else 0


def score_incident(alerts: List[Alert]) -> float:
    devices = sorted(set(a.source_device for a in alerts))
    max_sev = max(SEVERITY_WEIGHTS.get(a.severity.value, 0) for a in alerts)
    fanout = min(len(devices), 8) * 5          # cap so one giant incident doesn't dominate absurdly
    volume = min(len(alerts), 10) * 2
    criticality = _criticality_bonus(devices)
    score = max_sev + fanout + volume + criticality
    return round(score, 1)


def tier_for_score(score: float) -> PriorityTier:
    if score >= 70:
        return PriorityTier.P1
    if score >= 45:
        return PriorityTier.P2
    if score >= 25:
        return PriorityTier.P3
    return PriorityTier.P4
