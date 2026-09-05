"""
Core data models for the Network Incident Triage Assistant.
"""
from __future__ import annotations
from datetime import datetime
from enum import Enum
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field
import uuid


class AlertType(str, Enum):
    LINK_DOWN = "link_down"
    DEVICE_UNREACHABLE = "device_unreachable"
    HIGH_LATENCY = "high_latency"
    AUTH_FAILURE = "auth_failure"
    PACKET_LOSS = "packet_loss"
    INTERFACE_FLAPPING = "interface_flapping"
    BGP_SESSION_DOWN = "bgp_session_down"
    CPU_HIGH = "cpu_high"
    DISK_FULL = "disk_full"
    DNS_FAILURE = "dns_failure"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class Alert(BaseModel):
    id: str = Field(default_factory=lambda: f"alrt-{uuid.uuid4().hex[:8]}")
    timestamp: datetime
    source_device: str
    alert_type: AlertType
    severity: Severity
    raw_message: str
    region: Optional[str] = None
    interface: Optional[str] = None
    ip: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)
    # populated after processing
    incident_id: Optional[str] = None


class RunbookMatch(BaseModel):
    runbook_id: str
    title: str
    confidence: float
    recommended_steps: List[str]
    source_file: str


class IncidentStatus(str, Enum):
    OPEN = "open"
    ESCALATED = "escalated"
    RESOLVED = "resolved"


class PriorityTier(str, Enum):
    P1 = "P1"
    P2 = "P2"
    P3 = "P3"
    P4 = "P4"


class Incident(BaseModel):
    id: str = Field(default_factory=lambda: f"inc-{uuid.uuid4().hex[:8]}")
    title: str
    created_at: datetime
    updated_at: datetime
    alert_ids: List[str] = Field(default_factory=list)
    affected_devices: List[str] = Field(default_factory=list)
    dominant_alert_type: Optional[AlertType] = None
    priority_score: float = 0.0
    priority_tier: PriorityTier = PriorityTier.P4
    status: IncidentStatus = IncidentStatus.OPEN
    runbook_match: Optional[RunbookMatch] = None
    escalation_context: Optional[Dict[str, Any]] = None
    correlation_reason: str = ""
    duplicate_count: int = 0
    impact_explanation: List[str] = Field(default_factory=list)
    decision_trace: List[str] = Field(default_factory=list)


class TriageSnapshot(BaseModel):
    """Full state returned to the dashboard."""
    incidents: List[Incident]
    noise_alerts: List[Alert]
    all_alerts_processed: int
    generated_at: datetime
