import asyncio
import json
from datetime import datetime
from typing import List, Optional, Union
from fastapi import Body, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from app.models.schemas import Alert, TriageSnapshot, Incident
from app.alert_generator import generate_demo_stream
from app.pipeline import run_triage
from app.models.schemas import IncidentStatus

app = FastAPI(title="Network Incident Triage Assistant API")

# Allow the separately-hosted frontend (any origin, e.g. Vite dev server on
# localhost:5173, or a deployed static site) to call this API.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory alert store for this demo session
STATE = {"alerts": [], "snapshot": None}


class AlertIn(BaseModel):
    timestamp: Optional[datetime] = None
    source_device: str
    alert_type: str
    severity: str
    raw_message: str
    region: Optional[str] = None
    interface: Optional[str] = None
    ip: Optional[str] = None


def _current_snapshot() -> TriageSnapshot:
    if STATE["snapshot"] is None:
        alerts = generate_demo_stream(datetime.utcnow())
        STATE["alerts"] = alerts
        STATE["snapshot"] = run_triage(alerts)
    return STATE["snapshot"]


def _incident_payload(incident: Incident) -> dict:
    severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    incident_alerts = [alert for alert in STATE["alerts"] if alert.id in incident.alert_ids]
    severity = max((alert.severity.value for alert in incident_alerts), key=severity_order.get, default="low")
    impact = {"P1": "Critical", "P2": "High", "P3": "Medium", "P4": "Low"}[incident.priority_tier.value]
    recommendation = None
    runbook_id = None
    if incident.runbook_match:
        recommendation = incident.runbook_match.recommended_steps[0] if incident.runbook_match.recommended_steps else None
        runbook_id = incident.runbook_match.runbook_id
    return {
        "incidentId": incident.id,
        "title": incident.title,
        "severity": severity.title(),
        "impact": impact,
        "status": incident.status.value.title(),
        "alerts": [alert.model_dump(mode="json") for alert in incident_alerts],
        "likelyCause": incident.dominant_alert_type.value.replace("_", " ").title() if incident.dominant_alert_type else "Unknown",
        "recommendation": recommendation,
        "runbook": runbook_id,
        "escalated": incident.status.value == "escalated",
        "priorityScore": incident.priority_score,
        "correlationReason": incident.correlation_reason,
        "escalationContext": incident.escalation_context,
        "duplicateCount": incident.duplicate_count,
        "impactExplanation": incident.impact_explanation,
        "decisionTrace": incident.decision_trace,
    }


def _find_incident(incident_id: str) -> Incident:
    snapshot = _current_snapshot()
    incident = next((item for item in snapshot.incidents if item.id == incident_id), None)
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    return incident


@app.get("/api/health")
def health():
    return {"status": "ok"}


@app.post("/api/demo/generate")
def generate_demo():
    """Generate a fresh realistic demo alert stream and run triage on it."""
    alerts = generate_demo_stream(datetime.utcnow())
    STATE["alerts"] = alerts
    STATE["snapshot"] = run_triage(alerts)
    return STATE["snapshot"]


@app.get("/api/demo/stream")
async def stream_demo():
    """Stream a generated demo alert-by-alert while recomputing the snapshot."""
    alerts = generate_demo_stream(datetime.utcnow())

    async def events():
        processed = []
        for alert in alerts:
            processed.append(alert)
            STATE["alerts"] = processed.copy()
            STATE["snapshot"] = run_triage(processed)
            payload = {
                "alert": alert.model_dump(mode="json"),
                "snapshot": STATE["snapshot"].model_dump(mode="json"),
            }
            yield f"data: {json.dumps(payload)}\n\n"
            await asyncio.sleep(0.52)
        yield "event: complete\ndata: {}\n\n"

    return StreamingResponse(events(), media_type="text/event-stream", headers={
        "Cache-Control": "no-cache",
        "Connection": "keep-alive",
    })


@app.post("/api/alerts", response_model=TriageSnapshot)
def ingest_alerts(alerts_in: Union[AlertIn, List[AlertIn]]):
    """Ingest one alert or replace the current in-memory batch and triage it."""
    incoming = alerts_in if isinstance(alerts_in, list) else [alerts_in]
    alerts = []
    if not isinstance(alerts_in, list):
        alerts = list(STATE["alerts"])
    for a in incoming:
        alerts.append(Alert(
            timestamp=a.timestamp or datetime.utcnow(),
            source_device=a.source_device,
            alert_type=a.alert_type,
            severity=a.severity,
            raw_message=a.raw_message,
            region=a.region,
            interface=a.interface,
            ip=a.ip,
        ))
    STATE["alerts"] = alerts
    STATE["snapshot"] = run_triage(alerts)
    return STATE["snapshot"]


@app.post("/api/incidents/triage", response_model=TriageSnapshot)
def triage_incidents(alerts_in: Optional[List[AlertIn]] = Body(default=None)):
    """Run triage for supplied alerts, or the current in-memory alert set."""
    if alerts_in is not None:
        return ingest_alerts(alerts_in)
    return _current_snapshot()


@app.get("/api/snapshot", response_model=TriageSnapshot)
def get_snapshot():
    return _current_snapshot()


@app.get("/api/alerts")
def get_alerts():
    """Return the raw alerts from the current demo or submitted batch."""
    return [alert.model_dump(mode="json") for alert in STATE["alerts"]]


@app.get("/api/incidents")
def get_incidents():
    return [_incident_payload(incident) for incident in _current_snapshot().incidents]


@app.get("/api/incidents/{incident_id}")
def get_incident(incident_id: str):
    return _incident_payload(_find_incident(incident_id))


@app.post("/api/incidents/{incident_id}/recommend")
def recommend_incident(incident_id: str):
    """Return the current runbook recommendation or escalation context."""
    return _incident_payload(_find_incident(incident_id))


@app.patch("/api/incidents/{incident_id}", response_model=TriageSnapshot)
def update_incident_status(incident_id: str, status: IncidentStatus):
    """Update an incident's operational status in the in-memory demo state."""
    snapshot = STATE.get("snapshot")
    if snapshot is None:
        raise HTTPException(status_code=404, detail="No active triage snapshot")
    incident = next((item for item in snapshot.incidents if item.id == incident_id), None)
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    incident.status = status
    return snapshot


@app.get("/api/runbooks")
def list_runbooks():
    from app.runbook_engine import get_runbooks
    return [
        {"id": rb.id, "title": rb.title, "problem_type": rb.keywords[0] if rb.keywords else "general", "keywords": rb.keywords, "steps": rb.steps, "source_file": rb.source_file}
        for rb in get_runbooks()
    ]


@app.get("/api/runbooks/{runbook_id}")
def get_runbook(runbook_id: str):
    from app.runbook_engine import get_runbooks
    runbook = next((item for item in get_runbooks() if item.id == runbook_id), None)
    if runbook is None:
        raise HTTPException(status_code=404, detail="Runbook not found")
    return {"id": runbook.id, "title": runbook.title, "problem_type": runbook.keywords[0] if runbook.keywords else "general", "keywords": runbook.keywords, "steps": runbook.steps, "source_file": runbook.source_file}


@app.get("/api/noise-alerts")
def get_noise_alerts():
    return [alert.model_dump(mode="json") for alert in _current_snapshot().noise_alerts]


@app.post("/api/incidents/{incident_id}/escalate")
def escalate_incident(incident_id: str):
    incident = _find_incident(incident_id)
    incident.status = IncidentStatus.ESCALATED
    incident.escalation_context = incident.escalation_context or {
        "what_happened": incident.correlation_reason,
        "timeline": _incident_payload(incident)["alerts"],
        "runbooks_considered": "Available runbooks were reviewed; no sufficient match was selected.",
        "suggested_next_step": "Escalate to Network Engineering with the attached incident evidence.",
    }
    return _incident_payload(incident)


@app.get("/")
def root():
    return {
        "service": "Network Incident Triage Assistant API",
        "docs": "/docs",
        "endpoints": ["/api/health", "/api/demo/generate", "/api/demo/stream", "/api/alerts", "/api/incidents", "/api/incidents/triage", "/api/runbooks", "/api/noise-alerts"],
    }
