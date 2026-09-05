"""
Simulates a realistic stream of network alerts, including bursts where one
underlying failure produces many overlapping signals, plus some genuinely
unrelated noise alerts.
"""
import random
from datetime import datetime, timedelta
from app.models.schemas import Alert, AlertType, Severity

DEVICES = {
    "core-rtr-01": {"region": "us-east", "depends_on": []},
    "core-rtr-02": {"region": "us-east", "depends_on": ["core-rtr-01"]},
    "agg-sw-11": {"region": "us-east", "depends_on": ["core-rtr-01"]},
    "agg-sw-12": {"region": "us-east", "depends_on": ["core-rtr-01"]},
    "edge-sw-101": {"region": "us-east", "depends_on": ["agg-sw-11"]},
    "edge-sw-102": {"region": "us-east", "depends_on": ["agg-sw-11"]},
    "core-rtr-03": {"region": "eu-west", "depends_on": []},
    "agg-sw-21": {"region": "eu-west", "depends_on": ["core-rtr-03"]},
    "edge-sw-201": {"region": "eu-west", "depends_on": ["agg-sw-21"]},
    "aaa-server-01": {"region": "global", "depends_on": []},
    "dns-server-01": {"region": "global", "depends_on": []},
    "vpn-gw-01": {"region": "us-east", "depends_on": ["core-rtr-01"]},
    "core-rtr-05": {"region": "ap-south", "depends_on": []},
    "agg-sw-41": {"region": "ap-south", "depends_on": ["core-rtr-05"]},
    "edge-sw-401": {"region": "ap-south", "depends_on": ["agg-sw-41"]},
    "mgmt-sw-01": {"region": "us-east", "depends_on": []},
}


def _mk(alert_type, device, sev, msg, t, **kw):
    d = DEVICES[device]
    return Alert(
        timestamp=t,
        source_device=device,
        alert_type=alert_type,
        severity=sev,
        raw_message=msg,
        region=d["region"],
        **kw,
    )


def generate_incident_burst_link_down(base_time: datetime):
    """core-rtr-01 link fails -> cascades to everything downstream."""
    alerts = []
    alerts.append(_mk(AlertType.LINK_DOWN, "core-rtr-01", Severity.CRITICAL,
                       "Interface Gi0/0/1 on core-rtr-01 changed state to DOWN",
                       base_time, interface="Gi0/0/1"))
    alerts.append(_mk(AlertType.BGP_SESSION_DOWN, "core-rtr-01", Severity.HIGH,
                       "BGP session to peer 10.0.0.2 down (core-rtr-02)",
                       base_time + timedelta(seconds=5)))
    for dev, delay in [("core-rtr-02", 8), ("agg-sw-11", 12), ("agg-sw-12", 14),
                       ("edge-sw-101", 20), ("edge-sw-102", 22), ("vpn-gw-01", 25)]:
        alerts.append(_mk(AlertType.DEVICE_UNREACHABLE, dev, Severity.HIGH,
                           f"{dev} not responding to SNMP/ICMP polling",
                           base_time + timedelta(seconds=delay)))
    alerts.append(_mk(AlertType.HIGH_LATENCY, "agg-sw-11", Severity.MEDIUM,
                       "Latency to agg-sw-11 exceeded 400ms threshold",
                       base_time + timedelta(seconds=18)))
    return alerts


def generate_incident_burst_auth_outage(base_time: datetime):
    """AAA server dies -> auth failures across many unrelated devices."""
    alerts = [_mk(AlertType.DEVICE_UNREACHABLE, "aaa-server-01", Severity.CRITICAL,
                  "aaa-server-01 not responding to health check", base_time)]
    for dev, delay in [("edge-sw-201", 10), ("vpn-gw-01", 15), ("core-rtr-03", 20),
                       ("agg-sw-21", 25)]:
        alerts.append(_mk(AlertType.AUTH_FAILURE, dev, Severity.MEDIUM,
                           f"5 consecutive RADIUS authentication failures on {dev}",
                           base_time + timedelta(seconds=delay)))
    return alerts


def generate_incident_burst_latency_congestion(base_time: datetime):
    """Congestion on eu-west path -> latency + packet loss, no clean root cause -> escalation."""
    alerts = [
        _mk(AlertType.HIGH_LATENCY, "core-rtr-03", Severity.HIGH,
            "Latency to core-rtr-03 exceeded 500ms threshold", base_time),
        _mk(AlertType.HIGH_LATENCY, "agg-sw-21", Severity.HIGH,
            "Latency to agg-sw-21 exceeded 480ms threshold", base_time + timedelta(seconds=6)),
        _mk(AlertType.PACKET_LOSS, "edge-sw-201", Severity.MEDIUM,
            "Packet loss of 12% detected on edge-sw-201 uplink", base_time + timedelta(seconds=9)),
        _mk(AlertType.CPU_HIGH, "core-rtr-03", Severity.MEDIUM,
            "CPU utilization on core-rtr-03 at 96%", base_time + timedelta(seconds=3)),
    ]
    return alerts


def generate_incident_burst_capacity_escalation(base_time: datetime):
    """
    A pattern not covered by any runbook in the library: disk capacity
    exhaustion cascading into interface instability on ap-south devices.
    No runbook keywords match disk_full/interface_flapping together, so this
    should be escalated with assembled context rather than force-matched.
    """
    alerts = [
        _mk(AlertType.DISK_FULL, "core-rtr-05", Severity.HIGH,
            "Disk usage on core-rtr-05 at 97% (log partition)", base_time),
        _mk(AlertType.DISK_FULL, "agg-sw-41", Severity.MEDIUM,
            "Disk usage on agg-sw-41 at 91% (log partition)", base_time + timedelta(seconds=15)),
        _mk(AlertType.DISK_FULL, "edge-sw-401", Severity.MEDIUM,
            "Disk usage on edge-sw-401 at 89% (log partition)", base_time + timedelta(seconds=28)),
    ]
    return alerts


def generate_noise_alerts(base_time: datetime, n=3):
    """
    Standalone alerts on devices/times that are deliberately isolated from any
    incident burst (different devices, widely spaced timestamps) so they
    correctly remain unlinked -> noise, not forced into an incident.
    """
    options = [
        ("cpu_high", "dns-server-01", Severity.LOW, "CPU utilization on dns-server-01 at 71% (within normal variance)"),
        ("disk_full", "mgmt-sw-01", Severity.LOW, "Disk usage on mgmt-sw-01 at 82%"),
        ("dns_failure", "dns-server-01", Severity.LOW, "Single DNS resolution timeout, auto-retried successfully"),
    ]
    alerts = []
    for i in range(min(n, len(options))):
        atype, dev, sev, msg = options[i]
        # spaced far apart (10+ min gaps) so they never fall in the same
        # correlation window as each other or as any incident burst
        alerts.append(_mk(AlertType(atype), dev, sev, msg,
                           base_time + timedelta(minutes=10 * i, seconds=random.randint(0, 20))))
    return alerts


def generate_demo_stream(start_time: datetime = None):
    """Builds one realistic mixed batch: 3 incident bursts + noise, well separated in time
    so the correlation window groups each burst correctly without bleeding into the others."""
    start_time = start_time or datetime.utcnow()
    all_alerts = []
    all_alerts += generate_incident_burst_link_down(start_time)
    all_alerts += generate_incident_burst_auth_outage(start_time + timedelta(minutes=3))
    all_alerts += generate_incident_burst_latency_congestion(start_time + timedelta(minutes=6))
    all_alerts += generate_incident_burst_capacity_escalation(start_time + timedelta(minutes=9))
    all_alerts += generate_noise_alerts(start_time + timedelta(minutes=13))
    all_alerts.sort(key=lambda a: a.timestamp)
    return all_alerts
