"""
Correlation engine: groups a stream of alerts into incidents.

Approach (transparent, rule-based — no black box):
  1. Build a device dependency graph (which devices sit downstream of which).
  2. Alerts are candidates for the same incident if, within a sliding time
     window, they involve devices that are the same, adjacent in the
     dependency graph, or share a region AND a commonly-co-occurring
     alert-type pair (e.g. high_latency + packet_loss + cpu_high).
  3. Union-Find (disjoint set) merges alerts that satisfy any pairwise rule
     into connected components -> each component becomes one incident.
  4. Any alert that never gets linked to another alert stays as noise
     (a "group" of size 1 is not promoted to an incident) UNLESS it is
     high/critical severity on its own, in which case it becomes a
     single-alert incident (a lone critical alert still deserves triage).
"""
from datetime import timedelta
from typing import List, Dict, Tuple
from collections import defaultdict

from app.models.schemas import Alert, AlertType
from app.alert_generator import DEVICES

TIME_WINDOW = timedelta(seconds=90)

# Alert type pairs that commonly co-occur from the SAME underlying failure
# even without a direct device-dependency link (e.g. congestion symptoms).
COOCCURRING_TYPES = {
    frozenset({AlertType.HIGH_LATENCY, AlertType.PACKET_LOSS}),
    frozenset({AlertType.HIGH_LATENCY, AlertType.CPU_HIGH}),
    frozenset({AlertType.PACKET_LOSS, AlertType.CPU_HIGH}),
    frozenset({AlertType.LINK_DOWN, AlertType.BGP_SESSION_DOWN}),
    frozenset({AlertType.DEVICE_UNREACHABLE, AlertType.LINK_DOWN}),
    frozenset({AlertType.AUTH_FAILURE, AlertType.DEVICE_UNREACHABLE}),
}


def _build_adjacency() -> Dict[str, set]:
    """Undirected adjacency: device <-> its parent, and device <-> siblings."""
    adj = defaultdict(set)
    for dev, info in DEVICES.items():
        for parent in info.get("depends_on", []):
            adj[dev].add(parent)
            adj[parent].add(dev)
    # siblings (share the same parent) are also network-adjacent
    parent_to_children = defaultdict(list)
    for dev, info in DEVICES.items():
        for parent in info.get("depends_on", []):
            parent_to_children[parent].append(dev)
    for parent, children in parent_to_children.items():
        for i in range(len(children)):
            for j in range(i + 1, len(children)):
                adj[children[i]].add(children[j])
                adj[children[j]].add(children[i])
    return adj


DEVICE_ADJACENCY = _build_adjacency()


class UnionFind:
    def __init__(self, items):
        self.parent = {i: i for i in items}

    def find(self, x):
        while self.parent[x] != x:
            self.parent[x] = self.parent[self.parent[x]]
            x = self.parent[x]
        return x

    def union(self, a, b):
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.parent[ra] = rb


def _devices_related(dev_a: str, dev_b: str) -> bool:
    if dev_a == dev_b:
        return True
    return dev_b in DEVICE_ADJACENCY.get(dev_a, set())


def _types_cooccur(type_a: AlertType, type_b: AlertType) -> bool:
    if type_a == type_b:
        return True
    return frozenset({type_a, type_b}) in COOCCURRING_TYPES


def _should_link(a: Alert, b: Alert) -> Tuple[bool, str]:
    """Returns (should_link, reason) explaining WHY two alerts are related."""
    if abs((a.timestamp - b.timestamp)) > TIME_WINDOW:
        return False, ""

    same_or_adjacent_device = _devices_related(a.source_device, b.source_device)
    types_cooccur = _types_cooccur(a.alert_type, b.alert_type)

    # Rule 1: same device, any alert types within window -> clearly related
    if a.source_device == b.source_device:
        return True, f"same device ({a.source_device}) within {TIME_WINDOW}"

    # Rule 2: adjacent devices in the dependency graph + co-occurring types
    if same_or_adjacent_device and types_cooccur:
        return True, (f"adjacent devices ({a.source_device} <-> {b.source_device}) "
                       f"with correlated alert types ({a.alert_type.value}/{b.alert_type.value})")

    # Rule 3: adjacent devices with a direct cascade pattern (unreachable following link_down etc.)
    if same_or_adjacent_device and (
        a.alert_type == AlertType.LINK_DOWN or b.alert_type == AlertType.LINK_DOWN
    ):
        return True, f"cascading from link failure on adjacent device"

    # Rule 4: identical alert type, non-adjacent devices, but both plausibly caused
    # by one shared upstream dependency (e.g. an AAA server outage produces the
    # SAME symptom - auth_failure - on many otherwise-unrelated devices at once).
    if a.alert_type == b.alert_type and a.alert_type == AlertType.AUTH_FAILURE:
        return True, "identical auth-failure symptom appearing near-simultaneously on multiple devices (likely shared upstream cause, e.g. AAA outage)"

    return False, ""


def correlate(alerts: List[Alert]) -> Tuple[List[List[Alert]], List[Alert]]:
    """
    Returns (incident_groups, noise_alerts).
    incident_groups: list of alert-lists, each representing one incident (size >= 2,
                      or size 1 if the lone alert is high/critical severity).
    noise_alerts: alerts that didn't link to anything and aren't severe enough
                  to stand alone.
    """
    if not alerts:
        return [], []

    ordered = sorted(alerts, key=lambda a: a.timestamp)
    uf = UnionFind([a.id for a in ordered])
    reasons: Dict[Tuple[str, str], str] = {}

    n = len(ordered)
    for i in range(n):
        for j in range(i + 1, n):
            a, b = ordered[i], ordered[j]
            if (b.timestamp - a.timestamp) > TIME_WINDOW:
                break  # sorted by time, no need to check further j's for this i
            linked, reason = _should_link(a, b)
            if linked:
                uf.union(a.id, b.id)
                reasons[(a.id, b.id)] = reason

    groups: Dict[str, List[Alert]] = defaultdict(list)
    for a in ordered:
        groups[uf.find(a.id)].append(a)

    incident_groups = []
    noise_alerts = []
    for root, group in groups.items():
        if len(group) >= 2:
            incident_groups.append(group)
        else:
            lone = group[0]
            if lone.severity.value in ("critical", "high"):
                incident_groups.append(group)  # single-alert incident
            else:
                noise_alerts.append(lone)

    return incident_groups, noise_alerts


def explain_grouping(group: List[Alert]) -> str:
    """Human-readable summary of why these alerts were grouped together."""
    if len(group) == 1:
        return f"Single {group[0].severity.value}-severity alert triaged individually (no correlated alerts found)."
    devices = sorted(set(a.source_device for a in group))
    types = sorted(set(a.alert_type.value for a in group))
    span = (max(a.timestamp for a in group) - min(a.timestamp for a in group)).total_seconds()
    return (f"{len(group)} alerts across {len(devices)} device(s) "
            f"[{', '.join(devices)}] within {span:.0f}s — alert types: {', '.join(types)}.")
