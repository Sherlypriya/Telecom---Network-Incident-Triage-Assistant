---
id: rb-high-latency
title: High Latency
keywords: [high_latency, packet_loss, cpu_high]
---

# High Latency

## Applies when
Round-trip latency on a path or interface exceeds normal thresholds, potentially
with associated packet loss.

## Initial Response Steps
1. Identify the affected path/segment and check for concurrent packet loss alerts.
2. Check interface utilization — latency often follows congestion above ~80% utilization.
3. Check CPU load on routing devices along the path (high CPU can delay packet
   forwarding even without link saturation).
4. Look for QoS misconfiguration or a recent routing change that shifted traffic
   onto a longer/slower path.
5. If congestion-related, consider traffic engineering/load balancing; if isolated
   to one device, investigate that device's health directly.
