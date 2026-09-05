---
id: rb-device-unreachable
title: Device Unreachable
keywords: [device_unreachable, link_down, cpu_high]
---

# Device Unreachable

## Applies when
A device stops responding to ICMP/SNMP polling, either standalone or alongside
upstream link failures.

## Initial Response Steps
1. Ping and traceroute the device from multiple vantage points to rule out a
   routing-only issue vs total device failure.
2. Check upstream link/interface alerts for the same device or its parent switch —
   this is very often a symptom of an upstream link_down incident, not a device fault.
3. Check for high CPU/memory alerts on the device just prior to the outage.
4. Attempt out-of-band (console/management network) access if available.
5. If no upstream cause found and OOB access fails, escalate for a physical
   power-cycle / on-site check.
