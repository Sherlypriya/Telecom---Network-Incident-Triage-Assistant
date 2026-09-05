---
id: rb-link-down
title: Link Down / Circuit Failure
keywords: [link_down, interface_flapping, packet_loss, bgp_session_down]
---

# Link Down / Circuit Failure

## Applies when
A physical or logical link between two network devices goes down, often producing
downstream device-unreachable and BGP session alerts.

## Initial Response Steps
1. Confirm the link status via `show interface <if>` on both endpoints.
2. Check for correlated alerts on adjacent devices (device unreachable, BGP down) to
   scope the blast radius.
3. Check circuit provider status page / NOC ticket queue for a known carrier outage.
4. If physical (fiber cut, SFP failure): dispatch field team or attempt automatic
   failover to backup path if configured.
5. If logical (misconfiguration, protocol flap): review recent config changes on the
   interface within the last 24 hours.
6. Once restored, verify BGP/OSPF adjacencies re-establish and traffic re-balances.
