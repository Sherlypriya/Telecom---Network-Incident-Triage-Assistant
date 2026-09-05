---
id: rb-bgp-session
title: BGP Session Down
keywords: [bgp_session_down, link_down]
---

# BGP Session Down

## Applies when
A BGP peering session drops, often as a direct consequence of an underlying
link failure but sometimes due to protocol-level issues alone.

## Initial Response Steps
1. Check underlying physical/logical link status to the peer first — most BGP
   flaps are downstream symptoms, not the root cause.
2. If the link is up, check for BGP hold-timer expiry, MTU mismatch, or a
   recent ACL/firewall change blocking TCP 179.
3. Check peer AS for a known maintenance window or route-flap damping event.
4. Verify route table impact — identify which prefixes were withdrawn and
   what alternate paths (if any) are carrying traffic now.
5. Once session re-establishes, confirm full route convergence before closing.
