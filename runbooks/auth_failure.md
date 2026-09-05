---
id: rb-auth-failure
title: Repeated Authentication Failures
keywords: [auth_failure]
---

# Repeated Authentication Failures

## Applies when
A device or user shows repeated failed authentication attempts (RADIUS/TACACS+,
VPN, or device login) in a short window.

## Initial Response Steps
1. Determine if failures are concentrated on one account/device (possible
   credential issue or brute-force attempt) or spread across many (possible
   AAA server outage).
2. Check AAA server (RADIUS/TACACS+) health and reachability — a downed auth
   server produces exactly this pattern network-wide.
3. Check for a recent password/certificate expiry or rotation that wasn't
   propagated to all devices.
4. If pattern suggests brute-force/security incident rather than an outage,
   route to the security team instead of continuing network troubleshooting.
5. Once root cause identified, confirm authentication succeeds again from a
   sample of affected devices before closing.
