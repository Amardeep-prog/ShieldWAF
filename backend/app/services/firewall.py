"""
Generates ready-to-review block commands/config snippets for a
malicious IP, at two levels a real WAF deployment cares about:

  1. The WAF's own in-process blocklist (immediately effective via
     `rate_limiter.manual_block`, already real and applied -- see
     routers/blocklist.py).
  2. Upstream network/edge firewall advisory commands, for defence in
     depth (so the attacker's traffic is dropped before it even
     reaches the reverse proxy). Advisory only -- never auto-applied
     to the host, same design decision as the NIDS project's firewall
     advisory module.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class FirewallAdvisory:
    ip: str
    reason: str
    iptables_cmd: str
    ufw_cmd: str
    nginx_deny_snippet: str
    cloudflare_note: str


def build_block_advisory(ip: str, reason: str = "flagged by ShieldWAF") -> FirewallAdvisory:
    return FirewallAdvisory(
        ip=ip,
        reason=reason,
        iptables_cmd=f"sudo iptables -A INPUT -s {ip} -j DROP",
        ufw_cmd=f"sudo ufw deny from {ip} to any",
        nginx_deny_snippet=f"deny {ip};  # add to nginx.conf, then: nginx -s reload",
        cloudflare_note=(
            f"Cloudflare/edge WAF users: add {ip} to a custom IP Access Rule "
            f"(Block) in the dashboard or via the Firewall Rules API."
        ),
    )
