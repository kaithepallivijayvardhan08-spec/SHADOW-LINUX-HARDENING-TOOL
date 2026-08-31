#!/usr/bin/env python3
"""
Shadow Network Module
=====================

Security checks for network configuration.

Modules:
    firewall.py     : Firewall status and rules
    ports.py        : Open ports and listening services
    dns.py          : DNS security and configuration
    connections.py  : Active network connections

All modules implement:
    def check(config: dict) -> tuple:
        Returns: (status, message, details)
        status: 'PASS', 'FAIL', 'WARN', or 'ERROR'

Optional fix functions:
    def fix(config: dict, dry_run: bool = False, force: bool = False) -> bool:
        Returns: True if fix applied successfully

Module Metadata:
    SEVERITY: HIGH - Network security is critical for system protection
    RECOMMENDATION: "Enable firewall and restrict open ports to only required services"
"""

# ============================================================
# MODULE METADATA
# ============================================================
SEVERITY = "HIGH"
RECOMMENDATION = "Enable firewall and restrict open ports to only required services"

# Import all submodules for easy access
from shadow.modules.network import firewall
from shadow.modules.network import ports
from shadow.modules.network import dns
from shadow.modules.network import connections

__all__ = [
    "firewall",
    "ports",
    "dns",
    "connections",
]