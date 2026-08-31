#!/usr/bin/env python3
"""
Shadow Remote Access Module
===========================

Security checks for remote access services.

Modules:
    ssh.py      : SSH configuration, root login, protocols, ciphers
    telnet.py   : Telnet detection and disabling
    rdp_vnc.py  : RDP/VNC security checks

All modules implement:
    def check(config: dict) -> tuple:
        Returns: (status, message, details)
        status: 'PASS', 'FAIL', 'WARN', or 'ERROR'

Optional fix functions:
    def fix(config: dict, dry_run: bool = False, force: bool = False) -> bool:
        Returns: True if fix applied successfully

Module Metadata:
    SEVERITY: HIGH - Remote access is a common attack vector
    RECOMMENDATION: "Disable insecure protocols and secure SSH with key-based authentication"
"""

# ============================================================
# MODULE METADATA
# ============================================================
SEVERITY = "HIGH"
RECOMMENDATION = "Disable insecure protocols and secure SSH with key-based authentication"

# Import all submodules for easy access
from shadow.modules.remote_access import ssh
from shadow.modules.remote_access import telnet
from shadow.modules.remote_access import rdp_vnc

__all__ = [
    "ssh",
    "telnet",
    "rdp_vnc",
]