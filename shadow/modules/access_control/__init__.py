#!/usr/bin/env python3
"""
Shadow Access Control Module
============================

Security checks for access control systems.

Modules:
    selinux.py           : SELinux status
    apparmor.py          : AppArmor status
    capabilities.py      : Linux capabilities

All modules implement:
    def check(config: dict) -> tuple:
        Returns: (status, message, details)
        status: 'PASS', 'FAIL', 'WARN', or 'ERROR'

Optional fix functions:
    def fix(config: dict, dry_run: bool = False, force: bool = False) -> bool:
        Returns: True if fix applied successfully

Module Metadata:
    SEVERITY: CRITICAL - Access control prevents unauthorized access
    RECOMMENDATION: "Enable SELinux or AppArmor for mandatory access control"
"""

# ============================================================
# MODULE METADATA
# ============================================================
SEVERITY = "CRITICAL"
RECOMMENDATION = "Enable SELinux or AppArmor for mandatory access control"

# Import all submodules for easy access
from shadow.modules.access_control import selinux
from shadow.modules.access_control import apparmor
from shadow.modules.access_control import capabilities

__all__ = [
    "selinux",
    "apparmor",
    "capabilities",
]