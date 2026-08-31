#!/usr/bin/env python3
"""
Shadow Storage Module
=====================

Security checks for storage configuration.

Modules:
    disk_check.py   : Disk space and mount point security
    lvm.py          : LVM (Logical Volume Manager) security
    encryption.py   : Disk encryption status

All modules implement:
    def check(config: dict) -> tuple:
        Returns: (status, message, details)
        status: 'PASS', 'FAIL', 'WARN', or 'ERROR'

Optional fix functions:
    def fix(config: dict, dry_run: bool = False, force: bool = False) -> bool:
        Returns: True if fix applied successfully

Module Metadata:
    SEVERITY: MEDIUM - Storage security protects data at rest
    RECOMMENDATION: "Enable encryption for sensitive data and monitor disk usage"
"""

# ============================================================
# MODULE METADATA
# ============================================================
SEVERITY = "MEDIUM"
RECOMMENDATION = "Enable encryption for sensitive data and monitor disk usage"

# Import all submodules for easy access
from shadow.modules.storage import disk_check
from shadow.modules.storage import lvm
from shadow.modules.storage import encryption

__all__ = [
    "disk_check",
    "lvm",
    "encryption",
]