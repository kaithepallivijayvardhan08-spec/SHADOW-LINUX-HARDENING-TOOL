#!/usr/bin/env python3
"""
Shadow Integrity Module
=======================

Security checks for system integrity.

Modules:
    file_integrity.py    : File integrity verification
    hash_monitor.py      : File hash monitoring
    change_detection.py  : System change detection

All modules implement:
    def check(config: dict) -> tuple:
        Returns: (status, message, details)
        status: 'PASS', 'FAIL', 'WARN', or 'ERROR'

Optional fix functions:
    def fix(config: dict, dry_run: bool = False, force: bool = False) -> bool:
        Returns: True if fix applied successfully

Module Metadata:
    SEVERITY: HIGH - Integrity monitoring detects unauthorized changes
    RECOMMENDATION: "Install and configure AIDE for file integrity monitoring"
"""

# ============================================================
# MODULE METADATA
# ============================================================
SEVERITY = "HIGH"
RECOMMENDATION = "Install and configure AIDE for file integrity monitoring"

# Import all submodules for easy access
from shadow.modules.integrity import file_integrity
from shadow.modules.integrity import hash_monitor
from shadow.modules.integrity import change_detection

__all__ = [
    "file_integrity",
    "hash_monitor",
    "change_detection",
]