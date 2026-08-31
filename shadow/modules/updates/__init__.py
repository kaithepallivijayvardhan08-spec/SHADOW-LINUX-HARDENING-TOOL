#!/usr/bin/env python3
"""
Shadow Updates Module
=====================

Security checks for package updates and integrity.

Modules:
    package_updates.py      : Available package updates
    package_integrity.py    : Package integrity verification

All modules implement:
    def check(config: dict) -> tuple:
        Returns: (status, message, details)
        status: 'PASS', 'FAIL', 'WARN', or 'ERROR'

Optional fix functions:
    def fix(config: dict, dry_run: bool = False, force: bool = False) -> bool:
        Returns: True if fix applied successfully

Module Metadata:
    SEVERITY: CRITICAL - Outdated software is a major security risk
    RECOMMENDATION: "Enable unattended-upgrades for automatic security updates"
"""

# ============================================================
# MODULE METADATA
# ============================================================
SEVERITY = "CRITICAL"
RECOMMENDATION = "Enable unattended-upgrades for automatic security updates"

# Import all submodules for easy access
from shadow.modules.updates import package_updates
from shadow.modules.updates import package_integrity

__all__ = [
    "package_updates",
    "package_integrity",
]