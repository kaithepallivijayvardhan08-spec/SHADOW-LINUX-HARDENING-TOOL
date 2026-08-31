#!/usr/bin/env python3
"""
Shadow Monitoring Module
========================

Security checks for system monitoring.

Modules:
    logs.py                  : System logging configuration
    suspicious_process.py    : Suspicious running processes
    malware_scan.py         : Basic malware detection

All modules implement:
    def check(config: dict) -> tuple:
        Returns: (status, message, details)
        status: 'PASS', 'FAIL', 'WARN', or 'ERROR'

Optional fix functions:
    def fix(config: dict, dry_run: bool = False, force: bool = False) -> bool:
        Returns: True if fix applied successfully

Module Metadata:
    SEVERITY: MEDIUM - Monitoring provides visibility into security events
    RECOMMENDATION: "Enable logging and monitoring for security events"
"""

# ============================================================
# MODULE METADATA
# ============================================================
SEVERITY = "MEDIUM"
RECOMMENDATION = "Enable logging and monitoring for security events"

# Import all submodules for easy access
from shadow.modules.monitoring import logs
from shadow.modules.monitoring import suspicious_process
from shadow.modules.monitoring import malware_scan

__all__ = [
    "logs",
    "suspicious_process",
    "malware_scan",
]