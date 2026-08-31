#!/usr/bin/env python3
"""
Shadow Processes Module
=======================

Security checks for running processes.

Modules:
    process_audit.py     : Process auditing
    startup_process.py   : Startup processes
    resource_check.py    : System resource usage

Module Metadata:
    SEVERITY: MEDIUM - Process security prevents resource abuse
    RECOMMENDATION: "Monitor processes and set resource limits for users"
"""

# ============================================================
# MODULE METADATA
# ============================================================
SEVERITY = "MEDIUM"
RECOMMENDATION = "Monitor processes and set resource limits for users"

# Import all submodules for easy access
from shadow.modules.processes import process_audit
from shadow.modules.processes import startup_process
from shadow.modules.processes import resource_check

__all__ = [
    "process_audit",
    "startup_process",
    "resource_check",
]