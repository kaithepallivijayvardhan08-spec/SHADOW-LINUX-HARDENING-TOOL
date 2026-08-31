#!/usr/bin/env python3
"""
Shadow Scheduled Tasks Module
==============================

Security checks for scheduled tasks.

Modules:
    cron_check.py        : Cron jobs security
    systemd_timer.py     : Systemd timers
    startup_jobs.py      : Startup jobs

All modules implement:
    def check(config: dict) -> tuple:
        Returns: (status, message, details)
        status: 'PASS', 'FAIL', 'WARN', or 'ERROR'

Optional fix functions:
    def fix(config: dict, dry_run: bool = False, force: bool = False) -> bool:
        Returns: True if fix applied successfully

Module Metadata:
    SEVERITY: MEDIUM - Scheduled tasks can be abused for persistence
    RECOMMENDATION: "Review and secure scheduled tasks to prevent abuse"
"""

# ============================================================
# MODULE METADATA
# ============================================================
SEVERITY = "MEDIUM"
RECOMMENDATION = "Review and secure scheduled tasks to prevent abuse"

# Import all submodules for easy access
from shadow.modules.scheduled_tasks import cron_check
from shadow.modules.scheduled_tasks import systemd_timer
from shadow.modules.scheduled_tasks import startup_jobs

__all__ = [
    "cron_check",
    "systemd_timer",
    "startup_jobs",
]