#!/usr/bin/env python3
"""
Shadow Audit Module
===================

Security checks for system auditing.

Modules:
    auditd_check.py      : Auditd service status
    audit_rules.py       : Audit rules configuration
    system_events.py     : System event monitoring

Module Metadata:
    SEVERITY: HIGH - Auditing is critical for compliance and forensics
    RECOMMENDATION: "Enable auditd and configure audit rules for security events"
"""

# ============================================================
# MODULE METADATA
# ============================================================
SEVERITY = "HIGH"
RECOMMENDATION = "Enable auditd and configure audit rules for security events"

# Import all submodules for easy access
from shadow.modules.audit import auditd_check
from shadow.modules.audit import audit_rules
from shadow.modules.audit import system_events

__all__ = [
    "auditd_check",
    "audit_rules",
    "system_events",
]