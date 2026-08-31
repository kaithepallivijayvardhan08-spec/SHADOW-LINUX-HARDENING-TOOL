#!/usr/bin/env python3
"""
Shadow File Security Module
===========================

Security checks for file system security.

Modules:
    permissions.py      : File and directory permissions
    ownership.py        : File and directory ownership
    sensitive_files.py  : Sensitive file protection

All modules implement:
    def check(config: dict) -> tuple:
        Returns: (status, message, details)
        status: 'PASS', 'FAIL', 'WARN', or 'ERROR'

Optional fix functions:
    def fix(config: dict, dry_run: bool = False, force: bool = False) -> bool:
        Returns: True if fix applied successfully

Module Metadata:
    SEVERITY: CRITICAL - File permissions protect sensitive system files
    RECOMMENDATION: "Secure file permissions with: sudo shadow --harden"
"""

# ============================================================
# MODULE METADATA
# ============================================================
SEVERITY = "CRITICAL"
RECOMMENDATION = "Secure file permissions with: sudo shadow --harden"

# Import all submodules for easy access
from shadow.modules.file_security import permissions
from shadow.modules.file_security import ownership
from shadow.modules.file_security import sensitive_files

__all__ = [
    "permissions",
    "ownership",
    "sensitive_files",
]