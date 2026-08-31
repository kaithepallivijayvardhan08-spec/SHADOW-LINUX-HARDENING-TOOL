#!/usr/bin/env python3
"""
Shadow Kernel Module
====================

Security checks for kernel configuration.

Modules:
    kernel_check.py      : Kernel version and vulnerabilities
    sysctl_security.py   : Sysctl security parameters
    kernel_modules.py    : Loaded kernel modules

Module Metadata:
    SEVERITY: HIGH - Kernel security affects the entire system
    RECOMMENDATION: "Apply kernel hardening with sysctl settings"
"""

# ============================================================
# MODULE METADATA
# ============================================================
SEVERITY = "HIGH"
RECOMMENDATION = "Apply kernel hardening with sysctl settings"

# Import all submodules for easy access
from shadow.modules.kernel import kernel_check
from shadow.modules.kernel import sysctl_security
from shadow.modules.kernel import kernel_modules

__all__ = [
    "kernel_check",
    "sysctl_security",
    "kernel_modules",
]