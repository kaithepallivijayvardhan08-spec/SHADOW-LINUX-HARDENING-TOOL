#!/usr/bin/env python3
"""
Shadow Authentication Module
============================

Security checks for authentication and user management.

Modules:
    password_policy.py  : Password length, age, complexity
    login_protection.py : 3 attempts lockout (YOUR FEATURE)
    sudo_check.py       : Sudoers file security
    users.py            : User accounts, UID 0, empty passwords

All modules implement:
    def check(config: dict) -> tuple:
        Returns: (status, message, details)
        status: 'PASS', 'FAIL', 'WARN', or 'ERROR'

Optional fix functions:
    def fix(config: dict, dry_run: bool = False, force: bool = False) -> bool:
        Returns: True if fix applied successfully

Module Metadata:
    SEVERITY: CRITICAL - Authentication is the first line of defense
    RECOMMENDATION: "Run: sudo shadow --harden to apply all authentication fixes"
"""

# ============================================================
# MODULE METADATA
# ============================================================
SEVERITY = "CRITICAL"
RECOMMENDATION = "Run: sudo shadow --harden to apply all authentication fixes"

# Import all submodules for easy access
from shadow.modules.authentication import password_policy
from shadow.modules.authentication import login_protection
from shadow.modules.authentication import sudo_check
from shadow.modules.authentication import users

__all__ = [
    "password_policy",
    "login_protection",
    "sudo_check",
    "users",
]