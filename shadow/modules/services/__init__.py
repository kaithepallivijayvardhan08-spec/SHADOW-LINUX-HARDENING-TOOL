#!/usr/bin/env python3
"""
Shadow Services Module
======================

Security checks for running services.

Modules:
    apache.py    : Apache web server security
    nginx.py     : Nginx web server security
    mysql.py     : MySQL database security
    docker.py    : Docker container security
    nfs.py       : NFS file sharing security

All modules implement:
    def check(config: dict) -> tuple:
        Returns: (status, message, details)
        status: 'PASS', 'FAIL', 'WARN', or 'ERROR'

Optional fix functions:
    def fix(config: dict, dry_run: bool = False, force: bool = False) -> bool:
        Returns: True if fix applied successfully

Module Metadata:
    SEVERITY: HIGH - Services often expose attack surfaces
    RECOMMENDATION: "Review and secure running services with: sudo shadow --harden"
"""

# ============================================================
# MODULE METADATA
# ============================================================
SEVERITY = "HIGH"
RECOMMENDATION = "Review and secure running services with: sudo shadow --harden"

# Import all submodules for easy access
from shadow.modules.services import apache
from shadow.modules.services import nginx
from shadow.modules.services import mysql
from shadow.modules.services import docker
from shadow.modules.services import nfs

__all__ = [
    "apache",
    "nginx",
    "mysql",
    "docker",
    "nfs",
]