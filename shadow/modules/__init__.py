#!/usr/bin/env python3
"""
Shadow Modules Package
======================

Contains all security check modules organized by category:

Categories:
- authentication/  : Password policy, login protection, sudo, users
- remote_access/   : SSH, Telnet, RDP/VNC
- network/         : Firewall, ports, DNS, connections
- file_security/   : Permissions, ownership, sensitive files
- services/        : Apache, Nginx, MySQL, Docker, NFS
- storage/         : Disk, LVM, encryption
- monitoring/      : Logs, suspicious processes, malware
- updates/         : Package updates, package integrity
- kernel/          : Kernel check, sysctl security, kernel modules
- processes/       : Process audit, startup processes, resource check
- audit/           : Auditd check, audit rules, system events
- access_control/  : SELinux, AppArmor, capabilities
- scheduled_tasks/ : Cron check, systemd timers, startup jobs
- integrity/       : File integrity, hash monitoring, change detection

Each module must implement:
    def check(config: dict) -> tuple:
        Returns: (status, message, details)
        status: 'PASS', 'FAIL', 'WARN', or 'ERROR'
        message: String description
        details: Optional dict with additional info

Optional:
    def fix(config: dict, dry_run: bool = False, force: bool = False) -> bool:
        Returns: True if fix applied successfully

Module Metadata (optional but recommended):
    SEVERITY: 'CRITICAL', 'HIGH', 'MEDIUM', or 'LOW'
    RECOMMENDATION: str - Recommendation for fixing the issue
"""

# Import all categories
from shadow.modules import authentication
from shadow.modules import remote_access
from shadow.modules import network
from shadow.modules import file_security
from shadow.modules import services
from shadow.modules import storage
from shadow.modules import monitoring
from shadow.modules import updates
from shadow.modules import kernel
from shadow.modules import processes
from shadow.modules import audit
from shadow.modules import access_control
from shadow.modules import scheduled_tasks
from shadow.modules import integrity

__all__ = [
    "authentication",
    "remote_access",
    "network",
    "file_security",
    "services",
    "storage",
    "monitoring",
    "updates",
    "kernel",
    "processes",
    "audit",
    "access_control",
    "scheduled_tasks",
    "integrity",
]

# Category metadata for automatic discovery
CATEGORY_METADATA = {
    "authentication": {
        "description": "Password policy, login protection, sudo, users",
        "modules": ["password_policy", "login_protection", "sudo_check", "users"],
        "default_enabled": True
    },
    "remote_access": {
        "description": "SSH, Telnet, RDP/VNC",
        "modules": ["ssh", "telnet", "rdp_vnc"],
        "default_enabled": True
    },
    "network": {
        "description": "Firewall, ports, DNS, connections",
        "modules": ["firewall", "ports", "dns", "connections"],
        "default_enabled": True
    },
    "file_security": {
        "description": "Permissions, ownership, sensitive files",
        "modules": ["permissions", "ownership", "sensitive_files"],
        "default_enabled": True
    },
    "services": {
        "description": "Apache, Nginx, MySQL, Docker, NFS",
        "modules": ["apache", "nginx", "mysql", "docker", "nfs"],
        "default_enabled": True
    },
    "storage": {
        "description": "Disk, LVM, encryption",
        "modules": ["disk_check", "lvm", "encryption"],
        "default_enabled": True
    },
    "monitoring": {
        "description": "Logs, suspicious processes, malware",
        "modules": ["logs", "suspicious_process", "malware_scan"],
        "default_enabled": True
    },
    "updates": {
        "description": "Package updates, package integrity",
        "modules": ["package_updates", "package_integrity"],
        "default_enabled": True
    },
    "kernel": {
        "description": "Kernel check, sysctl security, kernel modules",
        "modules": ["kernel_check", "sysctl_security", "kernel_modules"],
        "default_enabled": True
    },
    "processes": {
        "description": "Process audit, startup processes, resource check",
        "modules": ["process_audit", "startup_process", "resource_check"],
        "default_enabled": True
    },
    "audit": {
        "description": "Auditd check, audit rules, system events",
        "modules": ["auditd_check", "audit_rules", "system_events"],
        "default_enabled": True
    },
    "access_control": {
        "description": "SELinux, AppArmor, capabilities",
        "modules": ["selinux", "apparmor", "capabilities"],
        "default_enabled": True
    },
    "scheduled_tasks": {
        "description": "Cron check, systemd timers, startup jobs",
        "modules": ["cron_check", "systemd_timer", "startup_jobs"],
        "default_enabled": True
    },
    "integrity": {
        "description": "File integrity, hash monitoring, change detection",
        "modules": ["file_integrity", "hash_monitor", "change_detection"],
        "default_enabled": True
    }
}

def get_all_categories() -> list:
    """Get list of all available categories."""
    return list(CATEGORY_METADATA.keys())

def get_category_info(category: str) -> dict:
    """Get metadata for a specific category."""
    return CATEGORY_METADATA.get(category, {})

def get_modules_for_category(category: str) -> list:
    """Get list of modules for a specific category."""
    return CATEGORY_METADATA.get(category, {}).get("modules", [])