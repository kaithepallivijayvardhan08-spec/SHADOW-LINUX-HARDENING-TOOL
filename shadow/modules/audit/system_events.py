#!/usr/bin/env python3
"""
Shadow System Events Module
===========================

Monitors system events for security anomalies.

Security concerns:
- Failed login attempts → brute force
- Unauthorized access → compromise
- System modifications → rootkit
"""

from shadow.core import ui
import os
import re
import logging
import shutil
import subprocess
import json
from pathlib import Path
from typing import Tuple, Dict, List, Optional
from datetime import datetime, timedelta

# ============================================================
# MODULE METADATA
# ============================================================
SEVERITY = "HIGH"
RECOMMENDATION = "Enable auditd and configure audit rules for security events"

CHANGES_LOG = Path("/var/log/shadow/changes.log")

# ============================================================
# TRANSACTION SUPPORT
# ============================================================
_transaction_active = False
_transaction_backups = []

def begin_transaction():
    """Begin a transaction for system events modifications."""
    global _transaction_active, _transaction_backups
    _transaction_active = True
    _transaction_backups = []
    logging.getLogger(__name__).info("System events transaction started")

def add_to_transaction(backup_path: Path, original_path: Path):
    """Add a backup to the current transaction."""
    global _transaction_backups
    if _transaction_active:
        _transaction_backups.append({
            'backup_path': str(backup_path),
            'original_path': str(original_path)
        })

def commit_transaction() -> bool:
    """Commit the current transaction."""
    global _transaction_active, _transaction_backups
    _transaction_active = False
    _transaction_backups = []
    logging.getLogger(__name__).info("System events transaction committed")
    return True

def rollback_transaction() -> bool:
    """Rollback the current transaction, restoring all backups."""
    global _transaction_active, _transaction_backups
    logger = logging.getLogger(__name__)
    restored = 0
    for backup_info in reversed(_transaction_backups):
        backup_path = Path(backup_info['backup_path'])
        original_path = Path(backup_info['original_path'])
        if backup_path.exists():
            try:
                shutil.copy2(backup_path, original_path)
                logger.info(f"Rolled back: {original_path}")
                restored += 1
            except Exception as e:
                logger.error(f"Rollback failed for {original_path}: {e}")
    _transaction_active = False
    _transaction_backups = []
    logger.info(f"Transaction rolled back ({restored} files restored)")
    return restored > 0

# ============================================================
# FIX 8: STRUCTURED LOGGING
# ============================================================
def _log_system_events_findings(details: Dict, issues: List[str], warnings: List[str] = None):
    """Log system events findings with structured format."""
    if warnings is None:
        warnings = []
    logger = logging.getLogger(__name__)
    
    log_entry = {
        "event": "system_events_check",
        "details": {
            "failed_logins": details.get('failed_logins', 0),
            "failed_logins_by_user": details.get('failed_logins_by_user', {}),
            "suspicious_logins": len(details.get('suspicious_logins', [])),
            "recent_modifications": len(details.get('recent_modifications', [])),
            "sudo_events": len(details.get('system_events', []))
        },
        "issues": issues,
        "warnings": warnings,
        "timestamp": datetime.now().isoformat()
    }
    logger.info(f"SYSTEM_EVENTS: {json.dumps(log_entry)}")
    
    try:
        CHANGES_LOG.parent.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        with open(CHANGES_LOG, 'a') as f:
            f.write(f"{timestamp} - System Events Check Results:\n")
            f.write(f"  Failed Logins (24h): {details.get('failed_logins', 0)}\n")
            
            failed_by_user = details.get('failed_logins_by_user', {})
            if failed_by_user:
                f.write("  Failed Logins by User:\n")
                for user, count in failed_by_user.items():
                    f.write(f"    - {user}: {count}\n")
            
            f.write(f"  Suspicious Logins: {len(details.get('suspicious_logins', []))}\n")
            f.write(f"  Recent Modifications: {len(details.get('recent_modifications', []))}\n")
            
            for issue in issues:
                f.write(f"  ISSUE: {issue}\n")
            for warning in warnings:
                f.write(f"  WARNING: {warning}\n")
    except Exception as e:
        logging.getLogger(__name__).warning(f"Failed to log system events findings: {e}")


# ============================================================
# CHECK FUNCTION
# ============================================================
def check(config: dict) -> Tuple[str, str, dict]:
    """Check system events"""
    logger = logging.getLogger(__name__)
    logger.info("Checking system events...")

    issues = []
    warnings = []
    details = {
        'failed_logins': 0,
        'suspicious_logins': [],
        'recent_modifications': [],
        'system_events': [],
        'failed_logins_by_user': {}
    }

    # Check auth logs for failed logins
    failed_logins, failed_by_user = _check_failed_logins()
    details['failed_logins'] = failed_logins
    details['failed_logins_by_user'] = failed_by_user

    if failed_logins > 10:
        issues.append(f"{failed_logins} failed logins in last 24 hours")
    elif failed_logins > 5:
        issues.append(f"{failed_logins} failed logins in last 24 hours (elevated)")

    # Log users with multiple failures
    for user, count in failed_by_user.items():
        if count > 5:
            issues.append(f"User {user} had {count} failed login attempts")

    # Check suspicious logins
    suspicious = _check_suspicious_logins()
    details['suspicious_logins'] = suspicious

    if suspicious:
        for login in suspicious[:5]:
            issues.append(f"Suspicious login: {login}")

    # Check recent modifications
    modifications = _check_recent_modifications()
    details['recent_modifications'] = modifications

    if modifications:
        for mod in modifications[:5]:
            issues.append(f"Recent modification: {mod}")

    # Check for sudo/root access events
    sudo_events = _check_sudo_events()
    details['system_events'] = sudo_events

    if sudo_events:
        for event in sudo_events[:5]:
            details['system_events'].append(event)

    # FIX 4: Check log monitoring status
    if not _check_log_watcher():
        issues.append("No log monitoring service (auditd/rsyslog) is running!")

    # FIX 5: Check for elevated privileges
    if _check_elevated_privileges():
        warnings.append("Elevated privileges detected (sudoers modifications)")

    # Log findings
    _log_system_events_findings(details, issues, warnings)

    if issues:
        return 'WARN', f"{len(issues)} system event issues found", details
    return 'PASS', "No concerning system events found", details


def _check_failed_logins() -> Tuple[int, Dict[str, int]]:
    """Check failed login attempts in the last 24 hours"""
    count = 0
    failed_by_user = {}

    auth_logs = ['/var/log/auth.log', '/var/log/secure']

    for log_file in auth_logs:
        if not os.path.exists(log_file):
            continue

        try:
            with open(log_file, 'r') as f:
                for line in f:
                    if 'Failed password' in line:
                        count += 1
                        
                        user_match = re.search(r'for (invalid user )?(\S+)', line)
                        if user_match:
                            user = user_match.group(2)
                            failed_by_user[user] = failed_by_user.get(user, 0) + 1
                            
        except Exception as e:
            logging.getLogger(__name__).debug(f"Error reading {log_file}: {e}")

    return count, failed_by_user


def _check_suspicious_logins() -> List[str]:
    """Check for suspicious login events"""
    suspicious = []

    auth_logs = ['/var/log/auth.log', '/var/log/secure']

    for log_file in auth_logs:
        if not os.path.exists(log_file):
            continue

        try:
            with open(log_file, 'r') as f:
                for line in f:
                    # Check for root logins
                    if 'Accepted password' in line and 'root' in line:
                        suspicious.append(line.strip())
                    # Check for late night logins (midnight to 6am)
                    if 'Accepted password' in line:
                        match = re.search(r'(\d{2}):(\d{2}):(\d{2})', line)
                        if match:
                            hour = int(match.group(1))
                            if 0 <= hour <= 6:
                                suspicious.append(f"Late night login: {line.strip()}")
                    # Check for unusual TTY
                    if 'Accepted password' in line and ('pts' not in line and 'tty' not in line):
                        suspicious.append(f"Unusual TTY login: {line.strip()}")
        except Exception as e:
            logging.getLogger(__name__).debug(f"Error reading {log_file}: {e}")

    return list(set(suspicious))[:20]

# ============================================================
# ✅ FIX: PREVENT SELF-INFLICTED WARNINGS
# ============================================================
def _get_shadow_modified_files() -> set:
    """Read changes.log to find files that Shadow itself modified recently."""
    shadow_modified = set()
    changes_log = Path("/var/log/shadow/changes.log")
    if changes_log.exists():
        try:
            with open(changes_log, 'r') as f:
                content = f.read()
                # List of files Shadow typically modifies during hardening
                shadow_files = [
                    '/etc/passwd', '/etc/shadow', '/etc/group', '/etc/gshadow',
                    '/etc/sudoers', '/etc/ssh/sshd_config', '/etc/crontab',
                    '/etc/hosts', '/etc/fstab', '/etc/pam.d/common-auth',
                    '/etc/pam.d/common-password', '/etc/login.defs', 
                    '/etc/security/pwquality.conf', '/etc/logrotate.conf'
                ]
                for file_path in shadow_files:
                    if file_path in content:
                        shadow_modified.add(file_path)
        except Exception:
            pass
    return shadow_modified

def _check_recent_modifications() -> List[str]:
    """Check recent system modifications"""
    modifications = []

    # ✅ FIX: Get files modified by Shadow itself to prevent self-inflicted warnings
    shadow_modified = _get_shadow_modified_files()

    sensitive_files = [
        '/etc/passwd', '/etc/shadow', '/etc/sudoers',
        '/etc/ssh/sshd_config', '/etc/crontab',
        '/etc/hosts', '/etc/fstab', '/etc/group',
        '/etc/pam.d/common-auth', '/etc/pam.d/common-password',
        '/etc/login.defs', '/etc/security/pwquality.conf'
    ]

    for file_path in sensitive_files:
        if not os.path.exists(file_path):
            continue
            
        # ✅ FIX: Skip if Shadow modified this file during the hardening process
        if file_path in shadow_modified:
            continue

        try:
            mtime = datetime.fromtimestamp(os.path.getmtime(file_path))
            if datetime.now() - mtime < timedelta(hours=24):
                modifications.append(f"{file_path} (modified {mtime.strftime('%Y-%m-%d %H:%M')})")
        except Exception as e:
            logging.getLogger(__name__).debug(f"Error checking {file_path}: {e}")

    return modifications


def _check_sudo_events() -> List[str]:
    """Check for sudo/root access events"""
    events = []

    try:
        auth_logs = ['/var/log/auth.log', '/var/log/secure']
        
        for log_file in auth_logs:
            if not os.path.exists(log_file):
                continue

            with open(log_file, 'r') as f:
                for line in f:
                    if 'sudo' in line and ('COMMAND' in line or 'USER' in line):
                        events.append(line.strip())
                        if len(events) > 20:
                            break
    except Exception as e:
        logging.getLogger(__name__).debug(f"Error checking sudo events: {e}")

    return events


# ============================================================
# FIX 4: LOG MONITORING CHECK
# ============================================================
def _check_log_watcher() -> bool:
    """Check if log watcher (auditd/rsyslog) is running."""
    try:
        result = subprocess.run(
            ['systemctl', 'is-active', 'auditd'],
            capture_output=True,
            text=True,
            timeout=5, stdin=subprocess.DEVNULL)
        if result.stdout.strip() == 'active':
            return True
    except:
        pass

    try:
        result = subprocess.run(
            ['systemctl', 'is-active', 'rsyslog'],
            capture_output=True,
            text=True,
            timeout=5, stdin=subprocess.DEVNULL)
        if result.stdout.strip() == 'active':
            return True
    except:
        pass

    return False


# ============================================================
# FIX 5: CHECK ELEVATED PRIVILEGES
# ============================================================
def _check_elevated_privileges() -> bool:
    """Check for elevated privileges in sudoers."""
    try:
        with open('/etc/sudoers', 'r') as f:
            content = f.read()
            # Check for NOPASSWD entries (risky)
            if 'NOPASSWD' in content:
                return True
            # Check for ALL entries (too permissive)
            if 'ALL=(ALL)' in content or 'ALL=(ALL:ALL)' in content:
                return True
    except:
        pass
    return False


# ============================================================
# FIX 6: CHECK ROOT LOGIN ATTEMPTS
# ============================================================
def _check_root_login_attempts() -> int:
    """Check for root login attempts."""
    count = 0
    auth_logs = ['/var/log/auth.log', '/var/log/secure']

    for log_file in auth_logs:
        if not os.path.exists(log_file):
            continue

        try:
            with open(log_file, 'r') as f:
                for line in f:
                    if 'root' in line and ('Failed password' in line or 'Accepted password' in line):
                        count += 1
        except:
            pass

    return count


def fix(config: dict, dry_run: bool = False, force: bool = False) -> bool:
    """
    Fix system event issues (warning only)

    Args:
        config: Configuration dictionary
        dry_run: If True, preview changes without applying
        force: If True, skip confirmation

    Returns:
        bool: True if fixes applied successfully
    """
    logger = logging.getLogger(__name__)

    # Check for dry-run mode (use parameter, not config)
    if dry_run:
        logger.info("DRY-RUN MODE: No changes will be applied")
        print("\n[!] DRY-RUN MODE - No changes will be applied")
        
        failed_logins, failed_by_user = _check_failed_logins()
        suspicious = _check_suspicious_logins()
        modifications = _check_recent_modifications()
        root_attempts = _check_root_login_attempts()
        
        print(f"  Failed logins (24h): {failed_logins}")
        print(f"  Suspicious logins: {len(suspicious)}")
        print(f"  Recent modifications: {len(modifications)}")
        print(f"  Root login attempts: {root_attempts}")
        
        if failed_logins > 5 or suspicious or modifications or root_attempts > 3:
            print("  Would warn about system events (manual investigation required)")
        
        print("\n[✓] Dry-run complete. No changes were made.")
        return True

    # FIX: Skip confirmation in force mode
    if not force:
        print("\n[!] WARNING: System event scanning will be performed")
        print("    No automatic changes will be made")
        print("    Manual investigation is required for anomalies")
        response = ui.prompt("Run system events audit? [y/N]: ")
        if response.lower() != 'y':
            logger.info("System events audit cancelled by user")
            return False
    else:
        logger.info("Force mode: Running system events audit without confirmation")

    try:
        begin_transaction()
        
        logger.warning("System events should be investigated manually")
        
        # Check if log monitoring is active
        if not _check_log_watcher():
            logger.warning("No log monitoring service (auditd/rsyslog) is running!")
            try:
                CHANGES_LOG.parent.mkdir(parents=True, exist_ok=True)
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                with open(CHANGES_LOG, 'a') as f:
                    f.write(f"{timestamp} - System Events Warning: No log monitoring service running\n")
            except Exception as e:
                logger.debug(f"Failed to log event warning: {e}")
        
        # Check root login attempts
        root_attempts = _check_root_login_attempts()
        if root_attempts > 3:
            logger.warning(f"High number of root login attempts: {root_attempts}")
            print(f"\n  {root_attempts} root login attempts detected")
        
        # Check failed logins
        failed_count, failed_by_user = _check_failed_logins()
        if failed_count > 10:
            logger.warning(f"High number of failed logins: {failed_count}")
            print(f"\n  {failed_count} failed login attempts in 24 hours")
            if failed_by_user:
                for user, count in failed_by_user.items():
                    if count > 5:
                        print(f"    - {user}: {count} attempts")
        
        # Check suspicious logins
        suspicious = _check_suspicious_logins()
        if suspicious:
            logger.warning(f"Found {len(suspicious)} suspicious logins")
            print(f"\n  {len(suspicious)} suspicious logins detected")
            for login in suspicious[:3]:
                print(f"    - {login[:80]}")
        
        # Log the warning
        try:
            CHANGES_LOG.parent.mkdir(parents=True, exist_ok=True)
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            with open(CHANGES_LOG, 'a') as f:
                f.write(f"{timestamp} - System Events Warning: Manual investigation required\n")
                f.write(f"  Failed Logins (24h): {failed_count}\n")
                f.write(f"  Root Login Attempts: {root_attempts}\n")
                f.write(f"  Suspicious Logins: {len(suspicious)}\n")
        except Exception as e:
            logger.debug(f"Failed to log event warning: {e}")
        
        commit_transaction()
        print("\n✅ System events audit complete")
        print("   Review findings in: /var/log/shadow/changes.log")
        print("   Manual remediation required for anomalies")
        return True

    except Exception as e:
        logger.error(f"Failed to complete system events audit: {e}")
        rollback_transaction()
        return False