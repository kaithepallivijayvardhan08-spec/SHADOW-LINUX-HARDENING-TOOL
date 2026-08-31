#!/usr/bin/env python3
"""
Shadow Logs Module
==================

Checks system logging configuration:
- Syslog/rsyslog is running
- Log rotation is configured
- Log file permissions
- Remote logging
- Auditd configuration
- Log retention period
- Log file integrity
"""

from shadow.core import ui
import os
import re
import shutil
import logging
import subprocess
import time
import json
import fcntl
import tempfile
import socket
from pathlib import Path
from datetime import datetime
from typing import Tuple, Dict, List, Optional, Any

# ============================================================
# MODULE METADATA
# ============================================================
SEVERITY = "MEDIUM"
RECOMMENDATION = "Enable logging and monitoring for security events"

BACKUP_DIR = Path("/var/backups/shadow/")
CHANGES_LOG = Path("/var/log/shadow/changes.log")

# ============================================================
# TRANSACTION SUPPORT
# ============================================================
_transaction_active = False
_transaction_backups = []

def begin_transaction():
    """Begin a transaction for logging modifications."""
    global _transaction_active, _transaction_backups
    _transaction_active = True
    _transaction_backups = []
    logging.getLogger(__name__).info("Logging transaction started")

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
    logging.getLogger(__name__).info("Logging transaction committed")
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
def _log_logging_change(action: str, details: str, success: bool):
    """Log logging modifications with structured format."""
    logger = logging.getLogger(__name__)
    status = "SUCCESS" if success else "FAILED"
    
    log_entry = {
        "event": "logging_change",
        "action": action,
        "details": details,
        "status": status,
        "timestamp": datetime.now().isoformat()
    }
    logger.info(f"LOGGING: {json.dumps(log_entry)}")
    
    try:
        CHANGES_LOG.parent.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(CHANGES_LOG, 'a') as f:
            f.write(f"{timestamp} - Logging: {action} - {details} ({status})\n")
    except Exception as e:
        logger.debug(f"Failed to log change: {e}")


# ============================================================
# CHECK FUNCTION
# ============================================================
def check(config: dict) -> Tuple[str, str, dict]:
    """
    Check system logging configuration
    """
    logger = logging.getLogger(__name__)
    logger.info("Checking logging configuration...")

    issues = []
    warnings = []
    details = {
        'rsyslog_running': False,
        'auditd_running': False,
        'logrotate_installed': False,
        'remote_logging': False,
        'log_permissions': {},
        'log_rotation_configured': False,
        'auditd_configured': False,
        'log_files': [],
        'log_retention_days': None
    }

    rsyslog_info = _check_rsyslog()
    details.update(rsyslog_info)
    if not details.get('rsyslog_running', False):
        issues.append("rsyslog is not running (system logging disabled)")

    auditd_info = _check_auditd()
    details.update(auditd_info)
    if not details.get('auditd_running', False):
        warnings.append("auditd is not running (access logging disabled)")

    logrotate_info = _check_logrotate()
    details.update(logrotate_info)
    if not details.get('logrotate_installed', False):
        warnings.append("logrotate is not installed")

    remote_logging = _check_remote_logging()
    details['remote_logging'] = remote_logging
    if not remote_logging:
        warnings.append("Remote logging not configured (logs lost on system compromise)")

    log_perms = _check_log_permissions()
    details['log_permissions'] = log_perms
    for log_file, perms in log_perms.items():
        if not perms.get('secure'):
            issues.append(f"Insecure log permissions: {log_file} ({perms['permissions']})")

    log_rotation = _check_log_rotation_config()
    details['log_rotation_configured'] = log_rotation
    if not log_rotation:
        warnings.append("Log rotation not configured")

    auditd_configured = _check_auditd_config()
    details['auditd_configured'] = auditd_configured
    if not auditd_configured:
        warnings.append("auditd not properly configured")

    retention_days = _check_log_retention()
    details['log_retention_days'] = retention_days
    if retention_days is not None and retention_days < 30:
        warnings.append(f"Log retention: {retention_days} days (recommended: 30+)")

    if issues:
        critical = [i for i in issues if 'rsyslog is not running' in i]
        if critical:
            status = 'FAIL'
            message = f"{len(issues)} critical logging issues found"
        else:
            status = 'WARN'
            message = f"{len(issues)} logging issues found"
    elif warnings:
        status = 'WARN'
        message = f"{len(warnings)} logging warnings found"
    else:
        status = 'PASS'
        message = "Logging is properly configured"

    return status, message, details


def _check_rsyslog() -> dict:
    """Check rsyslog status"""
    info = {'rsyslog_running': False, 'rsyslog_version': None}
    try:
        result = subprocess.run(['systemctl', 'is-active', 'rsyslog'], capture_output=True, text=True, timeout=5, stdin=subprocess.DEVNULL)
        if result.stdout.strip() == 'active':
            info['rsyslog_running'] = True
    except: pass

    try:
        result = subprocess.run(['rsyslogd', '-version'], capture_output=True, text=True, timeout=5, stdin=subprocess.DEVNULL)
        for line in result.stderr.split('\n'):
            if 'rsyslogd' in line:
                match = re.search(r'rsyslogd\s+(\d+\.\d+\.\d+)', line)
                if match:
                    info['rsyslog_version'] = match.group(1)
                    break
    except: pass
    return info


def _check_auditd() -> dict:
    """Check auditd status"""
    info = {'auditd_running': False, 'auditd_version': None}
    try:
        result = subprocess.run(['systemctl', 'is-active', 'auditd'], capture_output=True, text=True, timeout=5, stdin=subprocess.DEVNULL)
        if result.stdout.strip() == 'active':
            info['auditd_running'] = True
    except: pass

    try:
        result = subprocess.run(['auditd', '--version'], capture_output=True, text=True, timeout=5, stdin=subprocess.DEVNULL)
        if result.returncode == 0:
            info['auditd_version'] = result.stdout.strip()
    except: pass
    return info


def _check_logrotate() -> dict:
    """Check logrotate installation"""
    info = {'logrotate_installed': False, 'logrotate_version': None}
    try:
        result = subprocess.run(['logrotate', '--version'], capture_output=True, text=True, timeout=5, stdin=subprocess.DEVNULL)
        if result.returncode == 0:
            info['logrotate_installed'] = True
            match = re.search(r'(\d+\.\d+\.\d+)', result.stdout)
            if match:
                info['logrotate_version'] = match.group(1)
    except: pass
    return info


def _check_remote_logging() -> bool:
    """Check if remote logging is configured"""
    rsyslog_conf = '/etc/rsyslog.conf'
    if not os.path.exists(rsyslog_conf): return False

    try:
        with open(rsyslog_conf, 'r') as f:
            content = f.read()
            if '@' in content and ('.' in content or ':' in content):
                if '@127.0.0.1' not in content and '@localhost' not in content:
                    return True
            rsyslog_d = '/etc/rsyslog.d/'
            if os.path.exists(rsyslog_d):
                for file in Path(rsyslog_d).iterdir():
                    if file.is_file():
                        with open(file, 'r') as f:
                            content = f.read()
                            if '@' in content and '127.0.0.1' not in content and 'localhost' not in content:
                                return True
    except Exception as e:
        logging.getLogger(__name__).debug(f"Error checking remote logging: {e}")
    return False


def _check_log_permissions() -> dict:
    """Check log file permissions"""
    log_files = [
        '/var/log/syslog', '/var/log/auth.log', '/var/log/kern.log',
        '/var/log/dmesg', '/var/log/dpkg.log', '/var/log/apt/history.log',
        '/var/log/audit/audit.log'
    ]
    perms = {}
    for log_file in log_files:
        if os.path.exists(log_file):
            try:
                stat_info = os.stat(log_file)
                file_perms = oct(stat_info.st_mode)[-3:]
                perms[log_file] = {
                    'permissions': file_perms,
                    'secure': file_perms in ['600', '640', '644']
                }
            except Exception as e:
                perms[log_file] = {'error': str(e), 'secure': False}
    return perms


def _check_log_rotation_config() -> bool:
    """Check if log rotation is configured"""
    if os.path.exists('/etc/logrotate.conf'): return True
    logrotate_d = '/etc/logrotate.d/'
    if os.path.exists(logrotate_d):
        if list(Path(logrotate_d).iterdir()): return True
    return False


def _check_auditd_config() -> bool:
    """Check auditd configuration"""
    auditd_conf = '/etc/audit/auditd.conf'
    if not os.path.exists(auditd_conf): return False
    try:
        with open(auditd_conf, 'r') as f:
            content = f.read()
            if 'log_file' in content and 'max_log_file' in content:
                return True
    except: pass
    return False


def _check_log_retention() -> Optional[int]:
    """Check log retention days"""
    logrotate_conf = '/etc/logrotate.conf'
    if os.path.exists(logrotate_conf):
        try:
            with open(logrotate_conf, 'r') as f:
                content = f.read()
                match = re.search(r'rotate\s+(\d+)', content)
                if match: return int(match.group(1))
        except: pass

    logrotate_d = '/etc/logrotate.d/'
    if os.path.exists(logrotate_d):
        for file in Path(logrotate_d).iterdir():
            if file.is_file():
                try:
                    with open(file, 'r') as f:
                        content = f.read()
                        match = re.search(r'rotate\s+(\d+)', content)
                        if match: return int(match.group(1))
                except: continue
    return None


def _verify_backup(backup_path: Path) -> bool:
    """Verify that a backup was created successfully."""
    if not backup_path.exists(): return False
    if backup_path.stat().st_size == 0: return False
    return True


def _backup_config(file_path: str) -> Dict[str, Any]:
    """Backup configuration file with metadata."""
    result = {'path': file_path, 'backup_path': None, 'success': False}
    try:
        BACKUP_DIR.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        if os.path.exists(file_path):
            backup_path = BACKUP_DIR / f"{Path(file_path).name}.backup_{timestamp}"
            shutil.copy2(file_path, backup_path)
            result['backup_path'] = str(backup_path)
            if _verify_backup(backup_path):
                result['success'] = True
                logging.getLogger(__name__).info(f"Backup created: {backup_path}")
                add_to_transaction(backup_path, Path(file_path))
    except Exception as e:
        logging.getLogger(__name__).error(f"Failed to backup {file_path}: {e}")
    return result


def _rollback_config(backup_metadata: Dict[str, Any]) -> bool:
    """Rollback configuration from backup."""
    if not backup_metadata.get('success'): return False
    backup_path = Path(backup_metadata['backup_path'])
    original_path = backup_metadata['path']
    if not backup_path.exists(): return False
    try:
        shutil.copy2(backup_path, original_path)
        logging.getLogger(__name__).info(f"Rolled back config: {original_path}")
        return True
    except Exception as e:
        logging.getLogger(__name__).error(f"Rollback failed for {original_path}: {e}")
        return False


def _verify_service_running(service_name: str) -> bool:
    """Verify a service is running."""
    try:
        result = subprocess.run(['systemctl', 'is-active', service_name], capture_output=True, text=True, timeout=10, stdin=subprocess.DEVNULL)
        return result.stdout.strip() == 'active'
    except: return False


def _dry_run_logging_fix(action: str, details: str) -> bool:
    """Simulate logging modification without actually changing anything."""
    logging.getLogger(__name__).info(f"[DRY-RUN] Would perform: {action} - {details}")
    print(f"[DRY-RUN] Would perform: {action}")
    return True


def _confirm_logging_modification(action: str) -> bool:
    """Ask for confirmation before modifying logging."""
    print(f"\n[!] WARNING: About to modify logging configuration")
    print(f"    Action: {action}")
    response = ui.prompt("Proceed? [y/N]: ")
    if response.lower() == 'y':
        print("\n[*] Applying fixes... please wait")
        return True
    return False


def _progress_indicator(current: int, total: int, message: str = ""):
    """Show progress during operations."""
    if total > 0:
        percent = (current / total) * 100
        print(f"\r\033[K[{current}/{total}] {percent:.1f}% - {message}", end="", flush=True)


# ============================================================
# ✅ FIX 10: PACKAGE INSTALLATION HELPER
# ============================================================
def _ensure_package_installed(package_name: str) -> bool:
    """Ensure a package is installed using apt (fixes missing auditd/rsyslog)."""
    logger = logging.getLogger(__name__)
    try:
        # Check if package is installed
        result = subprocess.run(['dpkg', '-s', package_name], capture_output=True, text=True, timeout=10, stdin=subprocess.DEVNULL)
        if result.returncode == 0:
            return True
        
        # Not installed, try to install
        logger.info(f"Installing missing package: {package_name}")
        subprocess.run(['apt-get', 'update', '-qq'], capture_output=True, timeout=30, stdin=subprocess.DEVNULL)
        install_result = subprocess.run(
            ['apt-get', 'install', '-y', '-qq', package_name], 
            capture_output=True, text=True, timeout=60, stdin=subprocess.DEVNULL)
        if install_result.returncode == 0:
            logger.info(f"Successfully installed {package_name}")
            return True
        else:
            logger.warning(f"Failed to install {package_name}: {install_result.stderr}")
            return False
    except Exception as e:
        logger.warning(f"Failed to check/install package {package_name}: {e}")
        return False


# ============================================================
# MAIN FIX FUNCTION
# ============================================================
def fix(config: dict, dry_run: bool = False, force: bool = False) -> bool:
    """Fix logging issues"""
    logger = logging.getLogger(__name__)
    logger.info("Fixing logging issues...")

    if dry_run:
        logger.info("DRY-RUN MODE: No changes will be applied")
        print("\n[!] DRY-RUN MODE - No changes will be applied")
        steps = []
        if config.get('logging', {}).get('enable_rsyslog', True): steps.append("Enable rsyslog")
        if config.get('logging', {}).get('enable_auditd', True): steps.append("Enable auditd")
        if config.get('logging', {}).get('configure_logrotate', True): steps.append("Configure logrotate")
        if config.get('logging', {}).get('fix_log_perms', True): steps.append("Fix log permissions")
        
        print("  Would perform the following fixes:")
        for step in steps: print(f"    • {step}")
        print("\n[✓] Dry-run complete. No changes were made.")
        return True

    if not force:
        print("\n[!] WARNING: Logging fixes will be applied")
        response = ui.prompt("Proceed? [y/N]: ")
        if response.lower() != 'y':
            logger.info("Logging fixes cancelled by user")
            return False
    else:
        logger.info("Force mode: Applying logging fixes without confirmation")

    try:
        begin_transaction()
        steps = []
        
        if config.get('logging', {}).get('enable_rsyslog', True):
            steps.append(("Enable rsyslog", _enable_rsyslog))
        if config.get('logging', {}).get('enable_auditd', True):
            steps.append(("Enable auditd", _enable_auditd))
        if config.get('logging', {}).get('configure_logrotate', True):
            steps.append(("Configure logrotate", _configure_logrotate))
        if config.get('logging', {}).get('fix_log_perms', True):
            steps.append(("Fix log permissions", _fix_log_permissions))
        
        total_steps = len(steps)
        for idx, (name, func) in enumerate(steps):
            _progress_indicator(idx + 1, total_steps, name)
            # ✅ FIX 2: Pass both dry_run and force to all functions
            func(dry_run, force)
        
        print()

        rsyslog_status = _verify_service_running('rsyslog')
        auditd_status = _verify_service_running('auditd')
        
        print("\n📊 LOGGING STATUS:")
        print(f"  rsyslog: {'✅ Running' if rsyslog_status else '❌ Not Running'}")
        print(f"  auditd : {'✅ Running' if auditd_status else '❌ Not Running'}")
        
        if not rsyslog_status:
            logger.warning("rsyslog is not running after fixes")
            rollback_transaction()
            return False
        if not auditd_status:
            logger.warning("auditd is not running after fixes")

        commit_transaction()
        logger.info("Logging fixes applied successfully")
        print("\n✅ Logging fixes applied successfully")
        return True

    except Exception as e:
        logger.error(f"Failed to fix logging issues: {e}")
        rollback_transaction()
        return False


def _enable_rsyslog(dry_run: bool = False, force: bool = False):
    """Enable rsyslog service - with improved verification"""
    logger = logging.getLogger(__name__)
    try:
        if dry_run:
            _dry_run_logging_fix("enable_rsyslog", "Would enable rsyslog")
            return
        
        # Ensure package is installed
        if not _ensure_package_installed('rsyslog'):
            logger.warning("Failed to install rsyslog package")
            print(" ⚠️ Could not install rsyslog package")
            return
        
        # Reload systemd to pick up newly installed service
        subprocess.run(['systemctl', 'daemon-reload'], 
                      capture_output=True, text=True, timeout=10, stdin=subprocess.DEVNULL)
        
        # Enable and start
        subprocess.run(['systemctl', 'enable', 'rsyslog'], 
                      capture_output=True, text=True, timeout=10, stdin=subprocess.DEVNULL)
        subprocess.run(['systemctl', 'restart', 'rsyslog'], 
                      capture_output=True, text=True, timeout=10, stdin=subprocess.DEVNULL)
        
        # Wait and verify
        time.sleep(3)
        if _verify_service_running('rsyslog'):
            logger.info("rsyslog enabled and running")
            _log_logging_change("enable_rsyslog", "rsyslog enabled", True)
            print("\n  ✅ rsyslog enabled successfully")
        else:
            logger.warning("rsyslog enable attempted but service not running")
            _log_logging_change("enable_rsyslog", "rsyslog not running after enable", False)
            print("\n  ⚠️ rsyslog installed but service not running (may need manual start)")
            
    except Exception as e:
        logger.error(f"Error enabling rsyslog: {e}")
        _log_logging_change("enable_rsyslog", str(e), False)
    

def _enable_auditd(dry_run: bool = False, force: bool = False):
    """Enable auditd service - with improved verification"""
    logger = logging.getLogger(__name__)
    try:
        if dry_run:
            _dry_run_logging_fix("enable_auditd", "Would enable auditd")
            return
        
        if not force:
            print("\n[!] auditd is not running. Enabling it will increase system monitoring.")
            response = ui.prompt("Continue enabling auditd? [y/N]: ")
            if response.lower() != 'y':
                logger.info("auditd enable cancelled by user")
                return
        
        # Ensure package is installed
        if not _ensure_package_installed('auditd'):
            logger.warning("Failed to install auditd package")
            print(" ⚠️ Could not install auditd package")
            return
        
        # Reload systemd
        subprocess.run(['systemctl', 'daemon-reload'], 
                      capture_output=True, text=True, timeout=10, stdin=subprocess.DEVNULL)
        
        # Enable and start
        subprocess.run(['systemctl', 'enable', 'auditd'], 
                      capture_output=True, text=True, timeout=10, stdin=subprocess.DEVNULL)
        subprocess.run(['systemctl', 'restart', 'auditd'], 
                      capture_output=True, text=True, timeout=10, stdin=subprocess.DEVNULL)
        
        # Wait and verify
        time.sleep(3)
        if _verify_service_running('auditd'):
            logger.info("auditd enabled and running")
            _log_logging_change("enable_auditd", "auditd enabled", True)
            print("\n  ✅ auditd enabled successfully")
        else:
            logger.warning("auditd enable attempted but service not running")
            _log_logging_change("enable_auditd", "auditd not running after enable", False)
            print("\n  ⚠️ auditd installed but service not running (may need manual start)")
            
    except Exception as e:
        logger.error(f"Error enabling auditd: {e}")
        _log_logging_change("enable_auditd", str(e), False)


# ✅ FIX 2: Added `force` parameter to match the loop call signature
def _configure_logrotate(dry_run: bool = False, force: bool = False):
    """Configure log rotation"""
    logrotate_conf = '/etc/logrotate.conf'
    
    if dry_run:
        _dry_run_logging_fix("configure_logrotate", f"Would configure logrotate in {logrotate_conf}")
        return

    if os.path.exists(logrotate_conf):
        backup_metadata = _backup_config(logrotate_conf)
        try:
            with open(logrotate_conf, 'r') as f:
                content = f.read()

            if 'rotate 30' not in content and 'rotate 52' not in content:
                content = content + '\n# Shadow added - log retention\nrotate 30\n'
                with open(logrotate_conf, 'w') as f:
                    f.write(content)
                logging.getLogger(__name__).info("logrotate configured")
                _log_logging_change("configure_logrotate", "Set log retention to 30 days", True)
            else:
                logging.getLogger(__name__).debug("logrotate already configured")
        except Exception as e:
            logging.getLogger(__name__).error(f"Error configuring logrotate: {e}")
            if backup_metadata['success']:
                _rollback_config(backup_metadata)
            _log_logging_change("configure_logrotate", str(e), False)


# ✅ FIX 2: Added `force` parameter to match the loop call signature
def _fix_log_permissions(dry_run: bool = False, force: bool = False):
    """Fix log file permissions"""
    log_files = [
        '/var/log/syslog', '/var/log/auth.log', '/var/log/kern.log',
        '/var/log/dmesg', '/var/log/audit/audit.log'
    ]

    total_files = len(log_files)
    for idx, log_file in enumerate(log_files):
        if dry_run:
            _dry_run_logging_fix("fix_log_permissions", f"Would fix permissions on {log_file}")
            continue
        
        if os.path.exists(log_file):
            _progress_indicator(idx + 1, total_files, f"Fixing {Path(log_file).name}")
            try:
                stat_info = os.stat(log_file)
                current_perms = oct(stat_info.st_mode)[-3:]
                if current_perms != '640':
                    os.chmod(log_file, 0o640)
                    logging.getLogger(__name__).info(f"Fixed permissions for {log_file}: {current_perms} → 640")
                    _log_logging_change("fix_log_permissions", f"{log_file}: {current_perms} → 640", True)
            except Exception as e:
                logging.getLogger(__name__).error(f"Error fixing {log_file}: {e}")
                _log_logging_change("fix_log_permissions", f"{log_file} - {e}", False)
    print()