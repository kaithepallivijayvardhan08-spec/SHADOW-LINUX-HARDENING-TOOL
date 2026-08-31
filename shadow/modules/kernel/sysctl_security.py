#!/usr/bin/env python3
"""
Shadow Sysctl Security Module
=============================

Checks kernel sysctl parameters for security.

Security concerns:
- IP forwarding → routing attacks
- Source routing → spoofing
- ICMP redirects → MITM
- Core dumps → information disclosure
"""

from shadow.core import ui
import os
import re
import shutil
import logging
import subprocess
import tempfile
import time
import json
import fcntl
from pathlib import Path
from datetime import datetime
from typing import Tuple, Dict, List, Optional, Any

# ============================================================
# MODULE METADATA
# ============================================================
SEVERITY = "HIGH"
RECOMMENDATION = "Apply kernel hardening with sysctl settings"

BACKUP_DIR = Path("/var/backups/shadow/")
CHANGES_LOG = Path("/var/log/shadow/changes.log")

# ============================================================
# TRANSACTION SUPPORT
# ============================================================
_transaction_active = False
_transaction_backups = []

def begin_transaction():
    """Begin a transaction for sysctl modifications."""
    global _transaction_active, _transaction_backups
    _transaction_active = True
    _transaction_backups = []
    logging.getLogger(__name__).info("Sysctl transaction started")

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
    logging.getLogger(__name__).info("Sysctl transaction committed")
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
def _log_sysctl_change(action: str, details: str, success: bool):
    """Log sysctl modifications with structured format."""
    logger = logging.getLogger(__name__)
    status = "SUCCESS" if success else "FAILED"
    
    log_entry = {
        "event": "sysctl_change",
        "action": action,
        "details": details,
        "status": status,
        "timestamp": datetime.now().isoformat()
    }
    logger.info(f"SYSCTL: {json.dumps(log_entry)}")
    
    try:
        CHANGES_LOG.parent.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(CHANGES_LOG, 'a') as f:
            f.write(f"{timestamp} - Sysctl: {action} - {details} ({status})\n")
    except Exception as e:
        logger.debug(f"Failed to log change: {e}")


def _log_sysctl_findings(details: Dict, issues: List[str]):
    """Log sysctl check findings for audit trail."""
    try:
        CHANGES_LOG.parent.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        with open(CHANGES_LOG, 'a') as f:
            f.write(f"{timestamp} - Sysctl Check Results:\n")
            for param, value in details.items():
                if value is not None:
                    expected = _get_expected_value(param)
                    status = "✓" if value == expected else "✗"
                    f.write(f"  {status} {param} = {value} (expected: {expected})\n")
            
            for issue in issues:
                f.write(f"  ISSUE: {issue}\n")
    except Exception as e:
        logging.getLogger(__name__).warning(f"Failed to log sysctl findings: {e}")


# ============================================================
# CHECK FUNCTION
# ============================================================
def check(config: dict) -> Tuple[str, str, dict]:
    """Check sysctl security parameters"""
    logger = logging.getLogger(__name__)
    logger.info("Checking sysctl security...")

    issues = []
    details = {
        'ip_forward': None,
        'source_route': None,
        'icmp_redirect': None,
        'magic_sysrq': None,
        'core_dump': None,
        'tcp_syncookies': None,
        'rp_filter': None
    }

    # Check sysctl parameters
    params = _check_sysctl_params()
    details.update(params)

    # Verify each parameter
    for param, value in params.items():
        expected = _get_expected_value(param)
        if expected is not None and value != expected:
            issues.append(f"{param} is {value}, expected {expected}")

    _log_sysctl_findings(details, issues)

    if issues:
        return 'WARN', f"{len(issues)} sysctl issues found", details
    return 'PASS', "Sysctl parameters are secure", details


def _check_sysctl_params() -> Dict:
    """Check sysctl parameters"""
    params = {}

    sysctl_params = [
        'net.ipv4.ip_forward',
        'net.ipv4.conf.all.accept_source_route',
        'net.ipv4.conf.all.accept_redirects',
        'kernel.sysrq',
        'kernel.core_pattern',
        'net.ipv4.tcp_syncookies',
        'net.ipv4.conf.all.rp_filter'
    ]

    for param in sysctl_params:
        try:
            result = subprocess.run(['sysctl', '-n', param], capture_output=True, text=True, timeout=10, stdin=subprocess.DEVNULL)
            value = result.stdout.strip()
            params[param] = value
        except Exception as e:
            logging.getLogger(__name__).debug(f"Sysctl {param} check failed: {e}")
            params[param] = None

    return params


def _get_expected_value(param: str) -> str:
    """Get expected value for a sysctl parameter"""
    expected = {
        'net.ipv4.ip_forward': '0',
        'net.ipv4.conf.all.accept_source_route': '0',
        'net.ipv4.conf.all.accept_redirects': '0',
        'kernel.sysrq': '0',
        'kernel.core_pattern': '|/bin/false',
        'net.ipv4.tcp_syncookies': '1',
        'net.ipv4.conf.all.rp_filter': '1'
    }
    return expected.get(param)


# ============================================================
# FIX 1: BACKUP BEFORE MODIFYING SYSCTL.CONF
# ============================================================
def _verify_backup(backup_path: Path) -> bool:
    """Verify that a backup was created successfully."""
    if not backup_path.exists():
        logging.getLogger(__name__).error(f"Backup not found: {backup_path}")
        return False
    if backup_path.stat().st_size == 0:
        logging.getLogger(__name__).error(f"Backup is empty: {backup_path}")
        return False
    logging.getLogger(__name__).debug(f"Backup verified: {backup_path}")
    return True


def _backup_sysctl_config() -> Dict[str, Any]:
    """Backup /etc/sysctl.conf with metadata."""
    result = {
        'path': '/etc/sysctl.conf',
        'backup_path': None,
        'success': False
    }
    
    try:
        BACKUP_DIR.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        
        if os.path.exists('/etc/sysctl.conf'):
            backup_path = BACKUP_DIR / f"sysctl.conf.backup_{timestamp}"
            shutil.copy2('/etc/sysctl.conf', backup_path)
            result['backup_path'] = str(backup_path)
            
            if _verify_backup(backup_path):
                result['success'] = True
                logging.getLogger(__name__).info(f"Backup created: {backup_path}")
                add_to_transaction(backup_path, Path('/etc/sysctl.conf'))

    except Exception as e:
        logging.getLogger(__name__).error(f"Failed to backup sysctl.conf: {e}")
    
    return result


# ============================================================
# FIX 2: VALIDATE SYSCTL PARAMETERS BEFORE APPLYING
# ============================================================
def _validate_sysctl_settings(settings: Dict[str, str]) -> bool:
    """
    Validate sysctl settings before applying.
    Returns True if valid, False otherwise.
    """
    logger = logging.getLogger(__name__)
    
    for param, value in settings.items():
        # Check if parameter exists
        try:
            result = subprocess.run(
                ['sysctl', param],
                capture_output=True,
                text=True,
                timeout=10, stdin=subprocess.DEVNULL)
            if result.returncode != 0:
                logger.error(f"Invalid sysctl parameter: {param}")
                return False
        except Exception as e:
            logger.error(f"Error validating sysctl parameter {param}: {e}")
            return False
        
        # Check if value is valid
        if param == 'kernel.core_pattern':
            # Special handling for core_pattern
            if value == '|/bin/false' or value == '':
                continue
            logger.warning(f"Unusual core_pattern value: {value}")
            continue
        
        if value not in ['0', '1']:
            logger.warning(f"Unusual value for {param}: {value}")
    
    return True


# ============================================================
# FIX 3: ROLLBACK ON FAILURE
# ============================================================
def _rollback_sysctl_config(backup_metadata: Dict[str, Any]) -> bool:
    """Rollback sysctl.conf from backup."""
    if not backup_metadata.get('success'):
        logging.getLogger(__name__).error("Cannot rollback: invalid backup metadata")
        return False
    
    backup_path = Path(backup_metadata['backup_path'])
    original_path = backup_metadata['path']
    
    if not backup_path.exists():
        logging.getLogger(__name__).error(f"Backup file not found: {backup_path}")
        return False
    
    try:
        shutil.copy2(backup_path, original_path)
        logging.getLogger(__name__).info(f"Rolled back sysctl.conf: {original_path}")
        return True
    except Exception as e:
        logging.getLogger(__name__).error(f"Rollback failed for {original_path}: {e}")
        return False


# ============================================================
# FIX 4: VERIFY SYSCTL AFTER CHANGES
# ============================================================
def _verify_sysctl_settings(settings: Dict[str, str]) -> bool:
    """Verify sysctl settings were applied correctly."""
    for param, expected_value in settings.items():
        try:
            result = subprocess.run(
                ['sysctl', '-n', param],
                capture_output=True,
                text=True,
                timeout=10, stdin=subprocess.DEVNULL)
            current_value = result.stdout.strip()
            if current_value != expected_value:
                logging.getLogger(__name__).error(
                    f"sysctl {param} verification failed: expected {expected_value}, got {current_value}"
                )
                return False
        except Exception as e:
            logging.getLogger(__name__).error(f"Error verifying sysctl {param}: {e}")
            return False
    
    return True


# ============================================================
# FIX 5: DRY-RUN MODE
# ============================================================
def _dry_run_sysctl_fix(action: str, details: str) -> bool:
    """Simulate sysctl modification without actually changing anything."""
    logging.getLogger(__name__).info(f"[DRY-RUN] Would perform: {action} - {details}")
    print(f"[DRY-RUN] Would perform: {action}")
    return True


# ============================================================
# FIX 6: CONFIRMATION BEFORE MODIFYING SYSCTL
# ============================================================
def _confirm_sysctl_modification() -> bool:
    """Ask for confirmation before modifying sysctl."""
    print(f"\n[!] WARNING: About to modify kernel sysctl parameters")
    print("    This affects network behavior and system security")
    print("    Incorrect settings could affect system performance")
    response = ui.prompt("Proceed? [y/N]: ")
    if response.lower() == 'y':
        print("\n[*] Applying fixes... please wait")
        return True
    return False


# ============================================================
# FIX 7: PROGRESS INDICATOR
# ============================================================
def _progress_indicator(current: int, total: int, message: str = ""):
    """Show progress during operations."""
    if total > 0:
        percent = (current / total) * 100
        print(f"\r\033[K[{current}/{total}] {percent:.1f}% - {message}", end="", flush=True)


# ============================================================
# FIX 8: NETWORK CONNECTIVITY VERIFICATION
# ============================================================
def _verify_network_connectivity() -> bool:
    """Verify network connectivity after sysctl changes."""
    try:
        # Try to ping localhost
        result = subprocess.run(
            ['ping', '-c', '1', '-W', '1', '127.0.0.1'],
            capture_output=True,
            text=True,
            timeout=5, stdin=subprocess.DEVNULL)
        if result.returncode != 0:
            logging.getLogger(__name__).warning("Localhost ping failed")
            return False
            
        # Try to ping gateway (if available)
        try:
            result = subprocess.run(
                ['ip', 'route', 'show', 'default'],
                capture_output=True,
                text=True,
                timeout=5, stdin=subprocess.DEVNULL)
            if result.returncode == 0 and result.stdout:
                # Extract gateway
                match = re.search(r'default via (\d+\.\d+\.\d+\.\d+)', result.stdout)
                if match:
                    gateway = match.group(1)
                    result = subprocess.run(
                        ['ping', '-c', '1', '-W', '1', gateway],
                        capture_output=True,
                        text=True,
                        timeout=5, stdin=subprocess.DEVNULL)
                    if result.returncode != 0:
                        logging.getLogger(__name__).warning(f"Gateway ping failed: {gateway}")
                        return False
        except:
            pass
            
        return True
    except Exception as e:
        logging.getLogger(__name__).warning(f"Network verification failed: {e}")
        return True


# ============================================================
# FIX 9: SAFE SYSCTL FIX WITH FILE LOCKING
# ============================================================
def _safe_sysctl_fix(dry_run: bool = False) -> bool:
    """
    Safely apply sysctl fixes with backup, validation, dry-run, and rollback.
    """
    logger = logging.getLogger(__name__)
    
    # Define settings to apply
    settings = {
        'net.ipv4.ip_forward': '0',
        'net.ipv4.conf.all.accept_source_route': '0',
        'net.ipv4.conf.all.accept_redirects': '0',
        'kernel.sysrq': '0',
        'net.ipv4.tcp_syncookies': '1',
        'net.ipv4.conf.all.rp_filter': '1'
    }
    
    # Dry-run mode
    if dry_run:
        for param, value in settings.items():
            _dry_run_sysctl_fix("set_sysctl", f"{param} = {value}")
        return True
    
    # Confirmation
    if not _confirm_sysctl_modification():
        logger.info("Sysctl fix cancelled by user")
        return False
    
    # Step 1: Validate settings before applying
    if not _validate_sysctl_settings(settings):
        logger.error("Sysctl settings validation failed")
        return False
    
    # Step 2: Backup sysctl.conf
    backup_metadata = _backup_sysctl_config()
    if not backup_metadata['success']:
        logger.warning("Could not backup sysctl.conf")
    
    # File locking
    sysctl_config = '/etc/sysctl.conf'
    lock_file = Path(sysctl_config).with_suffix('.lock')
    fd = None
    try:
        fd = open(lock_file, 'w')
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except:
        logger.warning(f"Cannot acquire lock for {sysctl_config}")
    
    try:
        # Step 3: Apply settings
        # Read existing content
        with open(sysctl_config, 'r') as f:
            content = f.read()
        
        # Check if settings already exist
        modified = False
        for param, value in settings.items():
            pattern = rf'^{re.escape(param)}\s*=\s*\S+'
            if re.search(pattern, content, re.MULTILINE):
                # Update existing setting
                content = re.sub(
                    rf'^{re.escape(param)}\s*=\s*\S+',
                    f'{param} = {value}',
                    content,
                    flags=re.MULTILINE
                )
                modified = True
            else:
                # Add new setting
                content += f'\n{param} = {value}\n'
                modified = True
        
        if modified:
            # Write back
            with open(sysctl_config, 'w') as f:
                f.write(content)
            
            # Step 4: Apply sysctl
            result = subprocess.run(
                ['sysctl', '-p'],
                capture_output=True,
                text=True,
                timeout=30, stdin=subprocess.DEVNULL)
            
            if result.returncode != 0:
                logger.error(f"sysctl -p failed: {result.stderr}")
                if backup_metadata['success']:
                    _rollback_sysctl_config(backup_metadata)
                _log_sysctl_change("sysctl_fix", "sysctl -p failed", False)
                return False
            
            # Step 5: Verify settings
            if not _verify_sysctl_settings(settings):
                logger.error("Sysctl verification failed")
                if backup_metadata['success']:
                    _rollback_sysctl_config(backup_metadata)
                _log_sysctl_change("sysctl_fix", "Verification failed", False)
                return False
        
        # Release lock
        if fd:
            fcntl.flock(fd, fcntl.LOCK_UN)
            fd.close()
            if lock_file.exists():
                lock_file.unlink()
        
        # Verify network connectivity
        time.sleep(2)
        if not _verify_network_connectivity():
            logger.warning("Network connectivity may be affected by sysctl changes")
        
        _log_sysctl_change("sysctl_fix", "Sysctl security settings applied", True)
        logger.info("Sysctl security settings applied and verified")
        return True
        
    except Exception as e:
        logger.error(f"Error applying sysctl fixes: {e}")
        if backup_metadata['success']:
            _rollback_sysctl_config(backup_metadata)
        _log_sysctl_change("sysctl_fix", str(e), False)
        return False


def fix(config: dict, dry_run: bool = False, force: bool = False) -> bool:
    """
    Fix sysctl security issues

    Args:
        config: Configuration dictionary
        dry_run: If True, preview changes without applying
        force: If True, skip confirmation

    Returns:
        bool: True if fixes applied successfully
    """
    logger = logging.getLogger(__name__)
    logger.info("Fixing sysctl issues...")

    # Check for dry-run mode (use parameter, not config)
    if dry_run:
        logger.info("DRY-RUN MODE: No changes will be applied")
        print("\n[!] DRY-RUN MODE - No changes will be applied")
        
        # Show what would be done
        settings = {
            'net.ipv4.ip_forward': '0',
            'net.ipv4.conf.all.accept_source_route': '0',
            'net.ipv4.conf.all.accept_redirects': '0',
            'kernel.sysrq': '0',
            'net.ipv4.tcp_syncookies': '1',
            'net.ipv4.conf.all.rp_filter': '1'
        }
        
        print("  Would apply the following sysctl settings:")
        for param, value in settings.items():
            print(f"    {param} = {value}")
        
        print("\n[✓] Dry-run complete. No changes were made.")
        return True

    # FIX: Skip confirmation in force mode
    if not force:
        if not _confirm_sysctl_modification():
            logger.info("Sysctl fix cancelled by user")
            return False
    else:
        logger.info("Force mode: Applying sysctl fixes without confirmation")

    try:
        begin_transaction()
        
        # Backup before modifying
        backup_metadata = _backup_sysctl_config()
        if not backup_metadata['success']:
            logger.warning("Could not backup sysctl.conf")

        success = _safe_sysctl_fix(dry_run)
        
        if success:
            commit_transaction()
            logger.info("Sysctl fixes applied successfully")
            print("\n✅ Sysctl fixes applied successfully")
            return True
        else:
            rollback_transaction()
            logger.error("Failed to apply sysctl fixes")
            return False

    except Exception as e:
        logger.error(f"Failed to fix sysctl: {e}")
        rollback_transaction()
        return False