#!/usr/bin/env python3
"""
Shadow AppArmor Module
======================

Checks AppArmor status and configuration.

Security concerns:
- AppArmor disabled → weaker security
- Profiles not enforced
- Missing application profiles
"""

from shadow.core import ui
import os
import re
import shutil
import logging
import subprocess
import json
import fcntl
from pathlib import Path
from datetime import datetime
from typing import Tuple, Dict, List, Optional, Any

# ============================================================
# MODULE METADATA
# ============================================================
SEVERITY = "HIGH"
RECOMMENDATION = "Enable AppArmor and enforce security profiles for application confinement"

BACKUP_DIR = Path("/var/backups/shadow/")
CHANGES_LOG = Path("/var/log/shadow/changes.log")
APPARMOR_CONFIG = "/etc/apparmor/"

# ============================================================
# TRANSACTION SUPPORT
# ============================================================
_transaction_active = False
_transaction_backups = []

def begin_transaction():
    """Begin a transaction for AppArmor modifications."""
    global _transaction_active, _transaction_backups
    _transaction_active = True
    _transaction_backups = []
    logging.getLogger(__name__).info("AppArmor transaction started")

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
    logging.getLogger(__name__).info("AppArmor transaction committed")
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
def _log_apparmor_change(action: str, details: str, success: bool):
    """Log AppArmor modifications with structured format."""
    logger = logging.getLogger(__name__)
    status = "SUCCESS" if success else "FAILED"
    
    log_entry = {
        "event": "apparmor_change",
        "action": action,
        "details": details,
        "status": status,
        "timestamp": datetime.now().isoformat()
    }
    logger.info(f"APPARMOR: {json.dumps(log_entry)}")
    
    try:
        CHANGES_LOG.parent.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(CHANGES_LOG, 'a') as f:
            f.write(f"{timestamp} - AppArmor: {action} - {details} ({status})\n")
    except Exception as e:
        logger.debug(f"Failed to log change: {e}")


def _log_apparmor_findings(details: Dict, issues: List[str]):
    """Log AppArmor check findings for audit trail."""
    try:
        CHANGES_LOG.parent.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        with open(CHANGES_LOG, 'a') as f:
            f.write(f"{timestamp} - AppArmor Check Results:\n")
            f.write(f"  AppArmor Enabled: {details.get('apparmor_enabled', False)}\n")
            f.write(f"  Loaded Profiles: {details.get('loaded_profiles', 0)}\n")
            f.write(f"  Enforced Profiles: {details.get('enforced_profiles', 0)}\n")
            f.write(f"  Unconfined Processes: {details.get('unconfined_profiles', 0)}\n")
            f.write(f"  Tools Installed: {details.get('apparmor_installed', False)}\n")
            f.write(f"  AppArmor in Kernel: {details.get('apparmor_in_kernel', False)}\n")
            
            for issue in issues:
                f.write(f"  ISSUE: {issue}\n")
    except Exception as e:
        logging.getLogger(__name__).warning(f"Failed to log AppArmor findings: {e}")


# ============================================================
# CHECK FUNCTION
# ============================================================
def check(config: dict) -> Tuple[str, str, dict]:
    """Check AppArmor status"""
    logger = logging.getLogger(__name__)
    logger.info("Checking AppArmor...")

    issues = []
    details = {
        'apparmor_enabled': False,
        'apparmor_status': None,
        'loaded_profiles': 0,
        'enforced_profiles': 0,
        'complain_profiles': 0,
        'unconfined_profiles': 0,
        'apparmor_installed': False,
        'apparmor_in_kernel': False,
        'unconfined_profiles_list': [],
        'apparmor_error': None
    }

    # Check if AppArmor tools are installed
    status = _get_apparmor_status()
    details.update(status)

    if not status.get('apparmor_installed', False):
        issues.append("AppArmor tools are not installed")
        return 'WARN', "AppArmor tools not installed", details

    # Check if AppArmor is enabled in kernel
    if not status.get('apparmor_in_kernel', False):
        issues.append("AppArmor not enabled in kernel")

    if not status.get('apparmor_enabled', False):
        issues.append("AppArmor is not enabled")
    elif status.get('loaded_profiles', 0) == 0:
        issues.append("AppArmor is enabled but no profiles loaded")

    # Get list of unconfined profiles
    unconfined_profiles = _get_unconfined_profiles()
    if unconfined_profiles:
        details['unconfined_profiles_list'] = unconfined_profiles
        if len(unconfined_profiles) > 0:
            issues.append(f"{len(unconfined_profiles)} unconfined processes found")
            for profile in unconfined_profiles[:5]:
                issues.append(f"  - Unconfined: {profile}")

    # Check if profiles exist
    if status.get('apparmor_enabled', False) and status.get('loaded_profiles', 0) == 0:
        issues.append("No AppArmor profiles loaded")

    # Error handling for aa-status failure
    if status.get('apparmor_error'):
        issues.append(f"AppArmor status error: {status.get('apparmor_error')}")

    # FIX 12: Check AppArmor service status
    service_status = _check_apparmor_service()
    if service_status != 'active':
        issues.append(f"AppArmor service is {service_status}")

    # Log findings
    _log_apparmor_findings(details, issues)

    if issues:
        return 'WARN', f"{len(issues)} AppArmor issues found", details
    return 'PASS', "AppArmor is properly configured", details


def _get_apparmor_status() -> Dict:
    """Get AppArmor status"""
    status = {
        'apparmor_enabled': False,
        'apparmor_status': None,
        'loaded_profiles': 0,
        'enforced_profiles': 0,
        'complain_profiles': 0,
        'unconfined_profiles': 0,
        'apparmor_installed': False,
        'apparmor_in_kernel': False,
        'apparmor_error': None
    }

    # Check if AppArmor tools are installed
    try:
        result = subprocess.run(['which', 'aa-status'], capture_output=True, text=True, timeout=5, stdin=subprocess.DEVNULL)
        if result.returncode == 0:
            status['apparmor_installed'] = True
        else:
            return status
    except:
        return status

    # Check if AppArmor is enabled in kernel
    try:
        result = subprocess.run(['cat', '/proc/cmdline'], capture_output=True, text=True, timeout=5, stdin=subprocess.DEVNULL)
        if 'apparmor=0' not in result.stdout and 'apparmor=off' not in result.stdout:
            status['apparmor_in_kernel'] = True
    except:
        pass

    # Error handling for aa-status
    try:
        result = subprocess.run(['aa-status'], capture_output=True, text=True, timeout=30, stdin=subprocess.DEVNULL)

        if result.returncode == 0:
            status['apparmor_enabled'] = True
            status['apparmor_status'] = result.stdout

            logging.getLogger(__name__).info("AppArmor is enabled")

            for line in result.stdout.split('\n'):
                if 'profiles are loaded' in line:
                    match = re.search(r'(\d+)', line)
                    if match:
                        status['loaded_profiles'] = int(match.group(1))
                elif 'profiles are in enforce mode' in line:
                    match = re.search(r'(\d+)', line)
                    if match:
                        status['enforced_profiles'] = int(match.group(1))
                elif 'profiles are in complain mode' in line:
                    match = re.search(r'(\d+)', line)
                    if match:
                        status['complain_profiles'] = int(match.group(1))
                elif 'processes are unconfined' in line:
                    match = re.search(r'(\d+)', line)
                    if match:
                        status['unconfined_profiles'] = int(match.group(1))

            logging.getLogger(__name__).info(
                f"AppArmor: {status['loaded_profiles']} profiles loaded, "
                f"{status['enforced_profiles']} enforced, "
                f"{status['unconfined_profiles']} unconfined processes"
            )

        else:
            status['apparmor_error'] = f"aa-status returned {result.returncode}"

    except subprocess.TimeoutExpired:
        status['apparmor_error'] = "Timeout"
        logging.getLogger(__name__).error("aa-status timeout")
    except Exception as e:
        status['apparmor_error'] = str(e)
        logging.getLogger(__name__).error(f"aa-status error: {e}")

    return status


def _get_unconfined_profiles() -> List[str]:
    """Get list of unconfined profiles"""
    unconfined = []

    try:
        result = subprocess.run(['aa-status'], capture_output=True, text=True, timeout=30, stdin=subprocess.DEVNULL)

        if result.returncode == 0:
            capture = False
            for line in result.stdout.split('\n'):
                if 'processes are unconfined' in line:
                    capture = True
                    continue
                if capture and line.strip():
                    parts = line.split()
                    if len(parts) >= 3:
                        pid = parts[0]
                        user = parts[1]
                        process = ' '.join(parts[2:])
                        unconfined.append(f"{process} (PID: {pid}, User: {user})")
    except:
        pass

    return unconfined


def _check_apparmor_service() -> str:
    """Check AppArmor service status."""
    try:
        result = subprocess.run(
            ['systemctl', 'is-active', 'apparmor'],
            capture_output=True,
            text=True,
            timeout=10, stdin=subprocess.DEVNULL)
        return result.stdout.strip()
    except:
        return 'unknown'


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


def _backup_apparmor_config() -> Dict[str, Any]:
    """Backup AppArmor configuration directory."""
    result = {
        'path': str(APPARMOR_CONFIG),
        'backup_path': None,
        'success': False
    }
    
    try:
        BACKUP_DIR.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        
        if os.path.exists(APPARMOR_CONFIG):
            backup_path = BACKUP_DIR / f"apparmor.backup_{timestamp}"
            shutil.copytree(APPARMOR_CONFIG, backup_path, dirs_exist_ok=True)
            result['backup_path'] = str(backup_path)
            
            if backup_path.exists():
                result['success'] = True
                logging.getLogger(__name__).info(f"AppArmor config backup created: {backup_path}")
                # FIX: Add to transaction
                add_to_transaction(backup_path, Path(APPARMOR_CONFIG))

    except Exception as e:
        logging.getLogger(__name__).error(f"Failed to backup AppArmor config: {e}")
    
    return result


def _rollback_apparmor(backup_metadata: Dict[str, Any]) -> bool:
    """Rollback AppArmor configuration from backup."""
    if not backup_metadata.get('success'):
        logging.getLogger(__name__).error("Cannot rollback: invalid backup metadata")
        return False
    
    backup_path = Path(backup_metadata['backup_path'])
    original_path = Path(backup_metadata['path'])
    
    if not backup_path.exists():
        logging.getLogger(__name__).error(f"Backup not found: {backup_path}")
        return False
    
    try:
        if original_path.exists():
            shutil.rmtree(original_path)
        shutil.copytree(backup_path, original_path)
        
        logging.getLogger(__name__).info(f"Rolled back AppArmor config: {original_path}")
        return True
    except Exception as e:
        logging.getLogger(__name__).error(f"Rollback failed: {e}")
        return False


def _validate_apparmor_before_enable() -> Tuple[bool, str]:
    """Validate that AppArmor can be enabled safely."""
    logger = logging.getLogger(__name__)
    
    try:
        result = subprocess.run(['which', 'aa-status'], capture_output=True, text=True, timeout=5, stdin=subprocess.DEVNULL)
        if result.returncode != 0:
            return False, "AppArmor tools not installed"
    except:
        return False, "AppArmor tools not available"
    
    if not os.path.exists('/etc/apparmor.d/'):
        return False, "AppArmor profiles directory not found"
    
    try:
        result = subprocess.run(['cat', '/proc/cmdline'], capture_output=True, text=True, timeout=5, stdin=subprocess.DEVNULL)
        if 'apparmor=0' in result.stdout or 'apparmor=off' in result.stdout:
            return False, "AppArmor disabled in kernel command line"
    except:
        pass
    
    try:
        result = subprocess.run(['systemctl', 'is-active', 'apparmor'], capture_output=True, text=True, timeout=10, stdin=subprocess.DEVNULL)
        if result.stdout.strip() == 'active':
            return True, "AppArmor already active"
    except:
        pass
    
    if not os.path.exists('/sys/module/apparmor'):
        return True, "AppArmor module not loaded. Reboot may be required."
    
    return True, "Can enable AppArmor"


def _verify_apparmor_active() -> Tuple[bool, str]:
    """Verify AppArmor is active after enabling."""
    try:
        result = subprocess.run(['systemctl', 'is-active', 'apparmor'], capture_output=True, text=True, timeout=10, stdin=subprocess.DEVNULL)
        if result.stdout.strip() == 'active':
            return True, "AppArmor is active"
        
        result = subprocess.run(['aa-status'], capture_output=True, text=True, timeout=10, stdin=subprocess.DEVNULL)
        if result.returncode == 0 and 'profiles are loaded' in result.stdout:
            return True, "AppArmor profiles loaded"
        
        return False, f"AppArmor is {result.stdout.strip()}"
        
    except Exception as e:
        return False, f"Verification error: {e}"


def _verify_profile_enforcement() -> Tuple[bool, str]:
    """Verify AppArmor profiles are being enforced."""
    try:
        result = subprocess.run(['aa-status'], capture_output=True, text=True, timeout=30, stdin=subprocess.DEVNULL)
        
        if result.returncode != 0:
            return False, "Cannot check enforcement status"
        
        for line in result.stdout.split('\n'):
            if 'profiles are in enforce mode' in line:
                match = re.search(r'(\d+)', line)
                if match and int(match.group(1)) > 0:
                    return True, f"{match.group(1)} profiles enforced"
        
        return False, "No profiles in enforce mode"
    except Exception as e:
        return False, f"Verification error: {e}"


def _dry_run_apparmor_fix(action: str, details: str) -> bool:
    """Simulate AppArmor modification without actually changing anything."""
    logging.getLogger(__name__).info(f"[DRY-RUN] Would perform: {action} - {details}")
    print(f"[DRY-RUN] Would perform: {action}")
    return True


def _confirm_apparmor_enable() -> bool:
    """Ask for confirmation before enabling AppArmor."""
    print(f"\n[!] WARNING: About to enable AppArmor")
    print("    AppArmor can break applications without proper profiles")
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


def _safe_enable_apparmor(dry_run: bool = False) -> bool:
    """Safely enable AppArmor with backup, validation, dry-run, and rollback."""
    logger = logging.getLogger(__name__)
    
    if dry_run:
        _dry_run_apparmor_fix("enable_apparmor", "Would enable AppArmor")
        return True
    
    if not _confirm_apparmor_enable():
        logger.info("AppArmor enable cancelled by user")
        return False
    
    is_valid, validation_message = _validate_apparmor_before_enable()
    if not is_valid:
        logger.error(f"AppArmor validation failed: {validation_message}")
        return False
    
    backup_metadata = _backup_apparmor_config()
    if not backup_metadata['success']:
        logger.warning("Could not backup AppArmor config")
    
    try:
        result = subprocess.run(['systemctl', 'enable', 'apparmor'], capture_output=True, text=True, timeout=30, stdin=subprocess.DEVNULL)
        if result.returncode != 0:
            logger.error(f"systemctl enable failed: {result.stderr}")
            if backup_metadata['success']:
                _rollback_apparmor(backup_metadata)
            _log_apparmor_change("enable_apparmor", "systemctl enable failed", False)
            return False
        
        result = subprocess.run(['systemctl', 'start', 'apparmor'], capture_output=True, text=True, timeout=30, stdin=subprocess.DEVNULL)
        if result.returncode != 0:
            logger.error(f"systemctl start failed: {result.stderr}")
            if backup_metadata['success']:
                _rollback_apparmor(backup_metadata)
            _log_apparmor_change("enable_apparmor", "systemctl start failed", False)
            return False
        
        is_active, verify_msg = _verify_apparmor_active()
        if not is_active:
            logger.error(f"Verification failed: {verify_msg}")
            if backup_metadata['success']:
                _rollback_apparmor(backup_metadata)
            _log_apparmor_change("enable_apparmor", f"Verification failed: {verify_msg}", False)
            return False
        
        is_enforced, enforcement_msg = _verify_profile_enforcement()
        if not is_enforced:
            logger.warning(f"Profile enforcement issue: {enforcement_msg}")
        else:
            logger.info(f"Profile enforcement verified: {enforcement_msg}")
        
        _log_apparmor_change("enable_apparmor", f"Success: {verify_msg}", True)
        logger.info(f"AppArmor enabled successfully: {verify_msg}")
        
        if not os.path.exists('/sys/module/apparmor'):
            logger.warning("AppArmor module not loaded. Reboot may be required.")
        
        return True
        
    except Exception as e:
        logger.error(f"Failed to enable AppArmor: {e}")
        if backup_metadata['success']:
            _rollback_apparmor(backup_metadata)
        _log_apparmor_change("enable_apparmor", str(e), False)
        return False


def fix(config: dict, dry_run: bool = False, force: bool = False) -> bool:
    """
    Fix AppArmor issues

    Args:
        config: Configuration dictionary
        dry_run: If True, preview changes without applying
        force: If True, skip confirmation

    Returns:
        bool: True if fixes applied successfully
    """
    logger = logging.getLogger(__name__)
    logger.info("Fixing AppArmor issues...")

    # Check for dry-run mode
    if dry_run:
        logger.info("DRY-RUN MODE: No changes will be applied")
        print("\n[!] DRY-RUN MODE - No changes will be applied")
        
        status = _get_apparmor_status()
        print(f"  AppArmor installed: {status.get('apparmor_installed', False)}")
        print(f"  AppArmor enabled: {status.get('apparmor_enabled', False)}")
        print(f"  Loaded profiles: {status.get('loaded_profiles', 0)}")
        print(f"  Unconfined processes: {status.get('unconfined_profiles', 0)}")
        
        if config.get('access_control', {}).get('apparmor_enabled', True):
            print("  Would enable AppArmor")
        else:
            print("  AppArmor disabled in config")
        
        print("\n[✓] Dry-run complete. No changes were made.")
        return True

    # FIX: Skip confirmation in force mode
    if not force:
        if not _confirm_apparmor_enable():
            logger.info("AppArmor enable cancelled by user")
            return False
    else:
        logger.info("Force mode: Enabling AppArmor without confirmation")

    try:
        begin_transaction()
        
        status = _get_apparmor_status()
        if not status.get('apparmor_installed', False):
            logger.warning("AppArmor tools not installed, cannot fix")
            rollback_transaction()
            return False

        if not os.path.exists('/etc/apparmor.d/'):
            logger.warning("AppArmor profiles directory not found, cannot fix")
            rollback_transaction()
            return False

        if not status.get('apparmor_in_kernel', False):
            logger.warning("AppArmor not enabled in kernel. May need kernel parameter.")
            rollback_transaction()
            return False

        if config.get('access_control', {}).get('apparmor_enabled', True):
            success = _safe_enable_apparmor(dry_run)
            if success:
                commit_transaction()
                logger.info("AppArmor enabled successfully")
                print("\n AppArmor enabled successfully")
                return True
            else:
                rollback_transaction()
                logger.error("Failed to enable AppArmor")
                print("\nX Failed to enable AppArmor")
                return False
        else:
            logger.info("AppArmor disabled in config")
            commit_transaction()
            return True

    except Exception as e:
        logger.error(f"Failed to fix AppArmor: {e}")
        rollback_transaction()
        return False