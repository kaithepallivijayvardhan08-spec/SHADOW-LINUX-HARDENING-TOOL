#!/usr/bin/env python3
"""
Shadow SELinux Module
=====================

Checks SELinux status and configuration.

Security concerns:
- SELinux disabled → weaker security
- SELinux in permissive mode → less effective
- SELinux policies not enforced
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


BACKUP_DIR = Path("/var/backups/shadow/")
CHANGES_LOG = Path("/var/log/shadow/changes.log")
SELINUX_CONFIG = "/etc/selinux/config"

# ============================================================
# TRANSACTION SUPPORT
# ============================================================
_transaction_active = False
_transaction_backups = []

def begin_transaction():
    """Begin a transaction for SELinux modifications."""
    global _transaction_active, _transaction_backups
    _transaction_active = True
    _transaction_backups = []
    logging.getLogger(__name__).info("SELinux transaction started")

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
    logging.getLogger(__name__).info("SELinux transaction committed")
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
# FIX 8: PROTECTED PATHS FOR SELINUX
# ============================================================
PROTECTED_PATHS = [
    '/etc/passwd', '/etc/shadow', '/etc/sudoers',
    '/etc/ssh/sshd_config', '/etc/fstab'
]


# ============================================================
# FIX 8: STRUCTURED LOGGING
# ============================================================
def _log_selinux_change(action: str, details: str, success: bool):
    """Log SELinux modifications with structured format."""
    logger = logging.getLogger(__name__)
    status = "SUCCESS" if success else "FAILED"
    
    log_entry = {
        "event": "selinux_change",
        "action": action,
        "details": details,
        "status": status,
        "timestamp": datetime.now().isoformat()
    }
    logger.info(f"SELINUX: {json.dumps(log_entry)}")
    
    try:
        CHANGES_LOG.parent.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(CHANGES_LOG, 'a') as f:
            f.write(f"{timestamp} - SELinux: {action} - {details} ({status})\n")
    except Exception as e:
        logger.debug(f"Failed to log change: {e}")


def _log_selinux_findings(details: Dict, issues: List[str]):
    """Log SELinux check findings for audit trail."""
    try:
        CHANGES_LOG.parent.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        with open(CHANGES_LOG, 'a') as f:
            f.write(f"{timestamp} - SELinux Check Results:\n")
            f.write(f"  SELinux Enabled: {details.get('selinux_enabled', False)}\n")
            f.write(f"  SELinux Mode: {details.get('selinux_mode', 'unknown')}\n")
            f.write(f"  SELinux Policy: {details.get('selinux_policy', 'unknown')}\n")
            f.write(f"  Tools Installed: {details.get('selinux_tools_installed', False)}\n")
            f.write(f"  Config Exists: {details.get('selinux_config_exists', False)}\n")
            f.write(f"  SELinux in Kernel: {details.get('selinux_in_kernel', False)}\n")
            f.write(f"  Policy Loaded: {details.get('selinux_policy_loaded', False)}\n")
            f.write(f"  Audit Denials: {details.get('selinux_audit_denials', 0)}\n")
            
            for issue in issues:
                f.write(f"  ISSUE: {issue}\n")
    except Exception as e:
        logging.getLogger(__name__).warning(f"Failed to log SELinux findings: {e}")


# ============================================================
# CHECK FUNCTION
# ============================================================
def check(config: dict) -> Tuple[str, str, dict]:
    """Check SELinux status"""
    logger = logging.getLogger(__name__)
    logger.info("Checking SELinux...")

    issues = []
    details = {
        'selinux_enabled': False,
        'selinux_mode': 'disabled',
        'selinux_policy': None,
        'selinux_status': None,
        'selinux_tools_installed': False,
        'selinux_config_exists': False,
        'selinux_in_kernel': False,
        'selinux_policy_loaded': False,
        'selinux_audit_denials': 0
    }

    # Check if config file exists
    if os.path.exists(SELINUX_CONFIG):
        details['selinux_config_exists'] = True
    else:
        issues.append(f"SELinux config file not found: {SELINUX_CONFIG}")

    # Check if SELinux tools are installed
    status = _get_selinux_status()
    details.update(status)

    if not status.get('selinux_tools_installed', False):
        issues.append("SELinux tools are not installed")
    elif not status.get('selinux_enabled', False):
        issues.append("SELinux is disabled")
    elif status.get('selinux_mode') == 'permissive':
        issues.append("SELinux is in permissive mode")

    # Error handling for getenforce failure
    if status.get('getenforce_error'):
        issues.append(f"SELinux getenforce error: {status.get('getenforce_error')}")

    # Check if SELinux is enabled in kernel
    if not status.get('selinux_in_kernel', False):
        issues.append("SELinux not enabled in kernel")

    # Check if SELinux policy is loaded
    if status.get('selinux_policy_loaded', False) is False and status.get('selinux_enabled', False):
        issues.append("SELinux policy is not loaded")

    # MEDIUM FIX 6: Check SELinux audit denials
    audit_denials = _check_selinux_audit_denials()
    details['selinux_audit_denials'] = audit_denials
    if audit_denials > 10:
        issues.append(f"High number of SELinux denials: {audit_denials}")

    # FIX 12: Check file contexts
    file_contexts_ok, context_msg = _check_selinux_file_contexts()
    if not file_contexts_ok:
        issues.append(f"SELinux file contexts issue: {context_msg}")

    # Log findings
    _log_selinux_findings(details, issues)

    if issues:
        return 'WARN', f"{len(issues)} SELinux issues found", details
    return 'PASS', "SELinux is enabled and enforcing", details


def _get_selinux_status() -> Dict:
    """Get SELinux status"""
    status = {
        'selinux_enabled': False,
        'selinux_mode': 'disabled',
        'selinux_policy': None,
        'selinux_tools_installed': False,
        'selinux_in_kernel': False,
        'selinux_policy_loaded': False,
        'getenforce_error': None
    }

    # Check if SELinux tools are installed
    try:
        result = subprocess.run(['which', 'getenforce'], capture_output=True, text=True, timeout=5, stdin=subprocess.DEVNULL)
        if result.returncode == 0:
            status['selinux_tools_installed'] = True
        else:
            return status
    except:
        return status

    # Error handling for getenforce
    try:
        result = subprocess.run(['getenforce'], capture_output=True, text=True, timeout=10, stdin=subprocess.DEVNULL)
        mode = result.stdout.strip()

        if mode:
            status['selinux_enabled'] = True
            status['selinux_mode'] = mode.lower()

        logging.getLogger(__name__).info(f"SELinux mode: {mode}")

    except subprocess.TimeoutExpired:
        status['getenforce_error'] = "Timeout"
        logging.getLogger(__name__).error("getenforce timeout")
    except subprocess.CalledProcessError as e:
        status['getenforce_error'] = str(e)
        logging.getLogger(__name__).error(f"getenforce failed: {e}")
    except Exception as e:
        status['getenforce_error'] = str(e)
        logging.getLogger(__name__).error(f"getenforce error: {e}")

    # Check if SELinux is enabled in kernel
    try:
        result = subprocess.run(['cat', '/proc/cmdline'], capture_output=True, text=True, timeout=5, stdin=subprocess.DEVNULL)
        if 'selinux=0' not in result.stdout and 'selinux=off' not in result.stdout:
            status['selinux_in_kernel'] = True
    except:
        pass

    # Check if SELinux policy is loaded
    try:
        result = subprocess.run(['selinuxenabled'], capture_output=True, text=True, timeout=5, stdin=subprocess.DEVNULL)
        if result.returncode == 0:
            status['selinux_policy_loaded'] = True
    except:
        pass

    # Get SELinux policy type from config
    if os.path.exists(SELINUX_CONFIG):
        try:
            with open(SELINUX_CONFIG, 'r') as f:
                content = f.read()
                match = re.search(r'SELINUXTYPE=(\w+)', content)
                if match:
                    status['selinux_policy'] = match.group(1)
        except Exception as e:
            logging.getLogger(__name__).debug(f"Error reading SELinux config: {e}")

    return status


def _check_selinux_audit_denials() -> int:
    """Check SELinux audit denials from audit logs."""
    count = 0
    
    try:
        result = subprocess.run(
            ['ausearch', '-m', 'avc', '--start', 'today'],
            capture_output=True,
            text=True,
            timeout=30, stdin=subprocess.DEVNULL)
        if result.returncode == 0:
            count = len(result.stdout.split('time->'))
    except:
        pass
    
    return count


def _check_selinux_file_contexts() -> Tuple[bool, str]:
    """Check if SELinux file contexts are set correctly."""
    try:
        critical_paths = ['/etc', '/bin', '/usr/bin', '/var']
        for path in critical_paths:
            if os.path.exists(path):
                result = subprocess.run(
                    ['ls', '-Z', path],
                    capture_output=True,
                    text=True,
                    timeout=10, stdin=subprocess.DEVNULL)
                if result.returncode != 0:
                    return False, f"Cannot check file contexts for {path}"
        
        return True, "File contexts accessible"
    except Exception as e:
        return False, f"File context check failed: {e}"


def _verify_selinux_policies() -> Tuple[bool, str]:
    """Verify SELinux policies are loaded correctly."""
    try:
        result = subprocess.run(
            ['semanage', 'login', '-l'],
            capture_output=True,
            text=True,
            timeout=10, stdin=subprocess.DEVNULL)
        if result.returncode == 0:
            return True, "Policies loaded"
    except:
        pass
    
    return False, "Cannot verify policies"


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


def _backup_selinux_config() -> Dict[str, Any]:
    """Backup SELinux config file with metadata."""
    result = {
        'path': SELINUX_CONFIG,
        'backup_path': None,
        'success': False,
        'original_mode': None
    }
    
    try:
        BACKUP_DIR.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        
        if os.path.exists(SELINUX_CONFIG):
            backup_path = BACKUP_DIR / f"selinux_config.backup_{timestamp}"
            shutil.copy2(SELINUX_CONFIG, backup_path)
            result['backup_path'] = str(backup_path)
            
            current_mode = _get_current_selinux_mode()
            result['original_mode'] = current_mode
            
            if _verify_backup(backup_path):
                result['success'] = True
                logging.getLogger(__name__).info(f"SELinux config backup created: {backup_path}")
                add_to_transaction(backup_path, Path(SELINUX_CONFIG))
    except Exception as e:
        logging.getLogger(__name__).error(f"Failed to backup SELinux config: {e}")
    
    return result


def _get_current_selinux_mode() -> str:
    """Get current SELinux mode from config file"""
    try:
        with open(SELINUX_CONFIG, 'r') as f:
            content = f.read()
            match = re.search(r'SELINUX=(\w+)', content)
            if match:
                return match.group(1)
    except:
        pass
    return 'unknown'


def _rollback_selinux_config(backup_metadata: Dict[str, Any]) -> bool:
    """Rollback SELinux config from backup."""
    if not backup_metadata.get('success'):
        logging.getLogger(__name__).error("Cannot rollback: invalid backup metadata")
        return False
    
    backup_path = Path(backup_metadata['backup_path'])
    original_path = backup_metadata['path']
    
    if not backup_path.exists():
        logging.getLogger(__name__).error(f"Backup not found: {backup_path}")
        return False
    
    try:
        shutil.copy2(backup_path, original_path)
        logging.getLogger(__name__).info(f"Rolled back SELinux config: {original_path}")
        
        return True
    except Exception as e:
        logging.getLogger(__name__).error(f"Rollback failed for {original_path}: {e}")
        return False


def _validate_selinux_before_enforce() -> Tuple[bool, str]:
    """Validate that SELinux can be set to enforcing safely."""
    logger = logging.getLogger(__name__)
    
    try:
        result = subprocess.run(['which', 'getenforce'], capture_output=True, text=True, timeout=5, stdin=subprocess.DEVNULL)
        if result.returncode != 0:
            return False, "SELinux tools not installed"
    except:
        return False, "SELinux tools not available"
    
    try:
        result = subprocess.run(['cat', '/proc/cmdline'], capture_output=True, text=True, timeout=5, stdin=subprocess.DEVNULL)
        if 'selinux=0' in result.stdout or 'selinux=off' in result.stdout:
            return False, "SELinux disabled in kernel command line"
    except:
        pass
    
    if not os.path.exists(SELINUX_CONFIG):
        return False, "SELinux config file not found"
    
    try:
        result = subprocess.run(['getenforce'], capture_output=True, text=True, timeout=10, stdin=subprocess.DEVNULL)
        current_mode = result.stdout.strip()
        logger.info(f"Current SELinux mode: {current_mode}")
        
        if current_mode.lower() == 'enforcing':
            return True, "Already enforcing"
            
        return True, "Can set to enforcing"
        
    except Exception as e:
        return False, f"Validation error: {e}"


def _verify_selinux_enforcing(backup_mode: str = None) -> Tuple[bool, str]:
    """Verify SELinux is enforcing after changes."""
    try:
        result = subprocess.run(['getenforce'], capture_output=True, text=True, timeout=10, stdin=subprocess.DEVNULL)
        current_mode = result.stdout.strip()
        
        if current_mode.lower() == 'enforcing':
            return True, "SELinux is enforcing"
        
        if backup_mode and backup_mode != current_mode.lower():
            return False, f"SELinux mode unchanged ({current_mode}). Reboot may be required."
        
        return False, f"SELinux is {current_mode}, not enforcing"
        
    except Exception as e:
        return False, f"Verification error: {e}"


def _dry_run_selinux_fix(action: str, details: str) -> bool:
    """Simulate SELinux modification without actually changing anything."""
    logging.getLogger(__name__).info(f"[DRY-RUN] Would perform: {action} - {details}")
    print(f"[DRY-RUN] Would perform: {action}")
    return True


def _confirm_selinux_enable() -> bool:
    """Ask for confirmation before enabling SELinux."""
    print(f"\n[!] WARNING: About to enable SELinux enforcing mode")
    print("    SELinux can break applications and services if not configured correctly")
    print("    Make sure you have console access in case of issues")
    response = ui.prompt("Proceed? [y/N]: ")
    if response.lower() == 'y':
        print("\n[*] Applying fixes... please wait")
        return True
    return False


def _warn_application_compatibility() -> bool:
    """Warn about application compatibility issues with SELinux."""
    print("\n[!] SELinux enforcing mode can break applications that don't have proper policies.")
    print("    Common issues: Apache, MySQL, PostgreSQL, custom applications.")
    print("    You can check denials with: ausearch -m avc")
    response = ui.prompt("Continue? [y/N]: ")
    return response.lower() == 'y'


def _progress_indicator(current: int, total: int, message: str = ""):
    """Show progress during operations."""
    if total > 0:
        percent = (current / total) * 100
        print(f"\r\033[K[{current}/{total}] {percent:.1f}% - {message}", end="", flush=True)


def _safe_set_selinux_enforcing(dry_run: bool = False) -> bool:
    """Safely set SELinux to enforcing with backup, validation, dry-run, and rollback."""
    logger = logging.getLogger(__name__)
    
    if dry_run:
        _dry_run_selinux_fix("set_enforcing", "Would set SELinux to enforcing")
        return True
    
    if not _warn_application_compatibility():
        logger.info("SELinux enable cancelled by user")
        return False
    
    if not _confirm_selinux_enable():
        logger.info("SELinux enable cancelled by user")
        return False
    
    is_valid, validation_message = _validate_selinux_before_enforce()
    if not is_valid:
        logger.error(f"SELinux validation failed: {validation_message}")
        return False
    
    backup_metadata = _backup_selinux_config()
    if not backup_metadata['success']:
        logger.warning("Could not backup SELinux config")
    
    original_mode = backup_metadata.get('original_mode', 'unknown')
    
    file_contexts_ok, context_msg = _check_selinux_file_contexts()
    if not file_contexts_ok:
        logger.warning(f"SELinux file contexts issue: {context_msg}")
    
    policies_ok, policies_msg = _verify_selinux_policies()
    if not policies_ok:
        logger.warning(f"SELinux policies issue: {policies_msg}")
    
    try:
        result = subprocess.run(['setenforce', '1'], capture_output=True, text=True, timeout=10, stdin=subprocess.DEVNULL)
        if result.returncode != 0:
            logger.error(f"setenforce failed: {result.stderr}")
            if backup_metadata['success']:
                _rollback_selinux_config(backup_metadata)
            _log_selinux_change("set_enforcing", "setenforce failed", False)
            return False
        
        if os.path.exists(SELINUX_CONFIG):
            with open(SELINUX_CONFIG, 'r') as f:
                content = f.read()
            
            content = content.replace('SELINUX=disabled', 'SELINUX=enforcing')
            content = content.replace('SELINUX=permissive', 'SELINUX=enforcing')
            
            with open(SELINUX_CONFIG, 'w') as f:
                f.write(content)
        
        is_enforcing, verify_msg = _verify_selinux_enforcing(original_mode)
        if not is_enforcing:
            logger.error(f"Verification failed: {verify_msg}")
            if backup_metadata['success']:
                _rollback_selinux_config(backup_metadata)
            _log_selinux_change("set_enforcing", f"Verification failed: {verify_msg}", False)
            return False
        
        _log_selinux_change("set_enforcing", f"Success: {verify_msg}", True)
        logger.info(f"SELinux set to enforcing successfully: {verify_msg}")
        
        if original_mode in ['disabled', 'permissive']:
            logger.warning("SELinux mode changed. System may need reboot for full effect.")
        
        return True
        
    except Exception as e:
        logger.error(f"Failed to set SELinux enforcing: {e}")
        if backup_metadata['success']:
            _rollback_selinux_config(backup_metadata)
        _log_selinux_change("set_enforcing", str(e), False)
        return False


def fix(config: dict, dry_run: bool = False, force: bool = False) -> bool:
    """
    Fix SELinux issues

    Args:
        config: Configuration dictionary
        dry_run: If True, preview changes without applying
        force: If True, skip confirmation

    Returns:
        bool: True if fixes applied successfully
    """
    logger = logging.getLogger(__name__)
    logger.info("Fixing SELinux issues...")

    # Check for dry-run mode (use parameter, not config)
    if dry_run:
        logger.info("DRY-RUN MODE: No changes will be applied")
        print("\n[!] DRY-RUN MODE - No changes will be applied")
        
        status = _get_selinux_status()
        print(f"  Current SELinux mode: {status.get('selinux_mode', 'unknown')}")
        print(f"  SELinux tools installed: {status.get('selinux_tools_installed', False)}")
        print(f"  SELinux in kernel: {status.get('selinux_in_kernel', False)}")
        
        if config.get('access_control', {}).get('selinux_mode', 'enforcing') != 'disabled':
            print("  Would enable SELinux enforcing mode")
        else:
            print("  SELinux enforcement disabled in config")
        
        print("\n[✓] Dry-run complete. No changes were made.")
        return True

    # FIX: Skip confirmation in force mode
    if not force:
        if not _warn_application_compatibility():
            logger.info("SELinux enable cancelled by user")
            return False
        if not _confirm_selinux_enable():
            logger.info("SELinux enable cancelled by user")
            return False
    else:
        logger.info("Force mode: Enabling SELinux without confirmation")

    try:
        begin_transaction()
        
        status = _get_selinux_status()
        if not status.get('selinux_tools_installed', False):
            logger.warning("SELinux tools not installed, cannot fix")
            rollback_transaction()
            return False

        if not os.path.exists(SELINUX_CONFIG):
            logger.error("SELinux config file not found, cannot fix")
            rollback_transaction()
            return False

        if not status.get('selinux_in_kernel', False):
            logger.warning("SELinux not enabled in kernel. May need kernel parameter.")
            rollback_transaction()
            return False

        if config.get('access_control', {}).get('selinux_mode', 'enforcing') != 'disabled':
            success = _safe_set_selinux_enforcing(dry_run)
            if success:
                commit_transaction()
                logger.info("SELinux enforcing mode enabled successfully")
                print("\n✓ SELinux enforcing mode enabled")
                return True
            else:
                rollback_transaction()
                logger.error("Failed to enable SELinux enforcing mode")
                print("\n✗ Failed to enable SELinux enforcing mode")
                return False
        else:
            logger.info("SELinux enforcement disabled in config")
            commit_transaction()
            return True

    except Exception as e:
        logger.error(f"Failed to fix SELinux: {e}")
        rollback_transaction()
        return False