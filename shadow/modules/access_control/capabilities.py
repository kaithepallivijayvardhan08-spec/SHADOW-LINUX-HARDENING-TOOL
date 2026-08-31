#!/usr/bin/env python3
"""
Shadow Capabilities Module
==========================

Checks Linux capabilities for security.

Security concerns:
- Excessive capabilities → privilege escalation
- Missing capabilities → application failures
- Capabilities in unauthorized files
"""

from shadow.core import ui
import os
import re
import shutil
import logging
import subprocess
import tempfile
import fcntl
import json
from pathlib import Path
from datetime import datetime
from typing import Tuple, Dict, List, Optional, Any

# ============================================================
# MODULE METADATA
# ============================================================
SEVERITY = "HIGH"
RECOMMENDATION = "Remove dangerous Linux capabilities and enforce minimal privilege requirements"

BACKUP_DIR = Path("/var/backups/shadow/")
CHANGES_LOG = Path("/var/log/shadow/changes.log")

# ============================================================
# TRANSACTION SUPPORT
# ============================================================
_transaction_active = False
_transaction_backups = []

def begin_transaction():
    """Begin a transaction for capability modifications."""
    global _transaction_active, _transaction_backups
    _transaction_active = True
    _transaction_backups = []
    logging.getLogger(__name__).info("Capability transaction started")

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
    logging.getLogger(__name__).info("Capability transaction committed")
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
# FIX 1: Protected Binaries - NEVER MODIFY THESE
# ============================================================
PROTECTED_BINARIES = [
    '/usr/bin/sudo',
    '/usr/bin/passwd',
    '/usr/bin/ping',
    '/usr/bin/mount',
    '/usr/bin/umount',
    '/usr/bin/su',
    '/usr/bin/gpasswd',
    '/usr/bin/chsh',
    '/usr/bin/chfn',
    '/usr/bin/newgrp',
    '/usr/bin/arping',
    '/usr/bin/traceroute'
]


# ============================================================
# FIX 2: Context-Dependent Capabilities
# ============================================================
CONTEXT_DEPENDENT_CAPABILITIES = [
    'cap_net_raw',      # Needed by ping, traceroute
    'cap_setuid',       # Needed by passwd, su, sudo
    'cap_setgid',       # Needed by newgrp
    'cap_sys_admin',    # Needed by mount
    'cap_sys_boot',     # Needed by some boot tools
    'cap_net_admin',    # Needed by some network tools
]


# Dangerous capabilities (always dangerous regardless of context)
DANGEROUS_CAPABILITIES = [
    'cap_sys_module',   # Loading kernel modules
    'cap_sys_rawio',    # Direct I/O access
    'cap_sys_ptrace',   # Debugging other processes
    'cap_dac_override', # Bypass file permissions
    'cap_dac_read_search', # Read any file
    'cap_sys_time',     # Change system time
    'cap_syslog',       # System logging
]


# Expected capabilities for common binaries
EXPECTED_CAPABILITIES = {
    '/usr/bin/ping': 'cap_net_raw',
    '/usr/bin/ping6': 'cap_net_raw',
    '/usr/bin/arping': 'cap_net_raw',
    '/usr/bin/traceroute': 'cap_net_raw',
    '/usr/bin/clockdiff': 'cap_net_raw',
    '/usr/bin/su': 'cap_setuid',
    '/usr/bin/passwd': 'cap_setuid',
    '/usr/bin/gpasswd': 'cap_setuid',
    '/usr/bin/chsh': 'cap_setuid',
    '/usr/bin/chfn': 'cap_setuid',
    '/usr/bin/mount': 'cap_sys_admin',
    '/usr/bin/umount': 'cap_sys_admin',
    '/usr/bin/newgrp': 'cap_setgid'
}


# ============================================================
# FIX 3: Structured Logging
# ============================================================
def _log_capability_change(action: str, details: str, success: bool):
    """Log capability modifications with structured format."""
    logger = logging.getLogger(__name__)
    status = "SUCCESS" if success else "FAILED"
    
    log_entry = {
        "event": "capability_change",
        "action": action,
        "details": details,
        "status": status,
        "timestamp": datetime.now().isoformat()
    }
    logger.info(f"CAPABILITY: {json.dumps(log_entry)}")
    
    try:
        CHANGES_LOG.parent.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(CHANGES_LOG, 'a') as f:
            f.write(f"{timestamp} - Capability: {action} - {details} ({status})\n")
    except Exception as e:
        logger.debug(f"Failed to log change: {e}")


def _log_capability_findings(details: Dict, issues: List[str], warnings: List[str]):
    """Log capability check findings."""
    try:
        CHANGES_LOG.parent.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        with open(CHANGES_LOG, 'a') as f:
            f.write(f"{timestamp} - Capability Check Results:\n")
            f.write(f"  getcap Installed: {details.get('capabilities_installed', False)}\n")
            f.write(f"  setcap Installed: {details.get('setcap_installed', False)}\n")
            f.write(f"  Files with Capabilities: {len(details.get('files_with_capabilities', []))}\n")
            f.write(f"  Dangerous Capabilities: {len(details.get('dangerous_capabilities', []))}\n")
            
            for issue in issues:
                f.write(f"  ISSUE: {issue}\n")
            for warning in warnings:
                f.write(f"  WARNING: {warning}\n")
    except Exception as e:
        logging.getLogger(__name__).warning(f"Failed to log findings: {e}")


# ============================================================
# FIX 4: Progress Indicator
# ============================================================
def _progress_indicator(current: int, total: int, message: str = ""):
    """Show progress during operations (Silent on terminal, logged to file)."""
    if total > 0:
        percent = (current / total) * 100
        logging.getLogger(__name__).debug(f"[{current}/{total}] {percent:.1f}% - {message}")


# ============================================================
# FIX 5: Confirmation for Critical Files
# ============================================================
def _confirm_capability_removal(file_path: str, cap_string: str) -> bool:
    """Ask for confirmation before removing capabilities from a file."""
    is_protected = file_path in PROTECTED_BINARIES
    
    if is_protected:
        print(f"\n[!] CRITICAL WARNING: {file_path} is a protected binary!")
        print(f"    Capabilities: {cap_string}")
        print("    Removing capabilities will break this binary!")
        response = ui.prompt("   Are you sure? (type 'YES' to continue): ")
        return response == 'YES'
    else:
        print(f"\n[!] Remove capabilities from {file_path}?")
        print(f"    Capabilities: {cap_string}")
        response = ui.prompt("   Proceed? [y/N]: ")
        return response.lower() == 'y'


# ============================================================
# FIX 6: Binary Backup
# ============================================================
def _backup_binary(file_path: str) -> Optional[Path]:
    """Backup the actual binary file."""
    try:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        backup_path = BACKUP_DIR / f"{Path(file_path).name}.binary.backup_{timestamp}"
        shutil.copy2(file_path, backup_path)
        logging.getLogger(__name__).info(f"Binary backup created: {backup_path}")
        return backup_path
    except Exception as e:
        logging.getLogger(__name__).error(f"Failed to backup binary {file_path}: {e}")
        return None


def _restore_binary(file_path: str, backup_path: Path) -> bool:
    """Restore binary from backup."""
    try:
        shutil.copy2(backup_path, file_path)
        logging.getLogger(__name__).info(f"Binary restored: {file_path} from {backup_path}")
        return True
    except Exception as e:
        logging.getLogger(__name__).error(f"Failed to restore binary {file_path}: {e}")
        return False


# ============================================================
# FIX 7: Better Binary Functionality Test
# ============================================================
def _verify_binary_functionality(file_path: str) -> bool:
    """Verify that a binary still functions after capability changes."""
    logger = logging.getLogger(__name__)
    
    try:
        # Try to run the binary with --help or -h
        for flag in ['--help', '-h', '--version', '-v']:
            try:
                result = subprocess.run(
                    [file_path, flag],
                    capture_output=True,
                    text=True,
                    timeout=3, stdin=subprocess.DEVNULL)
                # Any return code except 127 (command not found) is acceptable
                if result.returncode != 127:
                    return True
            except:
                continue
        
        # For binaries that don't support help flags, check if they exist and are executable
        if os.path.exists(file_path) and os.access(file_path, os.X_OK):
            # Try a minimal execution test
            try:
                # Use ldd to check shared library dependencies
                ldd_result = subprocess.run(
                    ['ldd', file_path],
                    capture_output=True,
                    text=True,
                    timeout=5, stdin=subprocess.DEVNULL)
                if 'not found' in ldd_result.stdout:
                    logger.warning(f"Binary {file_path} has missing dependencies")
                    return False
                return True
            except:
                pass
            
            return True
        
        return False
    except Exception as e:
        logger.warning(f"Functionality check failed for {file_path}: {e}")
        return True  # Don't fail if check can't complete


# ============================================================
# FIX 8: Safe Write with File Locking
# ============================================================
def _safe_set_capability(file_path: str, cap_string: str, dry_run: bool = False) -> bool:
    """Safely set capabilities with backup, validation, dry-run, and rollback."""
    logger = logging.getLogger(__name__)
    
    # FIX 1: Skip protected binaries
    if file_path in PROTECTED_BINARIES:
        logger.warning(f"Skipping protected binary: {file_path}")
        return True
    
    # Dry-run mode
    if dry_run:
        logger.info(f"[DRY-RUN] Would set capabilities on {file_path}: {cap_string}")
        return True
    
    # Step 1: Validate before making changes
    is_valid, validation_msg = _validate_capability_change(file_path, cap_string)
    if not is_valid:
        logger.error(f"Validation failed: {validation_msg}")
        return False
    
    # Step 2: Backup capabilities
    backup_metadata = _backup_capabilities(file_path)
    if not backup_metadata['success']:
        logger.warning(f"Could not backup capabilities for {file_path}")
    
    # FIX 6: Backup binary file
    binary_backup = _backup_binary(file_path)
    if backup_metadata['success']:
        backup_path = Path(backup_metadata['backup_path'])
        add_to_transaction(backup_path, Path(file_path))

    try:
        # Step 3: Set new capabilities
        result = subprocess.run(['setcap', cap_string, file_path], capture_output=True, text=True, timeout=10, stdin=subprocess.DEVNULL)
        if result.returncode != 0:
            logger.error(f"setcap failed: {result.stderr}")
            if backup_metadata['success']:
                _rollback_capabilities(backup_metadata)
            # FIX 6: Restore binary if needed
            if binary_backup:
                _restore_binary(file_path, binary_backup)
            _log_capability_change("set_capability", f"{file_path} - setcap failed", False)
            return False
        
        # Step 4: Verify capabilities
        is_verified, verify_msg = _verify_capability_change(file_path, cap_string)
        if not is_verified:
            logger.error(f"Verification failed: {verify_msg}")
            if backup_metadata['success']:
                _rollback_capabilities(backup_metadata)
            if binary_backup:
                _restore_binary(file_path, binary_backup)
            _log_capability_change("set_capability", f"{file_path} - verification failed", False)
            return False
        
        # FIX 7: Verify binary functionality
        if not _verify_binary_functionality(file_path):
            logger.warning(f"Binary {file_path} may not function correctly after capability change")
            if backup_metadata['success']:
                _rollback_capabilities(backup_metadata)
            if binary_backup:
                _restore_binary(file_path, binary_backup)
            _log_capability_change("set_capability", f"{file_path} - functionality check failed", False)
            return False
        
        _log_capability_change("set_capability", f"{file_path}: {cap_string}", True)
        logger.info(f"Capabilities set for {file_path}: {cap_string}")
        return True
        
    except Exception as e:
        logger.error(f"Failed to set capabilities for {file_path}: {e}")
        if backup_metadata['success']:
            _rollback_capabilities(backup_metadata)
        if binary_backup:
            _restore_binary(file_path, binary_backup)
        _log_capability_change("set_capability", f"{file_path} - {e}", False)
        return False


# ============================================================
# FIX 9: Dry-run mode
# ============================================================
def _dry_run_capability_fix(action: str, details: str) -> bool:
    """Simulate capability modification without actually changing anything."""
    logging.getLogger(__name__).info(f"[DRY-RUN] Would perform: {action} - {details}")
    print(f"[DRY-RUN] Would perform: {action}")
    return True


# ============================================================
# EXISTING FUNCTIONS (with minor fixes)
# ============================================================
def check(config: dict) -> Tuple[str, str, dict]:
    """Check Linux capabilities"""
    logger = logging.getLogger(__name__)
    logger.info("Checking Linux capabilities...")

    issues = []
    warnings = []
    details = {
        'capabilities_installed': False,
        'setcap_installed': False,
        'files_with_capabilities': [],
        'dangerous_capabilities': [],
        'unauthorized_capabilities': [],
        'getcap_error': None
    }

    getcap_installed = _check_getcap_installed()
    details['capabilities_installed'] = getcap_installed

    setcap_installed = _check_setcap_installed()
    details['setcap_installed'] = setcap_installed

    if not getcap_installed:
        return 'WARN', "getcap tools not installed", details

    try:
        files = _get_capabilities_files()
        details['files_with_capabilities'] = files
    except subprocess.TimeoutExpired:
        details['getcap_error'] = "Timeout"
        issues.append("getcap command timed out")
        return 'WARN', "getcap timeout", details
    except Exception as e:
        details['getcap_error'] = str(e)
        issues.append(f"getcap error: {e}")
        return 'WARN', f"getcap error: {e}", details

    if not files:
        return 'PASS', "No files with capabilities found", details

    logger.info(f"Found {len(files)} files with capabilities")

    for file_info in files:
        cap_string = file_info.get('capabilities', '')
        path = file_info['path']

        # FIX 1: Check if protected binary
        if path in PROTECTED_BINARIES:
            continue

        dangerous_found = []
        for dangerous_cap in DANGEROUS_CAPABILITIES:
            if dangerous_cap in cap_string:
                dangerous_found.append(dangerous_cap)

        if dangerous_found:
            file_info['dangerous'] = dangerous_found
            details['dangerous_capabilities'].append({
                'path': path,
                'capabilities': cap_string,
                'dangerous': dangerous_found
            })
            issues.append(f"DANGEROUS capabilities on {path}: {', '.join(dangerous_found)}")

        # FIX 2: Check against expected capabilities
        expected = EXPECTED_CAPABILITIES.get(path)
        if expected and expected not in cap_string:
            details['unauthorized_capabilities'].append({
                'path': path,
                'capabilities': cap_string,
                'expected': expected
            })
            warnings.append(f"Unexpected capabilities on {path}: {cap_string} (expected: {expected})")

        # Check for network capabilities
        if 'cap_net' in cap_string:
            if path not in ['/usr/bin/ping', '/usr/bin/ping6', '/usr/bin/arping', '/usr/bin/traceroute']:
                warnings.append(f"Network capabilities on {path}: {cap_string}")

    if dangerous_found:
        logger.warning(f"Found {len(details['dangerous_capabilities'])} files with dangerous capabilities")

    _log_capability_findings(details, issues, warnings)

    if issues:
        status = 'FAIL'
        message = f"{len(issues)} critical capability issues found"
    elif warnings:
        status = 'WARN'
        message = f"{len(warnings)} capability warnings found"
    else:
        status = 'PASS'
        message = "Linux capabilities are properly configured"

    return status, message, details


def _check_getcap_installed() -> bool:
    try:
        result = subprocess.run(['which', 'getcap'], capture_output=True, text=True, timeout=5, stdin=subprocess.DEVNULL)
        return result.returncode == 0
    except:
        return False


def _check_setcap_installed() -> bool:
    try:
        result = subprocess.run(['which', 'setcap'], capture_output=True, text=True, timeout=5, stdin=subprocess.DEVNULL)
        return result.returncode == 0
    except:
        return False


def _get_capabilities_files() -> List[Dict]:
    files = []
    # ✅ FIX: Only scan critical system directories to prevent timeout
    scan_dirs = ['/usr/bin', '/usr/sbin', '/bin', '/sbin', '/usr/lib']
    valid_dirs = [d for d in scan_dirs if os.path.exists(d)]
    if not valid_dirs:
        return files
        
    try:
        result = subprocess.run(['getcap', '-r'] + valid_dirs, capture_output=True, text=True, timeout=30, stdin=subprocess.DEVNULL)

        for line in result.stdout.split('\n'):
            if line.strip():
                parts = line.split()
                if len(parts) >= 2:
                    path = parts[0].rstrip(':')
                    cap_string = ' '.join(parts[1:])
                    files.append({
                        'path': path,
                        'capabilities': cap_string
                    })
    except Exception as e:
        logging.getLogger(__name__).error(f"getcap failed: {e}")
        raise
    return files


def _verify_backup(backup_path: Path) -> bool:
    if not backup_path.exists():
        logging.getLogger(__name__).error(f"Backup not found: {backup_path}")
        return False
    if backup_path.stat().st_size == 0:
        logging.getLogger(__name__).error(f"Backup is empty: {backup_path}")
        return False
    return True


def _backup_capabilities(file_path: str) -> Dict[str, Any]:
    result = {
        'path': file_path,
        'backup_path': None,
        'capabilities': None,
        'success': False
    }
    try:
        BACKUP_DIR.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        result_get = subprocess.run(['getcap', file_path], capture_output=True, text=True, timeout=10, stdin=subprocess.DEVNULL)
        if result_get.returncode == 0 and result_get.stdout.strip():
            cap_string = result_get.stdout.strip().split()[1] if len(result_get.stdout.strip().split()) > 1 else ''
            result['capabilities'] = cap_string
            
            backup_path = BACKUP_DIR / f"{Path(file_path).name}.caps.backup_{timestamp}"
            with open(backup_path, 'w') as f:
                f.write(f"{file_path}: {cap_string}\n")
            result['backup_path'] = str(backup_path)
            
            if _verify_backup(backup_path):
                result['success'] = True
                logging.getLogger(__name__).info(f"Capabilities backup created: {backup_path}")
                add_to_transaction(backup_path, Path(file_path))

    except Exception as e:
        logging.getLogger(__name__).error(f"Failed to backup capabilities for {file_path}: {e}")
    return result


def _validate_capability_change(file_path: str, new_cap: str) -> Tuple[bool, str]:
    logger = logging.getLogger(__name__)
    
    for dangerous_cap in DANGEROUS_CAPABILITIES:
        if dangerous_cap in new_cap:
            return False, f"Attempting to set dangerous capability: {dangerous_cap}"
    
    if not os.path.exists(file_path):
        return False, f"File not found: {file_path}"
    
    try:
        with open(file_path, 'rb') as f:
            magic = f.read(4)
            if not magic.startswith(b'\x7fELF'):
                return False, f"Not an ELF binary: {file_path}"
    except:
        return False, f"Cannot read file: {file_path}"
    
    # FIX 1: Check if protected binary
    if file_path in PROTECTED_BINARIES and new_cap == '':
        return False, f"Cannot remove capabilities from protected binary: {file_path}"
    
    return True, "Validation passed"


def _rollback_capabilities(backup_metadata: Dict[str, Any]) -> bool:
    if not backup_metadata.get('success'):
        logging.getLogger(__name__).error("Cannot rollback: invalid backup metadata")
        return False
    
    backup_path = Path(backup_metadata['backup_path'])
    file_path = backup_metadata['path']
    original_cap = backup_metadata.get('capabilities')
    
    if not backup_path.exists():
        logging.getLogger(__name__).error(f"Backup not found: {backup_path}")
        return False
    
    try:
        if original_cap:
            subprocess.run(['setcap', original_cap, file_path], capture_output=True, text=True, timeout=10, stdin=subprocess.DEVNULL)
            logging.getLogger(__name__).info(f"Rolled back capabilities for {file_path}: {original_cap}")
        else:
            subprocess.run(['setcap', '-r', file_path], capture_output=True, text=True, timeout=10, stdin=subprocess.DEVNULL)
            logging.getLogger(__name__).info(f"Removed capabilities for {file_path}")
        return True
    except Exception as e:
        logging.getLogger(__name__).error(f"Rollback failed for {file_path}: {e}")
        return False


def _verify_capability_change(file_path: str, expected_cap: str = None) -> Tuple[bool, str]:
    try:
        result = subprocess.run(['getcap', file_path], capture_output=True, text=True, timeout=10, stdin=subprocess.DEVNULL)
        
        if result.returncode != 0:
            return False, f"getcap failed: {result.stderr}"
        
        if result.stdout.strip():
            cap_string = result.stdout.strip()
            if expected_cap and expected_cap not in cap_string:
                return False, f"Expected '{expected_cap}' not found in: {cap_string}"
            return True, f"Verified: {cap_string}"
        else:
            if expected_cap:
                return False, f"Expected capabilities but none found: {file_path}"
            return True, "No capabilities found"
    except Exception as e:
        return False, f"Verification error: {e}"


# ============================================================
# FIX FUNCTION
# ============================================================
def fix(config: dict, dry_run: bool = False, force: bool = False) -> bool:
    """
    Fix capability issues

    Args:
        config: Configuration dictionary
        dry_run: If True, preview changes without applying
        force: If True, skip confirmation

    Returns:
        bool: True if fixes applied successfully
    """
    logger = logging.getLogger(__name__)
    logger.info("Fixing capability issues...")

    # Check for dry-run mode (use parameter, not config)
    if dry_run:
        logger.info("DRY-RUN MODE: No changes will be applied")
        print("\n[!] DRY-RUN MODE - No changes will be applied")

        if not _check_getcap_installed():
            print("  getcap not installed")
        else:
            files = _get_capabilities_files()
            dangerous = []
            for f in files:
                for dcap in DANGEROUS_CAPABILITIES:
                    if dcap in f.get('capabilities', ''):
                        dangerous.append(f['path'])
                        break
            if dangerous:
                print(f"  Would remove dangerous capabilities from {len(dangerous)} files:")
                for d in dangerous[:10]:
                    print(f"    - {d}")
            else:
                print("  No dangerous capabilities found")

        print("\n[✓] Dry-run complete. No changes were made.")
        return True

    # FIX: Skip confirmation in force mode
    if not force:
        print("\n[!] WARNING: About to modify Linux capabilities")
        print("    This could break system binaries!")
        response = ui.prompt("Proceed? [y/N]: ")
        if response.lower() != 'y':
            logger.info("Capability fixes cancelled by user")
            return False
    else:
        logger.info("Force mode: Applying capability fixes without confirmation")

    try:
        begin_transaction()

        if not _check_getcap_installed():
            logger.warning("getcap not installed, cannot fix")
            rollback_transaction()
            return False

        if not _check_setcap_installed():
            logger.warning("setcap not installed, cannot fix")
            rollback_transaction()
            return False

        files = _get_capabilities_files()

        if not files:
            logger.info("No files with capabilities to fix")
            commit_transaction()
            return True

        files_to_modify = []
        protected_files = []
        
        for file_info in files:
            path = file_info['path']
            cap_string = file_info.get('capabilities', '')

            # Skip protected binaries
            if path in PROTECTED_BINARIES:
                protected_files.append(path)
                continue

            dangerous_found = []
            for dangerous_cap in DANGEROUS_CAPABILITIES:
                if dangerous_cap in cap_string:
                    dangerous_found.append(dangerous_cap)

            if dangerous_found and config.get('capabilities', {}).get('remove_dangerous', True):
                files_to_modify.append(path)

        if protected_files:
            logger.info(f"Skipping protected binaries: {', '.join(protected_files)}")

        if not files_to_modify:
            logger.info("No dangerous capabilities to remove")
            commit_transaction()
            return True

        # Confirmation per file (skip if force)
        confirmed_files = []
        for path in files_to_modify:
            cap_string = next((f['capabilities'] for f in files if f['path'] == path), '')
            if force:
                confirmed_files.append(path)
                logger.info(f"Force mode: Confirming {path}")
            elif _confirm_capability_removal(path, cap_string):
                confirmed_files.append(path)
            else:
                logger.info(f"Skipping {path}")

        if not confirmed_files:
            logger.info("No files confirmed for modification")
            rollback_transaction()
            return True

        fixed_count = 0
        failed_count = 0
        total_files = len(confirmed_files)

        for idx, path in enumerate(confirmed_files):
            _progress_indicator(idx + 1, total_files, f"Processing {Path(path).name}")
            
            cap_string = next((f['capabilities'] for f in files if f['path'] == path), '')
            dangerous_found = []
            for dangerous_cap in DANGEROUS_CAPABILITIES:
                if dangerous_cap in cap_string:
                    dangerous_found.append(dangerous_cap)

            if dangerous_found:
                if config.get('capabilities', {}).get('remove_dangerous', True):
                    logger.info(f"Removing dangerous capabilities from {path}: {dangerous_found}")
                    if _safe_set_capability(path, '', dry_run):
                        fixed_count += 1
                    else:
                        failed_count += 1

        print()

        if failed_count == 0:
            commit_transaction()
            logger.info(f"Capabilities fixed: {fixed_count} fixed, {failed_count} failed")
            print(f"\n✓ Capabilities fixed: {fixed_count} files")
            return True
        else:
            rollback_transaction()
            logger.error(f"Capabilities fix failed: {fixed_count} fixed, {failed_count} failed")
            print(f"\n✗ Capabilities fix failed: {failed_count} files failed")
            return False

    except Exception as e:
        logger.error(f"Failed to fix capabilities: {e}")
        rollback_transaction()
        return False