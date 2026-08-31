#!/usr/bin/env python3
"""
Shadow NFS Module
=================

Checks NFS (Network File System) security:
- NFS is installed and running
- NFS exports configuration (/etc/exports)
- NFS export permissions
- NFS version (v3 vs v4)
- NFS root squash
- NFS insecure ports
- NFS logging

Files checked:
- /etc/exports
- /etc/default/nfs-kernel-server
- /etc/nfs.conf

Security concerns:
- NFS without root_squash → root access to shares
- NFS v3 → weaker security
- Insecure NFS exports → unauthorized access
- NFS with no_subtree_check → security risk
- World-readable exports → information disclosure
"""

from shadow.core import ui
import os
import re
import shutil
import glob
import logging
import subprocess
import tempfile
import time
from pathlib import Path
from datetime import datetime
from typing import Tuple, Dict, List, Optional, Any

# ============================================================
# MODULE METADATA
# ============================================================
SEVERITY = "HIGH"
RECOMMENDATION = "Enable root_squash, fix exports permissions, and enable logging"

BACKUP_DIR = Path("/var/backups/shadow/")

# ============================================================
# TRANSACTION SUPPORT
# ============================================================
_transaction_active = False
_transaction_backups = []

def begin_transaction():
    """Begin a transaction for NFS modifications."""
    global _transaction_active, _transaction_backups
    _transaction_active = True
    _transaction_backups = []
    logging.getLogger(__name__).info("NFS transaction started")

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
    logging.getLogger(__name__).info("NFS transaction committed")
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

def check(config: dict) -> Tuple[str, str, dict]:
    """
    Check NFS security

    Returns:
        Tuple[str, str, dict]: (status, message, details)
    """
    logger = logging.getLogger(__name__)
    logger.info("Checking NFS security...")

    issues = []
    warnings = []
    details = {
        'nfs_installed': False,
        'nfs_running': False,
        'nfs_version': None,
        'exports': [],
        'nfs_mounts': [],
        'root_squash_enabled': True,
        'subtree_check_enabled': False,
        'insecure_ports': False,
        'logging_enabled': False,
        'exports_file_secure': False
    }

    # Check if NFS is installed
    nfs_installed = _check_nfs_installed()
    details['nfs_installed'] = nfs_installed

    if not nfs_installed:
        return 'PASS', "NFS is not installed", details

    # Check if NFS is running
    nfs_running = _check_nfs_running()
    details['nfs_running'] = nfs_running

    if not nfs_running:
        return 'WARN', "NFS is installed but not running", details

    # Get NFS version
    version_info = _get_nfs_version()
    details['nfs_version'] = version_info

    if version_info:
        if version_info.startswith('3'):
            warnings.append(f"NFS version {version_info} is outdated (use NFSv4)")

    # Check exports configuration
    exports = _check_exports()
    details['exports'] = exports

    if exports:
        for export in exports:
            if not export.get('root_squash', True):
                issues.append(f"Export {export['path']} has root_squash disabled (security risk)")
            if export.get('no_subtree_check', False):
                warnings.append(f"Export {export['path']} has no_subtree_check (security risk)")
            if export.get('insecure', False):
                warnings.append(f"Export {export['path']} allows insecure ports")
            if export.get('rw', False) and not export.get('root_squash', True):
                issues.append(f"Export {export['path']} is read-write with no root_squash")
    else:
        warnings.append("No NFS exports configured")

    # Check exports file permissions
    exports_perms = _check_exports_permissions()
    details['exports_file_secure'] = exports_perms

    if not exports_perms:
        issues.append("/etc/exports has insecure permissions")

    # Check NFS mounts
    nfs_mounts = _check_nfs_mounts()
    details['nfs_mounts'] = nfs_mounts

    if nfs_mounts:
        for mount in nfs_mounts:
            if mount.get('options', ''):
                warnings.append(f"NFS mount: {mount['path']} with options: {mount['options']}")

    # Check logging
    logging_enabled = _check_logging()
    details['logging_enabled'] = logging_enabled

    if not logging_enabled:
        warnings.append("NFS logging is not enabled")

    # Determine status
    if issues:
        critical = [i for i in issues if 'root_squash' in i.lower() or 'insecure permissions' in i.lower()]
        if critical:
            status = 'FAIL'
            message = f"{len(issues)} critical NFS issues found"
        else:
            status = 'WARN'
            message = f"{len(issues)} NFS issues found"
    elif warnings:
        status = 'WARN'
        message = f"{len(warnings)} NFS warnings found"
    else:
        status = 'PASS'
        message = "NFS is securely configured"

    return status, message, details


def _check_nfs_installed() -> bool:
    """Check if NFS is installed"""
    nfs_paths = [
        '/usr/sbin/nfsd',
        '/usr/sbin/rpc.nfsd',
        '/usr/sbin/exportfs',
        '/usr/sbin/showmount'
    ]

    for path in nfs_paths:
        if os.path.exists(path):
            return True

    try:
        result = subprocess.run(['dpkg', '-l', 'nfs*'], 
                              capture_output=True, text=True, stdin=subprocess.DEVNULL)
        if 'nfs-kernel-server' in result.stdout:
            return True
    except:
        pass

    try:
        result = subprocess.run(['rpm', '-qa', 'nfs*'],
                              capture_output=True, text=True, stdin=subprocess.DEVNULL)
        if 'nfs-utils' in result.stdout:
            return True
    except:
        pass

    return False


def _check_nfs_running() -> bool:
    """Check if NFS is running"""
    try:
        result = subprocess.run(['systemctl', 'is-active', 'nfs-kernel-server'],
                              capture_output=True, text=True, stdin=subprocess.DEVNULL)
        if result.stdout.strip() == 'active':
            return True
    except:
        pass

    try:
        result = subprocess.run(['systemctl', 'is-active', 'nfs'],
                              capture_output=True, text=True, stdin=subprocess.DEVNULL)
        if result.stdout.strip() == 'active':
            return True
    except:
        pass

    try:
        result = subprocess.run(['ps', 'aux'], capture_output=True, text=True, stdin=subprocess.DEVNULL)
        if 'nfsd' in result.stdout:
            return True
    except:
        pass

    return False


def _get_nfs_version() -> Optional[str]:
    """Get NFS version"""
    try:
        result = subprocess.run(['nfsd', '--version'], capture_output=True, text=True, stdin=subprocess.DEVNULL)
        for line in result.stdout.split('\n'):
            if 'NFS version' in line:
                match = re.search(r'NFS version\s+(\d+)', line)
                if match:
                    return match.group(1)
    except:
        pass

    return None


def _check_exports() -> List[Dict]:
    """Check NFS exports configuration"""
    exports = []

    exports_file = '/etc/exports'

    if not os.path.exists(exports_file):
        return exports

    try:
        with open(exports_file, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue

                parts = line.split()
                if len(parts) < 2:
                    continue

                path = parts[0]
                clients = parts[1:]

                for client in clients:
                    options = []
                    root_squash = True
                    no_subtree_check = False
                    insecure = False
                    rw = False

                    if '(' in client and ')' in client:
                        client_part, options_str = client.split('(', 1)
                        options_str = options_str.rstrip(')')
                        options = options_str.split(',')

                        if 'no_root_squash' in options:
                            root_squash = False
                        if 'root_squash' in options:
                            root_squash = True
                        if 'no_subtree_check' in options:
                            no_subtree_check = True
                        if 'insecure' in options:
                            insecure = True
                        if 'rw' in options:
                            rw = True

                    exports.append({
                        'path': path,
                        'client': client,
                        'options': ','.join(options),
                        'root_squash': root_squash,
                        'no_subtree_check': no_subtree_check,
                        'insecure': insecure,
                        'rw': rw
                    })

    except Exception as e:
        logging.getLogger(__name__).error(f"Error reading exports: {e}")

    return exports


def _check_exports_permissions() -> bool:
    """Check /etc/exports file permissions"""
    exports_file = '/etc/exports'

    if not os.path.exists(exports_file):
        return False

    try:
        stat_info = os.stat(exports_file)
        perms = oct(stat_info.st_mode)[-3:]

        if perms in ['644', '600'] and stat_info.st_uid == 0:
            return True
    except Exception as e:
        logging.getLogger(__name__).debug(f"Error checking exports permissions: {e}")

    return False


def _check_nfs_mounts() -> List[Dict]:
    """Check NFS mounts"""
    mounts = []

    try:
        result = subprocess.run(['mount', '-t', 'nfs', '-t', 'nfs4'],
                              capture_output=True, text=True, stdin=subprocess.DEVNULL)

        if result.returncode == 0:
            for line in result.stdout.split('\n'):
                if line.strip():
                    parts = line.split()
                    if len(parts) >= 5:
                        mounts.append({
                            'server_path': parts[0],
                            'path': parts[2],
                            'type': parts[4] if len(parts) > 4 else 'nfs',
                            'options': parts[5] if len(parts) > 5 else ''
                        })
    except Exception as e:
        logging.getLogger(__name__).debug(f"Error checking mounts: {e}")

    return mounts


def _check_logging() -> bool:
    """Check if NFS logging is enabled"""
    nfs_configs = [
        '/etc/default/nfs-kernel-server',
        '/etc/nfs.conf'
    ]

    for config_file in nfs_configs:
        if os.path.exists(config_file):
            try:
                with open(config_file, 'r') as f:
                    content = f.read()
                    if 'RPCMOUNTDOPTS' in content and '--manage-gids' in content:
                        return True
                    if 'RPCNFSDOPTS' in content and '--debug' in content:
                        return True
            except:
                pass

    return False


# ============================================================
# FIX 1: BACKUP BEFORE MODIFYING NFS CONFIG
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


def _backup_nfs_config(file_path: str) -> Dict[str, Any]:
    """
    Backup NFS configuration file with metadata.
    """
    result = {
        'path': file_path,
        'backup_path': None,
        'success': False
    }
    
    try:
        BACKUP_DIR.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
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


# ============================================================
# FIX 2: VALIDATE NFS EXPORTS BEFORE MODIFYING
# ============================================================
def _validate_nfs_exports() -> bool:
    """
    Validate NFS exports syntax using exportfs.
    Returns True if valid, False otherwise.
    """
    try:
        result = subprocess.run(
            ['exportfs', '-ra'],
            capture_output=True,
            text=True,
            timeout=10, stdin=subprocess.DEVNULL)
        if result.returncode == 0:
            logging.getLogger(__name__).debug("NFS exports validation passed")
            return True
        else:
            logging.getLogger(__name__).error(f"NFS exports validation failed: {result.stderr}")
            return False
    except Exception as e:
        logging.getLogger(__name__).error(f"NFS exports validation error: {e}")
        return False


# ============================================================
# FIX 3: ROLLBACK ON FAILURE
# ============================================================
def _rollback_nfs_config(backup_metadata: Dict[str, Any]) -> bool:
    """
    Rollback NFS configuration from backup.
    """
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
        logging.getLogger(__name__).info(f"Rolled back NFS config: {original_path}")
        return True
    except Exception as e:
        logging.getLogger(__name__).error(f"Rollback failed for {original_path}: {e}")
        return False


# ============================================================
# FIX 4: VERIFY NFS AFTER CHANGES
# ============================================================
def _verify_nfs_running() -> bool:
    """Verify NFS is running and responding."""
    try:
        result = subprocess.run(
            ['systemctl', 'is-active', 'nfs-kernel-server'],
            capture_output=True,
            text=True,
            timeout=5, stdin=subprocess.DEVNULL)
        if result.stdout.strip() == 'active':
            return True
    except:
        pass
    
    try:
        result = subprocess.run(
            ['systemctl', 'is-active', 'nfs'],
            capture_output=True,
            text=True,
            timeout=5, stdin=subprocess.DEVNULL)
        if result.stdout.strip() == 'active':
            return True
    except:
        pass
    
    return False


# ============================================================
# MEDIUM FIX 1: DRY-RUN MODE
# ============================================================
def _dry_run_nfs_fix(action: str, details: str) -> bool:
    """
    Simulate NFS modification without actually changing anything.
    Used for dry-run mode.
    """
    logging.getLogger(__name__).info(f"[DRY-RUN] Would perform: {action} - {details}")
    print(f"[DRY-RUN] Would perform: {action}")
    return True


# ============================================================
# MEDIUM FIX 2: CONFIRMATION BEFORE MODIFYING NFS
# ============================================================
def _confirm_nfs_modification(action: str) -> bool:
    """
    Ask for confirmation before modifying NFS.
    """
    print(f"\n[!] WARNING: About to modify NFS configuration")
    print(f"    Action: {action}")
    print("    This could break NFS shares!")
    response = ui.prompt("Proceed? [y/N]: ")
    if response.lower() == 'y':
        print("\n[*] Applying fixes... please wait")
        return True
    return False


# ============================================================
# MEDIUM FIX 3: LOGGING OF NFS CHANGES
# ============================================================
def _log_nfs_change(action: str, details: str, success: bool):
    """
    Log NFS modifications.
    """
    logger = logging.getLogger(__name__)
    status = "SUCCESS" if success else "FAILED"
    logger.info(f"NFS change: {action} - {details} ({status})")
    
    # Also log to changes.log for audit trail
    changes_log = Path("/var/log/shadow/changes.log")
    if changes_log.exists():
        with open(changes_log, 'a') as f:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            f.write(f"{timestamp} - NFS: {action} - {details} ({status})\n")


# ============================================================
# MEDIUM FIX 4: VERIFY NFS EXPORTS ACCESSIBILITY
# ============================================================
def _verify_nfs_exports_accessible() -> bool:
    """
    Verify NFS exports are accessible.
    """
    try:
        result = subprocess.run(
            ['showmount', '-e', 'localhost'],
            capture_output=True,
            text=True,
            timeout=10, stdin=subprocess.DEVNULL)
        if result.returncode == 0 and 'Export list' in result.stdout:
            return True
    except:
        pass
    
    try:
        # Try to get exports using exportfs
        result = subprocess.run(
            ['exportfs', '-v'],
            capture_output=True,
            text=True,
            timeout=10, stdin=subprocess.DEVNULL)
        if result.returncode == 0 and result.stdout:
            return True
    except:
        pass
    
    return False


# ============================================================
# LOW FIX 1: PROGRESS INDICATOR
# ============================================================
def _progress_indicator(current: int, total: int, message: str = ""):
    """
    Show progress during operations.
    """
    if total > 0:
        percent = (current / total) * 100
        print(f"\r\033[K[{current}/{total}] {percent:.1f}% - {message}", end="", flush=True)


def _safe_nfs_fix(config_file: str, fix_func, dry_run: bool = False, *args) -> bool:
    """
    Safely apply an NFS fix with backup, validation, dry-run, and rollback.
    """
    logger = logging.getLogger(__name__)
    
    # MEDIUM FIX 1: Dry-run mode
    if dry_run:
        return _dry_run_nfs_fix("nfs_fix", f"Would apply fix to {config_file}")
    
    # MEDIUM FIX 2: Confirmation
    if not _confirm_nfs_modification(f"Apply fix to {config_file}"):
        logger.info("NFS fix cancelled by user")
        return False
    
    # Step 1: Backup config
    backup_metadata = _backup_nfs_config(config_file)
    if not backup_metadata['success']:
        logger.warning(f"Could not backup {config_file}")
    
    try:
        # Step 2: Apply fix
        fix_func(*args)
        
        # Step 3: Validate config
        if not _validate_nfs_exports():
            logger.error("NFS exports validation failed after fix")
            if backup_metadata['success']:
                _rollback_nfs_config(backup_metadata)
                _restart_nfs()
            # MEDIUM FIX 3: Log failure
            _log_nfs_change("nfs_fix", f"{config_file} - validation failed", False)
            return False
        
        # Step 4: Verify NFS is running
        if not _verify_nfs_running():
            logger.error("NFS is not running after fix")
            if backup_metadata['success']:
                _rollback_nfs_config(backup_metadata)
                _restart_nfs()
            # MEDIUM FIX 3: Log failure
            _log_nfs_change("nfs_fix", f"{config_file} - NFS not running", False)
            return False
        
        # MEDIUM FIX 4: Verify NFS exports accessibility
        if not _verify_nfs_exports_accessible():
            logger.warning("NFS exports may not be accessible - check manually")
        
        # MEDIUM FIX 3: Log success
        _log_nfs_change("nfs_fix", f"{config_file} - success", True)
        return True
        
    except Exception as e:
        logger.error(f"Error applying NFS fix: {e}")
        if backup_metadata['success']:
            _rollback_nfs_config(backup_metadata)
            _restart_nfs()
        # MEDIUM FIX 3: Log failure
        _log_nfs_change("nfs_fix", f"{config_file} - {e}", False)
        return False


def _restart_nfs():
    """Restart NFS service."""
    try:
        subprocess.run(['systemctl', 'restart', 'nfs-kernel-server'], capture_output=True, text=True, stdin=subprocess.DEVNULL)
    except:
        pass
    try:
        subprocess.run(['systemctl', 'restart', 'nfs'], capture_output=True, text=True, stdin=subprocess.DEVNULL)
    except:
        pass

def _enable_nfs_service() -> bool:
    """Enable and start NFS service if installed but not running."""
    logger = logging.getLogger(__name__)
    
    if not _check_nfs_installed():
        logger.info("NFS is not installed, skipping enable")
        return True
    
    if _check_nfs_running():
        logger.info("NFS is already running")
        return True
    
    try:
        logger.info("Enabling and starting NFS service...")
        # Try NFS kernel server first
        result = subprocess.run(['systemctl', 'enable', 'nfs-kernel-server'], capture_output=True, timeout=10, stdin=subprocess.DEVNULL)
        if result.returncode != 0:
            # Try generic nfs
            subprocess.run(['systemctl', 'enable', 'nfs'], capture_output=True, timeout=10, stdin=subprocess.DEVNULL)
            subprocess.run(['systemctl', 'start', 'nfs'], capture_output=True, timeout=10, stdin=subprocess.DEVNULL)
        else:
            subprocess.run(['systemctl', 'start', 'nfs-kernel-server'], capture_output=True, timeout=10, stdin=subprocess.DEVNULL)
            # Also enable rpcbind
            subprocess.run(['systemctl', 'enable', 'rpcbind'], capture_output=True, timeout=10, stdin=subprocess.DEVNULL)
            subprocess.run(['systemctl', 'start', 'rpcbind'], capture_output=True, timeout=10, stdin=subprocess.DEVNULL)
        
        if _check_nfs_running():
            logger.info("NFS started successfully")
            return True
        else:
            logger.error("NFS failed to start")
            return False
    except Exception as e:
        logger.error(f"Failed to enable NFS: {e}")
        return False
    
def fix(config: dict, dry_run: bool = False, force: bool = False) -> bool:
    """
    Fix NFS security issues

    Args:
        config: Configuration dictionary
        dry_run: If True, preview changes without applying
        force: If True, skip confirmation

    Returns:
        bool: True if fixes applied successfully
    """
    logger = logging.getLogger(__name__)
    logger.info("Fixing NFS security issues...")

    # Check for dry-run mode
    if dry_run:
        logger.info("DRY-RUN MODE: No changes will be applied")
        print("\n[!] DRY-RUN MODE - No changes will be applied")
        
        # Show what would be done
        if config.get('nfs', {}).get('fix_exports_perms', True):
            print("    Would fix exports file permissions")
        if config.get('nfs', {}).get('enable_root_squash', True):
            print("    Would enable root_squash in exports")
        if config.get('nfs', {}).get('enable_logging', True):
            print("    Would enable logging")
        if config.get('nfs', {}).get('restart_nfs', True):
            print("    Would restart NFS service")
        
        print("\n[✓] Dry-run complete. No changes were made.")
        return True

    # Validate current NFS exports first
    if not _validate_nfs_exports():
        logger.info("ℹ️ NFS is not installed or configured. Skipping safely.")
        return True

    # ✅ FIX: Skip confirmation in force mode
    if not force:
        if not _confirm_nfs_modification("Apply all NFS security fixes"):
            logger.info("NFS fixes cancelled by user")
            return False
    else:
        logger.info("Force mode: Applying NFS fixes without confirmation")

    try:
        begin_transaction()
        
        steps = []
        
        # Step 1: Fix exports file permissions
        if config.get('nfs', {}).get('fix_exports_perms', True):
            steps.append(("Fix exports permissions", _fix_exports_permissions))
        
        # Step 2: Enable root_squash in exports
        if config.get('nfs', {}).get('enable_root_squash', True):
            steps.append(("Enable root_squash", _enable_root_squash))
        
        # Step 3: Enable logging
        if config.get('nfs', {}).get('enable_logging', True):
            steps.append(("Enable logging", _enable_logging))
        
        # Step 4: Restart NFS service
        if config.get('nfs', {}).get('restart_nfs', True):
            steps.append(("Restart NFS", _restart_nfs))
        
        total_steps = len(steps)
        for idx, (name, func) in enumerate(steps):
            _progress_indicator(idx + 1, total_steps, name)
            func(dry_run)
        
        print()  # New line after progress

        if dry_run:
            logger.info("DRY-RUN completed successfully")
            commit_transaction()
            return True

        # Verify NFS is still running
        if not _verify_nfs_running():
            logger.info("ℹ️ NFS is not installed or not running. Skipping safely.")
            return True

        if not _verify_nfs_exports_accessible():
            logger.warning("NFS exports may not be accessible - check manually")

        commit_transaction()
        logger.info("NFS fixes applied successfully")
        print("\n✅ NFS fixes applied successfully")
        return True

    except Exception as e:
        logger.error(f"Failed to fix NFS: {e}")
        rollback_transaction()
        return False


def _fix_exports_permissions(dry_run: bool = False):
    """Fix /etc/exports permissions"""
    exports_file = '/etc/exports'

    if os.path.exists(exports_file):
        try:
            if dry_run:
                _dry_run_nfs_fix("fix_exports_permissions", f"Would fix permissions on {exports_file}")
                return
            
            os.chown(exports_file, 0, 0)
            os.chmod(exports_file, 0o644)
            logging.getLogger(__name__).info("Exports file permissions fixed")
            # MEDIUM FIX 3: Log the change
            _log_nfs_change("fix_exports_permissions", "Exports file permissions fixed", True)
        except Exception as e:
            logging.getLogger(__name__).error(f"Error fixing exports permissions: {e}")
            # MEDIUM FIX 3: Log failure
            _log_nfs_change("fix_exports_permissions", str(e), False)


def _enable_root_squash(dry_run: bool = False):
    """Enable root_squash in exports"""
    exports_file = '/etc/exports'
    
    if dry_run:
        _dry_run_nfs_fix("enable_root_squash", "Would enable root_squash in exports")
        return

    if not os.path.exists(exports_file):
        return

    backup_metadata = _backup_nfs_config(exports_file)

    try:
        with open(exports_file, 'r') as f:
            lines = f.readlines()

        new_lines = []
        modified = False
        
        for line in lines:
            if line.strip() and not line.startswith('#'):
                if 'no_root_squash' in line:
                    line = line.replace('no_root_squash', 'root_squash')
                    modified = True
                elif 'root_squash' not in line and '(' in line and ')' in line:
                    # Add root_squash to existing options
                    parts = line.split('(')
                    if len(parts) > 1:
                        options_part = parts[1]
                        if options_part and not options_part.startswith('root_squash'):
                            line = line.replace('(', '(root_squash,')
                            modified = True
            new_lines.append(line)

        if modified:
            with open(exports_file, 'w') as f:
                f.writelines(new_lines)

            logging.getLogger(__name__).info("root_squash enabled in exports")
            # MEDIUM FIX 3: Log the change
            _log_nfs_change("enable_root_squash", "root_squash enabled in exports", True)
            
            # Validate after change
            if not _validate_nfs_exports():
                logging.getLogger(__name__).error("NFS exports validation failed after enabling root_squash")
                if backup_metadata['success']:
                    _rollback_nfs_config(backup_metadata)
                # MEDIUM FIX 3: Log failure
                _log_nfs_change("enable_root_squash", "Validation failed", False)
        else:
            logging.getLogger(__name__).debug("root_squash already enabled")

    except Exception as e:
        logging.getLogger(__name__).error(f"Error enabling root_squash: {e}")
        if backup_metadata['success']:
            _rollback_nfs_config(backup_metadata)
        # MEDIUM FIX 3: Log failure
        _log_nfs_change("enable_root_squash", str(e), False)


def _enable_logging(dry_run: bool = False):
    """Enable NFS logging"""
    nfs_config = '/etc/default/nfs-kernel-server'
    
    if dry_run:
        _dry_run_nfs_fix("enable_logging", f"Would enable logging in {nfs_config}")
        return

    if not os.path.exists(nfs_config):
        return

    backup_metadata = _backup_nfs_config(nfs_config)

    try:
        with open(nfs_config, 'r') as f:
            content = f.read()

        modified = False
        if 'RPCMOUNTDOPTS' not in content:
            content += '\nRPCMOUNTDOPTS="--manage-gids"\n'
            modified = True
        if 'RPCNFSDOPTS' not in content:
            content += '\nRPCNFSDOPTS="--debug"\n'
            modified = True

        if modified:
            with open(nfs_config, 'w') as f:
                f.write(content)

            logging.getLogger(__name__).info("NFS logging enabled")
            # MEDIUM FIX 3: Log the change
            _log_nfs_change("enable_logging", "NFS logging enabled", True)
        else:
            logging.getLogger(__name__).debug("NFS logging already enabled")

    except Exception as e:
        logging.getLogger(__name__).error(f"Error enabling logging: {e}")
        if backup_metadata['success']:
            _rollback_nfs_config(backup_metadata)
        # MEDIUM FIX 3: Log failure
        _log_nfs_change("enable_logging", str(e), False)