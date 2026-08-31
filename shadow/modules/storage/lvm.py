#!/usr/bin/env python3
"""
Shadow LVM Module
=================

Checks LVM (Logical Volume Manager) security:
- LVM is installed
- LVM volume groups
- LVM logical volumes
- LVM snapshot protection
- LVM thin pools
- LVM metadata backup

Security concerns:
- Unprotected snapshots → data exposure
- Thin pool exhaustion → service failure
- Metadata corruption → data loss
- Unencrypted volumes → data exposure
- Removable LVM volumes → physical theft
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
SEVERITY = "MEDIUM"
RECOMMENDATION = "Enable encryption for sensitive data and monitor disk usage"

BACKUP_DIR = Path("/var/backups/shadow/")
CHANGES_LOG = Path("/var/log/shadow/changes.log")

# ============================================================
# TRANSACTION SUPPORT
# ============================================================
_transaction_active = False
_transaction_backups = []

def begin_transaction():
    """Begin a transaction for LVM modifications."""
    global _transaction_active, _transaction_backups
    _transaction_active = True
    _transaction_backups = []
    logging.getLogger(__name__).info("LVM transaction started")

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
    logging.getLogger(__name__).info("LVM transaction committed")
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
def _log_lvm_change(action: str, details: str, success: bool):
    """Log LVM modifications with structured format."""
    logger = logging.getLogger(__name__)
    status = "SUCCESS" if success else "FAILED"
    
    log_entry = {
        "event": "lvm_change",
        "action": action,
        "details": details,
        "status": status,
        "timestamp": datetime.now().isoformat()
    }
    logger.info(f"LVM: {json.dumps(log_entry)}")
    
    try:
        CHANGES_LOG.parent.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(CHANGES_LOG, 'a') as f:
            f.write(f"{timestamp} - LVM: {action} - {details} ({status})\n")
    except Exception as e:
        logger.debug(f"Failed to log change: {e}")


# ============================================================
# CHECK FUNCTION
# ============================================================
def check(config: dict) -> Tuple[str, str, dict]:
    """
    Check LVM configuration security

    Returns:
        Tuple[str, str, dict]: (status, message, details)
    """
    logger = logging.getLogger(__name__)
    logger.info("Checking LVM security...")

    issues = []
    warnings = []
    details = {
        'lvm_installed': False,
        'volume_groups': [],
        'logical_volumes': [],
        'snapshots': [],
        'thin_pools': [],
        'metadata_backup': False,
        'encrypted_volumes': []
    }

    # Check if LVM is installed
    lvm_installed = _check_lvm_installed()
    details['lvm_installed'] = lvm_installed

    if not lvm_installed:
        return 'PASS', "LVM is not installed", details

    # Check volume groups
    volume_groups = _check_volume_groups()
    details['volume_groups'] = volume_groups

    if volume_groups:
        for vg in volume_groups:
            if vg.get('pe_count', 0) == 0:
                warnings.append(f"Volume group {vg['name']} has no physical extents")

    # Check logical volumes
    logical_volumes = _check_logical_volumes()
    details['logical_volumes'] = logical_volumes

    for lv in logical_volumes:
        if lv.get('size', 0) == 0:
            warnings.append(f"Logical volume {lv['name']} has zero size")

    # Check snapshots
    snapshots = _check_snapshots()
    details['snapshots'] = snapshots

    if snapshots:
        for snapshot in snapshots:
            if snapshot.get('snap_percent', 0) >= 80:
                warnings.append(f"Snapshot {snapshot['name']} is {snapshot['snap_percent']}% used")

    # Check thin pools
    thin_pools = _check_thin_pools()
    details['thin_pools'] = thin_pools

    for pool in thin_pools:
        if pool.get('data_used', 0) >= 80:
            warnings.append(f"Thin pool {pool['name']} data usage: {pool['data_used']}%")

    # Check metadata backup
    metadata_backup = _check_metadata_backup()
    details['metadata_backup'] = metadata_backup

    if not metadata_backup:
        warnings.append("LVM metadata backup not found or outdated")

    # Check encrypted volumes
    encrypted = _check_encrypted_volumes()
    details['encrypted_volumes'] = encrypted

    if not encrypted and volume_groups:
        warnings.append("No LVM volumes appear to be encrypted")

    # Determine status
    if issues:
        status = 'FAIL'
        message = f"{len(issues)} critical LVM issues found"
    elif warnings:
        status = 'WARN'
        message = f"{len(warnings)} LVM warnings found"
    else:
        status = 'PASS'
        message = "LVM configuration is secure"

    return status, message, details


def _check_lvm_installed() -> bool:
    """Check if LVM is installed"""
    lvm_paths = [
        '/usr/sbin/lvm',
        '/usr/bin/lvm',
        '/usr/sbin/lvcreate',
        '/usr/sbin/vgcreate'
    ]

    for path in lvm_paths:
        if os.path.exists(path):
            return True

    try:
        result = subprocess.run(['which', 'lvm'], capture_output=True, text=True, timeout=5, stdin=subprocess.DEVNULL)
        if result.returncode == 0:
            return True
    except:
        pass

    return False


def _check_volume_groups() -> List[Dict]:
    """Check LVM volume groups"""
    volume_groups = []

    try:
        result = subprocess.run(['vgs', '--noheadings', '--units', 'g',
                                 '-o', 'vg_name,vg_size,vg_free,vg_pe_count,vg_pe_size'],
                              capture_output=True, text=True, timeout=10, stdin=subprocess.DEVNULL)

        if result.returncode == 0:
            for line in result.stdout.split('\n'):
                if line.strip():
                    parts = line.split()
                    if len(parts) >= 5:
                        volume_groups.append({
                            'name': parts[0],
                            'size': float(parts[1].rstrip('g')),
                            'free': float(parts[2].rstrip('g')),
                            'pe_count': int(parts[3]),
                            'pe_size': parts[4] + 'M'
                        })

    except subprocess.TimeoutExpired:
        logging.getLogger(__name__).warning("vgs command timed out")
    except Exception as e:
        logging.getLogger(__name__).debug(f"Error checking volume groups: {e}")

    return volume_groups


def _check_logical_volumes() -> List[Dict]:
    """Check LVM logical volumes"""
    logical_volumes = []

    try:
        result = subprocess.run(['lvs', '--noheadings', '--units', 'g',
                                 '-o', 'lv_name,vg_name,lv_size,origin,data_percent,snap_percent'],
                              capture_output=True, text=True, timeout=10, stdin=subprocess.DEVNULL)

        if result.returncode == 0:
            for line in result.stdout.split('\n'):
                if line.strip():
                    parts = line.split()
                    if len(parts) >= 3:
                        lv_data = {
                            'name': parts[0],
                            'vg_name': parts[1],
                            'size': float(parts[2].rstrip('g'))
                        }
                        if len(parts) > 3 and parts[3] != '-':
                            lv_data['origin'] = parts[3]
                        if len(parts) > 4 and parts[4] != '-':
                            lv_data['data_percent'] = float(parts[4].rstrip('%'))
                        logical_volumes.append(lv_data)

    except subprocess.TimeoutExpired:
        logging.getLogger(__name__).warning("lvs command timed out")
    except Exception as e:
        logging.getLogger(__name__).debug(f"Error checking logical volumes: {e}")

    return logical_volumes


def _check_snapshots() -> List[Dict]:
    """Check LVM snapshots"""
    snapshots = []

    try:
        result = subprocess.run(['lvs', '--noheadings', '--units', 'g',
                                 '-o', 'lv_name,vg_name,lv_size,origin,snap_percent,data_percent',
                                 '-S', 'origin!=""'],
                              capture_output=True, text=True, timeout=10, stdin=subprocess.DEVNULL)

        if result.returncode == 0:
            for line in result.stdout.split('\n'):
                if line.strip():
                    parts = line.split()
                    if len(parts) >= 4:
                        snapshot_data = {
                            'name': parts[0],
                            'vg_name': parts[1],
                            'size': float(parts[2].rstrip('g')),
                            'origin': parts[3] if len(parts) > 3 else 'unknown',
                            'snap_percent': float(parts[4].rstrip('%')) if len(parts) > 4 and parts[4] != '-' else 0
                        }
                        snapshots.append(snapshot_data)

    except subprocess.TimeoutExpired:
        logging.getLogger(__name__).warning("lvs snapshots command timed out")
    except Exception as e:
        logging.getLogger(__name__).debug(f"Error checking snapshots: {e}")

    return snapshots


def _check_thin_pools() -> List[Dict]:
    """Check LVM thin pools"""
    thin_pools = []

    try:
        result = subprocess.run(['lvs', '--noheadings', '--units', 'g',
                                 '-o', 'lv_name,vg_name,data_percent,metadata_percent,pool_lv',
                                 '-S', 'pool_lv!=""'],
                              capture_output=True, text=True, timeout=10, stdin=subprocess.DEVNULL)

        if result.returncode == 0:
            for line in result.stdout.split('\n'):
                if line.strip():
                    parts = line.split()
                    if len(parts) >= 5:
                        thin_pools.append({
                            'name': parts[0],
                            'vg_name': parts[1],
                            'data_used': float(parts[2].rstrip('%')) if parts[2] != '-' else 0,
                            'metadata_used': float(parts[3].rstrip('%')) if parts[3] != '-' else 0,
                            'pool_lv': parts[4]
                        })

    except subprocess.TimeoutExpired:
        logging.getLogger(__name__).warning("lvs thin pools command timed out")
    except Exception as e:
        logging.getLogger(__name__).debug(f"Error checking thin pools: {e}")

    return thin_pools


def _check_metadata_backup() -> bool:
    """Check if LVM metadata backup exists"""
    backup_dirs = [
        '/etc/lvm/backup',
        '/etc/lvm/archive'
    ]

    for backup_dir in backup_dirs:
        if os.path.exists(backup_dir):
            files = list(Path(backup_dir).iterdir())
            if files:
                for f in files:
                    try:
                        if time.time() - f.stat().st_mtime < 86400 * 7:
                            return True
                    except:
                        pass

    return False


def _check_encrypted_volumes() -> List[str]:
    """Check for encrypted LVM volumes"""
    encrypted = []

    try:
        result = subprocess.run(['which', 'cryptsetup'], capture_output=True, text=True, timeout=5, stdin=subprocess.DEVNULL)
        if result.returncode != 0:
            return encrypted

        result = subprocess.run(['cryptsetup', 'luksDump'],
                              capture_output=True, text=True, timeout=10, stdin=subprocess.DEVNULL)

        if 'LUKS' in result.stderr:
            result = subprocess.run(['lsblk', '-l', '-o', 'NAME,TYPE,FSTYPE'],
                                  capture_output=True, text=True, timeout=10, stdin=subprocess.DEVNULL)

            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if 'crypto_LUKS' in line:
                        parts = line.split()
                        if parts:
                            encrypted.append(parts[0])

    except subprocess.TimeoutExpired:
        logging.getLogger(__name__).warning("cryptsetup command timed out")
    except Exception as e:
        logging.getLogger(__name__).debug(f"Error checking encrypted volumes: {e}")

    return encrypted


# ============================================================
# BACKUP FUNCTIONS
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


def _execute_lvm_command(cmd: List[str], timeout: int = 30) -> Tuple[bool, str]:
    """
    Execute an LVM command with error handling and validation.
    Returns (success, output).
    """
    logger = logging.getLogger(__name__)
    
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout, stdin=subprocess.DEVNULL)
        if result.returncode == 0:
            logger.debug(f"LVM command succeeded: {' '.join(cmd)}")
            return True, result.stdout
        else:
            logger.error(f"LVM command failed: {' '.join(cmd)}")
            logger.error(f"Error: {result.stderr}")
            return False, result.stderr
    except subprocess.TimeoutExpired:
        logger.error(f"LVM command timed out: {' '.join(cmd)}")
        return False, "Command timed out"
    except Exception as e:
        logger.error(f"LVM command error: {e}")
        return False, str(e)


def _dry_run_lvm_fix(action: str, details: str) -> bool:
    """Simulate LVM modification without actually changing anything."""
    logging.getLogger(__name__).info(f"[DRY-RUN] Would perform: {action} - {details}")
    print(f"[DRY-RUN] Would perform: {action}")
    return True


def _confirm_lvm_modification(action: str) -> bool:
    """Ask for confirmation before modifying LVM."""
    print(f"\n[!] WARNING: About to perform LVM operation")
    print(f"    Action: {action}")
    print("    This could affect your storage volumes!")
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


def _safe_lvm_backup(dry_run: bool = False) -> bool:
    """
    Safely backup LVM metadata with dry-run support.
    """
    logger = logging.getLogger(__name__)
    
    if dry_run:
        _dry_run_lvm_fix("lvm_backup", "Would backup LVM metadata")
        return True
    
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
    backup_path = BACKUP_DIR / f"lvm_metadata.backup_{timestamp}"
    
    try:
        success, output = _execute_lvm_command(['vgcfgbackup'], timeout=60)
        
        if success:
            metadata_backup_dirs = ['/etc/lvm/backup', '/etc/lvm/archive']
            backup_found = False
            for backup_dir in metadata_backup_dirs:
                if os.path.exists(backup_dir):
                    shutil.copytree(backup_dir, backup_path, dirs_exist_ok=True)
                    backup_found = True
                    break
            
            if backup_found and _verify_backup(backup_path):
                logger.info(f"LVM metadata backup created and verified: {backup_path}")
                _log_lvm_change("lvm_backup", f"Backup created: {backup_path}", True)
                add_to_transaction(backup_path, Path('/etc/lvm/backup'))
                return True
            else:
                logger.warning("LVM metadata backup created but verification failed")
                _log_lvm_change("lvm_backup", "Verification failed", False)
                return False
        else:
            logger.error(f"LVM metadata backup failed: {output}")
            _log_lvm_change("lvm_backup", f"Failed: {output}", False)
            return False
            
    except Exception as e:
        logger.error(f"Error backing up LVM metadata: {e}")
        _log_lvm_change("lvm_backup", str(e), False)
        return False


def fix(config: dict, dry_run: bool = False, force: bool = False) -> bool:
    """
    Fix LVM security issues

    Args:
        config: Configuration dictionary
        dry_run: If True, preview changes without applying
        force: If True, skip confirmation

    Returns:
        bool: True if fixes applied successfully
    """
    logger = logging.getLogger(__name__)
    logger.info("Fixing LVM security issues...")

    # Check for dry-run mode (use parameter, not config)
    if dry_run:
        logger.info("DRY-RUN MODE: No changes will be applied")
        print("\n[!] DRY-RUN MODE - No changes will be applied")
        
        lvm_installed = _check_lvm_installed()
        print(f"  LVM installed: {lvm_installed}")
        if lvm_installed:
            vgs = _check_volume_groups()
            print(f"  Volume groups: {len(vgs)}")
            lvs = _check_logical_volumes()
            print(f"  Logical volumes: {len(lvs)}")
            snapshots = _check_snapshots()
            print(f"  Snapshots: {len(snapshots)}")
        
        if config.get('lvm', {}).get('backup_metadata', True):
            print("  Would backup LVM metadata")
        if config.get('lvm', {}).get('check_thin_pools', True):
            print("  Would check thin pool usage")
        
        print("\n[✓] Dry-run complete. No changes were made.")
        return True

    # FIX: Skip confirmation in force mode
    if not force:
        if not _confirm_lvm_modification("Apply all LVM security fixes"):
            logger.info("LVM fixes cancelled by user")
            return False
    else:
        logger.info("Force mode: Applying LVM fixes without confirmation")

    try:
        begin_transaction()
        
        steps = []
        
        if config.get('lvm', {}).get('backup_metadata', True):
            steps.append(("Backup LVM metadata", _backup_lvm_metadata))
        
        if config.get('lvm', {}).get('check_thin_pools', True):
            steps.append(("Check thin pools", _check_thin_pool_usage))
        
        if config.get('lvm', {}).get('warn_snapshots', True):
            steps.append(("Check snapshots", _warn_snapshot_usage))
        
        total_steps = len(steps)
        for idx, (name, func) in enumerate(steps):
            _progress_indicator(idx + 1, total_steps, name)
            if name == "Backup LVM metadata":
                _safe_lvm_backup(dry_run)
            else:
                func()
        
        print()

        commit_transaction()
        logger.info("LVM fixes applied successfully")
        print("\n LVM fixes applied successfully")
        return True

    except Exception as e:
        logger.error(f"Failed to fix LVM issues: {e}")
        rollback_transaction()
        return False


def _backup_lvm_metadata():
    """Backup LVM metadata with verification"""
    _safe_lvm_backup(False)


def _check_thin_pool_usage():
    """Check thin pool usage"""
    thin_pools = _check_thin_pools()

    for pool in thin_pools:
        if pool.get('data_used', 0) >= 80:
            logging.getLogger(__name__).warning(
                f"Thin pool {pool['name']} data usage: {pool['data_used']}% - consider extending"
            )
            _log_lvm_change("thin_pool_warning", f"{pool['name']} is {pool['data_used']}% used", True)


def _warn_snapshot_usage():
    """Warn about snapshot usage"""
    snapshots = _check_snapshots()

    for snapshot in snapshots:
        if snapshot.get('snap_percent', 0) >= 80:
            logging.getLogger(__name__).warning(
                f"Snapshot {snapshot['name']} is {snapshot['snap_percent']}% used - consider increasing size"
            )
            _log_lvm_change("snapshot_warning", f"{snapshot['name']} is {snapshot['snap_percent']}% used", True)