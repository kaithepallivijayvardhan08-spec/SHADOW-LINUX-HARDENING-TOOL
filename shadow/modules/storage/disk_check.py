#!/usr/bin/env python3
"""
Shadow Disk Check Module
========================

Checks disk space and mount point security:
- Disk usage (critical thresholds)
- Mount point permissions
- Mount point options (noexec, nosuid, nodev)
- Removable media security
- Inode usage
- Filesystem types

Files checked:
- /etc/fstab
- /proc/mounts
- df output

Security concerns:
- /tmp without noexec → malicious code execution
- /var without nosuid → privilege escalation
- Home directory with noexec → limiting user execution
- USB media with exec → malware spread
- Full disk → service failure
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
    """Begin a transaction for disk modifications."""
    global _transaction_active, _transaction_backups
    _transaction_active = True
    _transaction_backups = []
    logging.getLogger(__name__).info("Disk transaction started")

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
    logging.getLogger(__name__).info("Disk transaction committed")
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
# PROTECTED FILESYSTEMS - NEVER MODIFY THESE
# ============================================================
PROTECTED_FILESYSTEMS = [
    'ext4', 'xfs', 'btrfs', 'zfs', 'ntfs', 'vfat', 'exfat',
    'f2fs', 'jfs', 'reiserfs', 'ufs', 'hfs', 'hfsplus'
]


# ============================================================
# PROTECTED MOUNTS - NEVER MODIFY THESE
# ============================================================
PROTECTED_MOUNTS = [
    '/', '/boot', '/boot/efi', '/usr', '/var', '/lib', '/lib64',
    '/opt', '/run', '/sys', '/proc', '/dev'
]


# ============================================================
# FIX 8: STRUCTURED LOGGING
# ============================================================
def _log_disk_change(action: str, details: str, success: bool):
    """Log disk modifications with structured format."""
    logger = logging.getLogger(__name__)
    status = "SUCCESS" if success else "FAILED"
    
    log_entry = {
        "event": "disk_change",
        "action": action,
        "details": details,
        "status": status,
        "timestamp": datetime.now().isoformat()
    }
    logger.info(f"DISK: {json.dumps(log_entry)}")
    
    try:
        CHANGES_LOG.parent.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(CHANGES_LOG, 'a') as f:
            f.write(f"{timestamp} - Disk: {action} - {details} ({status})\n")
    except Exception as e:
        logger.debug(f"Failed to log change: {e}")


def _log_disk_findings(details: Dict, issues: List[str], warnings: List[str]):
    """Log disk check findings for audit trail."""
    try:
        CHANGES_LOG.parent.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        with open(CHANGES_LOG, 'a') as f:
            f.write(f"{timestamp} - Disk Check Results:\n")
            f.write(f"  Total Mounts: {len(details.get('mount_points', []))}\n")
            f.write(f"  Fstab Entries: {len(details.get('fstab_entries', []))}\n")
            f.write(f"  Dangerous Mounts: {len(details.get('dangerous_mounts', []))}\n")
            f.write(f"  Disk Usage: {len(details.get('disk_usage', {}))}\n")
            
            for issue in issues:
                f.write(f"  ISSUE: {issue}\n")
            for warning in warnings:
                f.write(f"  WARNING: {warning}\n")
    except Exception as e:
        logging.getLogger(__name__).warning(f"Failed to log disk findings: {e}")


# ============================================================
# CHECK FUNCTION
# ============================================================
def check(config: dict) -> Tuple[str, str, dict]:
    """
    Check disk space and mount point security

    Returns:
        Tuple[str, str, dict]: (status, message, details)
    """
    logger = logging.getLogger(__name__)
    logger.info("Checking disk security...")

    issues = []
    warnings = []
    details = {
        'disk_usage': {},
        'mount_points': [],
        'fstab_entries': [],
        'dangerous_mounts': [],
        'inode_usage': {},
        'filesystem_types': [],
        'removable_media': []
    }

    # Check disk usage
    disk_usage = _check_disk_usage()
    details['disk_usage'] = disk_usage

    for mount, usage in disk_usage.items():
        if usage.get('percent', 0) >= 90:
            issues.append(f"CRITICAL: {mount} is {usage['percent']}% full")
        elif usage.get('percent', 0) >= 80:
            warnings.append(f"{mount} is {usage['percent']}% full (approaching limit)")

    # Check mount points
    mount_points = _check_mount_points()
    details['mount_points'] = mount_points

    for mount in mount_points:
        if not mount.get('secure'):
            issues.append(f"Mount {mount['mount']} is not secure: {mount.get('issue')}")

    # Check fstab entries
    fstab_entries = _check_fstab()
    details['fstab_entries'] = fstab_entries

    for entry in fstab_entries:
        if entry.get('noexec') and entry.get('nosuid') and entry.get('nodev'):
            details['dangerous_mounts'].append(f"{entry['mount']} has secure options")
        elif not entry.get('noexec') and entry['mount'] in ['/tmp', '/var/tmp', '/dev/shm']:
            warnings.append(f"{entry['mount']} does NOT have noexec option")

    # Check inode usage
    inode_usage = _check_inode_usage()
    details['inode_usage'] = inode_usage

    for mount, usage in inode_usage.items():
        if usage.get('percent', 0) >= 90:
            warnings.append(f"{mount} inode usage is {usage['percent']}% (critical)")

    # Check filesystem types
    fs_types = _check_filesystem_types()
    details['filesystem_types'] = fs_types

    for fs, count in fs_types.items():
        if fs in ['vfat', 'ntfs', 'exfat']:
            warnings.append(f"Filesystem {fs} found (may be removable media)")

    # Check removable media
    removable = _check_removable_media()
    details['removable_media'] = removable

    if removable:
        for media in removable:
            warnings.append(f"Removable media detected: {media}")

    # Log findings
    _log_disk_findings(details, issues, warnings)

    # Determine status
    if issues:
        critical = [i for i in issues if 'CRITICAL' in i]
        if critical:
            status = 'FAIL'
            message = f"{len(issues)} critical disk issues found"
        else:
            status = 'WARN'
            message = f"{len(issues)} disk issues found"
    elif warnings:
        status = 'WARN'
        message = f"{len(warnings)} disk warnings found"
    else:
        status = 'PASS'
        message = "Disk configuration is secure"

    return status, message, details


def _check_disk_usage() -> Dict:
    """Check disk usage percentages"""
    usage = {}

    try:
        result = subprocess.run(['df', '-h', '--output=target,pcent,size,used,avail'],
                              capture_output=True, text=True, timeout=10, stdin=subprocess.DEVNULL)

        if result.returncode == 0:
            lines = result.stdout.split('\n')[1:]
            for line in lines:
                if line.strip():
                    parts = line.split()
                    if len(parts) >= 5:
                        mount = parts[0]
                        percent = parts[1].strip('%')
                        try:
                            percent_val = int(percent)
                            usage[mount] = {
                                'percent': percent_val,
                                'size': parts[2] if len(parts) > 2 else '0',
                                'used': parts[3] if len(parts) > 3 else '0',
                                'available': parts[4] if len(parts) > 4 else '0'
                            }
                        except ValueError:
                            continue

    except subprocess.TimeoutExpired:
        logging.getLogger(__name__).warning("df command timed out")
    except Exception as e:
        logging.getLogger(__name__).debug(f"Error checking disk usage: {e}")

    return usage


def _check_mount_points() -> List[Dict]:
    """Check mount point security"""
    mounts = []

    try:
        result = subprocess.run(['mount'], capture_output=True, text=True, timeout=10, stdin=subprocess.DEVNULL)

        if result.returncode == 0:
            for line in result.stdout.split('\n'):
                if line.strip():
                    parts = line.split()
                    if len(parts) >= 6:
                        mount_data = {
                            'device': parts[0],
                            'mount': parts[2],
                            'type': parts[4],
                            'options': parts[5] if len(parts) > 5 else '',
                            'secure': True,
                            'issue': None
                        }

                        # FIX 1: Skip protected mounts
                        if mount_data['mount'] in PROTECTED_MOUNTS:
                            mount_data['secure'] = True
                            mounts.append(mount_data)
                            continue

                        options = mount_data['options'].split(',')
                        if 'noexec' not in options and mount_data['mount'] in ['/tmp', '/var/tmp', '/dev/shm']:
                            mount_data['secure'] = False
                            mount_data['issue'] = 'noexec missing on temp directory'
                        if 'nosuid' not in options and mount_data['mount'] in ['/tmp', '/var/tmp']:
                            mount_data['secure'] = False
                            mount_data['issue'] = 'nosuid missing on temp directory'
                        if 'nodev' not in options and mount_data['mount'] in ['/tmp', '/dev/shm']:
                            mount_data['secure'] = False
                            mount_data['issue'] = 'nodev missing on temp directory'

                        if mount_data['mount'].startswith('/home'):
                            if 'nosuid' not in options:
                                mount_data['secure'] = False
                                mount_data['issue'] = 'nosuid missing on /home'

                        mounts.append(mount_data)

    except subprocess.TimeoutExpired:
        logging.getLogger(__name__).warning("mount command timed out")
    except Exception as e:
        logging.getLogger(__name__).debug(f"Error checking mounts: {e}")

    return mounts


def _check_fstab() -> List[Dict]:
    """Check /etc/fstab entries"""
    entries = []

    fstab_file = '/etc/fstab'

    if not os.path.exists(fstab_file):
        return entries

    try:
        with open(fstab_file, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue

                parts = line.split()
                if len(parts) >= 4:
                    entry = {
                        'device': parts[0],
                        'mount': parts[1],
                        'type': parts[2],
                        'options': parts[3],
                        'noexec': 'noexec' in parts[3],
                        'nosuid': 'nosuid' in parts[3],
                        'nodev': 'nodev' in parts[3],
                        'secure': True
                    }

                    # FIX 1: Skip protected mounts
                    if entry['mount'] in PROTECTED_MOUNTS:
                        entry['secure'] = True
                    elif entry['mount'] in ['/tmp', '/var/tmp', '/dev/shm']:
                        if not entry['noexec']:
                            entry['secure'] = False

                    entries.append(entry)

    except Exception as e:
        logging.getLogger(__name__).debug(f"Error reading fstab: {e}")

    return entries


def _check_inode_usage() -> Dict:
    """Check inode usage"""
    usage = {}

    try:
        result = subprocess.run(['df', '-i', '--output=target,ipcent'],
                              capture_output=True, text=True, timeout=10, stdin=subprocess.DEVNULL)

        if result.returncode == 0:
            lines = result.stdout.split('\n')[1:]
            for line in lines:
                if line.strip():
                    parts = line.split()
                    if len(parts) >= 2:
                        mount = parts[0]
                        percent = parts[1].strip('%')
                        try:
                            percent_val = int(percent)
                            usage[mount] = {'percent': percent_val}
                        except ValueError:
                            continue

    except subprocess.TimeoutExpired:
        logging.getLogger(__name__).warning("df -i command timed out")
    except Exception as e:
        logging.getLogger(__name__).debug(f"Error checking inode usage: {e}")

    return usage


def _check_filesystem_types() -> Dict:
    """Check filesystem types"""
    fs_types = {}

    try:
        result = subprocess.run(['df', '-T', '--output=fstype,target'],
                              capture_output=True, text=True, timeout=10, stdin=subprocess.DEVNULL)

        if result.returncode == 0:
            lines = result.stdout.split('\n')[1:]
            for line in lines:
                if line.strip():
                    parts = line.split()
                    if len(parts) >= 2:
                        fs_type = parts[0]
                        fs_types[fs_type] = fs_types.get(fs_type, 0) + 1

    except subprocess.TimeoutExpired:
        logging.getLogger(__name__).warning("df -T command timed out")
    except Exception as e:
        logging.getLogger(__name__).debug(f"Error checking filesystem types: {e}")

    return fs_types


def _check_removable_media() -> List[str]:
    """Check for removable media"""
    media = []

    try:
        result = subprocess.run(['lsblk', '-l', '-o', 'NAME,TYPE,MOUNTPOINT'],
                              capture_output=True, text=True, timeout=10, stdin=subprocess.DEVNULL)

        if result.returncode == 0:
            for line in result.stdout.split('\n')[1:]:
                if line.strip():
                    parts = line.split()
                    if len(parts) >= 3:
                        if parts[1] in ['disk', 'part'] and parts[2] != '':
                            if any(x in parts[0] for x in ['sd', 'mmc', 'usb']):
                                media.append(parts[2])

    except subprocess.TimeoutExpired:
        logging.getLogger(__name__).warning("lsblk command timed out")
    except Exception as e:
        logging.getLogger(__name__).debug(f"Error checking removable media: {e}")

    return media


# ============================================================
# FIX 1: BACKUP BEFORE MODIFYING FSTAB
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


def _backup_fstab() -> Dict[str, Any]:
    """Backup /etc/fstab with metadata."""
    result = {
        'path': '/etc/fstab',
        'backup_path': None,
        'success': False
    }
    
    try:
        BACKUP_DIR.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        
        if os.path.exists('/etc/fstab'):
            backup_path = BACKUP_DIR / f"fstab.backup_{timestamp}"
            shutil.copy2('/etc/fstab', backup_path)
            result['backup_path'] = str(backup_path)
            
            if _verify_backup(backup_path):
                result['success'] = True
                logging.getLogger(__name__).info(f"Backup created: {backup_path}")
                add_to_transaction(backup_path, Path('/etc/fstab'))

    except Exception as e:
        logging.getLogger(__name__).error(f"Failed to backup fstab: {e}")
    
    return result


# ============================================================
# FIX 2: VALIDATE FSTAB BEFORE MODIFYING
# ============================================================
def _validate_fstab() -> bool:
    """Validate fstab syntax."""
    try:
        # Use mount -a --fake to validate fstab
        result = subprocess.run(
            ['mount', '-a', '--fake'],
            capture_output=True,
            text=True,
            timeout=10, stdin=subprocess.DEVNULL)
        if result.returncode == 0:
            logging.getLogger(__name__).debug("fstab validation passed")
            return True
        else:
            logging.getLogger(__name__).error(f"fstab validation failed: {result.stderr}")
            return False
    except subprocess.TimeoutExpired:
        logging.getLogger(__name__).error("fstab validation timed out")
        return False
    except Exception as e:
        logging.getLogger(__name__).error(f"fstab validation error: {e}")
        return False


# ============================================================
# FIX 3: ROLLBACK ON FAILURE
# ============================================================
def _rollback_fstab(backup_metadata: Dict[str, Any]) -> bool:
    """Rollback fstab from backup."""
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
        logging.getLogger(__name__).info(f"Rolled back fstab: {original_path}")
        return True
    except Exception as e:
        logging.getLogger(__name__).error(f"Rollback failed for {original_path}: {e}")
        return False


# ============================================================
# FIX 4: VERIFY AFTER CHANGES
# ============================================================
def _verify_mounts() -> bool:
    """Verify mounts are working after changes."""
    try:
        result = subprocess.run(['mount'], capture_output=True, text=True, timeout=10, stdin=subprocess.DEVNULL)
        if result.returncode == 0 and result.stdout:
            return True
    except:
        pass
    return False


# ============================================================
# MEDIUM FIX 1: DRY-RUN MODE
# ============================================================
def _dry_run_disk_fix(action: str, details: str) -> bool:
    """Simulate disk/fstab modification without actually changing anything."""
    logging.getLogger(__name__).info(f"[DRY-RUN] Would perform: {action} - {details}")
    print(f"[DRY-RUN] Would perform: {action}")
    return True


# ============================================================
# MEDIUM FIX 2: CONFIRMATION BEFORE MODIFYING FSTAB
# ============================================================
def _confirm_fstab_modification(action: str) -> bool:
    """Ask for confirmation before modifying fstab."""
    print(f"\n[!] WARNING: About to modify /etc/fstab")
    print(f"    Action: {action}")
    print("    This could break boot if done incorrectly!")
    response = ui.prompt("Proceed? [y/N]: ")
    if response.lower() == 'y':
        print("\n[*] Applying fixes... please wait")
        return True
    return False


# ============================================================
# MEDIUM FIX 3: PROGRESS INDICATOR
# ============================================================
def _progress_indicator(current: int, total: int, message: str = ""):
    """Show progress during operations."""
    if total > 0:
        percent = (current / total) * 100
        print(f"\r\033[K[{current}/{total}] {percent:.1f}% - {message}", end="", flush=True)


# ============================================================
# FIX 5: SAFE FSTAB FIX WITH FILE LOCKING
# ============================================================
def _safe_fstab_fix(fix_func, dry_run: bool = False, *args) -> bool:
    """
    Safely apply an fstab fix with backup, validation, dry-run, and rollback.
    """
    logger = logging.getLogger(__name__)
    
    # Dry-run mode
    if dry_run:
        return _dry_run_disk_fix("fstab_fix", f"Would apply fix to /etc/fstab")
    
    # Confirmation
    if not _confirm_fstab_modification("Apply fstab fix"):
        logger.info("fstab fix cancelled by user")
        return False
    
    # File locking
    fstab_file = '/etc/fstab'
    lock_file = Path(fstab_file).with_suffix('.lock')
    fd = None
    try:
        fd = open(lock_file, 'w')
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except:
        logger.warning(f"Cannot acquire lock for {fstab_file}")
    
    # Step 1: Backup fstab
    backup_metadata = _backup_fstab()
    if not backup_metadata['success']:
        logger.warning("Could not backup fstab")
    
    try:
        # Step 2: Apply fix
        fix_func(*args)
        
        # Step 3: Validate fstab
        if not _validate_fstab():
            logger.error("fstab validation failed after fix")
            if backup_metadata['success']:
                _rollback_fstab(backup_metadata)
            # Release lock
            if fd:
                fcntl.flock(fd, fcntl.LOCK_UN)
                fd.close()
                if lock_file.exists():
                    lock_file.unlink()
            _log_disk_change("fstab_fix", "Validation failed", False)
            return False
        
        # Step 4: Verify mounts
        if not _verify_mounts():
            logger.error("Mounts verification failed after fix")
            if backup_metadata['success']:
                _rollback_fstab(backup_metadata)
            if fd:
                fcntl.flock(fd, fcntl.LOCK_UN)
                fd.close()
                if lock_file.exists():
                    lock_file.unlink()
            _log_disk_change("fstab_fix", "Mounts verification failed", False)
            return False
        
        # Release lock
        if fd:
            fcntl.flock(fd, fcntl.LOCK_UN)
            fd.close()
            if lock_file.exists():
                lock_file.unlink()
        
        _log_disk_change("fstab_fix", "fstab fix applied successfully", True)
        return True
        
    except Exception as e:
        logger.error(f"Error applying fstab fix: {e}")
        if backup_metadata['success']:
            _rollback_fstab(backup_metadata)
        if fd:
            fcntl.flock(fd, fcntl.LOCK_UN)
            fd.close()
            if lock_file.exists():
                lock_file.unlink()
        _log_disk_change("fstab_fix", str(e), False)
        return False


# ============================================================
# MAIN FIX FUNCTION
# ============================================================
def fix(config: dict, dry_run: bool = False, force: bool = False) -> bool:
    """
    Fix disk security issues

    Args:
        config: Configuration dictionary
        dry_run: If True, preview changes without applying
        force: If True, skip confirmation

    Returns:
        bool: True if fixes applied successfully
    """
    logger = logging.getLogger(__name__)
    logger.info("Fixing disk security issues...")

    # Check for dry-run mode (use parameter, not config)
    if dry_run:
        logger.info("DRY-RUN MODE: No changes will be applied")
        print("\n[!] DRY-RUN MODE - No changes will be applied")
        
        # Show what would be done
        disk_usage = _check_disk_usage()
        full_disks = [m for m, u in disk_usage.items() if u.get('percent', 0) >= 90]
        
        if full_disks:
            print(f"  Would warn about {len(full_disks)} full disks")
        
        if config.get('disk', {}).get('secure_tmp', True):
            print("  Would secure /tmp with noexec,nosuid,nodev")
        if config.get('disk', {}).get('secure_home', True):
            print("  Would secure /home with nosuid")
        
        print("\n[✓] Dry-run complete. No changes were made.")
        return True

    # FIX: Skip confirmation in force mode
    if not force:
        if not _confirm_fstab_modification("Apply all disk security fixes"):
            logger.info("Disk fixes cancelled by user")
            return False
    else:
        logger.info("Force mode: Applying disk fixes without confirmation")

    # Validate current fstab first
    if not _validate_fstab():
        logger.error("Current fstab is invalid. Aborting fixes.")
        return False

    try:
        begin_transaction()
        
        steps = []
        
        # Step 1: Add noexec, nosuid, nodev to /tmp
        if config.get('disk', {}).get('secure_tmp', True):
            steps.append(("Secure temp directories", _secure_temp_directories))
        
        # Step 2: Add nosuid to /home
        if config.get('disk', {}).get('secure_home', True):
            steps.append(("Secure home directory", _secure_home_directory))
        
        # Step 3: Warn about full disks
        if config.get('disk', {}).get('warn_full_disks', True):
            steps.append(("Check full disks", _warn_full_disks))
        
        total_steps = len(steps)
        for idx, (name, func) in enumerate(steps):
            _progress_indicator(idx + 1, total_steps, name)
            # For fstab modifications, use safe wrapper
            if name in ["Secure temp directories", "Secure home directory"]:
                _safe_fstab_fix(func, dry_run)
            else:
                func()
        
        print()

        # Final validation
        if not _validate_fstab():
            logger.error("fstab validation failed after all fixes")
            rollback_transaction()
            return False

        if not _verify_mounts():
            logger.error("Mounts verification failed after all fixes")
            rollback_transaction()
            return False

        commit_transaction()
        logger.info("Disk fixes applied successfully")
        print("\n Disk fixes applied successfully")
        return True

    except Exception as e:
        logger.error(f"Failed to fix disk issues: {e}")
        rollback_transaction()
        return False


def _secure_temp_directories():
    """Add secure options to /tmp in fstab"""
    fstab_file = '/etc/fstab'

    if not os.path.exists(fstab_file):
        return

    with open(fstab_file, 'r') as f:
        lines = f.readlines()

    new_lines = []
    modified = False
    
    for line in lines:
        new_line = line
        if '/tmp' in line and not line.startswith('#'):
            # FIX 1: Skip protected mounts
            if '/tmp' in PROTECTED_MOUNTS:
                continue
            if 'noexec' not in line:
                new_line = line.replace('defaults', 'defaults,noexec,nosuid,nodev')
                if 'defaults' not in line and ',' not in line:
                    parts = line.split()
                    if len(parts) >= 4:
                        parts[3] = 'defaults,noexec,nosuid,nodev'
                        new_line = '\t'.join(parts) + '\n'
                modified = True
        new_lines.append(new_line)

    if modified:
        with open(fstab_file, 'w') as f:
            f.writelines(new_lines)
        logging.getLogger(__name__).info("Temp directories secured in fstab")
        _log_disk_change("secure_temp", "Added noexec,nosuid,nodev to /tmp", True)
    else:
        logging.getLogger(__name__).debug("Temp directories already secured")


def _secure_home_directory():
    """Add nosuid to /home in fstab"""
    fstab_file = '/etc/fstab'

    if not os.path.exists(fstab_file):
        return

    with open(fstab_file, 'r') as f:
        lines = f.readlines()

    new_lines = []
    modified = False
    
    for line in lines:
        new_line = line
        if '/home' in line and not line.startswith('#'):
            # FIX 1: Skip protected mounts
            if '/home' in PROTECTED_MOUNTS:
                continue
            if 'nosuid' not in line:
                new_line = line.replace('defaults', 'defaults,nosuid')
                if 'defaults' not in line and ',' not in line:
                    parts = line.split()
                    if len(parts) >= 4:
                        parts[3] = 'defaults,nosuid'
                        new_line = '\t'.join(parts) + '\n'
                modified = True
        new_lines.append(new_line)

    if modified:
        with open(fstab_file, 'w') as f:
            f.writelines(new_lines)
        logging.getLogger(__name__).info("Home directory secured in fstab")
        _log_disk_change("secure_home", "Added nosuid to /home", True)
    else:
        logging.getLogger(__name__).debug("Home directory already secured")


def _warn_full_disks():
    """Warn about full disks"""
    disk_usage = _check_disk_usage()

    for mount, usage in disk_usage.items():
        if usage.get('percent', 0) >= 90:
            logging.getLogger(__name__).warning(
                f"CRITICAL: {mount} is {usage['percent']}% full. "
                f"Free space: {usage.get('available', '0')}"
            )
            _log_disk_change("warn_full_disk", f"{mount} is {usage['percent']}% full", True)