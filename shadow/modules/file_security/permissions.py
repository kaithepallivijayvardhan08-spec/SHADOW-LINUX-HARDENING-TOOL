#!/usr/bin/env python3
"""
Shadow Permissions Module
=========================

Checks file and directory permissions:
- Critical system files permissions
- World-writable files and directories
- SUID/SGID binaries
- Sticky bit on /tmp and /var/tmp
"""

from shadow.core import ui
import os
import re
import shutil
import stat
import logging
import subprocess
import tempfile
import time
import fcntl
import json
from pathlib import Path
from datetime import datetime
from typing import Tuple, Dict, List, Optional, Any

# ============================================================
# STRICT WHITELIST - ONLY THESE FILES ARE MODIFIED
# ============================================================
CRITICAL_FILES_WHITELIST = {
    '/etc/passwd': 0o644,
    '/etc/shadow': 0o600,
    '/etc/sudoers': 0o440,
    '/etc/ssh/sshd_config': 0o600,
    '/etc/security/pwquality.conf': 0o644,
    '/etc/login.defs': 0o644,
}

# ============================================================
# PROTECTED SUID BINARIES - NEVER REMOVE
# ============================================================
PROTECTED_SUID_BINARIES = [
    '/usr/bin/sudo', '/usr/bin/passwd', '/usr/bin/chsh', '/usr/bin/chfn',
    '/usr/bin/newgrp', '/usr/bin/gpasswd', '/usr/bin/mount', '/usr/bin/umount',
    '/usr/bin/pkexec', '/usr/bin/su', '/usr/bin/newuidmap', '/usr/bin/newgidmap',
    '/usr/sbin/unix_chkpwd', '/usr/lib/dbus-1.0/dbus-daemon-launch-helper',
    '/usr/lib/policykit-1/polkit-agent-helper-1', '/usr/lib/openssh/ssh-keysign',
]

BACKUP_DIR = Path("/var/backups/shadow/")
CHANGES_LOG = Path("/var/log/shadow/changes.log")

# ============================================================
# TRANSACTION SUPPORT
# ============================================================
_transaction_active = False
_transaction_backups = []

def begin_transaction():
    global _transaction_active, _transaction_backups
    _transaction_active = True
    _transaction_backups = []

def add_to_transaction(backup_path: Path, original_path: Path):
    global _transaction_backups
    if _transaction_active:
        _transaction_backups.append({'backup_path': str(backup_path), 'original_path': str(original_path)})

def commit_transaction() -> bool:
    global _transaction_active, _transaction_backups
    _transaction_active = False
    _transaction_backups = []
    return True

def rollback_transaction() -> bool:
    global _transaction_active, _transaction_backups
    logger = logging.getLogger(__name__)
    restored = 0
    for backup_info in reversed(_transaction_backups):
        backup_path = Path(backup_info['backup_path'])
        original_path = Path(backup_info['original_path'])
        if backup_path.exists():
            try:
                shutil.copy2(backup_path, original_path)
                if 'permissions' in backup_info:
                    os.chmod(original_path, backup_info['permissions'])
                restored += 1
            except Exception as e:
                logger.error(f"Rollback failed for {original_path}: {e}")
    _transaction_active = False
    _transaction_backups = []
    return restored > 0

# ============================================================
# STRUCTURED LOGGING
# ============================================================
def _log_permission_change(action: str, details: str, success: bool):
    logger = logging.getLogger(__name__)
    status = "SUCCESS" if success else "FAILED"
    log_entry = {
        "event": "permission_change", "action": action, "details": details,
        "status": status, "timestamp": datetime.now().isoformat()
    }
    logger.info(f"PERMISSION: {json.dumps(log_entry)}")
    try:
        CHANGES_LOG.parent.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(CHANGES_LOG, 'a') as f:
            f.write(f"{timestamp} - Permission: {action} - {details} ({status})\n")
    except Exception: pass

# ============================================================
# CHECK FUNCTION
# ============================================================
def check(config: dict) -> Tuple[str, str, dict]:
    logger = logging.getLogger(__name__)
    logger.info("Checking file permissions...")

    issues = []
    warnings = []
    details = {
        'critical_files': {}, 'world_writable_dirs': [],
        'suid_binaries': [], 'tmp_sticky_bit': False, 'var_tmp_sticky_bit': False,
    }

    for file_path, expected_perm in CRITICAL_FILES_WHITELIST.items():
        if not os.path.exists(file_path):
            warnings.append(f"File not found: {file_path}")
            continue
        try:
            stat_info = os.stat(file_path)
            perms = oct(stat_info.st_mode)[-3:]
            expected_str = oct(expected_perm)[-3:]
            details['critical_files'][file_path] = {'permissions': perms, 'expected': expected_str, 'secure': perms == expected_str}
            if perms != expected_str:
                issues.append(f"CRITICAL: {file_path} has insecure permissions: {perms} (expected {expected_str})")
        except Exception as e:
            details['critical_files'][file_path] = {'error': str(e), 'secure': False}

    tmp_sticky = _check_sticky_bit('/tmp')
    details['tmp_sticky_bit'] = tmp_sticky
    if not tmp_sticky: issues.append("/tmp does NOT have sticky bit set (security risk)")

    var_tmp_sticky = _check_sticky_bit('/var/tmp')
    details['var_tmp_sticky_bit'] = var_tmp_sticky
    if not var_tmp_sticky: issues.append("/var/tmp does NOT have sticky bit set (security risk)")

    suid_binaries = _find_suid_binaries()
    if suid_binaries:
        details['suid_binaries'] = suid_binaries
        for binary in suid_binaries:
            if binary in PROTECTED_SUID_BINARIES:
                warnings.append(f"SUID binary (protected): {binary}")
            else:
                warnings.append(f"SUID binary (review recommended): {binary}")

    if issues:
        critical = [i for i in issues if 'CRITICAL' in i]
        status = 'FAIL' if critical else 'WARN'
        message = f"{len(issues)} critical permission issues found" if critical else f"{len(issues)} permission issues found"
    elif warnings:
        status = 'WARN'
        message = f"{len(warnings)} permission warnings found"
    else:
        status = 'PASS'
        message = "File permissions are secure"

    return status, message, details

def _find_suid_binaries() -> List[str]:
    suid_binaries = []
    try:
        search_dirs = ['/usr/bin', '/usr/sbin', '/bin', '/sbin']
        for search_dir in search_dirs:
            if not os.path.exists(search_dir): continue
            result = subprocess.run(['find', search_dir, '-maxdepth', '2', '-type', 'f', '-perm', '-4000', '-ls'], capture_output=True, text=True, timeout=15, stdin=subprocess.DEVNULL)
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if line.strip():
                        parts = line.split()
                        if len(parts) > 10:
                            path = ' '.join(parts[10:])
                            if path not in suid_binaries: suid_binaries.append(path)
    except Exception: pass
    return suid_binaries[:20]

def _check_sticky_bit(directory: str) -> bool:
    if not os.path.exists(directory): return False
    try: return bool(os.stat(directory).st_mode & 0o1000)
    except: return False

def _verify_backup(backup_path: Path) -> bool:
    if not backup_path.exists(): return False
    if backup_path.stat().st_size == 0: return False
    return True

def _backup_permissions(file_path: str) -> Dict[str, Any]:
    result = {'path': file_path, 'backup_path': None, 'perms': None, 'uid': None, 'gid': None, 'size': None, 'success': False}
    try:
        BACKUP_DIR.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        if os.path.exists(file_path):
            backup_path = BACKUP_DIR / f"{Path(file_path).name}.backup_{timestamp}"
            shutil.copy2(file_path, backup_path)
            result['backup_path'] = str(backup_path)
            add_to_transaction(backup_path, Path(file_path))
            
            stat_info = os.stat(file_path)
            result['perms'] = oct(stat_info.st_mode)[-3:]
            result['uid'] = stat_info.st_uid
            result['gid'] = stat_info.st_gid
            
            if _verify_backup(backup_path):
                result['success'] = True
    except Exception: pass
    return result

def _validate_permission_change(file_path: str, current_perms: str, expected_perms: str) -> bool:
    unsafe_perm_combinations = [('/etc/shadow', '644'), ('/etc/sudoers', '777'), ('/etc/passwd', '777')]
    for critical_file, unsafe_perm in unsafe_perm_combinations:
        if critical_file in file_path and expected_perms == unsafe_perm: return False
    return True

def _rollback_permissions(backup_metadata: Dict[str, Any]) -> bool:
    if not backup_metadata.get('success'): return False
    backup_path = Path(backup_metadata['backup_path'])
    original_path = backup_metadata['path']
    if not backup_path.exists(): return False
    try:
        shutil.copy2(backup_path, original_path)
        if backup_metadata.get('perms'):
            os.chmod(original_path, int(backup_metadata['perms'], 8))
        if backup_metadata.get('uid') is not None and backup_metadata.get('gid') is not None:
            os.chown(original_path, backup_metadata['uid'], backup_metadata['gid'])
        return True
    except Exception: return False

def _verify_permission_change(file_path: str, expected_perms: int) -> bool:
    try:
        if not os.path.exists(file_path): return False
        current_perms = oct(os.stat(file_path).st_mode)[-3:]
        return current_perms == oct(expected_perms)[-3:]
    except Exception: return False

def _dry_run_permission_fix(action: str, details: str) -> bool:
    print(f"[DRY-RUN] Would perform: {action}")
    return True

def _confirm_permission_change(action: str, files_to_change: List[str]) -> bool:
    print(f"\n[!] WARNING: About to change permissions on {len(files_to_change)} files.")
    response = ui.prompt("Proceed? [y/N]: ")
    if response.lower() == 'y':
        print("\n[*] Applying fixes... please wait")
        return True
    return False

def _progress_indicator(current: int, total: int, message: str = ""):
    if total > 0:
        percent = (current / total) * 100
        print(f"\r\033[K[{current}/{total}] {percent:.1f}% - {message}", end="", flush=True)

def _test_login() -> bool:
    try:
        for f in ['/etc/passwd', '/etc/shadow']:
            if os.path.exists(f):
                with open(f, 'r') as file: file.read(1)
        return True
    except Exception: return False

# ✅ FIX: Merged the duplicate _safe_chmod functions into one perfect version
def _safe_chmod(file_path: str, mode: int, dry_run: bool = False) -> bool:
    """Safely change file permissions with backup, validation, rollback, and file locking."""
    logger = logging.getLogger(__name__)
    if not os.path.exists(file_path): return False
    if file_path not in CRITICAL_FILES_WHITELIST: return False
    if dry_run: return _dry_run_permission_fix("chmod", f"{file_path} → {oct(mode)[-3:]}")
    
    lock_file = Path(file_path).with_suffix('.lock')
    fd = None
    try:
        fd = open(lock_file, 'w')
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except Exception: pass
    
    backup_metadata = _backup_permissions(file_path)
    stat_info = os.stat(file_path)
    current_perms = oct(stat_info.st_mode)[-3:]
    expected_perms = oct(mode)[-3:]
    
    if current_perms == expected_perms:
        if fd: fcntl.flock(fd, fcntl.LOCK_UN); fd.close(); lock_file.unlink(missing_ok=True)
        return True
    
    if not _validate_permission_change(file_path, current_perms, expected_perms):
        if fd: fcntl.flock(fd, fcntl.LOCK_UN); fd.close(); lock_file.unlink(missing_ok=True)
        return False
    
    try:
        os.chmod(file_path, mode)
        if _verify_permission_change(file_path, mode):
            _log_permission_change("chmod", f"{file_path}: {current_perms} → {expected_perms}", True)
            return True
        else:
            if backup_metadata['success']: _rollback_permissions(backup_metadata)
            return False
    except Exception as e:
        if backup_metadata['success']: _rollback_permissions(backup_metadata)
        return False
    finally:
        if fd:
            try: fcntl.flock(fd, fcntl.LOCK_UN); fd.close(); lock_file.unlink(missing_ok=True)
            except Exception: pass

# ============================================================
# FIX FUNCTION
# ============================================================
def fix(config: dict, dry_run: bool = False, force: bool = False) -> bool:
    logger = logging.getLogger(__name__)
    logger.info("Fixing permission issues...")
    
    if dry_run:
        print("\n[!] DRY-RUN MODE - No changes will be applied")
        return True

    files_to_change = []
    for file_path, expected_perm in CRITICAL_FILES_WHITELIST.items():
        if os.path.exists(file_path):
            try:
                if oct(os.stat(file_path).st_mode)[-3:] != oct(expected_perm)[-3:]:
                    files_to_change.append(file_path)
            except: pass

    if not files_to_change:
        print("\n[✓] No permission fixes needed")
        return True

    if not force:
        if not _confirm_permission_change("Fix critical file permissions", files_to_change):
            return False

    try:
        # ✅ FIX 6: Correct progress bar math (6 files + 2 directories = 8 total steps)
        total_steps = len(CRITICAL_FILES_WHITELIST) + 2
        current_step = 0
        
        for file_path, expected_perm in CRITICAL_FILES_WHITELIST.items():
            current_step += 1
            _progress_indicator(current_step, total_steps, f"Fixing {Path(file_path).name}")
            if os.path.exists(file_path):
                _safe_chmod(file_path, expected_perm, dry_run)

        for directory in ['/tmp', '/var/tmp']:
            current_step += 1
            _progress_indicator(current_step, total_steps, f"Setting sticky bit on {directory}")
            if os.path.exists(directory):
                if not (os.stat(directory).st_mode & 0o1000):
                    os.chmod(directory, 0o1777)
        print()

        if not dry_run and not _test_login():
            return False

        suid_binaries = _find_suid_binaries()
        if suid_binaries:
            print(f"\n[!] Found {len(suid_binaries)} SUID binaries.")
            for binary in suid_binaries[:10]:
                if binary in PROTECTED_SUID_BINARIES: print(f"    ✅ {binary} (protected)")
                else: print(f"    ⚠️  {binary} (review recommended)")

        return True
    except Exception as e:
        logger.error(f"Failed to fix permissions: {e}")
        return False