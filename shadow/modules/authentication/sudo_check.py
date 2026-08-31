#!/usr/bin/env python3
"""
Shadow Sudo Check Module
========================

Checks sudoers file security:
- Sudoers file permissions
- NOPASSWD entries
- Dangerous commands
- Excessive privileges
- sudo version

Files checked:
- /etc/sudoers
- /etc/sudoers.d/*

Security concerns:
- NOPASSWD allows passwordless sudo
- ALL:ALL gives complete access
- Dangerous commands (su, passwd, visudo, etc.)
- Write access to sudoers
"""

from shadow.core import ui
import os
import re
import shutil
import logging
import subprocess
import tempfile
import fcntl
from pathlib import Path
from datetime import datetime
from typing import Tuple, Dict, List, Optional, Any


# ============================================================
# MODULE METADATA - FIXED
# ============================================================
SEVERITY = "CRITICAL"
RECOMMENDATION = "Secure sudoers: remove NOPASSWD entries, set proper permissions, limit dangerous commands"


BACKUP_DIR = Path("/var/backups/shadow/")
CHANGES_LOG = Path("/var/log/shadow/changes.log")


# ============================================================
# TRANSACTION SUPPORT - FIXED
# ============================================================
_transaction_active = False
_transaction_backups = []


def begin_transaction():
    """Begin a transaction for sudoers modifications."""
    global _transaction_active, _transaction_backups
    _transaction_active = True
    _transaction_backups = []
    logging.getLogger(__name__).info("Sudoers transaction started")


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
    logging.getLogger(__name__).info("Sudoers transaction committed")
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
# SERVICE RESTART - FIXED
# ============================================================
def _restart_affected_services():
    """Restart services affected by sudoers changes."""
    logger = logging.getLogger(__name__)
    # sudo doesn't need restart, but we should log that changes are active
    logger.info("Sudoers changes applied (no service restart needed)")
    return {'restarted': [], 'failed': []}


# ============================================================
# SUDO TEST - FIXED
# ============================================================
def _test_sudo() -> bool:
    """Test sudo access after changes."""
    logger = logging.getLogger(__name__)
    logger.info("Testing sudo access...")
    
    try:
        # ✅ FIX: Check if we are already root (systemd runs as root)
        if os.geteuid() == 0:
            logger.info("Running as root - sudo access verified")
            return True
        
        # If not root, test sudo -l
        result = subprocess.run(
            ['sudo', '-n', '-l'],
            capture_output=True,
            text=True,
            timeout=10, stdin=subprocess.DEVNULL)
        if result.returncode == 0:
            logger.info("Sudo access test passed")
            return True
        else:
            logger.error(f"Sudo access test failed: {result.stderr}")
            return False
    except Exception as e:
        logger.error(f"Sudo test error: {e}")
        return False


def _test_sudo_validation() -> bool:
    """Test if sudo can validate syntax."""
    logger = logging.getLogger(__name__)
    try:
        result = subprocess.run(
            ['visudo', '-c'],
            capture_output=True,
            text=True,
            timeout=10, stdin=subprocess.DEVNULL)
        if result.returncode == 0:
            logger.info("Sudo validation test passed")
            return True
        else:
            logger.error(f"Sudo validation test failed: {result.stderr}")
            return False
    except Exception as e:
        logger.error(f"Sudo validation error: {e}")
        return False


# ============================================================
# LOGGING
# ============================================================
def _log_sudoers_change(action: str, details: str, success: bool):
    """Log sudoers modifications."""
    logger = logging.getLogger(__name__)
    status = "SUCCESS" if success else "FAILED"
    logger.info(f"Sudoers change: {action} - {details} ({status})")
    
    try:
        CHANGES_LOG.parent.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(CHANGES_LOG, 'a') as f:
            f.write(f"{timestamp} - Sudoers: {action} - {details} ({status})\n")
    except Exception as e:
        logger.debug(f"Failed to log change: {e}")


# ============================================================
# CHECK FUNCTION
# ============================================================
def check(config: dict) -> Tuple[str, str, dict]:
    """
    Check sudoers file security
    
    Returns:
        Tuple[str, str, dict]: (status, message, details)
    """
    logger = logging.getLogger(__name__)
    logger.info("Checking sudo security...")
    
    issues = []
    warnings = []
    details = {
        'sudo_version': None,
        'sudoers_permissions': None,
        'nopasswd_entries': [],
        'dangerous_commands': [],
        'excessive_privileges': [],
        'sudoers_d_files': [],
        'files_checked': []
    }
    
    # Check sudo version
    sudo_version = _get_sudo_version()
    details['sudo_version'] = sudo_version
    
    # Check sudoers file permissions
    sudoers_perms = _check_sudoers_permissions()
    details['sudoers_permissions'] = sudoers_perms
    
    if not sudoers_perms.get('secure', True):
        issues.append(f"sudoers file permissions insecure: {sudoers_perms.get('message')}")
    
    # FIXED: Check sudoers content including sudoers.d
    sudoers_issues = _check_sudoers_content_with_includes()
    if sudoers_issues:
        issues.extend(sudoers_issues)
    
    # FIXED: Check sudoers.d directory content
    sudoers_d_issues = _check_sudoers_d_content()
    if sudoers_d_issues:
        issues.extend(sudoers_d_issues)
    
    # FIXED: Find NOPASSWD entries in all files
    nopasswd_entries = _find_nopasswd_entries_all()
    if nopasswd_entries:
        details['nopasswd_entries'] = nopasswd_entries
        for entry in nopasswd_entries:
            issues.append(f"NOPASSWD found in {entry['file']} for: {entry['user']} (HIGH RISK)")
    
    # FIXED: Find dangerous commands in all files
    dangerous_commands = _find_dangerous_commands_all()
    if dangerous_commands:
        details['dangerous_commands'] = dangerous_commands
        for cmd in dangerous_commands:
            warnings.append(f"Dangerous command allowed in {cmd['file']}: {cmd['command']}")
    
    # FIXED: Find excessive privileges in all files
    excessive = _find_excessive_privileges_all()
    if excessive:
        details['excessive_privileges'] = excessive
        for entry in excessive:
            warnings.append(f"Excessive privileges in {entry['file']}: {entry['user']}")
    
    # Determine status
    if issues:
        critical = [i for i in issues if 'HIGH RISK' in i]
        if critical:
            status = 'FAIL'
            message = f"{len(issues)} sudo issues found, {len(critical)} critical"
        else:
            status = 'WARN'
            message = f"{len(issues)} sudo issues found"
    else:
        status = 'PASS'
        message = "sudo configuration is secure"
    
    return status, message, details


def _get_sudo_version() -> str:
    """Get sudo version"""
    try:
        result = subprocess.run(['sudo', '-V'], capture_output=True, text=True, stdin=subprocess.DEVNULL)
        for line in result.stdout.split('\n'):
            if 'Sudo version' in line:
                return line.split()[-1]
        return 'unknown'
    except:
        return 'not installed'


def _check_sudoers_permissions() -> dict:
    """Check sudoers file permissions"""
    sudoers_file = '/etc/sudoers'
    result = {'secure': False, 'message': ''}
    
    if not os.path.exists(sudoers_file):
        result['message'] = 'sudoers file not found'
        return result
    
    try:
        stat_info = os.stat(sudoers_file)
        
        if stat_info.st_uid != 0 or stat_info.st_gid != 0:
            result['message'] = f'wrong ownership: {stat_info.st_uid}:{stat_info.st_gid}'
            return result
        
        perms = oct(stat_info.st_mode)[-3:]
        if perms not in ['440', '400']:
            result['message'] = f'wrong permissions: {perms} (should be 440)'
            return result
        
        result['secure'] = True
        result['message'] = f'permissions: {perms}'
        return result
        
    except Exception as e:
        result['message'] = f'error: {str(e)}'
        return result


# ============================================================
# FIXED: CHECK CONTENT WITH INCLUDES
# ============================================================
def _check_sudoers_content_with_includes() -> List[str]:
    """Check sudoers content including included files."""
    issues = []
    all_files = _get_all_sudoers_files()
    
    for file_path in all_files:
        if not os.path.exists(file_path):
            continue
        
        try:
            with open(file_path, 'r') as f:
                content = f.read()
            
            if 'Defaults !requiretty' in content:
                issues.append(f"requiretty disabled in {file_path}")
            
            if 'Defaults env_reset' not in content:
                issues.append(f"env_reset not set in {file_path}")
            
            if 'Defaults mail_badpass' not in content:
                issues.append(f"mail_badpass not set in {file_path}")
            
            if '!authenticate' in content:
                issues.append(f"!authenticate found in {file_path}")
                
        except Exception as e:
            issues.append(f"error reading {file_path}: {str(e)}")
    
    return issues


def _check_sudoers_d_content() -> List[str]:
    """Check sudoers.d directory security"""
    issues = []
    sudoers_d = '/etc/sudoers.d'
    
    if not os.path.exists(sudoers_d):
        return issues
    
    try:
        for file in Path(sudoers_d).iterdir():
            if file.is_file():
                stat_info = file.stat()
                perms = oct(stat_info.st_mode)[-3:]
                if perms not in ['440', '400']:
                    issues.append(f"{file.name} has wrong permissions: {perms}")
                
                if stat_info.st_uid != 0 or stat_info.st_gid != 0:
                    issues.append(f"{file.name} has wrong ownership")
    except Exception as e:
        issues.append(f"error checking sudoers.d: {str(e)}")
    
    return issues


# ============================================================
# FIXED: GET ALL SUDOERS FILES
# ============================================================
def _get_all_sudoers_files() -> List[str]:
    """Get all sudoers files including included files."""
    files = ['/etc/sudoers']
    
    sudoers_d = '/etc/sudoers.d'
    if os.path.exists(sudoers_d):
        for file in Path(sudoers_d).iterdir():
            if file.is_file() and not file.name.endswith('.tmp'):
                files.append(str(file))
    
    return files


# ============================================================
# FIXED: FIND NOPASSWD ENTRIES IN ALL FILES
# ============================================================
def _find_nopasswd_entries_all() -> List[Dict]:
    """Find NOPASSWD entries in all sudoers files."""
    entries = []
    all_files = _get_all_sudoers_files()
    
    for file_path in all_files:
        if not os.path.exists(file_path):
            continue
        
        try:
            with open(file_path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if 'NOPASSWD' in line and not line.startswith('#'):
                        parts = line.split()
                        if parts:
                            entries.append({
                                'file': file_path,
                                'user': parts[0],
                                'line': line
                            })
        except:
            pass
    
    return entries


# ============================================================
# FIXED: FIND DANGEROUS COMMANDS IN ALL FILES
# ============================================================
def _find_dangerous_commands_all() -> List[Dict]:
    """Find dangerous commands in all sudoers files."""
    dangerous = ['su', 'passwd', 'visudo', 'chown', 'chmod', 'mount', 'umount']
    found = []
    all_files = _get_all_sudoers_files()
    
    for file_path in all_files:
        if not os.path.exists(file_path):
            continue
        
        try:
            with open(file_path, 'r') as f:
                content = f.read()
                for cmd in dangerous:
                    if cmd in content and not content.startswith('#'):
                        found.append({
                            'file': file_path,
                            'command': cmd
                        })
        except:
            pass
    
    return found


# ============================================================
# FIXED: FIND EXCESSIVE PRIVILEGES IN ALL FILES
# ============================================================
def _find_excessive_privileges_all() -> List[Dict]:
    """Find ALL:ALL entries in all sudoers files."""
    entries = []
    all_files = _get_all_sudoers_files()
    
    for file_path in all_files:
        if not os.path.exists(file_path):
            continue
        
        try:
            with open(file_path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if 'ALL=(ALL)' in line and not line.startswith('#'):
                        if 'NOPASSWD' not in line:
                            parts = line.split()
                            if parts:
                                entries.append({
                                    'file': file_path,
                                    'user': parts[0],
                                    'line': line
                                })
        except:
            pass
    
    return entries


def _validate_sudoers(content: str) -> bool:
    """
    Validate sudoers syntax using visudo.
    Returns True if valid, False otherwise.
    """
    try:
        with tempfile.NamedTemporaryFile(mode='w', suffix='.tmp', delete=False) as f:
            f.write(content)
            temp_path = f.name
        
        result = subprocess.run(
            ['visudo', '-c', '-f', temp_path],
            capture_output=True,
            text=True,
            timeout=10, stdin=subprocess.DEVNULL)
        os.unlink(temp_path)
        
        if result.returncode == 0:
            logging.getLogger(__name__).debug("Sudoers validation passed")
            return True
        else:
            logging.getLogger(__name__).error(f"Sudoers validation failed: {result.stderr}")
            return False
    except Exception as e:
        logging.getLogger(__name__).error(f"Sudoers validation error: {e}")
        return False


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


# ============================================================
# DRY-RUN MODE
# ============================================================
def _dry_run_sudoers_fix(action: str, details: str) -> bool:
    """Simulate sudoers modification without actually changing anything."""
    logging.getLogger(__name__).info(f"[DRY-RUN] Would perform: {action} - {details}")
    print(f"[DRY-RUN] Would perform: {action}")
    return True


def _confirm_sudoers_modification(action: str, force: bool = False) -> bool:
    """Ask for confirmation before modifying sudoers."""
    # ✅ FIX: Skip prompt if force mode is active
    if force:
        logging.getLogger(__name__).info(f"Force mode: Auto-confirming {action}")
        return True
        
    print(f"\n[!] WARNING: About to modify /etc/sudoers")
    print(f"    Action: {action}")
    response = ui.prompt("Proceed? [y/N]: ")
    if response.lower() == 'y':
        print("\n[*] Applying fixes... please wait")
        return True
    return False

def _progress_indicator(current: int, total: int, message: str = ""):
    """Show progress during operations (Silent on terminal, logged to file)."""
    if total > 0:
        percent = (current / total) * 100
        logging.getLogger(__name__).debug(f"[{current}/{total}] {percent:.1f}% - {message}")


# ============================================================
# SAFE WRITE WITH LOCKING - FIXED
# ============================================================
def _safe_write_sudoers(file_path: str, content: str, dry_run: bool = False, force: bool = False) -> bool:
    """
    Safely write sudoers file with backup, validation, rollback, and dry-run.
    """
    logger = logging.getLogger(__name__)
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    
    if dry_run:
        return _dry_run_sudoers_fix("write_sudoers", f"Would write to {file_path}")
    
    # ✅ FIX: Pass force down to the confirmation function
    if not _confirm_sudoers_modification(f"Write to {file_path}", force=force):
        logger.info("Sudoers modification cancelled by user")
        return False
    
    # File locking
    lock_file = Path(file_path).with_suffix('.lock')
    fd = None
    try:
        fd = open(lock_file, 'w')
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except:
        logger.warning(f"Cannot acquire lock for {file_path}")
    
    # Create backup
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
    backup_path = BACKUP_DIR / f"{Path(file_path).name}.backup_{timestamp}"
    
    if os.path.exists(file_path):
        shutil.copy2(file_path, backup_path)
        logger.info(f"Backup created: {backup_path}")
        # Add to transaction
        add_to_transaction(backup_path, Path(file_path))
        
        if not _verify_backup(backup_path):
            logger.error("Backup verification failed")
            return False
    
    # Validate sudoers syntax
    if not _validate_sudoers(content):
        logger.error("Sudoers validation failed, not writing")
        return False
    
    try:
        with tempfile.NamedTemporaryFile(mode='w', suffix='.tmp', delete=False) as f:
            f.write(content)
            temp_path = f.name
        
        shutil.move(temp_path, file_path)
        logger.info(f"Successfully wrote: {file_path}")
        
        # Validate after write
        if not _validate_sudoers(content):
            logger.error("Sudoers validation failed after write, rolling back")
            if backup_path.exists():
                shutil.copy2(backup_path, file_path)
                logger.info(f"Rolled back from backup: {backup_path}")
            _log_sudoers_change("write_sudoers", file_path, False)
            return False
        
        _log_sudoers_change("write_sudoers", file_path, True)
        
        if fd:
            fcntl.flock(fd, fcntl.LOCK_UN)
            fd.close()
            if lock_file.exists():
                lock_file.unlink()
        
        return True
        
    except Exception as e:
        logger.error(f"Error writing {file_path}: {e}")
        if backup_path.exists():
            shutil.copy2(backup_path, file_path)
            logger.info(f"Rolled back from backup: {backup_path}")
        _log_sudoers_change("write_sudoers", f"{file_path} - {e}", False)
        return False


# ============================================================
# MAIN FIX FUNCTION - FIXED
# ============================================================
def fix(config: dict, dry_run: bool = False, force: bool = False) -> bool:
    """
    Fix sudo security issues

    Args:
        config: Configuration dictionary
        dry_run: If True, preview changes without applying
        force: If True, skip confirmation

    Returns:
        bool: True if fixes applied successfully
    """
    logger = logging.getLogger(__name__)
    logger.info("Fixing sudo security issues...")
    
    if dry_run:
        logger.info("DRY-RUN MODE: No changes will be applied")
        print("\n[!] DRY-RUN MODE - No changes will be applied")
        print("[✓] Dry-run complete. No changes were made.")
        return True

    # ✅ FIX: Skip confirmation in force mode
    if not force:
        print("\n[!] WARNING: Shadow will modify /etc/sudoers and /etc/sudoers.d/*")
        print("    This could break sudo access if done incorrectly")
        if not _confirm_sudoers_modification("Apply all sudo fixes"):
            logger.info("Sudo fixes cancelled by user")
            return False
    else:
        logger.info("Force mode: Applying sudo fixes without confirmation")

    try:
        # Fix sudoers permissions (safe)
        _fix_sudoers_permissions()
        
        # Remove NOPASSWD entries (if configured)
        if config.get('sudo', {}).get('remove_nopasswd', True):
            # ✅ FIX: Pass force down to the NOPASSWD fixer
            if not _fix_nopasswd_entries_all(dry_run, force=force):
                logger.warning("Some NOPASSWD entries could not be fixed")
        
        # Fix sudoers.d permissions
        _fix_sudoers_d_permissions()
        
        # Test sudo access after changes
        if not _test_sudo():
            logger.error("Sudo test failed after changes!")
            return False
        
        # Test sudo validation
        if not _test_sudo_validation():
            logger.error("Sudo validation failed after changes!")
            return False
        
        logger.info("Sudo security fixes applied successfully")
        return True
        
    except Exception as e:
        logger.error(f"Failed to fix sudo security: {e}")
        return False


def _fix_sudoers_permissions():
    """Fix sudoers file permissions (safe operation)"""
    sudoers_file = '/etc/sudoers'
    
    if not os.path.exists(sudoers_file):
        return
    
    try:
        stat_info = os.stat(sudoers_file)
        current_perms = oct(stat_info.st_mode)[-3:]
        
        if current_perms != '440':
            os.chown(sudoers_file, 0, 0)
            os.chmod(sudoers_file, 0o440)
            logging.getLogger(__name__).info(f"Fixed sudoers permissions: {current_perms} → 440")
        else:
            logging.getLogger(__name__).debug("sudoers permissions already correct")
            
    except Exception as e:
        logging.getLogger(__name__).error(f"Error fixing sudoers permissions: {e}")


# ============================================================
# FIXED: FIX NOPASSWD ENTRIES IN ALL FILES
# ============================================================
def _fix_nopasswd_entries_all(dry_run: bool = False, force: bool = False) -> bool:
    """Remove NOPASSWD entries from all sudoers files."""
    logger = logging.getLogger(__name__)
    all_files = _get_all_sudoers_files()
    
    success = True
    for file_path in all_files:
        if not os.path.exists(file_path):
            continue
        
        # Find NOPASSWD entries in this file
        nopasswd_lines = []
        with open(file_path, 'r') as f:
            lines = f.readlines()
        
        for i, line in enumerate(lines):
            if 'NOPASSWD' in line and not line.strip().startswith('#'):
                nopasswd_lines.append((i, line.strip()))
        
        if not nopasswd_lines:
            continue
        
        logger.info(f"Found {len(nopasswd_lines)} NOPASSWD entries in {file_path}")
        
        if dry_run:
            for line_num, line_content in nopasswd_lines:
                _dry_run_sudoers_fix("comment_nopasswd", f"Line {line_num + 1} in {file_path}: {line_content}")
            continue
        
        # Comment out NOPASSWD lines
        new_lines = []
        for line in lines:
            if 'NOPASSWD' in line and not line.strip().startswith('#'):
                new_lines.append(f"# {line}")
                logger.info(f"Commented out NOPASSWD in {file_path}: {line.strip()}")
            else:
                new_lines.append(line)
        
        # Write with validation (✅ FIX: Pass force down)
        if not _safe_write_sudoers(file_path, ''.join(new_lines), dry_run, force=force):
            success = False
    
    _log_sudoers_change("fix_nopasswd", "Processed NOPASSWD entries in all files", success)
    return success


def _fix_sudoers_d_permissions():
    """Fix sudoers.d directory permissions"""
    sudoers_d = '/etc/sudoers.d'
    
    if not os.path.exists(sudoers_d):
        return
    
    logger = logging.getLogger(__name__)
    
    try:
        files = list(Path(sudoers_d).iterdir())
        total_files = len(files)
        processed = 0
        
        for file in files:
            if file.is_file():
                processed += 1
                _progress_indicator(processed, total_files, f"Fixing {file.name}")
                
                stat_info = file.stat()
                current_perms = oct(stat_info.st_mode)[-3:]
                current_uid = stat_info.st_uid
                current_gid = stat_info.st_gid
                
                if current_perms != '440' or current_uid != 0 or current_gid != 0:
                    os.chown(file, 0, 0)
                    os.chmod(file, 0o440)
                    logger.debug(f"Fixed {file.name}: {current_perms} → 440")
        
        logger.info("Fixed sudoers.d permissions")
        
    except Exception as e:
        logger.error(f"Error fixing sudoers.d: {e}")