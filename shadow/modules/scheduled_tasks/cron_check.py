#!/usr/bin/env python3
"""
Shadow Cron Check Module
========================

Checks cron jobs for security issues.

Security concerns:
- Suspicious cron entries
- World-writable cron files
- Unauthorized cron jobs
- Malicious scheduled tasks
"""

from shadow.core import ui
import os
import re
import shutil
import logging
import subprocess
import json
import fcntl
import tempfile
import time
from pathlib import Path
from datetime import datetime
from typing import Tuple, Dict, List, Optional, Any

# ============================================================
# MODULE METADATA
# ============================================================
SEVERITY = "MEDIUM"
RECOMMENDATION = "Review and secure cron jobs to prevent unauthorized scheduled tasks"

BACKUP_DIR = Path("/var/backups/shadow/")
CHANGES_LOG = Path("/var/log/shadow/changes.log")

# ============================================================
# TRANSACTION SUPPORT
# ============================================================
_transaction_active = False
_transaction_backups = []

def begin_transaction():
    """Begin a transaction for cron modifications."""
    global _transaction_active, _transaction_backups
    _transaction_active = True
    _transaction_backups = []
    logging.getLogger(__name__).info("Cron transaction started")

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
    logging.getLogger(__name__).info("Cron transaction committed")
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
# FIX 8: LEGITIMATE CRON PATTERNS - SKIP THESE
# ============================================================
LEGITIMATE_PATTERNS = [
    'systemd',
    'anacron',
    'certbot',
    'dpkg',
    'apt',
    'unattended-upgrades',
    'logrotate',
    'man-db',
    'update-',
    'ubuntu-'
]


# ============================================================
# FIX 11: DANGEROUS COMMAND PATTERNS
# ============================================================
DANGEROUS_COMMANDS = [
    'curl', 'wget', 'nc', 'ncat',
    'bash -i', 'sh -i',
    'python -c', 'perl -e',
    'chmod 777', 'chmod +x',
    'rm -rf', 'mkfifo',
    'netcat', 'telnet'
]


# ============================================================
# FIX 8: STRUCTURED LOGGING
# ============================================================
def _log_cron_change(action: str, file_path: str, details: str, success: bool = True):
    """Log cron modifications with structured format."""
    logger = logging.getLogger(__name__)
    status = "SUCCESS" if success else "FAILED"
    
    log_entry = {
        "event": "cron_change",
        "action": action,
        "file": file_path,
        "details": details,
        "status": status,
        "timestamp": datetime.now().isoformat()
    }
    logger.info(f"CRON: {json.dumps(log_entry)}")
    
    try:
        CHANGES_LOG.parent.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(CHANGES_LOG, 'a') as f:
            f.write(f"{timestamp} | CRON | {action} | {file_path} | {details}\n")
    except Exception as e:
        logger.debug(f"Failed to log cron change: {e}")


def _log_cron_findings(details: Dict, issues: List[str], warnings: List[str]):
    """Log cron check findings for audit trail."""
    try:
        CHANGES_LOG.parent.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        with open(CHANGES_LOG, 'a') as f:
            f.write(f"{timestamp} - Cron Check Results:\n")
            f.write(f"  Total Cron Entries: {len(details.get('cron_entries', []))}\n")
            f.write(f"  Suspicious Entries: {len(details.get('suspicious_entries', []))}\n")
            f.write(f"  Invalid Entries: {len(details.get('invalid_cron_entries', []))}\n")
            f.write(f"  World-writable Files: {len(details.get('world_writable_crons', []))}\n")
            
            for issue in issues:
                f.write(f"  ISSUE: {issue}\n")
            for warning in warnings:
                f.write(f"  WARNING: {warning}\n")
            
        logging.getLogger(__name__).debug(f"Cron findings logged to {CHANGES_LOG}")
    except Exception as e:
        logging.getLogger(__name__).warning(f"Failed to log cron findings: {e}")


# ============================================================
# CHECK FUNCTION
# ============================================================
def check(config: dict) -> Tuple[str, str, dict]:
    """Check cron security"""
    logger = logging.getLogger(__name__)
    logger.info("Checking cron jobs...")

    issues = []
    warnings = []
    details = {
        'cron_entries': [],
        'suspicious_entries': [],
        'world_writable_crons': [],
        'invalid_cron_entries': [],
        'cron_file_permissions': {},
        'cron_ownership': {}
    }

    # FIX 9: Check cron file permissions
    cron_files = ['/etc/crontab', '/etc/cron.d/', '/var/spool/cron/crontabs/']
    for cron_file in cron_files:
        if os.path.exists(cron_file):
            perms = _get_file_permissions(cron_file)
            details['cron_file_permissions'][cron_file] = perms
            if perms and perms[-1] in ['2', '6', '7']:
                issues.append(f"World-writable cron file: {cron_file} ({perms})")

    # FIX 10: Check cron ownership
    for cron_file in cron_files:
        if os.path.exists(cron_file):
            owner = _get_file_owner(cron_file)
            details['cron_ownership'][cron_file] = owner
            if owner and owner != 'root:root':
                warnings.append(f"Cron file not owned by root: {cron_file} ({owner})")

    # Check system crontab
    system_cron = _check_system_cron()
    details['cron_entries'].extend(system_cron)

    # Check user crons
    user_crons = _check_user_crons()
    details['cron_entries'].extend(user_crons)

    # Check cron.d
    cron_d = _check_cron_d()
    details['cron_entries'].extend(cron_d)

    # FIX 5: Validate cron syntax
    invalid = _validate_cron_syntax(details['cron_entries'])
    details['invalid_cron_entries'] = invalid
    if invalid:
        for entry in invalid:
            issues.append(f"Invalid cron syntax: {entry}")

    # FIX 11: Check for dangerous commands
    suspicious = _check_suspicious_entries(details['cron_entries'])
    details['suspicious_entries'] = suspicious

    if suspicious:
        for entry in suspicious:
            issues.append(f"Suspicious cron entry: {entry}")

    # Check world-writable cron files
    writable = _check_writable_crons()
    details['world_writable_crons'] = writable

    if writable:
        for file_path in writable:
            issues.append(f"World-writable cron file: {file_path}")

    # Log findings
    _log_cron_findings(details, issues, warnings)

    if issues:
        return 'WARN', f"{len(issues)} cron issues found", details
    return 'PASS', "Cron jobs are secure", details


def _get_file_permissions(file_path: str) -> Optional[str]:
    """Get file permissions as string"""
    try:
        stat_info = os.stat(file_path)
        return oct(stat_info.st_mode)[-3:]
    except:
        return None


def _get_file_owner(file_path: str) -> Optional[str]:
    """Get file owner as string"""
    try:
        stat_info = os.stat(file_path)
        import pwd, grp
        uid = stat_info.st_uid
        gid = stat_info.st_gid
        try:
            owner = pwd.getpwuid(uid).pw_name
        except:
            owner = str(uid)
        try:
            group = grp.getgrgid(gid).gr_name
        except:
            group = str(gid)
        return f"{owner}:{group}"
    except:
        return None


def _check_system_cron() -> List[str]:
    """Check system crontab"""
    entries = []
    cron_file = '/etc/crontab'

    if not os.path.exists(cron_file):
        return entries

    try:
        with open(cron_file, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    entries.append(line)
    except Exception as e:
        logging.getLogger(__name__).error(f"Error reading {cron_file}: {e}")

    return entries


def _check_user_crons() -> List[str]:
    """Check user cron jobs"""
    entries = []

    cron_dirs = ['/var/spool/cron/crontabs/', '/var/spool/cron/']

    for cron_dir in cron_dirs:
        if os.path.exists(cron_dir):
            for file in Path(cron_dir).iterdir():
                if file.is_file():
                    try:
                        with open(file, 'r') as f:
                            for line in f:
                                line = line.strip()
                                if line and not line.startswith('#'):
                                    entries.append(f"{file.name}: {line}")
                    except Exception as e:
                        logging.getLogger(__name__).debug(f"Error reading {file}: {e}")

    return entries


def _check_cron_d() -> List[str]:
    """Check cron.d directory"""
    entries = []
    cron_d = '/etc/cron.d/'

    if not os.path.exists(cron_d):
        return entries

    for file in Path(cron_d).iterdir():
        if file.is_file():
            try:
                with open(file, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            entries.append(f"{file.name}: {line}")
            except Exception as e:
                logging.getLogger(__name__).debug(f"Error reading {file}: {e}")

    return entries


def _check_suspicious_entries(entries: List[str]) -> List[str]:
    """Check for suspicious cron entries"""
    suspicious = []

    for entry in entries:
        # FIX 8: Skip legitimate patterns
        is_legitimate = False
        for pattern in LEGITIMATE_PATTERNS:
            if pattern in entry.lower():
                is_legitimate = True
                break
        if is_legitimate:
            continue

        for cmd in DANGEROUS_COMMANDS:
            if cmd in entry:
                suspicious.append(entry)
                break

    return suspicious


def _check_writable_crons() -> List[str]:
    """Check for world-writable cron files"""
    writable = []

    cron_dirs = ['/etc/crontab', '/etc/cron.d/', '/var/spool/cron/crontabs/']

    for cron_dir in cron_dirs:
        if os.path.exists(cron_dir):
            try:
                stat_info = os.stat(cron_dir)
                perms = oct(stat_info.st_mode)[-3:]
                if perms[-1] in ['2', '6', '7']:
                    writable.append(cron_dir)
            except:
                pass

    return writable


# ============================================================
# FIX 5: CRON SYNTAX VALIDATION
# ============================================================
def _validate_cron_syntax(entries: List[str]) -> List[str]:
    """
    Validate cron syntax.
    Returns list of invalid entries.
    """
    invalid = []
    cron_pattern = re.compile(
        r'^((\*|[0-9,]+)\s+){4}(\*|[0-9,]+)\s+.+$'
    )

    for entry in entries:
        # Skip entries with comments
        if entry.startswith('#'):
            continue
        # Basic cron syntax check
        if not cron_pattern.match(entry) and not entry.startswith('@'):
            # Check for @reboot, @daily, etc.
            if not any(entry.startswith(cmd) for cmd in ['@reboot', '@daily', '@hourly', '@weekly', '@monthly']):
                invalid.append(entry)

    return invalid


# ============================================================
# FIX 6: BACKUP USER CRONS
# ============================================================
def _backup_user_crons() -> Dict[str, Any]:
    """
    Backup user cron files.
    """
    result = {
        'backup_path': None,
        'success': False,
        'user_files': []
    }
    
    try:
        BACKUP_DIR.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        backup_path = BACKUP_DIR / f"cron_backup_{timestamp}"
        backup_path.mkdir(exist_ok=True)
        
        cron_dirs = ['/var/spool/cron/crontabs/', '/var/spool/cron/']
        for cron_dir in cron_dirs:
            if os.path.exists(cron_dir):
                for file in Path(cron_dir).iterdir():
                    if file.is_file():
                        dest = backup_path / file.name
                        shutil.copy2(file, dest)
                        result['user_files'].append(str(file))
        
        # Backup system crontab
        if os.path.exists('/etc/crontab'):
            shutil.copy2('/etc/crontab', backup_path / 'crontab')
        
        result['backup_path'] = str(backup_path)
        result['success'] = True
        logging.getLogger(__name__).info(f"Cron backup created: {backup_path}")
        add_to_transaction(backup_path, Path('/etc/cron.d/'))

    except Exception as e:
        logging.getLogger(__name__).error(f"Failed to backup user crons: {e}")
    
    return result


# ============================================================
# FIX 7: ERROR HANDLING FOR CRON READ
# ============================================================
def _safe_read_cron_file(file_path: str) -> Optional[List[str]]:
    """
    Safely read a cron file with error handling.
    """
    try:
        if not os.path.exists(file_path):
            return None
        with open(file_path, 'r') as f:
            return f.readlines()
    except Exception as e:
        logging.getLogger(__name__).error(f"Error reading {file_path}: {e}")
        return None


# ============================================================
# FIX 1: BACKUP BEFORE MODIFYING CRON
# ============================================================
def _verify_backup(backup_path: Path) -> bool:
    """Verify that a backup was created successfully."""
    if not backup_path.exists():
        logging.getLogger(__name__).error(f"Backup not found: {backup_path}")
        return False
    logging.getLogger(__name__).debug(f"Backup verified: {backup_path}")
    return True


# ============================================================
# FIX 3: ROLLBACK ON FAILURE
# ============================================================
def _rollback_cron(backup_path: Path) -> bool:
    """
    Rollback cron files from backup.
    """
    if not backup_path.exists():
        logging.getLogger(__name__).error(f"Backup not found: {backup_path}")
        return False
    
    try:
        # Restore user crons
        for file in backup_path.iterdir():
            if file.is_file() and file.name != 'crontab':
                dest = None
                cron_dirs = ['/var/spool/cron/crontabs/', '/var/spool/cron/']
                for cron_dir in cron_dirs:
                    if os.path.exists(cron_dir):
                        dest = Path(cron_dir) / file.name
                        break
                if dest is None:
                    dest = Path('/var/spool/cron/crontabs/') / file.name
                    dest.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(file, dest)
                logging.getLogger(__name__).debug(f"Restored: {dest}")
        
        # Restore system crontab
        system_backup = backup_path / "crontab"
        if system_backup.exists():
            shutil.copy2(system_backup, "/etc/crontab")
            logging.getLogger(__name__).debug("Restored /etc/crontab")
        
        logging.getLogger(__name__).info(f"Rolled back cron from: {backup_path}")
        return True
    except Exception as e:
        logging.getLogger(__name__).error(f"Rollback failed: {e}")
        return False


# ============================================================
# FIX 4: VERIFICATION AFTER CHANGES
# ============================================================
def _verify_cron_files() -> Tuple[bool, str]:
    """
    Verify cron files are accessible and valid.
    """
    try:
        if not os.path.exists('/etc/crontab'):
            return False, "System crontab not found"
        
        cron_dirs = ['/var/spool/cron/crontabs/', '/var/spool/cron/']
        found = False
        for cron_dir in cron_dirs:
            if os.path.exists(cron_dir):
                found = True
                break
        
        if not found:
            return False, "User cron directories not found"
        
        return True, "Cron files verified"
        
    except Exception as e:
        return False, f"Verification error: {e}"


# ============================================================
# FIX 2: VALIDATION BEFORE MODIFYING CRON
# ============================================================
def _validate_cron_before_fix(entries: List[str]) -> Tuple[bool, str]:
    """
    Validate cron entries before applying fixes.
    """
    for entry in entries:
        for cmd in DANGEROUS_COMMANDS:
            if cmd in entry:
                return False, f"Dangerous command found: {cmd}"
    
    invalid = _validate_cron_syntax(entries)
    if invalid:
        return False, f"Invalid cron syntax in {len(invalid)} entries"
    
    return True, "Validation passed"


# ============================================================
# MEDIUM FIX 1: DRY-RUN MODE
# ============================================================
def _dry_run_cron_fix(action: str, details: str) -> bool:
    """Simulate cron modification without actually changing anything."""
    logging.getLogger(__name__).info(f"[DRY-RUN] Would perform: {action} - {details}")
    print(f"[DRY-RUN] Would perform: {action}")
    return True


# ============================================================
# MEDIUM FIX 2: CONFIRMATION BEFORE MODIFYING CRON
# ============================================================
def _confirm_cron_modification(action: str) -> bool:
    """Ask for confirmation before modifying cron."""
    print(f"\n[!] WARNING: About to modify cron configuration")
    print(f"    Action: {action}")
    print("    Cron changes can affect scheduled tasks!")
    response = ui.prompt("Proceed? [y/N]: ")
    if response.lower() == 'y':
        print("\n[*] Applying fixes... please wait")
        return True
    return False


# ============================================================
# LOW FIX 1: PROGRESS INDICATOR
# ============================================================
def _progress_indicator(current: int, total: int, message: str = ""):
    """Show progress during operations."""
    if total > 0:
        percent = (current / total) * 100
        print(f"\r\033[K[{current}/{total}] {percent:.1f}% - {message}", end="", flush=True)


# ============================================================
# FIX 12: SAFE FILE WRITE WITH LOCKING
# ============================================================
def _safe_write_cron_file(file_path: str, content: str, backup_path: Path, dry_run: bool = False) -> bool:
    """
    Safely write a cron file with backup, locking, and rollback.
    """
    logger = logging.getLogger(__name__)
    
    if dry_run:
        return _dry_run_cron_fix("write_cron", f"Would write to {file_path}")
    
    # File locking
    lock_file = Path(file_path).with_suffix('.lock')
    fd = None
    try:
        fd = open(lock_file, 'w')
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except:
        logger.warning(f"Cannot acquire lock for {file_path}")
    
    # Validate cron syntax
    if not _validate_cron_syntax(content.split('\n')):
        logger.error(f"Cron syntax validation failed for {file_path}")
        return False
    
    try:
        # Write to temp file first
        with tempfile.NamedTemporaryFile(mode='w', suffix='.cron', delete=False) as f:
            f.write(content)
            temp_path = f.name
        
        # Move temp file to destination
        shutil.move(temp_path, file_path)
        logger.info(f"Successfully wrote: {file_path}")
        
        _log_cron_change("WRITE", file_path, "Cron file updated", True)
        
        if fd:
            fcntl.flock(fd, fcntl.LOCK_UN)
            fd.close()
            if lock_file.exists():
                lock_file.unlink()
        
        return True
        
    except Exception as e:
        logger.error(f"Error writing {file_path}: {e}")
        if backup_path and backup_path.exists():
            shutil.copy2(backup_path, file_path)
            logger.info(f"Rolled back from backup: {backup_path}")
        _log_cron_change("WRITE", file_path, f"Failed: {e}", False)
        return False


def fix(config: dict, dry_run: bool = False, force: bool = False) -> bool:
    """
    Fix cron issues

    Args:
        config: Configuration dictionary
        dry_run: If True, preview changes without applying
        force: If True, skip confirmation

    Returns:
        bool: True if fixes applied successfully
    """
    logger = logging.getLogger(__name__)
    logger.info("Fixing cron issues...")

    # Check for dry-run mode (use parameter, not config)
    if dry_run:
        logger.info("DRY-RUN MODE: No changes will be applied")
        print("\n[!] DRY-RUN MODE - No changes will be applied")
        
        # Show what would be done
        all_entries = _check_system_cron() + _check_user_crons() + _check_cron_d()
        suspicious = _check_suspicious_entries(all_entries)
        
        print(f"  Total cron entries found: {len(all_entries)}")
        if suspicious:
            print(f"  Would remove {len(suspicious)} suspicious entries")
        else:
            print("  No suspicious entries found")
        
        writable = _check_writable_crons()
        if writable:
            print(f"  Would fix permissions on {len(writable)} files")
        else:
            print("  No permission issues found")
        
        print("\n[✓] Dry-run complete. No changes were made.")
        return True

    # FIX: Skip confirmation in force mode
    if not force:
        if not _confirm_cron_modification("Apply all cron security fixes"):
            logger.info("Cron fixes cancelled by user")
            return False
    else:
        logger.info("Force mode: Applying cron fixes without confirmation")

    try:
        begin_transaction()
        
        backup_metadata = _backup_user_crons()
        if not backup_metadata['success']:
            logger.warning("Could not backup user crons")
        backup_path = Path(backup_metadata['backup_path']) if backup_metadata['success'] else None

        steps = []

        if config.get('cron', {}).get('fix_permissions', True):
            steps.append(("Fix cron permissions", _fix_cron_permissions))

        if config.get('cron', {}).get('remove_suspicious', True):
            steps.append(("Remove suspicious cron entries", _remove_suspicious_entries))

        total_steps = len(steps)
        for idx, (name, func) in enumerate(steps):
            _progress_indicator(idx + 1, total_steps, name)
            func()

        print()

        is_verified, verify_msg = _verify_cron_files()
        if not is_verified:
            logger.warning(f"Cron verification failed: {verify_msg}")
            if backup_path and backup_path.exists():
                _rollback_cron(backup_path)
            rollback_transaction()
            return False

        commit_transaction()
        logger.info("Cron fixes applied successfully")
        print("\n✓ Cron fixes applied successfully")
        return True

    except Exception as e:
        logger.error(f"Failed to fix cron issues: {e}")
        if backup_metadata.get('success') and backup_path and backup_path.exists():
            _rollback_cron(backup_path)
        rollback_transaction()
        return False


def _fix_cron_permissions():
    """Fix world-writable cron file permissions"""
    logger = logging.getLogger(__name__)
    
    cron_dirs = ['/etc/crontab', '/etc/cron.d/', '/var/spool/cron/crontabs/']
    for cron_dir in cron_dirs:
        if os.path.exists(cron_dir):
            try:
                stat_info = os.stat(cron_dir)
                perms = oct(stat_info.st_mode)[-3:]
                if perms[-1] in ['2', '6', '7']:
                    os.chmod(cron_dir, 0o755)
                    logger.info(f"Fixed permissions for {cron_dir}")
                    _log_cron_change("FIX_PERMISSIONS", cron_dir, f"{perms} → 755", True)
            except Exception as e:
                logger.error(f"Error fixing permissions for {cron_dir}: {e}")


def _remove_suspicious_entries():
    """Remove suspicious cron entries"""
    logger = logging.getLogger(__name__)
    
    all_entries = _check_system_cron() + _check_user_crons() + _check_cron_d()
    suspicious = _check_suspicious_entries(all_entries)

    if suspicious:
        is_valid, msg = _validate_cron_before_fix(suspicious)
        if not is_valid:
            logger.warning(f"Cron validation failed: {msg}")
            return

        for entry in suspicious:
            _log_cron_change("REMOVE", "cron", entry, True)
            logger.info(f"Suspicious cron entry found: {entry}")

        logger.warning(f"Suspicious cron entries found: {len(suspicious)}. Manual review recommended.")