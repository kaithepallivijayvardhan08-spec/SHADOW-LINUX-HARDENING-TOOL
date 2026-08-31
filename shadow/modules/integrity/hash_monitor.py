#!/usr/bin/env python3
"""
Shadow Hash Monitor Module
==========================

Monitors file hashes for changes.

Security concerns:
- Hash changes → file modifications
- Suspicious file changes → compromise
- Unexpected hash changes → malware
"""

from shadow.core import ui
import os
import re
import json
import shutil
import hashlib
import logging
import subprocess
import time
import fcntl
from pathlib import Path
from datetime import datetime
from typing import Tuple, Dict, List, Optional, Any, Set

# ============================================================
# MODULE METADATA
# ============================================================
SEVERITY = "HIGH"
RECOMMENDATION = "Monitor file hashes to detect unauthorized modifications"

BACKUP_DIR = Path("/var/backups/shadow/")
CHANGES_LOG = Path("/var/log/shadow/changes.log")
HASH_DB = Path("/var/lib/shadow/hash_db.json")
HASH_DB_DIR = Path("/var/lib/shadow/")

# ============================================================
# TRANSACTION SUPPORT
# ============================================================
_transaction_active = False
_transaction_backups = []

def begin_transaction():
    """Begin a transaction for hash monitor modifications."""
    global _transaction_active, _transaction_backups
    _transaction_active = True
    _transaction_backups = []
    logging.getLogger(__name__).info("Hash monitor transaction started")

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
    logging.getLogger(__name__).info("Hash monitor transaction committed")
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

# FIX 9: Critical files to monitor
CRITICAL_FILES = [
    '/etc/passwd',
    '/etc/shadow',
    '/etc/sudoers',
    '/etc/ssh/sshd_config',
    '/etc/hosts',
    '/etc/resolv.conf',
    '/etc/login.defs',
    '/etc/security/pwquality.conf',
    '/etc/group',
    '/etc/gshadow'
]

# FIX 10: Additional files to monitor
ADDITIONAL_FILES = [
    '/etc/fstab',
    '/etc/crontab',
    '/etc/sysctl.conf',
    '/etc/profile',
    '/etc/bash.bashrc'
]

# FIX 11: Sensitive directories to monitor recursively
SENSITIVE_DIRS = [
    '/etc/ssh',
    '/etc/ssl',
    '/etc/pki',
    '/etc/systemd/system'
]

# FIX 8: LEGITIMATE FILE PATTERNS - SKIP THESE
LEGITIMATE_PATTERNS: Set[str] = {
    '.log', '.cache', '.lock', '.pid', '.socket',
    '.swp', '.bak', '.old', '.tmp', '.pyc', '.pyo'
}


def check(config: dict) -> Tuple[str, str, dict]:
    """Monitor file hashes"""
    logger = logging.getLogger(__name__)
    logger.info("Monitoring file hashes...")

    issues = []
    warnings = []
    details = {
        'monitored_files': [],
        'hash_changes': [],
        'new_files': [],
        'missing_files': [],
        'hash_db_exists': False,
        'hash_db_loaded': False,
        'total_files_scanned': 0
    }

    # FIX 6: Check if hash database exists
    if HASH_DB.exists():
        details['hash_db_exists'] = True
        # FIX 5: Load baseline
        baseline = _load_hash_db()
        details['hash_db_loaded'] = True
    else:
        warnings.append("Hash database not found. Creating baseline.")
        baseline = {}

    # FIX 9 & 10: Monitor critical files
    all_files = CRITICAL_FILES + ADDITIONAL_FILES
    details['total_files_scanned'] = len(all_files)

    for idx, file_path in enumerate(all_files):
        # LOW FIX 1: Progress indicator
        _progress_indicator(idx + 1, len(all_files), f"Checking {Path(file_path).name}")

        # FIX 8: Skip legitimate file patterns
        if _is_legitimate_file(file_path):
            continue

        if not os.path.exists(file_path):
            if file_path in baseline:
                details['missing_files'].append(file_path)
                warnings.append(f"File missing: {file_path}")
            continue

        # FIX 7: Error handling for file read
        try:
            hash_value = _get_file_hash(file_path)
            if hash_value:
                details['monitored_files'].append({
                    'path': file_path,
                    'hash': hash_value,
                    'algorithm': 'sha256'
                })

                # FIX 5: Compare with baseline
                if file_path in baseline:
                    if baseline[file_path] != hash_value:
                        details['hash_changes'].append({
                            'path': file_path,
                            'old_hash': baseline[file_path],
                            'new_hash': hash_value
                        })
                        issues.append(f"Hash changed: {file_path}")
                else:
                    details['new_files'].append(file_path)
                    if len(details['new_files']) <= 10:
                        warnings.append(f"New file: {file_path}")

        except Exception as e:
            logging.getLogger(__name__).error(f"Error processing {file_path}: {e}")
            warnings.append(f"Error processing {file_path}")


    # FIX 11: Monitor sensitive directories (recursive)
    total_dirs = len(SENSITIVE_DIRS)
    dir_idx = 0
    for sensitive_dir in SENSITIVE_DIRS:
        dir_idx += 1
        _progress_indicator(dir_idx, total_dirs, f"Scanning {sensitive_dir}")

        if os.path.exists(sensitive_dir):
            try:
                for root, dirs, files in os.walk(sensitive_dir):
                    # Skip too many files in a directory
                    if len(files) > 100:
                        logging.getLogger(__name__).debug(f"Directory {root} has {len(files)} files, limiting scan")
                        files = files[:100]

                    for file in files:
                        # FIX 8: Skip legitimate file patterns
                        if _is_legitimate_file(file):
                            continue

                        file_path = os.path.join(root, file)
                        # Skip if too large (>10MB)
                        try:
                            if os.path.getsize(file_path) > 10 * 1024 * 1024:
                                continue
                        except:
                            continue

                        try:
                            hash_value = _get_file_hash(file_path)
                            if hash_value:
                                details['monitored_files'].append({
                                    'path': file_path,
                                    'hash': hash_value,
                                    'algorithm': 'sha256'
                                })
                                details['total_files_scanned'] += 1

                                # Compare with baseline
                                if file_path in baseline:
                                    if baseline[file_path] != hash_value:
                                        details['hash_changes'].append({
                                            'path': file_path,
                                            'old_hash': baseline[file_path],
                                            'new_hash': hash_value
                                        })
                                        if len(details['hash_changes']) < 20:
                                            warnings.append(f"Hash changed: {file_path}")
                                else:
                                    if len(details['new_files']) < 20:
                                        details['new_files'].append(file_path)
                        except Exception as e:
                            continue
            except Exception as e:
                logging.getLogger(__name__).debug(f"Error scanning {sensitive_dir}: {e}")


    # FIX 8: Log hash changes
    if details['hash_changes']:
        logger.warning(f"Found {len(details['hash_changes'])} hash changes")
        _log_hash_changes(details['hash_changes'])

    # MEDIUM FIX 3: Log findings
    _log_hash_findings(details, issues, warnings)

    if not details['monitored_files']:
        return 'WARN', "No files monitored", details

    if issues:
        return 'FAIL', f"{len(issues)} hash changes found", details
    elif warnings:
        return 'WARN', f"{len(warnings)} hash warnings found", details
    return 'PASS', f"{len(details['monitored_files'])} files monitored, no changes", details


def _is_legitimate_file(file_path: str) -> bool:
    """Check if a file is legitimate and should be skipped."""
    file_lower = file_path.lower()
    for pattern in LEGITIMATE_PATTERNS:
        if pattern in file_lower:
            return True
    return False


def _get_file_hash(file_path: str, algorithm: str = 'sha256') -> str:
    """Get hash of file with error handling"""
    try:
        if algorithm == 'sha256':
            hash_obj = hashlib.sha256()
        elif algorithm == 'sha512':
            hash_obj = hashlib.sha512()
        elif algorithm == 'md5':
            hash_obj = hashlib.md5()
        else:
            hash_obj = hashlib.sha256()

        with open(file_path, 'rb') as f:
            for byte_block in iter(lambda: f.read(65536), b''):
                hash_obj.update(byte_block)

        return hash_obj.hexdigest()

    except PermissionError:
        logging.getLogger(__name__).warning(f"Permission denied: {file_path}")
        return ''
    except Exception as e:
        logging.getLogger(__name__).error(f"Hash failed for {file_path}: {e}")
        return ''


def _dry_run_hash_fix(action: str, details: str) -> bool:
    """Simulate hash DB modification without actually changing anything."""
    logging.getLogger(__name__).info(f"[DRY-RUN] Would perform: {action} - {details}")
    print(f"[DRY-RUN] Would perform: {action}")
    return True


def _confirm_hash_db_modification(action: str) -> bool:
    """Ask for confirmation before modifying hash database."""
    print(f"\n[!] WARNING: About to update hash database")
    print(f"    Action: {action}")
    print("    This will update the baseline for file integrity monitoring")
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
    
def _schedule_hash_monitoring() -> bool:
    """Schedule periodic hash monitoring using cron."""
    try:
        cron_file = '/etc/cron.d/shadow-hash-monitor'
        cron_content = """# Shadow Hash Monitor
# Run daily at 3 AM
0 3 * * * root /usr/local/bin/shadow --scan --hash-only > /var/log/shadow/hash_daily.log 2>&1
"""
        with open(cron_file, 'w') as f:
            f.write(cron_content)
        os.chmod(cron_file, 0o644)
        logging.getLogger(__name__).info("Hash monitoring scheduled daily at 3 AM")
        return True
    except Exception as e:
        logging.getLogger(__name__).error(f"Failed to schedule hash monitoring: {e}")
        return False


def _load_hash_db() -> Dict[str, str]:
    """Load hash database from file"""
    try:
        if HASH_DB.exists():
            with open(HASH_DB, 'r') as f:
                return json.load(f)
    except json.JSONDecodeError:
        logging.getLogger(__name__).error("Hash database corrupted")
    except Exception as e:
        logging.getLogger(__name__).error(f"Failed to load hash database: {e}")
    return {}


def _save_hash_db(hashes: Dict[str, str]) -> bool:
    """Save hash database to file"""
    try:
        HASH_DB_DIR.mkdir(parents=True, exist_ok=True)
        with open(HASH_DB, 'w') as f:
            json.dump(hashes, f, indent=2, sort_keys=True)
        logging.getLogger(__name__).info(f"Hash database saved: {HASH_DB}")
        return True
    except Exception as e:
        logging.getLogger(__name__).error(f"Failed to save hash database: {e}")
        return False


def _log_hash_changes(changes: List[Dict]):
    """Log hash changes for audit trail"""
    try:
        BACKUP_DIR.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_file = BACKUP_DIR / "hash_changes.log"
        
        with open(log_file, 'a') as f:
            f.write(f"\n=== HASH CHANGES: {timestamp} ===\n")
            f.write(f"Total changes: {len(changes)}\n")
            for change in changes[:20]:
                f.write(f"File: {change['path']}\n")
                f.write(f"  Old: {change['old_hash'][:16]}...\n")
                f.write(f"  New: {change['new_hash'][:16]}...\n")
            if len(changes) > 20:
                f.write(f"... and {len(changes) - 20} more changes\n")

        logging.getLogger(__name__).info(f"Hash changes logged: {log_file}")
    except Exception as e:
        logging.getLogger(__name__).error(f"Failed to log hash changes: {e}")


def _log_hash_findings(details: Dict, issues: List[str], warnings: List[str]):
    """Log hash monitoring findings for audit trail."""
    try:
        CHANGES_LOG.parent.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        with open(CHANGES_LOG, 'a') as f:
            f.write(f"{timestamp} - Hash Monitor Results:\n")
            f.write(f"  Monitored Files: {len(details.get('monitored_files', []))}\n")
            f.write(f"  Hash Changes: {len(details.get('hash_changes', []))}\n")
            f.write(f"  New Files: {len(details.get('new_files', []))}\n")
            f.write(f"  Missing Files: {len(details.get('missing_files', []))}\n")
            f.write(f"  Hash DB Exists: {details.get('hash_db_exists', False)}\n")
            
            for issue in issues:
                f.write(f"  ISSUE: {issue}\n")
            for warning in warnings[:10]:
                f.write(f"  WARNING: {warning}\n")
            if len(warnings) > 10:
                f.write(f"  ... and {len(warnings) - 10} more warnings\n")
    except Exception as e:
        logging.getLogger(__name__).warning(f"Failed to log hash findings: {e}")


def _verify_backup(backup_path: Path) -> bool:
    """Verify that a backup was created successfully."""
    if not backup_path.exists():
        logging.getLogger(__name__).error(f"Backup not found: {backup_path}")
        return False
    logging.getLogger(__name__).debug(f"Backup verified: {backup_path}")
    return True


def _backup_hash_db() -> Dict[str, Any]:
    """Backup hash database."""
    result = {
        'backup_path': None,
        'success': False,
        'files_backed_up': []
    }
    
    try:
        BACKUP_DIR.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        backup_path = BACKUP_DIR / f"hash_db_backup_{timestamp}"
        
        if HASH_DB.exists():
            shutil.copy2(HASH_DB, backup_path)
            result['files_backed_up'].append('hash_db.json')
        
        result['backup_path'] = str(backup_path)
        result['success'] = True
        logging.getLogger(__name__).info(f"Hash DB backup created: {backup_path}")
        add_to_transaction(backup_path, HASH_DB)

    except Exception as e:
        logging.getLogger(__name__).error(f"Failed to backup hash DB: {e}")
    
    return result


def _validate_hash_db(hashes: Dict[str, str]) -> Tuple[bool, str]:
    """Validate hash database."""
    logger = logging.getLogger(__name__)
    
    if not hashes:
        return False, "Hash database is empty"
    
    valid_count = 0
    invalid_count = 0
    for key, value in hashes.items():
        if not isinstance(key, str) or not isinstance(value, str):
            invalid_count += 1
            continue
        if len(value) != 64:
            invalid_count += 1
            logger.warning(f"Hash for {key} has unexpected length: {len(value)}")
        else:
            valid_count += 1
    
    if valid_count == 0:
        return False, "Hash database has no valid entries"
    
    if invalid_count > 0:
        logger.warning(f"Hash database has {invalid_count} invalid entries")
    
    return True, f"Hash database valid ({valid_count} entries)"


def _rollback_hash_db(backup_path: Path) -> bool:
    """Rollback hash database from backup."""
    if not backup_path.exists():
        logging.getLogger(__name__).error(f"Backup not found: {backup_path}")
        return False
    
    try:
        if backup_path.is_file():
            shutil.copy2(backup_path, HASH_DB)
        else:
            for file in backup_path.iterdir():
                if file.is_file() and file.name == 'hash_db.json':
                    shutil.copy2(file, HASH_DB)
                    break
        
        logging.getLogger(__name__).info(f"Rolled back hash DB from: {backup_path}")
        return True
    except Exception as e:
        logging.getLogger(__name__).error(f"Rollback failed: {e}")
        return False


def _verify_hash_db() -> Tuple[bool, str]:
    """Verify hash database is accessible."""
    try:
        if not HASH_DB.exists():
            return False, "Hash database file missing"
        
        hashes = _load_hash_db()
        if not hashes:
            return False, "Hash database is empty or corrupted"
        
        return True, "Hash database verified"
    except Exception as e:
        return False, f"Verification error: {e}"


def _detect_hash_changes(current_hashes: Dict[str, str], baseline: Dict[str, str]) -> Dict[str, Dict]:
    """Detect hash changes between current and baseline."""
    changes = {}
    
    for file_path, current_hash in current_hashes.items():
        if file_path in baseline and baseline[file_path] != current_hash:
            changes[file_path] = {
                'old': baseline[file_path],
                'new': current_hash
            }
    
    return changes


def _update_hash_db() -> bool:
    """Update hash database with current file hashes."""
    logger = logging.getLogger(__name__)
    
    current_hashes = {}
    all_files = CRITICAL_FILES + ADDITIONAL_FILES
    
    total_files = len(all_files)
    for idx, file_path in enumerate(all_files):
        _progress_indicator(idx + 1, total_files, f"Hashing {Path(file_path).name}")
        
        if os.path.exists(file_path):
            hash_value = _get_file_hash(file_path)
            if hash_value:
                current_hashes[file_path] = hash_value
        
    for sensitive_dir in SENSITIVE_DIRS:
        if os.path.exists(sensitive_dir):
            try:
                for root, dirs, files in os.walk(sensitive_dir):
                    for file in files[:50]:
                        if _is_legitimate_file(file):
                            continue
                        file_path = os.path.join(root, file)
                        try:
                            if os.path.getsize(file_path) > 10 * 1024 * 1024:
                                continue
                            hash_value = _get_file_hash(file_path)
                            if hash_value:
                                current_hashes[file_path] = hash_value
                        except:
                            continue
            except:
                continue
    
    if not current_hashes:
        logger.warning("No hashes generated")
        return False
    
    return _save_hash_db(current_hashes)


def fix(config: dict, dry_run: bool = False, force: bool = False) -> bool:
    """
    Fix hash monitoring issues

    Args:
        config: Configuration dictionary
        dry_run: If True, preview changes without applying
        force: If True, skip confirmation

    Returns:
        bool: True if fixes applied successfully
    """
    logger = logging.getLogger(__name__)
    logger.info("Fixing hash monitoring issues...")

    # Check for dry-run mode (use parameter, not config)
    if dry_run:
        logger.info("DRY-RUN MODE: No changes will be applied")
        print("\n[!] DRY-RUN MODE - No changes will be applied")
        
        baseline = _load_hash_db()
        print(f"  Hash database exists: {HASH_DB.exists()}")
        print(f"  Baseline entries: {len(baseline)}")
        print(f"  Critical files: {len(CRITICAL_FILES)}")
        print(f"  Additional files: {len(ADDITIONAL_FILES)}")
        print(f"  Sensitive directories: {len(SENSITIVE_DIRS)}")
        
        if config.get('hash_monitor', {}).get('update_db', False):
            print("  Would update hash database")
        if config.get('hash_monitor', {}).get('schedule_monitoring', True):
            print("  Would schedule periodic monitoring")
        
        print("\n[✓] Dry-run complete. No changes were made.")
        return True

    # FIX: Skip confirmation in force mode
    if not force:
        if not _confirm_hash_db_modification("Update hash database"):
            logger.info("Hash DB update cancelled by user")
            return False
    else:
        logger.info("Force mode: Updating hash database without confirmation")

    try:
        begin_transaction()
        
        backup_metadata = _backup_hash_db()
        if not backup_metadata['success']:
            logger.warning("Could not backup hash DB")

        baseline = _load_hash_db()
        if baseline:
            is_valid, msg = _validate_hash_db(baseline)
            if not is_valid:
                logger.warning(f"Hash DB validation failed: {msg}")

        current_hashes = {}
        all_files = CRITICAL_FILES + ADDITIONAL_FILES
        
        for file_path in all_files:
            if os.path.exists(file_path):
                hash_value = _get_file_hash(file_path)
                if hash_value:
                    current_hashes[file_path] = hash_value

        if baseline and config.get('hash_monitor', {}).get('detect_changes', True):
            changes = _detect_hash_changes(current_hashes, baseline)
            if changes:
                logger.warning(f"Found {len(changes)} hash changes")
                change_list = []
                for k, v in changes.items():
                    change_list.append({
                        'path': k,
                        'old_hash': v['old'],
                        'new_hash': v['new']
                    })
                _log_hash_changes(change_list)

        if config.get('hash_monitor', {}).get('update_db', False):
            if _update_hash_db():
                logger.info("Hash database updated")
            else:
                logger.warning("Failed to update hash database")
                rollback_transaction()
                return False

        if config.get('hash_monitor', {}).get('schedule_monitoring', True):
            _schedule_hash_monitoring()

        is_verified, verify_msg = _verify_hash_db()
        if not is_verified:
            logger.warning(f"Hash DB verification failed: {verify_msg}")
            if backup_metadata['success']:
                _rollback_hash_db(Path(backup_metadata['backup_path']))
            rollback_transaction()
            return False

        commit_transaction()
        logger.info("Hash monitoring fixes applied")
        print("\n[✓] Hash monitoring fixes applied successfully")
        
        return True

    except Exception as e:
        logger.error(f"Failed to fix hash monitoring: {e}")
        if backup_metadata.get('success'):
            _rollback_hash_db(Path(backup_metadata['backup_path']))
        rollback_transaction()
        return False