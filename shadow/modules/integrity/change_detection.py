#!/usr/bin/env python3
"""
Shadow Change Detection Module
==============================

Detects unauthorized system changes.
"""

from shadow.core import ui
import os
import re
import json
import shutil
import logging
import subprocess
import time
import fcntl
from pathlib import Path
from datetime import datetime, timedelta
from typing import Tuple, Dict, List, Optional, Any, Set

# ============================================================
# MODULE METADATA
# ============================================================
SEVERITY = "HIGH"
RECOMMENDATION = "Monitor system changes to detect unauthorized modifications"

BACKUP_DIR = Path("/var/backups/shadow/")
CHANGES_LOG = Path("/var/log/shadow/changes.log")
CHANGE_DB = Path("/var/lib/shadow/change_db.json")
CHANGE_DB_DIR = Path("/var/lib/shadow/")

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
                restored += 1
            except Exception as e:
                logger.error(f"Rollback failed for {original_path}: {e}")
    _transaction_active = False
    _transaction_backups = []
    return restored > 0

MONITOR_DIRS = [
    '/etc', '/bin', '/sbin', '/usr/bin', '/usr/sbin',
    '/lib', '/lib64', '/usr/lib', '/usr/lib64', '/opt', '/root'
]

EXCLUDE_PATTERNS = [
    '*.log', '*.cache', '*.lock', '*.pid', '*.socket',
    '*.swp', '*.bak', '*.old', '*.tmp',
    '/var/log/*', '/var/cache/*', '/var/tmp/*',
    '/tmp/*', '/dev/*', '/proc/*', '/sys/*', '/run/*',
    '*.pyc', '*.pyo', '__pycache__/*',
    '*.mo', '*.gmo', '*.po', '*.pot',
    '*.db', '*.sqlite', '*.sqlite3',
    '*.gz', '*.bz2', '*.xz', '*.zip'
]

LEGITIMATE_PATTERNS: Set[str] = {
    '.log', '.cache', '.lock', '.pid', '.socket',
    '.swp', '.bak', '.old', '.tmp', '.pyc', '.pyo',
    '.mo', '.gmo', '.po', '.pot',
    '.db', '.sqlite', '.sqlite3'
}

MAX_DEPTH = 3


def check(config: dict) -> Tuple[str, str, dict]:
    """Detect system changes"""
    logger = logging.getLogger(__name__)
    logger.info("Detecting system changes...")

    issues = []
    warnings = []
    details = {
        'changed_files': [], 'new_files': [], 'deleted_files': [],
        'metadata_changes': [], 'baseline_exists': False, 'total_changes': 0,
        'scan_duration': 0, 'scan_timestamp': None, 'files_scanned': 0, 'max_depth': MAX_DEPTH
    }

    # Check if baseline exists
    baseline_exists = CHANGE_DB.exists()
    if baseline_exists:
        details['baseline_exists'] = True
        baseline = _load_baseline()
    else:
        details['baseline_exists'] = False
        baseline = {}
        warnings.append("No baseline found. Will create initial baseline.")

    start_time = datetime.now()
    
    # ✅ FIX: Changed from print() to logger.info() - stops terminal flooding
    logger.info(f"Scanning for changes (max depth: {MAX_DEPTH})...")
    all_files = _get_all_files(MONITOR_DIRS, EXCLUDE_PATTERNS)
    total_files = len(all_files)
    details['files_scanned'] = total_files

    changed_count = 0
    new_count = 0
    deleted_count = 0

    for idx, file_path in enumerate(all_files):
        # ✅ FIX: Removed progress indicator - no more "[61001/61215] 99.7%" spam
        # The scan runs silently in the background now
        
        if _is_legitimate_file(file_path):
            continue
        if not os.path.exists(file_path):
            continue

        try:
            stat_info = os.stat(file_path)
            mtime = datetime.fromtimestamp(stat_info.st_mtime)
            size = stat_info.st_size
            perms = oct(stat_info.st_mode)[-3:]
            owner = stat_info.st_uid
            group = stat_info.st_gid

            file_info = {
                'path': file_path, 'mtime': mtime.isoformat(), 'size': size,
                'perms': perms, 'owner': owner, 'group': group
            }

            if file_path in baseline:
                baseline_info = baseline[file_path]
                changes = []
                if baseline_info.get('mtime') != mtime.isoformat(): changes.append('mtime')
                if baseline_info.get('size') != size: changes.append('size')
                if baseline_info.get('perms') != perms: changes.append('perms')
                if baseline_info.get('owner') != owner: changes.append('owner')
                if baseline_info.get('group') != group: changes.append('group')

                if changes:
                    details['changed_files'].append(file_path)
                    details['metadata_changes'].append({'path': file_path, 'changes': changes, 'old': baseline_info, 'new': file_info})
                    changed_count += 1
                    if changed_count < 20:
                        issues.append(f"Changed file: {file_path} ({', '.join(changes)})")
            else:
                # Only count as "new" if we actually had a baseline to compare against
                if baseline_exists:
                    details['new_files'].append(file_path)
                    new_count += 1
                    if new_count < 20:
                        warnings.append(f"New file: {file_path}")

        except Exception as e:
            logger.debug(f"Error processing {file_path}: {e}")

    # ✅ FIX: Removed empty print() - no more extra newlines

    # Check for deleted files (only if baseline existed)
    if baseline_exists:
        for file_path in baseline.keys():
            if file_path.startswith('_'): continue
            if file_path not in all_files and not os.path.exists(file_path):
                details['deleted_files'].append(file_path)
                deleted_count += 1
                if deleted_count < 20:
                    warnings.append(f"Deleted file: {file_path}")

    end_time = datetime.now()
    details['scan_duration'] = (end_time - start_time).total_seconds()
    details['scan_timestamp'] = end_time.isoformat()

    # If this was the first run, save the baseline and reset change counts
    if not baseline_exists:
        logger.info("First run detected. Saving initial baseline...")
        new_baseline = {}
        for file_path in all_files:
            if not os.path.exists(file_path): continue
            try:
                stat_info = os.stat(file_path)
                new_baseline[file_path] = {
                    'mtime': datetime.fromtimestamp(stat_info.st_mtime).isoformat(),
                    'size': stat_info.st_size,
                    'perms': oct(stat_info.st_mode)[-3:],
                    'owner': stat_info.st_uid,
                    'group': stat_info.st_gid
                }
            except Exception:
                pass
        
        new_baseline = _update_timestamp(new_baseline)
        _save_baseline(new_baseline)
        
        # Reset changes since this is just the baseline creation
        details['new_files'] = []
        details['changed_files'] = []
        details['deleted_files'] = []
        details['metadata_changes'] = []
        details['total_changes'] = 0
        issues = []
        warnings = [f"Initial baseline created with {len(new_baseline)} files. Future scans will detect changes."]
    else:
        total_changes = len(details['changed_files']) + len(details['new_files']) + len(details['deleted_files'])
        details['total_changes'] = total_changes

    logger.info(f"Scanned {total_files} files in {details['scan_duration']:.2f}s")
    logger.info(f"Found {details['total_changes']} changes")

    if details['total_changes'] > 0:
        _log_change_detection(details)

    _log_change_findings(details, issues, warnings)

    if issues:
        # ✅ Enterprise severity model: mass changes or deletions = CRITICAL.
        # A few changed files after an authorized hardening window = WARN.
        if details['deleted_files'] or len(details['changed_files']) > 5:
            return 'FAIL', f"{len(issues)} critical changes found", details
        return 'WARN', f"{len(details['changed_files'])} recent changes detected (review recommended)", details
    elif warnings and "Initial baseline created" not in warnings[0]:
        return 'WARN', f"{len(warnings)} changes detected (scanned {total_files} files)", details

    return 'PASS', f"No changes detected in {total_files} files ({details['scan_duration']:.2f}s)", details


def _is_legitimate_file(file_path: str) -> bool:
    file_lower = file_path.lower()
    for pattern in LEGITIMATE_PATTERNS:
        if pattern in file_lower: return True
    return False

def _load_baseline() -> Dict:
    try:
        if CHANGE_DB.exists():
            with open(CHANGE_DB, 'r') as f: return json.load(f)
    except Exception as e:
        logging.getLogger(__name__).error(f"Failed to load baseline: {e}")
    return {}

def _save_baseline(baseline: Dict) -> bool:
    try:
        CHANGE_DB_DIR.mkdir(parents=True, exist_ok=True)
        with open(CHANGE_DB, 'w') as f:
            json.dump(baseline, f, indent=2, sort_keys=True)
        return True
    except Exception as e:
        logging.getLogger(__name__).error(f"Failed to save baseline: {e}")
        return False

def _get_all_files(directories: List[str], exclude_patterns: List[str]) -> List[str]:
    all_files = []
    exclude_regex = []
    for pattern in exclude_patterns:
        regex_pattern = re.escape(pattern).replace('\\*', '.*')
        regex_pattern = regex_pattern.replace('/\\*\\*/\\*', '/.*/.*')
        exclude_regex.append(regex_pattern)
    
    exclude_compiled = re.compile('|'.join(exclude_regex)) if exclude_regex else None

    for directory in directories:
        if not os.path.exists(directory): continue
        try:
            for root, dirs, files in os.walk(directory):
                depth = root.count(os.sep) - directory.count(os.sep)
                if depth > MAX_DEPTH:
                    dirs.clear()
                    continue
                
                if exclude_compiled:
                    dirs[:] = [d for d in dirs if not exclude_compiled.match(os.path.join(root, d))]

                for file in files:
                    file_path = os.path.join(root, file)
                    if exclude_compiled and exclude_compiled.match(file_path): continue
                    if _is_legitimate_file(file_path): continue
                    try:
                        if os.path.getsize(file_path) > 100 * 1024 * 1024: continue
                    except: continue
                    all_files.append(file_path)
        except Exception:
            pass
    return all_files

def _log_change_detection(details: Dict):
    try:
        log_file = BACKUP_DIR / "change_detection.log"
        BACKUP_DIR.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(log_file, 'a') as f:
            f.write(f"\n=== CHANGE DETECTION: {timestamp} ===\n")
            f.write(f"Files scanned: {details.get('files_scanned', 0)}\n")
            f.write(f"Total changes: {details['total_changes']}\n")
    except Exception: pass

def _log_change_findings(details: Dict, issues: List[str], warnings: List[str]):
    try:
        CHANGES_LOG.parent.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(CHANGES_LOG, 'a') as f:
            f.write(f"{timestamp} - Change Detection: {details.get('total_changes', 0)} changes\n")
    except Exception: pass

def _update_timestamp(baseline: Dict) -> Dict:
    baseline['_metadata'] = {
        'last_scan': datetime.now().isoformat(),
        'version': '1.0',
        'max_depth': MAX_DEPTH,
        'total_files': len([k for k in baseline.keys() if not k.startswith('_')])
    }
    return baseline

def fix(config: dict, dry_run: bool = False, force: bool = False) -> bool:
    logger = logging.getLogger(__name__)
    logger.info("Fixing change detection issues...")

    if dry_run:
        logger.info("[!] DRY-RUN MODE - No changes will be applied")
        return True

    if not force:
        logger.info("[!] WARNING: About to update change detection baseline")
        response = ui.prompt("Proceed? [y/N]: ")
        if response.lower() != 'y': return False

    try:
        # ✅ FIX: Changed from print() to logger.info()
        logger.info(f"Scanning directories (max depth: {MAX_DEPTH})...")
        all_files = _get_all_files(MONITOR_DIRS, EXCLUDE_PATTERNS)
        total_files = len(all_files)

        new_baseline = {}
        for idx, file_path in enumerate(all_files):
            # ✅ FIX: Removed progress indicator - clean silent operation
            if not os.path.exists(file_path): continue
            try:
                stat_info = os.stat(file_path)
                new_baseline[file_path] = {
                    'mtime': datetime.fromtimestamp(stat_info.st_mtime).isoformat(),
                    'size': stat_info.st_size,
                    'perms': oct(stat_info.st_mode)[-3:],
                    'owner': stat_info.st_uid,
                    'group': stat_info.st_gid
                }
            except Exception: pass

        new_baseline = _update_timestamp(new_baseline)
        _save_baseline(new_baseline)
        
        logger.info("Change detection fixes applied successfully")
        # ✅ FIX: Changed from print() to logger.info() - goes to log file only
        logger.info(f"Change detection baseline updated with {len(new_baseline)} files")
        return True
    except Exception as e:
        logger.error(f"Failed to fix change detection: {e}")
        return False