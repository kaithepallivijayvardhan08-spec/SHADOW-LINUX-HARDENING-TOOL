#!/usr/bin/env python3
"""
Shadow Package Updates Module
=============================

Checks for available system package updates.
"""

from shadow.core import ui
import os
import re
import logging
import shutil
import subprocess
import json
import time
from pathlib import Path
from datetime import datetime
from typing import Tuple, Dict, List, Optional

# ============================================================
# MODULE METADATA
# ============================================================
SEVERITY = "CRITICAL"
RECOMMENDATION = "Enable unattended-upgrades for automatic security updates"

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
                restored += 1
            except Exception as e:
                logger.error(f"Rollback failed for {original_path}: {e}")
    _transaction_active = False
    _transaction_backups = []
    return restored > 0

# ============================================================
# STRUCTURED LOGGING
# ============================================================
def _log_update_results(details: Dict, issues: List[str]):
    logger = logging.getLogger(__name__)
    log_entry = {
        "event": "package_update_check",
        "details": {
            "package_manager": details.get('package_manager', 'unknown'),
            "updates_available": details.get('updates_available', 0),
            "security_updates": details.get('security_updates', 0),
            "upgradable_packages": details.get('upgradable_packages', [])[:10]
        },
        "issues": issues,
        "timestamp": datetime.now().isoformat()
    }
    logger.info(f"PACKAGE_UPDATES: {json.dumps(log_entry)}")
    
    try:
        CHANGES_LOG.parent.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(CHANGES_LOG, 'a') as f:
            f.write(f"{timestamp} - Package Update Check Results:\n")
            f.write(f"  Package Manager: {details.get('package_manager', 'unknown')}\n")
            f.write(f"  Updates Available: {details.get('updates_available', 0)}\n")
            for issue in issues:
                f.write(f"  ISSUE: {issue}\n")
    except Exception: pass

# ============================================================
# CHECK FUNCTION
# ============================================================
def check(config: dict) -> Tuple[str, str, dict]:
    logger = logging.getLogger(__name__)
    logger.info("Checking package updates...")

    issues = []
    details = {
        'package_manager': None, 'updates_available': 0,
        'security_updates': 0, 'last_update': None,
        'upgradable_packages': [], 'offline_mode': False, 'cache_outdated': False
    }

    offline_mode = config.get('updates', {}).get('offline', False)
    details['offline_mode'] = offline_mode

    pkg_manager = _detect_package_manager()
    details['package_manager'] = pkg_manager

    if pkg_manager == 'apt':
        result = _check_apt_updates(offline_mode)
    elif pkg_manager in ['yum', 'dnf']:
        result = _check_yum_updates()
    elif pkg_manager == 'zypper':
        result = _check_zypper_updates()
    else:
        issues.append(f"Unknown package manager: {pkg_manager}")
        return 'ERROR', f"Unknown package manager: {pkg_manager}", details

    details.update(result)

    if details.get('cache_outdated'):
        issues.append("APT package cache is outdated (>7 days). Run 'sudo apt update' manually.")
    if details.get('updates_available', 0) > 0:
        issues.append(f"{details['updates_available']} package updates available")
    if details.get('security_updates', 0) > 0:
        issues.append(f"{details['security_updates']} security updates available")

    last_update = _get_last_update_time()
    details['last_update'] = last_update
    if last_update:
        days_old = (datetime.now() - last_update).days
        if days_old > 30:
            issues.append(f"System not updated in {days_old} days (last update: {last_update.strftime('%Y-%m-%d')})")

    _log_update_results(details, issues)

    if issues:
        return 'WARN', f"{len(issues)} update issues found", details
    return 'PASS', "All packages are up to date", details

def _detect_package_manager() -> str:
    if os.path.exists('/usr/bin/apt') or os.path.exists('/usr/bin/apt-get'): return 'apt'
    if os.path.exists('/usr/bin/dnf'): return 'dnf'
    if os.path.exists('/usr/bin/yum'): return 'yum'
    if os.path.exists('/usr/bin/zypper'): return 'zypper'
    return 'unknown'

# ============================================================
# ✅ FIX 11: INSTANT LOCAL CACHE CHECK (Bypasses dpkg locks)
# ============================================================
def _check_apt_updates(offline_mode: bool = False) -> Dict:
    """Check for APT updates using local cache (prevents 30-60s network timeouts and dpkg lock hangs)."""
    result = {'updates_available': 0, 'security_updates': 0, 'upgradable_packages': [], 'cache_outdated': False}

    try:
        # Check if local cache is outdated (older than 7 days)
        cache_file = '/var/cache/apt/pkgcache.bin'
        if os.path.exists(cache_file):
            cache_age = time.time() - os.path.getmtime(cache_file)
            if cache_age > (7 * 24 * 3600):
                result['cache_outdated'] = True

        # ✅ FIX: Use 'apt list --upgradable' which is instant and bypasses dpkg locks
        # We also set APT_LISTCHANGES_FRONTEND=none to prevent any interactive changelog prompts
        env_vars = os.environ.copy()
        env_vars['APT_LISTCHANGES_FRONTEND'] = 'none'
        
        cmd = subprocess.run(
            ['apt', 'list', '--upgradable'],
            capture_output=True,
            text=True,
            timeout=5,
            env=env_vars, stdin=subprocess.DEVNULL)

        # Kali/Debian security patterns
        security_patterns = ['security', '-security', 'kali-rolling', 'kali-dev']

        for line in cmd.stdout.split('\n'):
            # Output format: "package_name/kali-rolling 1.2.3 amd64 [upgradable from: 1.2.2]"
            if '/' in line and 'upgradable from' in line:
                result['updates_available'] += 1
                parts = line.split('/')
                if len(parts) >= 2:
                    pkg_name = parts[0]
                    is_security = any(pattern.lower() in line.lower() for pattern in security_patterns)
                    if is_security:
                        result['security_updates'] += 1
                    if len(result['upgradable_packages']) < 20:
                        result['upgradable_packages'].append(pkg_name)

        if len(result['upgradable_packages']) > 20:
            result['upgradable_packages'] = result['upgradable_packages'][:20]

    except subprocess.TimeoutExpired:
        logging.getLogger(__name__).error("APT update check timed out")
    except Exception as e:
        logging.getLogger(__name__).error(f"APT update check failed: {e}")

    return result

def _check_yum_updates() -> Dict:
    result = {'updates_available': 0, 'security_updates': 0, 'upgradable_packages': []}
    try:
        cmd_bin = 'dnf' if os.path.exists('/usr/bin/dnf') else 'yum'
        cmd = subprocess.run([cmd_bin, 'check-update', '--quiet'], capture_output=True, text=True, timeout=120, stdin=subprocess.DEVNULL)
        for line in cmd.stdout.split('\n'):
            if line and not line.startswith('Loaded') and not line.startswith('Last'):
                parts = line.split()
                if len(parts) >= 3:
                    result['updates_available'] += 1
                    if 'security' in line.lower():
                        result['security_updates'] += 1
                    if len(result['upgradable_packages']) < 20:
                        result['upgradable_packages'].append(parts[0])
    except Exception: pass
    return result

def _check_zypper_updates() -> Dict:
    result = {'updates_available': 0, 'security_updates': 0, 'upgradable_packages': []}
    try:
        subprocess.run(['zypper', 'refresh', '--quiet'], capture_output=True, text=True, timeout=60, stdin=subprocess.DEVNULL)
        cmd = subprocess.run(['zypper', 'list-updates', '--quiet'], capture_output=True, text=True, timeout=120, stdin=subprocess.DEVNULL)
        for line in cmd.stdout.split('\n'):
            if '|' in line and 'security' in line.lower():
                result['security_updates'] += 1
                result['updates_available'] += 1
                parts = line.split('|')
                if len(parts) >= 2 and len(result['upgradable_packages']) < 20:
                    result['upgradable_packages'].append(parts[1].strip())
    except Exception: pass
    return result

def _get_last_update_time() -> Optional[datetime]:
    try:
        history_file = '/var/log/apt/history.log'
        if os.path.exists(history_file):
            with open(history_file, 'r') as f:
                matches = re.findall(r'Start-Date: (\d{4}-\d{2}-\d{2})', f.read())
                if matches: return datetime.strptime(matches[-1], '%Y-%m-%d')
        
        cache_file = '/var/cache/apt/pkgcache.bin'
        if os.path.exists(cache_file):
            return datetime.fromtimestamp(os.path.getmtime(cache_file))
    except Exception: pass
    return None

def fix(config: dict, dry_run: bool = False, force: bool = False) -> bool:
    logger = logging.getLogger(__name__)
    if dry_run:
        print("\n[!] DRY-RUN MODE - No changes will be applied")
        return True

    if not force:
        print("\n[!] WARNING: Package update check will be performed")
        response = ui.prompt("Proceed? [y/N]: ")
        if response.lower() != 'y': return False

    try:
        begin_transaction()
        try:
            CHANGES_LOG.parent.mkdir(parents=True, exist_ok=True)
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            with open(CHANGES_LOG, 'a') as f:
                f.write(f"{timestamp} - Package Update Warning: Manual updates required\n")
        except Exception: pass
        
        commit_transaction()
        print("\n✅ Package update check completed")
        return True
    except Exception:
        rollback_transaction()
        return False