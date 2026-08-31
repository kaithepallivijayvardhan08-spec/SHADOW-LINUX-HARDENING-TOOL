#!/usr/bin/env python3
"""
Shadow Systemd Timer Module
===========================

Checks systemd timers for security.

Security concerns:
- Suspicious timer units
- Unauthorized scheduled jobs
- Malicious timers
"""

from shadow.core import ui
import os
import re
import shutil
import logging
import subprocess
import time
import json
import fcntl
import tempfile
from pathlib import Path
from datetime import datetime
from typing import Tuple, Dict, List, Optional, Any, Callable

# ============================================================
# MODULE METADATA
# ============================================================
SEVERITY = "MEDIUM"
RECOMMENDATION = "Review and secure systemd timers to prevent unauthorized scheduled tasks"

BACKUP_DIR = Path("/var/backups/shadow/")
CHANGES_LOG = Path("/var/log/shadow/changes.log")
SYSTEMD_DIR = Path("/etc/systemd/system/")

# ============================================================
# TRANSACTION SUPPORT
# ============================================================
_transaction_active = False
_transaction_backups = []

def begin_transaction():
    """Begin a transaction for timer modifications."""
    global _transaction_active, _transaction_backups
    _transaction_active = True
    _transaction_backups = []
    logging.getLogger(__name__).info("Timer transaction started")

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
    logging.getLogger(__name__).info("Timer transaction committed")
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

# FIX 15: Suspicious patterns for timer content
SUSPICIOUS_PATTERNS = [
    ('curl', 'download command'),
    ('wget', 'download command'),
    ('nc', 'netcat'),
    ('bash -i', 'interactive shell'),
    ('sh -i', 'interactive shell'),
    ('python -c', 'inline python'),
    ('perl -e', 'inline perl'),
    ('rm -rf', 'dangerous removal'),
    ('chmod 777', 'world-writable permission'),
    ('chmod +x', 'executable permission'),
    ('mkfifo', 'named pipe'),
    ('telnet', 'telnet command'),
    ('ncat', 'netcat alternative'),
    ('/tmp/', 'temp directory execution'),
    ('/dev/shm/', 'shared memory execution')
]

# FIX 20: Suspicious timer name patterns
SUSPICIOUS_TIMER_NAMES = [
    'cron', 'at', 'anacron',
    'malware', 'virus', 'trojan',
    'backdoor', 'reverse', 'shell',
    'miner', 'crypto', 'xmrig'
]

# FIX 8: Legitimate timer names to skip
LEGITIMATE_TIMER_NAMES = [
    'systemd', 'apt', 'dpkg', 'logrotate', 'man-db',
    'fstrim', 'mlocate', 'unattended-upgrades'
]


# ============================================================
# FIX 8: STRUCTURED LOGGING
# ============================================================
def _log_timer_change(action: str, timer_name: str, details: str, success: bool = True):
    """Log timer modifications with structured format."""
    logger = logging.getLogger(__name__)
    status = "SUCCESS" if success else "FAILED"
    
    log_entry = {
        "event": "timer_change",
        "action": action,
        "timer": timer_name,
        "details": details,
        "status": status,
        "timestamp": datetime.now().isoformat()
    }
    logger.info(f"TIMER: {json.dumps(log_entry)}")
    
    try:
        CHANGES_LOG.parent.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(CHANGES_LOG, 'a') as f:
            f.write(f"{timestamp} | TIMER | {action} | {timer_name} | {details}\n")
    except Exception as e:
        logger.debug(f"Failed to log timer change: {e}")


def _log_timer_findings(details: Dict, issues: List[str], warnings: List[str]):
    """Log timer check findings for audit trail."""
    try:
        CHANGES_LOG.parent.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        with open(CHANGES_LOG, 'a') as f:
            f.write(f"{timestamp} - Timer Check Results:\n")
            f.write(f"  Active Timers: {len(details.get('active_timers', []))}\n")
            f.write(f"  Suspicious Timers: {len(details.get('suspicious_timers', []))}\n")
            f.write(f"  Failed Timers: {len(details.get('failed_timers', []))}\n")
            f.write(f"  Disabled Timers: {len(details.get('disabled_timers', []))}\n")
            
            for issue in issues:
                f.write(f"  ISSUE: {issue}\n")
            for warning in warnings:
                f.write(f"  WARNING: {warning}\n")
            
        logging.getLogger(__name__).debug(f"Timer findings logged to {CHANGES_LOG}")
    except Exception as e:
        logging.getLogger(__name__).warning(f"Failed to log timer findings: {e}")


# ============================================================
# PROGRESS INDICATOR
# ============================================================
def _progress_indicator(current: int, total: int, message: str = ""):
    """Show progress during operations (Silent on terminal, logged to file)."""
    if total > 0:
        percent = (current / total) * 100
        logging.getLogger(__name__).debug(f"[{current}/{total}] {percent:.1f}% - {message}")


def check(config: dict) -> Tuple[str, str, dict]:
    """Check systemd timers"""
    logger = logging.getLogger(__name__)
    logger.info("Checking systemd timers...")

    issues = []
    warnings = []
    details = {
        'active_timers': [],
        'failed_timers': [],
        'suspicious_timers': [],
        'timer_files': [],
        'timer_permissions': {},
        'timer_ownership': {},
        'timer_services': {},
        'timer_content_issues': [],
        'disabled_timers': [],
        'timer_overrides': []
    }

    # FIX 13: Check timer file permissions
    timer_files = list(SYSTEMD_DIR.glob("*.timer"))
    details['timer_files'] = [str(f) for f in timer_files]

    for timer_file in timer_files:
        if timer_file.is_file():
            perms = _get_file_permissions(str(timer_file))
            details['timer_permissions'][str(timer_file)] = perms
            if perms and perms[-1] in ['2', '6', '7']:
                issues.append(f"World-writable timer file: {timer_file.name} ({perms})")

    # FIX 14: Check timer ownership
    for timer_file in timer_files:
        if timer_file.is_file():
            owner = _get_file_owner(str(timer_file))
            details['timer_ownership'][str(timer_file)] = owner
            if owner and owner != 'root:root':
                warnings.append(f"Timer file not owned by root: {timer_file.name} ({owner})")

    # FIX 15: Check suspicious timer content
    suspicious_content = _check_suspicious_timer_content(timer_files)
    details['timer_content_issues'] = suspicious_content
    if suspicious_content:
        for timer_info in suspicious_content:
            issues.append(f"Suspicious content in timer {timer_info['file']}: {timer_info['reason']}")

    # FIX 19: Check timer overrides
    timer_overrides = _check_timer_overrides(timer_files)
    details['timer_overrides'] = timer_overrides
    if timer_overrides:
        for override in timer_overrides:
            warnings.append(f"Timer override found: {override}")

    # Get timers
    timers = _get_timers()
    details['active_timers'] = timers

    # FIX 12: Check timer services
    timer_services = _get_timer_services(timers)
    details['timer_services'] = timer_services
    for timer_name, service in timer_services.items():
        if not service:
            warnings.append(f"Timer {timer_name} has no associated service")
        else:
            service_file = SYSTEMD_DIR / service
            if not service_file.exists():
                if not service.endswith('.service'):
                    service_file = SYSTEMD_DIR / f"{service}.service"
                if not service_file.exists():
                    warnings.append(f"Timer {timer_name} points to missing service: {service}")

    # FIX 18: Check disabled timers
    disabled = _check_disabled_timers(timers)
    details['disabled_timers'] = disabled
    if disabled:
        warnings.append(f"{len(disabled)} timers are disabled")

    # Check failed timers
    failed = _check_failed_timers()
    details['failed_timers'] = failed
    if failed:
        for timer in failed:
            issues.append(f"Failed timer: {timer}")

    # FIX 5 & 20: Check suspicious timers (name + content)
    suspicious = _check_suspicious_timers(timers, timer_files)
    details['suspicious_timers'] = suspicious
    if suspicious:
        for timer in suspicious:
            issues.append(f"Suspicious timer: {timer}")

    _log_timer_findings(details, issues, warnings)

    if issues:
        return 'WARN', f"{len(issues)} timer issues found", details
    elif warnings:
        return 'WARN', f"{len(warnings)} timer warnings found", details
    return 'PASS', "Systemd timers are clean", details


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


def _get_timers() -> List[str]:
    """Get systemd timers with timeout and error handling"""
    timers = []

    try:
        result = subprocess.run(
            ['systemctl', 'list-timers', '--no-pager', '--no-legend'],
            capture_output=True,
            text=True,
            timeout=30, stdin=subprocess.DEVNULL)

        if result.returncode != 0:
            logging.getLogger(__name__).error(f"systemctl list-timers failed: {result.stderr}")
            return timers

        for line in result.stdout.split('\n'):
            if '.timer' in line:
                parts = line.split()
                if parts:
                    timer_name = parts[0]
                    if '.timer' in timer_name:
                        timers.append(timer_name)

    except subprocess.TimeoutExpired:
        logging.getLogger(__name__).error("systemctl list-timers timed out")
    except Exception as e:
        logging.getLogger(__name__).error(f"systemctl list-timers failed: {e}")

    return timers


def _get_timer_services(timers: List[str]) -> Dict[str, str]:
    """Get service associated with each timer"""
    timer_services = {}

    for timer in timers:
        try:
            result = subprocess.run(
                ['systemctl', 'show', timer, '--property=Unit'],
                capture_output=True,
                text=True,
                timeout=10, stdin=subprocess.DEVNULL)
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if line.startswith('Unit='):
                        service = line.replace('Unit=', '').strip()
                        timer_services[timer] = service
                        break
            else:
                timer_services[timer] = None
        except:
            timer_services[timer] = None

    return timer_services


def _check_disabled_timers(timers: List[str]) -> List[str]:
    """Check for disabled timers"""
    disabled = []

    for timer in timers:
        try:
            result = subprocess.run(
                ['systemctl', 'is-enabled', timer],
                capture_output=True,
                text=True,
                timeout=10, stdin=subprocess.DEVNULL)
            if result.stdout.strip() == 'disabled':
                disabled.append(timer)
        except:
            pass

    return disabled


def _check_timer_overrides(timer_files: List[Path]) -> List[str]:
    """Check for timer override directories"""
    overrides = []

    for timer_file in timer_files:
        override_dir = SYSTEMD_DIR / f"{timer_file.stem}.timer.d"
        if override_dir.exists():
            for file in override_dir.iterdir():
                if file.is_file():
                    overrides.append(f"{timer_file.name}: {file.name}")

    return overrides


def _check_suspicious_timer_content(timer_files: List[Path]) -> List[Dict]:
    """Check for suspicious content in timer files"""
    suspicious = []

    for timer_file in timer_files:
        try:
            with open(timer_file, 'r') as f:
                content = f.read()
                # FIX 8: Skip legitimate content
                if any(legit in content.lower() for legit in LEGITIMATE_TIMER_NAMES):
                    continue
                for pattern, reason in SUSPICIOUS_PATTERNS:
                    if pattern in content:
                        suspicious.append({
                            'file': timer_file.name,
                            'reason': reason,
                            'pattern': pattern
                        })
                        break
        except:
            pass

    return suspicious


def _validate_timer_syntax(timer_file: Path) -> Tuple[bool, str]:
    """Validate timer file syntax"""
    try:
        result = subprocess.run(
            ['systemd-analyze', 'verify', str(timer_file)],
            capture_output=True,
            text=True,
            timeout=10, stdin=subprocess.DEVNULL)
        if result.returncode == 0:
            return True, "Valid syntax"
        else:
            return False, f"Invalid syntax: {result.stderr}"
    except:
        return False, "Validation error"


def _check_suspicious_timers(timers: List[str], timer_files: List[Path]) -> List[str]:
    """Check for suspicious timers"""
    suspicious = []
    timer_names = [str(f.name) for f in timer_files]

    for timer in timers:
        # FIX 8: Skip legitimate timers
        if any(legit in timer.lower() for legit in LEGITIMATE_TIMER_NAMES):
            continue

        # FIX 20: Check suspicious names
        for pattern in SUSPICIOUS_TIMER_NAMES:
            if pattern in timer.lower():
                if timer not in suspicious:
                    suspicious.append(timer)
                break

        # Check if timer file exists
        timer_file = SYSTEMD_DIR / timer
        if not timer_file.exists():
            found = False
            for t in timer_names:
                if timer in t or t in timer:
                    found = True
                    break
            if not found:
                suspicious.append(f"{timer} (file missing)")
            continue

        # FIX 17: Check for suspicious paths
        try:
            result = subprocess.run(
                ['systemctl', 'show', timer, '--property=UnitPath'],
                capture_output=True,
                text=True,
                timeout=10, stdin=subprocess.DEVNULL)
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if line.startswith('UnitPath='):
                        path = line.replace('UnitPath=', '').strip()
                        if '/tmp/' in path or '/dev/shm/' in path or '/var/tmp/' in path:
                            if timer not in suspicious:
                                suspicious.append(f"{timer} (in {path})")
                        break
        except:
            pass

    return suspicious


def _check_failed_timers() -> List[str]:
    """Check for failed timers with timeout and error handling"""
    failed = []

    try:
        result = subprocess.run(
            ['systemctl', 'list-units', '--state=failed', '--no-pager', '--no-legend'],
            capture_output=True,
            text=True,
            timeout=30, stdin=subprocess.DEVNULL)

        if result.returncode == 0:
            for line in result.stdout.split('\n'):
                if '.timer' in line:
                    parts = line.split()
                    if parts:
                        failed.append(parts[0])
        else:
            logging.getLogger(__name__).error(f"systemctl list-units failed: {result.stderr}")

    except subprocess.TimeoutExpired:
        logging.getLogger(__name__).error("systemctl list-units timed out")
    except Exception as e:
        logging.getLogger(__name__).error(f"systemctl list-units failed: {e}")

    return failed


def _check_timer_dependencies(timer_names: List[str]) -> Dict[str, List[str]]:
    """Check timer dependencies"""
    dependencies = {}

    for timer in timer_names:
        try:
            result = subprocess.run(
                ['systemctl', 'list-dependencies', '--no-pager', timer],
                capture_output=True,
                text=True,
                timeout=15, stdin=subprocess.DEVNULL)
            if result.returncode == 0:
                deps = []
                for line in result.stdout.split('\n'):
                    if '.timer' in line or '.service' in line:
                        clean_line = line.strip().replace('●', '').replace('├─', '').replace('└─', '').strip()
                        if clean_line and clean_line != timer:
                            deps.append(clean_line)
                dependencies[timer] = deps
        except:
            dependencies[timer] = []

    return dependencies


def _verify_daemon_reload() -> bool:
    """Verify systemd daemon-reload succeeded"""
    try:
        result = subprocess.run(
            ['systemctl', 'is-system-running'],
            capture_output=True,
            text=True,
            timeout=10, stdin=subprocess.DEVNULL)
        return result.returncode in [0, 1]
    except:
        return False


def _validate_timer_schedule(timer_name: str) -> Tuple[bool, str]:
    """Validate timer schedule"""
    try:
        result = subprocess.run(
            ['systemctl', 'show', timer_name, '--property=NextElapseUSecRealtime'],
            capture_output=True,
            text=True,
            timeout=10, stdin=subprocess.DEVNULL)
        if result.returncode == 0:
            for line in result.stdout.split('\n'):
                if 'NextElapseUSecRealtime=' in line:
                    value = line.replace('NextElapseUSecRealtime=', '').strip()
                    if value and value != '0' and value != 'infinity':
                        return True, f"Next run: {value}"
                    else:
                        return False, "Timer not scheduled"
        return False, "Cannot determine schedule"
    except:
        return False, "Schedule validation error"


def _verify_backup(backup_path: Path) -> bool:
    """Verify that a backup was created successfully."""
    if not backup_path.exists():
        logging.getLogger(__name__).error(f"Backup not found: {backup_path}")
        return False
    logging.getLogger(__name__).debug(f"Backup verified: {backup_path}")
    return True


def _backup_timer_files(timer_names: List[str]) -> Dict[str, Any]:
    """Backup timer files."""
    result = {
        'backup_path': None,
        'success': False,
        'timer_files': []
    }
    
    try:
        BACKUP_DIR.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        backup_path = BACKUP_DIR / f"timer_backup_{timestamp}"
        backup_path.mkdir(exist_ok=True)
        
        for timer in timer_names:
            timer_file = SYSTEMD_DIR / timer
            if timer_file.exists():
                dest = backup_path / timer
                shutil.copy2(timer_file, dest)
                result['timer_files'].append(str(timer_file))
        
        result['backup_path'] = str(backup_path)
        result['success'] = True
        logging.getLogger(__name__).info(f"Timer backup created: {backup_path}")
        add_to_transaction(backup_path, SYSTEMD_DIR)

    except Exception as e:
        logging.getLogger(__name__).error(f"Failed to backup timers: {e}")
    
    return result


def _validate_timer_changes(timer_name: str) -> Tuple[bool, str]:
    """Validate that timer changes are safe."""
    logger = logging.getLogger(__name__)
    
    timer_file = SYSTEMD_DIR / timer_name
    if not timer_file.exists():
        for f in SYSTEMD_DIR.glob("*.timer"):
            if timer_name in f.name or f.name in timer_name:
                timer_file = f
                break
        else:
            return False, f"Timer file not found: {timer_name}"
    
    is_valid, msg = _validate_timer_syntax(timer_file)
    if not is_valid:
        return False, f"Timer syntax invalid: {msg}"
    
    is_scheduled, schedule_msg = _validate_timer_schedule(timer_name)
    if not is_scheduled:
        logger.warning(f"Timer {timer_name} schedule issue: {schedule_msg}")
    
    if '/etc/systemd/user/' in str(timer_file):
        logger.warning(f"User timer detected: {timer_name}")
    
    return True, "Validation passed"


def _rollback_timers(backup_path: Path) -> bool:
    """Rollback timer files from backup."""
    if not backup_path.exists():
        logging.getLogger(__name__).error(f"Backup not found: {backup_path}")
        return False
    
    try:
        for file in backup_path.iterdir():
            if file.is_file():
                dest = SYSTEMD_DIR / file.name
                shutil.copy2(file, dest)
        
        subprocess.run(['systemctl', 'daemon-reload'], capture_output=True, text=True, stdin=subprocess.DEVNULL)
        
        logging.getLogger(__name__).info(f"Rolled back timers from: {backup_path}")
        return True
    except Exception as e:
        logging.getLogger(__name__).error(f"Rollback failed: {e}")
        return False


def _verify_timers(timer_names: List[str]) -> Tuple[bool, str]:
    """Verify timers are accessible and valid."""
    try:
        result = subprocess.run(
            ['systemctl', 'list-timers', '--no-pager', '--no-legend'],
            capture_output=True,
            text=True,
            timeout=30, stdin=subprocess.DEVNULL)
        
        if result.returncode != 0:
            return False, f"systemctl list-timers failed: {result.stderr}"
        
        for timer in timer_names:
            if timer not in result.stdout:
                found = False
                for line in result.stdout.split('\n'):
                    if timer in line and '.timer' in line:
                        found = True
                        break
                if not found:
                    return False, f"Timer not found after changes: {timer}"
        
        return True, "Timers verified"
        
    except Exception as e:
        return False, f"Verification error: {e}"


def _reload_systemd() -> bool:
    """Reload systemd daemon"""
    try:
        result = subprocess.run(
            ['systemctl', 'daemon-reload'],
            capture_output=True,
            text=True,
            timeout=30, stdin=subprocess.DEVNULL)
        if result.returncode == 0:
            logging.getLogger(__name__).info("systemd daemon reloaded")
            return True
        else:
            logging.getLogger(__name__).error(f"daemon-reload failed: {result.stderr}")
            return False
    except Exception as e:
        logging.getLogger(__name__).error(f"daemon-reload error: {e}")
        return False


def _dry_run_timer_fix(action: str, details: str) -> bool:
    """Simulate timer modification without actually changing anything."""
    logging.getLogger(__name__).info(f"[DRY-RUN] Would perform: {action} - {details}")
    print(f"[DRY-RUN] Would perform: {action}")
    return True


def _confirm_timer_modification(action: str, timers: List[str]) -> bool:
    """Ask for confirmation before modifying timers."""
    print(f"\n[!] WARNING: About to modify systemd timers")
    print(f"    Action: {action}")
    print(f"    Timers: {', '.join(timers[:5])}")
    if len(timers) > 5:
        print(f"    ... and {len(timers) - 5} more")
    print("    This could affect scheduled system tasks!")
    response = ui.prompt("Proceed? [y/N]: ")
    if response.lower() == 'y':
        print("\n[*] Applying fixes... please wait")
        return True
    return False


def fix(config: dict, dry_run: bool = False, force: bool = False) -> bool:
    """
    Fix systemd timer issues

    Args:
        config: Configuration dictionary
        dry_run: If True, preview changes without applying
        force: If True, skip confirmation

    Returns:
        bool: True if fixes applied successfully
    """
    logger = logging.getLogger(__name__)
    logger.info("Fixing systemd timer issues...")

    # Check for dry-run mode (use parameter, not config)
    if dry_run:
        logger.info("DRY-RUN MODE: No changes will be applied")
        print("\n[!] DRY-RUN MODE - No changes will be applied")
        
        timers = _get_timers()
        timer_files = list(SYSTEMD_DIR.glob("*.timer"))
        suspicious = _check_suspicious_timers(timers, timer_files)
        failed = _check_failed_timers()
        
        print(f"  Active timers: {len(timers)}")
        print(f"  Suspicious timers: {len(suspicious)}")
        print(f"  Failed timers: {len(failed)}")
        
        if suspicious:
            print("  Would remove/disable suspicious timers:")
            for t in suspicious[:5]:
                print(f"    - {t}")
        
        if failed:
            print("  Would restart failed timers:")
            for t in failed[:5]:
                print(f"    - {t}")
        
        print("\n[✓] Dry-run complete. No changes were made.")
        return True

    # FIX: Skip confirmation in force mode
    if not force:
        timers_to_fix = list(set(_check_suspicious_timers(_get_timers(), list(SYSTEMD_DIR.glob("*.timer"))) + _check_failed_timers()))
        if timers_to_fix:
            if not _confirm_timer_modification("Apply timer fixes", timers_to_fix):
                logger.info("Timer fixes cancelled by user")
                return False
    else:
        logger.info("Force mode: Applying timer fixes without confirmation")

    try:
        begin_transaction()
        
        timers = _get_timers()
        timer_files = list(SYSTEMD_DIR.glob("*.timer"))
        suspicious = _check_suspicious_timers(timers, timer_files)
        failed = _check_failed_timers()

        all_timers = list(set(timers + suspicious + failed))
        timers_to_fix = list(set(suspicious + failed))

        if timers_to_fix:
            deps = _check_timer_dependencies(timers_to_fix)
            for timer, dep_list in deps.items():
                if dep_list:
                    logger.info(f"Timer {timer} depends on: {', '.join(dep_list)}")

        backup_metadata = _backup_timer_files(all_timers)
        if not backup_metadata['success']:
            logger.warning("Could not backup timers")

        fixed_issues = 0
        total_issues = len(suspicious) + len(failed)
        total_timers = len(timers_to_fix)

        for idx, timer in enumerate(timers_to_fix):
            _progress_indicator(idx + 1, total_timers, f"Validating {timer}")
            
            is_valid, msg = _validate_timer_changes(timer)
            if not is_valid:
                logger.warning(f"Timer validation failed: {msg}")
                continue

        if config.get('systemd_timer', {}).get('fix_failed', True):
            for idx, timer in enumerate(failed):
                _progress_indicator(idx + 1, len(failed), f"Fixing {timer}")
                
                if dry_run:
                    _dry_run_timer_fix("restart_timer", f"Would restart {timer}")
                    fixed_issues += 1
                    continue
                
                try:
                    subprocess.run(['systemctl', 'reset-failed', timer], capture_output=True, text=True, timeout=10, stdin=subprocess.DEVNULL)
                    subprocess.run(['systemctl', 'restart', timer], capture_output=True, text=True, timeout=10, stdin=subprocess.DEVNULL)
                    fixed_issues += 1
                    logger.info(f"Restarted failed timer: {timer}")
                    _log_timer_change("RESTART", timer, "Failed timer restarted", True)
                except Exception as e:
                    logger.error(f"Error fixing timer {timer}: {e}")

        if fixed_issues > 0:
            _reload_systemd()
            if not _verify_daemon_reload():
                logger.warning("systemd daemon may not be fully reloaded")

        is_verified, verify_msg = _verify_timers(all_timers)
        if not is_verified:
            logger.warning(f"Timer verification failed: {verify_msg}")
            if backup_metadata['success']:
                _rollback_timers(Path(backup_metadata['backup_path']))
            rollback_transaction()
            return False

        commit_transaction()
        logger.info(f"Timer fixes applied: {fixed_issues} issues fixed, {total_issues} total issues")
        print(f"\n[✓] Timer fixes applied: {fixed_issues} fixed, {total_issues - fixed_issues} failed")
        
        return True

    except Exception as e:
        logger.error(f"Failed to fix timer issues: {e}")
        if backup_metadata.get('success'):
            _rollback_timers(Path(backup_metadata['backup_path']))
        rollback_transaction()
        return False