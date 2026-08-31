#!/usr/bin/env python3
"""
Shadow Package Integrity Module
===============================

Checks package integrity using system package manager verification.

Security concerns:
- Modified system binaries → possible compromise
- Corrupted packages → system instability
- Unauthorized changes → malware
"""

from shadow.core import ui
import os
import logging
import shutil
import subprocess
import json
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
    """Begin a transaction for package integrity modifications."""
    global _transaction_active, _transaction_backups
    _transaction_active = True
    _transaction_backups = []
    logging.getLogger(__name__).info("Package integrity transaction started")

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
    logging.getLogger(__name__).info("Package integrity transaction committed")
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
def _log_integrity_results(details: Dict, issues: List[str]):
    """Log package integrity check results with structured format."""
    logger = logging.getLogger(__name__)
    
    log_entry = {
        "event": "package_integrity_check",
        "details": {
            "package_manager": details.get('package_manager', 'unknown'),
            "integrity_failures": details.get('integrity_failures', 0),
            "verified_packages": details.get('verified_packages', 0),
            "debsums_installed": details.get('debsums_installed', False),
            "modified_files": details.get('modified_files', [])[:10]
        },
        "issues": issues,
        "timestamp": datetime.now().isoformat()
    }
    logger.info(f"PACKAGE_INTEGRITY: {json.dumps(log_entry)}")
    
    try:
        CHANGES_LOG.parent.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        with open(CHANGES_LOG, 'a') as f:
            f.write(f"{timestamp} - Package Integrity Check Results:\n")
            f.write(f"  Package Manager: {details.get('package_manager', 'unknown')}\n")
            f.write(f"  Integrity Failures: {details.get('integrity_failures', 0)}\n")
            f.write(f"  Verified Packages: {details.get('verified_packages', 0)}\n")
            f.write(f"  debsums Installed: {details.get('debsums_installed', False)}\n")
            
            modified_files = details.get('modified_files', [])
            if modified_files:
                f.write(f"  Modified Files: {len(modified_files)} found\n")
                for file_path in modified_files[:10]:
                    f.write(f"    - {file_path}\n")
                if len(modified_files) > 10:
                    f.write(f"    ... and {len(modified_files) - 10} more\n")
            
            for issue in issues:
                f.write(f"  ISSUE: {issue}\n")
            
        logger.debug(f"Integrity results logged to {CHANGES_LOG}")
    except Exception as e:
        logger.warning(f"Failed to log integrity results: {e}")


# ============================================================
# CHECK FUNCTION
# ============================================================
def check(config: dict) -> Tuple[str, str, dict]:
    """Check package integrity"""
    logger = logging.getLogger(__name__)
    logger.info("Checking package integrity...")

    issues = []
    warnings = []
    details = {
        'package_manager': None,
        'verified_packages': 0,
        'modified_files': [],
        'integrity_failures': 0,
        'debsums_installed': False,
        'rpm_installed': False
    }

    pkg_manager = _detect_package_manager()
    details['package_manager'] = pkg_manager

    if pkg_manager == 'apt':
        result = _check_apt_integrity()
    elif pkg_manager in ['yum', 'dnf']:
        result = _check_rpm_integrity()
    else:
        warnings.append(f"Unknown package manager: {pkg_manager}")
        return 'WARN', f"Unknown package manager: {pkg_manager}", details

    details.update(result)

    if details.get('integrity_failures', 0) > 0:
        issues.append(f"{details['integrity_failures']} integrity failures found")

    # FIX 4: Check for debsums recommendation
    if pkg_manager == 'apt' and not details.get('debsums_installed', False):
        warnings.append("debsums not installed. Install with: apt-get install debsums")

    # Log the results
    _log_integrity_results(details, issues)

    if issues:
        status = 'FAIL'
        message = f"{len(issues)} integrity issues found"
    elif warnings:
        status = 'WARN'
        message = f"{len(warnings)} integrity warnings found"
    else:
        status = 'PASS'
        message = "Package integrity verified"

    return status, message, details


def _detect_package_manager() -> str:
    """Detect the system package manager"""
    if os.path.exists('/usr/bin/apt') or os.path.exists('/usr/bin/apt-get'):
        return 'apt'
    if os.path.exists('/usr/bin/dnf'):
        return 'dnf'
    if os.path.exists('/usr/bin/yum'):
        return 'yum'
    return 'unknown'


# ============================================================
# FIX 4: CHECK APT INTEGRITY WITH IMPROVED DETECTION
# ============================================================
def _check_apt_integrity() -> Dict:
    """Check APT package integrity"""
    result = {
        'verified_packages': 0,
        'modified_files': [],
        'integrity_failures': 0,
        'debsums_installed': False
    }

    # Check if debsums is installed
    try:
        check_cmd = subprocess.run(['which', 'debsums'], capture_output=True, text=True, timeout=5, stdin=subprocess.DEVNULL)
        if check_cmd.returncode != 0:
            logging.getLogger(__name__).debug("debsums not installed")
            result['debsums_installed'] = False
            return result
        result['debsums_installed'] = True
    except Exception as e:
        logging.getLogger(__name__).debug(f"Failed to check debsums: {e}")
        return result

    try:
        # Use debsums with timeout
        cmd = subprocess.run(['debsums', '-s', '-a'], capture_output=True, text=True, timeout=300, stdin=subprocess.DEVNULL)

        for line in cmd.stdout.split('\n'):
            if line.strip():
                result['modified_files'].append(line)
                result['integrity_failures'] += 1

        # Estimate verified packages
        try:
            total_cmd = subprocess.run(['dpkg', '-l'], capture_output=True, text=True, timeout=30, stdin=subprocess.DEVNULL)
            total_packages = len([l for l in total_cmd.stdout.split('\n') if l.strip().startswith('ii')])
            result['verified_packages'] = max(0, total_packages - result['integrity_failures'])
        except:
            pass

    except subprocess.TimeoutExpired:
        logging.getLogger(__name__).error("APT integrity check timed out")
    except Exception as e:
        logging.getLogger(__name__).error(f"APT integrity check failed: {e}")

    return result


def _check_rpm_integrity() -> Dict:
    """Check RPM package integrity"""
    result = {
        'verified_packages': 0,
        'modified_files': [],
        'integrity_failures': 0,
        'rpm_installed': True
    }

    # Check if rpm is installed
    try:
        check_cmd = subprocess.run(['which', 'rpm'], capture_output=True, text=True, timeout=5, stdin=subprocess.DEVNULL)
        if check_cmd.returncode != 0:
            logging.getLogger(__name__).debug("rpm not installed")
            result['rpm_installed'] = False
            return result
    except Exception as e:
        logging.getLogger(__name__).debug(f"Failed to check rpm: {e}")
        result['rpm_installed'] = False
        return result

    try:
        # Use rpm -Va with timeout
        cmd = subprocess.run(['rpm', '-Va', '--nofiles'], capture_output=True, text=True, timeout=300, stdin=subprocess.DEVNULL)

        for line in cmd.stdout.split('\n'):
            if line.strip():
                # RPM verification output format: status + file
                # Status codes: S=Size, M=Mode, 5=MD5, D=Device, L=Link, U=User, G=Group, T=Time
                if line[0] in ['S', 'M', '5', 'D', 'L', 'U', 'G', 'T']:
                    result['modified_files'].append(line)
                    result['integrity_failures'] += 1

        # Estimate verified packages
        try:
            pkg_cmd = subprocess.run(['rpm', '-qa'], capture_output=True, text=True, timeout=30, stdin=subprocess.DEVNULL)
            total_packages = len(pkg_cmd.stdout.split('\n')) - 1
            result['verified_packages'] = max(0, total_packages - result['integrity_failures'])
        except:
            pass

    except subprocess.TimeoutExpired:
        logging.getLogger(__name__).error("RPM integrity check timed out")
    except Exception as e:
        logging.getLogger(__name__).error(f"RPM integrity check failed: {e}")

    return result


# ============================================================
# PROGRESS INDICATOR
# ============================================================
def _progress_indicator(current: int, total: int, message: str = ""):
    """Show progress during operations."""
    if total > 0:
        percent = (current / total) * 100
        print(f"\r\033[K[{current}/{total}] {percent:.1f}% - {message}", end="", flush=True)


def fix(config: dict, dry_run: bool = False, force: bool = False) -> bool:
    """
    Fix package integrity issues (warning only - requires manual investigation)

    Args:
        config: Configuration dictionary
        dry_run: If True, preview changes without applying
        force: If True, skip confirmation

    Returns:
        bool: True if fixes applied successfully
    """
    logger = logging.getLogger(__name__)
    
    # Check for dry-run mode (use parameter, not config)
    if dry_run:
        logger.info("DRY-RUN MODE: No changes will be applied")
        print("\n[!] DRY-RUN MODE - No changes will be applied")
        
        pkg_manager = _detect_package_manager()
        print(f"  Package manager: {pkg_manager}")
        
        if pkg_manager == 'apt':
            result = _check_apt_integrity()
        elif pkg_manager in ['yum', 'dnf']:
            result = _check_rpm_integrity()
        else:
            result = {'integrity_failures': 0, 'modified_files': []}
        
        print(f"  Integrity failures: {result.get('integrity_failures', 0)}")
        print(f"  Modified files: {len(result.get('modified_files', []))}")
        
        if result.get('integrity_failures', 0) > 0:
            print("  Would warn about integrity failures (manual investigation required)")
        
        print("\n[✓] Dry-run complete. No changes were made.")
        return True

    # FIX: Skip confirmation in force mode
    if not force:
        print("\n[!] WARNING: Package integrity check will be performed")
        print("    No automatic changes will be made")
        print("    Manual investigation required for integrity failures")
        response = ui.prompt("Proceed? [y/N]: ")
        if response.lower() != 'y':
            logger.info("Package integrity check cancelled by user")
            return False
    else:
        logger.info("Force mode: Running package integrity check without confirmation")

    try:
        begin_transaction()
        
        logger.warning("Package integrity failures should be investigated manually")
        
        # Log the warning with recommendations
        try:
            CHANGES_LOG.parent.mkdir(parents=True, exist_ok=True)
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            with open(CHANGES_LOG, 'a') as f:
                f.write(f"{timestamp} - Package Integrity Warning: Manual investigation required\n")
                f.write(f"  Recommended actions:\n")
                f.write(f"  1. Check modified files: ls -la /path/to/modified/file\n")
                f.write(f"  2. Verify if changes are expected\n")
                f.write(f"  3. If unexpected, investigate possible compromise\n")
                
                pkg_manager = _detect_package_manager()
                if pkg_manager == 'apt':
                    f.write(f"  4. Reinstall packages: sudo apt-get install --reinstall <package>\n")
                    f.write(f"  5. Install debsums: sudo apt-get install debsums\n")
                elif pkg_manager in ['yum', 'dnf']:
                    f.write(f"  4. Reinstall packages: sudo {pkg_manager} reinstall <package>\n")
        except Exception as e:
            logger.debug(f"Failed to log integrity warning: {e}")
        
        commit_transaction()
        print("\n✅ Package integrity check completed")
        return True

    except Exception as e:
        logger.error(f"Failed to complete package integrity check: {e}")
        rollback_transaction()
        return False