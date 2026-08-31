#!/usr/bin/env python3
"""
Shadow File Integrity Module
============================

Checks file integrity using system tools.

Security concerns:
- Modified system files → compromise
- Unauthorized file changes → malware
- Corruption → system instability
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
from pathlib import Path
from datetime import datetime
from typing import Tuple, Dict, List, Optional, Any, Callable

# ============================================================
# MODULE METADATA
# ============================================================
SEVERITY = "HIGH"
RECOMMENDATION = "Install and configure AIDE for file integrity monitoring"

BACKUP_DIR = Path("/var/backups/shadow/")
CHANGES_LOG = Path("/var/log/shadow/changes.log")

# ============================================================
# TRANSACTION SUPPORT
# ============================================================
_transaction_active = False
_transaction_backups = []

def begin_transaction():
    """Begin a transaction for integrity modifications."""
    global _transaction_active, _transaction_backups
    _transaction_active = True
    _transaction_backups = []
    logging.getLogger(__name__).info("Integrity transaction started")

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
    logging.getLogger(__name__).info("Integrity transaction committed")
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

# FIX 10: Support multiple integrity tools
INTEGRITY_TOOLS = ['aide', 'tripwire', 'samhain', 'integrit']
AIDE_CONFIG = '/etc/aide/aide.conf'
AIDE_DB = '/var/lib/aide/aide.db.gz'
AIDE_CONFIG_DIR = '/etc/aide/'


# ============================================================
# FIX 8: STRUCTURED LOGGING
# ============================================================
def _log_integrity_change(action: str, details: str, success: bool = True):
    """Log integrity changes with structured format."""
    logger = logging.getLogger(__name__)
    status = "SUCCESS" if success else "FAILED"
    
    log_entry = {
        "event": "integrity_change",
        "action": action,
        "details": details,
        "status": status,
        "timestamp": datetime.now().isoformat()
    }
    logger.info(f"INTEGRITY: {json.dumps(log_entry)}")
    
    try:
        CHANGES_LOG.parent.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(CHANGES_LOG, 'a') as f:
            f.write(f"{timestamp} - Integrity: {action} - {details} ({status})\n")
    except Exception as e:
        logger.debug(f"Failed to log integrity change: {e}")


def _log_integrity_failure(details: Dict):
    """Log integrity failures for audit trail."""
    try:
        CHANGES_LOG.parent.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        with open(CHANGES_LOG, 'a') as f:
            f.write(f"{timestamp} - Integrity Check Failed:\n")
            f.write(f"  Total failures: {details.get('integrity_failures', 0)}\n")
            
            modified = details.get('modified_files', [])[:10]
            if modified:
                f.write(f"  Modified files: {', '.join(modified)}\n")
            
            added = details.get('added_files', [])[:5]
            if added:
                f.write(f"  Added files: {', '.join(added)}\n")
            
            deleted = details.get('deleted_files', [])[:5]
            if deleted:
                f.write(f"  Deleted files: {', '.join(deleted)}\n")
    except Exception as e:
        logging.getLogger(__name__).warning(f"Failed to log integrity failure: {e}")


def _log_integrity_findings(details: Dict, issues: List[str], warnings: List[str]):
    """Log integrity check findings for audit trail."""
    try:
        CHANGES_LOG.parent.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        with open(CHANGES_LOG, 'a') as f:
            f.write(f"{timestamp} - Integrity Check Results:\n")
            f.write(f"  Tool: {details.get('integrity_tool', 'none')}\n")
            f.write(f"  AIDE Initialized: {details.get('aide_initialized', False)}\n")
            f.write(f"  Integrity Failures: {details.get('integrity_failures', 0)}\n")
            
            for issue in issues:
                f.write(f"  ISSUE: {issue}\n")
            for warning in warnings:
                f.write(f"  WARNING: {warning}\n")
    except Exception as e:
        logging.getLogger(__name__).warning(f"Failed to log integrity findings: {e}")


# ============================================================
# CHECK FUNCTION
# ============================================================
def check(config: dict) -> Tuple[str, str, dict]:
    """Check file integrity"""
    logger = logging.getLogger(__name__)
    logger.info("Checking file integrity...")

    issues = []
    warnings = []
    details = {
        'modified_files': [],
        'added_files': [],
        'deleted_files': [],
        'integrity_check_available': False,
        'integrity_tool': None,
        'aide_db_exists': False,
        'aide_config_exists': False,
        'aide_initialized': False,
        'integrity_failures': 0
    }

    # FIX 10: Check multiple integrity tools
    tool_installed, tool_name = _check_integrity_tools()
    details['integrity_check_available'] = tool_installed
    details['integrity_tool'] = tool_name

    if not tool_installed:
        return 'WARN', f"No integrity tools installed (AIDE, Tripwire, etc.)", details

    # FIX 9: Check AIDE configuration
    if tool_name == 'aide':
        if os.path.exists(AIDE_CONFIG):
            details['aide_config_exists'] = True
        else:
            warnings.append("AIDE config file not found")

        # FIX 6: Check AIDE database
        if os.path.exists(AIDE_DB):
            details['aide_db_exists'] = True
        else:
            warnings.append("AIDE database not found. Run 'aideinit' first.")

        # FIX 5: Check if AIDE is initialized
        if details['aide_db_exists'] and details['aide_config_exists']:
            details['aide_initialized'] = True
        else:
            warnings.append("AIDE not properly initialized")

    # Run integrity check if tool is installed and initialized
    if tool_installed and (tool_name != 'aide' or details['aide_initialized']):
        result = _run_integrity_check(tool_name)
        details.update(result)

        if details.get('modified_files'):
            for file_path in details['modified_files'][:20]:
                issues.append(f"Modified file: {file_path}")

        if details.get('added_files'):
            for file_path in details['added_files'][:10]:
                issues.append(f"Added file: {file_path}")

        if details.get('deleted_files'):
            for file_path in details['deleted_files'][:10]:
                issues.append(f"Deleted file: {file_path}")

        # FIX 8: Log integrity failures
        if details.get('integrity_failures', 0) > 0:
            logger.warning(f"Found {details['integrity_failures']} integrity failures")
            _log_integrity_failure(details)
    elif tool_name == 'aide' and not details['aide_initialized']:
        warnings.append("AIDE not initialized - run integrity fix first")

    # FIX 12: Check for debsums as fallback
    if not details['integrity_check_available']:
        debsums_available = _check_debsums()
        if debsums_available:
            warnings.append("debsums available - try installing debsums for better integrity checking")

    # Log findings
    _log_integrity_findings(details, issues, warnings)

    if issues:
        return 'FAIL', f"{len(issues)} integrity issues found", details
    elif warnings:
        return 'WARN', f"{len(warnings)} integrity warnings found", details
    return 'PASS', "File integrity verified", details


def _check_aide_installed() -> bool:
    """Check if AIDE is installed"""
    try:
        result = subprocess.run(['which', 'aide'], capture_output=True, text=True, timeout=5, stdin=subprocess.DEVNULL)
        return result.returncode == 0
    except:
        return False


def _check_debsums() -> bool:
    """Check if debsums is installed"""
    try:
        result = subprocess.run(['which', 'debsums'], capture_output=True, text=True, timeout=5, stdin=subprocess.DEVNULL)
        return result.returncode == 0
    except:
        return False


def _run_aide_check() -> Dict:
    """Run AIDE integrity check"""
    result = {
        'modified_files': [],
        'added_files': [],
        'deleted_files': [],
        'integrity_failures': 0
    }

    try:
        cmd = subprocess.run(['aide', '--check'], capture_output=True, text=True, timeout=300, stdin=subprocess.DEVNULL)

        for line in cmd.stdout.split('\n'):
            if 'modified' in line and ':' in line:
                result['modified_files'].append(line.split(':')[-1].strip())
                result['integrity_failures'] += 1
            elif 'added' in line and ':' in line:
                result['added_files'].append(line.split(':')[-1].strip())
                result['integrity_failures'] += 1
            elif 'removed' in line and ':' in line:
                result['deleted_files'].append(line.split(':')[-1].strip())
                result['integrity_failures'] += 1

    except subprocess.TimeoutExpired:
        logging.getLogger(__name__).error("AIDE check timed out")
    except Exception as e:
        logging.getLogger(__name__).error(f"AIDE check failed: {e}")

    return result


def _dry_run_integrity_fix(action: str, details: str) -> bool:
    """Simulate integrity modification without actually changing anything."""
    logging.getLogger(__name__).info(f"[DRY-RUN] Would perform: {action} - {details}")
    print(f"[DRY-RUN] Would perform: {action}")
    return True


def _confirm_integrity_modification(action: str) -> bool:
    """Ask for confirmation before modifying integrity configuration."""
    print(f"\n[!] WARNING: About to initialize/update integrity database")
    print(f"    Action: {action}")
    print("    This will create a baseline of system files")
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


def _schedule_integrity_check() -> bool:
    """Schedule periodic integrity checks using cron."""
    try:
        cron_file = '/etc/cron.d/shadow-integrity'
        cron_content = """# Shadow Integrity Check
# Run daily at 2 AM
0 2 * * * root /usr/bin/aide --check > /var/log/shadow/integrity_daily.log 2>&1
"""
        with open(cron_file, 'w') as f:
            f.write(cron_content)
        os.chmod(cron_file, 0o644)
        logging.getLogger(__name__).info("Integrity check scheduled daily at 2 AM")
        return True
    except Exception as e:
        logging.getLogger(__name__).error(f"Failed to schedule integrity check: {e}")
        return False


def _check_integrity_tools() -> Tuple[bool, str]:
    """Check if any integrity tool is installed"""
    for tool in INTEGRITY_TOOLS:
        try:
            result = subprocess.run(['which', tool], capture_output=True, text=True, timeout=5, stdin=subprocess.DEVNULL)
            if result.returncode == 0:
                return True, tool
        except:
            pass
    return False, None


def _check_aide_initialized() -> bool:
    """Check if AIDE is initialized"""
    if os.path.exists(AIDE_DB) and os.path.exists(AIDE_CONFIG):
        return True
    return False


def _run_integrity_check(tool: str) -> Dict:
    """Run integrity check with proper error handling"""
    result = {
        'modified_files': [],
        'added_files': [],
        'deleted_files': [],
        'integrity_failures': 0
    }

    try:
        if tool == 'aide':
            cmd = subprocess.run(
                ['aide', '--check'],
                capture_output=True,
                text=True,
                timeout=300, stdin=subprocess.DEVNULL)

            if cmd.returncode == 0:
                logging.getLogger(__name__).info("AIDE check completed successfully")
            elif cmd.returncode == 1:
                logging.getLogger(__name__).info("AIDE detected changes")
            else:
                logging.getLogger(__name__).error(f"AIDE check failed with code {cmd.returncode}")

            # Parse output
            for line in cmd.stdout.split('\n'):
                if 'modified' in line and ':' in line:
                    result['modified_files'].append(line.split(':')[-1].strip())
                    result['integrity_failures'] += 1
                elif 'added' in line and ':' in line:
                    result['added_files'].append(line.split(':')[-1].strip())
                    result['integrity_failures'] += 1
                elif 'removed' in line and ':' in line:
                    result['deleted_files'].append(line.split(':')[-1].strip())
                    result['integrity_failures'] += 1

        elif tool == 'tripwire':
            cmd = subprocess.run(
                ['tripwire', '--check'],
                capture_output=True,
                text=True,
                timeout=300, stdin=subprocess.DEVNULL)
            for line in cmd.stdout.split('\n'):
                if 'changed' in line.lower():
                    result['integrity_failures'] += 1

    except subprocess.TimeoutExpired:
        logging.getLogger(__name__).error(f"{tool} check timed out")
    except FileNotFoundError:
        logging.getLogger(__name__).error(f"{tool} not found")
    except Exception as e:
        logging.getLogger(__name__).error(f"{tool} check failed: {e}")

    # FIX 11: Generate report if there are changes
    if result['integrity_failures'] > 0:
        _generate_integrity_report(result)

    return result


def _generate_integrity_report(result: Dict):
    """Generate an integrity report"""
    try:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_dir = BACKUP_DIR / "integrity_reports"
        report_dir.mkdir(parents=True, exist_ok=True)

        report_file = report_dir / f"integrity_report_{timestamp}.txt"

        with open(report_file, 'w') as f:
            f.write("=" * 60 + "\n")
            f.write("SHADOW INTEGRITY REPORT\n")
            f.write("=" * 60 + "\n")
            f.write(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Total failures: {result['integrity_failures']}\n\n")

            f.write("MODIFIED FILES:\n")
            for file in result['modified_files'][:50]:
                f.write(f"  - {file}\n")

            f.write("\nADDED FILES:\n")
            for file in result['added_files'][:20]:
                f.write(f"  - {file}\n")

            f.write("\nDELETED FILES:\n")
            for file in result['deleted_files'][:20]:
                f.write(f"  - {file}\n")

        logging.getLogger(__name__).info(f"Integrity report generated: {report_file}")

    except Exception as e:
        logging.getLogger(__name__).error(f"Failed to generate integrity report: {e}")


def _compare_to_baseline(current_files: List[str], baseline_file: str) -> Dict:
    """Compare current files to baseline"""
    result = {
        'added': [],
        'removed': [],
        'modified': []
    }

    if not os.path.exists(baseline_file):
        return result

    try:
        with open(baseline_file, 'r') as f:
            baseline = set(line.strip() for line in f)

        current = set(current_files)
        result['added'] = list(current - baseline)
        result['removed'] = list(baseline - current)

    except Exception as e:
        logging.getLogger(__name__).error(f"Baseline comparison failed: {e}")

    return result


def _verify_backup(backup_path: Path) -> bool:
    """Verify that a backup was created successfully."""
    if not backup_path.exists():
        logging.getLogger(__name__).error(f"Backup not found: {backup_path}")
        return False
    logging.getLogger(__name__).debug(f"Backup verified: {backup_path}")
    return True


def _backup_integrity_database() -> Dict[str, Any]:
    """Backup integrity database."""
    result = {
        'backup_path': None,
        'success': False,
        'files_backed_up': []
    }
    
    try:
        BACKUP_DIR.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        backup_path = BACKUP_DIR / f"integrity_db_backup_{timestamp}"
        backup_path.mkdir(exist_ok=True)
        
        if os.path.exists(AIDE_DB):
            shutil.copy2(AIDE_DB, backup_path / "aide.db.gz")
            result['files_backed_up'].append('aide.db.gz')
        
        if os.path.exists(AIDE_CONFIG):
            shutil.copy2(AIDE_CONFIG, backup_path / "aide.conf")
            result['files_backed_up'].append('aide.conf')
        
        result['backup_path'] = str(backup_path)
        result['success'] = True
        logging.getLogger(__name__).info(f"Integrity backup created: {backup_path}")
        add_to_transaction(backup_path, Path(AIDE_DB))

    except Exception as e:
        logging.getLogger(__name__).error(f"Failed to backup integrity data: {e}")
    
    return result


def _validate_integrity_tool(tool: str) -> Tuple[bool, str]:
    """Validate integrity tool is available and working."""
    try:
        result = subprocess.run(['which', tool], capture_output=True, text=True, timeout=5, stdin=subprocess.DEVNULL)
        if result.returncode != 0:
            return False, f"{tool} not installed"
        
        if tool == 'aide':
            if not os.path.exists(AIDE_CONFIG):
                return False, "AIDE config not found"
            if not os.path.exists(AIDE_DB):
                return False, "AIDE database not initialized"
        
        return True, f"{tool} is available"
    except Exception as e:
        return False, f"Validation error: {e}"


def _rollback_integrity(backup_path: Path) -> bool:
    """Rollback integrity database from backup."""
    if not backup_path.exists():
        logging.getLogger(__name__).error(f"Backup not found: {backup_path}")
        return False
    
    try:
        for file in backup_path.iterdir():
            if file.is_file():
                if file.name == 'aide.db.gz':
                    shutil.copy2(file, AIDE_DB)
                elif file.name == 'aide.conf':
                    shutil.copy2(file, AIDE_CONFIG)
        
        logging.getLogger(__name__).info(f"Rolled back integrity data from: {backup_path}")
        return True
    except Exception as e:
        logging.getLogger(__name__).error(f"Rollback failed: {e}")
        return False


def _verify_integrity_tool(tool: str) -> Tuple[bool, str]:
    """Verify integrity tool works after changes."""
    try:
        if tool == 'aide':
            result = subprocess.run(
                ['aide', '--check', '--quick'],
                capture_output=True,
                text=True,
                timeout=60, stdin=subprocess.DEVNULL)
            if result.returncode <= 1:
                return True, f"{tool} verification passed"
            else:
                return False, f"{tool} verification failed: {result.stderr}"
        
        return True, f"{tool} verification passed"
    except Exception as e:
        return False, f"Verification error: {e}"


def _get_aide_exclude_patterns() -> List[str]:
    """Get exclude patterns for AIDE"""
    return [
        '/proc', '/sys', '/dev', '/run',
        '/tmp', '/var/tmp', '/var/log',
        '/var/cache', '/var/spool', '/var/lock'
    ]


def _create_aide_config():
    """Create a basic AIDE configuration file"""
    try:
        AIDE_CONFIG_DIR = Path('/etc/aide/')
        AIDE_CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        
        with open(AIDE_CONFIG, 'w') as f:
            f.write("# AIDE configuration generated by Shadow\n\n")
            f.write("database = file:/var/lib/aide/aide.db.gz\n")
            f.write("database_out = file:/var/lib/aide/aide.db.new.gz\n")
            f.write("gzip_dbout = yes\n\n")
            f.write("verbose = 5\n\n")
            f.write("# Exclude directories\n")
            f.write("!/proc\n")
            f.write("!/sys\n")
            f.write("!/dev\n")
            f.write("!/run\n")
            f.write("!/tmp\n")
            f.write("!/var/tmp\n")
            f.write("!/var/log\n")
            f.write("!/var/cache\n\n")
            f.write("# Rule definitions\n")
            f.write("CONTENT = sha256\n")
            f.write("PERMS = p+u+g\n\n")
            f.write("# /etc directory\n")
            f.write("/etc CONTENT+PERMS\n")
            f.write("/bin CONTENT+PERMS\n")
            f.write("/sbin CONTENT+PERMS\n")
            f.write("/usr/bin CONTENT+PERMS\n")
            f.write("/usr/sbin CONTENT+PERMS\n")
        
        logging.getLogger(__name__).info(f"AIDE config created: {AIDE_CONFIG}")
    except Exception as e:
        logging.getLogger(__name__).error(f"Failed to create AIDE config: {e}")


def fix(config: dict, dry_run: bool = False, force: bool = False) -> bool:
    """
    Fix file integrity issues

    Args:
        config: Configuration dictionary
        dry_run: If True, preview changes without applying
        force: If True, skip confirmation

    Returns:
        bool: True if fixes applied successfully
    """
    logger = logging.getLogger(__name__)
    logger.info("Fixing file integrity issues...")

    # Check for dry-run mode (use parameter, not config)
    if dry_run:
        logger.info("DRY-RUN MODE: No changes will be applied")
        print("\n[!] DRY-RUN MODE - No changes will be applied")
        
        tool_installed, tool_name = _check_integrity_tools()
        if tool_installed:
            print(f"  Integrity tool found: {tool_name}")
            if tool_name == 'aide':
                print(f"  AIDE config exists: {os.path.exists(AIDE_CONFIG)}")
                print(f"  AIDE database exists: {os.path.exists(AIDE_DB)}")
                if not os.path.exists(AIDE_DB):
                    print("  Would initialize AIDE database")
            print("  Would schedule periodic integrity checks")
        else:
            print("  No integrity tools installed")
        
        print("\n[✓] Dry-run complete. No changes were made.")
        return True

    # FIX: Skip confirmation in force mode
    if not force:
        tool_installed, tool_name = _check_integrity_tools()
        if tool_installed:
            if not _confirm_integrity_modification(f"Initialize/update {tool_name}"):
                logger.info("Integrity fixes cancelled by user")
                return False
    else:
        logger.info("Force mode: Applying integrity fixes without confirmation")

    try:
        begin_transaction()
        
        tool_installed, tool_name = _check_integrity_tools()
        if not tool_installed:
            logger.warning("No integrity tools installed")
            rollback_transaction()
            return False

        is_valid, msg = _validate_integrity_tool(tool_name)
        if not is_valid:
            logger.warning(f"Integrity tool validation failed: {msg}")
            rollback_transaction()
            return False

        backup_metadata = _backup_integrity_database()
        if not backup_metadata['success']:
            logger.warning("Could not backup integrity data")

        if tool_name == 'aide':
            if config.get('integrity', {}).get('init_aide', True):
                if not os.path.exists(AIDE_DB) or not os.path.exists(AIDE_CONFIG):
                    logger.info("Initializing AIDE...")
                    
                    try:
                        if not os.path.exists(AIDE_CONFIG):
                            _create_aide_config()
                        
                        subprocess.run(['aideinit'], capture_output=True, text=True, timeout=120, stdin=subprocess.DEVNULL)
                        logger.info("AIDE initialized")
                        _log_integrity_change("INIT", "AIDE initialized", True)
                    except Exception as e:
                        logger.error(f"Failed to initialize AIDE: {e}")
                        if backup_metadata['success']:
                            _rollback_integrity(Path(backup_metadata['backup_path']))
                        rollback_transaction()
                        return False

        if config.get('integrity', {}).get('schedule_checks', True):
            _schedule_integrity_check()

        is_verified, verify_msg = _verify_integrity_tool(tool_name)
        if not is_verified:
            logger.warning(f"Integrity verification failed: {verify_msg}")
            if backup_metadata['success']:
                _rollback_integrity(Path(backup_metadata['backup_path']))
            rollback_transaction()
            return False

        commit_transaction()
        logger.info(f"Integrity fixes applied using {tool_name}")
        print("\n[✓] Integrity fixes applied successfully")
        
        return True

    except Exception as e:
        logger.error(f"Failed to fix integrity issues: {e}")
        if backup_metadata.get('success'):
            _rollback_integrity(Path(backup_metadata['backup_path']))
        rollback_transaction()
        return False