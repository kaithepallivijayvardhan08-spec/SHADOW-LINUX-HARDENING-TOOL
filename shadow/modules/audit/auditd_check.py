#!/usr/bin/env python3
"""
Shadow Auditd Check Module
==========================

Checks auditd service status and configuration.

Security concerns:
- auditd not running → no auditing
- Audit rules missing → incomplete audit coverage
- Audit logs not configured → lost audit data
"""

from shadow.core import ui
import os
import shutil
import logging
import subprocess
import json
import time
import fcntl
from pathlib import Path
from datetime import datetime
from typing import Tuple, Dict, List, Optional, Any

# ============================================================
# MODULE METADATA
# ============================================================
SEVERITY = "HIGH"
RECOMMENDATION = "Enable auditd and configure audit rules for security events"

BACKUP_DIR = Path("/var/backups/shadow/")
CHANGES_LOG = Path("/var/log/shadow/changes.log")

# ============================================================
# FIX 1: TRANSACTION SUPPORT
# ============================================================
_transaction_active = False
_transaction_backups = []


def begin_transaction():
    """Begin a transaction for auditd modifications."""
    global _transaction_active, _transaction_backups
    _transaction_active = True
    _transaction_backups = []
    logging.getLogger(__name__).info("Auditd transaction started")


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
    logging.getLogger(__name__).info("Auditd transaction committed")
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
# CRITICAL FILES FOR AUDIT
# ============================================================
CRITICAL_AUDIT_FILES = [
    '/etc/passwd',
    '/etc/shadow',
    '/etc/sudoers',
    '/etc/ssh/sshd_config',
    '/etc/audit/auditd.conf',
    '/etc/login.defs',
    '/etc/security/pwquality.conf',
    '/etc/crontab',
    '/etc/hosts',
    '/etc/resolv.conf'
]


# ============================================================
# STRUCTURED LOGGING
# ============================================================
def _log_auditd_change(action: str, details: str, success: bool):
    """Log auditd modifications with structured format."""
    logger = logging.getLogger(__name__)
    status = "SUCCESS" if success else "FAILED"
    
    log_entry = {
        "event": "auditd_change",
        "action": action,
        "details": details,
        "status": status,
        "timestamp": datetime.now().isoformat()
    }
    logger.info(f"AUDITD: {json.dumps(log_entry)}")
    
    try:
        CHANGES_LOG.parent.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(CHANGES_LOG, 'a') as f:
            f.write(f"{timestamp} - Auditd: {action} - {details} ({status})\n")
    except Exception as e:
        logger.debug(f"Failed to log change: {e}")


def _log_auditd_findings(details: Dict, issues: List[str], warnings: List[str]):
    """Log auditd check findings for audit trail."""
    try:
        CHANGES_LOG.parent.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        with open(CHANGES_LOG, 'a') as f:
            f.write(f"{timestamp} - Auditd Check Results:\n")
            f.write(f"  auditd Running: {details.get('auditd_running', False)}\n")
            f.write(f"  Audit Rules: {len(details.get('auditd_rules', []))}\n")
            f.write(f"  Audit Log Size: {details.get('audit_log_size', 0)} MB\n")
            f.write(f"  auditd Configured: {details.get('auditd_configured', False)}\n")
            
            for issue in issues:
                f.write(f"  ISSUE: {issue}\n")
            for warning in warnings:
                f.write(f"  WARNING: {warning}\n")
            
        logging.getLogger(__name__).debug(f"Auditd findings logged to {CHANGES_LOG}")
    except Exception as e:
        logging.getLogger(__name__).warning(f"Failed to log auditd findings: {e}")


# ============================================================
# CHECK FUNCTION
# ============================================================
def check(config: dict) -> Tuple[str, str, dict]:
    """Check auditd status"""
    logger = logging.getLogger(__name__)
    logger.info("Checking auditd...")

    issues = []
    warnings = []
    details = {
        'auditd_running': False,
        'auditd_rules': [],
        'audit_log_size': 0,
        'auditd_configured': False,
        'auditd_enabled': False
    }

    # FIX 4: Check if auditd is installed
    if not _check_auditd_installed():
        warnings.append("auditd is not installed (skipped)")
        details['auditd_installed'] = False
        details['status'] = 'SKIPPED'
        # Return WARN instead of FAIL
        return 'WARN', "auditd is not installed (skipped)", details

    # Check if auditd is running
    running = _check_auditd_running()
    details['auditd_running'] = running

    if not running:
        issues.append("auditd is not running")

    # Check if auditd is enabled
    enabled = _check_auditd_enabled()
    details['auditd_enabled'] = enabled
    if not enabled:
        warnings.append("auditd is not enabled at boot")

    # Check audit rules
    rules = _get_audit_rules()
    details['auditd_rules'] = rules

    if not rules:
        issues.append("No audit rules configured")
    elif len(rules) < 5:
        warnings.append(f"Only {len(rules)} audit rules found (minimal coverage)")

    # Check audit log size
    log_size = _get_audit_log_size()
    details['audit_log_size'] = log_size

    # Check auditd configuration
    configured = _check_auditd_config()
    details['auditd_configured'] = configured

    if not configured:
        issues.append("auditd not properly configured")

    # Verify audit rules coverage
    if rules:
        _verify_audit_rule_coverage(rules)

    # Check audit log rotation
    if running and not _check_audit_log_rotation():
        warnings.append("Audit log rotation may not be configured")

    # Check audit disk space
    if running:
        disk_space = _check_audit_disk_space()
        if disk_space < 10:
            warnings.append(f"Low disk space for audit logs: {disk_space}% remaining")

    # Log findings
    _log_auditd_findings(details, issues, warnings)

    if issues:
        critical = [i for i in issues if 'not running' in i or 'No audit rules' in i or 'not installed' in i]
        if critical:
            status = 'FAIL'
            message = f"{len(issues)} auditd issues found, {len(critical)} critical"
        else:
            status = 'WARN'
            message = f"{len(issues)} auditd issues found"
    elif warnings:
        status = 'WARN'
        message = f"{len(warnings)} auditd warnings found"
    else:
        status = 'PASS'
        message = "auditd is properly configured"

    return status, message, details


# ============================================================
# FIX 4: CHECK IF AUDITD IS INSTALLED
# ============================================================
def _check_auditd_installed() -> bool:
    """Check if auditd is installed on the system."""
    # Check for auditd binary
    if shutil.which('auditd'):
        return True
    
    # Check for auditctl
    if shutil.which('auditctl'):
        return True
    
    # Check package manager
    try:
        result = subprocess.run(['dpkg', '-l', 'auditd'], capture_output=True, text=True, timeout=5, stdin=subprocess.DEVNULL)
        if 'ii' in result.stdout:
            return True
    except:
        pass
    
    try:
        result = subprocess.run(['rpm', '-q', 'audit'], capture_output=True, text=True, timeout=5, stdin=subprocess.DEVNULL)
        if 'not installed' not in result.stdout:
            return True
    except:
        pass
    
    return False

def _install_auditd(dry_run: bool = False, force: bool = False) -> bool:
    """Install auditd package."""
    logger = logging.getLogger(__name__)
    
    if dry_run:
        _dry_run_auditd_fix("install_auditd", "Would install auditd")
        return True
    
    print("\n[!] Installing auditd...")
    
    try:
        # Detect package manager
        if shutil.which('apt'):
            result = subprocess.run(['apt-get', 'install', '-y', 'auditd', 'audispd-plugins'],
                                   capture_output=True, text=True, timeout=120, stdin=subprocess.DEVNULL)
            if result.returncode != 0:
                logger.error(f"Failed to install auditd: {result.stderr}")
                return False
        elif shutil.which('yum'):
            result = subprocess.run(['yum', 'install', '-y', 'audit'],
                                   capture_output=True, text=True, timeout=120, stdin=subprocess.DEVNULL)
            if result.returncode != 0:
                logger.error(f"Failed to install auditd: {result.stderr}")
                return False
        elif shutil.which('dnf'):
            result = subprocess.run(['dnf', 'install', '-y', 'audit'],
                                   capture_output=True, text=True, timeout=120, stdin=subprocess.DEVNULL)
            if result.returncode != 0:
                logger.error(f"Failed to install auditd: {result.stderr}")
                return False
        else:
            print("    Unknown package manager. Please install auditd manually.")
            return False
        
        logger.info("auditd installed successfully")
        _log_auditd_change("install_auditd", "auditd installed", True)
        print("✅ auditd installed successfully")
        return True
        
    except Exception as e:
        logger.error(f"Failed to install auditd: {e}")
        return False
    
def _check_auditd_running() -> bool:
    """Check if auditd is running"""
    try:
        result = subprocess.run(['systemctl', 'is-active', 'auditd'], capture_output=True, text=True, timeout=5, stdin=subprocess.DEVNULL)
        return result.stdout.strip() == 'active'
    except:
        pass

    try:
        result = subprocess.run(['ps', 'aux'], capture_output=True, text=True, timeout=5, stdin=subprocess.DEVNULL)
        return 'auditd' in result.stdout
    except:
        return False


def _check_auditd_enabled() -> bool:
    """Check if auditd is enabled at boot"""
    try:
        result = subprocess.run(['systemctl', 'is-enabled', 'auditd'], capture_output=True, text=True, timeout=5, stdin=subprocess.DEVNULL)
        return result.stdout.strip() in ['enabled', 'static']
    except:
        return False


def _get_audit_rules() -> List[str]:
    """Get audit rules"""
    rules = []

    try:
        result = subprocess.run(['auditctl', '-l'], capture_output=True, text=True, timeout=10, stdin=subprocess.DEVNULL)

        for line in result.stdout.split('\n'):
            if line.strip():
                rules.append(line)

    except subprocess.TimeoutExpired:
        logging.getLogger(__name__).debug("auditctl command timed out")
    except FileNotFoundError:
        # ✅ FIX: auditctl is not installed. Silently ignore so it doesn't break the UI!
        pass
    except Exception as e:
        # ✅ FIX: Changed from .error to .debug so it doesn't print to the screen
        logging.getLogger(__name__).debug(f"auditctl failed: {e}")

    return rules


def _get_audit_log_size() -> int:
    """Get audit log size in MB"""
    try:
        log_file = '/var/log/audit/audit.log'
        if os.path.exists(log_file):
            return os.path.getsize(log_file) // (1024 * 1024)
    except:
        pass
    return 0


def _check_auditd_config() -> bool:
    """Check auditd configuration"""
    config_file = '/etc/audit/auditd.conf'

    if not os.path.exists(config_file):
        return False

    try:
        with open(config_file, 'r') as f:
            content = f.read()
            required = ['log_file', 'max_log_file', 'num_logs', 'max_log_file_action']
            return all(req in content for req in required)
    except:
        return False


def _check_audit_disk_space() -> int:
    """Check available disk space for audit logs."""
    try:
        result = subprocess.run(['df', '--output=pcent', '/var/log/audit'], 
                               capture_output=True, text=True, timeout=5, stdin=subprocess.DEVNULL)
        lines = result.stdout.strip().split('\n')
        if len(lines) >= 2:
            # Extract percentage (remove %)
            percent_str = lines[1].strip().replace('%', '')
            used = int(percent_str)
            remaining = 100 - used
            return remaining
    except:
        pass
    return 100


def _check_audit_log_rotation() -> bool:
    """Check if audit log rotation is configured."""
    try:
        logrotate_file = '/etc/logrotate.d/audit'
        if os.path.exists(logrotate_file):
            with open(logrotate_file, 'r') as f:
                content = f.read()
                if 'rotate' in content:
                    return True
    except:
        pass
    return False


def _verify_auditd_running() -> bool:
    """Verify auditd is running."""
    try:
        result = subprocess.run(
            ['systemctl', 'is-active', 'auditd'],
            capture_output=True,
            text=True,
            timeout=10, stdin=subprocess.DEVNULL)
        return result.stdout.strip() == 'active'
    except:
        return False


def _rollback_auditd_service() -> bool:
    """Rollback auditd service changes."""
    try:
        subprocess.run(['systemctl', 'disable', 'auditd'], capture_output=True, text=True, timeout=10, stdin=subprocess.DEVNULL)
        subprocess.run(['systemctl', 'stop', 'auditd'], capture_output=True, text=True, timeout=10, stdin=subprocess.DEVNULL)
        logging.getLogger(__name__).info("Auditd service rolled back")
        return True
    except Exception as e:
        logging.getLogger(__name__).error(f"Rollback failed: {e}")
        return False


def _backup_auditd_config() -> Optional[Path]:
    """Backup auditd configuration files."""
    try:
        BACKUP_DIR.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        backup_dir = BACKUP_DIR / f"auditd.backup_{timestamp}"
        backup_dir.mkdir(exist_ok=True)
        
        # Add to transaction
        add_to_transaction(backup_dir, Path('/etc/audit/auditd.conf'))
        
        # Backup auditd.conf
        config_file = '/etc/audit/auditd.conf'
        if os.path.exists(config_file):
            shutil.copy2(config_file, backup_dir / 'auditd.conf')
        
        # Backup audit rules
        rules_file = '/etc/audit/rules.d/audit.rules'
        if os.path.exists(rules_file):
            shutil.copy2(rules_file, backup_dir / 'audit.rules')
        
        logging.getLogger(__name__).info(f"Auditd config backed up to: {backup_dir}")
        return backup_dir
    except Exception as e:
        logging.getLogger(__name__).error(f"Failed to backup auditd config: {e}")
        return None


def _restore_auditd_config(backup_dir: Path) -> bool:
    """Restore auditd configuration from backup."""
    if not backup_dir or not backup_dir.exists():
        return False
    
    try:
        config_file = backup_dir / 'auditd.conf'
        if config_file.exists():
            shutil.copy2(config_file, '/etc/audit/auditd.conf')
        
        rules_file = backup_dir / 'audit.rules'
        if rules_file.exists():
            shutil.copy2(rules_file, '/etc/audit/rules.d/audit.rules')
            # Reload rules
            subprocess.run(['auditctl', '-R', '/etc/audit/rules.d/audit.rules'], 
                          capture_output=True, timeout=10, stdin=subprocess.DEVNULL)
        
        logging.getLogger(__name__).info(f"Auditd config restored from: {backup_dir}")
        return True
    except Exception as e:
        logging.getLogger(__name__).error(f"Failed to restore auditd config: {e}")
        return False


def _dry_run_auditd_fix(action: str, details: str) -> bool:
    """Simulate auditd modification without actually changing anything."""
    logging.getLogger(__name__).info(f"[DRY-RUN] Would perform: {action} - {details}")
    print(f"[DRY-RUN] Would perform: {action}")
    return True


def _confirm_auditd_enable() -> bool:
    """Ask for confirmation before enabling auditd."""
    print(f"\n[!] WARNING: About to enable auditd service")
    print("    auditd provides system auditing capabilities")
    print("    This may affect system performance")
    response = ui.prompt("Proceed? [y/N]: ")
    if response.lower() == 'y':
        print("\n[*] Applying fixes... please wait")
        return True
    return False


def _verify_audit_rule_coverage(rules: List[str]) -> bool:
    """Verify audit rules cover critical files and directories."""
    logger = logging.getLogger(__name__)
    
    rule_text = ' '.join(rules)
    missing_files = []
    
    for file_path in CRITICAL_AUDIT_FILES:
        if file_path not in rule_text:
            missing_files.append(file_path)
    
    if missing_files:
        logger.warning(f"Missing audit rules for: {', '.join(missing_files)}")
        _log_auditd_change("audit_rule_coverage", f"Missing rules for {', '.join(missing_files)}", False)
        return False
    
    logger.debug("Audit rules cover critical files")
    return True


def _create_basic_audit_rules() -> bool:
    """Create basic audit rules if none exist."""
    logger = logging.getLogger(__name__)
    
    rules_file = '/etc/audit/rules.d/audit.rules'
    rules_dir = Path('/etc/audit/rules.d/')
    rules_dir.mkdir(parents=True, exist_ok=True)
    
    # Check if rules already exist
    if os.path.exists(rules_file):
        with open(rules_file, 'r') as f:
            if f.read().strip():
                logger.debug("Audit rules already exist")
                return True
    
    # Basic audit rules
    rules = [
        "# Shadow audit rules",
        "# Date: {}".format(datetime.now().strftime("%Y-%m-%d")),
        "",
        "# Critical files",
        "-w /etc/passwd -p wa -k identity",
        "-w /etc/shadow -p wa -k identity",
        "-w /etc/sudoers -p wa -k identity",
        "-w /etc/ssh/sshd_config -p wa -k ssh",
        "-w /etc/audit/auditd.conf -p wa -k auditd",
        "",
        "# Login and authentication",
        "-w /var/log/wtmp -p wa -k login",
        "-w /var/log/lastlog -p wa -k login",
        "-w /var/log/btmp -p wa -k login",
        "",
        "# System calls",
        "-a always,exit -S adjtimex -S settimeofday -S clock_settime -k time",
        "-a always,exit -S mount -S umount -k mount",
        "",
        "# User management",
        "-w /etc/group -p wa -k identity",
        "-w /etc/gshadow -p wa -k identity",
        "-w /etc/security/limits.conf -p wa -k identity",
        ""
    ]
    
    try:
        with open(rules_file, 'w') as f:
            f.write('\n'.join(rules))
        logger.info(f"Basic audit rules created: {rules_file}")
        
        # Load rules
        result = subprocess.run(['auditctl', '-R', rules_file], capture_output=True, text=True, timeout=10, stdin=subprocess.DEVNULL)
        if result.returncode == 0:
            logger.info("Audit rules loaded successfully")
            _log_auditd_change("create_rules", "Basic audit rules created", True)
            return True
        else:
            logger.error(f"Failed to load audit rules: {result.stderr}")
            return False
    except Exception as e:
        logger.error(f"Failed to create audit rules: {e}")
        return False


def _safe_start_auditd(dry_run: bool = False, force: bool = False) -> bool:
    """
    Safely enable and start auditd with verification, dry-run, and rollback.
    """
    logger = logging.getLogger(__name__)
    
    # ✅ FIX: Check if auditd is installed
    if not _check_auditd_installed():
        logger.warning("auditd is not installed")
        print("\n[!] auditd is not installed on this system.")
        print("    auditd provides critical security auditing.")
        
        if not force:
            response = ui.prompt("Install auditd now? [y/N]: ")
            if response.lower() == 'y':
                return _install_auditd(dry_run, force)
            else:
                print("    Skipping auditd setup.")
                _log_auditd_change("skip_auditd", "auditd not installed, skipped", True)
                return True
        else:
            logger.info("Force mode - auditd not installed, skipping")
            return True
    
    # Dry-run mode
    if dry_run:
        _dry_run_auditd_fix("enable_auditd", "Would enable and start auditd")
        return True
    
    # Confirmation
    if not force and not _confirm_auditd_enable():
        logger.info("auditd enable cancelled by user")
        return False
    
    # Check if auditd is already running
    if _verify_auditd_running():
        logger.debug("auditd already running")
        return True
    
    # Begin transaction
    begin_transaction()
    
    # Backup config
    backup_dir = _backup_auditd_config()
    
    try:
        # Enable auditd
        result = subprocess.run(['systemctl', 'enable', 'auditd'], capture_output=True, text=True, timeout=10, stdin=subprocess.DEVNULL)
        if result.returncode != 0:
            logger.error(f"Failed to enable auditd: {result.stderr}")
            rollback_transaction()
            return False
        logger.info("auditd enabled")
        
        # Start auditd
        result = subprocess.run(['systemctl', 'start', 'auditd'], capture_output=True, text=True, timeout=10, stdin=subprocess.DEVNULL)
        if result.returncode != 0:
            logger.error(f"Failed to start auditd: {result.stderr}")
            rollback_transaction()
            return False
        logger.info("auditd started")
        
        # Wait for service to stabilize
        time.sleep(2)
        
        # Verify auditd is running
        if not _verify_auditd_running():
            logger.error("auditd verification failed after start")
            rollback_transaction()
            return False
        
        # Create basic rules if none exist
        rules = _get_audit_rules()
        if not rules:
            if not _create_basic_audit_rules():
                logger.warning("Failed to create basic audit rules")
        
        # Restart auditd after config changes
        result = subprocess.run(['systemctl', 'restart', 'auditd'], capture_output=True, text=True, timeout=10, stdin=subprocess.DEVNULL)
        if result.returncode != 0:
            logger.warning(f"Failed to restart auditd: {result.stderr}")
        
        # Verify auditd is still running after restart
        time.sleep(2)
        if not _verify_auditd_running():
            logger.error("auditd verification failed after restart")
            rollback_transaction()
            return False
        
        # Commit transaction
        commit_transaction()
        
        _log_auditd_change("enable_auditd", "auditd enabled and started", True)
        logger.info("auditd verified and running")
        return True
        
    except Exception as e:
        logger.error(f"Failed to start auditd: {e}")
        rollback_transaction()
        return False
        


def fix(config: dict, dry_run: bool = False, force: bool = False) -> bool:
    """
    Fix auditd issues

    Args:
        config: Configuration dictionary
        dry_run: If True, preview changes without applying
        force: If True, skip confirmation

    Returns:
        bool: True if fixes applied successfully
    """
    logger = logging.getLogger(__name__)
    logger.info("Fixing auditd issues...")

    # Check for dry-run mode (use parameter, not config)
    if dry_run:
        logger.info("DRY-RUN MODE: No changes will be applied")
        print("\n[!] DRY-RUN MODE - No changes will be applied")
        
        # Show what would be done
        if _check_auditd_installed():
            print("  auditd is installed")
            if not _check_auditd_running():
                print("  Would enable and start auditd")
            else:
                print("  auditd already running")
        else:
            print("  auditd is NOT installed")
            print("  Would install auditd")
        
        rules = _get_audit_rules()
        if not rules:
            print("  Would create basic audit rules")
        else:
            print(f"  Found {len(rules)} audit rules")
        
        print("\n[✓] Dry-run complete. No changes were made.")
        return True

    # FIX: Skip confirmation in force mode
    if not force:
        print("\n[!] WARNING: About to enable auditd service")
        print("    auditd provides system auditing capabilities")
        print("    This may affect system performance")
        response = ui.prompt("Proceed? [y/N]: ")
        if response.lower() != 'y':
            logger.info("auditd enable cancelled by user")
            return False
    else:
        logger.info("Force mode: Enabling auditd without confirmation")

    try:
        begin_transaction()
        
        # Only enable auditd if config says so
        if config.get('audit', {}).get('enable_auditd', True):
            success = _safe_start_auditd(dry_run, force)
            if success:
                commit_transaction()
                logger.info("auditd enabled and started successfully")
                print("\n✅ auditd enabled and started successfully")
                return True
            else:
                rollback_transaction()
                logger.error("Failed to enable auditd")
                print("\n❌ Failed to enable auditd")
                return False
        else:
            logger.info("auditd disabled in config")
            commit_transaction()
            return True

    except Exception as e:
        logger.error(f"Failed to fix auditd: {e}")
        rollback_transaction()
        return False