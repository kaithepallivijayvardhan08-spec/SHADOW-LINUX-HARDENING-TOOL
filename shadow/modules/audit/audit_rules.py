#!/usr/bin/env python3
"""
Shadow Audit Rules Module
=========================

Checks and manages audit rules for security monitoring.

Security concerns:
- Missing audit rules → gaps in monitoring
- Ineffective audit rules → false negatives
- Overly broad rules → performance issues
"""

from shadow.core import ui
import os
import shutil
import logging
import subprocess
import tempfile
import json
import fcntl
import time
from pathlib import Path
from datetime import datetime
from typing import Tuple, Dict, List, Optional, Any

# ============================================================
# MODULE METADATA
# ============================================================
SEVERITY = "HIGH"
RECOMMENDATION = "Enable auditd and configure audit rules for security events"

BACKUP_DIR = Path("/var/backups/shadow/")
AUDIT_RULES_DIR = Path("/etc/audit/rules.d/")
CHANGES_LOG = Path("/var/log/shadow/changes.log")

# ============================================================
# TRANSACTION SUPPORT
# ============================================================
_transaction_active = False
_transaction_backups = []

def begin_transaction():
    """Begin a transaction for audit rules modifications."""
    global _transaction_active, _transaction_backups
    _transaction_active = True
    _transaction_backups = []
    logging.getLogger(__name__).info("Audit rules transaction started")

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
    logging.getLogger(__name__).info("Audit rules transaction committed")
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
# FIX 8: ESSENTIAL AUDIT RULES DEFINITION
# ============================================================
ESSENTIAL_RULES = [
    {
        'name': 'identity',
        'rule': '-w /etc/passwd -p wa -k identity',
        'description': 'Monitor /etc/passwd for changes'
    },
    {
        'name': 'shadow',
        'rule': '-w /etc/shadow -p wa -k identity',
        'description': 'Monitor /etc/shadow for changes'
    },
    {
        'name': 'sudoers',
        'rule': '-w /etc/sudoers -p wa -k identity',
        'description': 'Monitor /etc/sudoers for changes'
    },
    {
        'name': 'group',
        'rule': '-w /etc/group -p wa -k identity',
        'description': 'Monitor /etc/group for changes'
    },
    {
        'name': 'time',
        'rule': '-S adjtimex -S settimeofday -S clock_settime -k time',
        'description': 'Monitor time changes'
    },
    {
        'name': 'audit_logs',
        'rule': '-w /var/log/audit/ -p wa -k audited',
        'description': 'Monitor audit logs'
    },
    {
        'name': 'user_management',
        'rule': '-S useradd -S usermod -S userdel -S groupadd -S groupmod -S groupdel -k user_management',
        'description': 'Monitor user management'
    },
    {
        'name': 'privilege_escalation',
        'rule': '-S setuid -S setgid -S chown -S chmod -S fchown -S fchmod -k privilege',
        'description': 'Monitor privilege escalation attempts'
    }
]


# ============================================================
# FIX 8: STRUCTURED LOGGING
# ============================================================
def _log_audit_rules_change(action: str, details: str, success: bool):
    """Log audit rules modifications with structured format."""
    logger = logging.getLogger(__name__)
    status = "SUCCESS" if success else "FAILED"
    
    log_entry = {
        "event": "audit_rules_change",
        "action": action,
        "details": details,
        "status": status,
        "timestamp": datetime.now().isoformat()
    }
    logger.info(f"AUDIT_RULES: {json.dumps(log_entry)}")
    
    try:
        CHANGES_LOG.parent.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(CHANGES_LOG, 'a') as f:
            f.write(f"{timestamp} - Audit Rules: {action} - {details} ({status})\n")
    except Exception as e:
        logger.debug(f"Failed to log change: {e}")


def _log_audit_rules_findings(details: Dict, issues: List[str]):
    """Log audit rules check findings for audit trail."""
    try:
        CHANGES_LOG.parent.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        with open(CHANGES_LOG, 'a') as f:
            f.write(f"{timestamp} - Audit Rules Check Results:\n")
            f.write(f"  Total Rules: {details.get('total_rules', 0)}\n")
            
            missing = details.get('essential_rules_missing', [])
            if missing:
                f.write(f"  Missing Essential Rules: {', '.join(missing)}\n")
            
            for issue in issues:
                f.write(f"  ISSUE: {issue}\n")
    except Exception as e:
        logging.getLogger(__name__).warning(f"Failed to log audit rules findings: {e}")


# ============================================================
# CHECK FUNCTION
# ============================================================
def check(config: dict) -> Tuple[str, str, dict]:
    """Check audit rules"""
    logger = logging.getLogger(__name__)
    logger.info("Checking audit rules...")

    issues = []
    details = {
        'active_rules': [],
        'essential_rules_missing': [],
        'total_rules': 0
    }

    # Get current rules
    rules = _get_current_rules()
    details['active_rules'] = rules
    details['total_rules'] = len(rules)

    # FIX 2: Check essential rules
    missing = _check_essential_rules(rules)
    details['essential_rules_missing'] = missing

    if missing:
        for rule in missing:
            issues.append(f"Essential rule missing: {rule}")

    # FIX 5: Check for duplicate rules
    if _has_duplicate_rules(rules):
        issues.append("Duplicate audit rules found")

    # FIX 4: Verify rule effectiveness
    if rules:
        _verify_rule_effectiveness(rules)

    # Log findings
    _log_audit_rules_findings(details, issues)

    if issues:
        status = 'WARN'
        message = f"{len(issues)} audit rule issues found"
    else:
        status = 'PASS'
        message = "Audit rules are complete"

    return status, message, details


def _get_current_rules() -> List[str]:
    """Get current audit rules"""
    rules = []

    try:
        result = subprocess.run(['auditctl', '-l'], capture_output=True, text=True, timeout=10, stdin=subprocess.DEVNULL)

        for line in result.stdout.split('\n'):
            if line.strip():
                rules.append(line)

    except FileNotFoundError:
        pass  # Silently ignore if auditctl isn't installed
    except subprocess.TimeoutExpired:
        logging.getLogger(__name__).debug("auditctl command timed out")
    except Exception as e:
        logging.getLogger(__name__).debug(f"auditctl failed: {e}")
    return rules


def _check_essential_rules(rules: List[str]) -> List[str]:
    """Check for essential audit rules"""
    missing = []
    
    for essential in ESSENTIAL_RULES:
        rule_pattern = essential['rule']
        found = any(rule_pattern in rule for rule in rules)
        if not found:
            # FIX 2: More flexible matching for rules
            if 'adjtimex' in essential['rule'] and any('adjtimex' in rule for rule in rules):
                continue
            if 'settimeofday' in essential['rule'] and any('settimeofday' in rule for rule in rules):
                continue
            missing.append(essential['name'])

    return missing


# ============================================================
# FIX 1: BACKUP BEFORE MODIFYING AUDIT RULES
# ============================================================
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


def _backup_audit_rules() -> Dict[str, Any]:
    """Backup audit rules directory."""
    result = {
        'path': str(AUDIT_RULES_DIR),
        'backup_path': None,
        'success': False
    }
    
    try:
        BACKUP_DIR.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        
        if AUDIT_RULES_DIR.exists():
            backup_path = BACKUP_DIR / f"audit_rules.d.backup_{timestamp}"
            shutil.copytree(AUDIT_RULES_DIR, backup_path, dirs_exist_ok=True)
            result['backup_path'] = str(backup_path)
            
            if backup_path.exists():
                result['success'] = True
                logging.getLogger(__name__).info(f"Backup created: {backup_path}")
                add_to_transaction(backup_path, AUDIT_RULES_DIR)

    except FileNotFoundError:
        logging.getLogger(__name__).debug("Audit rules directory not found (auditd not installed)")
    except Exception as e:
        logging.getLogger(__name__).debug(f"Failed to backup audit rules: {e}")
    return result


# ============================================================
# FIX 3: VALIDATE AUDIT RULES BEFORE LOADING
# ============================================================
def _validate_audit_rules(rules_file: Path) -> bool:
    """Validate audit rules using augenrules --check."""
    try:
        result = subprocess.run(
            ['augenrules', '--check'],
            capture_output=True,
            text=True,
            timeout=10, stdin=subprocess.DEVNULL)
        if result.returncode == 0:
            return True
        else:
            logging.getLogger(__name__).debug(f"Audit rules validation failed: {result.stderr}")
            return False
    except FileNotFoundError:
        logging.getLogger(__name__).debug("augenrules not found (auditd not installed)")
        return False
    except Exception as e:
        logging.getLogger(__name__).debug(f"Audit rules validation error: {e}")
        return False


def _rollback_audit_rules(backup_metadata: Dict[str, Any]) -> bool:
    """Rollback audit rules from backup."""
    if not backup_metadata.get('success'):
        logging.getLogger(__name__).error("Cannot rollback: invalid backup metadata")
        return False
    
    backup_path = Path(backup_metadata['backup_path'])
    original_path = Path(backup_metadata['path'])
    
    if not backup_path.exists():
        logging.getLogger(__name__).error(f"Backup not found: {backup_path}")
        return False
    
    try:
        if original_path.exists():
            shutil.rmtree(original_path)
        shutil.copytree(backup_path, original_path)
        logging.getLogger(__name__).info(f"Rolled back audit rules: {original_path}")
        return True
    except Exception as e:
        logging.getLogger(__name__).error(f"Rollback failed: {e}")
        return False


def _dry_run_audit_rules_fix(action: str, details: str) -> bool:
    """Simulate audit rules modification without actually changing anything."""
    logging.getLogger(__name__).info(f"[DRY-RUN] Would perform: {action} - {details}")
    print(f"[DRY-RUN] Would perform: {action}")
    return True


def _confirm_audit_rules_add() -> bool:
    """Ask for confirmation before adding audit rules."""
    print(f"\n[!] WARNING: About to add audit rules")
    print("    Audit rules will generate additional system logs")
    response = ui.prompt("Proceed? [y/N]: ")
    if response.lower() == 'y':
        print("\n[*] Applying fixes... please wait")
        return True
    return False


def _verify_rule_effectiveness(rules: List[str]) -> bool:
    """Verify that audit rules are effective by checking their content."""
    logger = logging.getLogger(__name__)
    
    effective_patterns = ['all', 'watch', 'syscall']
    
    effective_count = 0
    for rule in rules:
        for pattern in effective_patterns:
            if pattern in rule:
                effective_count += 1
                break
    
    if effective_count < 5:
        logger.warning(f"Only {effective_count} effective audit rules found")
        return False
    
    logger.debug(f"Found {effective_count} effective audit rules")
    return True


def _has_duplicate_rules(rules: List[str]) -> bool:
    """Check if there are duplicate audit rules."""
    seen = set()
    duplicates = []
    
    for rule in rules:
        if rule in seen:
            duplicates.append(rule)
        else:
            seen.add(rule)
    
    if duplicates:
        logging.getLogger(__name__).warning(f"Duplicate audit rules found: {len(duplicates)}")
        return True
    
    return False


def _progress_indicator(current: int, total: int, message: str = ""):
    """Show progress during operations."""
    if total > 0:
        percent = (current / total) * 100
        print(f"\r\033[K[{current}/{total}] {percent:.1f}% - {message}", end="", flush=True)


# ============================================================
# FIX 6: SAFE LOAD AUDIT RULES WITH RETRY
# ============================================================
def _load_audit_rules(retries: int = 3) -> bool:
    """Load audit rules with retry mechanism."""
    logger = logging.getLogger(__name__)
    
    for attempt in range(retries):
        try:
            result = subprocess.run(
                ['augenrules', '--load'],
                capture_output=True,
                text=True,
                timeout=30, stdin=subprocess.DEVNULL)
            
            if result.returncode == 0:
                logger.info("Audit rules loaded successfully")
                return True
            else:
                logger.debug(f"Attempt {attempt + 1} failed: {result.stderr}")
                time.sleep(1)
        except FileNotFoundError:
            logger.debug("augenrules not found (auditd not installed)")
            return False
        except Exception as e:
            logger.debug(f"Attempt {attempt + 1} error: {e}")
            time.sleep(1)
    
    return False


def _safe_add_audit_rules(dry_run: bool = False) -> bool:
    """
    Safely add audit rules with backup, validation, dry-run, and rollback.
    """
    logger = logging.getLogger(__name__)
    
    if dry_run:
        _dry_run_audit_rules_fix("add_audit_rules", "Would add audit rules")
        return True
    
    if not _confirm_audit_rules_add():
        logger.info("Audit rules addition cancelled by user")
        return False
    
    # Check current rules for duplicates
    current_rules = _get_current_rules()
    if _has_duplicate_rules(current_rules):
        logger.warning("Duplicate rules already exist")
    
    # Backup current audit rules
    backup_metadata = _backup_audit_rules()
    if not backup_metadata['success']:
        logger.warning("Could not backup audit rules")
    
    try:
        AUDIT_RULES_DIR.mkdir(parents=True, exist_ok=True)
        rules_file = AUDIT_RULES_DIR / "shadow.rules"
        
        if rules_file.exists():
            logger.info("shadow.rules already exists, updating...")
        
        # Write rules
        rules_content = "# Shadow added - Essential audit rules\n"
        for essential in ESSENTIAL_RULES:
            rules_content += f"{essential['rule']}  # {essential['description']}\n"
        
        with open(rules_file, 'w') as f:
            f.write(rules_content)
        
        logger.info(f"Audit rules written to: {rules_file}")
        
        if not _validate_audit_rules(rules_file):
            logger.error("Audit rules validation failed")
            if backup_metadata['success']:
                _rollback_audit_rules(backup_metadata)
            _log_audit_rules_change("add_audit_rules", "Validation failed", False)
            return False
        
        # FIX 6: Load rules with retry
        if not _load_audit_rules():
            logger.error("Failed to load audit rules after retries")
            if backup_metadata['success']:
                _rollback_audit_rules(backup_metadata)
            _log_audit_rules_change("add_audit_rules", "Load failed", False)
            return False
        
        # Verify rules were loaded
        current_rules = _get_current_rules()
        missing = _check_essential_rules(current_rules)
        if missing:
            logger.error(f"Essential rules still missing: {missing}")
            if backup_metadata['success']:
                _rollback_audit_rules(backup_metadata)
            _log_audit_rules_change("add_audit_rules", f"Missing rules: {missing}", False)
            return False
        
        _verify_rule_effectiveness(current_rules)
        _log_audit_rules_change("add_audit_rules", "Audit rules added and loaded successfully", True)
        logger.info("Audit rules added and loaded successfully")
        return True
        
    except Exception as e:
        logger.error(f"Error adding audit rules: {e}")
        if backup_metadata['success']:
            _rollback_audit_rules(backup_metadata)
        _log_audit_rules_change("add_audit_rules", str(e), False)
        return False


def fix(config: dict, dry_run: bool = False, force: bool = False) -> bool:
    """
    Fix audit rules

    Args:
        config: Configuration dictionary
        dry_run: If True, preview changes without applying
        force: If True, skip confirmation

    Returns:
        bool: True if fixes applied successfully
    """
    logger = logging.getLogger(__name__)
    logger.info("Fixing audit rules...")

    # Check for dry-run mode (use parameter, not config)
    if dry_run:
        logger.info("DRY-RUN MODE: No changes will be applied")
        print("\n[!] DRY-RUN MODE - No changes will be applied")
        
        current_rules = _get_current_rules()
        missing = _check_essential_rules(current_rules)
        
        if missing:
            print(f"  Would add {len(missing)} missing audit rules:")
            for rule_name in missing:
                for essential in ESSENTIAL_RULES:
                    if essential['name'] == rule_name:
                        print(f"    {essential['rule']}")
        else:
            print("  All essential audit rules are present")
        
        print("\n[✓] Dry-run complete. No changes were made.")
        return True

    # FIX: Skip confirmation in force mode
    if not force:
        if not _confirm_audit_rules_add():
            logger.info("Audit rules addition cancelled by user")
            return False
    else:
        logger.info("Force mode: Adding audit rules without confirmation")

    try:
        begin_transaction()
        
        success = _safe_add_audit_rules(dry_run)
        
        if success:
            commit_transaction()
            logger.info("Audit rules added successfully")
            print("\n✅ Audit rules added successfully")
            return True
        else:
            rollback_transaction()
            logger.error("Failed to add audit rules")
            print("\n❌ Failed to add audit rules")
            return False

    except Exception as e:
        logger.error(f"Failed to add audit rules: {e}")
        rollback_transaction()
        return False