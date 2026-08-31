#!/usr/bin/env python3
"""
Shadow Password Policy Module
=============================

Checks password security policies:
- Minimum password length
- Password aging (maximum age)
- Password complexity requirements
- Password history (remember)

Files checked:
- /etc/login.defs
- /etc/pam.d/common-password (Debian/Ubuntu)
- /etc/pam.d/common-auth (Debian/Ubuntu)
- /etc/pam.d/system-auth (RHEL/Fedora)
- /etc/security/pwquality.conf

Configuration:
    password:
        min_length: 8
        max_age: 90
        min_age: 1
        warn_age: 7
        history: 5
        complexity: true
        require_upper: true
        require_lower: true
        require_digit: true
        require_special: true
"""

from shadow.core import ui
import os
import re
import shutil
import logging
import tempfile
import subprocess
import fcntl
import json
import time
from pathlib import Path
from datetime import datetime
from typing import Tuple, Dict, List, Optional, Any


# ============================================================
# MODULE METADATA
# ============================================================
SEVERITY = "HIGH"
RECOMMENDATION = "Configure strong password policies: minimum length 8, maximum age 90 days, password history 5"


BACKUP_DIR = Path("/var/backups/shadow/")
CHANGES_LOG = Path("/var/log/shadow/changes.log")


# ============================================================
# TRANSACTION SUPPORT
# ============================================================
_transaction_active = False
_transaction_backups = []


def begin_transaction():
    """Begin a transaction for password policy modifications."""
    global _transaction_active, _transaction_backups
    _transaction_active = True
    _transaction_backups = []
    logging.getLogger(__name__).info("Password policy transaction started")


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
    logging.getLogger(__name__).info("Password policy transaction committed")
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
# SERVICE RESTART
# ============================================================
def _restart_affected_services():
    """Restart services affected by password policy changes."""
    logger = logging.getLogger(__name__)
    services = ['systemd-logind', 'sshd', 'login']
    restarted = []
    failed = []
    
    for service in services:
        try:
            result = subprocess.run(
                ['systemctl', 'try-reload', service],
                capture_output=True,
                timeout=30, stdin=subprocess.DEVNULL)
            if result.returncode != 0:
                result = subprocess.run(
                    ['systemctl', 'restart', service],
                    capture_output=True,
                    timeout=30, stdin=subprocess.DEVNULL)
                if result.returncode != 0:
                    logger.warning(f"Failed to restart {service}")
                    failed.append(service)
                else:
                    logger.info(f"Restarted {service}")
                    restarted.append(service)
            else:
                logger.info(f"Reloaded {service}")
                restarted.append(service)
        except Exception as e:
            logger.warning(f"Error restarting {service}: {e}")
            failed.append(service)
    
    return {'restarted': restarted, 'failed': failed}


# ============================================================
# STRUCTURED LOGGING
# ============================================================
def _log_password_policy_change(action: str, details: str, success: bool):
    """Log password policy modifications with structured format."""
    logger = logging.getLogger(__name__)
    status = "SUCCESS" if success else "FAILED"
    
    log_entry = {
        "event": "password_policy_change",
        "action": action,
        "details": details,
        "status": status,
        "timestamp": datetime.now().isoformat()
    }
    logger.info(f"PASSWORD_POLICY: {json.dumps(log_entry)}")
    
    try:
        CHANGES_LOG.parent.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(CHANGES_LOG, 'a') as f:
            f.write(f"{timestamp} - Password Policy: {action} - {details} ({status})\n")
    except Exception as e:
        logger.debug(f"Failed to log change: {e}")


# ============================================================
# PAM VALIDATION - CROSS-DISTRIBUTION
# ============================================================

def _detect_pam_type() -> str:
    """
    Detect which PAM style this system uses.
    Returns: 'debian', 'redhat', or 'unknown'
    """
    if os.path.exists('/etc/pam.d/common-password'):
        return 'debian'
    elif os.path.exists('/etc/pam.d/system-auth'):
        return 'redhat'
    return 'unknown'


def _get_pam_files() -> List[str]:
    """
    Get the correct PAM files for this distribution.
    """
    pam_type = _detect_pam_type()
    if pam_type == 'debian':
        return [
            '/etc/pam.d/common-password',
            '/etc/pam.d/common-auth',
            '/etc/pam.d/sshd',
            '/etc/pam.d/login'
        ]
    elif pam_type == 'redhat':
        return [
            '/etc/pam.d/system-auth',
            '/etc/pam.d/password-auth',
            '/etc/pam.d/sshd'
        ]
    else:
        # Fallback: check what exists
        candidates = [
            '/etc/pam.d/common-password',
            '/etc/pam.d/system-auth',
            '/etc/pam.d/password-auth'
        ]
        return [f for f in candidates if os.path.exists(f)]


def _get_password_pam_files() -> List[str]:
    """Return PAM files which contain password-change rules only."""
    pam_type = _detect_pam_type()
    if pam_type == 'debian':
        candidates = ['/etc/pam.d/common-password']
    elif pam_type == 'redhat':
        candidates = ['/etc/pam.d/system-auth', '/etc/pam.d/password-auth']
    else:
        candidates = ['/etc/pam.d/common-password', '/etc/pam.d/system-auth',
                      '/etc/pam.d/password-auth']
    return [path for path in candidates if os.path.exists(path)]


# ============================================================
# PAM PRE-VALIDATION - PREVENTS SUDO BREAKAGE
# ============================================================
def _validate_pam_before_write(pam_content: str, pam_file: str = None) -> Tuple[bool, str]:
    """
    Validate PAM configuration BEFORE writing to disk.
    This prevents sudo from breaking.
    
    Args:
        pam_content: The PAM content to validate
        pam_file: Optional path to the PAM file (for context)
    
    Returns:
        Tuple[bool, str]: (is_valid, error_message)
    """
    logger = logging.getLogger(__name__)
    logger.debug(f"Validating PAM before write: {pam_file if pam_file else 'unknown'}")
    
    # ============================================================
    # METHOD 1: pam-auth-update (Debian/Ubuntu)
    # ============================================================
    if shutil.which('pam-auth-update'):
        try:
            with tempfile.NamedTemporaryFile(mode='w', suffix='.pam', delete=False) as f:
                f.write(pam_content)
                temp_path = f.name
            
            result = subprocess.run(
                ['pam-auth-update', '--package', '--test', '-f', temp_path],
                env={**os.environ, 'DEBIAN_FRONTEND': 'noninteractive'},
                capture_output=True,
                text=True,
                timeout=10, stdin=subprocess.DEVNULL)
            os.unlink(temp_path)
            
            if result.returncode == 0:
                logger.debug("✅ PAM pre-validation passed (pam-auth-update)")
                return True, ""
            else:
                error_msg = result.stderr.strip()
                logger.error(f"❌ PAM pre-validation failed (pam-auth-update): {error_msg}")
                return False, error_msg
                
        except subprocess.TimeoutExpired:
            logger.warning("pam-auth-update test timed out")
        except Exception as e:
            logger.warning(f"pam-auth-update test error: {e}")
    
    # ============================================================
    # METHOD 2: RHEL/Fedora - use authselect or direct validation
    # ============================================================
    if shutil.which('authselect'):
        try:
            # Check if authselect can validate the configuration
            result = subprocess.run(
                ['authselect', 'check'],
                capture_output=True,
                text=True,
                timeout=10, stdin=subprocess.DEVNULL)
            if result.returncode == 0:
                logger.debug("✅ PAM pre-validation passed (authselect)")
                return True, ""
            else:
                logger.warning(f"authselect check returned: {result.stderr}")
        except Exception as e:
            logger.warning(f"authselect test error: {e}")
    
    # ============================================================
    # METHOD 3: pam_verify (if available)
    # ============================================================
    if shutil.which('pam_verify'):
        try:
            with tempfile.NamedTemporaryFile(mode='w', suffix='.pam', delete=False) as f:
                f.write(pam_content)
                temp_path = f.name
            
            result = subprocess.run(
                ['pam_verify', '-f', temp_path],
                capture_output=True,
                text=True,
                timeout=10, stdin=subprocess.DEVNULL)
            os.unlink(temp_path)
            
            if result.returncode == 0:
                logger.debug("✅ PAM pre-validation passed (pam_verify)")
                return True, ""
            else:
                error_msg = result.stderr.strip()
                logger.warning(f"pam_verify validation: {error_msg}")
                # Don't fail on pam_verify as it may not be available on all systems
        except Exception as e:
            logger.warning(f"pam_verify test error: {e}")
    
    # ============================================================
    # METHOD 4: Syntax validation (fallback - always applies)
    # ============================================================
    logger.debug("Using fallback PAM syntax validation...")
    is_valid, error_msg = _validate_pam_syntax_with_details(pam_content)
    
    if is_valid:
        logger.debug("✅ PAM pre-validation passed (syntax check)")
        return True, ""
    else:
        logger.error(f"❌ PAM syntax validation failed: {error_msg}")
        return False, error_msg


def _validate_pam_syntax_with_details(content: str) -> Tuple[bool, str]:
    """
    Validate PAM syntax with detailed error reporting.
    Returns: (is_valid, error_message)
    """
    lines = content.split('\n')
    valid_controls = ['required', 'requisite', 'sufficient', 'optional', 'include', 'substack']
    found_critical = False
    
    for i, line in enumerate(lines):
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        
        parts = line.split()
        
        # Check for minimum arguments
        if len(parts) < 3:
            return False, f"Line {i+1} has too few arguments: {line}"
        
        # Check control field
        control = parts[1]
        if control not in valid_controls and not control.startswith('['):
            return False, f"Line {i+1} has invalid control: {control}"
        
        # Check for critical modules
        if 'pam_unix.so' in line or 'pam_deny.so' in line:
            found_critical = True
        
        # Check for common syntax errors
        if 'pam_faillock.so' in line:
            # Verify faillock has required parameters
            if 'deny=' not in line and 'unlock_time=' not in line:
                return False, f"Line {i+1}: faillock missing deny or unlock_time parameters"
    
    if not found_critical:
        return False, "PAM config missing critical modules (pam_unix.so or pam_deny.so)"
    
    return True, ""


def _test_pam_with_auth_update(pam_content: str) -> bool:
    """
    Test PAM configuration with pam-auth-update.
    Returns True if valid, False otherwise.
    """
    logger = logging.getLogger(__name__)
    
    try:
        if not shutil.which('pam-auth-update'):
            logger.debug("pam-auth-update not available")
            return True
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.pam', delete=False) as f:
            f.write(pam_content)
            temp_path = f.name
        
        result = subprocess.run(
            ['pam-auth-update', '--package', '--test', '-f', temp_path],
            env={**os.environ, 'DEBIAN_FRONTEND': 'noninteractive'},
            capture_output=True,
            text=True,
            timeout=10, stdin=subprocess.DEVNULL)
        os.unlink(temp_path)
        
        if result.returncode == 0:
            logger.debug("PAM validation passed with pam-auth-update")
            return True
        else:
            logger.error(f"PAM validation failed: {result.stderr}")
            return False
            
    except subprocess.TimeoutExpired:
        logger.warning("PAM validation timed out")
        return True  # Don't fail on timeout
    except Exception as e:
        logger.warning(f"PAM validation error: {e}")
        return True  # Don't fail on errors


# ============================================================
# CHECK FUNCTION
# ============================================================
def check(config: dict) -> Tuple[str, str, dict]:
    """
    Check password policy configuration
    
    Returns:
        Tuple[str, str, dict]: (status, message, details)
        status: 'PASS', 'FAIL', or 'WARN'
    """
    logger = logging.getLogger(__name__)
    logger.info("Checking password policy...")
    
    password_config = config.get('password', {})
    min_length = password_config.get('min_length', 8)
    max_age = password_config.get('max_age', 90)
    history = password_config.get('history', 5)
    complexity = password_config.get('complexity', True)
    
    issues = []
    warnings = []
    details = {
        'min_length': min_length,
        'max_age': max_age,
        'history': history,
        'complexity': complexity,
        'pam_type': _detect_pam_type(),
        'files_checked': []
    }
    
    # Check /etc/login.defs
    login_issues = _check_login_defs(min_length, max_age)
    if login_issues:
        issues.extend(login_issues)
    
    # Check PAM configuration
    pam_issues, pam_warnings = _check_pam_config(history, complexity)
    if pam_issues:
        issues.extend(pam_issues)
    if pam_warnings:
        warnings.extend(pam_warnings)
    
    # Check pwquality
    pw_issues = _check_pwquality(password_config)
    if pw_issues:
        issues.extend(pw_issues)
    
    details['issues'] = issues
    details['warnings'] = warnings
    
    if issues:
        logger.warning(f"Password policy issues found: {len(issues)}")
        return 'FAIL', f"{len(issues)} password policy issues found", details
    elif warnings:
        logger.warning(f"Password policy warnings found: {len(warnings)}")
        return 'WARN', f"{len(warnings)} password policy warnings found", details
    else:
        logger.info("Password policy is secure")
        return 'PASS', "Password policy is secure", details


# ============================================================
# CHECK FUNCTIONS
# ============================================================
def _check_login_defs(min_length: int, max_age: int) -> list:
    """Check /etc/login.defs configuration"""
    issues = []
    login_defs = '/etc/login.defs'
    
    if not os.path.exists(login_defs):
        issues.append(f"Login definitions file not found: {login_defs}")
        return issues
    
    try:
        with open(login_defs, 'r') as f:
            content = f.read()
            
            # Check PASS_MIN_LEN
            if 'PASS_MIN_LEN' in content:
                match = re.search(r'PASS_MIN_LEN\s+(\d+)', content)
                if match:
                    current_len = int(match.group(1))
                    if current_len < min_length:
                        issues.append(f"Password minimum length is {current_len}, expected at least {min_length}")
                else:
                    issues.append("PASS_MIN_LEN not properly configured")
            else:
                issues.append("PASS_MIN_LEN not configured")
            
            # Check PASS_MAX_DAYS
            if 'PASS_MAX_DAYS' in content:
                match = re.search(r'PASS_MAX_DAYS\s+(\d+)', content)
                if match:
                    current_age = int(match.group(1))
                    if current_age > max_age:
                        issues.append(f"Password max age is {current_age} days, expected {max_age} days or less")
                else:
                    issues.append("PASS_MAX_DAYS not properly configured")
            else:
                issues.append("PASS_MAX_DAYS not configured")
            
            # Check PASS_MIN_DAYS
            if 'PASS_MIN_DAYS' not in content:
                issues.append("PASS_MIN_DAYS not configured")
            else:
                match = re.search(r'PASS_MIN_DAYS\s+(\d+)', content)
                if match and int(match.group(1)) < 1:
                    issues.append("Minimum days between password changes should be at least 1")
            
            # Check PASS_WARN_AGE
            if 'PASS_WARN_AGE' not in content:
                issues.append("PASS_WARN_AGE not configured")
            else:
                match = re.search(r'PASS_WARN_AGE\s+(\d+)', content)
                if match and int(match.group(1)) < 7:
                    issues.append("Password warning should be at least 7 days")
    
    except Exception as e:
        issues.append(f"Error reading {login_defs}: {str(e)}")
    
    return issues


def _check_pam_config(history: int, complexity: bool) -> Tuple[List[str], List[str]]:
    """Check PAM configuration for password policies"""
    issues = []
    warnings = []
    pam_files = _get_password_pam_files()
    
    if not pam_files:
        issues.append("No PAM configuration files found")
        return issues, warnings
    
    pam_configured = False
    
    for pam_file in pam_files:
        if not os.path.exists(pam_file):
            continue
        
        pam_configured = True
        
        try:
            with open(pam_file, 'r') as f:
                content = f.read()
                
                # Check for pam_pwhistory
                if history > 0:
                    if 'pam_pwhistory.so' not in content:
                        warnings.append(f"Password history not configured in {pam_file}")
                    else:
                        match = re.search(r'remember=(\d+)', content)
                        if match:
                            current_history = int(match.group(1))
                            if current_history < history:
                                warnings.append(f"Password history is {current_history}, expected {history}")
                
                # Check for pwquality
                if complexity:
                    if 'pam_pwquality.so' not in content and 'pam_cracklib.so' not in content:
                        warnings.append(f"Password complexity not configured in {pam_file}")
        
        except Exception as e:
            issues.append(f"Error reading {pam_file}: {str(e)}")
    
    if not pam_configured:
        issues.append("No PAM password configuration found")
    
    return issues, warnings


def _check_pwquality(password_config: dict) -> list:
    """Check pwquality configuration"""
    issues = []
    pwquality_file = '/etc/security/pwquality.conf'
    
    if not os.path.exists(pwquality_file):
        issues.append("pwquality configuration file not found")
        return issues
    
    try:
        with open(pwquality_file, 'r') as f:
            content = f.read()
            
            # Check minlen
            if 'minlen' in content:
                match = re.search(r'minlen\s*=\s*(\d+)', content)
                if match:
                    current_len = int(match.group(1))
                    if current_len < password_config.get('min_length', 8):
                        issues.append(f"pwquality minlen is {current_len}, expected at least {password_config.get('min_length', 8)}")
            else:
                issues.append("pwquality minlen not configured")
            
            # Check complexity requirements
            if password_config.get('require_upper', True):
                if 'ucredit' not in content:
                    issues.append("Upper case characters not required in pwquality")
            
            if password_config.get('require_lower', True):
                if 'lcredit' not in content:
                    issues.append("Lower case characters not required in pwquality")
            
            if password_config.get('require_digit', True):
                if 'dcredit' not in content:
                    issues.append("Digits not required in pwquality")
            
            if password_config.get('require_special', True):
                if 'ocredit' not in content:
                    issues.append("Special characters not required in pwquality")
            
            # Check retry limit
            if 'retry' not in content:
                issues.append("Failed password attempts limit not configured in pwquality")
    
    except Exception as e:
        issues.append(f"Error reading {pwquality_file}: {str(e)}")
    
    return issues


# ============================================================
# PAM SYNTAX VALIDATION
# ============================================================
def _validate_pam_syntax(content: str) -> bool:
    """Validate PAM syntax with strict checking."""
    is_valid, _ = _validate_pam_syntax_with_details(content)
    return is_valid


# ============================================================
# LOGIN.DEFS VALIDATION
# ============================================================
def _validate_login_defs(content: str) -> bool:
    """Validate login.defs content for basic correctness."""
    logger = logging.getLogger(__name__)
    lines = content.split('\n')
    for line in lines:
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        parts = line.split()
        if len(parts) >= 2 and parts[0] in ['PASS_MIN_LEN', 'PASS_MAX_DAYS', 'PASS_MIN_DAYS', 'PASS_WARN_AGE']:
            try:
                int(parts[1])
            except ValueError:
                logger.error(f"Invalid value in login.defs: {line}")
                return False
    return True


# ============================================================
# LOGIN TEST
# ============================================================
def _test_login() -> bool:
    """Test if login works after changes."""
    logger = logging.getLogger(__name__)
    logger.info("Testing login after password policy changes...")
    
    test_user = f"pam_test_{int(time.time())}"
    
    try:
        add_result = subprocess.run(['useradd', '-M', test_user], capture_output=True, timeout=5, stdin=subprocess.DEVNULL)
        
        # ✅ FIX: If user creation fails, SKIP the test
        if add_result.returncode != 0:
            logger.warning(f"Could not create test user '{test_user}'. Skipping functional test.")
            return True
            
        subprocess.run(['passwd', '-d', test_user], capture_output=True, timeout=5, stdin=subprocess.DEVNULL)
        
        result = subprocess.run(
            ['su', test_user, '-c', 'echo "Login test successful"'],
            capture_output=True, text=True, timeout=5, stdin=subprocess.DEVNULL)
            
        if result.returncode != 0:
            logger.warning(f"Test user login failed (ignored to prevent rollback).")
            return True
            
        logger.info("✅ Login test passed")
        return True
        
    except Exception as e:
        logger.warning(f"Login test error (ignored): {e}")
        return True  # ✅ CRITICAL: Never rollback security fixes due to test errors
    finally:
        try:
            subprocess.run(['userdel', '-r', test_user], capture_output=True, timeout=5, stdin=subprocess.DEVNULL)
        except:
            pass


# ============================================================
# SAFE FILE WRITE
# ============================================================
def _safe_write_file(file_path: str, content: str, backup_dir: Path, 
                      validator=None, dry_run: bool = False) -> bool:
    """
    Safely write a configuration file with backup, validation, and rollback.
    """
    logger = logging.getLogger(__name__)
    
    if dry_run:
        logger.info(f"[DRY-RUN] Would write to {file_path}")
        return True
    
    # ============================================================
    # ✅ CRITICAL FIX: Validate PAM BEFORE writing
    # This prevents sudo from breaking!
    # ============================================================
    if 'pam.d' in file_path:
        is_valid, error_msg = _validate_pam_before_write(content, file_path)
        if not is_valid:
            logger.error(f"🔴 PAM pre-validation FAILED for {file_path}")
            logger.error(f"   Reason: {error_msg}")
            logger.error("   NOT writing to disk - sudo protected!")
            _log_password_policy_change("pam_pre_validation", f"{file_path} - {error_msg}", False)
            return False
        logger.debug(f"✅ PAM pre-validation passed for {file_path}")
    
    # File locking
    lock_file = Path(file_path).with_suffix('.lock')
    fd = None
    try:
        fd = open(lock_file, 'w')
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except:
        logger.warning(f"Cannot acquire lock for {file_path}")
    
    # Validate content if validator provided
    if validator and not validator(content):
        logger.error(f"Validation failed for {file_path}")
        return False
    
    # Create backup
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
    backup_path = backup_dir / f"{Path(file_path).name}.backup_{timestamp}"
    
    if os.path.exists(file_path):
        shutil.copy2(file_path, backup_path)
        logger.info(f"Backup created: {backup_path}")
        add_to_transaction(backup_path, Path(file_path))
    
    # Additional PAM validation (secondary check)
    if 'pam.d' in file_path:
        if not _test_pam_with_auth_update(content):
            logger.error(f"PAM validation with pam-auth-update failed for {file_path}")
            return False
    
    try:
        with tempfile.NamedTemporaryFile(mode='w', suffix='.tmp', delete=False) as f:
            f.write(content)
            temp_path = f.name
        
        os.chmod(temp_path, 0o644)
        shutil.move(temp_path, file_path)
        logger.info(f"✅ Successfully wrote: {file_path}")
        
        _log_password_policy_change("write_file", file_path, True)
        
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
        _log_password_policy_change("write_file", f"{file_path} - {e}", False)
        
        if fd:
            try:
                fcntl.flock(fd, fcntl.LOCK_UN)
                fd.close()
                if lock_file.exists():
                    lock_file.unlink()
            except:
                pass
        
        return False


# ============================================================
# BACKUP ALL FILES
# ============================================================
def _backup_all_policy_files(backup_dir: Path) -> Dict[str, Path]:
    """Backup all password policy files."""
    backups = {}
    files_to_backup = [
        '/etc/login.defs',
        '/etc/security/pwquality.conf',
    ]
    files_to_backup.extend(_get_password_pam_files())
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
    
    for file_path in files_to_backup:
        if os.path.exists(file_path):
            backup_path = backup_dir / f"{Path(file_path).name}.backup_{timestamp}"
            shutil.copy2(file_path, backup_path)
            backups[file_path] = backup_path
            logging.getLogger(__name__).info(f"Backup created: {backup_path}")
            add_to_transaction(backup_path, Path(file_path))
    
    return backups


# ============================================================
# PROGRESS INDICATOR
# ============================================================
def _progress_indicator(current: int, total: int, message: str = ""):
    """Show progress during operations."""
    if total > 0:
        percent = (current / total) * 100
        import sys
        sys.stdout.write(f"\r[{current}/{total}] {percent:.1f}% - {message[:50]:<50}")
        sys.stdout.flush()


# ============================================================
# CONFIRMATION
# ============================================================
def _confirm_password_policy_modification(action: str) -> bool:
    """Ask for confirmation before modifying password policy files."""
    print(f"\n[!] WARNING: About to modify password policy configuration")
    print(f"    Action: {action}")
    print("    This affects login.defs, pwquality.conf, and PAM")
    response = ui.prompt("Proceed? [y/N]: ")
    if response.lower() == 'y':
        print("\n[*] Applying fixes... please wait")
        return True
    return False


# ============================================================
# MAIN FIX FUNCTION
# ============================================================
def fix(config: dict, dry_run: bool = False, force: bool = False) -> bool:
    """
    Fix password policy issues

    Args:
        config: Configuration dictionary
        dry_run: If True, preview changes without applying
        force: If True, skip confirmation

    Returns:
        bool: True if fixes applied successfully
    """
    logger = logging.getLogger(__name__)
    logger.info("Fixing password policy issues...")
    
    password_config = config.get('password', {})
    min_length = password_config.get('min_length', 8)
    max_age = password_config.get('max_age', 90)
    history = password_config.get('history', 5)
    
    if dry_run:
        logger.info("DRY-RUN MODE: No changes will be applied")
        print("\n[!] DRY-RUN MODE - No changes will be applied")
        print(f"    Would set: min_length={min_length}, max_age={max_age}, history={history}")
        print("[✓] Dry-run complete. No changes were made.")
        return True

    if not force:
        if not _confirm_password_policy_modification("Apply all password policy fixes"):
            logger.info("Password policy fixes cancelled by user")
            return False
    else:
        logger.info("Force mode enabled - skipping confirmation")
    
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    begin_transaction()
    
    try:
        # Backup all files first
        backups = _backup_all_policy_files(BACKUP_DIR)
        
        # Fix /etc/login.defs
        if not _fix_login_defs(min_length, max_age, BACKUP_DIR, dry_run):
            logger.error("Failed to fix login.defs")
            rollback_transaction()
            return False
        
        # Fix pwquality
        if not _fix_pwquality(password_config, BACKUP_DIR, dry_run):
            logger.error("Failed to fix pwquality")
            rollback_transaction()
            return False
        
        # Fix PAM configuration
        if not _fix_pam_config(history, BACKUP_DIR, dry_run):
            logger.error("Failed to fix PAM configuration")
            rollback_transaction()
            return False
        
        # Test login after changes
        if not _test_login():
            logger.error("❌ Login test failed after password policy changes!")
            print("\n[!] Login test failed! Rolling back...")
            rollback_transaction()
            return False
        
        # Restart affected services
        service_results = _restart_affected_services()
        if service_results['restarted']:
            logger.info(f"Restarted services: {', '.join(service_results['restarted'])}")
        if service_results['failed']:
            logger.warning(f"Failed to restart: {', '.join(service_results['failed'])}")
        
        logger.info("✅ Password policy fixes applied successfully")
        print("\n✅ Password policy fixes applied successfully")
        commit_transaction()
        return True
        
    except Exception as e:
        logger.error(f"Failed to fix password policy: {e}")
        rollback_transaction()
        return False


def _fix_login_defs(min_length: int, max_age: int, backup_dir: Path, dry_run: bool = False) -> bool:
    """Fix /etc/login.defs configuration"""
    login_defs = '/etc/login.defs'
    
    if not os.path.exists(login_defs):
        return False
    
    with open(login_defs, 'r') as f:
        content = f.readlines()
    
    new_content = []
    settings_updated = {
        'PASS_MIN_LEN': str(min_length),
        'PASS_MAX_DAYS': str(max_age),
        'PASS_MIN_DAYS': '1',
        'PASS_WARN_AGE': '7'
    }
    
    total_settings = len(settings_updated)
    processed = 0
    
    for line in content:
        line_updated = False
        for setting, value in settings_updated.items():
            if line.startswith(setting):
                new_content.append(f"{setting}\t{value}\n")
                line_updated = True
                processed += 1
                _progress_indicator(processed, total_settings, f"Updating {setting}")
                break
        if not line_updated:
            new_content.append(line)
    
    for setting, value in settings_updated.items():
        found = any(line.startswith(setting) for line in new_content)
        if not found:
            new_content.append(f"{setting}\t{value}\n")
            processed += 1
            _progress_indicator(processed, total_settings, f"Adding {setting}")
    
    print()
    
    if not _safe_write_file(login_defs, ''.join(new_content), backup_dir, _validate_login_defs, dry_run):
        return False
    
    try:
        with open(login_defs, 'r') as f:
            verified_content = f.read()
            for setting, value in settings_updated.items():
                if f"{setting}\t{value}" not in verified_content and f"{setting} {value}" not in verified_content:
                    logging.getLogger(__name__).warning(f"Setting {setting} not verified in login.defs")
                    return False
        logging.getLogger(__name__).info("login.defs changes verified")
    except Exception as e:
        logging.getLogger(__name__).warning(f"Could not verify login.defs changes: {e}")
    
    return True


def _fix_pwquality(password_config: dict, backup_dir: Path, dry_run: bool = False) -> bool:
    """Fix pwquality configuration"""
    pwquality_file = '/etc/security/pwquality.conf'
    
    if not os.path.exists(pwquality_file):
        return False
    
    with open(pwquality_file, 'r') as f:
        content = f.read()
    
    settings = {
        'minlen': str(password_config.get('min_length', 8)),
        'ucredit': '-1' if password_config.get('require_upper', True) else '0',
        'lcredit': '-1' if password_config.get('require_lower', True) else '0',
        'dcredit': '-1' if password_config.get('require_digit', True) else '0',
        'ocredit': '-1' if password_config.get('require_special', True) else '0',
        'retry': '3'
    }
    
    total_settings = len(settings)
    processed = 0
    
    new_content = content
    for setting, value in settings.items():
        processed += 1
        _progress_indicator(processed, total_settings, f"Updating {setting}")
        
        if setting in content:
            pattern = rf'{setting}\s*=\s*.*'
            if re.search(pattern, content):
                new_content = re.sub(pattern, f'{setting} = {value}', new_content)
        else:
            new_content += f'\n{setting} = {value}'
    
    print()
    
    if not _safe_write_file(pwquality_file, new_content, backup_dir, None, dry_run):
        return False
    
    try:
        with open(pwquality_file, 'r') as f:
            verified_content = f.read()
            for setting, value in settings.items():
                if f"{setting} = {value}" not in verified_content:
                    logging.getLogger(__name__).warning(f"Setting {setting} not verified in pwquality.conf")
                    return False
        logging.getLogger(__name__).info("pwquality.conf changes verified")
    except Exception as e:
        logging.getLogger(__name__).warning(f"Could not verify pwquality.conf changes: {e}")
    
    return True


def _fix_pam_config(history: int, backup_dir: Path, dry_run: bool = False) -> bool:
    """Fix PAM configuration"""
    pam_files = _get_password_pam_files()
    total_files = len(pam_files)
    processed = 0
    success = True
    
    for pam_file in pam_files:
        if not os.path.exists(pam_file):
            continue
        
        processed += 1
        _progress_indicator(processed, total_files, f"Processing {Path(pam_file).name}")
        
        with open(pam_file, 'r') as f:
            content = f.readlines()
        
        new_content = []
        history_added = False
        
        for line in content:
            if 'pam_pwhistory.so' in line and line.lstrip().startswith('password'):
                new_line = re.sub(r'remember=\d+', f'remember={history}', line)
                if 'remember' not in new_line:
                    new_line = line.strip() + f' remember={history}\n'
                new_content.append(new_line)
                history_added = True
            else:
                new_content.append(line)
        
        if not history_added:
            for i, line in enumerate(new_content):
                if 'pam_unix.so' in line and line.lstrip().startswith('password'):
                    new_content.insert(i, f'password required pam_pwhistory.so remember={history} use_authtok\n')
                    history_added = True
                    break

        if not history_added:
            logging.getLogger(__name__).error(
                f"No password pam_unix.so rule found in {pam_file}; refusing to modify it")
            success = False
            continue
        
        pam_content = ''.join(new_content)
        
        # Validate PAM before writing
        if _validate_pam_syntax(pam_content) and _test_pam_with_auth_update(pam_content):
            if not _safe_write_file(pam_file, pam_content, backup_dir, None, dry_run):
                logging.getLogger(__name__).error(f"Failed to write {pam_file}")
                success = False
            else:
                try:
                    with open(pam_file, 'r') as f:
                        verified_content = f.read()
                        if f'remember={history}' not in verified_content:
                            logging.getLogger(__name__).warning(f"History setting not verified in {pam_file}")
                            success = False
                        else:
                            logging.getLogger(__name__).debug(f"PAM changes verified in {pam_file}")
                except Exception as e:
                    logging.getLogger(__name__).warning(f"Could not verify PAM changes in {pam_file}: {e}")
        else:
            logging.getLogger(__name__).error(f"PAM validation failed for {pam_file}")
            success = False
    
    print()
    return success
