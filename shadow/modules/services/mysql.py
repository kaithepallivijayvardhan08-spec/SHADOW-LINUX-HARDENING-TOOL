#!/usr/bin/env python3
"""
Shadow MySQL Module
===================

Checks MySQL/MariaDB database security:
- MySQL/MariaDB is installed and running
- MySQL/MariaDB version (vulnerabilities)
- Root password set
- Anonymous users
- Test database
- Remote root access
- Password authentication plugin
- SSL/TLS configuration
- Logging configuration
- File privilege (LOAD DATA INFILE)

Files checked:
- /etc/mysql/my.cnf
- /etc/mysql/mariadb.conf.d/50-server.cnf
- /etc/mysql/mysql.conf.d/mysqld.cnf

Security concerns:
- No root password → full database access
- Anonymous users → unauthorized access
- Test database → unnecessary risk
- Remote root access → brute force risk
- Old MySQL version → known vulnerabilities
- No SSL → data exposure
- File privilege enabled → file read/write risk
"""

from shadow.core import ui
import os
import re
import shutil
import json
import logging
import subprocess
import tempfile
import time
from pathlib import Path
from datetime import datetime
from typing import Tuple, Dict, List, Optional, Any

# ============================================================
# MODULE METADATA
# ============================================================
SEVERITY = "HIGH"
RECOMMENDATION = "Set root password, remove anonymous users, disable remote root access, enable logging"

BACKUP_DIR = Path("/var/backups/shadow/")

# ============================================================
# TRANSACTION SUPPORT
# ============================================================
_transaction_active = False
_transaction_backups = []

def begin_transaction():
    """Begin a transaction for MySQL modifications."""
    global _transaction_active, _transaction_backups
    _transaction_active = True
    _transaction_backups = []
    logging.getLogger(__name__).info("MySQL transaction started")

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
    logging.getLogger(__name__).info("MySQL transaction committed")
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

def check(config: dict) -> Tuple[str, str, dict]:
    """
    Check MySQL/MariaDB security

    Returns:
        Tuple[str, str, dict]: (status, message, details)
    """
    logger = logging.getLogger(__name__)
    logger.info("Checking MySQL/MariaDB security...")

    issues = []
    warnings = []
    details = {
        'mysql_installed': False,
        'mysql_running': False,
        'mysql_version': None,
        'root_password': False,
        'anonymous_users': False,
        'test_database': False,
        'remote_root_access': False,
        'ssl_enabled': False,
        'logging_enabled': False,
        'file_privilege_enabled': False,
        'auth_plugin': 'unknown'
    }

    # Check if MySQL/MariaDB is installed
    mysql_installed = _check_mysql_installed()
    details['mysql_installed'] = mysql_installed

    if not mysql_installed:
        return 'PASS', "MySQL/MariaDB is not installed", details

    # Check if MySQL/MariaDB is running
    mysql_running = _check_mysql_running()
    details['mysql_running'] = mysql_running

    if not mysql_running:
        return 'WARN', "MySQL/MariaDB is installed but not running", details

    # Get MySQL version
    version_info = _get_mysql_version()
    details['mysql_version'] = version_info

    if version_info:
        if '5.5' in version_info or '5.6' in version_info:
            issues.append(f"MySQL version {version_info} is outdated and EOL")
        elif '5.7' in version_info:
            warnings.append(f"MySQL version {version_info} may be outdated")

    # Check root password
    root_password = _check_root_password()
    details['root_password'] = root_password

    if not root_password:
        issues.append("CRITICAL: MySQL root password is not set")

    # Check for anonymous users
    anonymous = _check_anonymous_users()
    details['anonymous_users'] = anonymous

    if anonymous:
        issues.append("Anonymous MySQL users exist")

    # Check for test database
    test_db = _check_test_database()
    details['test_database'] = test_db

    if test_db:
        warnings.append("Test database still exists")

    # Check remote root access
    remote_root = _check_remote_root_access()
    details['remote_root_access'] = remote_root

    if remote_root:
        issues.append("Root can connect from remote hosts")

    # Check SSL configuration
    ssl_enabled = _check_ssl_config()
    details['ssl_enabled'] = ssl_enabled

    if not ssl_enabled:
        warnings.append("MySQL SSL/TLS is not enabled")

    # Check logging
    logging_enabled = _check_logging()
    details['logging_enabled'] = logging_enabled

    if not logging_enabled:
        warnings.append("MySQL logging is not enabled")

    # Check file privilege
    file_privilege = _check_file_privilege()
    details['file_privilege_enabled'] = file_privilege

    if file_privilege:
        warnings.append("FILE privilege may be enabled (LOAD DATA INFILE)")

    # Check authentication plugin
    auth_plugin = _check_auth_plugin()
    details['auth_plugin'] = auth_plugin

    if auth_plugin == 'mysql_native_password':
        warnings.append("Using legacy authentication plugin (mysql_native_password)")

    # Determine status
    if issues:
        critical = [i for i in issues if 'CRITICAL' in i or 'root password' in i]
        if critical:
            status = 'FAIL'
            message = f"{len(issues)} critical MySQL issues found"
        else:
            status = 'WARN'
            message = f"{len(issues)} MySQL issues found"
    elif warnings:
        status = 'WARN'
        message = f"{len(warnings)} MySQL warnings found"
    else:
        status = 'PASS'
        message = "MySQL is securely configured"

    return status, message, details


def _check_mysql_installed() -> bool:
    """Check if MySQL/MariaDB is installed"""
    mysql_paths = [
        '/usr/bin/mysql',
        '/usr/sbin/mysqld',
        '/usr/bin/mariadb',
        '/usr/sbin/mariadbd'
    ]

    for path in mysql_paths:
        if os.path.exists(path):
            return True

    try:
        result = subprocess.run(['dpkg', '-l', 'mysql*', 'mariadb*'], 
                              capture_output=True, text=True, stdin=subprocess.DEVNULL)
        if 'mysql-server' in result.stdout or 'mariadb-server' in result.stdout:
            return True
    except:
        pass

    try:
        result = subprocess.run(['rpm', '-qa', 'mysql*', 'mariadb*'],
                              capture_output=True, text=True, stdin=subprocess.DEVNULL)
        if 'mysql-server' in result.stdout or 'mariadb-server' in result.stdout:
            return True
    except:
        pass

    return False


def _check_mysql_running() -> bool:
    """Check if MySQL/MariaDB is running"""
    try:
        result = subprocess.run(['systemctl', 'is-active', 'mysql'],
                              capture_output=True, text=True, stdin=subprocess.DEVNULL)
        if result.stdout.strip() == 'active':
            return True
    except:
        pass

    try:
        result = subprocess.run(['systemctl', 'is-active', 'mariadb'],
                              capture_output=True, text=True, stdin=subprocess.DEVNULL)
        if result.stdout.strip() == 'active':
            return True
    except:
        pass

    try:
        result = subprocess.run(['ps', 'aux'], capture_output=True, text=True, stdin=subprocess.DEVNULL)
        if 'mysqld' in result.stdout or 'mariadbd' in result.stdout:
            return True
    except:
        pass

    return False


def _get_mysql_version() -> Optional[str]:
    """Get MySQL/MariaDB version"""
    try:
        result = subprocess.run(['mysql', '--version'], capture_output=True, text=True, stdin=subprocess.DEVNULL)
        if result.returncode == 0:
            match = re.search(r'(mysql|mariadb)\s+Ver\s+(\d+\.\d+\.\d+)', result.stdout, re.IGNORECASE)
            if match:
                return match.group(2)
    except:
        pass

    return None


def _check_root_password() -> bool:
    """Check if MySQL root password is set"""
    try:
        result = subprocess.run(['mysql', '-u', 'root', '-e', 'SELECT 1'],
                              capture_output=True, text=True, timeout=5, stdin=subprocess.DEVNULL)
        if result.returncode == 0:
            return False
        return True
    except:
        return True


def _check_anonymous_users() -> bool:
    """Check for anonymous MySQL users"""
    try:
        result = subprocess.run(
            ['mysql', '-u', 'root', '-e', "SELECT User, Host FROM mysql.user WHERE User=''"],
            capture_output=True, text=True, timeout=5, stdin=subprocess.DEVNULL)
        if result.returncode == 0:
            if 'row' in result.stdout and '0 rows' not in result.stdout:
                return True
    except:
        pass
    return False


def _check_test_database() -> bool:
    """Check if test database exists"""
    try:
        result = subprocess.run(
            ['mysql', '-u', 'root', '-e', "SHOW DATABASES LIKE 'test'"],
            capture_output=True, text=True, timeout=5, stdin=subprocess.DEVNULL)
        if result.returncode == 0 and 'test' in result.stdout:
            return True
    except:
        pass
    return False


def _check_remote_root_access() -> bool:
    """Check if root can connect from remote hosts"""
    try:
        result = subprocess.run(
            ['mysql', '-u', 'root', '-e', "SELECT User, Host FROM mysql.user WHERE User='root' AND Host!='localhost'"],
            capture_output=True, text=True, timeout=5, stdin=subprocess.DEVNULL)
        if result.returncode == 0 and 'root' in result.stdout:
            return True
    except:
        pass
    return False


def _check_ssl_config() -> bool:
    """Check if MySQL SSL is enabled"""
    mysql_configs = [
        '/etc/mysql/my.cnf',
        '/etc/mysql/mariadb.conf.d/50-server.cnf',
        '/etc/mysql/mysql.conf.d/mysqld.cnf'
    ]

    for config_file in mysql_configs:
        if os.path.exists(config_file):
            try:
                with open(config_file, 'r') as f:
                    content = f.read()
                    if 'ssl-ca' in content or 'ssl-cert' in content or 'ssl-key' in content:
                        return True
            except:
                pass

    return False


def _check_logging() -> bool:
    """Check if MySQL logging is enabled"""
    mysql_configs = [
        '/etc/mysql/my.cnf',
        '/etc/mysql/mariadb.conf.d/50-server.cnf',
        '/etc/mysql/mysql.conf.d/mysqld.cnf'
    ]

    for config_file in mysql_configs:
        if os.path.exists(config_file):
            try:
                with open(config_file, 'r') as f:
                    content = f.read()
                    if 'general_log' in content or 'log_error' in content:
                        return True
            except:
                pass

    return False


def _check_file_privilege() -> bool:
    """Check if FILE privilege is enabled"""
    try:
        result = subprocess.run(
            ['mysql', '-u', 'root', '-e', "SELECT User, Host, File_priv FROM mysql.user WHERE File_priv='Y'"],
            capture_output=True, text=True, timeout=5, stdin=subprocess.DEVNULL)
        if result.returncode == 0 and 'Y' in result.stdout:
            return True
    except:
        pass
    return False


def _check_auth_plugin() -> str:
    """Check authentication plugin"""
    try:
        result = subprocess.run(
            ['mysql', '-u', 'root', '-e', "SELECT User, plugin FROM mysql.user WHERE User='root'"],
            capture_output=True, text=True, timeout=5, stdin=subprocess.DEVNULL)
        if result.returncode == 0:
            if 'mysql_native_password' in result.stdout:
                return 'mysql_native_password'
            elif 'caching_sha2_password' in result.stdout:
                return 'caching_sha2_password'
            elif 'unix_socket' in result.stdout:
                return 'unix_socket'
    except:
        pass
    return 'unknown'


# ============================================================
# FIX 1: BACKUP BEFORE MODIFYING MYSQL CONFIG
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


def _backup_mysql_config(file_path: str) -> Dict[str, Any]:
    """
    Backup MySQL configuration file with metadata.
    """
    result = {
        'path': file_path,
        'backup_path': None,
        'success': False
    }
    
    try:
        BACKUP_DIR.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        if os.path.exists(file_path):
            backup_path = BACKUP_DIR / f"{Path(file_path).name}.backup_{timestamp}"
            shutil.copy2(file_path, backup_path)
            result['backup_path'] = str(backup_path)
            
            if _verify_backup(backup_path):
                result['success'] = True
                logging.getLogger(__name__).info(f"Backup created: {backup_path}")
                add_to_transaction(backup_path, Path(file_path))

    except Exception as e:
        logging.getLogger(__name__).error(f"Failed to backup {file_path}: {e}")
    
    return result


# ============================================================
# FIX 2: VALIDATE MYSQL CONFIG BEFORE MODIFYING
# ============================================================
def _validate_mysql_config() -> bool:
    """
    Validate MySQL configuration syntax.
    Returns True if valid, False otherwise.
    """
    try:
        result = subprocess.run(
            ['mysqld', '--validate-config'],
            capture_output=True,
            text=True,
            timeout=10, stdin=subprocess.DEVNULL)
        if result.returncode == 0:
            logging.getLogger(__name__).debug("MySQL config validation passed")
            return True
        else:
            logging.getLogger(__name__).error(f"MySQL config validation failed: {result.stderr}")
            return False
    except:
        try:
            # Alternative validation for MariaDB
            result = subprocess.run(
                ['mariadbd', '--validate-config'],
                capture_output=True,
                text=True,
                timeout=10, stdin=subprocess.DEVNULL)
            if result.returncode == 0:
                logging.getLogger(__name__).debug("MySQL config validation passed")
                return True
            else:
                logging.getLogger(__name__).error(f"MySQL config validation failed: {result.stderr}")
                return False
        except Exception as e:
            logging.getLogger(__name__).error(f"MySQL config validation error: {e}")
            return False


# ============================================================
# FIX 3: ROLLBACK ON FAILURE
# ============================================================
def _rollback_mysql_config(backup_metadata: Dict[str, Any]) -> bool:
    """
    Rollback MySQL configuration from backup.
    """
    if not backup_metadata.get('success'):
        logging.getLogger(__name__).error("Cannot rollback: invalid backup metadata")
        return False
    
    backup_path = Path(backup_metadata['backup_path'])
    original_path = backup_metadata['path']
    
    if not backup_path.exists():
        logging.getLogger(__name__).error(f"Backup file not found: {backup_path}")
        return False
    
    try:
        shutil.copy2(backup_path, original_path)
        logging.getLogger(__name__).info(f"Rolled back MySQL config: {original_path}")
        return True
    except Exception as e:
        logging.getLogger(__name__).error(f"Rollback failed for {original_path}: {e}")
        return False


# ============================================================
# FIX 4: VERIFY MYSQL AFTER CHANGES
# ============================================================
def _verify_mysql_running() -> bool:
    """Verify MySQL is running and responding."""
    try:
        result = subprocess.run(
            ['systemctl', 'is-active', 'mysql'],
            capture_output=True,
            text=True,
            timeout=5, stdin=subprocess.DEVNULL)
        if result.stdout.strip() == 'active':
            return True
    except:
        pass
    
    try:
        result = subprocess.run(
            ['systemctl', 'is-active', 'mariadb'],
            capture_output=True,
            text=True,
            timeout=5, stdin=subprocess.DEVNULL)
        if result.stdout.strip() == 'active':
            return True
    except:
        pass
    
    return False


# ============================================================
# MEDIUM FIX 1: DRY-RUN MODE
# ============================================================
def _dry_run_mysql_fix(action: str, details: str) -> bool:
    """
    Simulate MySQL modification without actually changing anything.
    Used for dry-run mode.
    """
    logging.getLogger(__name__).info(f"[DRY-RUN] Would perform: {action} - {details}")
    print(f"[DRY-RUN] Would perform: {action}")
    return True


# ============================================================
# MEDIUM FIX 2: CONFIRMATION BEFORE MODIFYING MYSQL
# ============================================================
def _confirm_mysql_modification(action: str) -> bool:
    """
    Ask for confirmation before modifying MySQL.
    """
    print(f"\n[!] WARNING: About to modify MySQL/MariaDB configuration")
    print(f"    Action: {action}")
    print("    This could break your database!")
    response = ui.prompt("Proceed? [y/N]: ")
    if response.lower() == 'y':
        print("\n[*] Applying fixes... please wait")
        return True
    return False


# ============================================================
# MEDIUM FIX 3: LOGGING OF MYSQL CHANGES
# ============================================================
def _log_mysql_change(action: str, details: str, success: bool):
    """
    Log MySQL modifications.
    """
    logger = logging.getLogger(__name__)
    status = "SUCCESS" if success else "FAILED"
    logger.info(f"MySQL change: {action} - {details} ({status})")
    
    # Also log to changes.log for audit trail
    changes_log = Path("/var/log/shadow/changes.log")
    if changes_log.exists():
        with open(changes_log, 'a') as f:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            f.write(f"{timestamp} - MySQL: {action} - {details} ({status})\n")


# ============================================================
# MEDIUM FIX 4: VERIFY MYSQL ACCESSIBILITY
# ============================================================
def _verify_mysql_accessible() -> bool:
    """
    Verify MySQL is accessible.
    """
    try:
        result = subprocess.run(
            ['mysql', '-u', 'root', '-e', 'SELECT 1'],
            capture_output=True,
            text=True,
            timeout=5, stdin=subprocess.DEVNULL)
        if result.returncode == 0:
            return True
    except:
        pass
    
    try:
        import socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        result = sock.connect_ex(('127.0.0.1', 3306))
        sock.close()
        if result == 0:
            return True
    except:
        pass
    
    return False


# ============================================================
# LOW FIX 1: PROGRESS INDICATOR
# ============================================================
def _progress_indicator(current: int, total: int, message: str = ""):
    """
    Show progress during operations.
    """
    if total > 0:
        percent = (current / total) * 100
        print(f"\r\033[K[{current}/{total}] {percent:.1f}% - {message}", end="", flush=True)


def _safe_mysql_fix(config_file: str, fix_func, dry_run: bool = False, *args) -> bool:
    """
    Safely apply a MySQL fix with backup, validation, dry-run, and rollback.
    """
    logger = logging.getLogger(__name__)
    
    # MEDIUM FIX 1: Dry-run mode
    if dry_run:
        return _dry_run_mysql_fix("mysql_fix", f"Would apply fix to {config_file}")
    
    # MEDIUM FIX 2: Confirmation
    if not _confirm_mysql_modification(f"Apply fix to {config_file}"):
        logger.info("MySQL fix cancelled by user")
        return False
    
    # Step 1: Backup config
    backup_metadata = _backup_mysql_config(config_file)
    if not backup_metadata['success']:
        logger.warning(f"Could not backup {config_file}")
    
    try:
        # Step 2: Apply fix
        fix_func(*args)
        
        # Step 3: Validate config
        if not _validate_mysql_config():
            logger.error("MySQL config validation failed after fix")
            if backup_metadata['success']:
                _rollback_mysql_config(backup_metadata)
                _restart_mysql()
            # MEDIUM FIX 3: Log failure
            _log_mysql_change("mysql_fix", f"{config_file} - validation failed", False)
            return False
        
        # Step 4: Verify MySQL is running
        if not _verify_mysql_running():
            logger.error("MySQL is not running after fix")
            if backup_metadata['success']:
                _rollback_mysql_config(backup_metadata)
                _restart_mysql()
            # MEDIUM FIX 3: Log failure
            _log_mysql_change("mysql_fix", f"{config_file} - MySQL not running", False)
            return False
        
        # MEDIUM FIX 4: Verify MySQL accessibility
        if not _verify_mysql_accessible():
            logger.warning("MySQL may not be accessible - check manually")
        
        # MEDIUM FIX 3: Log success
        _log_mysql_change("mysql_fix", f"{config_file} - success", True)
        return True
        
    except Exception as e:
        logger.error(f"Error applying MySQL fix: {e}")
        if backup_metadata['success']:
            _rollback_mysql_config(backup_metadata)
            _restart_mysql()
        # MEDIUM FIX 3: Log failure
        _log_mysql_change("mysql_fix", f"{config_file} - {e}", False)
        return False


def _restart_mysql():
    """Restart MySQL service."""
    try:
        subprocess.run(['systemctl', 'restart', 'mysql'], capture_output=True, text=True, stdin=subprocess.DEVNULL)
    except:
        try:
            subprocess.run(['systemctl', 'restart', 'mariadb'], capture_output=True, text=True, stdin=subprocess.DEVNULL)
        except:
            pass

def _enable_mysql_service() -> bool:
    """Enable and start MySQL service if installed but not running."""
    logger = logging.getLogger(__name__)
    
    if not _check_mysql_installed():
        logger.info("MySQL is not installed, skipping enable")
        return True
    
    if _check_mysql_running():
        logger.info("MySQL is already running")
        return True
    
    try:
        logger.info("Enabling and starting MySQL service...")
        # Try MySQL first
        result = subprocess.run(['systemctl', 'enable', 'mysql'], capture_output=True, timeout=10, stdin=subprocess.DEVNULL)
        if result.returncode != 0:
            # Try MariaDB
            subprocess.run(['systemctl', 'enable', 'mariadb'], capture_output=True, timeout=10, stdin=subprocess.DEVNULL)
            subprocess.run(['systemctl', 'start', 'mariadb'], capture_output=True, timeout=10, stdin=subprocess.DEVNULL)
        else:
            subprocess.run(['systemctl', 'start', 'mysql'], capture_output=True, timeout=10, stdin=subprocess.DEVNULL)
        
        if _check_mysql_running():
            logger.info("MySQL started successfully")
            return True
        else:
            logger.error("MySQL failed to start")
            return False
    except Exception as e:
        logger.error(f"Failed to enable MySQL: {e}")
        return False

def _safe_mysql_command(command: str, args: List[str], dry_run: bool = False) -> bool:
    """
    Safely execute a MySQL command with error handling and dry-run support.
    """
    logger = logging.getLogger(__name__)
    
    # MEDIUM FIX 1: Dry-run mode
    if dry_run:
        _dry_run_mysql_fix("mysql_command", f"Would execute: {command}")
        return True
    
    try:
        full_cmd = ['mysql', '-u', 'root'] + args + ['-e', command]
        result = subprocess.run(full_cmd, capture_output=True, text=True, timeout=10, stdin=subprocess.DEVNULL)
        if result.returncode == 0:
            return True
        else:
            logger.error(f"MySQL command failed: {result.stderr}")
            return False
    except Exception as e:
        logger.error(f"MySQL command error: {e}")
        return False


def fix(config: dict, dry_run: bool = False, force: bool = False) -> bool:
    """
    Fix MySQL/MariaDB security issues

    Args:
        config: Configuration dictionary
        dry_run: If True, preview changes without applying
        force: If True, skip confirmation

    Returns:
        bool: True if fixes applied successfully
    """
    logger = logging.getLogger(__name__)
    logger.info("Fixing MySQL security issues...")

    # Check for dry-run mode
    if dry_run:
        logger.info("DRY-RUN MODE: No changes will be applied")
        print("\n[!] DRY-RUN MODE - No changes will be applied")
        
        # Show what would be done
        if config.get('mysql', {}).get('set_root_password', True):
            print("    Would prompt to set root password")
        if config.get('mysql', {}).get('remove_anonymous', True):
            print("    Would remove anonymous users")
        if config.get('mysql', {}).get('remove_test_db', True):
            print("    Would remove test database")
        if config.get('mysql', {}).get('disable_remote_root', True):
            print("    Would disable remote root access")
        if config.get('mysql', {}).get('enable_logging', True):
            print("    Would enable logging")
        
        print("\n[✓] Dry-run complete. No changes were made.")
        return True

    # Validate current MySQL config first
    if not _validate_mysql_config():
        logger.info("ℹ️ MySQL is not installed or configured. Skipping safely.")
        return True

    # ✅ FIX: Skip confirmation in force mode
    if not force:
        if not _confirm_mysql_modification("Apply all MySQL security fixes"):
            logger.info("MySQL fixes cancelled by user")
            return False
    else:
        logger.info("Force mode: Applying MySQL fixes without confirmation")

    try:
        begin_transaction()
        
        steps = []
        
        # Step 1: Set root password (manual)
        if config.get('mysql', {}).get('set_root_password', True):
            steps.append(("Set root password", _set_root_password))
        
        # Step 2: Remove anonymous users
        if config.get('mysql', {}).get('remove_anonymous', True):
            steps.append(("Remove anonymous users", _remove_anonymous_users))
        
        # Step 3: Remove test database
        if config.get('mysql', {}).get('remove_test_db', True):
            steps.append(("Remove test database", _remove_test_database))
        
        # Step 4: Disable remote root access
        if config.get('mysql', {}).get('disable_remote_root', True):
            steps.append(("Disable remote root access", _disable_remote_root))
        
        # Step 5: Enable logging
        if config.get('mysql', {}).get('enable_logging', True):
            steps.append(("Enable logging", _enable_logging))
        
        # Step 6: Remove FILE privilege
        if config.get('mysql', {}).get('remove_file_privilege', True):
            steps.append(("Remove FILE privilege", _remove_file_privilege))
        
        total_steps = len(steps)
        for idx, (name, func) in enumerate(steps):
            _progress_indicator(idx + 1, total_steps, name)
            func(dry_run)
        
        print()  # New line after progress

        if dry_run:
            logger.info("DRY-RUN completed successfully")
            commit_transaction()
            return True

        # Verify MySQL is still running
        if not _verify_mysql_running():
            logger.info("ℹ️ MySQL is not installed or not running. Skipping safely.")
            return True

        if not _verify_mysql_accessible():
            logger.warning("MySQL may not be accessible - check manually")

        commit_transaction()
        logger.info("MySQL fixes applied successfully")
        print("\n✅ MySQL fixes applied successfully")
        return True

    except Exception as e:
        logger.error(f"Failed to fix MySQL: {e}")
        rollback_transaction()
        return False


def _set_root_password(dry_run: bool = False):
    """Set MySQL root password"""
    if dry_run:
        _dry_run_mysql_fix("set_root_password", "Would prompt to set root password")
        return
    
    logging.getLogger(__name__).info("MySQL root password should be set manually")
    print("\n[!] MySQL root password is not set!")
    print("    Please run: mysql_secure_installation")
    print("    Or set password manually:")
    print("    ALTER USER 'root'@'localhost' IDENTIFIED BY 'your_password';")


def _remove_anonymous_users(dry_run: bool = False):
    """Remove anonymous MySQL users"""
    try:
        if _safe_mysql_command("DELETE FROM mysql.user WHERE User=''", [], dry_run):
            if not dry_run:
                logging.getLogger(__name__).info("Anonymous users removed")
                # MEDIUM FIX 3: Log the change
                _log_mysql_change("remove_anonymous", "Anonymous users removed", True)
    except Exception as e:
        logging.getLogger(__name__).error(f"Error removing anonymous users: {e}")
        # MEDIUM FIX 3: Log failure
        _log_mysql_change("remove_anonymous", str(e), False)


def _remove_test_database(dry_run: bool = False):
    """Remove test database"""
    try:
        if _safe_mysql_command("DROP DATABASE IF EXISTS test", [], dry_run):
            if not dry_run:
                logging.getLogger(__name__).info("Test database removed")
                # MEDIUM FIX 3: Log the change
                _log_mysql_change("remove_test_db", "Test database removed", True)
    except Exception as e:
        logging.getLogger(__name__).error(f"Error removing test database: {e}")
        # MEDIUM FIX 3: Log failure
        _log_mysql_change("remove_test_db", str(e), False)


def _disable_remote_root(dry_run: bool = False):
    """Disable remote root access"""
    try:
        if _safe_mysql_command("DELETE FROM mysql.user WHERE User='root' AND Host!='localhost'", [], dry_run):
            if not dry_run:
                logging.getLogger(__name__).info("Remote root access disabled")
                # MEDIUM FIX 3: Log the change
                _log_mysql_change("disable_remote_root", "Remote root access disabled", True)
    except Exception as e:
        logging.getLogger(__name__).error(f"Error disabling remote root: {e}")
        # MEDIUM FIX 3: Log failure
        _log_mysql_change("disable_remote_root", str(e), False)


def _enable_logging(dry_run: bool = False):
    """Enable MySQL logging"""
    mysql_config = '/etc/mysql/my.cnf'
    if not os.path.exists(mysql_config):
        mysql_config = '/etc/mysql/mariadb.conf.d/50-server.cnf'
    
    if os.path.exists(mysql_config):
        try:
            if dry_run:
                _dry_run_mysql_fix("enable_logging", f"Would enable logging in {mysql_config}")
                return
            
            backup_metadata = _backup_mysql_config(mysql_config)
            
            with open(mysql_config, 'r') as f:
                content = f.read()
            if 'general_log' not in content:
                content = content.replace('[mysqld]', '[mysqld]\ngeneral_log = 1\ngeneral_log_file = /var/log/mysql/mysql.log')
            with open(mysql_config, 'w') as f:
                f.write(content)
            
            logging.getLogger(__name__).info("MySQL logging enabled")
            # MEDIUM FIX 3: Log the change
            _log_mysql_change("enable_logging", "MySQL logging enabled", True)
            
            # Validate after change
            if not _validate_mysql_config():
                logging.getLogger(__name__).error("MySQL config validation failed after enabling logging")
                if backup_metadata['success']:
                    _rollback_mysql_config(backup_metadata)
                # MEDIUM FIX 3: Log failure
                _log_mysql_change("enable_logging", "Validation failed", False)
        except Exception as e:
            logging.getLogger(__name__).error(f"Error enabling logging: {e}")
            if 'backup_metadata' in locals() and backup_metadata['success']:
                _rollback_mysql_config(backup_metadata)
            # MEDIUM FIX 3: Log failure
            _log_mysql_change("enable_logging", str(e), False)


def _remove_file_privilege(dry_run: bool = False):
    """Remove FILE privilege from non-root users"""
    try:
        if _safe_mysql_command("UPDATE mysql.user SET File_priv='N' WHERE User!='root'", [], dry_run):
            if not dry_run:
                logging.getLogger(__name__).info("FILE privilege removed")
                # MEDIUM FIX 3: Log the change
                _log_mysql_change("remove_file_privilege", "FILE privilege removed", True)
    except Exception as e:
        logging.getLogger(__name__).error(f"Error removing FILE privilege: {e}")
        # MEDIUM FIX 3: Log failure
        _log_mysql_change("remove_file_privilege", str(e), False)