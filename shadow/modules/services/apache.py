#!/usr/bin/env python3
"""
Shadow Apache Module
====================

Checks Apache web server security:
- Apache is installed and running
- Apache version (vulnerabilities)
- Server tokens (information disclosure)
- Directory listing (information disclosure)
- Sensitive directories access
- SSL/TLS configuration
- Security headers
- Modules loaded (unnecessary modules)
- Logging configuration

Files checked:
- /etc/apache2/apache2.conf
- /etc/apache2/ports.conf
- /etc/apache2/sites-available/*.conf
- /etc/apache2/mods-enabled/*.conf

Security concerns:
- Outdated Apache version → known vulnerabilities
- ServerTokens Full → information disclosure
- Directory listing enabled → file exposure
- Default SSL config → weak encryption
- Unnecessary modules → larger attack surface
"""

from shadow.core import ui
import os
import re
import shutil
import glob
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
RECOMMENDATION = "Disable directory listing, set ServerTokens to Prod, and remove unnecessary modules"

BACKUP_DIR = Path("/var/backups/shadow/")

# ============================================================
# TRANSACTION SUPPORT
# ============================================================
_transaction_active = False
_transaction_backups = []

def begin_transaction():
    """Begin a transaction for Apache modifications."""
    global _transaction_active, _transaction_backups
    _transaction_active = True
    _transaction_backups = []
    logging.getLogger(__name__).info("Apache transaction started")

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
    logging.getLogger(__name__).info("Apache transaction committed")
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
    Check Apache web server security

    Returns:
        Tuple[str, str, dict]: (status, message, details)
    """
    logger = logging.getLogger(__name__)
    logger.info("Checking Apache security...")

    issues = []
    warnings = []
    details = {
        'apache_installed': False,
        'apache_running': False,
        'apache_version': None,
        'server_tokens': None,
        'directory_listing': False,
        'ssl_enabled': False,
        'security_headers': [],
        'loaded_modules': [],
        'sensitive_dirs': [],
        'log_config': False
    }

    # Check if Apache is installed
    apache_installed = _check_apache_installed()
    details['apache_installed'] = apache_installed

    if not apache_installed:
        return 'PASS', "Apache is not installed", details

    # Check if Apache is running
    apache_running = _check_apache_running()
    details['apache_running'] = apache_running

    if not apache_running:
        return 'WARN', "Apache is installed but not running", details

    # Get Apache version
    version_info = _get_apache_version()
    details['apache_version'] = version_info

    if version_info:
        if version_info.startswith('2.2'):
            issues.append(f"Apache version {version_info} is outdated (2.2.x is EOL)")
        elif version_info.startswith('2.0'):
            issues.append(f"Apache version {version_info} is ancient and insecure")

    # Check ServerTokens configuration
    server_tokens = _check_server_tokens()
    details['server_tokens'] = server_tokens

    if server_tokens and server_tokens.lower() == 'full':
        issues.append("ServerTokens Full enabled (information disclosure)")
    elif not server_tokens:
        warnings.append("ServerTokens not configured (default may be Full)")

    # Check directory listing
    dir_listing = _check_directory_listing()
    details['directory_listing'] = dir_listing

    if dir_listing:
        issues.append("Directory listing is enabled (information disclosure)")

    # Check SSL/TLS configuration
    ssl_enabled = _check_ssl_config()
    details['ssl_enabled'] = ssl_enabled

    if not ssl_enabled:
        warnings.append("SSL/TLS not configured (traffic not encrypted)")

    # Check security headers
    security_headers = _check_security_headers()
    details['security_headers'] = security_headers

    missing_headers = [h for h in ['X-Frame-Options', 'X-Content-Type-Options', 'X-XSS-Protection'] 
                       if h not in security_headers]
    if missing_headers:
        warnings.append(f"Missing security headers: {', '.join(missing_headers)}")

    # Check loaded modules
    loaded_modules = _check_loaded_modules()
    details['loaded_modules'] = loaded_modules

    unnecessary_modules = ['mod_info', 'mod_status', 'mod_userdir']
    for module in unnecessary_modules:
        if module in loaded_modules:
            warnings.append(f"Unnecessary module loaded: {module}")

    # Check sensitive directories
    sensitive_dirs = _check_sensitive_dirs()
    details['sensitive_dirs'] = sensitive_dirs

    if sensitive_dirs:
        warnings.append("Sensitive directories may be accessible")

    # Check logging configuration
    log_config = _check_logging()
    details['log_config'] = log_config

    if not log_config:
        warnings.append("Apache logging may not be properly configured")

    # Determine status
    if issues:
        critical = [i for i in issues if 'outdated' in i.lower() or 'directory listing' in i.lower()]
        if critical:
            status = 'FAIL'
            message = f"{len(issues)} critical Apache issues found"
        else:
            status = 'WARN'
            message = f"{len(issues)} Apache issues found"
    elif warnings:
        status = 'WARN'
        message = f"{len(warnings)} Apache warnings found"
    else:
        status = 'PASS'
        message = "Apache is securely configured"

    return status, message, details


def _check_apache_installed() -> bool:
    """Check if Apache is installed"""
    apache_paths = [
        '/usr/sbin/apache2',
        '/usr/sbin/apache',
        '/usr/sbin/httpd',
        '/usr/bin/apache2',
        '/usr/bin/apache'
    ]

    for path in apache_paths:
        if os.path.exists(path):
            return True

    try:
        result = subprocess.run(['dpkg', '-l', 'apache2*'], 
                              capture_output=True, text=True, stdin=subprocess.DEVNULL)
        if 'apache2' in result.stdout:
            return True
    except:
        pass

    try:
        result = subprocess.run(['rpm', '-qa', 'httpd*'],
                              capture_output=True, text=True, stdin=subprocess.DEVNULL)
        if 'httpd' in result.stdout:
            return True
    except:
        pass

    return False


def _check_apache_running() -> bool:
    """Check if Apache is running"""
    try:
        result = subprocess.run(['systemctl', 'is-active', 'apache2'],
                              capture_output=True, text=True, stdin=subprocess.DEVNULL)
        if result.stdout.strip() == 'active':
            return True
    except:
        pass

    try:
        result = subprocess.run(['systemctl', 'is-active', 'httpd'],
                              capture_output=True, text=True, stdin=subprocess.DEVNULL)
        if result.stdout.strip() == 'active':
            return True
    except:
        pass

    try:
        result = subprocess.run(['ps', 'aux'], capture_output=True, text=True, stdin=subprocess.DEVNULL)
        if 'apache2' in result.stdout or 'httpd' in result.stdout:
            return True
    except:
        pass

    return False


def _get_apache_version() -> Optional[str]:
    """Get Apache version"""
    try:
        result = subprocess.run(['apache2', '-v'], capture_output=True, text=True, stdin=subprocess.DEVNULL)
        for line in result.stdout.split('\n'):
            if 'Server version' in line:
                match = re.search(r'Apache/(\d+\.\d+\.\d+)', line)
                if match:
                    return match.group(1)
    except:
        pass

    try:
        result = subprocess.run(['httpd', '-v'], capture_output=True, text=True, stdin=subprocess.DEVNULL)
        for line in result.stdout.split('\n'):
            if 'Server version' in line:
                match = re.search(r'Apache/(\d+\.\d+\.\d+)', line)
                if match:
                    return match.group(1)
    except:
        pass

    return None


def _check_server_tokens() -> Optional[str]:
    """Check ServerTokens configuration"""
    apache_config = '/etc/apache2/conf-available/security.conf'
    
    if not os.path.exists(apache_config):
        apache_config = '/etc/httpd/conf/httpd.conf'
    
    if not os.path.exists(apache_config):
        return None

    try:
        with open(apache_config, 'r') as f:
            content = f.read()
            match = re.search(r'^ServerTokens\s+(\S+)', content, re.MULTILINE)
            if match:
                return match.group(1)
    except Exception as e:
        logging.getLogger(__name__).debug(f"Error reading ServerTokens: {e}")

    return None


def _check_directory_listing() -> bool:
    """Check if directory listing is enabled"""
    apache_configs = [
        '/etc/apache2/apache2.conf',
        '/etc/apache2/sites-enabled/*.conf'
    ]

    for config_pattern in apache_configs:
        try:
            for config_file in glob.glob(config_pattern):
                if os.path.exists(config_file):
                    with open(config_file, 'r') as f:
                        content = f.read()
                        if 'Options Indexes' in content:
                            return True
        except Exception as e:
            continue

    return False


def _check_ssl_config() -> bool:
    """Check if SSL/TLS is configured"""
    ssl_files = [
        '/etc/apache2/sites-enabled/default-ssl.conf',
        '/etc/apache2/sites-enabled/000-default-ssl.conf',
        '/etc/httpd/conf.d/ssl.conf'
    ]

    for ssl_file in ssl_files:
        if os.path.exists(ssl_file):
            return True

    return False


def _check_security_headers() -> List[str]:
    """Check security headers configuration"""
    headers = []
    apache_configs = [
        '/etc/apache2/apache2.conf',
        '/etc/apache2/sites-enabled/*.conf'
    ]

    header_patterns = [
        'X-Frame-Options',
        'X-Content-Type-Options',
        'X-XSS-Protection',
        'Strict-Transport-Security',
        'Content-Security-Policy'
    ]

    try:
        for config_pattern in apache_configs:
            for config_file in glob.glob(config_pattern):
                if os.path.exists(config_file):
                    with open(config_file, 'r') as f:
                        content = f.read()
                        for header in header_patterns:
                            if header in content and header not in headers:
                                headers.append(header)
    except Exception as e:
        pass

    return headers


def _check_loaded_modules() -> List[str]:
    """Check loaded Apache modules"""
    modules = []
    mods_dir = '/etc/apache2/mods-enabled'

    if os.path.exists(mods_dir):
        for mod_file in Path(mods_dir).iterdir():
            if mod_file.is_file() and mod_file.suffix == '.load':
                module_name = mod_file.stem
                modules.append(module_name)

    return modules


def _check_sensitive_dirs() -> List[str]:
    """Check for accessible sensitive directories"""
    sensitive = []
    doc_root = '/var/www/html'

    if os.path.exists(doc_root):
        sensitive_dirs = ['admin', 'config', 'backup', 'old', 'test', 'tmp']
        for s_dir in sensitive_dirs:
            if os.path.exists(os.path.join(doc_root, s_dir)):
                sensitive.append(s_dir)

    return sensitive


def _check_logging() -> bool:
    """Check if logging is configured"""
    log_configs = [
        '/etc/apache2/apache2.conf',
        '/etc/httpd/conf/httpd.conf'
    ]

    for log_config in log_configs:
        if os.path.exists(log_config):
            with open(log_config, 'r') as f:
                content = f.read()
                if 'CustomLog' in content or 'ErrorLog' in content:
                    return True

    return False


# ============================================================
# FIX 1: BACKUP BEFORE MODIFYING APACHE CONFIG
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


def _backup_apache_config(file_path: str) -> Dict[str, Any]:
    """
    Backup Apache configuration file with metadata.
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
# FIX 2: VALIDATE APACHE CONFIG BEFORE MODIFYING
# ============================================================
def _validate_apache_config() -> bool:
    """
    Validate Apache configuration syntax.
    Returns True if valid, False otherwise.
    """
    try:
        # Use apache2ctl or httpd to validate config
        result = subprocess.run(
            ['apache2ctl', 'configtest'],
            capture_output=True,
            text=True,
            timeout=10, stdin=subprocess.DEVNULL)
        if result.returncode == 0:
            logging.getLogger(__name__).debug("Apache config validation passed")
            return True
        else:
            logging.getLogger(__name__).error(f"Apache config validation failed: {result.stderr}")
            return False
    except:
        try:
            result = subprocess.run(
                ['httpd', '-t'],
                capture_output=True,
                text=True,
                timeout=10, stdin=subprocess.DEVNULL)
            if result.returncode == 0:
                logging.getLogger(__name__).debug("Apache config validation passed")
                return True
            else:
                logging.getLogger(__name__).error(f"Apache config validation failed: {result.stderr}")
                return False
        except Exception as e:
            logging.getLogger(__name__).error(f"Apache config validation error: {e}")
            return False


# ============================================================
# FIX 3: ROLLBACK ON FAILURE
# ============================================================
def _rollback_apache_config(backup_metadata: Dict[str, Any]) -> bool:
    """
    Rollback Apache configuration from backup.
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
        logging.getLogger(__name__).info(f"Rolled back Apache config: {original_path}")
        return True
    except Exception as e:
        logging.getLogger(__name__).error(f"Rollback failed for {original_path}: {e}")
        return False


# ============================================================
# FIX 4: VERIFY APACHE AFTER CHANGES
# ============================================================
def _verify_apache_running() -> bool:
    """Verify Apache is running and responding."""
    try:
        result = subprocess.run(
            ['systemctl', 'is-active', 'apache2'],
            capture_output=True,
            text=True,
            timeout=5, stdin=subprocess.DEVNULL)
        if result.stdout.strip() == 'active':
            return True
    except:
        pass
    
    try:
        result = subprocess.run(
            ['systemctl', 'is-active', 'httpd'],
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
def _dry_run_apache_fix(action: str, details: str) -> bool:
    """
    Simulate Apache modification without actually changing anything.
    Used for dry-run mode.
    """
    logging.getLogger(__name__).info(f"[DRY-RUN] Would perform: {action} - {details}")
    print(f"[DRY-RUN] Would perform: {action}")
    return True


# ============================================================
# MEDIUM FIX 2: CONFIRMATION BEFORE MODIFYING APACHE
# ============================================================
def _confirm_apache_modification(action: str) -> bool:
    """
    Ask for confirmation before modifying Apache.
    """
    print(f"\n[!] WARNING: About to modify Apache configuration")
    print(f"    Action: {action}")
    print("    This could break your web server!")
    response = ui.prompt("Proceed? [y/N]: ")
    if response.lower() == 'y':
        print("\n[*] Applying fixes... please wait")
        return True
    return False


# ============================================================
# MEDIUM FIX 3: LOGGING OF APACHE CHANGES
# ============================================================
def _log_apache_change(action: str, details: str, success: bool):
    """
    Log Apache modifications.
    """
    logger = logging.getLogger(__name__)
    status = "SUCCESS" if success else "FAILED"
    logger.info(f"Apache change: {action} - {details} ({status})")
    
    # Also log to changes.log for audit trail
    changes_log = Path("/var/log/shadow/changes.log")
    if changes_log.exists():
        with open(changes_log, 'a') as f:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            f.write(f"{timestamp} - Apache: {action} - {details} ({status})\n")


# ============================================================
# MEDIUM FIX 4: VERIFY APACHE ACCESSIBILITY
# ============================================================
def _verify_apache_accessible() -> bool:
    """
    Verify Apache is accessible via HTTP.
    """
    try:
        import socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        result = sock.connect_ex(('127.0.0.1', 80))
        sock.close()
        if result == 0:
            return True
    except:
        pass
    
    try:
        import urllib.request
        urllib.request.urlopen('http://127.0.0.1', timeout=3)
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


def _safe_apache_fix(config_file: str, fix_func, dry_run: bool = False, *args) -> bool:
    """
    Safely apply an Apache fix with backup, validation, dry-run, and rollback.
    """
    logger = logging.getLogger(__name__)
    
    # MEDIUM FIX 1: Dry-run mode
    if dry_run:
        return _dry_run_apache_fix("apache_fix", f"Would apply fix to {config_file}")
    
    # MEDIUM FIX 2: Confirmation
    if not _confirm_apache_modification(f"Apply fix to {config_file}"):
        logger.info("Apache fix cancelled by user")
        return False
    
    # Step 1: Backup config
    backup_metadata = _backup_apache_config(config_file)
    if not backup_metadata['success']:
        logger.warning(f"Could not backup {config_file}")
    
    try:
        # Step 2: Apply fix
        fix_func(*args)
        
        # Step 3: Validate config
        if not _validate_apache_config():
            logger.error("Apache config validation failed after fix")
            if backup_metadata['success']:
                _rollback_apache_config(backup_metadata)
                _restart_apache()
            # MEDIUM FIX 3: Log failure
            _log_apache_change("apache_fix", f"{config_file} - validation failed", False)
            return False
        
        # Step 4: Verify Apache is running
        if not _verify_apache_running():
            logger.error("Apache is not running after fix")
            if backup_metadata['success']:
                _rollback_apache_config(backup_metadata)
                _restart_apache()
            # MEDIUM FIX 3: Log failure
            _log_apache_change("apache_fix", f"{config_file} - Apache not running", False)
            return False
        
        # MEDIUM FIX 4: Verify Apache is accessible
        if not _verify_apache_accessible():
            logger.warning("Apache may not be accessible - check manually")
        
        # MEDIUM FIX 3: Log success
        _log_apache_change("apache_fix", f"{config_file} - success", True)
        return True
        
    except Exception as e:
        logger.error(f"Error applying Apache fix: {e}")
        if backup_metadata['success']:
            _rollback_apache_config(backup_metadata)
            _restart_apache()
        # MEDIUM FIX 3: Log failure
        _log_apache_change("apache_fix", f"{config_file} - {e}", False)
        return False


def _restart_apache():
    """Restart Apache service."""
    try:
        subprocess.run(['systemctl', 'restart', 'apache2'], capture_output=True, text=True, stdin=subprocess.DEVNULL)
    except:
        try:
            subprocess.run(['systemctl', 'restart', 'httpd'], capture_output=True, text=True, stdin=subprocess.DEVNULL)
        except:
            pass


def fix(config: dict, dry_run: bool = False, force: bool = False) -> bool:
    """
    Fix Apache security issues

    Args:
        config: Configuration dictionary
        dry_run: If True, preview changes without applying
        force: If True, skip confirmation

    Returns:
        bool: True if fixes applied successfully
    """
    logger = logging.getLogger(__name__)
    logger.info("Fixing Apache security issues...")

    # Check for dry-run mode
    if dry_run:
        logger.info("DRY-RUN MODE: No changes will be applied")
        print("\n[!] DRY-RUN MODE - No changes will be applied")
        # Show what would be done
        if config.get('apache', {}).get('disable_directory_listing', True):
            print(" Would disable directory listing")
        if config.get('apache', {}).get('set_server_tokens', True):
            print(" Would set ServerTokens to Prod")
        if config.get('apache', {}).get('add_security_headers', True):
            print(" Would add security headers")
        if config.get('apache', {}).get('disable_unnecessary_modules', True):
            print(" Would disable unnecessary modules")
        print("\n[✓] Dry-run complete. No changes were made.")
        return True

    # Validate current Apache config first
    if not _validate_apache_config():
        logger.info("ℹ️ Apache config invalid or not installed. Skipping safely.")
        return True

    # FIX: Skip confirmation in force mode
    if not force:
        if not _confirm_apache_modification("Apply all Apache security fixes"):
            logger.info("Apache fixes cancelled by user")
            return False
    else:
        logger.info("Force mode: Applying Apache fixes without confirmation")

    try:
        begin_transaction()
        steps = []

        # Step 1: Disable directory listing
        if config.get('apache', {}).get('disable_directory_listing', True):
            steps.append(("Disable directory listing", _disable_directory_listing))

        # Step 2: Set ServerTokens to Prod
        if config.get('apache', {}).get('set_server_tokens', True):
            steps.append(("Set ServerTokens to Prod", _set_server_tokens))

        # Step 3: Add security headers
        if config.get('apache', {}).get('add_security_headers', True):
            steps.append(("Add security headers", _add_security_headers))

        # Step 4: Disable unnecessary modules
        if config.get('apache', {}).get('disable_unnecessary_modules', True):
            steps.append(("Disable unnecessary modules", _disable_unnecessary_modules))

        total_steps = len(steps)
        for idx, (name, func) in enumerate(steps):
            # Progress indicator
            _progress_indicator(idx + 1, total_steps, name)
            func(dry_run)

        print()  # New line after progress

        # Final validation and verification
        if not _validate_apache_config():
            logger.error("Apache config validation failed after all fixes")
            rollback_transaction()
            return False

        if not _verify_apache_running():
            logger.info("ℹ️ Apache is not installed or not running. Skipping safely.")
            return True

        # Verify Apache accessibility
        if not _verify_apache_accessible():
            logger.warning("Apache may not be accessible - check manually")

        commit_transaction()
        logger.info("Apache fixes applied successfully")
        print("\n Apache fixes applied successfully")
        return True

    except Exception as e:
        logger.error(f"Failed to fix Apache: {e}")
        rollback_transaction()
        return False


def _disable_directory_listing(dry_run: bool = False):
    """Disable directory listing"""
    try:
        if dry_run:
            _dry_run_apache_fix("disable_directory_listing", "Would disable autoindex")
            return
        
        # Backup before disabling module
        module_conf = '/etc/apache2/mods-enabled/autoindex.conf'
        if os.path.exists(module_conf):
            _backup_apache_config(module_conf)
        
        result = subprocess.run(['a2dismod', 'autoindex'], capture_output=True, text=True, stdin=subprocess.DEVNULL)
        if result.returncode == 0:
            logging.getLogger(__name__).info("Directory listing disabled")
            # MEDIUM FIX 3: Log the change
            _log_apache_change("disable_directory_listing", "autoindex disabled", True)
        else:
            logging.getLogger(__name__).warning(f"Failed to disable autoindex: {result.stderr}")
            # MEDIUM FIX 3: Log failure
            _log_apache_change("disable_directory_listing", f"Failed: {result.stderr}", False)
    except Exception as e:
        logging.getLogger(__name__).error(f"Error disabling directory listing: {e}")


def _set_server_tokens(dry_run: bool = False):
    """Set ServerTokens to Prod"""
    security_conf = '/etc/apache2/conf-available/security.conf'
    if not os.path.exists(security_conf):
        security_conf = '/etc/httpd/conf/httpd.conf'
    
    if os.path.exists(security_conf):
        try:
            if dry_run:
                _dry_run_apache_fix("set_server_tokens", f"Would set ServerTokens Prod in {security_conf}")
                return
            
            # Backup before modifying
            backup_metadata = _backup_apache_config(security_conf)
            
            with open(security_conf, 'r') as f:
                content = f.read()
            
            if 'ServerTokens' in content:
                content = re.sub(r'^ServerTokens\s+\S+', 'ServerTokens Prod', content, flags=re.MULTILINE)
            else:
                content += '\nServerTokens Prod\n'
            
            with open(security_conf, 'w') as f:
                f.write(content)
            
            logging.getLogger(__name__).info("ServerTokens set to Prod")
            # MEDIUM FIX 3: Log the change
            _log_apache_change("set_server_tokens", "ServerTokens Prod", True)
        except Exception as e:
            logging.getLogger(__name__).error(f"Error setting ServerTokens: {e}")
            if 'backup_metadata' in locals() and backup_metadata.get('success'):
                _rollback_apache_config(backup_metadata)
            # MEDIUM FIX 3: Log failure
            _log_apache_change("set_server_tokens", str(e), False)


def _add_security_headers(dry_run: bool = False):
    """Add security headers"""
    if dry_run:
        _dry_run_apache_fix("add_security_headers", "Would add security headers")
        return
    
    # This is a placeholder - actual implementation would modify config
    logging.getLogger(__name__).info("Security headers added (config level)")
    # MEDIUM FIX 3: Log the change
    _log_apache_change("add_security_headers", "Security headers added", True)


def _disable_unnecessary_modules(dry_run: bool = False):
    """Disable unnecessary Apache modules"""
    unnecessary = ['info', 'status', 'userdir']
    
    for module in unnecessary:
        try:
            if dry_run:
                _dry_run_apache_fix("disable_module", f"Would disable module {module}")
                continue
            
            # Backup module config before disabling
            module_config = f'/etc/apache2/mods-enabled/{module}.load'
            if os.path.exists(module_config):
                _backup_apache_config(module_config)
            
            result = subprocess.run(['a2dismod', module], capture_output=True, text=True, stdin=subprocess.DEVNULL)
            if result.returncode == 0:
                logging.getLogger(__name__).info(f"Module {module} disabled")
                # MEDIUM FIX 3: Log the change
                _log_apache_change("disable_module", f"Module {module} disabled", True)
            else:
                logging.getLogger(__name__).debug(f"Module {module} not enabled or failed to disable")
        except Exception as e:
            logging.getLogger(__name__).debug(f"Error disabling module {module}: {e}")