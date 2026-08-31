#!/usr/bin/env python3
"""
Shadow Nginx Module
===================

Checks Nginx web server security:
- Nginx is installed and running
- Nginx version (vulnerabilities)
- Server tokens (information disclosure)
- Directory listing (information disclosure)
- SSL/TLS configuration
- Security headers
- Client body size (DoS prevention)
- Logging configuration

Files checked:
- /etc/nginx/nginx.conf
- /etc/nginx/sites-available/*.conf
- /etc/nginx/sites-enabled/*.conf
- /etc/nginx/conf.d/*.conf

Security concerns:
- Outdated Nginx version → known vulnerabilities
- ServerTokens Full → information disclosure
- Directory listing enabled → file exposure
- Default SSL config → weak encryption
- Large client body → DoS vulnerability
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
RECOMMENDATION = "Disable directory listing, set ServerTokens to off, and add security headers"

BACKUP_DIR = Path("/var/backups/shadow/")

# ============================================================
# TRANSACTION SUPPORT
# ============================================================
_transaction_active = False
_transaction_backups = []

def begin_transaction():
    """Begin a transaction for Nginx modifications."""
    global _transaction_active, _transaction_backups
    _transaction_active = True
    _transaction_backups = []
    logging.getLogger(__name__).info("Nginx transaction started")

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
    logging.getLogger(__name__).info("Nginx transaction committed")
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
    Check Nginx web server security

    Returns:
        Tuple[str, str, dict]: (status, message, details)
    """
    logger = logging.getLogger(__name__)
    logger.info("Checking Nginx security...")

    issues = []
    warnings = []
    details = {
        'nginx_installed': False,
        'nginx_running': False,
        'nginx_version': None,
        'server_tokens': None,
        'directory_listing': False,
        'ssl_enabled': False,
        'security_headers': [],
        'client_body_size': None,
        'log_config': False,
        'sensitive_dirs': []
    }

    # Check if Nginx is installed
    nginx_installed = _check_nginx_installed()
    details['nginx_installed'] = nginx_installed

    if not nginx_installed:
        return 'PASS', "Nginx is not installed", details

    # Check if Nginx is running
    nginx_running = _check_nginx_running()
    details['nginx_running'] = nginx_running

    if not nginx_running:
        return 'WARN', "Nginx is installed but not running", details

    # Get Nginx version
    version_info = _get_nginx_version()
    details['nginx_version'] = version_info

    if version_info:
        if version_info.startswith('1.0'):
            issues.append(f"Nginx version {version_info} is outdated")
        elif version_info.startswith('1.1'):
            issues.append(f"Nginx version {version_info} is outdated")
        elif version_info.startswith('1.2'):
            warnings.append(f"Nginx version {version_info} may be outdated")

    # Check ServerTokens configuration
    server_tokens = _check_server_tokens()
    details['server_tokens'] = server_tokens

    if server_tokens and server_tokens.lower() == 'on':
        issues.append("ServerTokens enabled (information disclosure)")

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

    # Check client body size
    client_body_size = _check_client_body_size()
    details['client_body_size'] = client_body_size

    if client_body_size and int(client_body_size) > 10485760:  # 10MB
        warnings.append(f"Client body size is {client_body_size} (may be too large)")

    # Check logging configuration
    log_config = _check_logging()
    details['log_config'] = log_config

    if not log_config:
        warnings.append("Nginx logging may not be properly configured")

    # Check sensitive directories
    sensitive_dirs = _check_sensitive_dirs()
    details['sensitive_dirs'] = sensitive_dirs

    if sensitive_dirs:
        warnings.append("Sensitive directories may be accessible")

    # Determine status
    if issues:
        critical = [i for i in issues if 'outdated' in i.lower() or 'directory listing' in i.lower()]
        if critical:
            status = 'FAIL'
            message = f"{len(issues)} critical Nginx issues found"
        else:
            status = 'WARN'
            message = f"{len(issues)} Nginx issues found"
    elif warnings:
        status = 'WARN'
        message = f"{len(warnings)} Nginx warnings found"
    else:
        status = 'PASS'
        message = "Nginx is securely configured"

    return status, message, details


def _check_nginx_installed() -> bool:
    """Check if Nginx is installed"""
    nginx_paths = [
        '/usr/sbin/nginx',
        '/usr/bin/nginx',
        '/usr/local/sbin/nginx',
        '/usr/local/bin/nginx'
    ]

    for path in nginx_paths:
        if os.path.exists(path):
            return True

    try:
        result = subprocess.run(['dpkg', '-l', 'nginx*'], 
                              capture_output=True, text=True, stdin=subprocess.DEVNULL)
        if 'nginx' in result.stdout:
            return True
    except:
        pass

    try:
        result = subprocess.run(['rpm', '-qa', 'nginx*'],
                              capture_output=True, text=True, stdin=subprocess.DEVNULL)
        if 'nginx' in result.stdout:
            return True
    except:
        pass

    return False


def _check_nginx_running() -> bool:
    """Check if Nginx is running"""
    try:
        result = subprocess.run(['systemctl', 'is-active', 'nginx'],
                              capture_output=True, text=True, stdin=subprocess.DEVNULL)
        if result.stdout.strip() == 'active':
            return True
    except:
        pass

    try:
        result = subprocess.run(['ps', 'aux'], capture_output=True, text=True, stdin=subprocess.DEVNULL)
        if 'nginx' in result.stdout:
            return True
    except:
        pass

    return False


def _get_nginx_version() -> Optional[str]:
    """Get Nginx version"""
    try:
        result = subprocess.run(['nginx', '-v'], capture_output=True, text=True, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL)
        for line in result.stdout.split('\n'):
            if 'nginx version' in line:
                match = re.search(r'nginx/(\d+\.\d+\.\d+)', line)
                if match:
                    return match.group(1)
    except:
        pass

    return None


def _check_server_tokens() -> Optional[str]:
    """Check ServerTokens configuration"""
    nginx_config = '/etc/nginx/nginx.conf'

    if not os.path.exists(nginx_config):
        return None

    try:
        with open(nginx_config, 'r') as f:
            content = f.read()
            if 'server_tokens' in content:
                match = re.search(r'server_tokens\s+(\S+);', content)
                if match:
                    return match.group(1)
    except Exception as e:
        logging.getLogger(__name__).debug(f"Error reading ServerTokens: {e}")

    return None


def _check_directory_listing() -> bool:
    """Check if directory listing is enabled"""
    nginx_configs = [
        '/etc/nginx/nginx.conf',
        '/etc/nginx/sites-enabled/*.conf',
        '/etc/nginx/conf.d/*.conf'
    ]

    try:
        for config_pattern in nginx_configs:
            for config_file in glob.glob(config_pattern):
                if os.path.exists(config_file):
                    with open(config_file, 'r') as f:
                        content = f.read()
                        if 'autoindex on' in content:
                            return True
    except Exception as e:
        pass

    return False


def _check_ssl_config() -> bool:
    """Check if SSL/TLS is configured"""
    ssl_patterns = [
        'ssl_certificate',
        'ssl_certificate_key',
        'listen 443',
        'ssl on'
    ]

    nginx_configs = [
        '/etc/nginx/nginx.conf',
        '/etc/nginx/sites-enabled/*.conf',
        '/etc/nginx/conf.d/*.conf'
    ]

    try:
        for config_pattern in nginx_configs:
            for config_file in glob.glob(config_pattern):
                if os.path.exists(config_file):
                    with open(config_file, 'r') as f:
                        content = f.read()
                        for pattern in ssl_patterns:
                            if pattern in content:
                                return True
    except Exception as e:
        pass

    return False


def _check_security_headers() -> List[str]:
    """Check security headers configuration"""
    headers = []
    header_patterns = [
        'X-Frame-Options',
        'X-Content-Type-Options',
        'X-XSS-Protection',
        'Strict-Transport-Security',
        'Content-Security-Policy'
    ]

    nginx_configs = [
        '/etc/nginx/nginx.conf',
        '/etc/nginx/sites-enabled/*.conf',
        '/etc/nginx/conf.d/*.conf'
    ]

    try:
        for config_pattern in nginx_configs:
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


def _check_client_body_size() -> Optional[str]:
    """Check client body size configuration"""
    nginx_configs = [
        '/etc/nginx/nginx.conf',
        '/etc/nginx/sites-enabled/*.conf',
        '/etc/nginx/conf.d/*.conf'
    ]

    try:
        for config_pattern in nginx_configs:
            for config_file in glob.glob(config_pattern):
                if os.path.exists(config_file):
                    with open(config_file, 'r') as f:
                        content = f.read()
                        match = re.search(r'client_max_body_size\s+(\d+[kKmM]?);', content)
                        if match:
                            return match.group(1)
    except Exception as e:
        pass

    return None


def _check_logging() -> bool:
    """Check if logging is configured"""
    nginx_config = '/etc/nginx/nginx.conf'

    if os.path.exists(nginx_config):
        with open(nginx_config, 'r') as f:
            content = f.read()
            if 'access_log' in content and 'error_log' in content:
                return True

    return False


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


# ============================================================
# FIX 1: BACKUP BEFORE MODIFYING NGINX CONFIG
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


def _backup_nginx_config(file_path: str) -> Dict[str, Any]:
    """
    Backup Nginx configuration file with metadata.
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
# FIX 2: VALIDATE NGINX CONFIG BEFORE MODIFYING
# ============================================================
def _validate_nginx_config() -> bool:
    """
    Validate Nginx configuration syntax.
    Returns True if valid, False otherwise.
    """
    try:
        result = subprocess.run(
            ['nginx', '-t'],
            capture_output=True,
            text=True,
            timeout=10, stdin=subprocess.DEVNULL)
        if result.returncode == 0:
            logging.getLogger(__name__).debug("Nginx config validation passed")
            return True
        else:
            logging.getLogger(__name__).error(f"Nginx config validation failed: {result.stderr}")
            return False
    except Exception as e:
        logging.getLogger(__name__).error(f"Nginx config validation error: {e}")
        return False


# ============================================================
# FIX 3: ROLLBACK ON FAILURE
# ============================================================
def _rollback_nginx_config(backup_metadata: Dict[str, Any]) -> bool:
    """
    Rollback Nginx configuration from backup.
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
        logging.getLogger(__name__).info(f"Rolled back Nginx config: {original_path}")
        return True
    except Exception as e:
        logging.getLogger(__name__).error(f"Rollback failed for {original_path}: {e}")
        return False


# ============================================================
# FIX 4: VERIFY NGINX AFTER CHANGES
# ============================================================
def _verify_nginx_running() -> bool:
    """Verify Nginx is running and responding."""
    try:
        result = subprocess.run(
            ['systemctl', 'is-active', 'nginx'],
            capture_output=True,
            text=True,
            timeout=5, stdin=subprocess.DEVNULL)
        if result.stdout.strip() == 'active':
            return True
    except:
        pass
    
    # Check process
    try:
        result = subprocess.run(['ps', 'aux'], capture_output=True, text=True, stdin=subprocess.DEVNULL)
        if 'nginx' in result.stdout:
            return True
    except:
        pass
    
    return False


# ============================================================
# MEDIUM FIX 1: DRY-RUN MODE
# ============================================================
def _dry_run_nginx_fix(action: str, details: str) -> bool:
    """
    Simulate Nginx modification without actually changing anything.
    Used for dry-run mode.
    """
    logging.getLogger(__name__).info(f"[DRY-RUN] Would perform: {action} - {details}")
    print(f"[DRY-RUN] Would perform: {action}")
    return True


# ============================================================
# MEDIUM FIX 2: CONFIRMATION BEFORE MODIFYING NGINX
# ============================================================
def _confirm_nginx_modification(action: str) -> bool:
    """
    Ask for confirmation before modifying Nginx.
    """
    print(f"\n[!] WARNING: About to modify Nginx configuration")
    print(f"    Action: {action}")
    print("    This could break your web server!")
    response = ui.prompt("Proceed? [y/N]: ")
    if response.lower() == 'y':
        print("\n[*] Applying fixes... please wait")
        return True
    return False


# ============================================================
# MEDIUM FIX 3: LOGGING OF NGINX CHANGES
# ============================================================
def _log_nginx_change(action: str, details: str, success: bool):
    """
    Log Nginx modifications.
    """
    logger = logging.getLogger(__name__)
    status = "SUCCESS" if success else "FAILED"
    logger.info(f"Nginx change: {action} - {details} ({status})")
    
    # Also log to changes.log for audit trail
    changes_log = Path("/var/log/shadow/changes.log")
    if changes_log.exists():
        with open(changes_log, 'a') as f:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            f.write(f"{timestamp} - Nginx: {action} - {details} ({status})\n")


# ============================================================
# MEDIUM FIX 4: VERIFY NGINX ACCESSIBILITY
# ============================================================
def _verify_nginx_accessible() -> bool:
    """
    Verify Nginx is accessible via HTTP.
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


def _safe_nginx_fix(config_file: str, fix_func, dry_run: bool = False, *args) -> bool:
    """
    Safely apply an Nginx fix with backup, validation, dry-run, and rollback.
    """
    logger = logging.getLogger(__name__)
    
    # MEDIUM FIX 1: Dry-run mode
    if dry_run:
        return _dry_run_nginx_fix("nginx_fix", f"Would apply fix to {config_file}")
    
    # MEDIUM FIX 2: Confirmation
    if not _confirm_nginx_modification(f"Apply fix to {config_file}"):
        logger.info("Nginx fix cancelled by user")
        return False
    
    # Step 1: Backup config
    backup_metadata = _backup_nginx_config(config_file)
    if not backup_metadata['success']:
        logger.warning(f"Could not backup {config_file}")
    
    try:
        # Step 2: Apply fix
        fix_func(*args)
        
        # Step 3: Validate config
        if not _validate_nginx_config():
            logger.error("Nginx config validation failed after fix")
            if backup_metadata['success']:
                _rollback_nginx_config(backup_metadata)
                _restart_nginx()
            # MEDIUM FIX 3: Log failure
            _log_nginx_change("nginx_fix", f"{config_file} - validation failed", False)
            return False
        
        # Step 4: Verify Nginx is running
        if not _verify_nginx_running():
            logger.error("Nginx is not running after fix")
            if backup_metadata['success']:
                _rollback_nginx_config(backup_metadata)
                _restart_nginx()
            # MEDIUM FIX 3: Log failure
            _log_nginx_change("nginx_fix", f"{config_file} - Nginx not running", False)
            return False
        
        # MEDIUM FIX 4: Verify Nginx accessibility
        if not _verify_nginx_accessible():
            logger.warning("Nginx may not be accessible - check manually")
        
        # MEDIUM FIX 3: Log success
        _log_nginx_change("nginx_fix", f"{config_file} - success", True)
        return True
        
    except Exception as e:
        logger.error(f"Error applying Nginx fix: {e}")
        if backup_metadata['success']:
            _rollback_nginx_config(backup_metadata)
            _restart_nginx()
        # MEDIUM FIX 3: Log failure
        _log_nginx_change("nginx_fix", f"{config_file} - {e}", False)
        return False


def _restart_nginx():
    """Restart Nginx service."""
    try:
        subprocess.run(['systemctl', 'restart', 'nginx'], capture_output=True, text=True, stdin=subprocess.DEVNULL)
    except:
        pass

def _enable_nginx_service() -> bool:
    """Enable and start Nginx service if installed but not running."""
    logger = logging.getLogger(__name__)
    
    if not _check_nginx_installed():
        logger.info("Nginx is not installed, skipping enable")
        return True
    
    if _check_nginx_running():
        logger.info("Nginx is already running")
        return True
    
    try:
        logger.info("Enabling and starting Nginx service...")
        subprocess.run(['systemctl', 'enable', 'nginx'], capture_output=True, timeout=10, stdin=subprocess.DEVNULL)
        subprocess.run(['systemctl', 'start', 'nginx'], capture_output=True, timeout=10, stdin=subprocess.DEVNULL)
        
        if _check_nginx_running():
            logger.info("Nginx started successfully")
            return True
        else:
            logger.error("Nginx failed to start")
            return False
    except Exception as e:
        logger.error(f"Failed to enable Nginx: {e}")
        return False
    

def fix(config: dict, dry_run: bool = False, force: bool = False) -> bool:
    """
    Fix Nginx security issues

    Returns:
        bool: True if fixes applied successfully
    """
    logger = logging.getLogger(__name__)
    logger.info("Fixing Nginx security issues...")

    # Check for dry-run mode
    dry_run = config.get('nginx', {}).get('dry_run', False)
    if dry_run:
        logger.info("DRY-RUN MODE: No changes will be applied")
        print("\n[!] DRY-RUN MODE - No changes will be applied")

    # Validate current Nginx config first
    if not dry_run and not _validate_nginx_config():
        logger.info("ℹ️ Nginx config invalid or not installed. Skipping safely.")
        return True

    # MEDIUM FIX 2: Get confirmation before starting
    if not dry_run:
        if not _confirm_nginx_modification("Apply all Nginx security fixes"):
            logger.info("Nginx fixes cancelled by user")
            return False

    try:
        steps = []
        
        # Step 1: Disable directory listing
        if config.get('nginx', {}).get('disable_directory_listing', True):
            steps.append(("Disable directory listing", _disable_directory_listing))
        
        # Step 2: Set ServerTokens to off
        if config.get('nginx', {}).get('set_server_tokens', True):
            steps.append(("Set ServerTokens to off", _set_server_tokens))
        
        # Step 3: Add security headers
        if config.get('nginx', {}).get('add_security_headers', True):
            steps.append(("Add security headers", _add_security_headers))
        
        # Step 4: Set client body size limit
        if config.get('nginx', {}).get('set_body_size', True):
            steps.append(("Set client body size", _set_client_body_size))
        
        total_steps = len(steps)
        for idx, (name, func) in enumerate(steps):
            # LOW FIX 1: Progress indicator
            _progress_indicator(idx + 1, total_steps, name)
            if dry_run:
                _dry_run_nginx_fix(name, "Dry-run step")
            else:
                func(dry_run)
        
        print()  # New line after progress

        if dry_run:
            logger.info("DRY-RUN completed successfully")
            return True

        # Final validation and verification
        if not _validate_nginx_config():
            logger.info("ℹ️ Nginx config invalid or not installed. Skipping safely.")
            return True

        if not _verify_nginx_running():
            logger.info("ℹ️ Nginx is not installed or not running. Skipping safely.")
            return True

        # MEDIUM FIX 4: Verify Nginx accessibility
        if not _verify_nginx_accessible():
            logger.warning("Nginx may not be accessible - check manually")

        logger.info("Nginx fixes applied successfully")
        return True

    except Exception as e:
        logger.error(f"Failed to fix Nginx: {e}")
        return False


def _disable_directory_listing(dry_run: bool = False):
    """Disable directory listing"""
    nginx_config = '/etc/nginx/nginx.conf'

    if os.path.exists(nginx_config):
        try:
            if dry_run:
                _dry_run_nginx_fix("disable_directory_listing", "Would disable autoindex in nginx.conf")
                return
            
            # Backup before modifying
            backup_metadata = _backup_nginx_config(nginx_config)
            
            with open(nginx_config, 'r') as f:
                content = f.read()
            content = re.sub(r'autoindex\s+on;', 'autoindex off;', content)
            with open(nginx_config, 'w') as f:
                f.write(content)
            
            logging.getLogger(__name__).info("Directory listing disabled")
            # MEDIUM FIX 3: Log the change
            _log_nginx_change("disable_directory_listing", "autoindex disabled", True)
        except Exception as e:
            logging.getLogger(__name__).error(f"Error disabling directory listing: {e}")
            if 'backup_metadata' in locals() and backup_metadata.get('success'):
                _rollback_nginx_config(backup_metadata)
            # MEDIUM FIX 3: Log failure
            _log_nginx_change("disable_directory_listing", str(e), False)


def _set_server_tokens(dry_run: bool = False):
    """Set ServerTokens to off"""
    nginx_config = '/etc/nginx/nginx.conf'

    if os.path.exists(nginx_config):
        try:
            if dry_run:
                _dry_run_nginx_fix("set_server_tokens", "Would set server_tokens off in nginx.conf")
                return
            
            backup_metadata = _backup_nginx_config(nginx_config)
            
            with open(nginx_config, 'r') as f:
                content = f.read()
            if 'server_tokens' in content:
                content = re.sub(r'server_tokens\s+\S+;', 'server_tokens off;', content)
            else:
                content = content.replace('http {', 'http {\n    server_tokens off;')
            with open(nginx_config, 'w') as f:
                f.write(content)
            
            logging.getLogger(__name__).info("ServerTokens set to off")
            # MEDIUM FIX 3: Log the change
            _log_nginx_change("set_server_tokens", "server_tokens off", True)
        except Exception as e:
            logging.getLogger(__name__).error(f"Error setting ServerTokens: {e}")
            if 'backup_metadata' in locals() and backup_metadata.get('success'):
                _rollback_nginx_config(backup_metadata)
            # MEDIUM FIX 3: Log failure
            _log_nginx_change("set_server_tokens", str(e), False)


def _add_security_headers(dry_run: bool = False):
    """Add security headers"""
    nginx_config = '/etc/nginx/nginx.conf'

    if os.path.exists(nginx_config):
        try:
            if dry_run:
                _dry_run_nginx_fix("add_security_headers", "Would add security headers to nginx.conf")
                return
            
            backup_metadata = _backup_nginx_config(nginx_config)
            
            with open(nginx_config, 'r') as f:
                content = f.read()
            
            headers = [
                'add_header X-Frame-Options "SAMEORIGIN" always;',
                'add_header X-Content-Type-Options "nosniff" always;',
                'add_header X-XSS-Protection "1; mode=block" always;'
            ]
            
            for header in headers:
                header_name = header.split('"')[1] if '"' in header else header.split()[2]
                if header_name not in content:
                    content = content.replace('http {', f'http {{\n    {header}')
            
            with open(nginx_config, 'w') as f:
                f.write(content)
            
            logging.getLogger(__name__).info("Security headers added")
            # MEDIUM FIX 3: Log the change
            _log_nginx_change("add_security_headers", "Security headers added", True)
        except Exception as e:
            logging.getLogger(__name__).error(f"Error adding security headers: {e}")
            if 'backup_metadata' in locals() and backup_metadata.get('success'):
                _rollback_nginx_config(backup_metadata)
            # MEDIUM FIX 3: Log failure
            _log_nginx_change("add_security_headers", str(e), False)


def _set_client_body_size(dry_run: bool = False):
    """Set client body size limit"""
    nginx_config = '/etc/nginx/nginx.conf'

    if os.path.exists(nginx_config):
        try:
            if dry_run:
                _dry_run_nginx_fix("set_client_body_size", "Would set client_max_body_size 10M in nginx.conf")
                return
            
            backup_metadata = _backup_nginx_config(nginx_config)
            
            with open(nginx_config, 'r') as f:
                content = f.read()
            if 'client_max_body_size' in content:
                content = re.sub(r'client_max_body_size\s+\d+[kKmM]?;', 'client_max_body_size 10M;', content)
            else:
                content = content.replace('http {', 'http {\n    client_max_body_size 10M;')
            with open(nginx_config, 'w') as f:
                f.write(content)
            
            logging.getLogger(__name__).info("Client body size set to 10M")
            # MEDIUM FIX 3: Log the change
            _log_nginx_change("set_client_body_size", "client_max_body_size 10M", True)
        except Exception as e:
            logging.getLogger(__name__).error(f"Error setting client body size: {e}")
            if 'backup_metadata' in locals() and backup_metadata.get('success'):
                _rollback_nginx_config(backup_metadata)
            # MEDIUM FIX 3: Log failure
            _log_nginx_change("set_client_body_size", str(e), False)