#!/usr/bin/env python3
"""
Shadow Sensitive Files Module
=============================

Checks sensitive file protection:
- Shadow file protection (/etc/shadow)
- Passwd file protection (/etc/passwd)
- Sudoers file protection (/etc/sudoers)
- Sensitive configuration files
- SSH keys and certificates
- SSL/TLS certificates
- Database credentials
- API keys and tokens
- Backup files containing sensitive data

Security concerns:
- Shadow file readable by non-root → password exposure
- Backup files with credentials → credential leakage
- SSH keys with weak permissions → key theft
- Unencrypted sensitive data → data exposure
- World-readable config files → information disclosure
"""

from shadow.core import ui
import os
import re
import shutil
import stat
import logging
import subprocess
import tempfile
import time
import json
import fcntl
from pathlib import Path
from datetime import datetime
from typing import Tuple, Dict, List, Optional, Any


BACKUP_DIR = Path("/var/backups/shadow/")
REMOVED_FILES_BACKUP = BACKUP_DIR / "removed_files"
CHANGES_LOG = Path("/var/log/shadow/changes.log")


# ============================================================
# FIX 8: STRUCTURED LOGGING
# ============================================================
def _log_file_change(action: str, details: str, success: bool):
    """Log file modifications with structured format."""
    logger = logging.getLogger(__name__)
    status = "SUCCESS" if success else "FAILED"
    
    log_entry = {
        "event": "file_security_change",
        "action": action,
        "details": details,
        "status": status,
        "timestamp": datetime.now().isoformat()
    }
    logger.info(f"FILE_SECURITY: {json.dumps(log_entry)}")
    
    try:
        CHANGES_LOG.parent.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(CHANGES_LOG, 'a') as f:
            f.write(f"{timestamp} - File: {action} - {details} ({status})\n")
    except Exception as e:
        logger.debug(f"Failed to log change: {e}")


# ============================================================
# CHECK FUNCTION
# ============================================================
def check(config: dict) -> Tuple[str, str, dict]:
    """
    Check sensitive file protection

    Returns:
        Tuple[str, str, dict]: (status, message, details)
    """
    logger = logging.getLogger(__name__)
    logger.info("Checking sensitive file protection...")

    issues = []
    warnings = []
    details = {
        'shadow_protected': False,
        'passwd_protected': False,
        'sudoers_protected': False,
        'ssh_keys': [],
        'ssl_certs': [],
        'config_files': [],
        'backup_files': [],
        'world_readable_sensitive': [],
        'credential_files': []
    }

    # Check shadow file protection
    shadow_info = _check_shadow_file()
    details['shadow_protected'] = shadow_info.get('protected', False)
    if not shadow_info.get('protected'):
        issues.append("CRITICAL: /etc/shadow is not properly protected")

    # Check passwd file protection
    passwd_info = _check_passwd_file()
    details['passwd_protected'] = passwd_info.get('protected', False)
    if not passwd_info.get('protected'):
        issues.append("/etc/passwd is not properly protected")

    # Check sudoers file protection
    sudoers_info = _check_sudoers_file()
    details['sudoers_protected'] = sudoers_info.get('protected', False)
    if not sudoers_info.get('protected'):
        issues.append("CRITICAL: /etc/sudoers is not properly protected")

    # Check SSH keys
    ssh_keys = _check_ssh_keys()
    if ssh_keys:
        details['ssh_keys'] = ssh_keys
        for key_info in ssh_keys:
            if not key_info.get('secure'):
                warnings.append(f"Insecure SSH key: {key_info['path']} ({key_info.get('permissions', 'unknown')})")

    # Check SSL/TLS certificates
    ssl_certs = _check_ssl_certs()
    if ssl_certs:
        details['ssl_certs'] = ssl_certs
        for cert_info in ssl_certs:
            if not cert_info.get('secure'):
                warnings.append(f"Insecure certificate: {cert_info['path']} ({cert_info.get('permissions', 'unknown')})")

    # Check sensitive configuration files
    config_files = _check_sensitive_configs()
    if config_files:
        details['config_files'] = config_files
        for config_info in config_files:
            if not config_info.get('secure'):
                warnings.append(f"Insecure config file: {config_info['path']}")

    # Check for backup files with sensitive data
    backup_files = _check_backup_files()
    if backup_files:
        details['backup_files'] = backup_files
        for backup_info in backup_files:
            warnings.append(f"Sensitive backup file found: {backup_info['path']}")

    # Check for world-readable sensitive files
    world_readable = _find_world_readable_sensitive()
    if world_readable:
        details['world_readable_sensitive'] = world_readable
        for file_info in world_readable:
            issues.append(f"World-readable sensitive file: {file_info['path']}")

    # Check for credential files
    credential_files = _find_credential_files()
    if credential_files:
        details['credential_files'] = credential_files
        for file_info in credential_files:
            warnings.append(f"Credential file found: {file_info['path']}")

    # Determine status
    if issues:
        critical = [i for i in issues if 'CRITICAL' in i]
        if critical:
            status = 'FAIL'
            message = f"{len(issues)} critical sensitive file issues found"
        else:
            status = 'WARN'
            message = f"{len(issues)} sensitive file issues found"
    elif warnings:
        status = 'WARN'
        message = f"{len(warnings)} sensitive file warnings found"
    else:
        status = 'PASS'
        message = "Sensitive files are properly protected"

    return status, message, details


def _check_shadow_file() -> Dict:
    """Check /etc/shadow file protection"""
    info = {'protected': False, 'permissions': None, 'owner': None}

    shadow_file = '/etc/shadow'

    if not os.path.exists(shadow_file):
        info['error'] = 'File not found'
        return info

    try:
        stat_info = os.stat(shadow_file)
        perms = oct(stat_info.st_mode)[-3:]
        info['permissions'] = perms

        if perms in ['600', '640']:
            info['protected'] = True

        uid = stat_info.st_uid
        gid = stat_info.st_gid
        info['owner'] = f"{uid}:{gid}"
        if uid == 0:
            info['protected'] = True

    except Exception as e:
        info['error'] = str(e)

    return info


def _check_passwd_file() -> Dict:
    """Check /etc/passwd file protection"""
    info = {'protected': False, 'permissions': None, 'owner': None}

    passwd_file = '/etc/passwd'

    if not os.path.exists(passwd_file):
        info['error'] = 'File not found'
        return info

    try:
        stat_info = os.stat(passwd_file)
        perms = oct(stat_info.st_mode)[-3:]
        info['permissions'] = perms

        if perms in ['644']:
            info['protected'] = True

        uid = stat_info.st_uid
        gid = stat_info.st_gid
        info['owner'] = f"{uid}:{gid}"
        if uid == 0:
            info['protected'] = True

    except Exception as e:
        info['error'] = str(e)

    return info


def _check_sudoers_file() -> Dict:
    """Check /etc/sudoers file protection"""
    info = {'protected': False, 'permissions': None, 'owner': None}

    sudoers_file = '/etc/sudoers'

    if not os.path.exists(sudoers_file):
        info['error'] = 'File not found'
        return info

    try:
        stat_info = os.stat(sudoers_file)
        perms = oct(stat_info.st_mode)[-3:]
        info['permissions'] = perms

        if perms in ['440']:
            info['protected'] = True

        uid = stat_info.st_uid
        gid = stat_info.st_gid
        info['owner'] = f"{uid}:{gid}"
        if uid == 0:
            info['protected'] = True

    except Exception as e:
        info['error'] = str(e)

    return info


def _check_single_file(file_path: str) -> Optional[Dict]:
    """Check a single file's security"""
    try:
        stat_info = os.stat(file_path)
        perms = oct(stat_info.st_mode)[-3:]

        secure = True
        if perms[-1] in ['4', '5', '6', '7']:
            secure = False

        if perms[-1] in ['2', '6', '7']:
            secure = False

        return {
            'path': file_path,
            'permissions': perms,
            'secure': secure,
            'owner': f"{stat_info.st_uid}:{stat_info.st_gid}"
        }
    except Exception as e:
        return None


def _check_ssh_keys() -> List[Dict]:
    """Check SSH key permissions - ONLY /etc/ssh"""
    ssh_keys = []

    # ✅ FIX: ONLY check /etc/ssh, NOT /root/.ssh, /home/*/.ssh
    ssh_dirs = ['/etc/ssh']

    for ssh_dir in ssh_dirs:
        if not os.path.exists(ssh_dir):
            continue

        try:
            for key_file in Path(ssh_dir).iterdir():
                if key_file.is_file():
                    key_info = _check_single_file(str(key_file))
                    if key_info:
                        ssh_keys.append(key_info)
        except Exception as e:
            logging.getLogger(__name__).debug(f"Error checking SSH keys: {e}")

    return ssh_keys[:20]


def _check_ssl_certs() -> List[Dict]:
    """Check SSL/TLS certificate permissions - ONLY /etc/ssl"""
    certs = []

    # ✅ FIX: ONLY check /etc/ssl, NOT /etc/pki
    cert_dirs = ['/etc/ssl/certs', '/etc/ssl/private']

    for cert_dir in cert_dirs:
        if not os.path.exists(cert_dir):
            continue

        try:
            for cert_file in Path(cert_dir).iterdir():
                if cert_file.is_file():
                    cert_info = _check_single_file(str(cert_file))
                    if cert_info:
                        certs.append(cert_info)
        except Exception as e:
            logging.getLogger(__name__).debug(f"Error checking SSL certs: {e}")

    return certs[:20]


def _check_sensitive_configs() -> List[Dict]:
    """Check sensitive configuration files"""
    configs = []

    sensitive_configs = [
        '/etc/apache2/apache2.conf',
        '/etc/nginx/nginx.conf',
        '/etc/mysql/my.cnf',
        '/etc/postgresql/*/main/postgresql.conf',
        '/etc/redis/redis.conf',
        '/etc/docker/daemon.json',
        '/etc/kubernetes/*.conf',
        '/etc/samba/smb.conf'
    ]

    for pattern in sensitive_configs:
        try:
            import glob
            for config_file in glob.glob(pattern):
                if os.path.exists(config_file):
                    config_info = _check_single_file(config_file)
                    if config_info:
                        configs.append(config_info)
        except Exception as e:
            logging.getLogger(__name__).debug(f"Error checking configs: {e}")

    return configs


def _check_backup_files() -> List[Dict]:
    """Check for backup files with sensitive data - ONLY IN /etc"""
    backup_files = []

    backup_patterns = [
        '*.backup',
        '*.bak',
        '*.old',
        '*.orig',
        '*~',
        '*.swp',
        '*.tmp'
    ]

    # ✅ FIX: ONLY search /etc, NOT /var, /root, /home
    search_dir = '/etc'

    if not os.path.exists(search_dir):
        return backup_files

    for pattern in backup_patterns:
        try:
            import glob
            for backup_file in glob.glob(f"{search_dir}/**/{pattern}", recursive=True):
                if os.path.exists(backup_file) and os.path.isfile(backup_file):
                    if _is_sensitive_file(str(backup_file)):
                        backup_info = _check_single_file(str(backup_file))
                        if backup_info:
                            backup_files.append(backup_info)
        except Exception as e:
            continue

    return backup_files[:20]


def _find_world_readable_sensitive() -> List[Dict]:
    """Find world-readable sensitive files - ONLY IN /etc"""
    sensitive = []

    # ✅ FIX: ONLY check /etc, NOT /var/log, /var/backups
    search_dir = '/etc'

    if not os.path.exists(search_dir):
        return sensitive

    try:
        result = subprocess.run(
            ['find', search_dir, '-maxdepth', '3', '-type', 'f', '-perm', '-004', '-ls'],
            capture_output=True,
            text=True,
            timeout=10, stdin=subprocess.DEVNULL)

        if result.returncode == 0:
            for line in result.stdout.split('\n'):
                if line.strip():
                    parts = line.split()
                    if len(parts) > 10:
                        path = ' '.join(parts[10:])
                        if _is_sensitive_file(path):
                            sensitive.append({
                                'path': path,
                                'reason': 'World-readable sensitive file'
                            })
    except Exception as e:
        logging.getLogger(__name__).warning(f"World-readable find failed: {e}")

    return sensitive[:20]


def _find_credential_files() -> List[Dict]:
    """Find credential files - ONLY IN /etc"""
    credential_files = []

    credential_patterns = [
        '*.pem', '*.key', '*.crt', '*.csr', '*.p12', '*.pfx',
        '*_key', '*_pass', '*_secret',
        '.env'
    ]

    # ✅ FIX: ONLY search /etc, NOT /root, /home, /opt, /var
    search_dir = '/etc'

    if not os.path.exists(search_dir):
        return credential_files

    for pattern in credential_patterns:
        try:
            import glob
            for cred_file in glob.glob(f"{search_dir}/**/{pattern}", recursive=True):
                if os.path.exists(cred_file) and os.path.isfile(cred_file):
                    credential_files.append({
                        'path': str(cred_file),
                        'reason': f'Credential file pattern: {pattern}'
                    })
        except Exception as e:
            continue

    return credential_files[:20]


def _is_sensitive_file(file_path: str) -> bool:
    """Check if a file is likely sensitive"""
    sensitive_patterns = [
        'shadow', 'passwd', 'sudoers',
        'key', 'cert', 'pem', 'crt',
        'secret', 'credential', 'password', 'token',
        '.env', '.aws', '.kube', '.docker'
    ]

    file_lower = file_path.lower()
    for pattern in sensitive_patterns:
        if pattern in file_lower:
            return True

    if file_path.endswith(('.pem', '.key', '.crt', '.csr', '.p12', '.pfx')):
        return True

    return False


# ============================================================
# FIX 1: BACKUP BEFORE CHANGING PERMISSIONS
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


def _backup_file(file_path: str) -> Dict[str, Any]:
    """Backup a file with metadata."""
    result = {
        'path': file_path,
        'backup_path': None,
        'perms': None,
        'uid': None,
        'gid': None,
        'success': False
    }
    
    try:
        BACKUP_DIR.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        
        if os.path.exists(file_path):
            backup_path = BACKUP_DIR / f"{Path(file_path).name}.backup_{timestamp}"
            shutil.copy2(file_path, backup_path)
            result['backup_path'] = str(backup_path)
            
            stat_info = os.stat(file_path)
            result['perms'] = oct(stat_info.st_mode)[-3:]
            result['uid'] = stat_info.st_uid
            result['gid'] = stat_info.st_gid
            
            meta_path = BACKUP_DIR / f"{Path(file_path).name}.meta_{timestamp}"
            with open(meta_path, 'w') as f:
                f.write(f"path={file_path}\n")
                f.write(f"perms={oct(stat_info.st_mode)[-3:]}\n")
                f.write(f"uid={stat_info.st_uid}\n")
                f.write(f"gid={stat_info.st_gid}\n")
            
            if _verify_backup(backup_path):
                result['success'] = True
                logging.getLogger(__name__).info(f"Backup created: {backup_path}")
                
    except Exception as e:
        logging.getLogger(__name__).error(f"Failed to backup {file_path}: {e}")
    
    return result


def _rollback_file(backup_metadata: Dict[str, Any]) -> bool:
    """Rollback a file from backup."""
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
        logging.getLogger(__name__).info(f"Restored file: {original_path}")
        
        if backup_metadata.get('perms'):
            perms = int(backup_metadata['perms'], 8)
            os.chmod(original_path, perms)
            logging.getLogger(__name__).info(f"Restored permissions for {original_path}: {backup_metadata['perms']}")
        
        return True
    except Exception as e:
        logging.getLogger(__name__).error(f"Rollback failed for {original_path}: {e}")
        return False


# ============================================================
# FIX 2 & 4: SAFE CHMOD WITH VALIDATION AND VERIFICATION
# ============================================================
def _safe_chmod(file_path: str, mode: int, dry_run: bool = False) -> bool:
    """
    Safely change file permissions with backup, validation, dry-run, and verification.
    """
    logger = logging.getLogger(__name__)
    
    if not os.path.exists(file_path):
        logger.error(f"File not found: {file_path}")
        return False
    
    if dry_run:
        return _dry_run_file_fix("chmod", f"{file_path} → {oct(mode)[-3:]}")
    
    # File locking
    lock_file = Path(file_path).with_suffix('.lock')
    fd = None
    try:
        fd = open(lock_file, 'w')
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except:
        logger.warning(f"Cannot acquire lock for {file_path}")
    
    # Create backup
    backup_metadata = _backup_file(file_path)
    if not backup_metadata['success']:
        logger.warning(f"Could not backup {file_path} before chmod")
    
    stat_info = os.stat(file_path)
    current_perms = oct(stat_info.st_mode)[-3:]
    expected_perms = oct(mode)[-3:]
    
    if current_perms == expected_perms:
        logger.debug(f"Permissions already correct for {file_path}")
        return True
    
    try:
        os.chmod(file_path, mode)
        logger.info(f"Changed permissions for {file_path}: {current_perms} → {expected_perms}")
        _log_file_change("chmod", f"{file_path}: {current_perms} → {expected_perms}", True)
        
        new_stat = os.stat(file_path)
        new_perms = oct(new_stat.st_mode)[-3:]
        if new_perms == expected_perms:
            return True
        else:
            logger.error(f"Permission verification failed for {file_path}")
            if backup_metadata['success']:
                _rollback_file(backup_metadata)
            _log_file_change("chmod", f"{file_path} - verification failed", False)
            return False
            
    except Exception as e:
        logger.error(f"Error changing permissions for {file_path}: {e}")
        if backup_metadata['success']:
            _rollback_file(backup_metadata)
        _log_file_change("chmod", f"{file_path} - {e}", False)
        return False


# ============================================================
# FIX 5: SAFE REMOVAL OF BACKUP FILES
# ============================================================
def _safe_remove_file(file_path: str, dry_run: bool = False) -> bool:
    """
    Safely remove a file with backup before deletion and dry-run support.
    """
    logger = logging.getLogger(__name__)
    
    if not os.path.exists(file_path):
        return True
    
    if dry_run:
        return _dry_run_file_fix("remove", f"Would remove {file_path}")
    
    # Verify this is a backup file
    backup_indicators = ['.backup', '.bak', '.old', '.orig', '~', '.swp', '.tmp']
    is_backup_file = any(indicator in file_path for indicator in backup_indicators)
    
    if not is_backup_file:
        logger.warning(f"File {file_path} doesn't appear to be a backup file. Skipping.")
        return False
    
    # Create backup before removal
    backup_metadata = _backup_file(file_path)
    if not backup_metadata['success']:
        logger.warning(f"Could not backup {file_path} before removal")
    
    try:
        REMOVED_FILES_BACKUP.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        dest_path = REMOVED_FILES_BACKUP / f"{Path(file_path).name}.removed_{timestamp}"
        shutil.move(file_path, dest_path)
        logger.info(f"Moved file to: {dest_path}")
        _log_file_change("remove", f"{file_path} → {dest_path}", True)
        return True
    except Exception as e:
        logger.error(f"Error removing {file_path}: {e}")
        if backup_metadata['success']:
            _rollback_file(backup_metadata)
        _log_file_change("remove", f"{file_path} - {e}", False)
        return False


def _dry_run_file_fix(action: str, details: str) -> bool:
    """Simulate file modification without actually changing anything."""
    logging.getLogger(__name__).info(f"[DRY-RUN] Would perform: {action} - {details}")
    print(f"[DRY-RUN] Would perform: {action}")
    return True


def _confirm_file_removal(files_to_remove: List[str]) -> bool:
    """Ask for confirmation before removing files."""
    print(f"\n[!] WARNING: About to remove {len(files_to_remove)} backup files:")
    for file_path in files_to_remove[:5]:
        print(f"    - {file_path}")
    if len(files_to_remove) > 5:
        print(f"    ... and {len(files_to_remove) - 5} more")
    print(f"    These files will be moved to: {REMOVED_FILES_BACKUP}")
    response = ui.prompt("Proceed? [y/N]: ")
    if response.lower() == 'y':
        print("\n[*] Applying fixes... please wait")
        return True
    return False


def _verify_backup_file_safety(file_path: str) -> bool:
    """Verify that removing a backup file is safe."""
    backup_indicators = ['.backup', '.bak', '.old', '.orig', '~', '.swp', '.tmp']
    is_backup = any(indicator in file_path for indicator in backup_indicators)
    
    if not is_backup:
        return False
    
    original = file_path
    for indicator in backup_indicators:
        original = original.replace(indicator, '')
    
    if not os.path.exists(original):
        logging.getLogger(__name__).warning(f"Original file not found for {file_path}")
    
    return True


def _progress_indicator(current: int, total: int, message: str = ""):
    """Show progress during operations."""
    if total > 0:
        percent = (current / total) * 100
        print(f"\r\033[K[{current}/{total}] {percent:.1f}% - {message}", end="", flush=True)


def fix(config: dict, dry_run: bool = False, force: bool = False) -> bool:
    """
    Fix sensitive file issues

    Returns:
        bool: True if fixes applied successfully
    """
    logger = logging.getLogger(__name__)
    logger.info("Fixing sensitive file issues...")

    dry_run = config.get('file_security', {}).get('dry_run', False)
    if dry_run:
        logger.info("DRY-RUN MODE: No changes will be applied")
        print("\n[!] DRY-RUN MODE - No changes will be applied")

    try:
        steps = []
        
        steps.append(("Fix sensitive permissions", _fix_sensitive_permissions))
        
        if config.get('file_security', {}).get('remove_backup_files', True):
            steps.append(("Remove backup files", _remove_backup_files))
        
        steps.append(("Secure SSH keys", _secure_ssh_keys))
        
        total_steps = len(steps)
        for idx, (name, func) in enumerate(steps):
            _progress_indicator(idx + 1, total_steps, name)
            if dry_run:
                _dry_run_file_fix(name, "Dry-run step")
            else:
                func(dry_run)
        
        print()

        logger.info("Sensitive file fixes applied successfully")
        return True

    except Exception as e:
        logger.error(f"Failed to fix sensitive files: {e}")
        return False


def _fix_sensitive_permissions(dry_run: bool = False):
    """Fix sensitive file permissions"""
    sensitive_files = {
        '/etc/shadow': 0o600,
        '/etc/passwd': 0o644,
        '/etc/sudoers': 0o440
    }

    for file_path, perms in sensitive_files.items():
        if os.path.exists(file_path):
            _safe_chmod(file_path, perms, dry_run)


def _remove_backup_files(dry_run: bool = False):
    """Remove backup files with sensitive data - ONLY CONFIRMED SENSITIVE"""
    patterns = ['*.backup', '*.bak', '*.old', '*.orig', '*~', '*.swp']
    removed_count = 0
    files_to_remove = []

    for pattern in patterns:
        try:
            # ✅ FIX: Limit to /etc and maxdepth 3
            result = subprocess.run(
                ['find', '/etc', '-maxdepth', '3', '-type', 'f', '-name', pattern],
                capture_output=True,
                text=True,
                timeout=30, stdin=subprocess.DEVNULL)
            
            if result.returncode == 0:
                for file_path in result.stdout.split('\n'):
                    if file_path.strip() and os.path.exists(file_path):
                        # ✅ FIX: Only remove if confirmed sensitive AND backup file
                        if _is_sensitive_file(file_path) and _verify_backup_file_safety(file_path):
                            files_to_remove.append(file_path)
        except Exception as e:
            logging.getLogger(__name__).error(f"Error finding backup files with pattern {pattern}: {e}")

    if files_to_remove and not dry_run and not _confirm_file_removal(files_to_remove):
        logging.getLogger(__name__).info("Backup file removal cancelled by user")
        return
    
    # ✅ FIX: Limit to 20 files
    files_to_remove = files_to_remove[:20]
    
    total_files = len(files_to_remove)
    for idx, file_path in enumerate(files_to_remove):
        _progress_indicator(idx + 1, total_files, f"Removing {Path(file_path).name}")
        if _safe_remove_file(file_path, dry_run):
            removed_count += 1
    
    print()
    logging.getLogger(__name__).info(f"Removed {removed_count} backup files (backed up to {REMOVED_FILES_BACKUP})")

def _secure_ssh_keys(dry_run: bool = False):
    """Secure SSH keys - ONLY SYSTEM SSH KEYS"""
    logger = logging.getLogger(__name__)
    
    # ✅ FIX: ONLY check /etc/ssh, NOT /root/.ssh or /home
    # System SSH keys are in /etc/ssh
    # User SSH keys should NOT be modified by system hardening
    try:
        system_ssh_dirs = ['/etc/ssh']
        key_files = []
        
        for ssh_dir in system_ssh_dirs:
            if not os.path.exists(ssh_dir):
                continue
            
            for file_path in Path(ssh_dir).iterdir():
                if file_path.is_file():
                    # Only secure system SSH host keys
                    if 'ssh_host' in str(file_path) or 'moduli' in str(file_path):
                        key_files.append(str(file_path))
        
        if not key_files:
            logger.info("No system SSH keys found to secure")
            return
        
        total_keys = len(key_files)
        print(f"\n[✓] Securing {total_keys} system SSH keys in /etc/ssh")
        
        for idx, file_path in enumerate(key_files):
            _progress_indicator(idx + 1, total_keys, f"Securing {Path(file_path).name}")
            _safe_chmod(file_path, 0o600, dry_run)
        
        print()
        logger.info(f"Secured {total_keys} system SSH keys")
        
    except Exception as e:
        logger.error(f"Error securing SSH keys: {e}")