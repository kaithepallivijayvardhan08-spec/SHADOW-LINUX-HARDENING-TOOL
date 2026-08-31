#!/usr/bin/env python3
"""
Shadow Ownership Module
=======================

Checks file and directory ownership:
- Critical system files ownership
- Files owned by non-existent users
- Files owned by root but writable by others
- Unusual ownership patterns
- Group ownership security
"""

from shadow.core import ui
import os
import pwd
import grp
import shutil
import logging
import subprocess
import tempfile
import time
import fcntl
import json
from pathlib import Path
from datetime import datetime
from typing import Tuple, Dict, List, Optional, Set, Any


BACKUP_DIR = Path("/var/backups/shadow/")
CHANGES_LOG = Path("/var/log/shadow/changes.log")


# ============================================================
# PROTECTED FILES - NEVER MODIFY OWNERSHIP
# ============================================================
PROTECTED_FILES = [
    '/etc/passwd',
    '/etc/shadow',
    '/etc/sudoers',
    '/etc/ssh/sshd_config',
    '/etc/fstab',
    '/etc/crontab',
    '/etc/hosts',
    '/etc/resolv.conf'
]


# ============================================================
# STRUCTURED LOGGING
# ============================================================
def _log_ownership_change(action: str, details: str, success: bool):
    """Log ownership modifications with structured format."""
    logger = logging.getLogger(__name__)
    status = "SUCCESS" if success else "FAILED"
    
    log_entry = {
        "event": "ownership_change",
        "action": action,
        "details": details,
        "status": status,
        "timestamp": datetime.now().isoformat()
    }
    logger.info(f"OWNERSHIP: {json.dumps(log_entry)}")
    
    try:
        CHANGES_LOG.parent.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(CHANGES_LOG, 'a') as f:
            f.write(f"{timestamp} - Ownership: {action} - {details} ({status})\n")
    except Exception as e:
        logger.debug(f"Failed to log change: {e}")


# ============================================================
# CHECK FUNCTION
# ============================================================
def check(config: dict) -> Tuple[str, str, dict]:
    """
    Check file and directory ownership
    """
    logger = logging.getLogger(__name__)
    logger.info("Checking file ownership...")

    issues = []
    warnings = []
    details = {
        'critical_files': {},
        'non_existent_owners': [],
        'root_writable_files': [],
        'group_owned_issues': [],
        'orphaned_files': [],
        'suspicious_ownership': []
    }

    valid_users = _get_valid_users()
    valid_groups = _get_valid_groups()

    critical_files = _check_critical_ownership()
    details['critical_files'] = critical_files

    for file_path, owner_info in critical_files.items():
        if not owner_info.get('secure'):
            issues.append(f"CRITICAL: {file_path} has insecure ownership: {owner_info.get('owner')}:{owner_info.get('group')}")

    non_existent_owners = _find_non_existent_owners(valid_users)
    if non_existent_owners:
        details['non_existent_owners'] = non_existent_owners
        for file_info in non_existent_owners[:10]:
            warnings.append(f"File owned by non-existent user: {file_info['path']} (UID: {file_info['uid']})")
        if len(non_existent_owners) > 10:
            warnings.append(f"... and {len(non_existent_owners) - 10} more files")

    root_writable = _find_root_writable_files()
    if root_writable:
        details['root_writable_files'] = root_writable
        for file_info in root_writable[:10]:
            issues.append(f"Root-owned file writable by others: {file_info['path']} ({file_info['permissions']})")
        if len(root_writable) > 10:
            issues.append(f"... and {len(root_writable) - 10} more files")

    group_issues = _check_group_ownership(valid_groups)
    if group_issues:
        details['group_owned_issues'] = group_issues
        for file_info in group_issues[:5]:
            warnings.append(f"Group ownership issue: {file_info['path']} (Group: {file_info['group']})")
        if len(group_issues) > 5:
            warnings.append(f"... and {len(group_issues) - 5} more files")

    orphaned = _find_orphaned_files(valid_users, valid_groups)
    if orphaned:
        details['orphaned_files'] = orphaned
        for file_info in orphaned[:5]:
            warnings.append(f"Orphaned file: {file_info['path']} (Owner: {file_info.get('owner', 'unknown')})")
        if len(orphaned) > 5:
            warnings.append(f"... and {len(orphaned) - 5} more files")

    suspicious = _find_suspicious_ownership()
    if suspicious:
        details['suspicious_ownership'] = suspicious
        for file_info in suspicious:
            warnings.append(f"Suspicious ownership: {file_info['path']} (Owner: {file_info['owner']})")

    if issues:
        critical = [i for i in issues if 'CRITICAL' in i]
        if critical:
            status = 'FAIL'
            message = f"{len(critical)} critical ownership issues found"
        else:
            status = 'WARN'
            message = f"{len(issues)} ownership issues found"
    elif warnings:
        status = 'WARN'
        message = f"{len(warnings)} ownership warnings found"
    else:
        status = 'PASS'
        message = "File ownership is secure"

    return status, message, details


def _get_valid_users() -> Set[str]:
    """Get set of valid usernames using getent"""
    users = set()
    try:
        result = subprocess.run(['getent', 'passwd'], capture_output=True, text=True, timeout=10, stdin=subprocess.DEVNULL)
        if result.returncode == 0:
            for line in result.stdout.split('\n'):
                if ':' in line:
                    users.add(line.split(':')[0])
    except Exception as e:
        logging.getLogger(__name__).warning(f"Error getting users: {e}")
    return users


def _get_valid_groups() -> Set[str]:
    """Get set of valid group names using getent"""
    groups = set()
    try:
        result = subprocess.run(['getent', 'group'], capture_output=True, text=True, timeout=10, stdin=subprocess.DEVNULL)
        if result.returncode == 0:
            for line in result.stdout.split('\n'):
                if ':' in line:
                    groups.add(line.split(':')[0])
    except Exception as e:
        logging.getLogger(__name__).warning(f"Error getting groups: {e}")
    return groups


def _check_critical_ownership() -> Dict:
    """Check critical system files ownership"""
    critical_files = {}
    critical_paths = [
        '/etc/passwd', '/etc/shadow', '/etc/sudoers', '/etc/ssh/sshd_config',
        '/etc/security/pwquality.conf', '/etc/login.defs', '/etc/hosts',
        '/etc/hosts.allow', '/etc/hosts.deny'
    ]

    for file_path in critical_paths:
        if not os.path.exists(file_path):
            continue

        try:
            stat_info = os.stat(file_path)
            owner_uid = stat_info.st_uid
            group_gid = stat_info.st_gid

            try: owner_name = pwd.getpwuid(owner_uid).pw_name
            except KeyError: owner_name = str(owner_uid)

            try: group_name = grp.getgrgid(group_gid).gr_name
            except KeyError: group_name = str(group_gid)

            secure = True
            issues_list = []

            if owner_uid != 0:
                secure = False
                issues_list.append(f"Owner is not root: {owner_name}")

            if file_path in ['/etc/shadow', '/etc/sudoers']:
                if group_gid != 0:
                    secure = False
                    issues_list.append(f"Group is not root: {group_name}")

            critical_files[file_path] = {
                'owner': owner_name, 'group': group_name,
                'uid': owner_uid, 'gid': group_gid,
                'secure': secure, 'issues': issues_list
            }
        except Exception as e:
            critical_files[file_path] = {'error': str(e), 'secure': False}

    return critical_files


def _find_non_existent_owners(valid_users: Set[str]) -> List[Dict]:
    """Find files owned by non-existent users - ONLY IN /etc, limited depth."""
    non_existent = []
    search_dir = '/etc'
    if not os.path.exists(search_dir): return non_existent

    try:
        result = subprocess.run(
            ['find', search_dir, '-maxdepth', '3', '-type', 'f', '-nouser', '-ls'],
            capture_output=True, text=True, timeout=30, stdin=subprocess.DEVNULL)
        if result.returncode == 0:
            for line in result.stdout.split('\n'):
                if line.strip():
                    parts = line.split()
                    if len(parts) > 10:
                        uid = parts[2] if len(parts) > 2 else 'unknown'
                        gid = parts[3] if len(parts) > 3 else 'unknown'
                        path = ' '.join(parts[10:])
                        if path.endswith('.conf') or path.endswith('.cfg') or path in PROTECTED_FILES:
                            non_existent.append({'path': path, 'uid': uid, 'gid': gid})
                            if len(non_existent) > 20: break
    except Exception as e:
        logging.getLogger(__name__).warning(f"Find -nouser failed: {e}")

    return non_existent[:20]


def _find_root_writable_files() -> List[Dict]:
    """Find files owned by root but writable by others - ONLY IN /etc, limited depth."""
    root_writable = []
    search_dir = '/etc'
    if not os.path.exists(search_dir): return root_writable

    try:
        result = subprocess.run(
            ['find', search_dir, '-maxdepth', '3', '-type', 'f', '-user', 'root', '-perm', '-o+w', '-ls'],
            capture_output=True, text=True, timeout=30, stdin=subprocess.DEVNULL)
        if result.returncode == 0:
            for line in result.stdout.split('\n'):
                if line.strip():
                    parts = line.split()
                    if len(parts) > 10:
                        perms = parts[1] if len(parts) > 1 else 'unknown'
                        path = ' '.join(parts[10:])
                        if path not in PROTECTED_FILES:
                            root_writable.append({'path': path, 'permissions': perms})
                            if len(root_writable) > 20: break
    except Exception as e:
        logging.getLogger(__name__).warning(f"Find root writable failed: {e}")

    return root_writable[:20]


def _check_group_ownership(valid_groups: Set[str]) -> List[Dict]:
    """Check for group ownership issues"""
    group_issues = []
    search_dir = '/etc'

    try:
        result = subprocess.run(
            ['find', search_dir, '-maxdepth', '3', '-type', 'f', '-nogroup', '-ls'],
            capture_output=True, text=True, timeout=30, stdin=subprocess.DEVNULL)
        if result.returncode == 0:
            for line in result.stdout.split('\n'):
                if line.strip():
                    parts = line.split()
                    if len(parts) > 10:
                        gid = parts[3] if len(parts) > 3 else 'unknown'
                        path = ' '.join(parts[10:])
                        group_issues.append({'path': path, 'group': gid})
                        if len(group_issues) > 20: break
    except Exception as e:
        logging.getLogger(__name__).warning(f"Find -nogroup failed: {e}")

    try:
        for group in ['root', 'shadow', 'sudo', 'admin']:
            result = subprocess.run(
                ['find', '/etc', '-type', 'f', '-group', group, '-perm', '-g+w', '-ls'],
                capture_output=True, text=True, timeout=10, stdin=subprocess.DEVNULL)
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if line.strip():
                        parts = line.split()
                        if len(parts) > 10:
                            perms = parts[1] if len(parts) > 1 else 'unknown'
                            path = ' '.join(parts[10:])
                            group_issues.append({'path': path, 'group': group, 'permissions': perms})
    except Exception as e:
        logging.getLogger(__name__).debug(f"Group writable find failed: {e}")

    return group_issues


def _find_orphaned_files(valid_users: Set[str], valid_groups: Set[str]) -> List[Dict]:
    """Find orphaned files - ONLY IN /etc, limited depth."""
    orphaned = []
    search_dir = '/etc'
    if not os.path.exists(search_dir): return orphaned

    try:
        # Fixed: properly escaped parentheses for find command
        result = subprocess.run(
            ['find', search_dir, '-maxdepth', '3', '-type', 'f', '(', '-nouser', '-o', '-nogroup', ')', '-ls'],
            capture_output=True, text=True, timeout=30, stdin=subprocess.DEVNULL)
        if result.returncode == 0:
            for line in result.stdout.split('\n'):
                if line.strip():
                    parts = line.split()
                    if len(parts) > 10:
                        uid = parts[2] if len(parts) > 2 else 'unknown'
                        gid = parts[3] if len(parts) > 3 else 'unknown'
                        path = ' '.join(parts[10:])
                        if path.endswith('.conf') or path in PROTECTED_FILES:
                            orphaned.append({'path': path, 'uid': uid, 'gid': gid})
                            if len(orphaned) > 20: break
    except Exception as e:
        logging.getLogger(__name__).warning(f"Orphaned find failed: {e}")

    return orphaned[:20]


def _find_suspicious_ownership() -> List[Dict]:
    """Find suspicious ownership patterns"""
    suspicious = []
    system_users = ['daemon', 'bin', 'sys', 'sync', 'games', 'man', 'lp', 'mail', 'news']
    search_dirs = ['/home', '/tmp', '/var/tmp', '/opt']

    for user in system_users:
        for search_dir in search_dirs:
            if not os.path.exists(search_dir): continue
            try:
                result = subprocess.run(
                    ['find', search_dir, '-type', 'f', '-user', user, '-ls'],
                    capture_output=True, text=True, timeout=5, stdin=subprocess.DEVNULL)
                if result.returncode == 0:
                    for line in result.stdout.split('\n'):
                        if line.strip():
                            parts = line.split()
                            if len(parts) > 10:
                                path = ' '.join(parts[10:])
                                suspicious.append({
                                    'path': path, 'owner': user,
                                    'reason': f'System user {user} owns file in {search_dir}'
                                })
            except Exception:
                continue
    return suspicious


def _verify_backup(backup_path: Path) -> bool:
    """Verify that a backup was created successfully."""
    if not backup_path.exists():
        logging.getLogger(__name__).error(f"Backup not found: {backup_path}")
        return False
    if backup_path.stat().st_size == 0:
        logging.getLogger(__name__).error(f"Backup is empty: {backup_path}")
        return False
    return True


def _backup_ownership(file_path: str) -> Dict[str, Any]:
    """Backup current file ownership and metadata."""
    result = {'path': file_path, 'backup_path': None, 'uid': None, 'gid': None, 'perms': None, 'success': False}
    
    try:
        BACKUP_DIR.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        
        if os.path.exists(file_path):
            file_name = Path(file_path).name
            backup_path = BACKUP_DIR / f"{file_name}.backup_{timestamp}"
            shutil.copy2(file_path, backup_path)
            result['backup_path'] = str(backup_path)
            
            stat_info = os.stat(file_path)
            result['uid'] = stat_info.st_uid
            result['gid'] = stat_info.st_gid
            result['perms'] = oct(stat_info.st_mode)[-3:]
            
            if _verify_backup(backup_path):
                result['success'] = True
                logging.getLogger(__name__).info(f"Backup created: {backup_path}")
    except Exception as e:
        logging.getLogger(__name__).error(f"Failed to backup {file_path}: {e}")
    
    return result


def _validate_ownership_change(file_path: str, uid: int, gid: int) -> bool:
    """Validate that ownership change is safe."""
    critical_files = {
        '/etc/passwd': (0, 0), '/etc/shadow': (0, 0),
        '/etc/sudoers': (0, 0), '/etc/ssh/sshd_config': (0, 0),
    }
    
    if file_path in critical_files:
        expected_uid, expected_gid = critical_files[file_path]
        if uid != expected_uid or gid != expected_gid:
            logging.getLogger(__name__).error(f"Unsafe ownership change attempted on {file_path}")
            return False
    return True


def _rollback_ownership(backup_metadata: Dict[str, Any]) -> bool:
    """Rollback ownership and file content from backup."""
    if not backup_metadata.get('success'): return False
    
    backup_path = Path(backup_metadata['backup_path'])
    original_path = backup_metadata['path']
    
    if not backup_path.exists(): return False
    
    try:
        shutil.copy2(backup_path, original_path)
        if backup_metadata.get('uid') is not None and backup_metadata.get('gid') is not None:
            os.chown(original_path, backup_metadata['uid'], backup_metadata['gid'])
        return True
    except Exception as e:
        logging.getLogger(__name__).error(f"Rollback failed for {original_path}: {e}")
        return False


def _verify_ownership_change(file_path: str, expected_uid: int, expected_gid: int) -> bool:
    """Verify that ownership was changed correctly."""
    try:
        if not os.path.exists(file_path): return False
        stat_info = os.stat(file_path)
        return stat_info.st_uid == expected_uid and stat_info.st_gid == expected_gid
    except Exception:
        return False


def _safe_chown(file_path: str, uid: int, gid: int, dry_run: bool = False, force: bool = False) -> bool:
    """Safely change file ownership with backup, validation, and rollback."""
    logger = logging.getLogger(__name__)
    
    if not os.path.exists(file_path): return False
    if dry_run: return True
    
    lock_file = Path(file_path).with_suffix('.lock')
    fd = None
    try:
        fd = open(lock_file, 'w')
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except Exception:
        pass
    
    # ✅ FIX: Pass force down to the warning function
    if not _warn_system_file_ownership(file_path, force=force): return False
    
    backup_metadata = _backup_ownership(file_path)
    if not _validate_ownership_change(file_path, uid, gid): return False
    
    try:
        os.chown(file_path, uid, gid)
        logger.info(f"Changed ownership for {file_path}: → {uid}:{gid}")
        _log_ownership_change("chown", f"{file_path}: → {uid}:{gid}", True)
        
        if _verify_ownership_change(file_path, uid, gid):
            return True
        else:
            if backup_metadata['success']: _rollback_ownership(backup_metadata)
            return False
    except Exception as e:
        logger.error(f"Error changing ownership for {file_path}: {e}")
        if backup_metadata['success']: _rollback_ownership(backup_metadata)
        return False
    finally:
        if fd:
            try:
                fcntl.flock(fd, fcntl.LOCK_UN)
                fd.close()
                lock_file.unlink(missing_ok=True)
            except Exception:
                pass


def _fix_orphaned_files(dry_run: bool = False):
    """Fix orphaned files - ONLY IN /etc and ONLY config files."""
    logger = logging.getLogger(__name__)
    try:
        if dry_run: return
        orphaned = _find_orphaned_files(set(), set())
        if not orphaned: return
            
        config_files = [f for f in orphaned if f['path'].endswith('.conf') or f['path'].endswith('.cfg')]
        if config_files:
            print(f"\n[!] Found {len(config_files)} orphaned config files.")
            response = ui.prompt("Fix orphaned files by assigning to root? [y/N]: ")
            if response.lower() != 'y': return
        
        for file_info in config_files[:20]:
            if os.path.exists(file_info['path']):
                _safe_chown(file_info['path'], 0, 0, dry_run)
    except Exception as e:
        logger.error(f"Error fixing orphaned files: {e}")


def _fix_root_writable_files(dry_run: bool = False):
    """Fix root-owned files writable by others"""
    logger = logging.getLogger(__name__)
    try:
        if dry_run: return
        result = subprocess.run(
            ['find', '/etc', '-maxdepth', '3', '-type', 'f', '-user', 'root', '-perm', '-o+w', '-ls'],
            capture_output=True, text=True, timeout=30, stdin=subprocess.DEVNULL)
        
        if result.returncode == 0:
            files = []
            for line in result.stdout.split('\n'):
                if line.strip():
                    parts = line.split()
                    if len(parts) > 10:
                        files.append(' '.join(parts[10:]))
            
            if files:
                print(f"\n[!] Found {len(files)} root-writable files.")
                response = ui.prompt("Fix permissions on these files? [y/N]: ")
                if response.lower() != 'y': return
            
            for file_path in files[:100]:
                if os.path.exists(file_path) and file_path not in PROTECTED_FILES:
                    backup_meta = _backup_ownership(file_path)
                    try:
                        stat_info = os.stat(file_path)
                        os.chmod(file_path, stat_info.st_mode & ~0o002)
                        _log_ownership_change("fix_root_writable", file_path, True)
                    except Exception as e:
                        logger.error(f"Error fixing {file_path}: {e}")
                        if backup_meta['success']: _rollback_ownership(backup_meta)
    except Exception as e:
        logger.error(f"Error fixing root writable files: {e}")


def _warn_system_file_ownership(file_path: str, force: bool = False) -> bool:
    """Warn before changing ownership of system files."""
    system_files = [
        '/etc/passwd', '/etc/shadow', '/etc/sudoers', '/etc/ssh/sshd_config',
        '/etc/security/pwquality.conf', '/etc/login.defs', '/etc/hosts'
    ]
    
    if file_path in system_files:
        # ✅ FIX: Skip prompt if force mode is active
        if force:
            logging.getLogger(__name__).info(f"Force mode: Auto-confirming ownership change for {file_path}")
            return True
            
        print(f"\n[!] CRITICAL WARNING: {file_path} is a critical system file!")
        print("Changing ownership incorrectly will break the system.")
        response = ui.prompt("Continue with ownership change? [y/N]: ")
        return response.lower() == 'y'
    return True


# ============================================================
# FIX 11: SAFER LOGIN TEST (FIXED)
# ============================================================
def _test_login() -> bool:
    """Test if system auth files are still valid after ownership changes."""
    try:
        # Instead of 'su' which might hang asking for password, 
        # we just verify we can read the critical files we modified
        for f in ['/etc/passwd', '/etc/shadow']:
            if os.path.exists(f):
                with open(f, 'r') as file:
                    file.read(1)
        return True
    except Exception as e:
        logging.getLogger(__name__).warning(f"File access test failed: {e}")
        return False


def fix(config: dict, dry_run: bool = False, force: bool = False) -> bool:
    """Fix ownership issues - ONLY WHITELISTED FILES"""
    logger = logging.getLogger(__name__)
    logger.info("Fixing ownership issues...")
    
    if dry_run:
        logger.info("DRY-RUN MODE: No changes will be applied")
        return True

    critical_files = {
        '/etc/passwd': (0, 0), '/etc/shadow': (0, 0), '/etc/sudoers': (0, 0),
        '/etc/ssh/sshd_config': (0, 0), '/etc/security/pwquality.conf': (0, 0),
        '/etc/login.defs': (0, 0)
    }
    
    files_to_change = []
    for file_path, (uid, gid) in critical_files.items():
        if os.path.exists(file_path):
            try:
                stat_info = os.stat(file_path)
                if stat_info.st_uid != uid or stat_info.st_gid != gid:
                    files_to_change.append(file_path)
            except Exception:
                pass

    if not files_to_change:
        logger.info("All ownerships are already correct")
        return True

    if not force:
        print(f"\n[!] Found {len(files_to_change)} files with incorrect ownership.")
        # ✅ Use the bulletproof prompt that guarantees echo is ON
        response = ui.prompt("Fix critical file ownership? [y/N]: ")
        if response.lower() not in ('y', 'yes'):
            print("Skipped.")
            return False

    try:
        for idx, file_path in enumerate(files_to_change):
            print(f"\r[{idx+1}/{len(files_to_change)}] Fixing {Path(file_path).name}", end="", flush=True)
            uid, gid = critical_files[file_path]
            # ✅ FIX: Pass force down to safe_chown
            _safe_chown(file_path, uid, gid, dry_run, force=force)
        print()

        if not dry_run:
            if not _test_login():
                logger.error("File access test failed after ownership changes!")
                return False

        logger.info("Ownership fixes applied successfully")
        return True

    except Exception as e:
        logger.error(f"Failed to fix ownership: {e}")
        return False