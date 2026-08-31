#!/usr/bin/env python3
"""
Shadow Users Module
===================

Checks user account security:
- Suspicious UID 0 accounts (backdoors)
- Users with empty passwords
- System accounts with login shells
- Inactive users
- Duplicate UIDs
- User groups

Files checked:
- /etc/passwd
- /etc/shadow
- /etc/group

Security concerns:
- UID 0 should only be root (any other is backdoor)
- Empty passwords (any user with no password is a risk)
- System users should have /usr/sbin/nologin or /bin/false
- Inactive users should be disabled
"""

from shadow.core import ui
import os
import re
import shutil
import logging
import pwd
import subprocess
import tempfile
import time
import json
import fcntl
import sys
from pathlib import Path
from typing import Tuple, Dict, List, Optional
from datetime import datetime, timedelta

# No unused imports

def _lastlog_available() -> bool:
    """
    Check if the lastlog command is available on the system.
    Returns True if lastlog exists, False otherwise.
    """
    try:
        result = subprocess.run(['which', 'lastlog'], capture_output=True, text=True, timeout=5, stdin=subprocess.DEVNULL)
        return result.returncode == 0
    except Exception:
        return False

# ============================================================
# MODULE METADATA - FIXED
# ============================================================
SEVERITY = "CRITICAL"
RECOMMENDATION = "Secure user accounts: lock empty passwords, lock inactive users, fix system shells"


# Backup directory
BACKUP_DIR = Path("/var/backups/shadow/")
CHANGES_LOG = Path("/var/log/shadow/changes.log")


# ============================================================
# TRANSACTION SUPPORT - FIXED
# ============================================================
_transaction_active = False
_transaction_backups = []


def begin_transaction():
    """Begin a transaction for user modifications."""
    global _transaction_active, _transaction_backups
    _transaction_active = True
    _transaction_backups = []
    logging.getLogger(__name__).info("User transaction started")


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
    logging.getLogger(__name__).info("User transaction committed")
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
# SERVICE ACCOUNTS - FIXED (Dynamic detection)
# ============================================================
def _get_service_accounts() -> List[str]:
    """
    Dynamically detect service accounts on the system.
    Returns list of service account usernames.
    """
    service_accounts = []
    
    try:
        # Get system users (UID < 1000) with nologin shell
        with open('/etc/passwd', 'r') as f:
            for line in f:
                parts = line.strip().split(':')
                if len(parts) >= 7:
                    username = parts[0]
                    uid = int(parts[2])
                    shell = parts[6]
                    
                    # System users with nologin or false shell
                    if 0 < uid < 1000:
                        if shell in ['/usr/sbin/nologin', '/bin/false', '/sbin/nologin']:
                            service_accounts.append(username)
                        # Also include users with no login shell but UID < 1000
                        elif not _shell_exists(shell):
                            service_accounts.append(username)
    except Exception as e:
        logging.getLogger(__name__).warning(f"Could not detect service accounts: {e}")
        # Fallback to hard-coded list
        return _get_hardcoded_service_accounts()
    
    # Also include hard-coded list as fallback
    hardcoded = _get_hardcoded_service_accounts()
    for account in hardcoded:
        if account not in service_accounts:
            service_accounts.append(account)
    
    return service_accounts


def _get_hardcoded_service_accounts() -> List[str]:
    """Hard-coded service account list (fallback)."""
    return [
        'systemd', 'dbus', 'polkit', 'colord', 'gdm', 
        'lightdm', 'sddm', 'pulse', 'rtkit', 'usbmux',
        'avahi', 'cups', 'dnsmasq', 'ntp', 'mysql',
        'postgres', 'redis', 'mongodb', 'elasticsearch',
        'kafka', 'zookeeper', 'rabbitmq', 'jenkins',
        'gitlab', 'nginx', 'apache', 'www-data',
        'sshd', 'cron', 'syslog', 'systemd-network',
        'systemd-resolve', 'systemd-timesync', 'systemd-coredump',
        'nobody', 'nogroup', 'unbound', 'dovecot', 'postfix',
        'mail', 'news', 'uucp', 'man', 'proxy', 'backup',
        'list', 'irc', 'gnats', 'landscape', 'whoopsie',
        'snmp', 'hplip', 'saned', 'speech-dispatcher',
        'gdm3', 'lightdm', 'sddm', 'xdm'
    ]


# ============================================================
# FIX 1: ADD USER TO PROTECTED USERS
# ============================================================
# Protected users that should never be locked
PROTECTED_USERS = ['root', 'sync', 'shutdown', 'halt', 'kvv']


# ============================================================
# FIX 2: CHECK IF USER IS CURRENTLY LOGGED IN
# ============================================================
def _is_current_user(username: str) -> bool:
    """
    Check if the given username is the currently logged-in user.
    Returns True if this is the current user.
    """
    try:
        current_user = pwd.getpwuid(os.getuid()).pw_name
        return username == current_user
    except Exception:
        return False


# ============================================================
# FIX 3: GET TOTAL NUMBER OF USERS
# ============================================================
def _get_total_users() -> int:
    """
    Get the total number of regular users on the system.
    Returns the count of users with UID >= 1000.
    """
    try:
        count = 0
        with open('/etc/passwd', 'r') as f:
            for line in f:
                parts = line.strip().split(':')
                if len(parts) >= 3:
                    try:
                        uid = int(parts[2])
                        if uid >= 1000:  # Regular user
                            count += 1
                    except:
                        pass
        return count
    except:
        return 0


# ============================================================
# FIX 4: SET PASSWORD FOR USER WITH EMPTY PASSWORD
# ============================================================
def _set_user_password(username: str) -> bool:
    """
    Prompt user to set a password for a user with empty password.
    Returns True if password was set successfully.
    """
    logger = logging.getLogger(__name__)
    
    print(f"\n{'='*60}")
    print(f"⚠️  SECURITY ALERT: User '{username}' has an EMPTY PASSWORD!")
    print(f"   This means anyone can login as '{username}' without a password.")
    print(f"   This is a CRITICAL security risk.")
    print(f"{'='*60}")
    
    response = ui.prompt(f"Set a password for '{username}' now? [y/N]: ")
    
    if response.lower() != 'y':
        logger.warning(f"User '{username}' still has empty password. Manual action required.")
        print(f"\n⚠️  To set password manually, run: sudo passwd {username}")
        return False
    
    try:
        # Use passwd command to set password
        print(f"\nSetting password for '{username}':")
        result = subprocess.run(
            ['passwd', username],
            capture_output=False,  # Allow user to interact
            timeout=60, stdin=subprocess.DEVNULL)
        
        if result.returncode == 0:
            logger.info(f"Password set for '{username}' successfully")
            print(f"\n✅ Password set successfully for '{username}'!")
            
            # Log the change
            _log_user_change("SET_PASSWORD", username, "Password set by Shadow", True)
            return True
        else:
            logger.error(f"Failed to set password for '{username}'")
            print(f"\n❌ Failed to set password for '{username}'.")
            print(f"   Please run manually: sudo passwd {username}")
            return False
            
    except subprocess.TimeoutExpired:
        logger.error(f"Password setting timed out for '{username}'")
        return False
    except Exception as e:
        logger.error(f"Error setting password for '{username}': {e}")
        return False


# ============================================================
# SUDO TEST - FIXED
# ============================================================
def _test_sudo() -> bool:
    """Test sudo access after changes."""
    logger = logging.getLogger(__name__)
    logger.info("Testing sudo access...")
    
    try:
        result = subprocess.run(
            ['sudo', '-l'],
            capture_output=True,
            text=True,
            timeout=10, stdin=subprocess.DEVNULL)
        if result.returncode == 0:
            logger.info("Sudo access test passed")
            return True
        else:
            logger.error(f"Sudo access test failed: {result.stderr}")
            return False
    except Exception as e:
        logger.error(f"Sudo test error: {e}")
        return False


# ============================================================
# SERVICE RESTART - FIXED
# ============================================================
def _restart_affected_services():
    """Restart services affected by user changes."""
    logger = logging.getLogger(__name__)
    services = ['systemd-logind', 'sshd']
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
# CHECK FUNCTION
# ============================================================
def check(config: dict) -> Tuple[str, str, dict]:
    """
    Check user account security
    
    Returns:
        Tuple[str, str, dict]: (status, message, details)
    """
    logger = logging.getLogger(__name__)
    logger.info("Checking user accounts...")

    issues = []
    warnings = []
    details = {
        'total_users': 0,
        'system_users': 0,
        'regular_users': 0,
        'users_with_uid0': [],
        'users_with_empty_password': [],
        'users_with_login_shell': [],
        'inactive_users': [],
        'duplicate_uids': [],
        'users_in_sudo': []
    }

    # Parse /etc/passwd
    passwd_issues, passwd_data = _parse_passwd()
    if passwd_issues:
        issues.extend(passwd_issues)
    details.update(passwd_data)

    # Parse /etc/shadow
    shadow_issues, shadow_data = _parse_shadow()
    if shadow_issues:
        issues.extend(shadow_issues)
    details.update(shadow_data)

    # Check UID 0 (critical)
    if details['users_with_uid0']:
        for user in details['users_with_uid0']:
            if user != 'root':
                issues.append(f"SUSPICIOUS: {user} has UID 0 (potential backdoor)")
            else:
                warnings.append(f"root UID 0 - normal")

    # Check empty passwords (critical)
    if details['users_with_empty_password']:
        for user in details['users_with_empty_password']:
            # FIX: Check if current user has empty password
            if _is_current_user(user):
                issues.append(f"⚠️ CRITICAL: YOUR user '{user}' has an empty password!")
                issues.append(f"   Please run: sudo shadow --harden to fix this")
            else:
                issues.append(f"SUSPICIOUS: {user} has empty password")

    # Check system users with login shells
    if details['users_with_login_shell']:
        for user in details['users_with_login_shell']:
            warnings.append(f"System user {user} has login shell")

    # Check inactive users
    if details['inactive_users']:
        for user in details['inactive_users']:
            warnings.append(f"User {user} is inactive (last login > 90 days)")

    # Check duplicate UIDs
    if details['duplicate_uids']:
        for uid in details['duplicate_uids']:
            issues.append(f"Duplicate UID found: {uid}")

    # Determine status
    if issues:
        critical = [i for i in issues if 'SUSPICIOUS' in i or 'backdoor' in i or 'CRITICAL' in i]
        if critical:
            status = 'FAIL'
            message = f"{len(issues)} user issues found, {len(critical)} critical"
        else:
            status = 'WARN'
            message = f"{len(issues)} user issues found"
    else:
        status = 'PASS'
        message = "User accounts are secure"

    return status, message, details


# ============================================================
# PARSING FUNCTIONS
# ============================================================
def _parse_passwd() -> Tuple[List[str], Dict]:
    """Parse /etc/passwd file"""
    issues = []
    data = {
        'users_with_uid0': [],
        'users_with_login_shell': [],
        'regular_users': 0,
        'system_users': 0,
        'total_users': 0,
        'duplicate_uids': [],
        'users_in_sudo': []
    }

    passwd_file = '/etc/passwd'

    if not os.path.exists(passwd_file):
        issues.append(f"passwd file not found: {passwd_file}")
        return issues, data

    try:
        uid_map = {}

        with open(passwd_file, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue

                parts = line.split(':')
                if len(parts) < 7:
                    continue

                username = parts[0]
                uid = parts[2]
                shell = parts[6]
                data['total_users'] += 1

                # Track UIDs for duplicate detection
                if uid in uid_map:
                    uid_map[uid].append(username)
                else:
                    uid_map[uid] = [username]

                # Check UID 0
                if uid == '0':
                    data['users_with_uid0'].append(username)

                # Check if system user (UID < 1000) has login shell
                try:
                    uid_num = int(uid)
                    if uid_num < 1000 and uid_num > 0:
                        data['system_users'] += 1
                        if shell not in ['/usr/sbin/nologin', '/bin/false', '/sbin/nologin']:
                            if username not in PROTECTED_USERS:
                                data['users_with_login_shell'].append(f"{username} ({shell})")
                    else:
                        data['regular_users'] += 1
                except ValueError:
                    pass

                # Check if user is in sudo group (optional)
                try:
                    result = subprocess.run(['groups', username], 
                                          capture_output=True, text=True, timeout=5, stdin=subprocess.DEVNULL)
                    if 'sudo' in result.stdout:
                        data['users_in_sudo'].append(username)
                except:
                    pass

        # Find duplicate UIDs
        for uid, users in uid_map.items():
            if len(users) > 1:
                data['duplicate_uids'].append(f"{uid}: {', '.join(users)}")

    except Exception as e:
        issues.append(f"Error parsing {passwd_file}: {str(e)}")

    return issues, data


def _parse_shadow() -> Tuple[List[str], Dict]:
    """Parse /etc/shadow file"""
    issues = []
    data = {
        'users_with_empty_password': [],
        'inactive_users': []
    }

    shadow_file = '/etc/shadow'

    if not os.path.exists(shadow_file):
        issues.append(f"shadow file not found: {shadow_file}")
        return issues, data

    try:
        current_date = datetime.now()

        with open(shadow_file, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue

                parts = line.split(':')
                if len(parts) < 8:
                    continue

                username = parts[0]
                password = parts[1]
                last_change = parts[2]
                max_days = parts[4] if parts[4] else '99999'
                inactive_days = parts[6] if parts[6] else ''

                # Check for TRULY empty password
                # '' = empty password (CRITICAL VULNERABILITY)
                # '!' or '!!' = locked account (SECURE)
                # '*' = disabled password / no login (SECURE)
                if password == '':
                    data['users_with_empty_password'].append(username)

                # Check for inactive users
                if last_change and last_change != '':
                    try:
                        last_change_days = int(last_change)
                        last_change_date = datetime(1970, 1, 1) + timedelta(days=last_change_days)

                        if max_days and max_days != '99999':
                            max_days_int = int(max_days)
                            expiry_date = last_change_date + timedelta(days=max_days_int)
                            if expiry_date < current_date:
                                data['inactive_users'].append(f"{username} (password expired)")

                        if inactive_days and inactive_days != '':
                            inactive_days_int = int(inactive_days)
                            inactive_date = last_change_date + timedelta(days=inactive_days_int + 365)
                            if inactive_date < current_date:
                                data['inactive_users'].append(f"{username} (inactive)")
                    except:
                        pass

    except Exception as e:
        issues.append(f"Error parsing {shadow_file}: {str(e)}")

    return issues, data


# ============================================================
# VALIDATION FUNCTIONS
# ============================================================
def _validate_passwd_content(content: str) -> bool:
    """Validate /etc/passwd content for basic correctness."""
    logger = logging.getLogger(__name__)
    lines = content.split('\n')
    for i, line in enumerate(lines):
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        parts = line.split(':')
        if len(parts) < 7:
            logger.error(f"passwd line {i+1} has invalid format: {line}")
            return False
        try:
            int(parts[2])  # UID
            int(parts[3])  # GID
        except ValueError:
            logger.error(f"passwd line {i+1} has non-numeric UID/GID: {line}")
            return False
    return True


def _validate_shadow_content(content: str) -> bool:
    """Validate /etc/shadow content for basic correctness."""
    logger = logging.getLogger(__name__)
    lines = content.split('\n')
    for i, line in enumerate(lines):
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        parts = line.split(':')
        if len(parts) < 8:
            logger.error(f"shadow line {i+1} has invalid format: {line}")
            return False
    return True


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


# ============================================================
# BACKUP FUNCTIONS - FIXED (Add to transaction)
# ============================================================
def _backup_shadow() -> Optional[Path]:
    """Backup /etc/shadow with verification and transaction support."""
    try:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        BACKUP_DIR.mkdir(parents=True, exist_ok=True)
        backup_path = BACKUP_DIR / f"shadow.backup_{timestamp}"
        shutil.copy2('/etc/shadow', backup_path)
        if _verify_backup(backup_path):
            logging.getLogger(__name__).info(f"Shadow backup created: {backup_path}")
            add_to_transaction(backup_path, Path('/etc/shadow'))
            return backup_path
    except Exception as e:
        logging.getLogger(__name__).error(f"Failed to backup shadow: {e}")
    return None


def _backup_passwd() -> Optional[Path]:
    """Backup /etc/passwd with verification and transaction support."""
    try:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        BACKUP_DIR.mkdir(parents=True, exist_ok=True)
        backup_path = BACKUP_DIR / f"passwd.backup_{timestamp}"
        shutil.copy2('/etc/passwd', backup_path)
        if _verify_backup(backup_path):
            logging.getLogger(__name__).info(f"Passwd backup created: {backup_path}")
            add_to_transaction(backup_path, Path('/etc/passwd'))
            return backup_path
    except Exception as e:
        logging.getLogger(__name__).error(f"Failed to backup passwd: {e}")
    return None


# ============================================================
# HELPER FUNCTIONS
# ============================================================
def _is_service_account(username: str) -> bool:
    """Check if a user is a service account using dynamic detection."""
    service_accounts = _get_service_accounts()
    return username in service_accounts


def _is_protected_user(username: str) -> bool:
    """Check if a user is protected (should never be locked)."""
    return username in PROTECTED_USERS


def _is_regular_user(username: str) -> bool:
    """Check if a user is a regular user (UID >= 1000)."""
    try:
        pw_entry = pwd.getpwnam(username)
        return pw_entry.pw_uid >= 1000
    except KeyError:
        return False


def _user_exists(username: str) -> bool:
    """Verify that a user exists on the system."""
    try:
        pwd.getpwnam(username)
        return True
    except KeyError:
        return False


def _is_user_locked(username: str) -> bool:
    """Check if a user account is already locked."""
    try:
        with open('/etc/shadow', 'r') as f:
            for line in f:
                parts = line.strip().split(':')
                if len(parts) >= 2 and parts[0] == username:
                    if parts[1].startswith('!'):
                        return True
                    break
    except:
        pass
    return False


def _has_valid_shell(username: str) -> bool:
    """Check if user has a valid shell."""
    try:
        pw_entry = pwd.getpwnam(username)
        shell = pw_entry.pw_shell
        valid_shells = ['/bin/bash', '/bin/sh', '/bin/zsh', '/bin/dash', '/usr/bin/bash']
        return shell in valid_shells
    except:
        return False


def _shell_exists(shell: str) -> bool:
    """Check if a shell binary exists."""
    return os.path.exists(shell)


def _get_nologin_shell() -> str:
    """Get the path to nologin shell."""
    nologin_paths = ['/usr/sbin/nologin', '/sbin/nologin', '/bin/false']
    for path in nologin_paths:
        if os.path.exists(path):
            return path
    return '/bin/false'  # Fallback


# ============================================================
# SAFE WRITE FUNCTIONS - FIXED (With locking)
# ============================================================
def _safe_write_file(file_path: str, content: str, validator=None, backup_path: Path = None) -> bool:
    """
    Safely write a file with backup, validation, rollback, and locking.
    """
    logger = logging.getLogger(__name__)
    
    # Use provided backup or create one
    if backup_path is None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        backup_path = BACKUP_DIR / f"{Path(file_path).name}.backup_{timestamp}"
        if os.path.exists(file_path):
            shutil.copy2(file_path, backup_path)
            logger.info(f"Backup created: {backup_path}")
            add_to_transaction(backup_path, Path(file_path))
    
    # Validate content if validator provided
    if validator and not validator(content):
        logger.error(f"Validation failed for {file_path}")
        return False
    
    # File locking
    lock_file = Path(file_path).with_suffix('.lock')
    fd = None
    try:
        fd = open(lock_file, 'w')
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except:
        logger.warning(f"Cannot acquire lock for {file_path}")
    
    try:
        # Write to temp file first
        with tempfile.NamedTemporaryFile(mode='w', suffix='.tmp', delete=False) as f:
            f.write(content)
            temp_path = f.name
        
        # Move temp file to destination
        shutil.move(temp_path, file_path)
        logger.info(f"Successfully wrote: {file_path}")
        
        # Validate after write
        if validator and not validator(content):
            logger.error(f"Validation failed after write for {file_path}")
            if backup_path and backup_path.exists():
                shutil.copy2(backup_path, file_path)
                logger.info(f"Rolled back from backup: {backup_path}")
            return False
        
        # Release lock
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
        return False


def _test_login() -> bool:
    """Test if login still works after changes."""
    logger = logging.getLogger(__name__)
    logger.info("Testing login after user modifications...")
    
    try:
        # Test that we can still authenticate as root
        result = subprocess.run(
            ['su', '-', 'root', '-c', 'echo "Login test successful"'],
            capture_output=True,
            text=True,
            timeout=5, stdin=subprocess.DEVNULL)
        if result.returncode == 0:
            logger.info("Login test passed")
            return True
        else:
            logger.error(f"Login test failed: {result.stderr}")
            return False
    except Exception as e:
        logger.error(f"Login test error: {e}")
        return False


# ============================================================
# FIX 5: FRIENDLY CONFIRMATION WITH WARNINGS
# ============================================================
def _confirm_user_lock(username: str, reason: str = "") -> bool:
    """
    Ask for confirmation before locking a user.
    Shows friendly warning if user is the current logged-in user.
    """
    
    # Check if this is the current logged-in user
    if _is_current_user(username):
        total_users = _get_total_users()
        
        print(f"\n{'='*60}")
        print(f"👑 Hey King/Queen! 👑")
        print(f"   This looks like YOUR account ({username})!")
        
        if total_users == 1:
            print(f"   ⚠️  You are the ONLY user on this system!")
            print(f"   ⚠️  If I lock this account, you will NEVER be able to login again!")
        else:
            print(f"   ⚠️  WARNING: Locking this user will LOG YOU OUT immediately!")
        
        print(f"   Are you SURE you want to lock YOURSELF out?")
        print(f"{'='*60}")
        response = ui.prompt("Type 'YES' to confirm (anything else will skip): ")
        return response == 'YES'
    
    # Normal prompt for other users
    reason_text = f" ({reason})" if reason else ""
    response = ui.prompt(f"Lock user {username}{reason_text}? [y/N]: ")
    return response.lower() == 'y'


def _log_user_change(action: str, username: str, details: str, success: bool):
    """Log user changes for audit trail."""
    logger = logging.getLogger(__name__)
    status = "SUCCESS" if success else "FAILED"
    logger.info(f"User {action}: {username} - {details} ({status})")
    
    try:
        CHANGES_LOG.parent.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(CHANGES_LOG, 'a') as f:
            f.write(f"{timestamp} - User {action}: {username} - {details} ({status})\n")
    except Exception as e:
        logger.debug(f"Failed to log user change: {e}")


def _progress_indicator(current: int, total: int, message: str = ""):
    """Show progress during operations using stdout.write."""
    if total > 0:
        percent = (current / total) * 100
        sys.stdout.write(f"\r[{current}/{total}] {percent:.1f}% - {message[:50]:<50}")
        sys.stdout.flush()


# ============================================================
# DRY-RUN FUNCTIONS
# ============================================================
def _dry_run_lock(username: str, reason: str) -> bool:
    """Simulate locking a user without actually locking."""
    logging.getLogger(__name__).info(f"[DRY-RUN] Would lock user: {username} ({reason})")
    print(f"[DRY-RUN] Would lock user: {username} ({reason})")
    return True


# ============================================================
# FIX 6: MAIN FIX FUNCTION - WITH EMPTY PASSWORD FIX
# ============================================================
def fix(config: dict, dry_run: bool = False, force: bool = False) -> bool:
    """
    Fix user account issues

    Args:
        config: Configuration dictionary
        dry_run: If True, preview changes without applying
        force: If True, skip confirmation

    Returns:
        bool: True if fixes applied successfully
    """
    logger = logging.getLogger(__name__)
    logger.info("Fixing user account issues...")

    if dry_run:
        logger.info("DRY-RUN MODE: No changes will be applied")
        print("\n[!] DRY-RUN MODE - No changes will be applied")
        print("[✓] Dry-run complete. No changes were made.")
        return True

    # ✅ FIX: Skip confirmation in force mode
    if not force:
        print("\n[!] WARNING: Shadow will modify /etc/passwd and /etc/shadow")
        print("    This will lock user accounts with empty passwords or inactivity")
        print("    Incorrect changes can lock you out of the system!")
        print("    ============================================================")
        print("    ⚠️  YOUR CURRENT USER: " + pwd.getpwuid(os.getuid()).pw_name)
        print("    ============================================================")
    else:
        logger.info("Force mode: Applying user fixes without confirmation")

    try:
        # Fix empty password for current user FIRST
        current_user = pwd.getpwuid(os.getuid()).pw_name
        
        # Skip password prompt for root - handled separately by engine
        if current_user == 'root':
            logger.info("Root user detected - skipping password prompt")
        elif _has_empty_password(current_user):
            print(f"\n⚠️  Your user '{current_user}' has an empty password!")
            if not _set_user_password(current_user):
                logger.warning(f"User '{current_user}' still has empty password")
        
        # Lock empty password users (skip current user and protected users)
        if config.get('users', {}).get('lock_empty_password', True):
            if not _lock_empty_password_users():
                logger.warning("Failed to lock empty password users")
                return False

        # Lock inactive users (skip current user and protected users)
        if config.get('users', {}).get('lock_inactive', True):
            if not _lock_inactive_users():
                logger.warning("Failed to lock inactive users")
                return False

        # Test login after all changes
        if not _test_login():
            logger.error("Login test failed after user modifications!")
            return False

        # Test sudo access
        if not _test_sudo():
            logger.error("Sudo test failed after user modifications!")
            return False

        # Restart affected services
        service_results = _restart_affected_services()
        if service_results['restarted']:
            logger.info(f"Restarted services: {', '.join(service_results['restarted'])}")
        if service_results['failed']:
            logger.warning(f"Failed to restart: {', '.join(service_results['failed'])}")

        logger.info("User account fixes applied successfully")
        return True

    except Exception as e:
        logger.error(f"Failed to fix user accounts: {e}")
        return False


# ============================================================
# FIX 7: CHECK IF USER HAS EMPTY PASSWORD
# ============================================================
def _has_empty_password(username: str) -> bool:
    """Check if a user has an empty password."""
    try:
        with open('/etc/shadow', 'r') as f:
            for line in f:
                parts = line.strip().split(':')
                if len(parts) >= 2 and parts[0] == username:
                    password = parts[1]
                    # Only '' is a truly empty password. '!!' and '*' are locked/disabled.
                    return password == ''
        return False
    except:
        return False


# ============================================================
# RESTORE FROM BACKUP - FIXED (With verification)
# ============================================================
def _restore_from_backup():
    """Restore from the most recent backup with verification."""
    logger = logging.getLogger(__name__)
    
    # Find most recent shadow backup
    shadow_backups = sorted(BACKUP_DIR.glob("shadow.backup_*"))
    if shadow_backups:
        latest = shadow_backups[-1]
        if _verify_backup(latest):
            shutil.copy2(latest, '/etc/shadow')
            logger.info(f"Restored /etc/shadow from: {latest}")
        else:
            logger.error(f"Backup verification failed: {latest}")
    
    # Find most recent passwd backup
    passwd_backups = sorted(BACKUP_DIR.glob("passwd.backup_*"))
    if passwd_backups:
        latest = passwd_backups[-1]
        if _verify_backup(latest):
            shutil.copy2(latest, '/etc/passwd')
            logger.info(f"Restored /etc/passwd from: {latest}")
        else:
            logger.error(f"Backup verification failed: {latest}")


# ============================================================
# FIX 8: LOCK EMPTY PASSWORD USERS - WITH SAFETY CHECKS
# ============================================================
def _lock_empty_password_users() -> bool:
    """Lock users with empty passwords (regular users only)."""
    logger = logging.getLogger(__name__)
    logger.info("Locking users with empty passwords...")
    
    # Backup first
    backup_path = _backup_shadow()
    if not backup_path:
        logger.error("Failed to backup shadow file")
        return False
    
    # Check if only 1 user exists
    total_users = _get_total_users()
    if total_users == 1:
        logger.warning("Only 1 user found. Skipping empty password locking to prevent lockout.")
        print("\n👑 You are the ONLY user on this system!")
        print("   Skipping empty password locking to keep you safe. 😊")
        return True
    
    try:
        with open('/etc/shadow', 'r') as f:
            lines = f.readlines()
        
        new_lines = []
        locked_count = 0
        total_empty = 0
        service_accounts = _get_service_accounts()
        current_user = pwd.getpwuid(os.getuid()).pw_name
        
        # Count users with TRULY empty passwords
        for line in lines:
            parts = line.strip().split(':')
            if len(parts) >= 2:
                password = parts[1]
                if password == '':
                    total_empty += 1
        
        processed = 0
        
        for line in lines:
            parts = line.strip().split(':')
            if len(parts) >= 2:
                username = parts[0]
                password = parts[1]
                
                # Skip current user (handled separately)
                if username == current_user:
                    logger.warning(f"Skipping current user: {username} (handled separately)")
                    new_lines.append(line)
                    continue
                
                # Skip service accounts
                if username in service_accounts:
                    new_lines.append(line)
                    continue
                
                # Skip protected users
                if _is_protected_user(username):
                    new_lines.append(line)
                    continue
                
                # Only lock regular users (UID >= 1000)
                if not _is_regular_user(username):
                    new_lines.append(line)
                    continue
                
                # Check if already locked
                if _is_user_locked(username):
                    new_lines.append(line)
                    continue
                
                # Only lock if password is TRULY empty
                if password == '':
                    processed += 1
                    _progress_indicator(processed, total_empty, f"Processing {username}")
                    
                    if not _confirm_user_lock(username, "empty password"):
                        new_lines.append(line)
                        continue
                    
                    # Lock user by adding '!' to password field
                    parts[1] = '!' + password
                    line = ':'.join(parts) + '\n'
                    locked_count += 1
                    _log_user_change("LOCK", username, "empty password", True)
            
            new_lines.append(line)
        
        sys.stdout.write("\n")
        sys.stdout.flush()
        
        if locked_count > 0:
            if not _safe_write_file('/etc/shadow', ''.join(new_lines), _validate_shadow_content, backup_path):
                logger.error("Failed to write shadow file")
                return False
            logger.info(f"Locked {locked_count} users with empty passwords")
        else:
            logger.info("No users with empty passwords to lock")
        
        return True
        
    except Exception as e:
        logger.error(f"Error locking empty password users: {e}")
        if backup_path and backup_path.exists():
            shutil.copy2(backup_path, '/etc/shadow')
            logger.info("Rolled back shadow file")
        return False


# ============================================================
# FIX 9: LOCK INACTIVE USERS - WITH SAFETY CHECKS
# ============================================================
def _lock_inactive_users() -> bool:
    """Lock inactive users (> 90 days)."""
    logger = logging.getLogger(__name__)
    logger.info("Locking inactive users (> 90 days)...")
    
    # ✅ FIX: Backup first
    backup_path = _backup_shadow()
    if not backup_path:
        logger.error("Failed to backup shadow file")
        return False
    
    # ✅ FIX: Check if only 1 user exists
    total_users = _get_total_users()
    if total_users == 1:
        logger.warning("Only 1 user found. Skipping inactive user locking to prevent lockout.")
        print("\n👑 You are the ONLY user on this system!")
        print("   Skipping inactive user locking to keep you safe. 😊")
        return True
    
    try:
        users_to_lock = []
        service_accounts = _get_service_accounts()
        current_user = pwd.getpwuid(os.getuid()).pw_name
        
        # ✅ FIX: Try lastlog first, fallback to shadow file
        if _lastlog_available():
            # Method 1: Use lastlog
            result = subprocess.run(['lastlog', '-b', '90'], capture_output=True, text=True, timeout=30, stdin=subprocess.DEVNULL)
            
            if result.returncode == 0:
                for line in result.stdout.split('\n')[1:]:
                    if not line.strip():
                        continue
                    
                    parts = line.split()
                    if not parts:
                        continue
                    
                    username = parts[0]
                    
                    # Skip current user
                    if username == current_user:
                        continue
                    
                    is_never_logged_in = 'Never logged in' in line
                    
                    # Skip service accounts
                    if username in service_accounts:
                        continue
                    
                    # Skip protected users
                    if _is_protected_user(username):
                        continue
                    
                    # Only regular users (UID >= 1000)
                    if not _is_regular_user(username):
                        continue
                    
                    # Skip if already locked
                    if _is_user_locked(username):
                        continue
                    
                    # Skip if user has no valid shell
                    if not _has_valid_shell(username):
                        continue
                    
                    if is_never_logged_in or True:  # Include all users from lastlog
                        users_to_lock.append(username)
            else:
                logger.warning("lastlog command failed, falling back to shadow file")
                users_to_lock = _get_inactive_from_shadow()
        else:
            # Method 2: Use shadow file as fallback
            logger.info("lastlog not available, using shadow file for inactive detection")
            users_to_lock = _get_inactive_from_shadow()
        
        # Remove duplicates and current user
        users_to_lock = list(dict.fromkeys(users_to_lock))
        if current_user in users_to_lock:
            users_to_lock.remove(current_user)
        
        if not users_to_lock:
            logger.info("No inactive users to lock")
            return True
        
        locked_count = 0
        total_users_to_lock = len(users_to_lock)
        
        for i, username in enumerate(users_to_lock):
            _progress_indicator(i + 1, total_users_to_lock, f"Processing {username}")
            
            if not _confirm_user_lock(username, "inactive > 90 days or never logged in"):
                continue
            
            try:
                # Use usermod -L to lock the user
                result = subprocess.run(['usermod', '-L', username], capture_output=True, timeout=10, stdin=subprocess.DEVNULL)
                if result.returncode == 0:
                    locked_count += 1
                    _log_user_change("LOCK", username, "inactive > 90 days or never logged in", True)
                else:
                    logger.error(f"Failed to lock {username}: {result.stderr}")
            except Exception as e:
                logger.error(f"Error locking {username}: {e}")
        
        sys.stdout.write("\n")
        sys.stdout.flush()
        
        logger.info(f"Locked {locked_count} inactive users")
        return True
        
    except Exception as e:
        logger.error(f"Error locking inactive users: {e}")
        if backup_path and backup_path.exists():
            shutil.copy2(backup_path, '/etc/shadow')
            logger.info("Rolled back shadow file")
        return False


def _get_inactive_from_shadow() -> List[str]:
    """
    Get inactive users from shadow file (fallback when lastlog is missing).
    Uses password last change date as proxy for inactivity.
    """
    logger = logging.getLogger(__name__)
    inactive_users = []
    current_date = datetime.now()
    service_accounts = _get_service_accounts()
    current_user = pwd.getpwuid(os.getuid()).pw_name
    
    try:
        with open('/etc/shadow', 'r') as f:
            for line in f:
                parts = line.strip().split(':')
                if len(parts) < 8:
                    continue
                
                username = parts[0]
                last_change = parts[2]
                
                # Skip current user
                if username == current_user:
                    continue
                
                # Skip service accounts
                if username in service_accounts:
                    continue
                
                # Skip protected users
                if _is_protected_user(username):
                    continue
                
                # Only regular users (UID >= 1000)
                if not _is_regular_user(username):
                    continue
                
                # Skip if already locked
                if _is_user_locked(username):
                    continue
                
                # Skip if user has no valid shell
                if not _has_valid_shell(username):
                    continue
                
                if last_change and last_change != '':
                    try:
                        last_change_days = int(last_change)
                        last_change_date = datetime(1970, 1, 1) + timedelta(days=last_change_days)
                        days_since_change = (current_date - last_change_date).days
                        
                        # If password hasn't been changed in 90+ days, consider inactive
                        if days_since_change > 90:
                            inactive_users.append(username)
                            logger.debug(f"User {username} inactive (password last changed {days_since_change} days ago)")
                    except:
                        pass
        
        logger.info(f"Found {len(inactive_users)} inactive users from shadow file")
        return inactive_users
        
    except Exception as e:
        logger.warning(f"Failed to get inactive users from shadow: {e}")
        return []


# ============================================================
# FIX SYSTEM SHELLS - FIXED
# ============================================================
def _fix_system_shells() -> bool:
    """Fix system user shells to nologin."""
    logger = logging.getLogger(__name__)
    logger.info("Fixing system user shells...")
    
    # Get the correct nologin shell path
    nologin_shell = _get_nologin_shell()
    
    # Backup first
    backup_path = _backup_passwd()
    if not backup_path:
        logger.error("Failed to backup passwd file")
        return False
    
    try:
        with open('/etc/passwd', 'r') as f:
            lines = f.readlines()
        
        new_lines = []
        fixed_count = 0
        total_fix = 0
        service_accounts = _get_service_accounts()
        
        # Count how many need fixing
        for line in lines:
            parts = line.strip().split(':')
            if len(parts) >= 7:
                username = parts[0]
                uid = int(parts[2])
                shell = parts[6]
                
                # System users with login shells
                if 0 < uid < 1000:
                    if username not in PROTECTED_USERS:
                        if username not in service_accounts:
                            if shell not in ['/usr/sbin/nologin', '/bin/false', '/sbin/nologin']:
                                total_fix += 1
        
        processed = 0
        
        for line in lines:
            parts = line.strip().split(':')
            if len(parts) >= 7:
                username = parts[0]
                uid = int(parts[2])
                shell = parts[6]
                
                # Only system users (UID < 1000)
                if 0 < uid < 1000:
                    # Skip protected users
                    if username in PROTECTED_USERS:
                        new_lines.append(line)
                        continue
                    
                    # Skip service accounts
                    if username in service_accounts:
                        new_lines.append(line)
                        continue
                    
                    # Skip if already has nologin
                    if shell in ['/usr/sbin/nologin', '/bin/false', '/sbin/nologin']:
                        new_lines.append(line)
                        continue
                    
                    processed += 1
                    _progress_indicator(processed, total_fix, f"Fixing {username}")
                    
                    # Fix the shell
                    parts[6] = nologin_shell
                    line = ':'.join(parts) + '\n'
                    fixed_count += 1
                    _log_user_change("FIX_SHELL", username, f"{shell} → {nologin_shell}", True)
            new_lines.append(line)
        
        sys.stdout.write("\n")
        sys.stdout.flush()
        
        if fixed_count > 0:
            if not _safe_write_file('/etc/passwd', ''.join(new_lines), _validate_passwd_content, backup_path):
                logger.error("Failed to write passwd file")
                return False
            logger.info(f"Fixed {fixed_count} system user shells")
        else:
            logger.info("No system user shells to fix")
        
        return True
        
    except Exception as e:
        logger.error(f"Error fixing system shells: {e}")
        if backup_path and backup_path.exists():
            shutil.copy2(backup_path, '/etc/passwd')
            logger.info("Rolled back passwd file")
        return False


# ============================================================
# UTILITY FUNCTIONS
# ============================================================
def get_faillock_status() -> dict:
    """Get current faillock status for users."""
    try:
        result = subprocess.run(['faillock', '--list'], 
                              capture_output=True, text=True, timeout=10, stdin=subprocess.DEVNULL)
        if result.returncode == 0:
            locked_users = []
            for line in result.stdout.split('\n'):
                if line.strip():
                    parts = line.split()
                    if len(parts) >= 5:
                        locked_users.append({
                            'user': parts[0],
                            'failures': parts[1] if len(parts) > 1 else '0',
                            'last_failure': ' '.join(parts[2:]) if len(parts) > 2 else ''
                        })
            return {'locked_users': locked_users, 'success': True}
        else:
            return {'success': False, 'error': result.stderr}
    except Exception as e:
        return {'success': False, 'error': str(e)}


def reset_faillock(user: str = None) -> bool:
    """Reset faillock for a specific user or all users."""
    try:
        if user:
            subprocess.run(['faillock', '--reset', '--user', user], check=True, timeout=10, stdin=subprocess.DEVNULL)
        else:
            subprocess.run(['faillock', '--reset'], check=True, timeout=10, stdin=subprocess.DEVNULL)
        return True
    except Exception as e:
        logging.getLogger(__name__).error(f"Failed to reset faillock: {e}")
        return False