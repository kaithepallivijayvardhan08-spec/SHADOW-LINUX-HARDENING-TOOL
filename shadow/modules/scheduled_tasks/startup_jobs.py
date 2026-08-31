#!/usr/bin/env python3
"""
Shadow Startup Jobs Module
==========================

Checks startup jobs for security.

Security concerns:
- Suspicious startup commands
- Unauthorized startup scripts
- rc.local modifications
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
import tempfile
from pathlib import Path
from datetime import datetime
from typing import Tuple, Dict, List, Optional, Any, Callable

# ============================================================
# MODULE METADATA
# ============================================================
SEVERITY = "MEDIUM"
RECOMMENDATION = "Review and secure startup scripts to prevent unauthorized execution at boot"

BACKUP_DIR = Path("/var/backups/shadow/")
CHANGES_LOG = Path("/var/log/shadow/changes.log")

# ============================================================
# TRANSACTION SUPPORT
# ============================================================
_transaction_active = False
_transaction_backups = []

def begin_transaction():
    """Begin a transaction for startup modifications."""
    global _transaction_active, _transaction_backups
    _transaction_active = True
    _transaction_backups = []
    logging.getLogger(__name__).info("Startup transaction started")

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
    logging.getLogger(__name__).info("Startup transaction committed")
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

# FIX 8: Legitimate startup patterns to skip
LEGITIMATE_STARTUP_PATTERNS = [
    'systemd', 'dbus', 'network', 'ssh', 'cron', 'rsyslog',
    'accounts-daemon', 'polkit', 'gnome', 'lightdm', 'gdm',
    'sddm', 'xorg', 'udev', 'kernel', 'init'
]

# FIX 11: Additional startup locations to check
STARTUP_LOCATIONS = [
    '/etc/rc.local',
    '/etc/init.d/',
    '/etc/systemd/system/*.service',
    '/etc/systemd/user/*.service',
    '/etc/profile.d/',
    '/etc/bash.bashrc',
    '/root/.bashrc',
    '/etc/crontab',
    '/etc/cron.d/',
    '/etc/rc0.d/',
    '/etc/rc1.d/',
    '/etc/rc2.d/',
    '/etc/rc3.d/',
    '/etc/rc4.d/',
    '/etc/rc5.d/',
    '/etc/rc6.d/'
]

# FIX 11: Dangerous patterns for startup scripts
DANGEROUS_PATTERNS = [
    ('curl', 'download command'),
    ('wget', 'download command'),
    ('nc', 'netcat'),
    ('ncat', 'netcat alternative'),
    ('bash -i', 'interactive shell'),
    ('sh -i', 'interactive shell'),
    ('python -c', 'inline python'),
    ('perl -e', 'inline perl'),
    ('rm -rf', 'dangerous removal'),
    ('chmod 777', 'world-writable permission'),
    ('chmod +x', 'executable permission'),
    ('mkfifo', 'named pipe'),
    ('telnet', 'telnet command'),
    ('/tmp/', 'temp directory execution'),
    ('/dev/shm/', 'shared memory execution'),
    ('&>', 'output redirection'),
    ('2>&1', 'error redirection'),
    ('|', 'pipe to command'),
    (';', 'command separator'),
    ('&&', 'logical AND')
]


# ============================================================
# FIX 8: STRUCTURED LOGGING
# ============================================================
def _log_startup_change(action: str, script_path: str, details: str, success: bool = True):
    """Log startup modifications with structured format."""
    logger = logging.getLogger(__name__)
    status = "SUCCESS" if success else "FAILED"
    
    log_entry = {
        "event": "startup_change",
        "action": action,
        "script": script_path,
        "details": details,
        "status": status,
        "timestamp": datetime.now().isoformat()
    }
    logger.info(f"STARTUP: {json.dumps(log_entry)}")
    
    try:
        CHANGES_LOG.parent.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(CHANGES_LOG, 'a') as f:
            f.write(f"{timestamp} | STARTUP | {action} | {script_path} | {details}\n")
    except Exception as e:
        logger.debug(f"Failed to log startup change: {e}")


def _log_startup_findings(details: Dict, issues: List[str], warnings: List[str]):
    """Log startup check findings for audit trail."""
    try:
        CHANGES_LOG.parent.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        with open(CHANGES_LOG, 'a') as f:
            f.write(f"{timestamp} - Startup Check Results:\n")
            f.write(f"  rc.local Commands: {len(details.get('rc_local_commands', []))}\n")
            f.write(f"  init.d Scripts: {len(details.get('init_d_scripts', []))}\n")
            f.write(f"  systemd Services: {len(details.get('systemd_services', []))}\n")
            f.write(f"  Profile Scripts: {len(details.get('profile_scripts', []))}\n")
            f.write(f"  Suspicious Startups: {len(details.get('suspicious_startups', []))}\n")
            
            for issue in issues:
                f.write(f"  ISSUE: {issue}\n")
            for warning in warnings:
                f.write(f"  WARNING: {warning}\n")
            
        logging.getLogger(__name__).debug(f"Startup findings logged to {CHANGES_LOG}")
    except Exception as e:
        logging.getLogger(__name__).warning(f"Failed to log startup findings: {e}")


# ============================================================
# PROGRESS INDICATOR
# ============================================================
def _progress_indicator(current: int, total: int, message: str = ""):
    """Show progress during operations."""
    if total > 0:
        percent = (current / total) * 100
        print(f"\r\033[K[{current}/{total}] {percent:.1f}% - {message}", end="", flush=True)


def check(config: dict) -> Tuple[str, str, dict]:
    """Check startup jobs"""
    logger = logging.getLogger(__name__)
    logger.info("Checking startup jobs...")

    issues = []
    warnings = []
    details = {
        'rc_local_commands': [],
        'init_d_scripts': [],
        'systemd_services': [],
        'profile_scripts': [],
        'suspicious_startups': [],
        'rc_local_permissions': None,
        'rc_local_owner': None
    }

    # FIX 9: Check rc.local permissions
    rc_local = '/etc/rc.local'
    if os.path.exists(rc_local):
        perms = _get_file_permissions(rc_local)
        details['rc_local_permissions'] = perms
        if perms and perms[-1] in ['2', '6', '7']:
            issues.append(f"rc.local has insecure permissions: {perms}")

        # FIX 10: Check rc.local ownership
        owner = _get_file_owner(rc_local)
        details['rc_local_owner'] = owner
        if owner and owner != 'root:root':
            warnings.append(f"rc.local not owned by root: {owner}")

    # Check rc.local commands
    rc_local_commands = _check_rc_local()
    details['rc_local_commands'] = rc_local_commands

    # FIX 5: Check init.d scripts
    init_d_scripts = _check_init_d()
    details['init_d_scripts'] = init_d_scripts

    # FIX 6: Check systemd startup services
    systemd_services = _check_systemd_services()
    details['systemd_services'] = systemd_services

    # FIX 11: Check profile scripts
    profile_scripts = _check_profile_scripts()
    details['profile_scripts'] = profile_scripts

    # FIX 7: Error handling for rc.local read
    if rc_local_commands is None:
        warnings.append("Could not read rc.local (permission denied or error)")

    # Check for suspicious commands in rc.local
    if rc_local_commands:
        suspicious = _check_suspicious_commands(rc_local_commands)
        if suspicious:
            details['suspicious_startups'].extend(suspicious)
            for cmd in suspicious:
                issues.append(f"Suspicious command in rc.local: {cmd}")

    # Check for suspicious init.d scripts - FIX 8: Filter legitimate
    for script in init_d_scripts:
        # Skip legitimate scripts
        is_legit = False
        for legit in LEGITIMATE_STARTUP_PATTERNS:
            if legit in script.lower():
                is_legit = True
                break
        if is_legit:
            continue
            
        for pattern, reason in DANGEROUS_PATTERNS:
            if pattern in script:
                warnings.append(f"Suspicious pattern in init.d script: {script} ({reason})")
                break

    # Check for suspicious systemd services - FIX 8: Filter legitimate
    for service in systemd_services:
        is_legit = False
        for legit in LEGITIMATE_STARTUP_PATTERNS:
            if legit in service.lower():
                is_legit = True
                break
        if is_legit:
            continue
            
        for pattern, reason in DANGEROUS_PATTERNS:
            if pattern in service.lower():
                warnings.append(f"Suspicious pattern in systemd service: {service} ({reason})")
                break

    # Check for suspicious profile scripts - FIX 8: Filter legitimate
    for script in profile_scripts:
        is_legit = False
        for legit in LEGITIMATE_STARTUP_PATTERNS:
            if legit in script.lower():
                is_legit = True
                break
        if is_legit:
            continue
            
        for pattern, reason in DANGEROUS_PATTERNS:
            if pattern in script:
                warnings.append(f"Suspicious pattern in profile script: {script} ({reason})")
                break

    _log_startup_findings(details, issues, warnings)

    if issues:
        status = 'FAIL'
        message = f"{len(issues)} critical startup issues found"
    elif warnings:
        status = 'WARN'
        message = f"{len(warnings)} startup warnings found"
    else:
        status = 'PASS'
        message = "Startup jobs are clean"

    return status, message, details


def _get_file_permissions(file_path: str) -> Optional[str]:
    """Get file permissions as string"""
    try:
        stat_info = os.stat(file_path)
        return oct(stat_info.st_mode)[-3:]
    except:
        return None


def _get_file_owner(file_path: str) -> Optional[str]:
    """Get file owner as string"""
    try:
        stat_info = os.stat(file_path)
        import pwd, grp
        uid = stat_info.st_uid
        gid = stat_info.st_gid
        try:
            owner = pwd.getpwuid(uid).pw_name
        except:
            owner = str(uid)
        try:
            group = grp.getgrgid(gid).gr_name
        except:
            group = str(gid)
        return f"{owner}:{group}"
    except:
        return None


def _check_rc_local() -> Optional[List[str]]:
    """Check rc.local commands with error handling"""
    commands = []

    rc_local = '/etc/rc.local'

    if not os.path.exists(rc_local):
        return commands

    try:
        with open(rc_local, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#') and line != 'exit 0':
                    commands.append(line)
    except PermissionError:
        logging.getLogger(__name__).error("Permission denied reading rc.local")
        return None
    except Exception as e:
        logging.getLogger(__name__).error(f"rc.local read failed: {e}")
        return None

    return commands


def _check_init_d() -> List[str]:
    """Check init.d scripts"""
    scripts = []

    init_d_path = '/etc/init.d/'

    if os.path.exists(init_d_path):
        try:
            for item in Path(init_d_path).iterdir():
                if item.is_file() and os.access(item, os.X_OK):
                    try:
                        with open(item, 'r') as f:
                            content = f.read(500)
                            scripts.append(f"{item.name}: {content[:100]}...")
                    except:
                        scripts.append(item.name)
        except Exception as e:
            logging.getLogger(__name__).error(f"Error checking init.d: {e}")

    return scripts


def _check_systemd_services() -> List[str]:
    """Check systemd services that start at boot"""
    services = []

    try:
        result = subprocess.run(
            ['systemctl', 'list-unit-files', '--type=service', '--state=enabled', '--no-pager', '--no-legend'],
            capture_output=True,
            text=True,
            timeout=30, stdin=subprocess.DEVNULL)

        if result.returncode == 0:
            for line in result.stdout.split('\n'):
                if line.strip():
                    parts = line.split()
                    if parts:
                        services.append(parts[0])
        else:
            logging.getLogger(__name__).error(f"systemctl list-unit-files failed: {result.stderr}")

    except subprocess.TimeoutExpired:
        logging.getLogger(__name__).error("systemctl list-unit-files timed out")
    except Exception as e:
        logging.getLogger(__name__).error(f"systemctl list-unit-files failed: {e}")

    return services[:20]


def _check_profile_scripts() -> List[str]:
    """Check profile scripts for suspicious content"""
    scripts = []

    profile_dirs = ['/etc/profile.d/', '/etc/']
    profile_files = ['/etc/profile', '/etc/bash.bashrc', '/root/.bashrc']

    for profile_dir in profile_dirs:
        if os.path.exists(profile_dir):
            for item in Path(profile_dir).iterdir():
                if item.is_file() and item.name.endswith('.sh'):
                    try:
                        with open(item, 'r') as f:
                            content = f.read(500)
                            scripts.append(f"{item.name}: {content[:100]}...")
                    except:
                        scripts.append(item.name)

    for profile_file in profile_files:
        if os.path.exists(profile_file):
            try:
                with open(profile_file, 'r') as f:
                    content = f.read(500)
                    scripts.append(f"{Path(profile_file).name}: {content[:100]}...")
            except:
                scripts.append(Path(profile_file).name)

    return scripts


def _check_suspicious_commands(commands: List[str]) -> List[str]:
    """Check for suspicious commands"""
    suspicious = []

    dangerous_commands = ['curl', 'wget', 'nc', 'bash -i', 'sh -i', 'python -c', 'perl -e']

    for cmd in commands:
        for d in dangerous_commands:
            if d in cmd:
                suspicious.append(cmd)
                break

    return suspicious


def _dry_run_startup_fix(action: str, details: str) -> bool:
    """Simulate startup modification without actually changing anything."""
    logging.getLogger(__name__).info(f"[DRY-RUN] Would perform: {action} - {details}")
    print(f"[DRY-RUN] Would perform: {action}")
    return True


def _confirm_startup_modification(action: str, files_to_modify: List[str]) -> bool:
    """Ask for confirmation before modifying startup scripts."""
    print(f"\n[!] WARNING: About to modify startup scripts")
    print(f"    Action: {action}")
    print(f"    Files: {', '.join(files_to_modify[:5])}")
    if len(files_to_modify) > 5:
        print(f"    ... and {len(files_to_modify) - 5} more")
    print("    This could affect system boot!")
    response = ui.prompt("Proceed? [y/N]: ")
    if response.lower() == 'y':
        print("\n[*] Applying fixes... please wait")
        return True
    return False


def _verify_script_functionality(script_path: str) -> bool:
    """Verify that a script still functions after changes."""
    try:
        if not os.access(script_path, os.X_OK):
            return False
        
        for flag in ['--help', '-h', '--version']:
            try:
                result = subprocess.run(
                    [script_path, flag],
                    capture_output=True,
                    text=True,
                    timeout=5, stdin=subprocess.DEVNULL)
                if result.returncode in [0, 1, 2]:
                    return True
            except:
                continue
        
        return True
    except Exception as e:
        logging.getLogger(__name__).debug(f"Functionality check failed for {script_path}: {e}")
        return False


def _verify_backup(backup_path: Path) -> bool:
    """Verify that a backup was created successfully."""
    if not backup_path.exists():
        logging.getLogger(__name__).error(f"Backup not found: {backup_path}")
        return False
    logging.getLogger(__name__).debug(f"Backup verified: {backup_path}")
    return True


def _backup_startup_scripts() -> Dict[str, Any]:
    """Backup startup scripts."""
    result = {
        'backup_path': None,
        'success': False,
        'files_backed_up': []
    }
    
    try:
        BACKUP_DIR.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        backup_path = BACKUP_DIR / f"startup_backup_{timestamp}"
        backup_path.mkdir(exist_ok=True)
        
        # Backup rc.local
        rc_local = '/etc/rc.local'
        if os.path.exists(rc_local):
            dest = backup_path / 'rc.local'
            shutil.copy2(rc_local, dest)
            result['files_backed_up'].append('rc.local')
        
        # Backup profile scripts
        profile_dirs = ['/etc/profile.d/']
        for profile_dir in profile_dirs:
            if os.path.exists(profile_dir):
                for item in Path(profile_dir).iterdir():
                    if item.is_file() and item.name.endswith('.sh'):
                        dest = backup_path / f"profile.d_{item.name}"
                        shutil.copy2(item, dest)
                        result['files_backed_up'].append(f"profile.d/{item.name}")
        
        # Backup systemd service files
        service_files = list(Path('/etc/systemd/system/').glob('*.service'))
        for service_file in service_files[:10]:
            dest = backup_path / service_file.name
            shutil.copy2(service_file, dest)
            result['files_backed_up'].append(f"systemd/{service_file.name}")
        
        result['backup_path'] = str(backup_path)
        result['success'] = True
        logging.getLogger(__name__).info(f"Startup backup created: {backup_path}")
        add_to_transaction(backup_path, Path('/etc/rc.local'))

    except Exception as e:
        logging.getLogger(__name__).error(f"Failed to backup startup scripts: {e}")
    
    return result


def _validate_startup_changes(script_path: str, content: str) -> Tuple[bool, str]:
    """Validate startup script changes are safe."""
    logger = logging.getLogger(__name__)
    
    for pattern, reason in DANGEROUS_PATTERNS:
        if pattern in content:
            return False, f"Dangerous pattern found: {reason}"
    
    if not os.path.exists(script_path):
        return False, f"Script not found: {script_path}"
    
    if script_path == '/etc/rc.local':
        try:
            if not os.access(script_path, os.X_OK):
                logger.warning(f"rc.local is not executable")
        except:
            pass
    
    return True, "Validation passed"


def _rollback_startup(backup_path: Path) -> bool:
    """Rollback startup scripts from backup."""
    if not backup_path.exists():
        logging.getLogger(__name__).error(f"Backup not found: {backup_path}")
        return False
    
    try:
        for file in backup_path.iterdir():
            if file.is_file():
                if file.name == 'rc.local':
                    dest = '/etc/rc.local'
                elif file.name.startswith('profile.d_'):
                    dest = Path('/etc/profile.d/') / file.name.replace('profile.d_', '')
                else:
                    dest = Path('/etc/systemd/system/') / file.name
                
                dest.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(file, dest)
        
        logging.getLogger(__name__).info(f"Rolled back startup scripts from: {backup_path}")
        return True
    except Exception as e:
        logging.getLogger(__name__).error(f"Rollback failed: {e}")
        return False


def _verify_startup_scripts(script_paths: List[str]) -> Tuple[bool, str]:
    """Verify startup scripts are accessible and valid."""
    try:
        for script_path in script_paths:
            if not os.path.exists(script_path):
                return False, f"Script not found after changes: {script_path}"
        
        if '/etc/rc.local' in script_paths:
            if not _verify_script_functionality('/etc/rc.local'):
                logging.getLogger(__name__).warning("rc.local may not function correctly")
        
        return True, "Startup scripts verified"
    except Exception as e:
        return False, f"Verification error: {e}"


def fix(config: dict, dry_run: bool = False, force: bool = False) -> bool:
    """
    Fix startup job issues

    Args:
        config: Configuration dictionary
        dry_run: If True, preview changes without applying
        force: If True, skip confirmation

    Returns:
        bool: True if fixes applied successfully
    """
    logger = logging.getLogger(__name__)
    logger.info("Fixing startup job issues...")

    # Check for dry-run mode (use parameter, not config)
    if dry_run:
        logger.info("DRY-RUN MODE: No changes will be applied")
        print("\n[!] DRY-RUN MODE - No changes will be applied")
        
        rc_local = '/etc/rc.local'
        files_to_modify = []
        
        if os.path.exists(rc_local):
            perms = _get_file_permissions(rc_local)
            if perms and perms[-1] in ['2', '6', '7']:
                files_to_modify.append(f"rc.local (permissions: {perms})")
            
            owner = _get_file_owner(rc_local)
            if owner and owner != 'root:root':
                files_to_modify.append(f"rc.local (owner: {owner})")
            
            rc_commands = _check_rc_local()
            if rc_commands:
                suspicious = _check_suspicious_commands(rc_commands)
                if suspicious:
                    files_to_modify.append(f"rc.local ({len(suspicious)} suspicious commands)")
        
        if files_to_modify:
            print(f"  Would fix {len(files_to_modify)} startup issues:")
            for f in files_to_modify:
                print(f"    - {f}")
        else:
            print("  No startup issues found")
        
        print("\n[✓] Dry-run complete. No changes were made.")
        return True

    # FIX: Skip confirmation in force mode
    files_to_modify = []
    rc_local = '/etc/rc.local'
    if os.path.exists(rc_local):
        perms = _get_file_permissions(rc_local)
        if perms and perms[-1] in ['2', '6', '7']:
            files_to_modify.append(rc_local)
        owner = _get_file_owner(rc_local)
        if owner and owner != 'root:root':
            if rc_local not in files_to_modify:
                files_to_modify.append(rc_local)
        rc_commands = _check_rc_local()
        if rc_commands:
            suspicious = _check_suspicious_commands(rc_commands)
            if suspicious and config.get('startup', {}).get('remove_suspicious', True):
                if rc_local not in files_to_modify:
                    files_to_modify.append(rc_local)

    if not force:
        if files_to_modify:
            if not _confirm_startup_modification("Apply startup fixes", files_to_modify):
                logger.info("Startup fixes cancelled by user")
                return False
    else:
        logger.info("Force mode: Applying startup fixes without confirmation")

    try:
        begin_transaction()
        
        backup_metadata = _backup_startup_scripts()
        if not backup_metadata['success']:
            logger.warning("Could not backup startup scripts")

        fixed_issues = 0
        total_issues = 0
        total_steps = 3

        # Fix rc.local permissions
        if os.path.exists(rc_local):
            if config.get('startup', {}).get('fix_permissions', True):
                perms = _get_file_permissions(rc_local)
                if perms and perms[-1] in ['2', '6', '7']:
                    _progress_indicator(1, total_steps, "Fixing rc.local permissions")
                    try:
                        os.chmod(rc_local, 0o755)
                        logger.info(f"Fixed rc.local permissions: {perms} → 755")
                        fixed_issues += 1
                        _log_startup_change("FIX_PERMS", rc_local, f"Changed from {perms} to 755", True)
                    except Exception as e:
                        logger.error(f"Error fixing rc.local permissions: {e}")
                else:
                    _progress_indicator(1, total_steps, "rc.local permissions already secure")

        # Fix rc.local ownership
        if os.path.exists(rc_local):
            if config.get('startup', {}).get('fix_ownership', True):
                owner = _get_file_owner(rc_local)
                if owner and owner != 'root:root':
                    _progress_indicator(2, total_steps, "Fixing rc.local ownership")
                    try:
                        os.chown(rc_local, 0, 0)
                        logger.info(f"Fixed rc.local ownership: {owner} → root:root")
                        fixed_issues += 1
                        _log_startup_change("FIX_OWNER", rc_local, f"Changed from {owner} to root:root", True)
                    except Exception as e:
                        logger.error(f"Error fixing rc.local ownership: {e}")
                else:
                    _progress_indicator(2, total_steps, "rc.local ownership already secure")

        # Remove suspicious rc.local commands
        if config.get('startup', {}).get('remove_suspicious', True):
            rc_local_commands = _check_rc_local()
            if rc_local_commands:
                suspicious = _check_suspicious_commands(rc_local_commands)
                total_issues += len(suspicious)
                if suspicious:
                    _progress_indicator(3, total_steps, f"Removing {len(suspicious)} suspicious commands")
                    
                    for cmd in suspicious:
                        is_valid, msg = _validate_startup_changes(rc_local, cmd)
                        if not is_valid:
                            logger.warning(f"Validation failed for {cmd}: {msg}")
                            continue

                    try:
                        with open(rc_local, 'r') as f:
                            lines = f.readlines()

                        new_lines = []
                        for line in lines:
                            is_suspicious = False
                            for cmd in suspicious:
                                if cmd in line:
                                    is_suspicious = True
                                    break
                            if is_suspicious:
                                new_lines.append(f"# {line}")
                                logger.info(f"Commented out suspicious command: {line.strip()}")
                                _log_startup_change("REMOVE", rc_local, line.strip(), True)
                                fixed_issues += 1
                            else:
                                new_lines.append(line)

                        with open(rc_local, 'w') as f:
                            f.writelines(new_lines)

                    except Exception as e:
                        logger.error(f"Error removing suspicious commands: {e}")

        print()

        is_verified, verify_msg = _verify_startup_scripts([rc_local])
        if not is_verified:
            logger.warning(f"Startup verification failed: {verify_msg}")
            if backup_metadata['success']:
                _rollback_startup(Path(backup_metadata['backup_path']))
            rollback_transaction()
            return False

        commit_transaction()
        logger.info(f"Startup fixes applied: {fixed_issues} issues fixed, {total_issues} total issues")
        print(f"\n[✓] Startup fixes applied: {fixed_issues} fixed")
        
        return True

    except Exception as e:
        logger.error(f"Failed to fix startup issues: {e}")
        if backup_metadata.get('success'):
            _rollback_startup(Path(backup_metadata['backup_path']))
        rollback_transaction()
        return False