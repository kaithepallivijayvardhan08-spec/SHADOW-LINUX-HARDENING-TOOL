#!/usr/bin/env python3
"""
Shadow Encryption Module
========================

Checks disk encryption status:
- Full disk encryption (LUKS)
- Home directory encryption
- Swap encryption
- Encrypted file systems
- Encryption key management
- Encryption algorithms

Files checked:
- /etc/crypttab
- /etc/fstab
- /etc/lvm/lvm.conf
- /home/.ecryptfs
- /var/log/cryptsetup*

Security concerns:
- Unencrypted system disk → data exposure
- Unencrypted home directory → user data exposure
- Unencrypted swap → memory data exposure
- Weak encryption → cryptographic vulnerabilities
- Unmanaged keys → key exposure
"""

from shadow.core import ui
import os
import re
import logging
import shutil
import subprocess
import time
import json
from pathlib import Path
from datetime import datetime
from typing import Tuple, Dict, List, Optional

# ============================================================
# MODULE METADATA
# ============================================================
SEVERITY = "MEDIUM"
RECOMMENDATION = "Enable encryption for sensitive data and monitor disk usage"

BACKUP_DIR = Path("/var/backups/shadow/")
CHANGES_LOG = Path("/var/log/shadow/changes.log")

# ============================================================
# TRANSACTION SUPPORT
# ============================================================
_transaction_active = False
_transaction_backups = []

def begin_transaction():
    """Begin a transaction for encryption modifications."""
    global _transaction_active, _transaction_backups
    _transaction_active = True
    _transaction_backups = []
    logging.getLogger(__name__).info("Encryption transaction started")

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
    logging.getLogger(__name__).info("Encryption transaction committed")
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
# FIX 8: STRUCTURED LOGGING
# ============================================================
def _log_encryption_check(status: str, message: str, details: Dict):
    """Log encryption check results with structured format."""
    logger = logging.getLogger(__name__)
    
    log_entry = {
        "event": "encryption_check",
        "status": status,
        "message": message,
        "details": {
            "root_encrypted": details.get('root_encrypted', False),
            "home_encrypted": details.get('home_encrypted', False),
            "swap_encrypted": details.get('swap_encrypted', False),
            "luks_version": details.get('luks_version', 'unknown'),
            "encrypted_partitions": len(details.get('encrypted_partitions', [])),
            "crypttab_entries": len(details.get('crypttab_entries', [])),
            "ecryptfs_present": details.get('ecryptfs_present', False)
        },
        "timestamp": datetime.now().isoformat()
    }
    logger.info(f"ENCRYPTION: {json.dumps(log_entry)}")
    
    try:
        CHANGES_LOG.parent.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        with open(CHANGES_LOG, 'a') as f:
            f.write(f"{timestamp} - Encryption Check: {status} - {message}\n")
            f.write(f"  Root encrypted: {details.get('root_encrypted', False)}\n")
            f.write(f"  Home encrypted: {details.get('home_encrypted', False)}\n")
            f.write(f"  Swap encrypted: {details.get('swap_encrypted', False)}\n")
            f.write(f"  LUKS version: {details.get('luks_version', 'unknown')}\n")
            f.write(f"  Encrypted partitions: {len(details.get('encrypted_partitions', []))}\n")
            
        logger.debug(f"Encryption check logged to {CHANGES_LOG}")
    except Exception as e:
        logger.warning(f"Failed to log encryption check: {e}")


def _log_encryption_warning(message: str):
    """Log encryption warnings for audit trail."""
    try:
        CHANGES_LOG.parent.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(CHANGES_LOG, 'a') as f:
            f.write(f"{timestamp} - Encryption Warning: {message}\n")
    except Exception as e:
        logging.getLogger(__name__).debug(f"Failed to log encryption warning: {e}")


# ============================================================
# CHECK FUNCTION
# ============================================================
def check(config: dict) -> Tuple[str, str, dict]:
    """
    Check disk encryption status

    Returns:
        Tuple[str, str, dict]: (status, message, details)
    """
    logger = logging.getLogger(__name__)
    logger.info("Checking disk encryption...")

    issues = []
    warnings = []
    details = {
        'root_encrypted': False,
        'swap_encrypted': False,
        'home_encrypted': False,
        'encrypted_partitions': [],
        'encrypted_filesystems': [],
        'encryption_algorithms': [],
        'crypttab_entries': [],
        'ecryptfs_present': False,
        'luks_version': None,
        'cryptsetup_installed': False
    }

    # Check if cryptsetup is installed
    cryptsetup_installed = _check_cryptsetup()
    details['cryptsetup_installed'] = cryptsetup_installed
    
    if not cryptsetup_installed:
        warnings.append("cryptsetup is not installed (disk encryption not available)")
        _log_encryption_check('WARN', 'cryptsetup not installed', details)
        return 'WARN', "cryptsetup is not installed (disk encryption not available)", details

    # Check LUKS version
    luks_version = _check_luks_version()
    details['luks_version'] = luks_version

    if luks_version:
        logger.info(f"LUKS version: {luks_version}")
    else:
        warnings.append("Could not determine LUKS version")

    # Check for encrypted partitions (LUKS)
    encrypted_partitions = _check_luks_partitions()
    details['encrypted_partitions'] = encrypted_partitions

    if encrypted_partitions:
        for partition in encrypted_partitions:
            mountpoint = partition.get('mountpoint', '')
            if mountpoint == '/':
                details['root_encrypted'] = True
            elif mountpoint == '/home':
                details['home_encrypted'] = True
            # Check if it's swap
            if partition.get('name', '').startswith('swap'):
                details['swap_encrypted'] = True
    else:
        warnings.append("No LUKS encrypted partitions found")

    # Check /etc/crypttab
    crypttab_entries = _check_crypttab()
    details['crypttab_entries'] = crypttab_entries

    if crypttab_entries:
        for entry in crypttab_entries:
            if entry.get('device'):
                logger.info(f"crypttab entry: {entry['name']} -> {entry['device']}")
            # Check for swap in crypttab
            if 'swap' in entry.get('name', '').lower():
                details['swap_encrypted'] = True
    else:
        warnings.append("No entries found in /etc/crypttab")

    # Check for encrypted filesystems (ecryptfs)
    ecryptfs_present = _check_ecryptfs()
    details['ecryptfs_present'] = ecryptfs_present

    if ecryptfs_present:
        details['home_encrypted'] = True
        logger.info("eCryptfs found (home directory encryption)")

    # Check encryption algorithms in use
    algorithms = _check_encryption_algorithms()
    details['encryption_algorithms'] = algorithms

    if algorithms:
        weak_algorithms = ['aes-cbc', 'aes128-cbc', 'aes256-cbc', 'des', '3des']
        for algo in algorithms:
            if any(weak in algo.lower() for weak in weak_algorithms):
                warnings.append(f"Weak encryption algorithm: {algo}")
    else:
        warnings.append("No encryption algorithms identified")

    # Check for encrypted swap
    swap_encrypted = _check_swap_encryption()
    details['swap_encrypted'] = swap_encrypted

    if not swap_encrypted:
        warnings.append("Swap partition does not appear to be encrypted")

    # Check for LUKS key management (FIX 4)
    if encrypted_partitions:
        key_issues = _check_luks_key_management()
        if key_issues:
            for issue in key_issues:
                warnings.append(issue)

    # Determine status
    if issues:
        status = 'FAIL'
        message = f"{len(issues)} critical encryption issues found"
    elif warnings:
        status = 'WARN'
        message = f"{len(warnings)} encryption warnings found"
    else:
        status = 'PASS'
        message = "Disk encryption is properly configured"

    _log_encryption_check(status, message, details)

    return status, message, details


def _check_cryptsetup() -> bool:
    """Check if cryptsetup is installed"""
    try:
        result = subprocess.run(['which', 'cryptsetup'], capture_output=True, text=True, timeout=5, stdin=subprocess.DEVNULL)
        if result.returncode == 0:
            return True
    except:
        pass

    cryptsetup_paths = [
        '/usr/sbin/cryptsetup',
        '/usr/bin/cryptsetup',
        '/sbin/cryptsetup'
    ]

    for path in cryptsetup_paths:
        if os.path.exists(path):
            return True

    return False


def _check_luks_version() -> Optional[str]:
    """Check LUKS version"""
    try:
        result = subprocess.run(['cryptsetup', '--version'], capture_output=True, text=True, timeout=5, stdin=subprocess.DEVNULL)
        for line in result.stderr.split('\n'):
            if 'LUKS' in line:
                match = re.search(r'LUKS (\d+)', line)
                if match:
                    return match.group(1)
    except subprocess.TimeoutExpired:
        logging.getLogger(__name__).debug("cryptsetup --version timed out")
    except Exception as e:
        logging.getLogger(__name__).debug(f"Error checking LUKS version: {e}")
    return None


def _check_luks_partitions() -> List[Dict]:
    """Check LUKS encrypted partitions"""
    partitions = []

    try:
        # Check using lsblk to find LUKS partitions
        result = subprocess.run(['lsblk', '-l', '-o', 'NAME,TYPE,FSTYPE,MOUNTPOINT,LABEL'],
                              capture_output=True, text=True, timeout=10, stdin=subprocess.DEVNULL)

        if result.returncode == 0:
            for line in result.stdout.split('\n')[1:]:
                if line.strip():
                    parts = line.split()
                    if len(parts) >= 3 and 'crypto_LUKS' in parts[2]:
                        partition_data = {
                            'name': parts[0],
                            'type': parts[1],
                            'fstype': parts[2],
                            'mountpoint': parts[3] if len(parts) > 3 else None
                        }
                        partitions.append(partition_data)

    except subprocess.TimeoutExpired:
        logging.getLogger(__name__).debug("lsblk command timed out")
    except Exception as e:
        logging.getLogger(__name__).debug(f"Error checking LUKS partitions: {e}")

    return partitions


def _check_crypttab() -> List[Dict]:
    """Check /etc/crypttab entries"""
    entries = []
    crypttab_file = '/etc/crypttab'

    if not os.path.exists(crypttab_file):
        return entries

    try:
        with open(crypttab_file, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue

                parts = line.split()
                if len(parts) >= 2:
                    entry = {
                        'name': parts[0],
                        'device': parts[1],
                        'keyfile': parts[2] if len(parts) > 2 else None,
                        'options': parts[3] if len(parts) > 3 else None
                    }
                    entries.append(entry)

    except Exception as e:
        logging.getLogger(__name__).debug(f"Error reading crypttab: {e}")

    return entries


def _check_ecryptfs() -> bool:
    """Check if eCryptfs is present"""
    # Check for ecryptfs-utils
    try:
        result = subprocess.run(['which', 'ecryptfs-mount-private'],
                              capture_output=True, text=True, timeout=5, stdin=subprocess.DEVNULL)
        if result.returncode == 0:
            return True
    except:
        pass

    # Check for .ecryptfs directories
    home_dirs = ['/home', '/root']
    for home_dir in home_dirs:
        if os.path.exists(home_dir):
            ecryptfs_dir = os.path.join(home_dir, '.ecryptfs')
            if os.path.exists(ecryptfs_dir):
                return True

    # Check for ecryptfs mount
    try:
        result = subprocess.run(['mount', '-t', 'ecryptfs'],
                              capture_output=True, text=True, timeout=5, stdin=subprocess.DEVNULL)
        if result.returncode == 0 and result.stdout:
            return True
    except:
        pass

    return False


def _check_encryption_algorithms() -> List[str]:
    """Check encryption algorithms in use"""
    algorithms = []

    try:
        # Check LUKS header for cipher information
        result = subprocess.run(['cryptsetup', 'luksDump'],
                              capture_output=True, text=True, timeout=10, stdin=subprocess.DEVNULL)

        if result.returncode == 0:
            for line in result.stdout.split('\n'):
                if 'Cipher name' in line:
                    match = re.search(r'Cipher name:\s+(\S+)', line)
                    if match:
                        algorithms.append(match.group(1))
                if 'Cipher mode' in line:
                    match = re.search(r'Cipher mode:\s+(\S+)', line)
                    if match:
                        algorithms.append(match.group(1))
    except subprocess.TimeoutExpired:
        logging.getLogger(__name__).debug("cryptsetup luksDump timed out")
    except Exception as e:
        logging.getLogger(__name__).debug(f"Error checking encryption algorithms: {e}")

    return algorithms


def _check_swap_encryption() -> bool:
    """Check if swap is encrypted"""
    # Check /etc/fstab for encrypted swap
    fstab_file = '/etc/fstab'

    if os.path.exists(fstab_file):
        try:
            with open(fstab_file, 'r') as f:
                for line in f:
                    if 'swap' in line and 'crypt' in line:
                        return True
                    if 'swap' in line and '/dev/mapper' in line:
                        return True
        except:
            pass

    # Check crypttab for swap
    crypttab_entries = _check_crypttab()
    for entry in crypttab_entries:
        if 'swap' in entry.get('name', '').lower():
            return True

    return False


# ============================================================
# FIX 4: CHECK LUKS KEY MANAGEMENT
# ============================================================
def _check_luks_key_management() -> List[str]:
    """Check if LUKS keys are properly managed."""
    issues = []

    # Check for keys in /root (should be encrypted/safe)
    key_files = ['/root/luks-keyfile', '/root/disk.key']
    for key_file in key_files:
        if os.path.exists(key_file):
            try:
                stat_info = os.stat(key_file)
                perms = oct(stat_info.st_mode)[-3:]
                if perms != '600':
                    issues.append(f"Key file {key_file} has insecure permissions: {perms}")
            except:
                pass

    return issues


# ============================================================
# PROGRESS INDICATOR
# ============================================================
def _progress_indicator(current: int, total: int, message: str = ""):
    """Show progress during operations."""
    if total > 0:
        percent = (current / total) * 100
        print(f"\r\033[K[{current}/{total}] {percent:.1f}% - {message}", end="", flush=True)


def fix(config: dict, dry_run: bool = False, force: bool = False) -> bool:
    """
    Fix encryption issues (warning only - encryption setup is manual)

    Args:
        config: Configuration dictionary
        dry_run: If True, preview changes without applying
        force: If True, skip confirmation

    Returns:
        bool: True if fixes applied successfully
    """
    logger = logging.getLogger(__name__)
    logger.info("Checking encryption issues...")

    # Check for dry-run mode (use parameter, not config)
    if dry_run:
        logger.info("DRY-RUN MODE: No changes will be applied")
        print("\n[!] DRY-RUN MODE - No changes will be applied")
        
        cryptsetup_installed = _check_cryptsetup()
        print(f"  cryptsetup installed: {cryptsetup_installed}")
        if cryptsetup_installed:
            encrypted_partitions = _check_luks_partitions()
            print(f"  Encrypted partitions: {len(encrypted_partitions)}")
            crypttab_entries = _check_crypttab()
            print(f"  crypttab entries: {len(crypttab_entries)}")
            ecryptfs_present = _check_ecryptfs()
            print(f"  eCryptfs present: {ecryptfs_present}")
        
        if config.get('encryption', {}).get('warn_no_encryption', True):
            print("  Would warn about missing encryption")
        if config.get('encryption', {}).get('check_ciphers', True):
            print("  Would check for weak ciphers")
        
        print("\n[✓] Dry-run complete. No changes were made.")
        return True

    # FIX: Skip confirmation in force mode
    if not force:
        print("\n[!] WARNING: Encryption checks will be performed")
        print("    No automatic changes will be made")
        print("    Manual setup required for encryption")
        response = ui.prompt("Proceed? [y/N]: ")
        if response.lower() != 'y':
            logger.info("Encryption checks cancelled by user")
            return False
    else:
        logger.info("Force mode: Running encryption checks without confirmation")

    try:
        begin_transaction()
        
        steps = []
        
        # Step 1: Warn about missing encryption
        if config.get('encryption', {}).get('warn_no_encryption', True):
            steps.append(("Warn about missing encryption", _warn_no_encryption))
        
        # Step 2: Check LUKS version and warn about weak ciphers
        if config.get('encryption', {}).get('check_ciphers', True):
            steps.append(("Check for weak ciphers", _warn_weak_ciphers))
        
        total_steps = len(steps)
        for idx, (name, func) in enumerate(steps):
            _progress_indicator(idx + 1, total_steps, name)
            func()
        
        print()

        commit_transaction()
        logger.info("Encryption warnings completed")
        print("\n Encryption checks completed successfully")
        return True

    except Exception as e:
        logger.error(f"Failed to complete encryption checks: {e}")
        rollback_transaction()
        return False


def _warn_no_encryption():
    """Warn if no encryption is found"""
    encrypted_partitions = _check_luks_partitions()

    if not encrypted_partitions:
        logging.getLogger(__name__).warning(
            "NO encryption detected! Consider encrypting sensitive data."
        )
        _log_encryption_warning("No encryption detected")

    # Check root encryption
    root_encrypted = False
    for partition in encrypted_partitions:
        if partition.get('mountpoint') == '/':
            root_encrypted = True
            break

    if not root_encrypted:
        logging.getLogger(__name__).warning(
            "Root partition is not encrypted! Consider full disk encryption."
        )
        _log_encryption_warning("Root partition not encrypted")


def _warn_weak_ciphers():
    """Warn about weak encryption algorithms"""
    algorithms = _check_encryption_algorithms()

    weak_algorithms = ['aes-cbc', 'aes128-cbc', 'aes256-cbc', 'des', '3des']

    for algo in algorithms:
        if any(weak in algo.lower() for weak in weak_algorithms):
            logging.getLogger(__name__).warning(
                f"Weak encryption algorithm detected: {algo}. Consider using AES-XTS."
            )
            _log_encryption_warning(f"Weak encryption algorithm: {algo}")