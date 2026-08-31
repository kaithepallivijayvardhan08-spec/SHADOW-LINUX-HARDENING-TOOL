#!/usr/bin/env python3
"""
Shadow Telnet Module
====================

Checks Telnet service security:
- Telnet server installation
- Telnet service status
- Telnet listening ports

Security concerns:
- Telnet transmits credentials in plaintext
- No encryption
- Easy to intercept and sniff
- Should be disabled and replaced with SSH

Files checked:
- /etc/inetd.conf
- /etc/xinetd.d/telnet
- Systemd service status
"""

from shadow.core import ui
import os
import re
import shutil
import logging
import subprocess
from pathlib import Path
from datetime import datetime
from typing import Tuple, Dict, List, Optional


BACKUP_DIR = Path("/var/backups/shadow/")


def check(config: dict) -> Tuple[str, str, dict]:
    """
    Check Telnet service security

    Returns:
        Tuple[str, str, dict]: (status, message, details)
    """
    logger = logging.getLogger(__name__)
    logger.info("Checking Telnet security...")

    issues = []
    warnings = []
    details = {
        'telnet_installed': False,
        'telnet_running': False,
        'telnet_port_open': False,
        'telnet_port': 23,
        'inetd_config': False,
        'xinetd_config': False,
        'systemd_service': False
    }

    # Check if Telnet is installed
    telnet_installed = _check_telnet_installed()
    details['telnet_installed'] = telnet_installed

    if not telnet_installed:
        return 'PASS', "Telnet is not installed", details

    # Check if Telnet is running
    telnet_running = _check_telnet_running()
    details['telnet_running'] = telnet_running

    if telnet_running:
        issues.append("Telnet service is RUNNING (SECURITY RISK)")
        details['telnet_running'] = True

    # Check if Telnet port is open
    telnet_port_open = _check_telnet_port()
    details['telnet_port_open'] = telnet_port_open

    if telnet_port_open:
        issues.append("Telnet port 23 is OPEN (SECURITY RISK)")

    # Check inetd configuration
    inetd_config = _check_inetd()
    details['inetd_config'] = inetd_config

    if inetd_config:
        warnings.append("Telnet configured in inetd")

    # Check xinetd configuration
    xinetd_config = _check_xinetd()
    details['xinetd_config'] = xinetd_config

    if xinetd_config:
        warnings.append("Telnet configured in xinetd")

    # Check systemd service
    systemd_service = _check_systemd_telnet()
    details['systemd_service'] = systemd_service

    if systemd_service:
        warnings.append("Telnet systemd service exists")

    # Determine status
    if issues:
        status = 'FAIL'
        message = "Telnet is running or active - HIGH SECURITY RISK"
    elif warnings:
        status = 'WARN'
        message = "Telnet configuration found, but not active"
    else:
        status = 'PASS'
        message = "Telnet is properly disabled"

    return status, message, details


def _check_telnet_installed() -> bool:
    """Check if Telnet is installed"""
    # Check for telnet binaries
    telnet_binaries = [
        '/usr/sbin/in.telnetd',
        '/usr/sbin/telnetd',
        '/usr/bin/telnet'
    ]

    for binary in telnet_binaries:
        if os.path.exists(binary):
            return True

    # Check if package is installed
    try:
        result = subprocess.run(['dpkg', '-l', 'telnet*'], 
                              capture_output=True, text=True, stdin=subprocess.DEVNULL)
        if 'telnetd' in result.stdout or 'telnet' in result.stdout:
            return True
    except:
        pass

    try:
        result = subprocess.run(['rpm', '-qa', 'telnet*'],
                              capture_output=True, text=True, stdin=subprocess.DEVNULL)
        if 'telnet' in result.stdout:
            return True
    except:
        pass

    return False


def _check_telnet_running() -> bool:
    """Check if Telnet service is running"""
    # Check systemd
    try:
        result = subprocess.run(['systemctl', 'is-active', 'telnet'],
                              capture_output=True, text=True, stdin=subprocess.DEVNULL)
        if result.stdout.strip() == 'active':
            return True
    except:
        pass

    # Check for running processes
    try:
        result = subprocess.run(['ps', 'aux'], capture_output=True, text=True, stdin=subprocess.DEVNULL)
        if 'telnetd' in result.stdout or 'in.telnetd' in result.stdout:
            return True
    except:
        pass

    # Check if port 23 is listening
    try:
        result = subprocess.run(['ss', '-tln'], capture_output=True, text=True, stdin=subprocess.DEVNULL)
        if ':23' in result.stdout:
            return True
    except:
        pass

    return False


def _check_telnet_port() -> bool:
    """Check if Telnet port 23 is open"""
    try:
        result = subprocess.run(['ss', '-tln'], capture_output=True, text=True, stdin=subprocess.DEVNULL)
        if ':23' in result.stdout:
            return True
    except:
        pass

    try:
        import socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex(('127.0.0.1', 23))
        sock.close()
        return result == 0
    except:
        pass

    return False


def _check_inetd() -> bool:
    """Check inetd configuration for Telnet"""
    inetd_files = ['/etc/inetd.conf', '/etc/inetd/inetd.conf']

    for file in inetd_files:
        if not os.path.exists(file):
            continue

        try:
            with open(file, 'r') as f:
                for line in f:
                    if 'telnet' in line and not line.strip().startswith('#'):
                        return True
        except:
            pass

    return False


def _check_xinetd() -> bool:
    """Check xinetd configuration for Telnet"""
    xinetd_dir = '/etc/xinetd.d/'

    if not os.path.exists(xinetd_dir):
        return False

    try:
        for file in Path(xinetd_dir).iterdir():
            if file.is_file() and 'telnet' in file.name:
                with open(file, 'r') as f:
                    content = f.read()
                    if 'disable' in content and 'yes' not in content:
                        return True
                return True
    except:
        pass

    return False


def _check_systemd_telnet() -> bool:
    """Check if Telnet systemd service exists"""
    try:
        result = subprocess.run(['systemctl', 'list-unit-files', 'telnet*'],
                              capture_output=True, text=True, stdin=subprocess.DEVNULL)
        if 'telnet' in result.stdout:
            return True
    except:
        pass

    return False


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
# MEDIUM FIX 1: DRY-RUN MODE
# ============================================================
def _dry_run_telnet_fix(action: str, details: str) -> bool:
    """
    Simulate Telnet modification without actually changing anything.
    Used for dry-run mode.
    """
    logging.getLogger(__name__).info(f"[DRY-RUN] Would perform: {action} - {details}")
    print(f"[DRY-RUN] Would perform: {action}")
    return True


# ============================================================
# MEDIUM FIX 2: CONFIRMATION BEFORE DISABLING TELNET
# ============================================================
def _confirm_telnet_disable(action: str) -> bool:
    """
    Ask for confirmation before disabling Telnet.
    """
    print(f"\n[!] WARNING: About to disable Telnet service")
    print(f"    Action: {action}")
    response = ui.prompt("Proceed? [y/N]: ")
    if response.lower() == 'y':
        print("\n[*] Applying fixes... please wait")
        return True
    return False


# ============================================================
# MEDIUM FIX 3: LOGGING OF TELNET CHANGES
# ============================================================
def _log_telnet_change(action: str, details: str, success: bool):
    """
    Log Telnet modifications.
    """
    logger = logging.getLogger(__name__)
    status = "SUCCESS" if success else "FAILED"
    logger.info(f"Telnet change: {action} - {details} ({status})")
    
    # Also log to changes.log for audit trail
    changes_log = Path("/var/log/shadow/changes.log")
    if changes_log.exists():
        with open(changes_log, 'a') as f:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            f.write(f"{timestamp} - Telnet: {action} - {details} ({status})\n")


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


def _safe_write_config(file_path: str, content: str, dry_run: bool = False) -> bool:
    """
    Safely write a configuration file with backup, dry-run, and rollback.
    """
    logger = logging.getLogger(__name__)
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    
    # MEDIUM FIX 1: Dry-run mode
    if dry_run:
        return _dry_run_telnet_fix("write_config", f"Would write to {file_path}")
    
    # Create backup
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_path = BACKUP_DIR / f"{Path(file_path).name}.backup_{timestamp}"
    
    if os.path.exists(file_path):
        shutil.copy2(file_path, backup_path)
        logger.info(f"Backup created: {backup_path}")
        
        if not _verify_backup(backup_path):
            logger.error("Backup verification failed")
            return False
    
    try:
        with open(file_path, 'w') as f:
            f.write(content)
        logger.info(f"Successfully wrote: {file_path}")
        
        # MEDIUM FIX 3: Log success
        _log_telnet_change("write_config", file_path, True)
        return True
    except Exception as e:
        logger.error(f"Error writing {file_path}: {e}")
        if backup_path.exists():
            shutil.copy2(backup_path, file_path)
            logger.info(f"Rolled back from backup: {backup_path}")
        # MEDIUM FIX 3: Log failure
        _log_telnet_change("write_config", f"{file_path} - {e}", False)
        return False


def fix(config: dict, dry_run: bool = False, force: bool = False) -> bool:
    """
    Fix Telnet security issues by disabling Telnet

    Args:
        config: Configuration dictionary
        dry_run: If True, preview changes without applying
        force: If True, skip confirmation

    Returns:
        bool: True if fixes applied successfully
    """
    logger = logging.getLogger(__name__)
    logger.info("Fixing Telnet security issues...")
    
    if dry_run:
        logger.info("DRY-RUN MODE: No changes will be applied")
        print("\n[!] DRY-RUN MODE - No changes will be applied")
        print("[✓] Dry-run complete. No changes were made.")
        return True

    # ✅ FIX: Skip confirmation in force mode
    if not force:
        if not _confirm_telnet_disable("Disable Telnet service completely"):
            logger.info("Telnet disable cancelled by user")
            return False
    else:
        logger.info("Force mode: Disabling Telnet without confirmation")

    try:
        steps = [
            ("Stop Telnet service", lambda: _stop_telnet()),
            ("Disable Telnet service", lambda: _disable_telnet(dry_run)),
            ("Remove Telnet packages", lambda: _remove_telnet_packages()),
            ("Close Telnet port", lambda: _close_telnet_port())
        ]
        
        total_steps = len(steps)
        for idx, (name, func) in enumerate(steps):
            _progress_indicator(idx + 1, total_steps, name)
            
            if dry_run:
                _dry_run_telnet_fix(name, "Dry-run step")
            else:
                func()
        
        print()

        # Verify Telnet is disabled
        if not dry_run and not _verify_telnet_disabled():
            logger.warning("Telnet may still be active")
            return False

        logger.info("Telnet fixes applied successfully")
        return True

    except Exception as e:
        logger.error(f"Failed to fix Telnet: {e}")
        return False


def _verify_telnet_disabled() -> bool:
    """Verify that Telnet is properly disabled."""
    results = []
    
    # Check if running
    if _check_telnet_running():
        logging.getLogger(__name__).warning("Telnet is still running")
        results.append(False)
    
    # Check if port is open
    if _check_telnet_port():
        logging.getLogger(__name__).warning("Telnet port 23 is still open")
        results.append(False)
    
    # Check inetd
    if _check_inetd():
        logging.getLogger(__name__).warning("Telnet still configured in inetd")
        results.append(False)
    
    if results:
        logging.getLogger(__name__).warning("Telnet not fully disabled")
        return False
    
    logging.getLogger(__name__).info("Telnet is properly disabled")
    return True


def _stop_telnet():
    """Stop Telnet service"""
    try:
        # Stop systemd service
        subprocess.run(['systemctl', 'stop', 'telnet'],
                      capture_output=True, text=True, stdin=subprocess.DEVNULL)
        logging.getLogger(__name__).info("Telnet systemd service stopped")
    except:
        pass

    try:
        # Stop via service command
        subprocess.run(['service', 'telnet', 'stop'],
                      capture_output=True, text=True, stdin=subprocess.DEVNULL)
        logging.getLogger(__name__).info("Telnet service stopped")
    except:
        pass

    # Kill any running telnet processes
    try:
        subprocess.run(['pkill', '-f', 'telnetd'], capture_output=True, stdin=subprocess.DEVNULL)
        subprocess.run(['pkill', '-f', 'in.telnetd'], capture_output=True, stdin=subprocess.DEVNULL)
        logging.getLogger(__name__).info("Telnet processes killed")
    except:
        pass


def _disable_telnet(dry_run: bool = False):
    """Disable Telnet service"""
    # Disable systemd service
    try:
        subprocess.run(['systemctl', 'disable', 'telnet'],
                      capture_output=True, text=True, stdin=subprocess.DEVNULL)
        logging.getLogger(__name__).info("Telnet systemd service disabled")
    except:
        pass

    # Comment out inetd configuration
    _disable_inetd_telnet(dry_run)

    # Disable xinetd configuration
    _disable_xinetd_telnet(dry_run)


def _disable_inetd_telnet(dry_run: bool = False):
    """Disable Telnet in inetd"""
    inetd_files = ['/etc/inetd.conf', '/etc/inetd/inetd.conf']

    for file in inetd_files:
        if not os.path.exists(file):
            continue

        try:
            with open(file, 'r') as f:
                lines = f.readlines()

            new_lines = []
            modified = False
            for line in lines:
                if 'telnet' in line and not line.strip().startswith('#'):
                    new_lines.append(f"# {line}")
                    modified = True
                else:
                    new_lines.append(line)

            if modified:
                # Write with backup
                _safe_write_config(file, ''.join(new_lines), dry_run)
                logging.getLogger(__name__).info(f"Telnet disabled in {file}")
            else:
                logging.getLogger(__name__).debug(f"No Telnet config found in {file}")
        except Exception as e:
            logging.getLogger(__name__).error(f"Error disabling Telnet in {file}: {e}")


def _disable_xinetd_telnet(dry_run: bool = False):
    """Disable Telnet in xinetd"""
    xinetd_dir = '/etc/xinetd.d/'

    if not os.path.exists(xinetd_dir):
        return

    try:
        for file in Path(xinetd_dir).iterdir():
            if file.is_file() and 'telnet' in file.name:
                with open(file, 'r') as f:
                    content = f.read()

                # Set disable = yes
                if 'disable' in content:
                    content = re.sub(r'disable\s*=\s*\S+', 'disable = yes', content)
                else:
                    content += '\ndisable = yes\n'

                # Write with backup
                _safe_write_config(str(file), content, dry_run)
                logging.getLogger(__name__).info(f"Telnet disabled in {file}")
    except Exception as e:
        logging.getLogger(__name__).error(f"Error disabling Telnet in xinetd: {e}")


def _remove_telnet_packages():
    """Remove Telnet packages"""
    try:
        # Ubuntu/Debian
        result = subprocess.run(['apt-get', 'remove', '-y', 'telnetd', 'telnet'],
                      capture_output=True, text=True, stdin=subprocess.DEVNULL)
        if result.returncode == 0:
            logging.getLogger(__name__).info("Telnet packages removed (apt)")
    except:
        pass

    try:
        # RHEL/CentOS
        result = subprocess.run(['yum', 'remove', '-y', 'telnet', 'telnet-server'],
                      capture_output=True, text=True, stdin=subprocess.DEVNULL)
        if result.returncode == 0:
            logging.getLogger(__name__).info("Telnet packages removed (yum)")
    except:
        pass

    try:
        # Arch
        result = subprocess.run(['pacman', '-R', '--noconfirm', 'telnet'],
                      capture_output=True, text=True, stdin=subprocess.DEVNULL)
        if result.returncode == 0:
            logging.getLogger(__name__).info("Telnet packages removed (pacman)")
    except:
        pass


def _close_telnet_port():
    """Close Telnet port 23 using firewall"""
    try:
        # Using ufw
        result = subprocess.run(['ufw', 'deny', '23'],
                      capture_output=True, text=True, stdin=subprocess.DEVNULL)
        if result.returncode == 0:
            logging.getLogger(__name__).info("Telnet port 23 blocked via ufw")
    except:
        pass

    try:
        # Using iptables
        result = subprocess.run(['iptables', '-A', 'INPUT', '-p', 'tcp',
                       '--dport', '23', '-j', 'DROP'],
                      capture_output=True, text=True, stdin=subprocess.DEVNULL)
        if result.returncode == 0:
            logging.getLogger(__name__).info("Telnet port 23 blocked via iptables")
    except:
        pass

    try:
        # Using firewalld
        result = subprocess.run(['firewall-cmd', '--add-rich-rule',
                       'rule family="ipv4" port port="23" protocol="tcp" reject',
                       '--permanent'],
                      capture_output=True, text=True, stdin=subprocess.DEVNULL)
        if result.returncode == 0:
            subprocess.run(['firewall-cmd', '--reload'],
                          capture_output=True, text=True, stdin=subprocess.DEVNULL)
            logging.getLogger(__name__).info("Telnet port 23 blocked via firewalld")
    except:
        pass