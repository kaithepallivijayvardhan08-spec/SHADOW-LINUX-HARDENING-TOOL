#!/usr/bin/env python3
"""
Shadow RDP/VNC Module
=====================

Checks RDP and VNC security:
- RDP/Xrdp installation and status
- VNC server installation and status
- VNC password security
- VNC listening ports
- Encryption status

Security concerns:
- VNC without password → unauthenticated access
- VNC without encryption → credentials exposed
- RDP without TLS → session vulnerable
- Open remote desktop ports → attack surface
- Default VNC ports (5900-5909) → easy to find
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
    Check RDP and VNC security

    Returns:
        Tuple[str, str, dict]: (status, message, details)
    """
    logger = logging.getLogger(__name__)
    logger.info("Checking RDP/VNC security...")

    issues = []
    warnings = []
    details = {
        'rdp_installed': False,
        'rdp_running': False,
        'rdp_port_open': False,
        'vnc_installed': False,
        'vnc_running': False,
        'vnc_password_secure': False,
        'vnc_ports_open': [],
        'rdp_config_file': None,
        'vnc_config_files': []
    }

    # Check RDP/Xrdp
    rdp_info = _check_rdp()
    details.update(rdp_info)

    if rdp_info.get('rdp_installed'):
        details['rdp_installed'] = True
        if rdp_info.get('rdp_running'):
            details['rdp_running'] = True
            issues.append("RDP service is RUNNING")
            if not rdp_info.get('rdp_secure'):
                issues.append("RDP security configuration is weak")
        if rdp_info.get('rdp_port_open'):
            details['rdp_port_open'] = True
            warnings.append("RDP port 3389 is open")
        if rdp_info.get('rdp_config_file'):
            details['rdp_config_file'] = rdp_info['rdp_config_file']

    # Check VNC
    vnc_info = _check_vnc()
    details.update(vnc_info)

    if vnc_info.get('vnc_installed'):
        details['vnc_installed'] = True
        if vnc_info.get('vnc_running'):
            details['vnc_running'] = True
            issues.append("VNC service is RUNNING")
            if not vnc_info.get('vnc_password_secure'):
                issues.append("VNC password is WEAK or not set")
            if not vnc_info.get('vnc_encrypted'):
                issues.append("VNC traffic is not encrypted")
        if vnc_info.get('vnc_ports_open'):
            details['vnc_ports_open'] = vnc_info['vnc_ports_open']
            for port in details['vnc_ports_open']:
                warnings.append(f"VNC port {port} is open")
        if vnc_info.get('vnc_config_files'):
            details['vnc_config_files'] = vnc_info['vnc_config_files']

    # Check VNC password strength
    if details.get('vnc_installed'):
        vnc_password_issues = _check_vnc_password()
        if vnc_password_issues:
            issues.extend(vnc_password_issues)

    # Check for VNC without authentication
    if details.get('vnc_running'):
        vnc_auth_check = _check_vnc_authentication()
        if vnc_auth_check:
            issues.append("VNC may have no authentication")

    # Determine status
    if issues:
        critical = [i for i in issues if 'without authentication' in i.lower() or 'weak' in i.lower()]
        if critical:
            status = 'FAIL'
            message = f"{len(issues)} RDP/VNC issues found, {len(critical)} critical"
        else:
            status = 'WARN'
            message = f"{len(issues)} RDP/VNC issues found"
    elif warnings:
        status = 'WARN'
        message = "RDP/VNC warnings found"
    else:
        status = 'PASS'
        message = "RDP/VNC services are not installed or are secure"

    return status, message, details


def _check_rdp() -> dict:
    """Check RDP/Xrdp installation and status"""
    info = {
        'rdp_installed': False,
        'rdp_running': False,
        'rdp_port_open': False,
        'rdp_secure': False,
        'rdp_config_file': None
    }

    # Check if xrdp is installed
    xrdp_paths = [
        '/usr/sbin/xrdp',
        '/usr/lib/xrdp/xrdp',
        '/usr/local/sbin/xrdp'
    ]

    for path in xrdp_paths:
        if os.path.exists(path):
            info['rdp_installed'] = True
            break

    # Check if xrdp is running
    try:
        result = subprocess.run(['systemctl', 'is-active', 'xrdp'],
                              capture_output=True, text=True, stdin=subprocess.DEVNULL)
        if result.stdout.strip() == 'active':
            info['rdp_running'] = True
    except:
        pass

    try:
        result = subprocess.run(['ps', 'aux'], capture_output=True, text=True, stdin=subprocess.DEVNULL)
        if 'xrdp' in result.stdout:
            info['rdp_running'] = True
    except:
        pass

    # Check if RDP port 3389 is open
    try:
        result = subprocess.run(['ss', '-tln'], capture_output=True, text=True, stdin=subprocess.DEVNULL)
        if ':3389' in result.stdout:
            info['rdp_port_open'] = True
    except:
        pass

    # Check xrdp configuration file
    xrdp_ini = '/etc/xrdp/xrdp.ini'
    if os.path.exists(xrdp_ini):
        info['rdp_config_file'] = xrdp_ini
        # Check security settings
        try:
            with open(xrdp_ini, 'r') as f:
                content = f.read()
                if 'security_layer=negotiate' in content or 'security_layer=tls' in content:
                    info['rdp_secure'] = True
        except:
            pass

    return info


def _check_vnc() -> dict:
    """Check VNC installation and status"""
    info = {
        'vnc_installed': False,
        'vnc_running': False,
        'vnc_password_secure': False,
        'vnc_encrypted': False,
        'vnc_ports_open': [],
        'vnc_config_files': []
    }

    # Check VNC binaries
    vnc_binaries = [
        '/usr/bin/vncserver',
        '/usr/bin/vncviewer',
        '/usr/sbin/vncserver',
        '/usr/bin/tightvncserver',
        '/usr/bin/tigervncserver'
    ]

    for binary in vnc_binaries:
        if os.path.exists(binary):
            info['vnc_installed'] = True
            break

    # Check if VNC is running
    try:
        result = subprocess.run(['ps', 'aux'], capture_output=True, text=True, stdin=subprocess.DEVNULL)
        if 'vnc' in result.stdout and 'Xvnc' in result.stdout:
            info['vnc_running'] = True
    except:
        pass

    # Check VNC ports (5900-5909)
    try:
        result = subprocess.run(['ss', '-tln'], capture_output=True, text=True, stdin=subprocess.DEVNULL)
        for port in range(5900, 5910):
            if f':{port}' in result.stdout:
                info['vnc_ports_open'].append(port)
    except:
        pass

    # Check VNC configuration files
    vnc_configs = [
        '/etc/vnc.conf',
        '/etc/vnc/config',
        '/etc/tigervnc/vncserver-config-defaults',
        '~/.vnc/config'
    ]

    for config in vnc_configs:
        expanded_path = os.path.expanduser(config)
        if os.path.exists(expanded_path):
            info['vnc_config_files'].append(expanded_path)

    # Check VNC password
    vnc_passwd = os.path.expanduser('~/.vnc/passwd')
    if os.path.exists(vnc_passwd):
        # Check if password file has proper permissions
        try:
            stat_info = os.stat(vnc_passwd)
            perms = oct(stat_info.st_mode)[-3:]
            if perms == '600':
                info['vnc_password_secure'] = True
        except:
            pass

    # Check if VNC uses encryption
    for config in info['vnc_config_files']:
        try:
            with open(config, 'r') as f:
                content = f.read()
                if 'SecurityTypes' in content and 'TLS' in content:
                    info['vnc_encrypted'] = True
                    break
                if 'securitytypes' in content and 'tls' in content:
                    info['vnc_encrypted'] = True
                    break
        except:
            pass

    return info


def _check_vnc_password() -> list:
    """Check VNC password strength"""
    issues = []
    vnc_passwd = os.path.expanduser('~/.vnc/passwd')

    if not os.path.exists(vnc_passwd):
        return issues

    try:
        stat_info = os.stat(vnc_passwd)
        perms = oct(stat_info.st_mode)[-3:]

        if perms != '600':
            issues.append(f"VNC password file has weak permissions: {perms}")

    except Exception as e:
        issues.append(f"Error checking VNC password: {str(e)}")

    return issues


def _check_vnc_authentication() -> bool:
    """Check if VNC has authentication enabled"""
    try:
        result = subprocess.run(['ps', 'aux'], capture_output=True, text=True, stdin=subprocess.DEVNULL)
        if '-authentication' in result.stdout:
            return True
        if 'SecurityTypes=None' in result.stdout:
            return False
    except:
        pass
    return False


def _verify_service_disabled(service_name: str) -> bool:
    """Verify that a service is disabled."""
    try:
        result = subprocess.run(
            ['systemctl', 'is-active', service_name],
            capture_output=True,
            text=True, stdin=subprocess.DEVNULL)
        if result.stdout.strip() == 'active':
            logging.getLogger(__name__).warning(f"Service {service_name} is still active")
            return False
    except:
        pass
    return True


def _backup_service_config(service_name: str) -> bool:
    """Backup a service configuration file."""
    service_files = {
        'xrdp': '/etc/xrdp/xrdp.ini',
        'vncserver': '/etc/vnc.conf'
    }
    
    config_file = service_files.get(service_name)
    if not config_file or not os.path.exists(config_file):
        return True
    
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_path = BACKUP_DIR / f"{Path(config_file).name}.backup_{timestamp}"
    
    try:
        shutil.copy2(config_file, backup_path)
        logging.getLogger(__name__).info(f"Backup created: {backup_path}")
        return True
    except Exception as e:
        logging.getLogger(__name__).error(f"Failed to backup {config_file}: {e}")
        return False


# ============================================================
# MEDIUM FIX 1: DRY-RUN MODE
# ============================================================
def _dry_run_rdp_vnc_fix(action: str, details: str) -> bool:
    """
    Simulate RDP/VNC modification without actually changing anything.
    Used for dry-run mode.
    """
    logging.getLogger(__name__).info(f"[DRY-RUN] Would perform: {action} - {details}")
    print(f"[DRY-RUN] Would perform: {action}")
    return True


# ============================================================
# MEDIUM FIX 2: CONFIRMATION BEFORE DISABLING
# ============================================================
def _confirm_rdp_vnc_disable(action: str) -> bool:
    """
    Ask for confirmation before disabling RDP/VNC.
    """
    print(f"\n[!] WARNING: About to disable RDP/VNC services")
    print(f"    Action: {action}")
    response = ui.prompt("Proceed? [y/N]: ")
    if response.lower() == 'y':
        print("\n[*] Applying fixes... please wait")
        return True
    return False


# ============================================================
# MEDIUM FIX 3: LOGGING OF CHANGES
# ============================================================
def _log_rdp_vnc_change(action: str, details: str, success: bool):
    """
    Log RDP/VNC modifications.
    """
    logger = logging.getLogger(__name__)
    status = "SUCCESS" if success else "FAILED"
    logger.info(f"RDP/VNC change: {action} - {details} ({status})")
    
    # Also log to changes.log for audit trail
    changes_log = Path("/var/log/shadow/changes.log")
    if changes_log.exists():
        with open(changes_log, 'a') as f:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            f.write(f"{timestamp} - RDP/VNC: {action} - {details} ({status})\n")


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


def fix(config: dict, dry_run: bool = False, force: bool = False) -> bool:
    """
    Fix RDP/VNC security issues

    Args:
        config: Configuration dictionary
        dry_run: If True, preview changes without applying
        force: If True, skip confirmation

    Returns:
        bool: True if fixes applied successfully
    """
    logger = logging.getLogger(__name__)
    logger.info("Fixing RDP/VNC security issues...")
    
    if dry_run:
        logger.info("DRY-RUN MODE: No changes will be applied")
        print("\n[!] DRY-RUN MODE - No changes will be applied")
        print("[✓] Dry-run complete. No changes were made.")
        return True

    # ✅ FIX: Skip confirmation in force mode
    if not force:
        if not _confirm_rdp_vnc_disable("Disable RDP and VNC services"):
            logger.info("RDP/VNC disable cancelled by user")
            return False
    else:
        logger.info("Force mode: Disabling RDP/VNC without confirmation")

    try:
        # Backup configs before disabling
        if not dry_run:
            _backup_service_config('xrdp')
            _backup_service_config('vncserver')

        steps = [
            ("Disable VNC", lambda: _disable_vnc(dry_run)),
            ("Disable RDP", lambda: _disable_rdp(dry_run)),
            ("Close VNC ports", lambda: _close_vnc_ports(dry_run)),
            ("Close RDP port", lambda: _close_rdp_port(dry_run)),
            ("Verify services disabled", lambda: _verify_services_disabled())
        ]
        
        total_steps = len(steps)
        for idx, (name, func) in enumerate(steps):
            _progress_indicator(idx + 1, total_steps, name)
            
            if dry_run:
                _dry_run_rdp_vnc_fix(name, "Dry-run step")
            else:
                func()
        
        print()

        # Verify services are disabled
        if not dry_run:
            if not _verify_service_disabled('xrdp'):
                logger.warning("RDP service may still be running")
            if not _verify_service_disabled('vncserver'):
                logger.warning("VNC service may still be running")

        logger.info("RDP/VNC fixes applied successfully")
        return True

    except Exception as e:
        logger.error(f"Failed to fix RDP/VNC: {e}")
        return False


def _disable_vnc(dry_run: bool = False):
    """Disable VNC service"""
    try:
        # Kill VNC processes
        subprocess.run(['pkill', '-f', 'vncserver'], capture_output=True, stdin=subprocess.DEVNULL)
        subprocess.run(['pkill', '-f', 'Xvnc'], capture_output=True, stdin=subprocess.DEVNULL)
        logging.getLogger(__name__).info("VNC processes stopped")
    except:
        pass

    # Disable VNC service
    try:
        subprocess.run(['systemctl', 'stop', 'vncserver@*'],
                      capture_output=True, text=True, stdin=subprocess.DEVNULL)
        subprocess.run(['systemctl', 'disable', 'vncserver@*'],
                      capture_output=True, text=True, stdin=subprocess.DEVNULL)
        logging.getLogger(__name__).info("VNC systemd service disabled")
    except:
        pass


def _disable_rdp(dry_run: bool = False):
    """Disable RDP service"""
    try:
        subprocess.run(['systemctl', 'stop', 'xrdp'],
                      capture_output=True, text=True, stdin=subprocess.DEVNULL)
        subprocess.run(['systemctl', 'disable', 'xrdp'],
                      capture_output=True, text=True, stdin=subprocess.DEVNULL)
        logging.getLogger(__name__).info("RDP service disabled")
    except:
        pass


def _close_vnc_ports(dry_run: bool = False):
    """Close VNC ports using firewall"""
    for port in range(5900, 5910):
        try:
            subprocess.run(['ufw', 'deny', str(port)],
                          capture_output=True, text=True, stdin=subprocess.DEVNULL)
        except:
            pass
        try:
            subprocess.run(['iptables', '-A', 'INPUT', '-p', 'tcp',
                           '--dport', str(port), '-j', 'DROP'],
                          capture_output=True, text=True, stdin=subprocess.DEVNULL)
        except:
            pass
    logging.getLogger(__name__).info("VNC ports blocked")


def _close_rdp_port(dry_run: bool = False):
    """Close RDP port 3389 using firewall"""
    try:
        subprocess.run(['ufw', 'deny', '3389'],
                      capture_output=True, text=True, stdin=subprocess.DEVNULL)
    except:
        pass
    try:
        subprocess.run(['iptables', '-A', 'INPUT', '-p', 'tcp',
                       '--dport', '3389', '-j', 'DROP'],
                      capture_output=True, text=True, stdin=subprocess.DEVNULL)
    except:
        pass
    logging.getLogger(__name__).info("RDP port blocked")


def _verify_services_disabled():
    """Verify all services are disabled."""
    # RDP verification
    if not _verify_service_disabled('xrdp'):
        logging.getLogger(__name__).warning("RDP service is still active")
    
    # VNC verification  
    if not _verify_service_disabled('vncserver'):
        logging.getLogger(__name__).warning("VNC service is still active")
    
    # Check VNC ports
    try:
        result = subprocess.run(['ss', '-tln'], capture_output=True, text=True, stdin=subprocess.DEVNULL)
        for port in range(5900, 5910):
            if f':{port}' in result.stdout:
                logging.getLogger(__name__).warning(f"VNC port {port} is still open")
    except:
        pass
    
    # Check RDP port
    try:
        result = subprocess.run(['ss', '-tln'], capture_output=True, text=True, stdin=subprocess.DEVNULL)
        if ':3389' in result.stdout:
            logging.getLogger(__name__).warning("RDP port 3389 is still open")
    except:
        pass
    
    logging.getLogger(__name__).info("Service verification complete")
    return True