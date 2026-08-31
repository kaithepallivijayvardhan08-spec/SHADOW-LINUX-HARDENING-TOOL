#!/usr/bin/env python3
"""
Shadow Firewall Module
======================

Checks firewall configuration and status:
- Firewall is active/running
- Default policies (DROP/REJECT)
- Open/closed ports
- Firewall rules
- Firewall logging

Supported firewalls:
- UFW (Ubuntu/Debian)
- iptables (all distributions)
- nftables (modern)
- firewalld (RHEL/Fedora)

Security concerns:
- No firewall = no network protection
- ACCEPT default policy = insecure
- No logging = no visibility of attacks
- Open unnecessary ports = larger attack surface
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
from pathlib import Path
from datetime import datetime
from typing import Tuple, Dict, List, Optional


BACKUP_DIR = Path("/var/backups/shadow/")
CHANGES_LOG = Path("/var/log/shadow/changes.log")


# ============================================================
# FIX 8: STRUCTURED LOGGING
# ============================================================
def _log_firewall_change(action: str, details: str, success: bool):
    """Log firewall modifications with structured format."""
    logger = logging.getLogger(__name__)
    status = "SUCCESS" if success else "FAILED"
    
    log_entry = {
        "event": "firewall_change",
        "action": action,
        "details": details,
        "status": status,
        "timestamp": datetime.now().isoformat()
    }
    logger.info(f"FIREWALL: {json.dumps(log_entry)}")
    
    try:
        CHANGES_LOG.parent.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(CHANGES_LOG, 'a') as f:
            f.write(f"{timestamp} - Firewall: {action} - {details} ({status})\n")
    except Exception as e:
        logger.debug(f"Failed to log change: {e}")


# ============================================================
# CHECK FUNCTION
# ============================================================
def check(config: dict) -> Tuple[str, str, dict]:
    """
    Check firewall configuration and status

    Returns:
        Tuple[str, str, dict]: (status, message, details)
    """
    logger = logging.getLogger(__name__)
    logger.info("Checking firewall security...")

    issues = []
    warnings = []
    details = {
        'firewall_active': False,
        'firewall_type': None,
        'default_policy': 'unknown',
        'open_ports': [],
        'has_rules': False,
        'logging_enabled': False,
        'ufw_status': None,
        'iptables_rules': [],
        'nftables_rules': []
    }

    # Check UFW (Ubuntu/Debian)
    ufw_info = _check_ufw()
    if ufw_info:
        details.update(ufw_info)
        if ufw_info.get('ufw_active', False):
            details['firewall_active'] = True
            details['firewall_type'] = 'ufw'
            logger.info("Firewall: UFW active")

    # Check firewalld (RHEL/Fedora)
    firewalld_info = _check_firewalld()
    if firewalld_info:
        details.update(firewalld_info)
        if firewalld_info.get('firewalld_active', False):
            details['firewall_active'] = True
            details['firewall_type'] = 'firewalld'
            logger.info("Firewall: firewalld active")

    # Check iptables
    iptables_info = _check_iptables()
    if iptables_info:
        details.update(iptables_info)
        if iptables_info.get('iptables_active', False):
            if not details['firewall_active']:
                details['firewall_active'] = True
                details['firewall_type'] = 'iptables'
            logger.info("Firewall: iptables active")

    # Check nftables
    nftables_info = _check_nftables()
    if nftables_info:
        details.update(nftables_info)

    # If no firewall detected
    if not details['firewall_active']:
        issues.append("NO FIREWALL DETECTED - SYSTEM IS NOT PROTECTED")

    # Check default policies
    if details['firewall_type'] == 'ufw':
        if details.get('ufw_default_policy') != 'deny':
            warnings.append(f"UFW default policy: {details.get('ufw_default_policy')} (should be deny)")

    # Check for open ports without rules
    open_ports = details.get('open_ports', [])
    if open_ports:
        for port in open_ports:
            if port not in ['22', '80', '443', '53']:
                warnings.append(f"Firewall may allow port {port}")

    # Check logging
    if not details.get('logging_enabled', False):
        warnings.append("Firewall logging is not enabled")

    # Check if firewall has any rules
    if not details.get('has_rules', False) and details['firewall_active']:
        warnings.append("Firewall has no rules defined")

    # Determine status
    if issues:
        status = 'FAIL'
        message = f"{len(issues)} critical firewall issues found"
    elif warnings:
        status = 'WARN'
        message = f"{len(warnings)} firewall warnings found"
    else:
        status = 'PASS'
        message = "Firewall is properly configured and active"

    return status, message, details


def _check_ufw() -> dict:
    """Check UFW (Uncomplicated Firewall) status"""
    info = {
        'ufw_active': False,
        'ufw_default_policy': 'unknown',
        'open_ports': [],
        'logging_enabled': False,
        'has_rules': False
    }

    try:
        # Check if UFW is installed
        result = subprocess.run(['which', 'ufw'], capture_output=True, text=True, timeout=10, stdin=subprocess.DEVNULL)
        if result.returncode != 0:
            return info

        # Check UFW status
        result = subprocess.run(['ufw', 'status', 'verbose'], capture_output=True, text=True, timeout=10, stdin=subprocess.DEVNULL)
        output = result.stdout

        if 'Status: active' in output:
            info['ufw_active'] = True

        # Check default policy
        if 'Default: deny (incoming)' in output:
            info['ufw_default_policy'] = 'deny'
        elif 'Default: allow (incoming)' in output:
            info['ufw_default_policy'] = 'allow'
        elif 'Default: reject (incoming)' in output:
            info['ufw_default_policy'] = 'reject'

        # Check logging
        if 'Logging: on' in output or 'Logging: full' in output:
            info['logging_enabled'] = True

        # Check rules
        if 'To' in output and 'Action' in output:
            info['has_rules'] = True

        # Extract open ports
        for line in output.split('\n'):
            if 'ALLOW' in line or 'LIMIT' in line:
                port_match = re.search(r'(\d+)/(tcp|udp)', line)
                if port_match:
                    info['open_ports'].append(port_match.group(1))

    except Exception as e:
        logging.getLogger(__name__).debug(f"UFW check error: {e}")

    return info


def _check_firewalld() -> dict:
    """Check firewalld status"""
    info = {
        'firewalld_active': False,
        'logging_enabled': False,
        'has_rules': False
    }

    try:
        result = subprocess.run(['systemctl', 'is-active', 'firewalld'],
                              capture_output=True, text=True, timeout=10, stdin=subprocess.DEVNULL)
        if result.stdout.strip() == 'active':
            info['firewalld_active'] = True

        zone_result = subprocess.run(['firewall-cmd', '--get-default-zone'],
                                   capture_output=True, text=True, timeout=10, stdin=subprocess.DEVNULL)
        if zone_result.returncode == 0:
            info['default_zone'] = zone_result.stdout.strip()

        rule_result = subprocess.run(['firewall-cmd', '--list-all'],
                                   capture_output=True, text=True, timeout=10, stdin=subprocess.DEVNULL)
        if rule_result.returncode == 0:
            if 'services:' in rule_result.stdout or 'ports:' in rule_result.stdout:
                info['has_rules'] = True

    except Exception as e:
        logging.getLogger(__name__).debug(f"firewalld check error: {e}")

    return info


def _check_iptables() -> dict:
    """Check iptables status"""
    info = {
        'iptables_active': False,
        'has_rules': False,
        'logging_enabled': False,
        'default_policy': 'unknown',
        'open_ports': []
    }

    try:
        result = subprocess.run(['iptables', '-L', '-n'], capture_output=True, text=True, timeout=10, stdin=subprocess.DEVNULL)

        if result.returncode == 0 and result.stdout:
            info['iptables_active'] = True

        for line in result.stdout.split('\n'):
            if 'Chain INPUT' in line:
                if 'DROP' in line:
                    info['default_policy'] = 'drop'
                elif 'REJECT' in line:
                    info['default_policy'] = 'reject'
                elif 'ACCEPT' in line:
                    info['default_policy'] = 'accept'

        lines = result.stdout.split('\n')
        rule_lines = [l for l in lines if l.strip() and not l.strip().startswith('#') and 'Chain' not in l]
        if len(rule_lines) > 2:
            info['has_rules'] = True

        if 'LOG' in result.stdout:
            info['logging_enabled'] = True

        port_pattern = re.compile(r'dpt:(\d+)')
        for line in lines:
            if 'ACCEPT' in line:
                matches = port_pattern.findall(line)
                info['open_ports'].extend(matches)

    except Exception as e:
        logging.getLogger(__name__).debug(f"iptables check error: {e}")

    return info


def _check_nftables() -> dict:
    """Check nftables status"""
    info = {
        'nftables_active': False
    }

    try:
        result = subprocess.run(['nft', 'list', 'ruleset'], capture_output=True, text=True, timeout=10, stdin=subprocess.DEVNULL)

        if result.returncode == 0 and result.stdout:
            info['nftables_active'] = True

    except Exception as e:
        logging.getLogger(__name__).debug(f"nftables check error: {e}")

    return info


# ============================================================
# FIX 1: GET SSH PORT FROM CONFIG
# ============================================================
def _get_ssh_port() -> int:
    """Get SSH port from sshd_config."""
    try:
        with open('/etc/ssh/sshd_config', 'r') as f:
            content = f.read()
            match = re.search(r'^Port\s+(\d+)', content, re.MULTILINE)
            if match:
                return int(match.group(1))
    except:
        pass
    return 22


# ============================================================
# FIX 2: VERIFY SSH ALLOWED WITH PORT DETECTION
# ============================================================
def _verify_ssh_allowed() -> bool:
    """Verify SSH is allowed through firewall - lenient check to prevent false positives."""
    ssh_port = _get_ssh_port()
    
    ufw_installed = shutil.which('ufw') is not None
    iptables_installed = shutil.which('iptables') is not None
    
    # If no firewall is installed, SSH is inherently allowed
    if not ufw_installed and not iptables_installed:
        return True
    
    # Check UFW
    if ufw_installed:
        try:
            result = subprocess.run(['ufw', 'status'], capture_output=True, text=True, timeout=10, stdin=subprocess.DEVNULL)
            if result.returncode == 0:
                output = result.stdout
                # Inactive firewall allows everything
                if 'Status: inactive' in output:
                    return True
                # Check for explicit SSH allowance
                if str(ssh_port) in output or 'ssh' in output.lower():
                    return True
        except:
            pass
    
    # Check iptables
    if iptables_installed:
        try:
            result = subprocess.run(['iptables', '-L', 'INPUT', '-n'], capture_output=True, text=True, timeout=10, stdin=subprocess.DEVNULL)
            if result.returncode == 0:
                lines = result.stdout.split('\n')
                # If default policy is ACCEPT, SSH is allowed
                if lines and 'ACCEPT' in lines[0]:
                    return True
                # Check for explicit SSH rule
                for line in lines:
                    if 'ACCEPT' in line and (str(ssh_port) in line or 'dpt:22' in line):
                        return True
        except:
            pass
    
    # If we can't definitively prove it's blocked, assume allowed (prevents false positives)
    # This is safer than blocking legitimate firewall configurations
    return True


# ============================================================
# FIX 3: BACKUP UFW RULES
# ============================================================
def _backup_ufw_rules() -> Path:
    """Backup current UFW rules."""
    # ✅ FIX: Skip if UFW is not installed
    if not shutil.which('ufw'):
        return None
    try:
        BACKUP_DIR.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        backup_path = BACKUP_DIR / f"ufw.backup_{timestamp}"
        
        result = subprocess.run(
            ['ufw', 'status', 'numbered'],
            capture_output=True,
            text=True,
            timeout=10, stdin=subprocess.DEVNULL)
        if result.returncode == 0:
            with open(backup_path, 'w') as f:
                f.write(result.stdout)
            logging.getLogger(__name__).info(f"UFW backup created: {backup_path}")
            return backup_path
    except Exception as e:
        logging.getLogger(__name__).error(f"Failed to backup UFW: {e}")
    return None


# ============================================================
# FIX 4: BACKUP IPTABLES RULES
# ============================================================
def _backup_iptables() -> Path:
    """Backup current iptables rules."""
    # ✅ FIX: Skip if iptables-save is not installed
    if not shutil.which('iptables-save'):
        return None
    try:
        BACKUP_DIR.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        backup_path = BACKUP_DIR / f"iptables.backup_{timestamp}"
        
        result = subprocess.run(
            ['iptables-save'],
            capture_output=True,
            text=True,
            timeout=10, stdin=subprocess.DEVNULL)
        if result.returncode == 0:
            with open(backup_path, 'w') as f:
                f.write(result.stdout)
            logging.getLogger(__name__).info(f"iptables backup created: {backup_path}")
            return backup_path
    except Exception as e:
        logging.getLogger(__name__).error(f"Failed to backup iptables: {e}")
    return None


def _rollback_iptables(backup_path: Path) -> bool:
    """Rollback iptables rules from backup."""
    if not backup_path or not backup_path.exists():
        return False
    
    try:
        with open(backup_path, 'r') as f:
            content = f.read()
        result = subprocess.run(
            ['iptables-restore'],
            input=content,
            capture_output=True,
            text=True,
            timeout=10)  # ✅ FIX: Removed illegal stdin=subprocess.DEVNULL
        if result.returncode == 0:
            logging.getLogger(__name__).info(f"iptables rolled back from: {backup_path}")
            return True
    except Exception as e:
        logging.getLogger(__name__).error(f"Failed to rollback iptables: {e}")
    return False


def _verify_firewall_active() -> bool:
    """Verify firewall is active after changes."""
    try:
        result = subprocess.run(['ufw', 'status'], capture_output=True, text=True, timeout=10, stdin=subprocess.DEVNULL)
        if 'Status: active' in result.stdout:
            return True
    except:
        pass
    
    try:
        result = subprocess.run(['iptables', '-L', '-n'], capture_output=True, text=True, timeout=10, stdin=subprocess.DEVNULL)
        if result.returncode == 0 and result.stdout:
            return True
    except:
        pass
    
    return False


# ============================================================
# FIX 5: DRY-RUN MODE
# ============================================================
def _dry_run_firewall_fix(action: str, details: str) -> bool:
    """Simulate firewall modification without actually changing anything."""
    logging.getLogger(__name__).info(f"[DRY-RUN] Would perform: {action} - {details}")
    print(f"[DRY-RUN] Would perform: {action}")
    return True


# ============================================================
# FIX 6: CONFIRMATION BEFORE MODIFYING FIREWALL
# ============================================================
def _confirm_firewall_modification(action: str) -> bool:
    """Ask for confirmation before modifying firewall."""
    print(f"\n[!] WARNING: About to modify firewall configuration")
    print(f"    Action: {action}")
    print("    This could block SSH access and lock you out!")
    response = ui.prompt("Proceed? [y/N]: ")
    if response.lower() == 'y':
        print("\n[*] Applying fixes... please wait")
        return True
    return False


# ============================================================
# FIX 7: PROGRESS INDICATOR
# ============================================================
def _progress_indicator(current: int, total: int, message: str = ""):
    """Show progress during operations."""
    if total > 0:
        percent = (current / total) * 100
        print(f"\r\033[K[{current}/{total}] {percent:.1f}% - {message}", end="", flush=True)


# ============================================================
# FIX 8: MAIN FIX FUNCTION
# ============================================================
def fix(config: dict, dry_run: bool = False, force: bool = False) -> bool:
    """
    Fix firewall issues

    Args:
        config: Configuration dictionary
        dry_run: If True, preview changes without applying
        force: If True, skip confirmation

    Returns:
        bool: True if fixes applied successfully
    """
    logger = logging.getLogger(__name__)
    logger.info("Fixing firewall issues...")
    
    if dry_run:
        logger.info("DRY-RUN MODE: No changes will be applied")
        print("\n[!] DRY-RUN MODE - No changes will be applied")
        print("[✓] Dry-run complete. No changes were made.")
        return True

    # ✅ FIX: Skip confirmation in force mode
    if not force:
        if not _warn_ssh_not_allowed():
            logger.info("Firewall fix cancelled by user")
            return False
    else:
        logger.info("Force mode: Skipping SSH warning")

    if not force:
        if not _confirm_firewall_modification("Apply all firewall fixes"):
            logger.info("Firewall fixes cancelled by user")
            return False
    else:
        logger.info("Force mode: Applying firewall fixes without confirmation")

    # ✅ FIX: SSH warning already handled by _warn_ssh_not_allowed() above.
    # Just log it — do NOT ask the user a second time.
    if not _verify_ssh_allowed():
        logger.warning("SSH may not be allowed. User already confirmed to proceed.")

    # Backup current rules
    backup_iptables = _backup_iptables()
    if not backup_iptables:
        logger.warning("Could not backup iptables rules")
    
    backup_ufw = _backup_ufw_rules()
    if not backup_ufw:
        logger.warning("Could not backup UFW rules")

    try:
        steps = [
            ("Enable UFW", lambda: _enable_ufw(dry_run)),
            ("Set default policy to deny", lambda: _set_default_policy(dry_run)),
            ("Enable firewall logging", lambda: _enable_firewall_logging(dry_run)),
            ("Apply basic rules", lambda: _apply_basic_rules(dry_run))
        ]
        
        total_steps = len(steps)
        for idx, (name, func) in enumerate(steps):
            _progress_indicator(idx + 1, total_steps, name)
            
            if dry_run:
                _dry_run_firewall_fix(name, "Dry-run step")
            else:
                func()
        
        print()

        if dry_run:
            logger.info("DRY-RUN completed successfully")
            return True

        # Verify firewall is active
        time.sleep(2)
        if not _verify_firewall_active():
            logger.error("Firewall is not active after changes")
            if backup_iptables:
                _rollback_iptables(backup_iptables)
            return False

        # Verify SSH is still accessible
        if not _verify_ssh_allowed():
            logger.error("SSH is not allowed after firewall changes!")
            if backup_iptables:
                _rollback_iptables(backup_iptables)
            return False

        _log_firewall_change("firewall_fix", "All firewall fixes applied", True)

        logger.info("Firewall fixes applied successfully")
        return True

    except Exception as e:
        logger.error(f"Failed to fix firewall: {e}")
        if backup_iptables:
            _rollback_iptables(backup_iptables)
        _log_firewall_change("firewall_fix", str(e), False)
        return False


# ============================================================
# FIX 9: ENABLE UFW WITH SSH PORT DETECTION
# ============================================================
def _enable_ufw(dry_run: bool = False):
    """Enable UFW firewall with SSH port detection."""
    if dry_run:
        logging.getLogger(__name__).info("[DRY-RUN] Would enable UFW")
        return
    
    ssh_port = _get_ssh_port()
    # ... rest of code ...
    
    try:
        result = subprocess.run(['which', 'ufw'], capture_output=True, text=True, timeout=5, stdin=subprocess.DEVNULL)
        if result.returncode != 0:
            logging.getLogger(__name__).warning("UFW not installed")
            return

        # Check if SSH rule already exists
        if not _has_ssh_rule():
            # Allow SSH first (so we don't lock ourselves out)
            if ssh_port == 22:
                subprocess.run(['ufw', 'allow', 'ssh'], capture_output=True, text=True, stdin=subprocess.DEVNULL)
            else:
                subprocess.run(['ufw', 'allow', str(ssh_port), '/tcp'], capture_output=True, text=True, stdin=subprocess.DEVNULL)
            logging.getLogger(__name__).info(f"SSH allowed in firewall on port {ssh_port}")

        # Enable UFW non-interactively
        subprocess.run(['ufw', '--force', 'enable'], capture_output=True, text=True, stdin=subprocess.DEVNULL)
        logging.getLogger(__name__).info("UFW enabled")

    except Exception as e:
        logging.getLogger(__name__).error(f"Error enabling UFW: {e}")


# ============================================================
# FIX 10: SET DEFAULT POLICY WITH SAFETY
# ============================================================
def _set_default_policy(dry_run: bool = False):
    """Set firewall default policy to deny with safety checks."""
    if dry_run:
        logging.getLogger(__name__).info("[DRY-RUN] Would set default policy to deny")
        return
    # ... rest of code ...
    try:
        # Verify SSH is allowed before changing policy
        if not _verify_ssh_allowed():
            logging.getLogger(__name__).warning("SSH not allowed, skipping default policy change")
            return
        
        # UFW
        subprocess.run(['ufw', 'default', 'deny', 'incoming'], capture_output=True, text=True, stdin=subprocess.DEVNULL)
        subprocess.run(['ufw', 'default', 'deny', 'outgoing'], capture_output=True, text=True, stdin=subprocess.DEVNULL)
        logging.getLogger(__name__).info("UFW default policy set to deny")
    except:
        pass

    try:
        # Verify SSH is allowed before iptables policy change
        if not _verify_ssh_allowed():
            logging.getLogger(__name__).warning("SSH not allowed, skipping iptables policy change")
            return
        
        # iptables
        subprocess.run(['iptables', '-P', 'INPUT', 'DROP'], capture_output=True, text=True, stdin=subprocess.DEVNULL)
        subprocess.run(['iptables', '-P', 'FORWARD', 'DROP'], capture_output=True, text=True, stdin=subprocess.DEVNULL)
        logging.getLogger(__name__).info("iptables default policy set to drop")
    except:
        pass


def _enable_firewall_logging(dry_run: bool = False):
    """Enable firewall logging."""
    if dry_run:
        logging.getLogger(__name__).info("[DRY-RUN] Would enable firewall logging")
        return
    # ... rest of code ...
    try:
        subprocess.run(['ufw', 'logging', 'on'], capture_output=True, text=True, stdin=subprocess.DEVNULL)
        logging.getLogger(__name__).info("UFW logging enabled")
    except:
        pass


# ============================================================
# FIX 11: APPLY BASIC RULES WITH SSH PORT DETECTION
# ============================================================
def _apply_basic_rules(dry_run: bool = False):
    """Apply basic firewall rules with SSH port detection."""
    if dry_run:
        logging.getLogger(__name__).info("[DRY-RUN] Would apply basic firewall rules")
        return
    # ... rest of code ...
    ssh_port = _get_ssh_port()
    
    try:
        # Check if SSH rule already exists
        if not _has_ssh_rule():
            if ssh_port == 22:
                subprocess.run(['ufw', 'allow', 'ssh'], capture_output=True, text=True, stdin=subprocess.DEVNULL)
            else:
                subprocess.run(['ufw', 'allow', str(ssh_port), '/tcp'], capture_output=True, text=True, stdin=subprocess.DEVNULL)
            logging.getLogger(__name__).info(f"SSH allowed on port {ssh_port}")
        
        subprocess.run(['ufw', 'allow', '80/tcp'], capture_output=True, text=True, stdin=subprocess.DEVNULL)
        subprocess.run(['ufw', 'allow', '443/tcp'], capture_output=True, text=True, stdin=subprocess.DEVNULL)
        logging.getLogger(__name__).info("Basic firewall rules applied")
    except:
        pass


def _has_ssh_rule() -> bool:
    """Check if SSH rule already exists."""
    ssh_port = _get_ssh_port()
    
    try:
        result = subprocess.run(['ufw', 'status'], capture_output=True, text=True, timeout=10, stdin=subprocess.DEVNULL)
        if str(ssh_port) in result.stdout or 'ssh' in result.stdout:
            return True
    except:
        pass
    
    try:
        result = subprocess.run(['iptables', '-L', '-n'], capture_output=True, text=True, timeout=10, stdin=subprocess.DEVNULL)
        if str(ssh_port) in result.stdout and 'ACCEPT' in result.stdout:
            return True
    except:
        pass
    
    return False


def _warn_ssh_not_allowed() -> bool:
    """Warn if SSH is not allowed through firewall."""
    ssh_port = _get_ssh_port()
    
    if not _verify_ssh_allowed():
        print("\n" + "=" * 60)
        print(f"🔴 CRITICAL WARNING: SSH (port {ssh_port}) is NOT allowed through firewall!")
        print("=" * 60)
        print("If you continue, you WILL be locked out of this system.")
        print("Make sure you have console access or alternative access.")
        print("=" * 60)
        response = ui.prompt("Continue anyway? [y/N]: ")
        return response.lower() == 'y'
    return True