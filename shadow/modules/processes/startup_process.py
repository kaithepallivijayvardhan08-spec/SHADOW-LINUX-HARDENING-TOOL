#!/usr/bin/env python3
"""
Shadow Startup Process Module
=============================

Checks processes that start at boot.
"""

from shadow.core import ui
import os
import re
import logging
import shutil
import subprocess
import json
from pathlib import Path
from datetime import datetime
from typing import Tuple, Dict, List, Set

# ============================================================
# MODULE METADATA
# ============================================================
SEVERITY = "MEDIUM"
RECOMMENDATION = "Monitor processes and set resource limits for users"

CHANGES_LOG = Path("/var/log/shadow/changes.log")

# ============================================================
# TRANSACTION SUPPORT
# ============================================================
_transaction_active = False
_transaction_backups = []

def begin_transaction():
    global _transaction_active, _transaction_backups
    _transaction_active = True
    _transaction_backups = []

def add_to_transaction(backup_path: Path, original_path: Path):
    global _transaction_backups
    if _transaction_active:
        _transaction_backups.append({'backup_path': str(backup_path), 'original_path': str(original_path)})

def commit_transaction() -> bool:
    global _transaction_active, _transaction_backups
    _transaction_active = False
    _transaction_backups = []
    return True

def rollback_transaction() -> bool:
    global _transaction_active, _transaction_backups
    logger = logging.getLogger(__name__)
    restored = 0
    for backup_info in reversed(_transaction_backups):
        backup_path = Path(backup_info['backup_path'])
        original_path = Path(backup_info['original_path'])
        if backup_path.exists():
            try:
                shutil.copy2(backup_path, original_path)
                restored += 1
            except Exception as e:
                logger.error(f"Rollback failed for {original_path}: {e}")
    _transaction_active = False
    _transaction_backups = []
    return restored > 0

LEGITIMATE_SERVICES: Set[str] = {
    'systemd', 'systemd-journald', 'systemd-logind', 'systemd-networkd',
    'systemd-resolved', 'systemd-timesyncd', 'systemd-udevd',
    'systemd-modules-load', 'systemd-sysctl', 'systemd-random-seed',
    'systemd-backlight', 'systemd-hostnamed', 'systemd-localed',
    'systemd-timedated', 'systemd-user-sessions', 'systemd-vconsole-setup',
    'NetworkManager', 'NetworkManager-dispatcher', 'networkd-dispatcher',
    'dhcpcd', 'wpa_supplicant', 'avahi-daemon', 'bluetooth', 'ModemManager',
    'dbus', 'polkit', 'accounts-daemon', 'colord', 'cups', 'cups-browsed',
    'gdm3', 'lightdm', 'sddm', 'xdm', 'slim',
    'auditd', 'fail2ban', 'apparmor', 'ufw', 'clamav-daemon',
    'rkhunter', 'aide', 'tripwire',
    'rsyslog', 'syslog', 'syslog-ng', 'journald',
    'chrony', 'ntpd', 'ntpsec',
    'cron', 'crond', 'anacron', 'atd',
    'ssh', 'sshd',
    'mysql', 'mariadb', 'postgresql', 'redis', 'mongodb',
    'apache2', 'nginx', 'httpd',
    'docker', 'containerd', 'runc',
    'acpid', 'bluetooth', 'cups', 'dbus', 'gdm', 'lightdm'
}

SUSPICIOUS_PATTERNS = [
    'crypto', 'miner', 'xmrig', 'cpuminer', 'cgminer',
    'backdoor', 'reverse', 'shell', 'meterpreter',
    'trojan', 'worm', 'ransom', 'cryptolocker'
]

def _log_startup_findings(details: Dict, issues: List[str]):
    logger = logging.getLogger(__name__)
    log_entry = {
        "event": "startup_check",
        "details": {
            "init_d_scripts": len(details.get('init_d_scripts', [])),
            "systemd_services": len(details.get('systemd_services', [])),
            "rc_local_modified": details.get('rc_local_modified', False),
            "suspicious_startups": len(details.get('suspicious_startups', []))
        },
        "issues": issues,
        "timestamp": datetime.now().isoformat()
    }
    logger.info(f"STARTUP: {json.dumps(log_entry)}")
    
    try:
        CHANGES_LOG.parent.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(CHANGES_LOG, 'a') as f:
            f.write(f"{timestamp} - Startup Process Check Results:\n")
            f.write(f"  init.d Scripts: {len(details.get('init_d_scripts', []))}\n")
            f.write(f"  systemd Services (enabled): {len(details.get('systemd_services', []))}\n")
            f.write(f"  rc.local Modified: {details.get('rc_local_modified', False)}\n")
            f.write(f"  Suspicious Startups: {len(details.get('suspicious_startups', []))}\n")
            for issue in issues:
                f.write(f"  ISSUE: {issue}\n")
    except Exception as e:
        logger.warning(f"Failed to log startup findings: {e}")

def check(config: dict) -> Tuple[str, str, dict]:
    logger = logging.getLogger(__name__)
    logger.info("Checking startup processes...")

    issues = []
    details = {
        'init_d_scripts': [],
        'systemd_services': [],
        'rc_local_modified': False,
        'suspicious_startups': []
    }

    init_d = _check_init_d()
    details['init_d_scripts'] = init_d

    systemd = _check_systemd_services()
    details['systemd_services'] = systemd

    rc_local = _check_rc_local()
    details['rc_local_modified'] = rc_local
    if rc_local:
        issues.append("rc.local file exists (may contain startup commands)")

    suspicious = _check_suspicious_startups(init_d, systemd)
    details['suspicious_startups'] = suspicious
    if suspicious:
        for startup in suspicious:
            issues.append(f"Suspicious startup: {startup}")

    orphaned = _check_orphaned_init_d(init_d)
    if orphaned:
        for script in orphaned:
            issues.append(f"Orphaned init.d script: {script}")

    suspicious_content = _check_systemd_service_content(systemd)
    if suspicious_content:
        for service, reason in suspicious_content:
            issues.append(f"Suspicious content in {service}: {reason}")

    _log_startup_findings(details, issues)

    if issues:
        return 'WARN', f"{len(issues)} startup issues found", details
    return 'PASS', "Startup processes are clean", details

def _check_init_d() -> List[str]:
    scripts = []
    init_d_path = '/etc/init.d/'
    if os.path.exists(init_d_path):
        try:
            for item in Path(init_d_path).iterdir():
                if item.is_file() and os.access(item, os.X_OK):
                    scripts.append(item.name)
        except Exception: pass
    return scripts

def _check_systemd_services() -> List[str]:
    services = []
    try:
        result = subprocess.run(['systemctl', 'list-unit-files', '--type=service', '--no-pager'],
                              capture_output=True, text=True, timeout=30, stdin=subprocess.DEVNULL)
        for line in result.stdout.split('\n'):
            if '.service' in line and 'enabled' in line:
                parts = line.split()
                if parts:
                    service_name = parts[0]
                    if service_name.endswith('.service'):
                        service_name = service_name[:-8]
                    if service_name not in LEGITIMATE_SERVICES:
                        services.append(service_name)
    except Exception: pass
    return services[:30]

def _check_rc_local() -> bool:
    rc_local = '/etc/rc.local'
    if os.path.exists(rc_local):
        try:
            with open(rc_local, 'r') as f:
                content = f.read()
                if 'exit 0' not in content or len(content) > 100:
                    return True
        except Exception: return True
    return False

def _check_suspicious_startups(init_d: List[str], systemd: List[str]) -> List[str]:
    suspicious = []
    suspicious_names = ['atd', 'anacron', 'ntp', 'ntpd', 'chronyd']

    for script in init_d:
        if script in LEGITIMATE_SERVICES: continue
        for pattern in SUSPICIOUS_PATTERNS:
            if pattern in script.lower():
                suspicious.append(f"init.d/{script} (pattern: {pattern})")
                break
        if script in suspicious_names:
            suspicious.append(f"init.d/{script}")

    for service in systemd:
        if service in LEGITIMATE_SERVICES: continue
        for pattern in SUSPICIOUS_PATTERNS:
            if pattern in service.lower():
                suspicious.append(f"systemd/{service} (pattern: {pattern})")
                break
        for name in suspicious_names:
            if name in service.lower():
                suspicious.append(f"systemd/{service}")

    return suspicious[:20]

# ============================================================
# ✅ FIX: SMART ORPHAN CHECK (Ignores disabled/harmless legacy scripts)
# ============================================================
def _check_orphaned_init_d(init_d: List[str]) -> List[str]:
    """Check for init.d scripts that are truly orphaned and actively enabled."""
    orphaned = []
    
    # Known harmless legacy init.d scripts on Debian/Kali/Ubuntu kept for compatibility
    harmless_legacy = {
        'cryptdisks', 'cryptdisks-early', 'lm-sensors', 'x11-common', 
        'sysstat', 'apache-htcacheclean', 'smbd', 'nmbd', 'atftpd', 
        'smartmontools', 'redis-server', 'nfs-common', 'rpcbind',
        'sudo', 'rsync', 'saned', 'openbsd-inetd', 'nfs-kernel-server',
        'hwclock', 'console-setup', 'keyboard-setup'
    }

    for script in init_d:
        if script in LEGITIMATE_SERVICES or script in harmless_legacy:
            continue
            
        # ✅ FIX: Check if it's actually enabled in systemd. 
        # If it's disabled/masked/static, it's not running at boot, so it's not a risk.
        try:
            result = subprocess.run(
                ['systemctl', 'is-enabled', f'{script}.service'],
                capture_output=True, text=True, timeout=5, stdin=subprocess.DEVNULL)
            if result.stdout.strip() in ['disabled', 'masked', 'not-found', 'indirect', 'static']:
                continue
        except Exception:
            pass

        # Check if it belongs to an installed package
        try:
            result = subprocess.run(
                ['dpkg', '-S', f'/etc/init.d/{script}'],
                capture_output=True, text=True, timeout=5, stdin=subprocess.DEVNULL)
            if result.returncode == 0:
                continue
        except Exception:
            pass
            
        orphaned.append(script)

    return orphaned[:10]

# ============================================================
# ✅ FIX 14: REGEX WORD BOUNDARIES (Fixes 'nc' in 'function' bug)
# ============================================================
def _check_systemd_service_content(services: List[str]) -> List[Tuple[str, str]]:
    """Check systemd service files for suspicious content using exact word boundaries."""
    suspicious = []

    # ✅ FIX: Use regex \b (word boundaries) so 'nc' doesn't match 'function' or 'sync'
    dangerous_patterns = {
        'curl': r'\bcurl\b',
        'wget': r'\bwget\b',
        'nc': r'\bnc\b',
        'ncat': r'\bncat\b',
        'bash -i': r'\bbash\s+-i',
        'sh -i': r'\bsh\s+-i',
        'python -c': r'\bpython[23]?\s+-c',
        'perl -e': r'\bperl\s+-e',
        'chmod 777': r'\bchmod\s+777\b',
        'chmod +x': r'\bchmod\s+\+x',
        'rm -rf': r'\brm\s+-rf',
        'mkfifo': r'\bmkfifo\b'
    }

    for service in services:
        service_file = Path('/etc/systemd/system') / f"{service}.service"
        if not service_file.exists():
            for path in ['/lib/systemd/system/', '/usr/lib/systemd/system/']:
                alt_file = Path(path) / f"{service}.service"
                if alt_file.exists():
                    service_file = alt_file
                    break

        if service_file.exists():
            try:
                with open(service_file, 'r') as f:
                    content = f.read()
                    for name, pattern in dangerous_patterns.items():
                        if re.search(pattern, content):
                            suspicious.append((service, f"contains '{name}'"))
                            break
            except Exception: pass

    return suspicious

def fix(config: dict, dry_run: bool = False, force: bool = False) -> bool:
    logger = logging.getLogger(__name__)

    if dry_run:
        print("\n[!] DRY-RUN MODE - No changes will be applied")
        init_d = _check_init_d()
        systemd = _check_systemd_services()
        rc_local = _check_rc_local()
        suspicious = _check_suspicious_startups(init_d, systemd)
        
        print(f"  init.d scripts: {len(init_d)}")
        print(f"  systemd services: {len(systemd)}")
        print(f"  rc.local modified: {rc_local}")
        print(f"  Suspicious startups: {len(suspicious)}")
        print("\n[✓] Dry-run complete. No changes were made.")
        return True

    if not force:
        print("\n[!] WARNING: Startup process audit will be performed")
        response = ui.prompt("Proceed? [y/N]: ")
        if response.lower() != 'y':
            return False

    try:
        begin_transaction()
        try:
            CHANGES_LOG.parent.mkdir(parents=True, exist_ok=True)
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            with open(CHANGES_LOG, 'a') as f:
                f.write(f"{timestamp} - Startup Process Warning: Manual review required\n")
        except Exception: pass
        
        commit_transaction()
        print("\n✅ Startup audit completed")
        return True
    except Exception as e:
        logger.error(f"Failed to complete startup audit: {e}")
        rollback_transaction()
        return False