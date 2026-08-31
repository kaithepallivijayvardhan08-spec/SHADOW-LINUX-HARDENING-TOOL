#!/usr/bin/env python3
"""
Shadow Process Audit Module
===========================

Audits running processes for security issues.
"""

from shadow.core import ui
import os
import re
import logging
import shutil
import subprocess
import hashlib
import json
from pathlib import Path
from datetime import datetime
from typing import Tuple, Dict, List, Optional, Set

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
            except Exception: pass
    _transaction_active = False
    _transaction_backups = []
    return restored > 0

# ============================================================
# LEGITIMATE PROCESS PATTERNS - SKIP THESE
# ============================================================
LEGITIMATE_PATTERNS: Set[str] = {
    'systemd', 'dbus', 'polkit', 'gnome', 'gdm', 'lightdm',
    'sddm', 'xorg', 'Xorg', 'udev', 'kernel', 'init',
    'sshd', 'cron', 'rsyslog', 'auditd', 'NetworkManager', 'ModemManager',
    'accounts-daemon', 'bluetooth', 'cups', 'docker', 'containerd',
    'bash', 'sh', 'zsh', 'fish', 'python', 'python3',
    'grep', 'awk', 'sed', 'ps', 'top', 'htop', 'less', 'more',
    'vim', 'nano', 'tmux', 'screen', 'cat', 'echo', 'ls',
    'sleep', 'kill', 'pkill', 'killall', 'mount', 'umount',
    'node', 'npm', 'java', 'gcc', 'make', 'git',
    'clamav', 'rkhunter', 'chkrootkit', 'aide',
    'fail2ban', 'rsyslogd', 'haveged', 'vboxservice', 'vboxdrmclient',
    'networkmanager', 'wpa_supplicant', 'avahi-daemon'
}

LEGITIMATE_PATHS: Set[str] = {
    '/usr/bin/', '/usr/sbin/', '/bin/', '/sbin/',
    '/lib/', '/lib64/', '/usr/lib/', '/usr/lib64/',
    '/usr/local/bin/', '/usr/local/sbin/', '/opt/',
    '/snap/', '/var/lib/', '/usr/share/', '/usr/libexec/'
}

# ============================================================
# STRUCTURED LOGGING
# ============================================================
def _log_process_audit_findings(details: Dict, issues: List[str]):
    logger = logging.getLogger(__name__)
    log_entry = {
        "event": "process_audit",
        "details": {
            "total_processes": details.get('total_processes', 0),
            "suspicious_names": len(details.get('suspicious_names', [])),
            "temp_processes": len(details.get('temp_processes', [])),
            "high_cpu": len(details.get('high_cpu', []))
        },
        "issues": issues,
        "timestamp": datetime.now().isoformat()
    }
    logger.info(f"PROCESS_AUDIT: {json.dumps(log_entry)}")
    
    try:
        CHANGES_LOG.parent.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(CHANGES_LOG, 'a') as f:
            f.write(f"{timestamp} - Process Audit Results:\n")
            f.write(f"  Total Processes: {details.get('total_processes', 0)}\n")
            for issue in issues:
                f.write(f"  ISSUE: {issue}\n")
    except Exception: pass

def _log_process_audit_warning(message: str):
    try:
        CHANGES_LOG.parent.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(CHANGES_LOG, 'a') as f:
            f.write(f"{timestamp} - Process Audit Warning: {message}\n")
    except Exception: pass

# ============================================================
# CHECK FUNCTION
# ============================================================
def check(config: dict) -> Tuple[str, str, dict]:
    logger = logging.getLogger(__name__)
    logger.info("Auditing processes...")

    issues = []
    details = {
        'total_processes': 0, 'suspicious_names': [],
        'temp_processes': [], 'high_cpu': [], 'orphaned': []
    }

    processes = _get_processes()
    details['total_processes'] = len(processes)

    suspicious = _check_suspicious_names(processes)
    details['suspicious_names'] = suspicious
    if suspicious:
        for proc in suspicious[:5]:
            issues.append(f"Suspicious process: {proc['pid']} ({proc['cmd'][:80]})")

    temp = _check_temp_processes(processes)
    details['temp_processes'] = temp
    if temp:
        for proc in temp[:5]:
            issues.append(f"Process from temp: {proc['pid']} ({proc['cmd'][:80]})")

    high_cpu = _check_high_cpu(processes)
    details['high_cpu'] = high_cpu
    if high_cpu:
        for proc in high_cpu[:5]:
            issues.append(f"High CPU process: {proc['pid']} ({proc['cpu']}%) - {proc['cmd'][:50]}")

    orphaned = _check_orphaned_processes()
    details['orphaned'] = orphaned
    if orphaned:
        for proc in orphaned[:5]:
            issues.append(f"Orphaned process: {proc['pid']} (PPID: {proc['ppid']}) - {proc['cmd'][:50]}")

    hidden = _check_hidden_processes()
    if hidden:
        issues.append(f"Hidden processes detected: {len(hidden)}")

    _log_process_audit_findings(details, issues)

    if issues:
        return 'WARN', f"{len(issues)} process issues found", details
    return 'PASS', "Processes appear normal", details

def _get_processes() -> List[Dict]:
    processes = []
    try:
        result = subprocess.run(['ps', 'aux', '--no-headers'], capture_output=True, text=True, timeout=10, stdin=subprocess.DEVNULL)
        for line in result.stdout.split('\n'):
            if line.strip():
                parts = line.split(None, 10)
                if len(parts) >= 11:
                    processes.append({
                        'user': parts[0], 'pid': parts[1],
                        'cpu': float(parts[2]) if parts[2] != '0.0' else 0.0,
                        'mem': float(parts[3]) if parts[3] != '0.0' else 0.0,
                        'cmd': parts[10],
                        'path': parts[10].split()[0] if parts[10] else ''
                    })
    except Exception: pass
    return processes

# ✅ FIX: Corrected case-sensitivity bug
def _is_legitimate_process(cmd: str, path: str) -> bool:
    if not cmd: return False
    cmd_lower = cmd.lower()
    for legit in LEGITIMATE_PATTERNS:
        if legit.lower() in cmd_lower: return True
    if path:
        path_lower = path.lower()
        for legit_path in LEGITIMATE_PATHS:
            if path_lower.startswith(legit_path.lower()): return True
    return False

def _check_suspicious_names(processes: List[Dict]) -> List[Dict]:
    suspicious = []
    patterns = ['miner', 'crypto', 'xmrig', 'xmr-stak', 'cpuminer']
    for proc in processes:
        cmd = proc.get('cmd', '').lower()
        path = proc.get('path', '').lower()
        if _is_legitimate_process(cmd, path): continue
        for pattern in patterns:
            if pattern in cmd:
                suspicious.append(proc)
                break
    return suspicious

def _check_temp_processes(processes: List[Dict]) -> List[Dict]:
    temp = []
    for proc in processes:
        cmd = proc.get('cmd', '')
        path = proc.get('path', '')
        if _is_legitimate_process(cmd, path): continue
        if '/tmp/' in cmd or '/dev/shm/' in cmd or '/var/tmp/' in cmd:
            temp.append(proc)
    return temp

def _check_high_cpu(processes: List[Dict]) -> List[Dict]:
    high = []
    for proc in processes:
        if proc.get('cpu', 0) > 80:
            if _is_legitimate_process(proc.get('cmd', ''), proc.get('path', '')): continue
            high.append(proc)
    return high

# ✅ FIX 15: Ignore standard system daemons AND resolve short paths like 'xcape'
def _check_orphaned_processes() -> List[Dict]:
    orphaned = []
    daemon_paths = ['/usr/sbin/', '/usr/bin/', '/sbin/', '/bin/', '/usr/libexec/', '/usr/lib/']

    try:
        result = subprocess.run(['ps', '-eo', 'pid,ppid,cmd', '--no-headers'],
                              capture_output=True, text=True, timeout=10, stdin=subprocess.DEVNULL)

        if result.returncode == 0:
            for line in result.stdout.split('\n'):
                if line.strip():
                    parts = line.split(None, 2)
                    if len(parts) >= 3:
                        pid = parts[0]
                        ppid = parts[1]
                        cmd = parts[2]

                        if ppid == '1' and 'init' not in cmd and 'systemd' not in cmd:
                            # ✅ FIX: Resolve the actual binary path (e.g., 'xcape' -> '/usr/bin/xcape')
                            import shutil
                            bin_name = cmd.split()[0]
                            bin_path = shutil.which(bin_name) or bin_name
                            
                            if any(bin_path.startswith(d_path) for d_path in daemon_paths):
                                continue
                            if _is_legitimate_process(cmd, ''):
                                continue
                            orphaned.append({'pid': pid, 'ppid': ppid, 'cmd': cmd[:80]})
    except Exception: pass

    return orphaned

# ✅ FIX: Prevent race-condition false positives for short-lived tasks
def _check_hidden_processes() -> List[str]:
    hidden = []
    try:
        proc_dirs = [d.name for d in Path('/proc').iterdir() if d.is_dir() and d.name.isdigit()]
        ps_result = subprocess.run(['ps', '-e', '-o', 'pid='], capture_output=True, text=True, timeout=10, stdin=subprocess.DEVNULL)
        ps_pids = set(ps_result.stdout.split())
        for pid in proc_dirs:
            if pid not in ps_pids:
                # If the process is already gone from /proc, it was just a short-lived task
                if not os.path.exists(f"/proc/{pid}"):
                    continue
                # Ignore kernel threads (they don't have a cmdline)
                try:
                    with open(f"/proc/{pid}/cmdline", 'r') as f:
                        if not f.read().strip():
                            continue
                except Exception:
                    continue
                hidden.append(pid)
    except Exception: pass
    return hidden

# ✅ FIX: Disabled dummy hash checking which caused endless false warnings
def _verify_process_signatures(processes: List[Dict]):
    """Real hash verification is handled by the integrity/hash_monitor module."""
    pass

def fix(config: dict, dry_run: bool = False, force: bool = False) -> bool:
    logger = logging.getLogger(__name__)

    if dry_run:
        print("\n[!] DRY-RUN MODE - No changes will be applied")
        processes = _get_processes()
        print(f"  Total processes: {len(processes)}")
        print("\n[✓] Dry-run complete. No changes were made.")
        return True

    if not force:
        print("\n[!] WARNING: Process audit will be performed")
        response = ui.prompt("Proceed? [y/N]: ")
        if response.lower() != 'y': return False

    try:
        begin_transaction()
        try:
            CHANGES_LOG.parent.mkdir(parents=True, exist_ok=True)
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            with open(CHANGES_LOG, 'a') as f:
                f.write(f"{timestamp} - Process Audit Warning: Manual investigation required\n")
        except Exception: pass
        
        commit_transaction()
        print("\n✅ Process audit completed")
        return True
    except Exception:
        rollback_transaction()
        return False