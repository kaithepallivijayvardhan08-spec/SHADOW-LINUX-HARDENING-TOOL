#!/usr/bin/env python3
"""
Shadow Suspicious Process Module
================================

Checks for suspicious running processes:
- Processes running as root
- Processes with unusual names
- Processes from suspicious locations
- High resource usage processes
- Hidden processes
- Orphaned processes
- Process anomalies
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
RECOMMENDATION = "Monitor suspicious processes and investigate anomalies"

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

LEGITIMATE_PROCESSES: Set[str] = {
    'kworker', 'kthreadd', 'ksoftirqd', 'migration', 'rcu_sched',
    'rcuos', 'rcuob', 'watchdog', 'khungtaskd', 'oom_reaper',
    'writeback', 'jbd2', 'ext4', 'xfs', 'kdevtmpfs', 'khelper',
    'kblockd', 'kjournald', 'netns', 'systemd-journald',
    'sshd', 'cron', 'systemd', 'systemd-logind',
    'auditd', 'dbus-daemon', 'polkitd', 'NetworkManager', 'accounts-daemon',
    'gnome-shell', 'lightdm', 'gdm', 'sddm', 'xorg', 'Xorg',
    'bash', 'sh', 'zsh', 'fish', 'python', 'python3', 'python2',
    'node', 'npm', 'java', 'gcc', 'make', 'git', 'vim', 'nano',
    'tmux', 'screen', 'htop', 'top', 'ps', 'grep', 'awk', 'sed',
    'docker', 'containerd', 'runc', 'kubelet', 'kubectl', 'kube-apiserver',
    'shadow', 'main.py'
}

LEGITIMATE_PATHS: Set[str] = {
    '/usr/bin/', '/usr/sbin/', '/bin/', '/sbin/', '/lib/', '/lib64/',
    '/usr/lib/', '/usr/lib64/', '/usr/local/bin/', '/usr/local/sbin/',
    '/opt/', '/snap/', '/var/lib/', '/usr/share/', '/usr/libexec/', '/run/'
}

def _log_process_warnings(warnings: List[str], issues: List[str]):
    logger = logging.getLogger(__name__)
    log_entry = {
        "event": "process_warning",
        "warnings": warnings[:10],
        "issues": issues[:10],
        "total_warnings": len(warnings),
        "total_issues": len(issues),
        "timestamp": datetime.now().isoformat()
    }
    logger.info(f"PROCESS: {json.dumps(log_entry)}")
    
    try:
        CHANGES_LOG.parent.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(CHANGES_LOG, 'a') as f:
            f.write(f"{timestamp} - Process Check Warnings:\n")
            for warning in warnings[:10]:
                f.write(f"  WARNING: {warning}\n")
            for issue in issues[:10]:
                f.write(f"  ISSUE: {issue}\n")
    except Exception: pass

def _log_process_warning(message: str):
    try:
        CHANGES_LOG.parent.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(CHANGES_LOG, 'a') as f:
            f.write(f"{timestamp} - Process Warning: {message}\n")
    except Exception: pass

def _is_legitimate_process_full(process_name: str, cmdline: str = "", path: str = "") -> bool:
    if 'shadow' in cmdline.lower() and ('main.py' in cmdline or '/opt/shadow' in cmdline):
        return True
    for legit in LEGITIMATE_PROCESSES:
        if legit in process_name.lower(): return True
    if path:
        for legit_path in LEGITIMATE_PATHS:
            if path.startswith(legit_path): return True
    if cmdline:
        for legit in LEGITIMATE_PROCESSES:
            if legit in cmdline.lower(): return True
    return False

def check(config: dict) -> Tuple[str, str, dict]:
    logger = logging.getLogger(__name__)
    logger.info("Checking suspicious processes...")

    issues = []
    warnings = []
    details = {
        'total_processes': 0, 'root_processes': [], 'processes_from_tmp': [],
        'processes_from_dev': [], 'high_cpu_processes': [], 'high_memory_processes': [],
        'hidden_processes': [], 'orphaned_processes': [], 'suspicious_names': [],
        'known_good_processes': []
    }

    processes = _get_processes()
    details['total_processes'] = len(processes)

    root_processes = [p for p in processes if p.get('user') == 'root']
    details['root_processes'] = root_processes
    if len(root_processes) > 50:
        warnings.append(f"High number of root processes: {len(root_processes)}")

    tmp_processes = [p for p in processes if '/tmp/' in p.get('cmdline', '')]
    if tmp_processes:
        filtered = [p for p in tmp_processes if not _is_legitimate_process_full('', p.get('cmdline', ''), '')]
        if filtered:
            details['processes_from_tmp'] = filtered
            for proc in filtered[:10]:
                issues.append(f"Process running from /tmp: {proc['pid']} ({proc['cmdline'][:50]}...)")

    dev_processes = [p for p in processes if '/dev/shm/' in p.get('cmdline', '')]
    if dev_processes:
        filtered = [p for p in dev_processes if not _is_legitimate_process_full('', p.get('cmdline', ''), '')]
        if filtered:
            details['processes_from_dev'] = filtered
            for proc in filtered[:10]:
                issues.append(f"Process running from /dev/shm: {proc['pid']} ({proc['cmdline'][:50]}...)")

    high_cpu = [p for p in processes if p.get('cpu', 0) > 80]
    if high_cpu:
        filtered = [p for p in high_cpu if not _is_legitimate_process_full('', p.get('cmdline', ''), '')]
        if filtered:
            details['high_cpu_processes'] = filtered
            for proc in filtered[:5]:
                warnings.append(f"High CPU process: {proc['pid']} ({proc.get('cmdline', 'unknown')[:30]}) CPU: {proc['cpu']}%")

    high_memory = [p for p in processes if p.get('memory', 0) > 30]
    if high_memory:
        filtered = [p for p in high_memory if not _is_legitimate_process_full('', p.get('cmdline', ''), '')]
        if filtered:
            details['high_memory_processes'] = filtered
            for proc in filtered[:5]:
                warnings.append(f"High memory process: {proc['pid']} ({proc.get('cmdline', 'unknown')[:30]}) MEM: {proc['memory']}%")

    suspicious_names = _check_suspicious_names(processes)
    if suspicious_names:
        details['suspicious_names'] = suspicious_names
        for proc in suspicious_names[:10]:
            issues.append(f"Suspicious process name: {proc['pid']} ({proc['cmdline'][:50]})")

    hidden = _check_hidden_processes()
    if hidden:
        details['hidden_processes'] = hidden
        for proc in hidden[:5]:
            warnings.append(f"Hidden process detected: {proc}")

    orphaned = _check_orphaned_processes()
    if orphaned:
        details['orphaned_processes'] = orphaned
        for proc in orphaned[:5]:
            warnings.append(f"Orphaned process: {proc['pid']} (PPID: {proc['ppid']})")

    impersonated = _check_process_impersonation(processes)
    if impersonated:
        for proc in impersonated[:5]:
            warnings.append(f"Process may be impersonating: {proc['pid']} ({proc['cmdline'][:50]})")

    unusual_paths = _check_unusual_paths(processes)
    if unusual_paths:
        for proc in unusual_paths[:5]:
            warnings.append(f"Process from unusual location: {proc['pid']} ({proc['path']})")

    if warnings or issues:
        _log_process_warnings(warnings, issues)

    _verify_process_signatures(processes)

    if issues:
        critical = [i for i in issues if '/tmp/' in i or '/dev/shm/' in i]
        status = 'FAIL' if critical else 'WARN'
        message = f"{len(issues)} critical process issues found" if critical else f"{len(issues)} process issues found"
    elif warnings:
        status = 'WARN'
        message = f"{len(warnings)} process warnings found"
    else:
        status = 'PASS'
        message = "No suspicious processes detected"

    return status, message, details

def _get_processes() -> List[Dict]:
    processes = []
    try:
        result = subprocess.run(['ps', 'aux', '--sort=-%cpu', '--no-headers'], capture_output=True, text=True, timeout=10, stdin=subprocess.DEVNULL)
        if result.returncode == 0:
            for line in result.stdout.split('\n'):
                if not line.strip(): continue
                parts = line.split(None, 10)
                if len(parts) >= 11:
                    process = {
                        'user': parts[0], 'pid': parts[1],
                        'cpu': float(parts[2]) if parts[2] != '0.0' else 0.0,
                        'memory': float(parts[3]) if parts[3] != '0.0' else 0.0,
                        'vsz': parts[4], 'rss': parts[5], 'tty': parts[6],
                        'stat': parts[7], 'start': parts[8], 'time': parts[9],
                        'cmdline': parts[10] if len(parts) > 10 else ''
                    }
                    cmdline = process['cmdline']
                    if cmdline and cmdline[0] != '[':
                        process['path'] = cmdline.split()[0] if cmdline else ''
                    processes.append(process)
    except Exception: pass
    return processes

def _check_suspicious_names(processes: List[Dict]) -> List[Dict]:
    suspicious = []
    suspicious_patterns = ['miner', 'crypto', 'xmrig', 'cpuminer', 'cgminer', 'bfgminer', 'xmr-stak', 'cryptonight']
    for proc in processes:
        cmdline = proc.get('cmdline', '')
        if not cmdline: continue
        if _is_legitimate_process_full('', cmdline, ''): continue
        for pattern in suspicious_patterns:
            if pattern in cmdline.lower():
                suspicious.append(proc)
                break
    return suspicious

# ✅ FIX: Improved hidden process detection to prevent race-condition false positives
def _check_hidden_processes() -> List[str]:
    hidden = []
    try:
        proc_dirs = [d.name for d in Path('/proc').iterdir() if d.is_dir() and d.name.isdigit()]
        ps_result = subprocess.run(['ps', '-e', '-o', 'pid='], capture_output=True, text=True, timeout=10, stdin=subprocess.DEVNULL)
        ps_pids = set(ps_result.stdout.split())

        for pid in proc_dirs:
            if pid not in ps_pids:
                # If the process is already gone from /proc, it was just a short-lived task (race condition)
                if not os.path.exists(f"/proc/{pid}"):
                    continue
                # Ignore kernel threads (they don't have an exe or cmdline)
                try:
                    with open(f"/proc/{pid}/cmdline", 'r') as f:
                        if not f.read().strip():
                            continue
                except Exception:
                    continue
                hidden.append(pid)
    except Exception: pass
    return hidden[:20]

# ✅ FIX 15: Ignore standard system daemons AND resolve short paths
def _check_orphaned_processes() -> List[Dict]:
    orphaned = []
    daemon_paths = ['/usr/sbin/', '/usr/bin/', '/sbin/', '/bin/', '/usr/libexec/', '/usr/lib/', '/opt/']
    
    # Known safe daemon names that often run with PPID 1
    safe_daemon_names = {
        'haveged', 'NetworkManager', 'ModemManager', 'VBoxService', 'VBoxDRMClient',
        'accounts-daemon', 'polkitd', 'rsyslogd', 'auditd', 'cron', 'sshd',
        'dbus-daemon', 'systemd-logind', 'xcape', 'wpa_supplicant', 'avahi-daemon',
        'bluetoothd', 'cupsd', 'snapd', 'dockerd', 'containerd'
    }

    try:
        result = subprocess.run(['ps', '-eo', 'pid,ppid,cmd', '--no-headers'], capture_output=True, text=True, timeout=10, stdin=subprocess.DEVNULL)
        if result.returncode == 0:
            for line in result.stdout.split('\n'):
                if line.strip():
                    parts = line.split(None, 2)
                    if len(parts) >= 3:
                        pid, ppid, cmd = parts[0], parts[1], parts[2]
                        if ppid == '1' and 'init' not in cmd and 'systemd' not in cmd:
                            # Check if it's a known safe daemon by name
                            bin_name = cmd.split()[0].split('/')[-1]
                            if bin_name in safe_daemon_names:
                                continue
                                
                            # Resolve short paths (e.g., 'xcape' -> '/usr/bin/xcape')
                            import shutil
                            bin_path = shutil.which(bin_name) or cmd.split()[0]
                            
                            if any(bin_path.startswith(d_path) for d_path in daemon_paths): 
                                continue
                            if 'shadow' in cmd and 'main.py' in cmd: 
                                continue
                                
                            orphaned.append({'pid': pid, 'ppid': ppid, 'cmd': cmd[:50]})
    except Exception: pass
    return orphaned

# ✅ FIX 12: Fixed impersonation false positives (ignores own tool, strips colons, checks cmdline paths)
def _check_process_impersonation(processes: List[Dict]) -> List[Dict]:
    impersonated = []
    my_pid = str(os.getpid())
    my_ppid = str(os.getppid())

    # Only these exact binary names are worth checking for impersonation
    critical_binaries = {'sshd', 'cron', 'crond', 'systemd', 'init', 'sudo', 'su', 'polkitd'}
    
    # Safe directories where these binaries SHOULD live
    safe_dirs = ('/usr/sbin/', '/usr/bin/', '/sbin/', '/bin/', '/lib/systemd/', '/usr/lib/', '/opt/shadow/')

    for proc in processes:
        cmdline = proc.get('cmdline', '')
        path = proc.get('path', '')
        pid = proc.get('pid', '')

        if not cmdline or not path or not pid: continue
        if pid in (my_pid, my_ppid): continue
        
        # ✅ FIX: Ignore our own tool and sudo wrapper
        if 'shadow' in cmdline and ('main.py' in cmdline or '/opt/shadow' in cmdline): continue
        if 'sudo' in cmdline and 'shadow' in cmdline: continue

        # Strip trailing colon (e.g., 'sshd:' becomes 'sshd')
        bin_name = os.path.basename(path).rstrip(':') 
        
        if bin_name in critical_binaries:
            # If the cmdline contains a safe path, it's the real binary (e.g. 'sshd: /usr/sbin/sshd -D')
            if any(safe in cmdline for safe in safe_dirs):
                continue
            if any(path.startswith(safe) for safe in safe_dirs):
                continue
            
            # Only flag if it's running from a dangerous location like /tmp or /dev/shm
            impersonated.append({'pid': pid, 'cmdline': cmdline[:50], 'path': path})
                
    return impersonated

def _check_unusual_paths(processes: List[Dict]) -> List[Dict]:
    unusual = []
    unusual_dirs = ['/tmp', '/var/tmp', '/dev/shm', '/root']
    for proc in processes:
        path = proc.get('path', '')
        if not path: continue
        if _is_legitimate_process_full('', '', path): continue
        for unusual_dir in unusual_dirs:
            if unusual_dir in path:
                unusual.append({'pid': proc['pid'], 'path': path, 'cmdline': proc.get('cmdline', '')[:50]})
                break
    return unusual

def _verify_process_signatures(processes: List[Dict]):
    """Real hash verification is handled by the integrity/hash_monitor module."""
    pass

def fix(config: dict, dry_run: bool = False, force: bool = False) -> bool:
    logger = logging.getLogger(__name__)
    logger.info("Processing suspicious process findings...")

    if dry_run:
        print("\n[!] DRY-RUN MODE - No changes will be applied")
        processes = _get_processes()
        print(f"  Total processes: {len(processes)}")
        print("\n[✓] Dry-run complete. No changes were made.")
        return True

    if not force:
        print("\n[!] WARNING: Process scanning will be performed")
        response = ui.prompt("Proceed? [y/N]: ")
        if response.lower() != 'y': return False

    try:
        begin_transaction()
        if config.get('process', {}).get('warn_suspicious', True):
            _warn_suspicious_processes()
        commit_transaction()
        print("\n✅ Process checks completed successfully")
        return True
    except Exception as e:
        logger.error(f"Failed to complete process checks: {e}")
        rollback_transaction()
        return False

def _warn_suspicious_processes():
    processes = _get_processes()
    suspicious_names = _check_suspicious_names(processes)
    for proc in suspicious_names[:10]:
        logging.getLogger(__name__).warning(f"Suspicious process found: PID {proc['pid']} - {proc['cmdline'][:50]}")
        _log_process_warning(f"Suspicious process: PID {proc['pid']} - {proc['cmdline'][:50]}")

    high_cpu = [p for p in processes if p.get('cpu', 0) > 100]
    for proc in high_cpu:
        cmdline = proc.get('cmdline', '')
        if cmdline and any(miner in cmdline.lower() for miner in ['miner', 'crypto', 'xmrig']):
            if _is_legitimate_process_full('', cmdline, ''): continue
            logging.getLogger(__name__).warning(f"Potential crypto miner: PID {proc['pid']} - {cmdline[:50]}")
            _log_process_warning(f"Potential crypto miner: PID {proc['pid']} - {cmdline[:50]}")