#!/usr/bin/env python3
"""
Shadow Resource Check Module
============================

Checks system resource usage.
"""

from shadow.core import ui
import os
import re
import logging
import shutil
import subprocess
import signal
import json
import time
from pathlib import Path
from datetime import datetime
from typing import Tuple, Dict, List, Optional

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

def _log_resource_findings(details: Dict, issues: List[str]):
    logger = logging.getLogger(__name__)
    log_entry = {
        "event": "resource_check",
        "details": {
            "total_memory": details.get('total_memory', 0),
            "used_memory": details.get('used_memory', 0),
            "free_memory": details.get('free_memory', 0),
            "swap_used": details.get('swap_used', 0),
            "zombie_processes": details.get('zombie_processes', 0),
            "memory_percent": details.get('memory_percent', 0),
            "load_average": details.get('load_average', [])
        },
        "issues": issues,
        "timestamp": datetime.now().isoformat()
    }
    logger.info(f"RESOURCE: {json.dumps(log_entry)}")
    
    try:
        CHANGES_LOG.parent.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(CHANGES_LOG, 'a') as f:
            f.write(f"{timestamp} - Resource Check Results:\n")
            f.write(f"  Total Memory: {details.get('total_memory', 0)} MB\n")
            f.write(f"  Used Memory: {details.get('used_memory', 0)} MB ({details.get('memory_percent', 0):.1f}%)\n")
            f.write(f"  Swap Used: {details.get('swap_used', 0)} MB\n")
            for issue in issues:
                f.write(f"  ISSUE: {issue}\n")
    except Exception: pass

def _log_resource_action(message: str):
    try:
        CHANGES_LOG.parent.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(CHANGES_LOG, 'a') as f:
            f.write(f"{timestamp} - Resource Action: {message}\n")
    except Exception: pass

def check(config: dict) -> Tuple[str, str, dict]:
    logger = logging.getLogger(__name__)
    logger.info("Checking system resources...")

    issues = []
    details = {
        'total_memory': 0, 'used_memory': 0, 'free_memory': 0,
        'swap_used': 0, 'swap_total': 0, 'zombie_processes': 0,
        'load_average': [], 'memory_percent': 0
    }

    mem_info = _get_memory_info()
    details.update(mem_info)

    memory_percent = (details['used_memory'] / details['total_memory'] * 100) if details['total_memory'] > 0 else 0
    details['memory_percent'] = memory_percent

    if memory_percent > 90:
        issues.append(f"Memory usage: {memory_percent:.1f}% (critical)")
    elif memory_percent > 80:
        issues.append(f"Memory usage: {memory_percent:.1f}% (warning)")

    # ✅ FIX 18: SMART SWAP CHECK (Ignores normal Linux swap caching on low-RAM VMs)
    swap_total = details.get('swap_total', 0)
    swap_used = details.get('swap_used', 0)
    
    if swap_total > 0:
        swap_percent = (swap_used / swap_total) * 100
        if swap_percent > 80 and swap_used > 100:
            issues.append(f"Swap usage critical: {swap_used} MB / {swap_total} MB ({swap_percent:.0f}%)")
        elif swap_used > 500 and memory_percent > 80:
            issues.append(f"High swap usage: {swap_used} MB (Memory at {memory_percent:.0f}%)")
    elif swap_used > 500:
        issues.append(f"High swap usage: {swap_used} MB")

    load = _get_load_average()
    details['load_average'] = load

    cpu_count = os.cpu_count() or 1
    if load and load[0] > cpu_count * 2:
        issues.append(f"Load average: {load[0]:.2f} (high)")
    elif load and load[0] > cpu_count * 1.5:
        issues.append(f"Load average: {load[0]:.2f} (elevated)")

    zombies = _get_zombie_processes()
    details['zombie_processes'] = zombies

    # ✅ FIX 18: Ignore 1-5 transient zombies
    if zombies > 5:
        issues.append(f"High number of zombie processes: {zombies}")

    fd_usage = _check_file_descriptors()
    if fd_usage.get('used', 0) / max(fd_usage.get('limit', 1), 1) > 0.8:
        issues.append(f"File descriptor usage: {fd_usage['used']} / {fd_usage['limit']} (high)")

    if _check_memory_pressure():
        issues.append("Severe memory pressure detected (possible OOM)")

    _log_resource_findings(details, issues)

    if issues:
        return 'WARN', f"{len(issues)} resource issues found", details
    return 'PASS', "System resources are normal", details


def _get_memory_info() -> Dict:
    info = {'total_memory': 0, 'used_memory': 0, 'free_memory': 0, 'swap_used': 0, 'swap_total': 0}
    try:
        result = subprocess.run(['free', '-m'], capture_output=True, text=True, timeout=10, stdin=subprocess.DEVNULL)
        for line in result.stdout.split('\n'):
            if line.startswith('Mem:'):
                parts = line.split()
                if len(parts) >= 4:
                    info['total_memory'] = int(parts[1])
                    info['used_memory'] = int(parts[2])
                    info['free_memory'] = int(parts[3])
            elif line.startswith('Swap:'):
                parts = line.split()
                if len(parts) >= 3:
                    info['swap_total'] = int(parts[1])
                    info['swap_used'] = int(parts[2])
    except Exception: pass
    return info


def _get_load_average() -> List[float]:
    load = []
    try:
        result = subprocess.run(['uptime'], capture_output=True, text=True, timeout=10, stdin=subprocess.DEVNULL)
        match = re.search(r'load average:\s+([\d.]+),\s+([\d.]+),\s+([\d.]+)', result.stdout)
        if match:
            load = [float(match.group(1)), float(match.group(2)), float(match.group(3))]
    except Exception: pass
    return load


def _get_zombie_processes() -> int:
    count = 0
    try:
        result = subprocess.run(['ps', 'aux'], capture_output=True, text=True, timeout=10, stdin=subprocess.DEVNULL)
        for line in result.stdout.split('\n'):
            if 'defunct' in line or 'Z' in line.split()[7] if len(line.split()) > 7 else False:
                count += 1
    except Exception: pass
    return count


def _check_file_descriptors() -> Dict:
    info = {'used': 0, 'limit': 0}
    try:
        fd_count = len(os.listdir('/proc/self/fd'))
        info['used'] = fd_count
        import resource
        info['limit'] = resource.getrlimit(resource.RLIMIT_NOFILE)[0]
    except Exception: pass
    return info


# ✅ FIX 18: ENVIRONMENT-AWARE MEMORY PRESSURE CHECK
def _check_memory_pressure() -> bool:
    """Check for severe memory pressure (OOM conditions) using PSI."""
    try:
        with open('/proc/pressure/memory', 'r') as f:
            content = f.read()
            for line in content.split('\n'):
                # 'full' means ALL non-idle tasks are stalled (real OOM freeze)
                if line.startswith('full'):
                    parts = line.split()
                    for part in parts:
                        if part.startswith('avg10='):
                            avg10 = float(part.split('=')[1])
                            if avg10 > 5.0:
                                return True
                # 'some' means at least one task is stalled (normal on VMs)
                # We raise the threshold to 25.0 to ignore normal VM background stalls
                if line.startswith('some'):
                    parts = line.split()
                    for part in parts:
                        if part.startswith('avg10='):
                            avg10 = float(part.split('=')[1])
                            if avg10 > 25.0:
                                return True
    except Exception:
        pass
    return False


def _kill_process_by_pid(pid: int, signal_type: int = signal.SIGTERM) -> bool:
    logger = logging.getLogger(__name__)
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    
    try:
        os.kill(pid, signal_type)
        time.sleep(1)
        try:
            os.kill(pid, 0)
            if signal_type != signal.SIGKILL:
                os.kill(pid, signal.SIGKILL)
                time.sleep(1)
                try:
                    os.kill(pid, 0)
                    return False
                except OSError:
                    return True
        except OSError:
            return True
    except Exception:
        return False


def _kill_zombie_processes() -> int:
    logger = logging.getLogger(__name__)
    killed = 0
    try:
        result = subprocess.run(['ps', 'aux'], capture_output=True, text=True, timeout=10, stdin=subprocess.DEVNULL)
        for line in result.stdout.split('\n'):
            if 'defunct' in line:
                parts = line.split()
                if len(parts) >= 2:
                    pid = int(parts[1])
                    ppid = int(parts[2]) if len(parts) > 2 else None
                    if ppid and ppid > 1:
                        if _kill_process_by_pid(ppid, signal.SIGCHLD):
                            killed += 1
                        elif _kill_process_by_pid(pid, signal.SIGKILL):
                            killed += 1
    except Exception: pass
    return killed


def fix(config: dict, dry_run: bool = False, force: bool = False) -> bool:
    logger = logging.getLogger(__name__)

    if dry_run:
        print("\n[!] DRY-RUN MODE - No changes will be applied")
        mem_info = _get_memory_info()
        if mem_info.get('total_memory', 0) > 0:
            memory_percent = (mem_info.get('used_memory', 0) / mem_info.get('total_memory', 1) * 100)
            print(f"  Memory usage: {memory_percent:.1f}%")
        print("\n[✓] Dry-run complete. No changes were made.")
        return True

    if not force:
        print("\n[!] WARNING: Resource fixes will be applied")
        response = ui.prompt("Proceed? [y/N]: ")
        if response.lower() != 'y': return False

    try:
        begin_transaction()
        killed = 0
        
        kill_zombies = config.get('process', {}).get('kill_zombies', False)
        if kill_zombies:
            killed = _kill_zombie_processes()
            if killed > 0:
                print(f"\n Killed {killed} zombie processes")

        mem_info = _get_memory_info()
        if mem_info.get('total_memory', 0) > 0:
            memory_percent = (mem_info.get('used_memory', 0) / mem_info.get('total_memory', 1) * 100)
            if memory_percent > 90:
                print(f"\n High memory usage: {memory_percent:.1f}%")

        if _check_memory_pressure():
            print("\n Severe memory pressure detected - possible OOM")

        commit_transaction()
        print("\n✅ Resource checks completed successfully")
        return True
    except Exception as e:
        logger.error(f"Failed to fix resource issues: {e}")
        rollback_transaction()
        return False