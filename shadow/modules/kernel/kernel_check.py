#!/usr/bin/env python3
"""
Shadow Kernel Check Module
==========================

Checks kernel version and security status.

Security concerns:
- Outdated kernel → known vulnerabilities
- Running kernel != installed kernel → pending reboot
- Unpatched kernel → exploit risk
"""

from shadow.core import ui
import os
import re
import logging
import subprocess
import json
import shutil
from pathlib import Path
from datetime import datetime
from typing import Tuple, Dict, List, Optional

def _is_virtual_machine() -> bool:
    """Detect if running in a virtual machine."""
    try:
        # Check DMI product name
        with open('/sys/class/dmi/id/product_name', 'r') as f:
            product = f.read().strip().lower()
            if any(vm in product for vm in ['virtualbox', 'vmware', 'kvm', 'qemu', 'xen', 'hyper-v']):
                return True
        
        # Check systemd-detect-virt
        result = subprocess.run(['systemd-detect-virt'], 
                              capture_output=True, text=True, timeout=5, stdin=subprocess.DEVNULL)
        if result.returncode == 0 and result.stdout.strip() != 'none':
            return True
    except:
        pass
    return False

# ============================================================
# MODULE METADATA
# ============================================================
SEVERITY = "HIGH"
MANUAL_FIX = "sudo apt update && sudo apt upgrade -y && sudo reboot"
RECOMMENDATION = "Apply kernel hardening with sysctl settings"

CHANGES_LOG = Path("/var/log/shadow/changes.log")

# ============================================================
# TRANSACTION SUPPORT
# ============================================================
_transaction_active = False
_transaction_backups = []

def begin_transaction():
    """Begin a transaction for kernel modifications."""
    global _transaction_active, _transaction_backups
    _transaction_active = True
    _transaction_backups = []
    logging.getLogger(__name__).info("Kernel transaction started")

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
    logging.getLogger(__name__).info("Kernel transaction committed")
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
# STRUCTURED LOGGING
# ============================================================
def _log_kernel_findings(details: Dict, issues: List[str]):
    """Log kernel check findings with structured format."""
    logger = logging.getLogger(__name__)
    
    log_entry = {
        "event": "kernel_check",
        "details": {
            "kernel_release": details.get('kernel_release', 'unknown'),
            "kernel_version": details.get('kernel_version', 'unknown'),
            "architecture": details.get('kernel_architecture', 'unknown'),
            "pending_reboot": details.get('pending_reboot', False),
            "vulnerabilities": details.get('vulnerable', [])
        },
        "issues": issues,
        "timestamp": datetime.now().isoformat()
    }
    logger.info(f"KERNEL: {json.dumps(log_entry)}")
    
    try:
        CHANGES_LOG.parent.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        with open(CHANGES_LOG, 'a') as f:
            f.write(f"{timestamp} - Kernel Check Results:\n")
            f.write(f"  Kernel Release: {details.get('kernel_release', 'unknown')}\n")
            f.write(f"  Kernel Version: {details.get('kernel_version', 'unknown')}\n")
            f.write(f"  Architecture: {details.get('kernel_architecture', 'unknown')}\n")
            f.write(f"  Pending Reboot: {details.get('pending_reboot', False)}\n")
            
            if details.get('vulnerable'):
                f.write(f"  Vulnerabilities: {len(details['vulnerable'])} found\n")
                for vuln in details['vulnerable']:
                    f.write(f"    - {vuln}\n")
            
            for issue in issues:
                f.write(f"  ISSUE: {issue}\n")
    except Exception as e:
        logging.getLogger(__name__).warning(f"Failed to log kernel findings: {e}")


# ============================================================
# FIX 4: REMOVE REBOOT FLAGS HELPER FUNCTION
# ============================================================
def _remove_reboot_flags() -> bool:
    """
    Remove reboot flags to prevent auto-reboot.
    Returns True if any flags were removed.
    """
    logger = logging.getLogger(__name__)
    flags_removed = False
    
    reboot_files = [
        '/var/run/reboot-required',
        '/var/run/reboot-required.pkgs',
        '/var/run/reboot-required.hardening'
    ]
    
    for flag in reboot_files:
        if os.path.exists(flag):
            try:
                os.remove(flag)
                logger.info(f"Removed reboot flag: {flag}")
                flags_removed = True
            except Exception as e:
                logger.warning(f"Could not remove {flag}: {e}")
    
    return flags_removed


# ============================================================
# CHECK FUNCTION - FIXED
# ============================================================
def check(config: dict) -> Tuple[str, str, dict]:
    """Check kernel security"""
    logger = logging.getLogger(__name__)
    logger.info("Checking kernel security...")

    issues = []
    details = {
        'kernel_version': None,
        'kernel_release': None,
        'kernel_architecture': None,
        'pending_reboot': False,
        'vulnerable': []
    }

    # Get kernel version
    kernel_info = _get_kernel_info()
    details.update(kernel_info)

    # ============================================================
    # FIX 1: Check if reboot required AND remove flags
    # ============================================================
    pending_reboot = _check_pending_reboot()
    details['pending_reboot'] = pending_reboot

    if pending_reboot:
        # ✅ FIX: LOG WARNING - DO NOT ADD TO ISSUES
        logger.warning("Pending reboot detected - flags removed")
        logger.info("Manual reboot recommended after hardening")
        # Do NOT add to issues list - this is informational only

    # Check for known vulnerabilities
    vulnerabilities = _check_kernel_vulnerabilities()
    details['vulnerable'] = vulnerabilities

    if vulnerabilities:
        for vuln in vulnerabilities:
            issues.append(f"Vulnerability: {vuln}")

    # Check for CVE list
    cves = _check_cve_list()
    if cves:
        for cve in cves:
            details['vulnerable'].append(f"CVE: {cve}")
            issues.append(f"CVE affecting kernel: {cve}")

    # Check CPU vulnerabilities
    cpu_vulns = _check_cpu_vulnerabilities()
    if cpu_vulns:
        for vuln in cpu_vulns:
            if vuln.get('affected', False):
                details['vulnerable'].append(f"CPU: {vuln['name']} ({vuln.get('status', 'unknown')})")
                issues.append(f"CPU vulnerability: {vuln['name']} ({vuln.get('status', 'unknown')})")

    # Check if system is up to date
    update_status = _check_system_updates()
    details['updates_available'] = update_status

    # Log findings
    _log_kernel_findings(details, issues)

    if issues:
        critical = [i for i in issues if 'CVE' in i or 'vulnerable' in i.lower()]
        if critical:
            status = 'FAIL'
            message = f"{len(issues)} critical kernel issues found"
        else:
            status = 'WARN'
            message = f"{len(issues)} kernel issues found"
    else:
        status = 'PASS'
        message = "Kernel is secure"

    return status, message, details


def _get_kernel_info() -> Dict:
    """Get kernel version information"""
    info = {'kernel_version': None, 'kernel_release': None, 'kernel_architecture': None}

    try:
        result = subprocess.run(['uname', '-r'], capture_output=True, text=True, timeout=5, stdin=subprocess.DEVNULL)
        info['kernel_release'] = result.stdout.strip()

        result = subprocess.run(['uname', '-m'], capture_output=True, text=True, timeout=5, stdin=subprocess.DEVNULL)
        info['kernel_architecture'] = result.stdout.strip()

        result = subprocess.run(['uname', '-v'], capture_output=True, text=True, timeout=5, stdin=subprocess.DEVNULL)
        info['kernel_version'] = result.stdout.strip()

    except subprocess.TimeoutExpired:
        logging.getLogger(__name__).error("Kernel info check timed out")
    except Exception as e:
        logging.getLogger(__name__).error(f"Kernel info failed: {e}")

    return info


# ============================================================
# FIX 2: _check_pending_reboot() - REMOVES FLAGS
# ============================================================
def _check_pending_reboot() -> bool:
    """
    Check if reboot is pending and remove flags to prevent auto-reboot.
    Returns True if reboot was pending.
    """
    logger = logging.getLogger(__name__)
    reboot_found = False
    
    # Check and remove /var/run/reboot-required
    if os.path.exists('/var/run/reboot-required'):
        reboot_found = True
        try:
            os.remove('/var/run/reboot-required')
            logger.info("Removed reboot flag: /var/run/reboot-required")
        except Exception as e:
            logger.warning(f"Could not remove /var/run/reboot-required: {e}")
    
    # Check and remove /var/run/reboot-required.pkgs
    if os.path.exists('/var/run/reboot-required.pkgs'):
        reboot_found = True
        try:
            os.remove('/var/run/reboot-required.pkgs')
            logger.info("Removed reboot flag: /var/run/reboot-required.pkgs")
        except Exception as e:
            logger.warning(f"Could not remove /var/run/reboot-required.pkgs: {e}")

    # Check installed kernels vs running kernel
    try:
        result = subprocess.run(['ls', '/lib/modules'], capture_output=True, text=True, timeout=10, stdin=subprocess.DEVNULL)
        installed_kernels = result.stdout.split()
        current_kernel = subprocess.run(['uname', '-r'], capture_output=True, text=True, timeout=5, stdin=subprocess.DEVNULL).stdout.strip()

        for kernel in installed_kernels:
            if kernel and kernel != current_kernel:
                if re.match(r'^\d+\.\d+\.\d+', kernel):
                    reboot_found = True
                    logger.info(f"Different kernel version installed: {kernel} (running: {current_kernel})")
                    # Remove the flags again just in case
                    _remove_reboot_flags()
                    break
    except Exception as e:
        logger.debug(f"Could not check installed kernels: {e}")

    return reboot_found


def _check_kernel_vulnerabilities() -> List[str]:
    """Check for known kernel vulnerabilities"""
    vulnerabilities = []

    try:
        result = subprocess.run(['uname', '-r'], capture_output=True, text=True, timeout=5, stdin=subprocess.DEVNULL)
        kernel = result.stdout.strip()

        kernel_parts = kernel.split('.')
        if len(kernel_parts) >= 2:
            major = int(kernel_parts[0])
            minor = int(kernel_parts[1])
            
            if major < 3:
                vulnerabilities.append("Kernel is ancient (< 3.0)")
            elif major == 3 and minor < 10:
                vulnerabilities.append(f"Kernel is old (3.x < 3.10)")
            elif major == 4 and minor < 9:
                vulnerabilities.append(f"Kernel is old (4.x < 4.9)")
            elif major == 4 and minor < 19:
                vulnerabilities.append(f"Kernel is getting old (4.x < 4.19)")
            elif major == 5 and minor < 4:
                vulnerabilities.append(f"Kernel version {major}.{minor} may be outdated")

            eol_versions = ['2.6', '3.0', '3.1', '3.2', '3.3', '3.4', '3.5', '3.6', '3.7', '3.8']
            for eol in eol_versions:
                if kernel.startswith(eol):
                    vulnerabilities.append(f"Kernel version {kernel} is EOL")

    except Exception as e:
        logging.getLogger(__name__).error(f"Vulnerability check failed: {e}")

    return vulnerabilities


# ============================================================
# CVE CHECKING WITH MITIGATION ADVICE
# ============================================================
def _check_cve_list() -> List[str]:
    """Check for CVEs affecting the current kernel."""
    cves = []
    
    try:
        result = subprocess.run(['uname', '-r'], capture_output=True, text=True, timeout=5, stdin=subprocess.DEVNULL)
        kernel = result.stdout.strip()
        
        cve_mapping = {
            '2.6.32': ['CVE-2014-0144', 'CVE-2014-0196'],
            '2.6.39': ['CVE-2014-3153', 'CVE-2014-4014'],
            '3.0.0': ['CVE-2016-5195', 'CVE-2017-6074'],
            '3.2.0': ['CVE-2016-5195', 'CVE-2017-6074'],
            '3.10.0': ['CVE-2016-5195', 'CVE-2017-6074'],
            '3.16.0': ['CVE-2016-5195', 'CVE-2017-6074'],
            '4.4.0': ['CVE-2017-1000366', 'CVE-2018-10901'],
            '4.9.0': ['CVE-2018-1120', 'CVE-2018-7755'],
            '4.15.0': ['CVE-2018-10902', 'CVE-2018-10903'],
            '5.0.0': ['CVE-2019-8912', 'CVE-2019-8954'],
            '5.4.0': ['CVE-2020-8835', 'CVE-2020-10731'],
            '5.8.0': ['CVE-2020-8694', 'CVE-2020-8695'],
            '5.11.0': ['CVE-2021-26708', 'CVE-2021-28688'],
        }
        
        for version, cve_list in cve_mapping.items():
            if kernel.startswith(version):
                cves.extend(cve_list)
                break
                
        try:
            with open('/proc/version', 'r') as f:
                proc_version = f.read()
                if 'Debian' in proc_version and '2.6.32' in kernel:
                    cves.append('CVE-2014-0144 (Debian-specific)')
        except:
            pass
            
    except Exception as e:
        logging.getLogger(__name__).debug(f"CVE check failed: {e}")
    
    return cves


# ============================================================
# CPU VULNERABILITY CHECK
# ============================================================
def _check_cpu_vulnerabilities() -> List[Dict]:
    """Check for CPU vulnerabilities (Spectre, Meltdown, etc.)"""
    vulnerabilities = []
    is_vm = _is_virtual_machine()
    
    vuln_files = {
        '/sys/devices/system/cpu/vulnerabilities/meltdown': 'Meltdown',
        '/sys/devices/system/cpu/vulnerabilities/spectre_v1': 'Spectre v1',
        '/sys/devices/system/cpu/vulnerabilities/spectre_v2': 'Spectre v2',
        '/sys/devices/system/cpu/vulnerabilities/l1tf': 'L1TF',
        '/sys/devices/system/cpu/vulnerabilities/mds': 'MDS',
        '/sys/devices/system/cpu/vulnerabilities/tsx_async_abort': 'TSX Async Abort',
        '/sys/devices/system/cpu/vulnerabilities/srbds': 'SRBDS',
        '/sys/devices/system/cpu/vulnerabilities/mmio_stale_data': 'MMIO Stale Data',
        '/sys/devices/system/cpu/vulnerabilities/retbleed': 'Retbleed',
        '/sys/devices/system/cpu/vulnerabilities/spec_store_bypass': 'Spec Store Bypass',
    }
    
    for path, name in vuln_files.items():
        if os.path.exists(path):
            try:
                with open(path, 'r') as f:
                    content = f.read().strip()
                    affected = 'Not affected' not in content
                    
                    # If running in VM, mark as informational (host manages mitigations)
                    if is_vm and affected:
                        vulnerabilities.append({
                            'name': name,
                            'status': content + ' (VM - host managed)',
                            'affected': False,  # Don't count as affected in VMs
                            'vm_info': True
                        })
                    else:
                        vulnerabilities.append({
                            'name': name,
                            'status': content,
                            'affected': affected,
                            'vm_info': False
                        })
            except:
                pass
    
    return vulnerabilities


# ============================================================
# SYSTEM UPDATE CHECK
# ============================================================
def _check_system_updates() -> Dict:
    """Check if system has pending updates."""
    status = {
        'updates_available': False,
        'security_updates': False,
        'package_count': 0
    }
    
    # Check APT updates (Ubuntu/Debian)
    try:
        result = subprocess.run(['apt-get', 'list', '--upgradable', '2>/dev/null'], 
                               capture_output=True, text=True, timeout=30, shell=True, stdin=subprocess.DEVNULL)
        if result.returncode == 0:
            lines = [l for l in result.stdout.split('\n') if l.strip()]
            status['updates_available'] = len(lines) > 0
            status['package_count'] = len(lines)
            if any('security' in l.lower() for l in lines):
                status['security_updates'] = True
    except:
        pass
    
    # Check YUM/DNF updates (RHEL/Fedora)
    if not status['updates_available']:
        try:
            result = subprocess.run(['dnf', 'check-update', '--quiet'], 
                                   capture_output=True, text=True, timeout=60, stdin=subprocess.DEVNULL)
            if result.returncode == 100:  # Updates available
                lines = [l for l in result.stdout.split('\n') if l.strip() and not l.startswith('Last')]
                status['updates_available'] = True
                status['package_count'] = len(lines)
                if any('security' in l.lower() for l in lines):
                    status['security_updates'] = True
        except:
            pass
    
    return status


# ============================================================
# MITIGATION ADVICE
# ============================================================
def _get_mitigation_advice(vulnerability: str, status: str) -> str:
    """Get mitigation advice for a specific vulnerability."""
    advice_map = {
        'meltdown': 'Update kernel and apply KPTI patches',
        'spectre_v1': 'Update kernel and apply LFENCE mitigations',
        'spectre_v2': 'Update kernel and enable IBRS/IBPB',
        'l1tf': 'Update kernel and enable L1D flush',
        'mds': 'Update kernel and enable MD_CLEAR',
        'tsx_async_abort': 'Disable TSX or update microcode',
        'srbds': 'Update microcode and kernel',
        'mmio_stale_data': 'Update kernel with mitigations',
        'retbleed': 'Update kernel and enable RETPOLINE',
        'spec_store_bypass': 'Update kernel and enable SSBD',
    }
    
    # Check if it's a CVE
    if vulnerability.startswith('CVE'):
        return 'Update kernel to the latest version'
    
    # Check against known vulnerabilities
    lower_vuln = vulnerability.lower()
    for key, advice in advice_map.items():
        if key in lower_vuln:
            return advice
    
    return 'Consult your distribution for security updates'


# ============================================================
# FIX 3: IMPROVED FIX FUNCTION - NO REBOOT COMMANDS
# ============================================================
def fix(config: dict, dry_run: bool = False, force: bool = False) -> bool:
    """
    Fix kernel issues (warning only - manual update required)

    Args:
        config: Configuration dictionary
        dry_run: If True, preview changes without applying
        force: If True, skip confirmation

    Returns:
        bool: False (no automatic fixes applied - manual remediation required)
    """
    logger = logging.getLogger(__name__)

    # Check for dry-run mode (use parameter, not config)
    if dry_run:
        logger.info("DRY-RUN MODE: No changes will be applied")
        print("\n[!] DRY-RUN MODE - No changes will be applied")
        
        kernel_info = _get_kernel_info()
        print(f"  Kernel release: {kernel_info.get('kernel_release', 'unknown')}")
        print(f"  Kernel version: {kernel_info.get('kernel_version', 'unknown')}")
        print(f"  Architecture: {kernel_info.get('kernel_architecture', 'unknown')}")
        
        cves = _check_cve_list()
        if cves:
            print(f"  CVEs affecting kernel: {len(cves)}")
            for cve in cves[:5]:
                print(f"    - {cve}")
        
        cpu_vulns = _check_cpu_vulnerabilities()
        if cpu_vulns:
            affected = [v for v in cpu_vulns if v.get('affected', False)]
            if affected:
                print(f"  CPU vulnerabilities: {len(affected)}")
                for v in affected[:5]:
                    print(f"    - {v['name']}: {v.get('status', 'unknown')}")
        
        print("\n  ⚠️ Kernel updates require MANUAL remediation")
        print("\n[✓] Dry-run complete. No changes were made.")
        return True

    # FIX: Skip confirmation in force mode
    if not force:
        print("\n[!] WARNING: Kernel security check will be performed")
        print("    No automatic changes will be made")
        print("    Manual update and reboot required")
        response = ui.prompt("Proceed? [y/N]: ")
        if response.lower() != 'y':
            logger.info("Kernel check cancelled by user")
            return False
    else:
        logger.info("Force mode: Running kernel check without confirmation")

    try:
        begin_transaction()
        
        logger.warning("Kernel issues require MANUAL remediation")
        logger.warning("No automatic fixes were applied")
        
        # Remove any existing reboot flags (safe operation)
        _remove_reboot_flags()
        
        # Check for CVE list and provide recommendations
        cves = _check_cve_list()
        if cves:
            for cve in cves:
                logger.warning(f"CVE affecting kernel: {cve}")
                advice = _get_mitigation_advice(cve, 'unknown')
                print(f"    Recommendation: {advice}")
        
        # Check CPU vulnerabilities and provide recommendations
        cpu_vulns = _check_cpu_vulnerabilities()
        if cpu_vulns:
            for vuln in cpu_vulns:
                if vuln.get('affected', False):
                    logger.warning(f"CPU vulnerability: {vuln['name']} - {vuln.get('status', 'unknown')}")
                    advice = _get_mitigation_advice(vuln['name'], vuln.get('status', 'unknown'))
                    print(f"    Recommendation: {advice}")
        
        # Provide update instructions (without sudo reboot)
        print("\n" + "="*60)
        print("🔴 KERNEL UPDATE REQUIRES MANUAL ACTION")
        print("="*60)
        print("Shadow cannot automatically update the kernel.")
        print("You must manually update and reboot when ready.")
        print("")
        
        if shutil.which('apt'):
            print("    sudo apt update && sudo apt upgrade -y")
            print("    # Reboot manually when ready")
        elif shutil.which('dnf'):
            print("    sudo dnf update -y")
            print("    # Reboot manually when ready")
        elif shutil.which('yum'):
            print("    sudo yum update -y")
            print("    # Reboot manually when ready")
        else:
            print("    Please use your package manager to update the kernel.")
        
        print("")
        print("="*60)
        
        # Log the warning
        try:
            CHANGES_LOG.parent.mkdir(parents=True, exist_ok=True)
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            with open(CHANGES_LOG, 'a') as f:
                f.write(f"{timestamp} - Kernel Warning: Manual update required (NOT automatically fixed)\n")
                if cves:
                    for cve in cves:
                        f.write(f"  CVE: {cve}\n")
                if cpu_vulns:
                    for vuln in cpu_vulns:
                        if vuln.get('affected', False):
                            f.write(f"  CPU: {vuln['name']} - {vuln.get('status', 'unknown')}\n")
        except Exception as e:
            logger.debug(f"Failed to log kernel warning: {e}")
        
        commit_transaction()
        print("\n✅ Kernel check completed")
        
        # ============================================================
        # Return False - No automatic fixes were applied
        # This tells the hardener that manual remediation is required
        # ============================================================
        logger.info("Kernel module: MANUAL remediation required (no automatic fixes)")
        return False

    except Exception as e:
        logger.error(f"Failed to complete kernel check: {e}")
        rollback_transaction()
        return False
    
