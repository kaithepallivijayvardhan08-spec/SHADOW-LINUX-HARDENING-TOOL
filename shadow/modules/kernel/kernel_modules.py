#!/usr/bin/env python3
"""
Shadow Kernel Modules Module
============================

Checks loaded kernel modules for security.

Security concerns:
- Unnecessary modules → larger attack surface
- Dangerous modules → security risk
- Loading modules from non-standard locations
"""

from shadow.core import ui
import os
import shutil
import logging
import subprocess
import json
from pathlib import Path
from datetime import datetime
from typing import Tuple, Dict, List, Optional, Any

# ============================================================
# MODULE METADATA
# ============================================================
SEVERITY = "HIGH"
RECOMMENDATION = "Apply kernel hardening with sysctl settings"

BACKUP_DIR = Path("/var/backups/shadow/")
CHANGES_LOG = Path("/var/log/shadow/changes.log")

# ============================================================
# TRANSACTION SUPPORT
# ============================================================
_transaction_active = False
_transaction_backups = []

def begin_transaction():
    """Begin a transaction for kernel module modifications."""
    global _transaction_active, _transaction_backups
    _transaction_active = True
    _transaction_backups = []
    logging.getLogger(__name__).info("Kernel module transaction started")

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
    logging.getLogger(__name__).info("Kernel module transaction committed")
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
# EXPANDED CRITICAL MODULES LIST
# ============================================================
CRITICAL_MODULES = [
    # Filesystems
    'ext4', 'xfs', 'btrfs', 'zfs', 'ntfs', 'fat', 'vfat', 'exfat', 'f2fs', 'jfs', 'reiserfs',
    # Storage
    'nvme', 'ahci', 'libata', 'sd_mod', 'scsi_mod', 'megaraid_sas', 'mpt3sas', 'virtio_blk',
    # Network
    'e1000', 'e1000e', 'igb', 'ixgbe', 'i40e', 'bnx2', 'tg3', 'r8169', 'virtio_net', 'mlx4_core',
    'mlx5_core', 'cxgb4', 'qede',
    # USB
    'usb_storage', 'usbhid', 'xhci_hcd', 'ehci_hcd', 'ohci_hcd', 'usbcore',
    # Graphics
    'i915', 'amdgpu', 'nouveau', 'radeon', 'nvidia', 'vmwgfx', 'virtio_gpu',
    # Audio
    'snd_hda_intel', 'snd_intel8x0', 'snd_ens1371', 'snd_ac97_codec',
    # Virtualization
    'virtio', 'virtio_pci', 'virtio_balloon', 'virtio_rng', 'virtio_console',
    'xen_blkfront', 'xen_netfront', 'kvm', 'kvm_intel', 'kvm_amd',
    # Power management
    'acpi', 'battery', 'fan', 'processor', 'thermal',
    # Input
    'psmouse', 'i8042', 'serio', 'evdev'
]


# ============================================================
# STRUCTURED LOGGING
# ============================================================
def _log_module_change(action: str, details: str, success: bool):
    """Log module modifications with structured format."""
    logger = logging.getLogger(__name__)
    status = "SUCCESS" if success else "FAILED"
    
    log_entry = {
        "event": "module_change",
        "action": action,
        "details": details,
        "status": status,
        "timestamp": datetime.now().isoformat()
    }
    logger.info(f"MODULE: {json.dumps(log_entry)}")
    
    try:
        CHANGES_LOG.parent.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(CHANGES_LOG, 'a') as f:
            f.write(f"{timestamp} - Module: {action} - {details} ({status})\n")
    except Exception as e:
        logger.debug(f"Failed to log change: {e}")


def _log_module_findings(details: Dict, issues: List[str]):
    """Log module check findings for audit trail."""
    try:
        CHANGES_LOG.parent.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        with open(CHANGES_LOG, 'a') as f:
            f.write(f"{timestamp} - Module Check Results:\n")
            f.write(f"  Total Modules: {details.get('module_count', 0)}\n")
            f.write(f"  Dangerous Modules: {len(details.get('dangerous_modules', []))}\n")
            
            for issue in issues:
                f.write(f"  ISSUE: {issue}\n")
    except Exception as e:
        logging.getLogger(__name__).warning(f"Failed to log module findings: {e}")


# ============================================================
# CHECK FUNCTION
# ============================================================
def check(config: dict) -> Tuple[str, str, dict]:
    """Check kernel modules security"""
    logger = logging.getLogger(__name__)
    logger.info("Checking kernel modules...")

    issues = []
    details = {
        'loaded_modules': [],
        'dangerous_modules': [],
        'unnecessary_modules': [],
        'module_count': 0
    }

    # Get loaded modules
    modules = _get_loaded_modules()
    details['loaded_modules'] = modules
    details['module_count'] = len(modules)

    # Check for dangerous modules
    dangerous = _check_dangerous_modules(modules)
    details['dangerous_modules'] = dangerous

    if dangerous:
        for mod in dangerous:
            issues.append(f"Dangerous module loaded: {mod}")

    # Check for unnecessary modules
    unnecessary = _check_unnecessary_modules(modules)
    details['unnecessary_modules'] = unnecessary

    if unnecessary:
        for mod in unnecessary[:5]:
            issues.append(f"Unnecessary module: {mod}")

    _log_module_findings(details, issues)

    if issues:
        return 'WARN', f"{len(issues)} module issues found", details
    return 'PASS', "Kernel modules are secure", details


def _get_loaded_modules() -> List[str]:
    """Get list of loaded kernel modules"""
    modules = []

    try:
        result = subprocess.run(['lsmod'], capture_output=True, text=True, timeout=10, stdin=subprocess.DEVNULL)

        for line in result.stdout.split('\n')[1:]:
            if line.strip():
                parts = line.split()
                if parts:
                    modules.append(parts[0])

    except Exception as e:
        logging.getLogger(__name__).error(f"lsmod failed: {e}")

    return modules


def _check_dangerous_modules(modules: List[str]) -> List[str]:
    """Check for dangerous kernel modules"""
    dangerous = []
    
    dangerous_modules = [
        # Legacy networking (security risks)
        'ipx', 'appletalk', 'ax25', 'netrom', 'rose',
        'dccp', 'sctp',
        'irda', 'bluez',
        'usb_storage',  # Can be used for USB attacks
        'squashfs',     # Can be used for hidden filesystems
        'tcp_diag',     # Information disclosure
        'udp_diag',     # Information disclosure
        'raw_diag',     # Information disclosure
        'crypto_user',  # Crypto information disclosure
        'nfsv3',        # Insecure NFS version
        'nfsv4',        # May be needed, but risky
        'cifs',         # CIFS/SMB can be risky
        'vfat',         # Insecure filesystem
        'msdos',        # Insecure filesystem
        'kexec',        # Can be used for boot attacks
        'kexec_load',   # Can be used for boot attacks
        'crash',        # Core dump information
        'debugfs',      # Debug filesystem
        'tracefs',      # Trace filesystem
        'ftrace',       # Function tracing
        'kprobe',       # Kernel probe
        'uprobe',       # User probe
        'perf',         # Performance monitoring (information)
    ]

    # Only check if module is loaded
    for mod in dangerous_modules:
        if mod in modules:
            dangerous.append(mod)

    return dangerous


def _check_unnecessary_modules(modules: List[str]) -> List[str]:
    """Check for unnecessary modules"""
    unnecessary = []

    unnecessary_modules = [
        'soundcore', 'snd', 'snd_pcm', 'snd_timer',
        'firewire_core', 'firewire_ohci',
        'crypto', 'cryptd', 'aes'
    ]

    for mod in unnecessary_modules:
        if mod in modules:
            unnecessary.append(mod)

    return unnecessary[:10]


# ============================================================
# BACKUP BEFORE MODIFYING MODPROBE.D
# ============================================================
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


def _backup_modprobe_config() -> Dict[str, Any]:
    """Backup modprobe.d configuration files."""
    result = {
        'path': '/etc/modprobe.d/',
        'backup_path': None,
        'success': False
    }
    
    try:
        BACKUP_DIR.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        
        modprobe_d = Path('/etc/modprobe.d/')
        if modprobe_d.exists():
            backup_path = BACKUP_DIR / f"modprobe.d.backup_{timestamp}"
            shutil.copytree(modprobe_d, backup_path, dirs_exist_ok=True)
            result['backup_path'] = str(backup_path)
            
            if backup_path.exists():
                result['success'] = True
                logging.getLogger(__name__).info(f"Backup created: {backup_path}")
                add_to_transaction(backup_path, Path('/etc/modprobe.d/'))

    except Exception as e:
        logging.getLogger(__name__).error(f"Failed to backup modprobe.d: {e}")
    
    return result


# ============================================================
# VALIDATE MODULES BEFORE BLACKLISTING
# ============================================================
def _validate_module_blacklist(module_name: str) -> Tuple[bool, str]:
    """
    Validate that a module can be safely blacklisted.
    Returns (is_safe, reason).
    """
    logger = logging.getLogger(__name__)
    
    if module_name in CRITICAL_MODULES:
        return False, f"Critical system module: {module_name}"
    
    # Check for kernel core modules (by prefix)
    critical_prefixes = ['ext', 'xfs', 'btrfs', 'zfs', 'ntfs', 'fat', 'vfat', 
                         'exfat', 'f2fs', 'jfs', 'reiserfs']
    for prefix in critical_prefixes:
        if module_name.startswith(prefix):
            return False, f"Critical filesystem module: {module_name}"
    
    # Check if module is loaded and has dependencies
    try:
        result = subprocess.run(['lsmod'], capture_output=True, text=True, timeout=5, stdin=subprocess.DEVNULL)
        for line in result.stdout.split('\n'):
            if module_name in line and 'Used by' in line:
                parts = line.split()
                if len(parts) > 3 and parts[3] != '0':
                    return False, f"Module {module_name} has {parts[3]} dependencies"
                break
    except:
        pass
    
    return True, "Safe to blacklist"


# ============================================================
# ROLLBACK ON FAILURE
# ============================================================
def _rollback_modprobe_config(backup_metadata: Dict[str, Any]) -> bool:
    """Rollback modprobe.d from backup."""
    if not backup_metadata.get('success'):
        logging.getLogger(__name__).error("Cannot rollback: invalid backup metadata")
        return False
    
    backup_path = Path(backup_metadata['backup_path'])
    original_path = Path(backup_metadata['path'])
    
    if not backup_path.exists():
        logging.getLogger(__name__).error(f"Backup not found: {backup_path}")
        return False
    
    try:
        if original_path.exists():
            shutil.rmtree(original_path)
        shutil.copytree(backup_path, original_path)
        logging.getLogger(__name__).info(f"Rolled back modprobe.d: {original_path}")
        return True
    except Exception as e:
        logging.getLogger(__name__).error(f"Rollback failed: {e}")
        return False


# ============================================================
# DRY-RUN MODE
# ============================================================
def _dry_run_module_fix(action: str, details: str) -> bool:
    """Simulate module modification without actually changing anything."""
    logging.getLogger(__name__).info(f"[DRY-RUN] Would perform: {action} - {details}")
    print(f"[DRY-RUN] Would perform: {action}")
    return True


# ============================================================
# CONFIRMATION BEFORE BLACKLISTING - FIXED (No Reboot)
# ============================================================
def _confirm_module_blacklist(modules: List[str]) -> bool:
    """Ask for confirmation before blacklisting modules."""
    print(f"\n[!] WARNING: About to blacklist {len(modules)} kernel modules:")
    for module in modules:
        print(f"    - {module}")
    print("    Blacklisting modules can break hardware functionality!")
    print("    Changes will take effect after a manual reboot.")
    response = ui.prompt("Proceed? [y/N]: ")
    if response.lower() == 'y':
        print("\n[*] Applying fixes... please wait")
        return True
    return False


# ============================================================
# PROGRESS INDICATOR
# ============================================================
def _progress_indicator(current: int, total: int, message: str = ""):
    """Show progress during operations."""
    if total > 0:
        percent = (current / total) * 100
        print(f"\r\033[K[{current}/{total}] {percent:.1f}% - {message}", end="", flush=True)


# ============================================================
# MODULE DEPENDENCY CHECKER
# ============================================================
def _get_module_dependencies(module_name: str) -> List[str]:
    """Get dependencies for a module."""
    dependencies = []
    
    try:
        result = subprocess.run(['modinfo', module_name], capture_output=True, text=True, timeout=5, stdin=subprocess.DEVNULL)
        for line in result.stdout.split('\n'):
            if line.startswith('depends:'):
                dep_str = line.replace('depends:', '').strip()
                if dep_str:
                    dependencies = [d.strip() for d in dep_str.split(',') if d.strip()]
                break
    except:
        pass
    
    return dependencies


def _get_module_used_by(module_name: str) -> List[str]:
    """Get modules that depend on this module."""
    used_by = []
    
    try:
        result = subprocess.run(['lsmod'], capture_output=True, text=True, timeout=5, stdin=subprocess.DEVNULL)
        for line in result.stdout.split('\n'):
            if module_name in line:
                parts = line.split()
                if len(parts) > 3 and parts[3] != '0':
                    # The used-by modules are in the line
                    if len(parts) > 4:
                        used_by = parts[4:]
                break
    except:
        pass
    
    return used_by


# ============================================================
# WARN ABOUT LOADED MODULES - FIXED (No Reboot)
# ============================================================
def _warn_loaded_modules(modules: List[str]) -> bool:
    """Warn about currently loaded modules that will be blacklisted."""
    print(f"\n[!] WARNING: The following modules are currently LOADED:")
    for module in modules:
        # Check dependencies
        deps = _get_module_dependencies(module)
        used_by = _get_module_used_by(module)
        print(f"    - {module} (loaded)")
        if deps:
            print(f"      Depends on: {', '.join(deps)}")
        if used_by:
            print(f"      Used by: {', '.join(used_by)}")
    print("    Blacklisting loaded modules takes effect on next boot.")
    print("    If other modules depend on these, they will also be affected.")
    response = ui.prompt("Continue? [y/N]: ")
    return response.lower() == 'y'


# ============================================================
# SAFE BLACKLIST MODULES
# ============================================================
def _safe_blacklist_modules(modules_to_blacklist: List[str], dry_run: bool = False) -> bool:
    """
    Safely blacklist modules with backup, validation, dry-run, and rollback.
    """
    logger = logging.getLogger(__name__)
    
    if not modules_to_blacklist:
        logger.info("No modules to blacklist")
        return True
    
    # Dry-run mode
    if dry_run:
        for module in modules_to_blacklist:
            _dry_run_module_fix("blacklist_module", f"Would blacklist {module}")
        return True
    
    # Warn about loaded modules
    loaded_modules = _get_loaded_modules()
    loaded_to_blacklist = [m for m in modules_to_blacklist if m in loaded_modules]
    if loaded_to_blacklist:
        if not _warn_loaded_modules(loaded_to_blacklist):
            logger.info("Module blacklist cancelled by user")
            return False
    
    # Validate each module
    valid_modules = []
    skipped_modules = []
    for module in modules_to_blacklist:
        is_safe, reason = _validate_module_blacklist(module)
        if is_safe:
            # Check dependencies
            deps = _get_module_dependencies(module)
            if deps:
                logger.info(f"Module {module} depends on: {', '.join(deps)}")
            used_by = _get_module_used_by(module)
            if used_by:
                logger.info(f"Module {module} is used by: {', '.join(used_by)}")
                # Ask for confirmation if module is used by others
                print(f"\n[!] Module {module} is used by: {', '.join(used_by)}")
                response = ui.prompt("Continue anyway? [y/N]: ")
                if response.lower() != 'y':
                    logger.info(f"Skipping {module} due to dependencies")
                    continue
            valid_modules.append(module)
        else:
            skipped_modules.append((module, reason))
    
    if skipped_modules:
        for module, reason in skipped_modules:
            logger.warning(f"Skipping {module}: {reason}")
    
    if not valid_modules:
        logger.info("No valid modules to blacklist")
        return True
    
    # Confirmation
    if not _confirm_module_blacklist(valid_modules):
        logger.info("Module blacklist cancelled by user")
        return False
    
    # Backup current modprobe.d
    backup_metadata = _backup_modprobe_config()
    if not backup_metadata['success']:
        logger.warning("Could not backup modprobe.d")
    
    try:
        # Create blacklist file
        blacklist_file = '/etc/modprobe.d/shadow-blacklist.conf'
        
        if os.path.exists(blacklist_file):
            with open(blacklist_file, 'r') as f:
                existing_content = f.read()
        else:
            existing_content = ''
        
        # Add new blacklist entries
        new_entries = []
        for module in valid_modules:
            if f'blacklist {module}' not in existing_content:
                new_entries.append(module)
        
        if not new_entries:
            logger.info("No new modules to blacklist")
            return True
        
        with open(blacklist_file, 'a') as f:
            f.write(f'\n# Shadow added - Module blacklist ({datetime.now().strftime("%Y-%m-%d")})\n')
            for module in new_entries:
                f.write(f'blacklist {module}\n')
        
        logger.info(f"Blacklisted modules: {', '.join(new_entries)}")
        _log_module_change("blacklist_modules", f"Blacklisted: {', '.join(new_entries)}", True)
        
        # ============================================================
        # FIX 1: Changed "REBOOT REQUIRED" to Informational Message
        # ============================================================
        print("\n" + "=" * 60)
        print("ℹ️  MODULE CHANGES SCHEDULED")
        print("=" * 60)
        print("Module blacklist changes will take effect on next boot.")
        print("Manual reboot recommended when convenient.")
        print("=" * 60)
        
        return True
        
    except Exception as e:
        logger.error(f"Failed to blacklist modules: {e}")
        if backup_metadata['success']:
            _rollback_modprobe_config(backup_metadata)
        _log_module_change("blacklist_modules", str(e), False)
        return False


# ============================================================
# FIX FUNCTION
# ============================================================
def fix(config: dict, dry_run: bool = False, force: bool = False) -> bool:
    """
    Fix kernel module issues

    Args:
        config: Configuration dictionary
        dry_run: If True, preview changes without applying
        force: If True, skip confirmation

    Returns:
        bool: True if fixes applied successfully
    """
    logger = logging.getLogger(__name__)
    logger.info("Fixing kernel module issues...")

    # Check for dry-run mode (use parameter, not config)
    if dry_run:
        logger.info("DRY-RUN MODE: No changes will be applied")
        print("\n[!] DRY-RUN MODE - No changes will be applied")
        
        modules = _get_loaded_modules()
        dangerous = _check_dangerous_modules(modules)
        
        print(f"  Loaded modules: {len(modules)}")
        print(f"  Dangerous modules found: {len(dangerous)}")
        
        if dangerous:
            print("  Would blacklist the following modules:")
            for mod in dangerous:
                print(f"    - {mod}")
        
        print("\n[✓] Dry-run complete. No changes were made.")
        return True

    # FIX: Skip confirmation in force mode
    if not force:
        print("\n[!] WARNING: Kernel module blacklist will be modified")
        print("    Module changes take effect on next boot")
        print("    Hardware functionality may be affected")
        response = ui.prompt("Proceed? [y/N]: ")
        if response.lower() != 'y':
            logger.info("Module fix cancelled by user")
            return False
    else:
        logger.info("Force mode: Applying module fixes without confirmation")

    try:
        begin_transaction()
        
        # Get loaded modules
        modules = _get_loaded_modules()
        
        # Check dangerous modules
        dangerous = _check_dangerous_modules(modules)
        
        if not dangerous:
            logger.info("No dangerous modules to blacklist")
            commit_transaction()
            return True
        
        # Blacklist dangerous modules
        success = _safe_blacklist_modules(dangerous, dry_run)
        
        if success:
            commit_transaction()
            logger.info("Dangerous modules blacklisted")
            print("\n✅ Module blacklist applied successfully")
            return True
        else:
            rollback_transaction()
            logger.error("Failed to blacklist modules")
            return False

    except Exception as e:
        logger.error(f"Failed to fix kernel modules: {e}")
        rollback_transaction()
        return False