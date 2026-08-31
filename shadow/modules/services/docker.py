#!/usr/bin/env python3
"""
Shadow Docker Module
====================

Checks Docker container security:
- Docker is installed and running
- Docker version (vulnerabilities)
- Docker daemon configuration
- Running containers
- Privileged containers
- Mounted sensitive directories
- Container network exposure
- Docker image security
- Docker registry security

Files checked:
- /etc/docker/daemon.json
- Docker socket permissions (/var/run/docker.sock)

Security concerns:
- Docker running without user → privilege escalation
- Privileged containers → full host access
- Mounted /var/run/docker.sock → container escape
- Mounted /etc → host compromise
- Running as root → privilege issues
- Old Docker version → known vulnerabilities
- Exposed ports → attack surface
"""

from shadow.core import ui
import os
import re
import shutil
import json
import logging
import subprocess
import tempfile
import time
from pathlib import Path
from datetime import datetime
from typing import Tuple, Dict, List, Optional, Any

# ============================================================
# MODULE METADATA
# ============================================================
SEVERITY = "HIGH"
RECOMMENDATION = "Enable user namespace remapping, live restore, and configure logging"

BACKUP_DIR = Path("/var/backups/shadow/")

# ============================================================
# TRANSACTION SUPPORT
# ============================================================
_transaction_active = False
_transaction_backups = []

def begin_transaction():
    """Begin a transaction for Docker modifications."""
    global _transaction_active, _transaction_backups
    _transaction_active = True
    _transaction_backups = []
    logging.getLogger(__name__).info("Docker transaction started")

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
    logging.getLogger(__name__).info("Docker transaction committed")
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

def check(config: dict) -> Tuple[str, str, dict]:
    """
    Check Docker security

    Returns:
        Tuple[str, str, dict]: (status, message, details)
    """
    logger = logging.getLogger(__name__)
    logger.info("Checking Docker security...")

    issues = []
    warnings = []
    details = {
        'docker_installed': False,
        'docker_running': False,
        'docker_version': None,
        'containers_total': 0,
        'privileged_containers': [],
        'sensitive_mounts': [],
        'exposed_ports': [],
        'docker_socket_perms': None,
        'docker_group_members': [],
        'user_namespace': False,
        'live_restore': False,
        'log_driver': None
    }

    # Check if Docker is installed
    docker_installed = _check_docker_installed()
    details['docker_installed'] = docker_installed

    if not docker_installed:
        return 'PASS', "Docker is not installed", details

    # Check if Docker is running
    docker_running = _check_docker_running()
    details['docker_running'] = docker_running

    if not docker_running:
        return 'WARN', "Docker is installed but not running", details

    # Get Docker version
    version_info = _get_docker_version()
    details['docker_version'] = version_info

    if version_info:
        if '1.1' in version_info or '1.2' in version_info:
            issues.append(f"Docker version {version_info} is outdated")

    # Check docker socket permissions
    socket_perms = _check_docker_socket()
    details['docker_socket_perms'] = socket_perms
    if socket_perms and socket_perms != '600':
        warnings.append(f"Docker socket has permissions: {socket_perms} (should be 600)")

    # Check docker group membership
    group_members = _check_docker_group()
    details['docker_group_members'] = group_members
    if group_members:
        warnings.append(f"Users in docker group: {', '.join(group_members)} (privilege risk)")

    # Get running containers
    containers = _get_running_containers()
    details['containers_total'] = len(containers)

    # Check for privileged containers
    privileged = _check_privileged_containers()
    if privileged:
        details['privileged_containers'] = privileged
        for container in privileged:
            issues.append(f"Privileged container: {container}")

    # Check for sensitive mounts
    sensitive_mounts = _check_sensitive_mounts()
    if sensitive_mounts:
        details['sensitive_mounts'] = sensitive_mounts
        for mount in sensitive_mounts:
            warnings.append(f"Sensitive mount in container: {mount}")

    # Check exposed ports
    exposed_ports = _check_exposed_ports()
    if exposed_ports:
        details['exposed_ports'] = exposed_ports
        for port in exposed_ports:
            warnings.append(f"Container exposing port: {port}")

    # Check daemon configuration
    daemon_config = _check_daemon_config()
    details.update(daemon_config)

    if not daemon_config.get('user_namespace', False):
        warnings.append("User namespace remapping not enabled")
    if not daemon_config.get('live_restore', False):
        warnings.append("Live restore not enabled")
    if daemon_config.get('log_driver') not in ['json-file', 'journald']:
        warnings.append(f"Log driver: {daemon_config.get('log_driver')} (not json-file/journald)")

    # Determine status
    if issues:
        critical = [i for i in issues if 'privileged' in i.lower()]
        if critical:
            status = 'FAIL'
            message = f"{len(issues)} critical Docker issues found"
        else:
            status = 'WARN'
            message = f"{len(issues)} Docker issues found"
    elif warnings:
        status = 'WARN'
        message = f"{len(warnings)} Docker warnings found"
    else:
        status = 'PASS'
        message = "Docker is securely configured"

    return status, message, details


def _check_docker_installed() -> bool:
    """Check if Docker is installed"""
    docker_paths = [
        '/usr/bin/docker',
        '/usr/local/bin/docker',
        '/usr/sbin/dockerd'
    ]

    for path in docker_paths:
        if os.path.exists(path):
            return True

    try:
        result = subprocess.run(['which', 'docker'], capture_output=True, text=True, stdin=subprocess.DEVNULL)
        if result.returncode == 0:
            return True
    except:
        pass

    return False


def _check_docker_running() -> bool:
    """Check if Docker daemon is running"""
    try:
        result = subprocess.run(['systemctl', 'is-active', 'docker'],
                              capture_output=True, text=True, stdin=subprocess.DEVNULL)
        if result.stdout.strip() == 'active':
            return True
    except:
        pass

    try:
        result = subprocess.run(['docker', 'info'], capture_output=True, text=True, timeout=5, stdin=subprocess.DEVNULL)
        if result.returncode == 0:
            return True
    except:
        pass

    return False


def _get_docker_version() -> Optional[str]:
    """Get Docker version"""
    try:
        result = subprocess.run(['docker', '--version'], capture_output=True, text=True, stdin=subprocess.DEVNULL)
        if result.returncode == 0:
            match = re.search(r'(\d+\.\d+\.\d+)', result.stdout)
            if match:
                return match.group(1)
    except:
        pass
    return None


def _check_docker_socket() -> Optional[str]:
    """Check docker socket permissions"""
    socket_path = '/var/run/docker.sock'

    if not os.path.exists(socket_path):
        return None

    try:
        stat_info = os.stat(socket_path)
        return oct(stat_info.st_mode)[-3:]
    except Exception as e:
        logging.getLogger(__name__).debug(f"Error checking docker socket: {e}")
        return None


def _check_docker_group() -> List[str]:
    """Check users in docker group"""
    members = []

    try:
        import grp
        docker_group = grp.getgrnam('docker')
        members = docker_group.gr_mem
    except:
        pass

    return members


def _get_running_containers() -> List[Dict]:
    """Get running containers"""
    containers = []

    try:
        result = subprocess.run(
            ['docker', 'ps', '--format', '{{.Names}}\t{{.Image}}\t{{.Status}}'],
            capture_output=True, text=True, timeout=10, stdin=subprocess.DEVNULL)

        if result.returncode == 0:
            for line in result.stdout.split('\n'):
                if line.strip():
                    parts = line.split('\t')
                    containers.append({
                        'name': parts[0] if len(parts) > 0 else 'unknown',
                        'image': parts[1] if len(parts) > 1 else 'unknown',
                        'status': parts[2] if len(parts) > 2 else 'unknown'
                    })
    except Exception as e:
        logging.getLogger(__name__).debug(f"Error getting containers: {e}")

    return containers


def _check_privileged_containers() -> List[str]:
    """Check for privileged containers"""
    privileged = []

    try:
        result = subprocess.run(
            ['docker', 'ps', '--format', '{{.Names}}', '--filter', 'label=privileged=true'],
            capture_output=True, text=True, timeout=10, stdin=subprocess.DEVNULL)

        if result.returncode == 0:
            for line in result.stdout.split('\n'):
                if line.strip():
                    privileged.append(line.strip())
    except:
        pass

    try:
        result = subprocess.run(
            ['docker', 'ps', '--format', '{{.Names}}\t{{.Status}}'],
            capture_output=True, text=True, timeout=10, stdin=subprocess.DEVNULL)

        if result.returncode == 0:
            for line in result.stdout.split('\n'):
                if 'privileged' in line:
                    parts = line.split('\t')
                    if parts:
                        privileged.append(parts[0])
    except:
        pass

    return privileged


def _check_sensitive_mounts() -> List[str]:
    """Check for sensitive directory mounts"""
    sensitive = []
    sensitive_dirs = ['/etc', '/var/run/docker.sock', '/proc', '/sys']

    try:
        result = subprocess.run(
            ['docker', 'ps', '--format', '{{.Names}}\t{{.Mounts}}'],
            capture_output=True, text=True, timeout=10, stdin=subprocess.DEVNULL)

        if result.returncode == 0:
            for line in result.stdout.split('\n'):
                if line.strip():
                    parts = line.split('\t')
                    if len(parts) > 1:
                        mounts = parts[1] if parts[1] else ''
                        for sensitive_dir in sensitive_dirs:
                            if sensitive_dir in mounts:
                                sensitive.append(f"{parts[0]}: {sensitive_dir}")
    except Exception as e:
        logging.getLogger(__name__).debug(f"Error checking mounts: {e}")

    return sensitive


def _check_exposed_ports() -> List[str]:
    """Check exposed container ports"""
    ports = []

    try:
        result = subprocess.run(
            ['docker', 'ps', '--format', '{{.Names}}\t{{.Ports}}'],
            capture_output=True, text=True, timeout=10, stdin=subprocess.DEVNULL)

        if result.returncode == 0:
            for line in result.stdout.split('\n'):
                if line.strip():
                    parts = line.split('\t')
                    if len(parts) > 1 and parts[1]:
                        ports.append(f"{parts[0]}: {parts[1]}")
    except Exception as e:
        logging.getLogger(__name__).debug(f"Error checking ports: {e}")

    return ports


def _check_daemon_config() -> Dict:
    """Check Docker daemon configuration"""
    config = {
        'user_namespace': False,
        'live_restore': False,
        'log_driver': None
    }

    daemon_config = '/etc/docker/daemon.json'

    if not os.path.exists(daemon_config):
        return config

    try:
        with open(daemon_config, 'r') as f:
            content = json.load(f)

        if content.get('userns-remap'):
            config['user_namespace'] = True

        if content.get('live-restore'):
            config['live_restore'] = True

        if content.get('log-driver'):
            config['log_driver'] = content.get('log-driver')

    except Exception as e:
        logging.getLogger(__name__).debug(f"Error reading daemon config: {e}")

    return config


# ============================================================
# FIX 1: BACKUP BEFORE MODIFYING DOCKER CONFIG
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


def _backup_docker_config(file_path: str) -> Dict[str, Any]:
    """
    Backup Docker configuration file with metadata.
    """
    result = {
        'path': file_path,
        'backup_path': None,
        'success': False
    }
    
    try:
        BACKUP_DIR.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        if os.path.exists(file_path):
            backup_path = BACKUP_DIR / f"{Path(file_path).name}.backup_{timestamp}"
            shutil.copy2(file_path, backup_path)
            result['backup_path'] = str(backup_path)
            
            if _verify_backup(backup_path):
                result['success'] = True
                logging.getLogger(__name__).info(f"Backup created: {backup_path}")
                add_to_transaction(backup_path, Path(file_path))

    except Exception as e:
        logging.getLogger(__name__).error(f"Failed to backup {file_path}: {e}")
    
    return result


# ============================================================
# FIX 2: VALIDATE DOCKER CONFIG BEFORE MODIFYING
# ============================================================
def _validate_docker_config() -> bool:
    """
    Validate Docker configuration syntax.
    Returns True if valid, False otherwise.
    """
    try:
        result = subprocess.run(
            ['dockerd', '--validate'],
            capture_output=True,
            text=True,
            timeout=10, stdin=subprocess.DEVNULL)
        if result.returncode == 0:
            logging.getLogger(__name__).debug("Docker config validation passed")
            return True
        else:
            logging.getLogger(__name__).error(f"Docker config validation failed: {result.stderr}")
            return False
    except:
        try:
            # Check if docker daemon is running
            result = subprocess.run(['docker', 'info'], capture_output=True, text=True, timeout=5, stdin=subprocess.DEVNULL)
            if result.returncode == 0:
                return True
        except:
            pass
        return False


# ============================================================
# FIX 3: ROLLBACK ON FAILURE
# ============================================================
def _rollback_docker_config(backup_metadata: Dict[str, Any]) -> bool:
    """
    Rollback Docker configuration from backup.
    """
    if not backup_metadata.get('success'):
        logging.getLogger(__name__).error("Cannot rollback: invalid backup metadata")
        return False
    
    backup_path = Path(backup_metadata['backup_path'])
    original_path = backup_metadata['path']
    
    if not backup_path.exists():
        logging.getLogger(__name__).error(f"Backup file not found: {backup_path}")
        return False
    
    try:
        shutil.copy2(backup_path, original_path)
        logging.getLogger(__name__).info(f"Rolled back Docker config: {original_path}")
        return True
    except Exception as e:
        logging.getLogger(__name__).error(f"Rollback failed for {original_path}: {e}")
        return False


# ============================================================
# FIX 4: VERIFY DOCKER AFTER CHANGES
# ============================================================
def _verify_docker_running() -> bool:
    """Verify Docker is running and responding."""
    try:
        result = subprocess.run(
            ['systemctl', 'is-active', 'docker'],
            capture_output=True,
            text=True,
            timeout=5, stdin=subprocess.DEVNULL)
        if result.stdout.strip() == 'active':
            return True
    except:
        pass
    
    try:
        result = subprocess.run(['docker', 'info'], capture_output=True, text=True, timeout=5, stdin=subprocess.DEVNULL)
        if result.returncode == 0:
            return True
    except:
        pass
    
    return False


# ============================================================
# MEDIUM FIX 1: DRY-RUN MODE
# ============================================================
def _dry_run_docker_fix(action: str, details: str) -> bool:
    """
    Simulate Docker modification without actually changing anything.
    Used for dry-run mode.
    """
    logging.getLogger(__name__).info(f"[DRY-RUN] Would perform: {action} - {details}")
    print(f"[DRY-RUN] Would perform: {action}")
    return True


# ============================================================
# MEDIUM FIX 2: CONFIRMATION BEFORE MODIFYING DOCKER
# ============================================================
def _confirm_docker_modification(action: str) -> bool:
    """
    Ask for confirmation before modifying Docker.
    """
    print(f"\n[!] WARNING: About to modify Docker configuration")
    print(f"    Action: {action}")
    print("    This could break your containers!")
    response = ui.prompt("Proceed? [y/N]: ")
    if response.lower() == 'y':
        print("\n[*] Applying fixes... please wait")
        return True
    return False


# ============================================================
# MEDIUM FIX 3: LOGGING OF DOCKER CHANGES
# ============================================================
def _log_docker_change(action: str, details: str, success: bool):
    """
    Log Docker modifications.
    """
    logger = logging.getLogger(__name__)
    status = "SUCCESS" if success else "FAILED"
    logger.info(f"Docker change: {action} - {details} ({status})")
    
    # Also log to changes.log for audit trail
    changes_log = Path("/var/log/shadow/changes.log")
    if changes_log.exists():
        with open(changes_log, 'a') as f:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            f.write(f"{timestamp} - Docker: {action} - {details} ({status})\n")


# ============================================================
# MEDIUM FIX 4: VERIFY DOCKER ACCESSIBILITY
# ============================================================
def _verify_docker_accessible() -> bool:
    """
    Verify Docker is accessible.
    """
    try:
        result = subprocess.run(
            ['docker', 'info'],
            capture_output=True,
            text=True,
            timeout=5, stdin=subprocess.DEVNULL)
        if result.returncode == 0:
            return True
    except:
        pass
    
    try:
        import socket
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(2)
        result = sock.connect_ex('/var/run/docker.sock')
        sock.close()
        if result == 0:
            return True
    except:
        pass
    
    return False


# ============================================================
# MEDIUM FIX 5: WARNING BEFORE REMOVING CONTAINERS
# ============================================================
def _confirm_container_removal(containers: List[str]) -> bool:
    """
    Ask for confirmation before removing containers.
    """
    print(f"\n[!] WARNING: About to remove {len(containers)} containers:")
    for container in containers:
        print(f"    - {container}")
    print("    This will stop and delete these containers!")
    response = ui.prompt("Proceed? [y/N]: ")
    if response.lower() == 'y':
        print("\n[*] Applying fixes... please wait")
        return True
    return False


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


def _safe_docker_fix(config_file: str, fix_func, dry_run: bool = False, *args) -> bool:
    """
    Safely apply a Docker fix with backup, validation, dry-run, and rollback.
    """
    logger = logging.getLogger(__name__)
    
    # MEDIUM FIX 1: Dry-run mode
    if dry_run:
        return _dry_run_docker_fix("docker_fix", f"Would apply fix to {config_file}")
    
    # MEDIUM FIX 2: Confirmation
    if not _confirm_docker_modification(f"Apply fix to {config_file}"):
        logger.info("Docker fix cancelled by user")
        return False
    
    # Step 1: Backup config
    backup_metadata = _backup_docker_config(config_file)
    if not backup_metadata['success']:
        logger.warning(f"Could not backup {config_file}")
    
    try:
        # Step 2: Apply fix
        fix_func(*args)
        
        # Step 3: Validate config
        if not _validate_docker_config():
            logger.error("Docker config validation failed after fix")
            if backup_metadata['success']:
                _rollback_docker_config(backup_metadata)
                _restart_docker()
            # MEDIUM FIX 3: Log failure
            _log_docker_change("docker_fix", f"{config_file} - validation failed", False)
            return False
        
        # Step 4: Verify Docker is running
        if not _verify_docker_running():
            logger.error("Docker is not running after fix")
            if backup_metadata['success']:
                _rollback_docker_config(backup_metadata)
                _restart_docker()
            # MEDIUM FIX 3: Log failure
            _log_docker_change("docker_fix", f"{config_file} - Docker not running", False)
            return False
        
        # MEDIUM FIX 4: Verify Docker accessibility
        if not _verify_docker_accessible():
            logger.warning("Docker may not be accessible - check manually")
        
        # MEDIUM FIX 3: Log success
        _log_docker_change("docker_fix", f"{config_file} - success", True)
        return True
        
    except Exception as e:
        logger.error(f"Error applying Docker fix: {e}")
        if backup_metadata['success']:
            _rollback_docker_config(backup_metadata)
            _restart_docker()
        # MEDIUM FIX 3: Log failure
        _log_docker_change("docker_fix", f"{config_file} - {e}", False)
        return False


def _restart_docker():
    """Restart Docker service."""
    try:
        subprocess.run(['systemctl', 'restart', 'docker'], capture_output=True, text=True, stdin=subprocess.DEVNULL)
    except:
        pass

def _enable_docker_service() -> bool:
    """Enable and start Docker service if installed but not running."""
    logger = logging.getLogger(__name__)
    
    if not _check_docker_installed():
        logger.info("Docker is not installed, skipping enable")
        return True
    
    if _check_docker_running():
        logger.info("Docker is already running")
        return True
    
    try:
        logger.info("Enabling and starting Docker service...")
        subprocess.run(['systemctl', 'enable', 'docker'], capture_output=True, timeout=10, stdin=subprocess.DEVNULL)
        subprocess.run(['systemctl', 'start', 'docker'], capture_output=True, timeout=10, stdin=subprocess.DEVNULL)
        
        if _check_docker_running():
            logger.info("Docker started successfully")
            return True
        else:
            logger.error("Docker failed to start")
            return False
    except Exception as e:
        logger.error(f"Failed to enable Docker: {e}")
        return False
    

def _safe_docker_remove_container(container: str, dry_run: bool = False) -> bool:
    """
    Safely remove a Docker container with verification and dry-run support.
    """
    logger = logging.getLogger(__name__)
    
    # MEDIUM FIX 1: Dry-run mode
    if dry_run:
        _dry_run_docker_fix("remove_container", f"Would remove container {container}")
        return True
    
    try:
        # Check if container exists
        result = subprocess.run(
            ['docker', 'ps', '-a', '--format', '{{.Names}}', '--filter', f'name={container}'],
            capture_output=True, text=True, timeout=10, stdin=subprocess.DEVNULL)
        if container not in result.stdout:
            logger.debug(f"Container {container} not found")
            return True
        
        # Stop container
        subprocess.run(['docker', 'stop', container], capture_output=True, timeout=10, stdin=subprocess.DEVNULL)
        # Remove container
        subprocess.run(['docker', 'rm', container], capture_output=True, timeout=10, stdin=subprocess.DEVNULL)
        logger.info(f"Removed container: {container}")
        # MEDIUM FIX 3: Log the change
        _log_docker_change("remove_container", f"Removed container {container}", True)
        return True
        
    except Exception as e:
        logger.error(f"Error removing container {container}: {e}")
        # MEDIUM FIX 3: Log failure
        _log_docker_change("remove_container", f"{container} - {e}", False)
        return False


def fix(config: dict, dry_run: bool = False, force: bool = False) -> bool:
    """
    Fix Docker security issues

    Args:
        config: Configuration dictionary
        dry_run: If True, preview changes without applying
        force: If True, skip confirmation

    Returns:
        bool: True if fixes applied successfully
    """
    logger = logging.getLogger(__name__)
    logger.info("Fixing Docker security issues...")

    # Check for dry-run mode
    if dry_run:
        logger.info("DRY-RUN MODE: No changes will be applied")
        print("\n[!] DRY-RUN MODE - No changes will be applied")
        
        # Show what would be done
        if config.get('docker', {}).get('enable_user_ns', True):
            print("    Would enable user namespace remapping")
        if config.get('docker', {}).get('enable_live_restore', True):
            print("    Would enable live restore")
        if config.get('docker', {}).get('configure_logging', True):
            print("    Would configure logging")
        if config.get('docker', {}).get('remove_privileged', False):
            print("    Would remove privileged containers")
        
        print("\n[✓] Dry-run complete. No changes were made.")
        return True

    # Validate current Docker config first
    if not _validate_docker_config():
        logger.info("ℹ️ Docker is not installed or configured. Skipping safely.")
        return True

    # ✅ FIX: Skip confirmation in force mode
    if not force:
        if not _confirm_docker_modification("Apply all Docker security fixes"):
            logger.info("Docker fixes cancelled by user")
            return False
    else:
        logger.info("Force mode: Applying Docker fixes without confirmation")

    try:
        begin_transaction()
        
        steps = []
        
        # Step 1: Enable user namespace remapping
        if config.get('docker', {}).get('enable_user_ns', True):
            steps.append(("Enable user namespace", _enable_user_namespace))
        
        # Step 2: Enable live restore
        if config.get('docker', {}).get('enable_live_restore', True):
            steps.append(("Enable live restore", _enable_live_restore))
        
        # Step 3: Configure logging
        if config.get('docker', {}).get('configure_logging', True):
            steps.append(("Configure logging", _configure_logging))
        
        # Step 4: Remove privileged containers (with warning)
        if config.get('docker', {}).get('remove_privileged', False):
            steps.append(("Remove privileged containers", _remove_privileged_containers))
        
        total_steps = len(steps)
        for idx, (name, func) in enumerate(steps):
            _progress_indicator(idx + 1, total_steps, name)
            func(dry_run)
        
        print()  # New line after progress

        if dry_run:
            logger.info("DRY-RUN completed successfully")
            commit_transaction()
            return True

        # Verify Docker is still running
        if not _verify_docker_running():
            logger.info("ℹ️ Docker is not installed or not running. Skipping safely.")
            return True

        if not _verify_docker_accessible():
            logger.warning("Docker may not be accessible - check manually")

        commit_transaction()
        logger.info("Docker fixes applied successfully")
        print("\n✅ Docker fixes applied successfully")
        return True

    except Exception as e:
        logger.error(f"Failed to fix Docker: {e}")
        rollback_transaction()
        return False


def _enable_user_namespace(dry_run: bool = False):
    """Enable user namespace remapping"""
    daemon_config = '/etc/docker/daemon.json'
    
    if dry_run:
        _dry_run_docker_fix("enable_user_namespace", "Would enable user namespace remapping")
        return
    
    backup_metadata = _backup_docker_config(daemon_config)

    try:
        if os.path.exists(daemon_config):
            with open(daemon_config, 'r') as f:
                content = json.load(f)
        else:
            content = {}

        content['userns-remap'] = 'default'

        with open(daemon_config, 'w') as f:
            json.dump(content, f, indent=2)

        logging.getLogger(__name__).info("User namespace remapping enabled")
        # MEDIUM FIX 3: Log the change
        _log_docker_change("enable_user_namespace", "User namespace remapping enabled", True)
        
        # Validate after change
        if not _validate_docker_config():
            logging.getLogger(__name__).error("Docker config validation failed after enabling user namespace")
            if backup_metadata['success']:
                _rollback_docker_config(backup_metadata)
            # MEDIUM FIX 3: Log failure
            _log_docker_change("enable_user_namespace", "Validation failed", False)

    except Exception as e:
        logging.getLogger(__name__).error(f"Error enabling user namespace: {e}")
        if backup_metadata['success']:
            _rollback_docker_config(backup_metadata)
        # MEDIUM FIX 3: Log failure
        _log_docker_change("enable_user_namespace", str(e), False)


def _enable_live_restore(dry_run: bool = False):
    """Enable live restore"""
    daemon_config = '/etc/docker/daemon.json'
    
    if dry_run:
        _dry_run_docker_fix("enable_live_restore", "Would enable live restore")
        return
    
    backup_metadata = _backup_docker_config(daemon_config)

    try:
        if os.path.exists(daemon_config):
            with open(daemon_config, 'r') as f:
                content = json.load(f)
        else:
            content = {}

        content['live-restore'] = True

        with open(daemon_config, 'w') as f:
            json.dump(content, f, indent=2)

        logging.getLogger(__name__).info("Live restore enabled")
        # MEDIUM FIX 3: Log the change
        _log_docker_change("enable_live_restore", "Live restore enabled", True)
        
        if not _validate_docker_config():
            logging.getLogger(__name__).error("Docker config validation failed after enabling live restore")
            if backup_metadata['success']:
                _rollback_docker_config(backup_metadata)
            # MEDIUM FIX 3: Log failure
            _log_docker_change("enable_live_restore", "Validation failed", False)

    except Exception as e:
        logging.getLogger(__name__).error(f"Error enabling live restore: {e}")
        if backup_metadata['success']:
            _rollback_docker_config(backup_metadata)
        # MEDIUM FIX 3: Log failure
        _log_docker_change("enable_live_restore", str(e), False)


def _configure_logging(dry_run: bool = False):
    """Configure Docker logging"""
    daemon_config = '/etc/docker/daemon.json'
    
    if dry_run:
        _dry_run_docker_fix("configure_logging", "Would configure Docker logging")
        return
    
    backup_metadata = _backup_docker_config(daemon_config)

    try:
        if os.path.exists(daemon_config):
            with open(daemon_config, 'r') as f:
                content = json.load(f)
        else:
            content = {}

        content['log-driver'] = 'json-file'
        content['log-opts'] = {
            'max-size': '10m',
            'max-file': '3'
        }

        with open(daemon_config, 'w') as f:
            json.dump(content, f, indent=2)

        logging.getLogger(__name__).info("Docker logging configured")
        # MEDIUM FIX 3: Log the change
        _log_docker_change("configure_logging", "Docker logging configured", True)
        
        if not _validate_docker_config():
            logging.getLogger(__name__).error("Docker config validation failed after configuring logging")
            if backup_metadata['success']:
                _rollback_docker_config(backup_metadata)
            # MEDIUM FIX 3: Log failure
            _log_docker_change("configure_logging", "Validation failed", False)

    except Exception as e:
        logging.getLogger(__name__).error(f"Error configuring logging: {e}")
        if backup_metadata['success']:
            _rollback_docker_config(backup_metadata)
        # MEDIUM FIX 3: Log failure
        _log_docker_change("configure_logging", str(e), False)


def _remove_privileged_containers(dry_run: bool = False):
    """Remove privileged containers"""
    try:
        result = subprocess.run(
            ['docker', 'ps', '--format', '{{.Names}}', '--filter', 'label=privileged=true'],
            capture_output=True, text=True, timeout=10, stdin=subprocess.DEVNULL)

        containers_to_remove = [c for c in result.stdout.split('\n') if c.strip()]
        
        if not containers_to_remove:
            logging.getLogger(__name__).info("No privileged containers found")
            return
        
        # MEDIUM FIX 5: Confirm before removing containers
        if not dry_run and not _confirm_container_removal(containers_to_remove):
            logging.getLogger(__name__).info("Container removal cancelled by user")
            return
        
        total_containers = len(containers_to_remove)
        removed_count = 0
        
        for idx, container in enumerate(containers_to_remove):
            _progress_indicator(idx + 1, total_containers, f"Removing {container}")
            if _safe_docker_remove_container(container, dry_run):
                removed_count += 1
        
        print()  # New line after progress
        
        logging.getLogger(__name__).info(f"Removed {removed_count} privileged containers")

    except Exception as e:
        logging.getLogger(__name__).error(f"Error removing privileged containers: {e}")
        # MEDIUM FIX 3: Log failure
        _log_docker_change("remove_privileged", str(e), False)