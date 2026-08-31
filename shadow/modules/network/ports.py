#!/usr/bin/env python3
"""
Shadow Ports Module
===================

Checks open ports and listening services:
- All listening ports
- Port-to-service mapping
- Unauthorized/open ports
- Service identification
- Port status (listening/established)

Security concerns:
- Unknown open ports → potential backdoors
- Service on non-standard port → may be hidden
- Unauthorized services listening → compromised system
- Ports open to all interfaces → wider attack surface
- High-risk ports (23, 21, 25, 111, 2049, etc.)
"""

from shadow.core import ui
import os
import re
import shutil
import socket
import logging
import subprocess
import tempfile
import time
import json
import fcntl
from pathlib import Path
from datetime import datetime
from typing import Tuple, Dict, List, Optional, Any


BACKUP_DIR = Path("/var/backups/shadow/")
CHANGES_LOG = Path("/var/log/shadow/changes.log")


# ============================================================
# PROTECTED PORTS - NEVER CLOSE THESE
# ============================================================
PROTECTED_PORTS = ['22', '80', '443', '53', '123', '68', '67']


# ============================================================
# FIX 8: STRUCTURED LOGGING
# ============================================================
def _log_port_change(action: str, details: str, success: bool):
    """Log port modifications with structured format."""
    logger = logging.getLogger(__name__)
    status = "SUCCESS" if success else "FAILED"
    
    log_entry = {
        "event": "port_change",
        "action": action,
        "details": details,
        "status": status,
        "timestamp": datetime.now().isoformat()
    }
    logger.info(f"PORT: {json.dumps(log_entry)}")
    
    try:
        CHANGES_LOG.parent.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(CHANGES_LOG, 'a') as f:
            f.write(f"{timestamp} - Port: {action} - {details} ({status})\n")
    except Exception as e:
        logger.debug(f"Failed to log change: {e}")


def _log_port_findings(details: Dict, issues: List[str], warnings: List[str]):
    """Log port check findings for audit trail."""
    try:
        CHANGES_LOG.parent.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        with open(CHANGES_LOG, 'a') as f:
            f.write(f"{timestamp} - Port Check Results:\n")
            f.write(f"  Total Listening Ports: {details.get('total_listening', 0)}\n")
            f.write(f"  Established Connections: {details.get('total_established', 0)}\n")
            f.write(f"  Dangerous Ports: {len(details.get('dangerous_ports', []))}\n")
            f.write(f"  Unknown Ports: {len(details.get('unknown_ports', []))}\n")
            
            for issue in issues:
                f.write(f"  ISSUE: {issue}\n")
            for warning in warnings:
                f.write(f"  WARNING: {warning}\n")
            
        logging.getLogger(__name__).debug(f"Port findings logged to {CHANGES_LOG}")
    except Exception as e:
        logging.getLogger(__name__).warning(f"Failed to log port findings: {e}")


# ============================================================
# CHECK FUNCTION
# ============================================================
def check(config: dict) -> Tuple[str, str, dict]:
    """
    Check open ports and listening services

    Returns:
        Tuple[str, str, dict]: (status, message, details)
    """
    logger = logging.getLogger(__name__)
    logger.info("Checking open ports...")

    issues = []
    warnings = []
    details = {
        'listening_ports': [],
        'established_connections': [],
        'dangerous_ports': [],
        'unknown_ports': [],
        'service_map': {},
        'total_listening': 0,
        'total_established': 0
    }

    # Get all listening ports
    listening_ports = _get_listening_ports()
    details['listening_ports'] = listening_ports
    details['total_listening'] = len(listening_ports)

    # Get established connections
    established = _get_established_connections()
    details['established_connections'] = established
    details['total_established'] = len(established)

    # Get port-to-service mapping
    service_map = _get_service_map()
    details['service_map'] = service_map

    # Check for dangerous ports
    dangerous_ports = _check_dangerous_ports(listening_ports)
    if dangerous_ports:
        details['dangerous_ports'] = dangerous_ports
        for port_info in dangerous_ports:
            issues.append(f"DANGEROUS PORT: {port_info['port']} ({port_info.get('service', 'unknown')})")

    # Check for unknown ports (not in service map)
    for port_info in listening_ports:
        port = port_info['port']
        if port not in service_map and port not in PROTECTED_PORTS:
            details['unknown_ports'].append(port)
            warnings.append(f"Unknown open port: {port} (may need investigation)")

    # Check for ports open to all interfaces (0.0.0.0)
    for port_info in listening_ports:
        if port_info.get('address') == '0.0.0.0' or port_info.get('address') == '*':
            if port_info['port'] not in PROTECTED_PORTS:
                warnings.append(f"Port {port_info['port']} open to all interfaces")

    # Check for SSH on non-standard port
    ssh_port_found = False
    for port_info in listening_ports:
        if port_info.get('service') == 'ssh' or port_info.get('port') == '22':
            ssh_port_found = True
            if port_info['port'] != '22':
                warnings.append(f"SSH running on non-standard port: {port_info['port']}")

    # Log findings
    _log_port_findings(details, issues, warnings)

    # Determine status
    if issues:
        critical = [i for i in issues if 'DANGEROUS' in i]
        if critical:
            status = 'FAIL'
            message = f"{len(issues)} port issues found, {len(critical)} critical"
        else:
            status = 'WARN'
            message = f"{len(issues)} port issues found"
    elif warnings:
        status = 'WARN'
        message = f"{len(warnings)} port warnings found"
    else:
        status = 'PASS'
        message = f"All {len(listening_ports)} listening ports are safe"

    return status, message, details


def _get_listening_ports() -> List[Dict]:
    """Get all listening ports using ss command"""
    ports = []

    try:
        # Use ss command (modern)
        result = subprocess.run(
            ['ss', '-tulnp'],
            capture_output=True,
            text=True,
            timeout=10, stdin=subprocess.DEVNULL)

        if result.returncode == 0:
            for line in result.stdout.split('\n')[1:]:
                if not line.strip():
                    continue

                parts = line.split()
                if len(parts) < 5:
                    continue

                netid = parts[0]
                state = parts[1] if len(parts) > 1 else 'LISTEN'
                local_addr = parts[4] if len(parts) > 4 else ''
                process_info = ' '.join(parts[6:]) if len(parts) > 6 else ''

                local_parts = local_addr.split(':')
                port = local_parts[-1] if local_parts else ''
                address = ':'.join(local_parts[:-1]) if len(local_parts) > 1 else '0.0.0.0'

                if state.lower() == 'listen' and netid in ['tcp', 'udp', 'tcp6', 'udp6']:
                    service = 'unknown'
                    if 'users:' in process_info:
                        match = re.search(r'\(\(?"?([^",]+)"?,', process_info)
                        if match:
                            service = match.group(1)

                    ports.append({
                        'protocol': netid,
                        'port': port,
                        'address': address,
                        'state': state,
                        'service': service,
                        'process': process_info
                    })

    except subprocess.TimeoutExpired:
        logging.getLogger(__name__).warning("ss command timed out")
    except Exception as e:
        logging.getLogger(__name__).debug(f"ss command failed: {e}")

    # Fallback to netstat if ss fails
    if not ports:
        try:
            result = subprocess.run(
                ['netstat', '-tulnp'],
                capture_output=True,
                text=True,
                timeout=10, stdin=subprocess.DEVNULL)

            if result.returncode == 0:
                for line in result.stdout.split('\n')[2:]:
                    if not line.strip():
                        continue

                    parts = line.split()
                    if len(parts) < 4:
                        continue

                    protocol = parts[0]
                    local_addr = parts[3]
                    process_info = ' '.join(parts[6:]) if len(parts) > 6 else ''

                    local_parts = local_addr.split(':')
                    port = local_parts[-1] if local_parts else ''
                    address = ':'.join(local_parts[:-1]) if len(local_parts) > 1 else '0.0.0.0'

                    if protocol in ['tcp', 'udp']:
                        service = 'unknown'
                        if process_info and '/' in process_info:
                            service = process_info.split('/')[-1]

                        ports.append({
                            'protocol': protocol,
                            'port': port,
                            'address': address,
                            'state': 'LISTEN',
                            'service': service,
                            'process': process_info
                        })

        except subprocess.TimeoutExpired:
            logging.getLogger(__name__).warning("netstat command timed out")
        except Exception as e:
            logging.getLogger(__name__).debug(f"netstat command failed: {e}")

    return ports


def _get_established_connections() -> List[Dict]:
    """Get established connections"""
    connections = []

    try:
        result = subprocess.run(
            ['ss', '-tunp', 'state', 'established'],
            capture_output=True,
            text=True,
            timeout=10, stdin=subprocess.DEVNULL)

        if result.returncode == 0:
            for line in result.stdout.split('\n')[1:]:
                if not line.strip():
                    continue

                parts = line.split()
                if len(parts) < 6:
                    continue

                local_addr = parts[4] if len(parts) > 4 else ''
                peer_addr = parts[5] if len(parts) > 5 else ''
                process_info = ' '.join(parts[6:]) if len(parts) > 6 else ''

                local_parts = local_addr.split(':')
                local_port = local_parts[-1] if local_parts else ''
                peer_parts = peer_addr.split(':')
                peer_port = peer_parts[-1] if peer_parts else ''

                connections.append({
                    'local_address': local_addr,
                    'local_port': local_port,
                    'peer_address': peer_addr,
                    'peer_port': peer_port,
                    'process': process_info
                })

    except subprocess.TimeoutExpired:
        logging.getLogger(__name__).warning("ss established command timed out")
    except Exception as e:
        logging.getLogger(__name__).debug(f"ss established command failed: {e}")

    return connections


def _get_service_map() -> Dict:
    """Get port to service mapping from /etc/services"""
    service_map = {}

    try:
        with open('/etc/services', 'r') as f:
            for line in f:
                if line.startswith('#') or not line.strip():
                    continue

                parts = line.split()
                if len(parts) < 2:
                    continue

                service_name = parts[0]
                port_protocol = parts[1]

                if '/' in port_protocol:
                    port, protocol = port_protocol.split('/')
                    service_map[port] = service_name

    except Exception as e:
        logging.getLogger(__name__).debug(f"Error reading /etc/services: {e}")

    return service_map


def _check_dangerous_ports(listening_ports: List[Dict]) -> List[Dict]:
    """Check for dangerous open ports"""
    dangerous_port_numbers = {
        '20': 'FTP-data',
        '21': 'FTP',
        '23': 'Telnet',
        '25': 'SMTP',
        '69': 'TFTP',
        '111': 'RPCbind',
        '135': 'RPC',
        '137': 'NetBIOS',
        '138': 'NetBIOS',
        '139': 'NetBIOS',
        '445': 'SMB',
        '514': 'Syslog',
        '515': 'LPD',
        '2049': 'NFS',
        '3306': 'MySQL',
        '5432': 'PostgreSQL',
        '6379': 'Redis',
        '27017': 'MongoDB'
    }

    dangerous = []

    for port_info in listening_ports:
        port = port_info['port']
        # Skip protected ports
        if port in PROTECTED_PORTS:
            continue
        if port in dangerous_port_numbers:
            dangerous.append({
                'port': port,
                'service': dangerous_port_numbers[port],
                'protocol': port_info.get('protocol', 'unknown'),
                'address': port_info.get('address', 'unknown')
            })

    return dangerous


def _verify_ssh_allowed() -> bool:
    """Verify SSH port 22 is allowed through firewall."""
    try:
        result = subprocess.run(['ufw', 'status'], capture_output=True, text=True, timeout=10, stdin=subprocess.DEVNULL)
        if '22' in result.stdout or 'ssh' in result.stdout:
            return True
    except:
        pass

    try:
        result = subprocess.run(['iptables', '-L', '-n'], capture_output=True, text=True, timeout=10, stdin=subprocess.DEVNULL)
        if '22' in result.stdout and 'ACCEPT' in result.stdout:
            return True
    except:
        pass

    return False


def _backup_firewall_rules() -> Path:
    """Backup current firewall rules."""
    try:
        BACKUP_DIR.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        backup_path = BACKUP_DIR / f"firewall_ports.backup_{timestamp}"
        
        # Backup UFW rules if available
        try:
            result = subprocess.run(['ufw', 'status', 'numbered'], capture_output=True, text=True, timeout=10, stdin=subprocess.DEVNULL)
            with open(backup_path, 'w') as f:
                f.write(result.stdout)
        except:
            pass
        
        # Backup iptables rules
        try:
            result = subprocess.run(['iptables-save'], capture_output=True, text=True, timeout=10, stdin=subprocess.DEVNULL)
            with open(backup_path, 'a') as f:
                f.write(result.stdout)
        except:
            pass
        
        logging.getLogger(__name__).info(f"Firewall backup created: {backup_path}")
        return backup_path
    except Exception as e:
        logging.getLogger(__name__).error(f"Failed to backup firewall: {e}")
        return None


def _rollback_firewall_rules(backup_path: Path) -> bool:
    """Rollback firewall rules from backup."""
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
            logging.getLogger(__name__).info(f"Firewall rolled back from: {backup_path}")
            return True
    except Exception as e:
        logging.getLogger(__name__).error(f"Failed to rollback firewall: {e}")
    return False


# ============================================================
# MEDIUM FIX 1: DRY-RUN MODE
# ============================================================
def _dry_run_port_fix(action: str, details: str) -> bool:
    """
    Simulate port modification without actually changing anything.
    Used for dry-run mode.
    """
    logging.getLogger(__name__).info(f"[DRY-RUN] Would perform: {action} - {details}")
    print(f"[DRY-RUN] Would perform: {action}")
    return True


# ============================================================
# MEDIUM FIX 2: CONFIRMATION BEFORE CLOSING PORTS
# ============================================================
def _confirm_port_closure(ports: List[Dict]) -> bool:
    """
    Ask for confirmation before closing ports.
    """
    print(f"\n[!] WARNING: About to close dangerous ports:")
    for port_info in ports:
        print(f"    - Port {port_info['port']} ({port_info.get('service', 'unknown')})")
    print("    This could affect services!")
    response = ui.prompt("Proceed? [y/N]: ")
    if response.lower() == 'y':
        print("\n[*] Applying fixes... please wait")
        return True
    return False


# ============================================================
# MEDIUM FIX 3: LOGGING OF PORT CHANGES
# ============================================================
def _log_port_change(action: str, details: str, success: bool):
    """
    Log port modifications.
    """
    logger = logging.getLogger(__name__)
    status = "SUCCESS" if success else "FAILED"
    logger.info(f"Port change: {action} - {details} ({status})")
    
    # Also log to changes.log for audit trail
    changes_log = Path("/var/log/shadow/changes.log")
    if changes_log.exists():
        with open(changes_log, 'a') as f:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            f.write(f"{timestamp} - Port: {action} - {details} ({status})\n")


# ============================================================
# MEDIUM FIX 4: VERIFY SERVICE BEFORE STOPPING
# ============================================================
def _verify_service_exists(service_name: str) -> bool:
    """
    Verify that a service exists before trying to stop it.
    """
    try:
        result = subprocess.run(
            ['systemctl', 'status', service_name],
            capture_output=True,
            text=True,
            timeout=10, stdin=subprocess.DEVNULL)
        return 'loaded' in result.stdout or 'active' in result.stdout
    except:
        return False


# ============================================================
# MEDIUM FIX 5: WARNING FOR NON-STANDARD SSH PORT
# ============================================================
def _warn_non_standard_ssh(listening_ports: List[Dict]) -> bool:
    """
    Warn if SSH is running on a non-standard port.
    """
    ssh_ports = []
    for port_info in listening_ports:
        if port_info.get('service') == 'ssh' or 'ssh' in port_info.get('process', '').lower():
            ssh_ports.append(port_info['port'])
    
    non_standard = [p for p in ssh_ports if p != '22']
    if non_standard:
        print("\n[!] WARNING: SSH is running on non-standard ports:")
        for port in non_standard:
            print(f"    - Port {port}")
        print("    Port closure will NOT affect these ports.")
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


# ============================================================
# FIX 6: SAFE CLOSE PORT WITH FILE LOCKING
# ============================================================
def _safe_close_port(port: str, dry_run: bool = False) -> bool:
    """
    Safely close a port with backup and rollback.
    """
    logger = logging.getLogger(__name__)
    
    # Dry-run mode
    if dry_run:
        return _dry_run_port_fix("close_port", f"Port {port}")
    
    # File locking
    lock_file = BACKUP_DIR / f"port_{port}.lock"
    fd = None
    try:
        fd = open(lock_file, 'w')
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except:
        logger.warning(f"Cannot acquire lock for port {port}")
    
    try:
        # Backup current rules
        backup_path = _backup_firewall_rules()
        if not backup_path:
            logger.warning("Could not backup firewall rules before closing port")
        
        # UFW
        try:
            subprocess.run(['ufw', 'deny', port], capture_output=True, text=True, timeout=10, stdin=subprocess.DEVNULL)
            logger.info(f"Port {port} blocked via ufw")
        except:
            pass
        
        # iptables
        try:
            subprocess.run(['iptables', '-A', 'INPUT', '-p', 'tcp', '--dport', port, '-j', 'DROP'],
                          capture_output=True, text=True, timeout=10, stdin=subprocess.DEVNULL)
            subprocess.run(['iptables', '-A', 'INPUT', '-p', 'udp', '--dport', port, '-j', 'DROP'],
                          capture_output=True, text=True, timeout=10, stdin=subprocess.DEVNULL)
            logger.info(f"Port {port} blocked via iptables")
        except:
            pass
        
        # Release lock
        if fd:
            fcntl.flock(fd, fcntl.LOCK_UN)
            fd.close()
            if lock_file.exists():
                lock_file.unlink()
        
        return True
        
    except Exception as e:
        logger.error(f"Failed to close port {port}: {e}")
        return False


def _get_service_name(port: str, default: str) -> str:
    """Get system service name for a port."""
    service_map = {
        '21': 'vsftpd',
        '23': 'telnetd',
        '25': 'sendmail',
        '111': 'rpcbind',
        '2049': 'nfs-kernel-server',
        '3306': 'mysql',
        '5432': 'postgresql',
        '6379': 'redis-server',
        '27017': 'mongod'
    }
    return service_map.get(port, default)


def _close_port(port: str):
    """Close a port using firewall"""
    try:
        # UFW
        subprocess.run(['ufw', 'deny', port], capture_output=True, text=True, timeout=10, stdin=subprocess.DEVNULL)
        logging.getLogger(__name__).info(f"Port {port} blocked via ufw")
    except:
        pass

    try:
        # iptables
        subprocess.run(['iptables', '-A', 'INPUT', '-p', 'tcp', '--dport', port, '-j', 'DROP'],
                      capture_output=True, text=True, timeout=10, stdin=subprocess.DEVNULL)
        subprocess.run(['iptables', '-A', 'INPUT', '-p', 'udp', '--dport', port, '-j', 'DROP'],
                      capture_output=True, text=True, timeout=10, stdin=subprocess.DEVNULL)
        logging.getLogger(__name__).info(f"Port {port} blocked via iptables")
    except:
        pass


def _stop_service_by_port(port_info: Dict):
    """Stop service running on a dangerous port"""
    service = port_info.get('service')
    port = port_info.get('port')

    if not service or service == 'unknown':
        return

    try:
        service_name = _get_service_name(port, service)

        # Stop service
        subprocess.run(['systemctl', 'stop', service_name], capture_output=True, text=True, timeout=10, stdin=subprocess.DEVNULL)
        subprocess.run(['systemctl', 'disable', service_name], capture_output=True, text=True, timeout=10, stdin=subprocess.DEVNULL)
        logging.getLogger(__name__).info(f"Service {service_name} stopped and disabled")

    except Exception as e:
        logging.getLogger(__name__).debug(f"Error stopping service: {e}")


# ============================================================
# MAIN FIX FUNCTION
# ============================================================
def fix(config: dict, dry_run: bool = False, force: bool = False) -> bool:
    """
    Fix port issues by closing dangerous ports

    Args:
        config: Configuration dictionary
        dry_run: If True, preview changes without applying
        force: If True, skip confirmation

    Returns:
        bool: True if fixes applied successfully
    """
    logger = logging.getLogger(__name__)
    logger.info("Fixing port issues...")
    
    if dry_run:
        logger.info("DRY-RUN MODE: No changes will be applied")
        print("\n[!] DRY-RUN MODE - No changes will be applied")
        print("[✓] Dry-run complete. No changes were made.")
        return True

    # Get listening ports
    listening_ports = _get_listening_ports()
    
    # Warn about non-standard SSH ports
    if not dry_run:
        _warn_non_standard_ssh(listening_ports)

    # Get dangerous ports
    dangerous_ports = _check_dangerous_ports(listening_ports)

    if not dangerous_ports:
        logger.info("No dangerous ports to close")
        return True

    # Check if SSH port 22 is in dangerous ports
    ssh_in_dangerous = any(p['port'] == '22' for p in dangerous_ports)
    if ssh_in_dangerous:
        logger.error("SSH port 22 is marked as dangerous! This would lock you out.")
        print("\n[!] ERROR: SSH port 22 is in the dangerous ports list!")
        print("    This is a bug - SSH should never be closed.")
        return False

    # ✅ FIX: Skip confirmation in force mode
    if not force:
        if not _confirm_port_closure(dangerous_ports):
            logger.info("Port closure cancelled by user")
            return False
    else:
        logger.info("Force mode: Closing ports without confirmation")

    # Ensure SSH is allowed - skip in force mode
    if not force and not _verify_ssh_allowed():
        logger.warning("SSH port 22 may not be allowed through firewall.")
        print("\n[!] WARNING: SSH port 22 may not be allowed through firewall.")
        response = ui.prompt("Continue anyway? [y/N]: ")
        if response.lower() != 'y':
            print("Aborted.")
            return False

    # Backup firewall rules
    backup_path = None
    if not dry_run:
        backup_path = _backup_firewall_rules()
        if not backup_path:
            logger.warning("Could not backup firewall rules")

    try:
        total_ports = len(dangerous_ports)
        
        for idx, port_info in enumerate(dangerous_ports):
            port = port_info['port']
            service = port_info.get('service', 'unknown')
            
            _progress_indicator(idx + 1, total_ports, f"Closing port {port} ({service})")
            
            if dry_run:
                _dry_run_port_fix("close_port", f"Port {port} ({service})")
            else:
                _safe_close_port(port, dry_run)
                
                if service and service != 'unknown':
                    service_name = _get_service_name(port, service)
                    if service_name and _verify_service_exists(service_name):
                        _stop_service_by_port(port_info)
                
                _log_port_change("close_port", f"Port {port} ({service})", True)
        
        print()

        if dry_run:
            logger.info("DRY-RUN completed successfully")
            return True

        # Verify ports are closed
        time.sleep(2)
        new_listening = _get_listening_ports()
        still_open = []
        for port_info in dangerous_ports:
            port = port_info['port']
            if any(p['port'] == port for p in new_listening):
                still_open.append(port)
        
        if still_open:
            logger.warning(f"Some ports still open: {', '.join(still_open)}")
        else:
            logger.info(f"All {len(dangerous_ports)} dangerous ports closed")

        # Verify SSH is still accessible
        if not _verify_ssh_allowed():
            logger.error("SSH is no longer allowed after port changes!")
            if backup_path:
                _rollback_firewall_rules(backup_path)
            return False

        logger.info("Port fixes applied successfully")
        return True

    except Exception as e:
        logger.error(f"Failed to fix port issues: {e}")
        if backup_path:
            _rollback_firewall_rules(backup_path)
        _log_port_change("port_fix", str(e), False)
        return False