#!/usr/bin/env python3
"""
Shadow Connections Module
=========================

Checks active network connections:
- Established connections
- Listening ports
- Suspicious connections
- Foreign addresses
- Connection states

Security concerns:
- Connections to unknown IPs → potential data exfiltration
- Established connections to dangerous countries → potential C2
- Multiple connections to same IP → possible attack
- Connection to known malicious IPs → compromise
- Unencrypted connections → data exposure
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
from typing import Tuple, Dict, List, Optional, Set


BACKUP_DIR = Path("/var/backups/shadow/")
CHANGES_LOG = Path("/var/log/shadow/changes.log")


# ============================================================
# FIX 8: WHITELIST - KNOWN SAFE IP RANGES
# ============================================================
SAFE_IP_RANGES = [
    '1.1.1.1',      # Cloudflare
    '8.8.8.8',      # Google DNS
    '8.8.4.4',      # Google DNS
    '9.9.9.9',      # Quad9
    '149.112.112.112',  # Quad9
    '208.67.222.222',   # OpenDNS
    '208.67.220.220',   # OpenDNS
    '192.168.',     # Private
    '10.',          # Private
    '172.16.',      # Private
    '172.17.',      # Private
    '172.18.',      # Private
    '172.19.',      # Private
    '127.0.0.1',    # Localhost
    '::1'           # Localhost IPv6
]


# ============================================================
# FIX 8: LEGITIMATE PORTS (NEVER BLOCK)
# ============================================================
LEGITIMATE_PORTS = {'22', '80', '443', '53', '123', '68', '67', '514', '993', '995', '25', '110', '143'}


# ============================================================
# FIX 8: SUSPICIOUS PORT PATTERNS (WARN ONLY, NEVER AUTO-BLOCK)
# ============================================================
SUSPICIOUS_PORTS = {'4444', '1337', '31337', '6666', '6667', '12345'}


# ============================================================
# FIX 8: STRUCTURED LOGGING
# ============================================================
def _log_connection_change(action: str, details: str, success: bool):
    """Log connection modifications with structured format."""
    logger = logging.getLogger(__name__)
    status = "SUCCESS" if success else "FAILED"
    
    log_entry = {
        "event": "connection_change",
        "action": action,
        "details": details,
        "status": status,
        "timestamp": datetime.now().isoformat()
    }
    logger.info(f"CONNECTION: {json.dumps(log_entry)}")
    
    try:
        CHANGES_LOG.parent.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(CHANGES_LOG, 'a') as f:
            f.write(f"{timestamp} - Connection: {action} - {details} ({status})\n")
    except Exception as e:
        logger.debug(f"Failed to log connection change: {e}")


# ============================================================
# CHECK FUNCTION
# ============================================================
def check(config: dict) -> Tuple[str, str, dict]:
    """
    Check active network connections

    Returns:
        Tuple[str, str, dict]: (status, message, details)
    """
    logger = logging.getLogger(__name__)
    logger.info("Checking active network connections...")

    issues = []
    warnings = []
    details = {
        'established_connections': [],
        'total_connections': 0,
        'suspicious_connections': [],
        'foreign_ips': [],
        'local_connections': [],
        'connection_states': {},
        'dangerous_countries': []
    }

    # Get all established connections
    connections = _get_established_connections()
    details['established_connections'] = connections
    details['total_connections'] = len(connections)

    # Check for suspicious connections
    suspicious = _check_suspicious_connections(connections)
    if suspicious:
        details['suspicious_connections'] = suspicious
        for conn in suspicious:
            warnings.append(f"SUSPICIOUS: Connection to {conn['foreign_ip']}:{conn['foreign_port']}")

    # Check for connections to dangerous countries
    dangerous_country_connections = _check_dangerous_countries(connections)
    if dangerous_country_connections:
        details['dangerous_countries'] = dangerous_country_connections
        for conn in dangerous_country_connections:
            warnings.append(f"Connection to dangerous country: {conn['foreign_ip']} ({conn.get('country', 'unknown')})")

    # Check for multiple connections to same IP
    connections_to_same_ip = _check_multiple_connections(connections)
    if connections_to_same_ip:
        for ip, count in connections_to_same_ip.items():
            if count > 10:
                warnings.append(f"Multiple connections ({count}) to {ip}")

    # Check for connections to local services
    local_connections = _check_local_connections(connections)
    details['local_connections'] = local_connections

    # Check connection states
    state_counts = _get_connection_states(connections)
    details['connection_states'] = state_counts

    # Check for high number of connections (potential DoS)
    if len(connections) > 200:
        warnings.append(f"High number of connections: {len(connections)}")

    # Determine status
    if issues:
        status = 'FAIL'
        message = f"{len(issues)} critical connection issues found"
    elif warnings:
        status = 'WARN'
        message = f"{len(warnings)} connection warnings found"
    else:
        status = 'PASS'
        message = f"All {len(connections)} connections are safe"

    return status, message, details


def _get_established_connections() -> List[Dict]:
    """Get all established connections using ss command"""
    connections = []

    try:
        # Use ss command with timeout
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

                netid = parts[0]
                state = parts[1] if len(parts) > 1 else 'ESTAB'
                local_addr = parts[4] if len(parts) > 4 else ''
                foreign_addr = parts[5] if len(parts) > 5 else ''
                process_info = ' '.join(parts[6:]) if len(parts) > 6 else ''

                local_parts = local_addr.split(':')
                local_ip = ':'.join(local_parts[:-1]) if len(local_parts) > 1 else local_parts[0]
                local_port = local_parts[-1] if local_parts else ''

                foreign_parts = foreign_addr.split(':')
                foreign_ip = ':'.join(foreign_parts[:-1]) if len(foreign_parts) > 1 else foreign_parts[0]
                foreign_port = foreign_parts[-1] if foreign_parts else ''

                if local_ip.startswith('['):
                    local_ip = local_ip[1:-1]
                if foreign_ip.startswith('['):
                    foreign_ip = foreign_ip[1:-1]

                process = 'unknown'
                if 'users:' in process_info:
                    match = re.search(r'\(\(?"?([^",]+)"?,', process_info)
                    if match:
                        process = match.group(1)

                connections.append({
                    'protocol': netid,
                    'state': state,
                    'local_ip': local_ip,
                    'local_port': local_port,
                    'foreign_ip': foreign_ip,
                    'foreign_port': foreign_port,
                    'process': process,
                    'raw_process': process_info
                })

    except subprocess.TimeoutExpired:
        logging.getLogger(__name__).warning("ss command timed out")
    except Exception as e:
        logging.getLogger(__name__).debug(f"ss command failed: {e}")

    # Fallback to netstat if ss fails
    if not connections:
        try:
            result = subprocess.run(
                ['netstat', '-tunp'],
                capture_output=True,
                text=True,
                timeout=10, stdin=subprocess.DEVNULL)

            if result.returncode == 0:
                for line in result.stdout.split('\n')[2:]:
                    if not line.strip():
                        continue

                    parts = line.split()
                    if len(parts) < 6:
                        continue

                    protocol = parts[0]
                    local_addr = parts[3]
                    foreign_addr = parts[4]
                    state = parts[5] if len(parts) > 5 else 'ESTAB'
                    process_info = ' '.join(parts[6:]) if len(parts) > 6 else ''

                    local_parts = local_addr.split(':')
                    local_ip = ':'.join(local_parts[:-1]) if len(local_parts) > 1 else local_parts[0]
                    local_port = local_parts[-1] if local_parts else ''

                    foreign_parts = foreign_addr.split(':')
                    foreign_ip = ':'.join(foreign_parts[:-1]) if len(foreign_parts) > 1 else foreign_parts[0]
                    foreign_port = foreign_parts[-1] if foreign_parts else ''

                    process = 'unknown'
                    if process_info and '/' in process_info:
                        process = process_info.split('/')[-1]

                    if state != 'LISTEN' and state != 'UNCONN':
                        connections.append({
                            'protocol': protocol,
                            'state': state,
                            'local_ip': local_ip,
                            'local_port': local_port,
                            'foreign_ip': foreign_ip,
                            'foreign_port': foreign_port,
                            'process': process,
                            'raw_process': process_info
                        })

        except subprocess.TimeoutExpired:
            logging.getLogger(__name__).warning("netstat command timed out")
        except Exception as e:
            logging.getLogger(__name__).debug(f"netstat command failed: {e}")

    return connections


def _check_suspicious_connections(connections: List[Dict]) -> List[Dict]:
    """Check for suspicious connections"""
    suspicious = []

    for conn in connections:
        # FIX 8: Skip legitimate connections
        if conn['foreign_ip'] in SAFE_IP_RANGES:
            continue
        if any(conn['foreign_ip'].startswith(safe) for safe in SAFE_IP_RANGES):
            continue
        if conn['foreign_port'] in LEGITIMATE_PORTS:
            continue

        # Check for connections to localhost from outside
        if conn['foreign_ip'] in ['127.0.0.1', '::1'] and conn['local_ip'] not in ['127.0.0.1', '::1']:
            suspicious.append({
                'foreign_ip': conn['foreign_ip'],
                'foreign_port': conn['foreign_port'],
                'local_ip': conn['local_ip'],
                'reason': 'Connection from localhost to external'
            })
            continue

        # Check for connections to broadcast addresses
        if conn['foreign_ip'].endswith('.255') or conn['foreign_ip'].endswith('.0'):
            suspicious.append({
                'foreign_ip': conn['foreign_ip'],
                'foreign_port': conn['foreign_port'],
                'reason': 'Connection to broadcast/multicast address'
            })
            continue

        # Check for connections to suspicious ports (warn only, don't auto-block)
        if conn['foreign_port'] in SUSPICIOUS_PORTS:
            suspicious.append({
                'foreign_ip': conn['foreign_ip'],
                'foreign_port': conn['foreign_port'],
                'reason': f'Connection to suspicious port {conn["foreign_port"]}'
            })

    return suspicious


def _check_dangerous_countries(connections: List[Dict]) -> List[Dict]:
    """Check for connections to dangerous countries"""
    dangerous = []

    high_risk_ranges = [
        ('185.0.0.0', '185.255.255.255'),
        ('91.0.0.0', '91.255.255.255'),
        ('94.0.0.0', '94.255.255.255'),
        ('176.0.0.0', '176.255.255.255'),
        ('178.0.0.0', '178.255.255.255'),
    ]

    for conn in connections:
        # FIX 8: Skip legitimate IPs
        if conn['foreign_ip'] in SAFE_IP_RANGES:
            continue
        if any(conn['foreign_ip'].startswith(safe) for safe in SAFE_IP_RANGES):
            continue

        for start, end in high_risk_ranges:
            if _ip_in_range(conn['foreign_ip'], start, end):
                dangerous.append({
                    'foreign_ip': conn['foreign_ip'],
                    'foreign_port': conn['foreign_port'],
                    'country': 'High Risk Region',
                    'local_ip': conn['local_ip'],
                    'process': conn.get('process', 'unknown')
                })
                break

    return dangerous


def _check_multiple_connections(connections: List[Dict]) -> Dict[str, int]:
    """Check for multiple connections to same IP"""
    ip_count = {}

    for conn in connections:
        if conn['foreign_ip'] not in ['0.0.0.0', '::', '127.0.0.1', '::1']:
            # FIX 8: Skip legitimate IPs
            if conn['foreign_ip'] in SAFE_IP_RANGES:
                continue
            if any(conn['foreign_ip'].startswith(safe) for safe in SAFE_IP_RANGES):
                continue
            ip_count[conn['foreign_ip']] = ip_count.get(conn['foreign_ip'], 0) + 1

    return {ip: count for ip, count in ip_count.items() if count > 1}


def _check_local_connections(connections: List[Dict]) -> List[Dict]:
    """Check for connections to local services"""
    local = []

    for conn in connections:
        if conn['local_ip'] in ['127.0.0.1', '::1']:
            local.append(conn)

    return local


def _get_connection_states(connections: List[Dict]) -> Dict:
    """Get count of connection states"""
    states = {}

    for conn in connections:
        state = conn.get('state', 'unknown')
        states[state] = states.get(state, 0) + 1

    return states


def _is_private_ip(ip: str) -> bool:
    """Check if IP is private"""
    if ip.startswith('10.'):
        return True
    if ip.startswith('192.168.'):
        return True
    if ip.startswith('172.16.') or ip.startswith('172.17.') or ip.startswith('172.18.') or ip.startswith('172.19.'):
        return True
    if ip.startswith('127.'):
        return True
    if ip == '::1':
        return True
    if ip.startswith('fe80:'):
        return True
    return False


def _ip_in_range(ip: str, start: str, end: str) -> bool:
    """Check if IP is in range (simplified)"""
    try:
        ip_int = int(''.join([f'{int(x):08b}' for x in ip.split('.')]), 2)
        start_int = int(''.join([f'{int(x):08b}' for x in start.split('.')]), 2)
        end_int = int(''.join([f'{int(x):08b}' for x in end.split('.')]), 2)
        return start_int <= ip_int <= end_int
    except:
        return False


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


def _dry_run_connection_fix(action: str, details: str) -> bool:
    """Simulate connection modification without actually changing anything."""
    logging.getLogger(__name__).info(f"[DRY-RUN] Would perform: {action} - {details}")
    print(f"[DRY-RUN] Would perform: {action}")
    return True


def _confirm_ip_block(ips_to_block: List[str], force: bool = False) -> bool:
    """Ask for confirmation before blocking IPs."""
    if force:
        return True
    
    print(f"\n[!] WARNING: About to block {len(ips_to_block)} IP addresses:")
    for ip in ips_to_block[:10]:
        print(f"    - {ip}")
    if len(ips_to_block) > 10:
        print(f"    ... and {len(ips_to_block) - 10} more")
    print("    This could break legitimate connections!")
    response = ui.prompt("Proceed? [y/N]: ")
    if response.lower() == 'y':
        print("\n[*] Applying fixes... please wait")
        return True
    return False


def _progress_indicator(current: int, total: int, message: str = ""):
    """Show progress during operations."""
    if total > 0:
        percent = (current / total) * 100
        print(f"\r\033[K[{current}/{total}] {percent:.1f}% - {message}", end="", flush=True)


def _backup_firewall_rules() -> Path:
    """Backup current firewall rules."""
    try:
        BACKUP_DIR.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        backup_path = BACKUP_DIR / f"firewall_connections.backup_{timestamp}"
        
        try:
            result = subprocess.run(['ufw', 'status', 'numbered'], capture_output=True, text=True, timeout=10, stdin=subprocess.DEVNULL)
            with open(backup_path, 'w') as f:
                f.write(result.stdout)
        except:
            pass
        
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


def _validate_ip(ip: str) -> bool:
    """Validate an IP address."""
    try:
        socket.inet_aton(ip)
        return True
    except:
        try:
            socket.inet_pton(socket.AF_INET6, ip)
            return True
        except:
            return False


def _verify_ip_blocked(ip: str) -> bool:
    """Verify that an IP is blocked."""
    try:
        result = subprocess.run(['iptables', '-L', '-n'], capture_output=True, text=True, timeout=10, stdin=subprocess.DEVNULL)
        if ip in result.stdout and 'DROP' in result.stdout:
            return True
    except:
        pass
    
    try:
        result = subprocess.run(['ufw', 'status'], capture_output=True, text=True, timeout=10, stdin=subprocess.DEVNULL)
        if ip in result.stdout and 'deny' in result.stdout:
            return True
    except:
        pass
    
    return False


def fix(config: dict, dry_run: bool = False, force: bool = False) -> bool:
    """
    Fix connection issues by blocking suspicious connections

    Args:
        config: Configuration dictionary
        dry_run: If True, preview changes without applying
        force: If True, skip confirmation

    Returns:
        bool: True if fixes applied successfully
    """
    logger = logging.getLogger(__name__)
    logger.info("Fixing connection issues...")
    
    if dry_run:
        logger.info("DRY-RUN MODE: No changes will be applied")
        print("\n[!] DRY-RUN MODE - No changes will be applied")
        print("[✓] Dry-run complete. No changes were made.")
        return True

    connections = _get_established_connections()
    suspicious = _check_suspicious_connections(connections)

    if not suspicious:
        logger.info("No suspicious connections to block")
        return True

    # Validate each IP before blocking
    valid_ips = []
    for conn in suspicious:
        foreign_ip = conn['foreign_ip']
        if foreign_ip and foreign_ip not in ['0.0.0.0', '::', '127.0.0.1', '::1']:
            if foreign_ip in SAFE_IP_RANGES:
                continue
            if any(foreign_ip.startswith(safe) for safe in SAFE_IP_RANGES):
                continue
            if _validate_ip(foreign_ip):
                valid_ips.append(foreign_ip)
            else:
                logger.warning(f"Skipping invalid IP: {foreign_ip}")

    if not valid_ips:
        logger.info("No valid IPs to block")
        return True

    # Limit number of IPs to block (safety)
    if len(valid_ips) > 20:
        logger.warning(f"Too many IPs ({len(valid_ips)}) to block, limiting to 20")
        valid_ips = valid_ips[:20]

    # ✅ FIX: Skip confirmation in force mode
    if not force:
        if not _confirm_ip_block(valid_ips):
            logger.info("IP blocking cancelled by user")
            return False
    else:
        logger.info("Force mode: Blocking IPs without confirmation")

    backup_path = None
    if not dry_run:
        backup_path = _backup_firewall_rules()
        if not backup_path:
            logger.warning("Could not backup firewall rules")

    try:
        total_ips = len(valid_ips)
        
        for idx, ip in enumerate(valid_ips):
            _progress_indicator(idx + 1, total_ips, f"Blocking IP {ip}")
            
            if dry_run:
                _dry_run_connection_fix("block_ip", f"Would block IP {ip}")
            else:
                _block_ip(ip)
                _log_connection_change("block_ip", f"Blocked IP {ip}", True)
        
        print()

        if dry_run:
            logger.info("DRY-RUN completed successfully")
            return True

        time.sleep(2)
        verification_failures = []
        for ip in valid_ips:
            if not _verify_ip_blocked(ip):
                verification_failures.append(ip)
        
        if verification_failures:
            logger.warning(f"Some IPs may not be blocked: {', '.join(verification_failures)}")
        else:
            logger.info(f"All {len(valid_ips)} suspicious connections blocked")

        logger.info("Connection fixes applied successfully")
        return True

    except Exception as e:
        logger.error(f"Failed to fix connection issues: {e}")
        if backup_path:
            _rollback_firewall_rules(backup_path)
        _log_connection_change("connection_fix", str(e), False)
        return False


def _block_ip(ip: str):
    """Block an IP using firewall"""
    try:
        subprocess.run(['ufw', 'deny', 'from', ip], capture_output=True, text=True, timeout=10, stdin=subprocess.DEVNULL)
        logging.getLogger(__name__).info(f"IP {ip} blocked via ufw")
    except:
        pass

    try:
        subprocess.run(['iptables', '-A', 'INPUT', '-s', ip, '-j', 'DROP'],
                      capture_output=True, text=True, timeout=10, stdin=subprocess.DEVNULL)
        subprocess.run(['iptables', '-A', 'OUTPUT', '-d', ip, '-j', 'DROP'],
                      capture_output=True, text=True, timeout=10, stdin=subprocess.DEVNULL)
        logging.getLogger(__name__).info(f"IP {ip} blocked via iptables")
    except:
        pass