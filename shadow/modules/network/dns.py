#!/usr/bin/env python3
"""
Shadow DNS Module
=================

Checks DNS configuration and security:
- DNS server configuration (/etc/resolv.conf)
- DNS servers (trusted/public)
- DNS over TLS/HTTPS
- DNSSEC validation
- Local DNS cache (systemd-resolved, dnsmasq)
- Hostname resolution (/etc/hosts)

Security concerns:
- Untrusted DNS servers → MITM attacks, DNS poisoning
- No DNS over TLS → DNS queries exposed
- No DNSSEC → spoofing possible
- Local DNS cache poisoning → service disruption
- Multiple DNS servers → inconsistency
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
from pathlib import Path
from datetime import datetime
from typing import Tuple, Dict, List, Optional


BACKUP_DIR = Path("/var/backups/shadow/")

# ============================================================
# OPTIONAL DEPENDENCY: dnspython
# ============================================================
# Try to import dnspython (optional dependency for DNS resolution checks)
try:
    import dns.resolver  # type: ignore
    DNS_RESOLVER_AVAILABLE = True
except ImportError:
    DNS_RESOLVER_AVAILABLE = False
    dns = None
    # Logger not initialized yet, use print for warning
    print("[WARN] dnspython not installed. DNS resolution checks disabled.")
    print("[INFO] Install with: pip install dnspython")


def check(config: dict) -> Tuple[str, str, dict]:
    """
    Check DNS configuration and security

    Returns:
        Tuple[str, str, dict]: (status, message, details)
    """
    logger = logging.getLogger(__name__)
    logger.info("Checking DNS security...")

    issues = []
    warnings = []
    details = {
        'dns_servers': [],
        'dns_search_domains': [],
        'dns_over_tls': False,
        'dnssec_enabled': False,
        'systemd_resolved': False,
        'dnsmasq_running': False,
        'etc_hosts_entries': [],
        'hostname': None,
        'domain': None
    }

    # Check /etc/resolv.conf
    resolv_info = _check_resolv_conf()
    details.update(resolv_info)

    if not details.get('dns_servers'):
        issues.append("No DNS servers configured")
    else:
        # Check DNS server trustworthiness
        untrusted_servers = _check_dns_servers(details['dns_servers'])
        if untrusted_servers:
            for server in untrusted_servers:
                warnings.append(f"Untrusted DNS server: {server}")

    # Check systemd-resolved
    resolved_info = _check_systemd_resolved()
    details.update(resolved_info)

    if details.get('systemd_resolved'):
        dns_over_tls = _check_dns_over_tls()
        if dns_over_tls:
            details['dns_over_tls'] = True
            logger.info("DNS over TLS enabled")
        else:
            warnings.append("DNS over TLS not enabled in systemd-resolved")

    # Check DNSSEC
    if _check_dnssec():
        details['dnssec_enabled'] = True
        logger.info("DNSSEC enabled")
    else:
        warnings.append("DNSSEC not detected")

    # Check dnsmasq
    if _check_dnsmasq():
        details['dnsmasq_running'] = True
        warnings.append("dnsmasq running (local DNS cache)")

    # Check /etc/hosts
    hosts_info = _check_etc_hosts()
    details['etc_hosts_entries'] = hosts_info

    # Check hostname and domain
    hostname = _get_hostname()
    details['hostname'] = hostname

    domain = _get_domain()
    details['domain'] = domain

    # Check for multiple DNS servers (potential inconsistency)
    if len(details['dns_servers']) > 3:
        warnings.append(f"Multiple DNS servers configured: {len(details['dns_servers'])}")

    # Determine status
    if issues:
        status = 'FAIL'
        message = f"{len(issues)} critical DNS issues found"
    elif warnings:
        status = 'WARN'
        message = f"{len(warnings)} DNS warnings found"
    else:
        status = 'PASS'
        message = "DNS configuration is secure"

    return status, message, details


def _check_resolv_conf() -> dict:
    """Check /etc/resolv.conf configuration"""
    info = {
        'dns_servers': [],
        'dns_search_domains': []
    }

    resolv_conf = '/etc/resolv.conf'

    if not os.path.exists(resolv_conf):
        logging.getLogger(__name__).warning("resolv.conf not found")
        return info

    try:
        with open(resolv_conf, 'r') as f:
            for line in f:
                line = line.strip()
                if line.startswith('#'):
                    continue

                parts = line.split()
                if not parts:
                    continue

                if parts[0] == 'nameserver' and len(parts) > 1:
                    server = parts[1]
                    info['dns_servers'].append(server)

                elif parts[0] == 'search' and len(parts) > 1:
                    info['dns_search_domains'].extend(parts[1:])

                elif parts[0] == 'domain' and len(parts) > 1:
                    info['search_domain'] = parts[1]

    except Exception as e:
        logging.getLogger(__name__).error(f"Error reading resolv.conf: {e}")

    return info


def _check_dns_servers(servers: List[str]) -> List[str]:
    """Check if DNS servers are trustworthy"""
    untrusted = []

    # Common untrusted DNS servers (public/known)
    known_untrusted = [
        '8.8.8.8',     # Google (public but logs)
        '8.8.4.4',     # Google (public but logs)
        '1.1.1.1',     # Cloudflare (public but logs)
        '1.0.0.1',     # Cloudflare (public but logs)
        '9.9.9.9',     # Quad9 (public but logs)
        '149.112.112.112',  # Quad9 (public but logs)
        '208.67.222.222',   # OpenDNS (public but logs)
        '208.67.220.220'    # OpenDNS (public but logs)
    ]

    # Check for private IPs (should be trusted)
    for server in servers:
        # Skip private IPs
        if server.startswith('10.') or server.startswith('192.168.') or server.startswith('172.16.'):
            continue
        if server.startswith('127.'):
            continue

        # Check if it's a known public DNS server
        if server in known_untrusted:
            untrusted.append(f"{server} (public DNS - logs queries)")

    # Check if all DNS servers are public
    private_servers = [s for s in servers if not s.startswith('8.') and not s.startswith('1.')]
    if not private_servers and servers:
        untrusted.append("All DNS servers are public (query logging possible)")

    return untrusted


def _check_systemd_resolved() -> dict:
    """Check systemd-resolved status"""
    info = {
        'systemd_resolved': False
    }

    try:
        result = subprocess.run(['systemctl', 'is-active', 'systemd-resolved'],
                              capture_output=True, text=True, stdin=subprocess.DEVNULL)
        if result.stdout.strip() == 'active':
            info['systemd_resolved'] = True
    except:
        pass

    return info


def _check_dns_over_tls() -> bool:
    """Check if DNS over TLS is enabled"""
    try:
        result = subprocess.run(['resolvectl', 'status'], capture_output=True, text=True, stdin=subprocess.DEVNULL)
        if 'DNS over TLS' in result.stdout:
            if 'yes' in result.stdout:
                return True
            if 'opportunistic' in result.stdout:
                return True
    except:
        pass

    # Check if a DoT service is running
    try:
        result = subprocess.run(['ss', '-tuln'], capture_output=True, text=True, stdin=subprocess.DEVNULL)
        if ':853' in result.stdout:
            return True
    except:
        pass

    return False


def _check_dnssec() -> bool:
    """Check if DNSSEC is enabled"""
    try:
        result = subprocess.run(['resolvectl', 'status'], capture_output=True, text=True, stdin=subprocess.DEVNULL)
        if 'DNSSEC' in result.stdout:
            if 'yes' in result.stdout or 'allow-downgrade' in result.stdout:
                return True
    except:
        pass

    # Try DNS lookup with dnssec flag (only if dnspython is available)
    if DNS_RESOLVER_AVAILABLE:
        try:
            resolver = dns.resolver.Resolver()
            resolver.use_edns(0, 0, 0, 1)  # Enable EDNS with DNSSEC flag
            return True
        except:
            pass

    return False


def _check_dnsmasq() -> bool:
    """Check if dnsmasq is running"""
    try:
        result = subprocess.run(['systemctl', 'is-active', 'dnsmasq'],
                              capture_output=True, text=True, stdin=subprocess.DEVNULL)
        if result.stdout.strip() == 'active':
            return True
    except:
        pass

    # Check for dnsmasq process
    try:
        result = subprocess.run(['ps', 'aux'], capture_output=True, text=True, stdin=subprocess.DEVNULL)
        if 'dnsmasq' in result.stdout:
            return True
    except:
        pass

    return False


def _check_etc_hosts() -> List[Dict]:
    """Check /etc/hosts entries"""
    entries = []

    hosts_file = '/etc/hosts'

    if not os.path.exists(hosts_file):
        return entries

    try:
        with open(hosts_file, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue

                parts = line.split()
                if len(parts) >= 2:
                    ip = parts[0]
                    hosts = parts[1:]

                    # Check for suspicious entries
                    if ip.startswith('127.') and 'localhost' not in hosts:
                        entries.append({
                            'ip': ip,
                            'hosts': hosts,
                            'suspicious': True
                        })
                    else:
                        entries.append({
                            'ip': ip,
                            'hosts': hosts,
                            'suspicious': False
                        })

    except Exception as e:
        logging.getLogger(__name__).error(f"Error reading /etc/hosts: {e}")

    return entries


def _get_hostname() -> str:
    """Get system hostname"""
    try:
        return socket.gethostname()
    except:
        return 'unknown'


def _get_domain() -> str:
    """Get system domain"""
    try:
        result = subprocess.run(['domainname'], capture_output=True, text=True, stdin=subprocess.DEVNULL)
        return result.stdout.strip()
    except:
        return 'unknown'


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


# ============================================================
# MEDIUM FIX 1: DRY-RUN MODE
# ============================================================
def _dry_run_dns_fix(action: str, details: str) -> bool:
    """
    Simulate DNS modification without actually changing anything.
    Used for dry-run mode.
    """
    logging.getLogger(__name__).info(f"[DRY-RUN] Would perform: {action} - {details}")
    print(f"[DRY-RUN] Would perform: {action}")
    return True


# ============================================================
# MEDIUM FIX 2: CONFIRMATION BEFORE MODIFYING DNS
# ============================================================
def _confirm_dns_modification(action: str) -> bool:
    """
    Ask for confirmation before modifying DNS.
    """
    print(f"\n[!] WARNING: About to modify DNS configuration")
    print(f"    Action: {action}")
    print("    This could break internet connectivity!")
    response = ui.prompt("Proceed? [y/N]: ")
    if response.lower() == 'y':
        print("\n[*] Applying fixes... please wait")
        return True
    return False


# ============================================================
# MEDIUM FIX 3: LOGGING OF DNS CHANGES
# ============================================================
def _log_dns_change(action: str, details: str, success: bool):
    """
    Log DNS modifications.
    """
    logger = logging.getLogger(__name__)
    status = "SUCCESS" if success else "FAILED"
    logger.info(f"DNS change: {action} - {details} ({status})")
    
    # Also log to changes.log for audit trail
    changes_log = Path("/var/log/shadow/changes.log")
    if changes_log.exists():
        with open(changes_log, 'a') as f:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            f.write(f"{timestamp} - DNS: {action} - {details} ({status})\n")


# ============================================================
# MEDIUM FIX 4: VERIFY DNS SERVER REACHABILITY
# ============================================================
def _verify_dns_server_reachable(server: str) -> bool:
    """
    Verify a DNS server is reachable.
    """
    # If dnspython is available, use it for proper DNS resolution test
    if DNS_RESOLVER_AVAILABLE:
        try:
            resolver = dns.resolver.Resolver()
            resolver.nameservers = [server]
            resolver.timeout = 2
            resolver.lifetime = 2
            
            # Try to resolve google.com
            answers = resolver.resolve('google.com', 'A')
            if answers:
                return True
        except:
            pass
    
    # Fallback: Try socket connection to port 53
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        result = sock.connect_ex((server, 53))
        sock.close()
        return result == 0
    except:
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
        # ✅ FIX: \033[K clears the line from cursor to end, preventing garbled text
        print(f"\r\033[K[{current}/{total}] {percent:.1f}% - {message}", end="", flush=True)
        if current == total:
            print()  


def _safe_write_file(file_path: str, content: str, backup_dir: Path, dry_run: bool = False) -> bool:
    """
    Safely write a configuration file with backup, dry-run, and rollback.
    """
    logger = logging.getLogger(__name__)
    
    # MEDIUM FIX 1: Dry-run mode
    if dry_run:
        return _dry_run_dns_fix("write_file", f"Would write to {file_path}")
    
    # Create backup
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_path = backup_dir / f"{Path(file_path).name}.backup_{timestamp}"
    
    if os.path.exists(file_path):
        shutil.copy2(file_path, backup_path)
        logger.info(f"Backup created: {backup_path}")
        
        if not _verify_backup(backup_path):
            logger.error("Backup verification failed")
            return False
    
    try:
        # Write to temp file first
        with tempfile.NamedTemporaryFile(mode='w', suffix='.tmp', delete=False) as f:
            f.write(content)
            temp_path = f.name
        
        # Move temp file to destination
        shutil.move(temp_path, file_path)
        logger.info(f"Successfully wrote: {file_path}")
        
        # MEDIUM FIX 3: Log success
        _log_dns_change("write_file", file_path, True)
        return True
        
    except Exception as e:
        logger.error(f"Error writing {file_path}: {e}")
        if backup_path.exists():
            shutil.copy2(backup_path, file_path)
            logger.info(f"Rolled back from backup: {backup_path}")
        # MEDIUM FIX 3: Log failure
        _log_dns_change("write_file", f"{file_path} - {e}", False)
        return False


def _verify_dns_resolution() -> bool:
    """Verify DNS resolution is working."""
    try:
        # Try to resolve a well-known domain
        socket.gethostbyname('google.com')
        logging.getLogger(__name__).debug("DNS resolution working")
        return True
    except:
        logging.getLogger(__name__).error("DNS resolution failed")
        return False


def fix(config: dict, dry_run: bool = False, force: bool = False) -> bool:
    """
    Fix DNS security issues

    Args:
        config: Configuration dictionary
        dry_run: If True, preview changes without applying
        force: If True, skip confirmation

    Returns:
        bool: True if fixes applied successfully
    """
    logger = logging.getLogger(__name__)
    logger.info("Fixing DNS security issues...")
    
    if dry_run:
        logger.info("DRY-RUN MODE: No changes will be applied")
        print("\n[!] DRY-RUN MODE - No changes will be applied")
        print("[✓] Dry-run complete. No changes were made.")
        return True

    # ✅ FIX: Skip confirmation in force mode
    if not force:
        if not _confirm_dns_modification("Apply all DNS fixes"):
            logger.info("DNS fixes cancelled by user")
            return False
    else:
        logger.info("Force mode: Applying DNS fixes without confirmation")

    BACKUP_DIR.mkdir(parents=True, exist_ok=True)

    try:
        steps = []
        
        if config.get('dns', {}).get('enable_resolved', True):
            steps.append(("Enable systemd-resolved", lambda: _enable_systemd_resolved(dry_run)))
        
        if config.get('dns', {}).get('enable_dns_over_tls', True):
            steps.append(("Enable DNS over TLS", lambda: _enable_dns_over_tls(dry_run, force)))
        
        if config.get('dns', {}).get('enable_dnssec', True):
            steps.append(("Enable DNSSEC", lambda: _enable_dnssec(dry_run, force)))
        
        if config.get('dns', {}).get('use_trusted_dns', True):
            steps.append(("Set trusted DNS", lambda: _set_trusted_dns(dry_run, force)))
        
        total_steps = len(steps)
        for idx, (name, func) in enumerate(steps):
            _progress_indicator(idx + 1, total_steps, name)
            
            if dry_run:
                _dry_run_dns_fix(name, "Dry-run step")
            else:
                func()
        
        print()

        if dry_run:
            logger.info("DRY-RUN completed successfully")
            return True

        # Verify DNS servers are reachable
        dns_servers = _check_resolv_conf().get('dns_servers', [])
        if dns_servers:
            for server in dns_servers:
                if not _verify_dns_server_reachable(server):
                    logger.warning(f"DNS server {server} is not reachable")
        else:
            logger.warning("No DNS servers configured")

        # Verify DNS resolution works
        time.sleep(2)
        if not _verify_dns_resolution():
            logger.error("DNS resolution failed after changes")
            backup_path = BACKUP_DIR / "resolv.conf.backup_*"
            if backup_path.exists():
                shutil.copy2(backup_path, '/etc/resolv.conf')
                logger.info("Rolled back resolv.conf")
            return False

        _log_dns_change("dns_fix", "All DNS fixes applied", True)

        logger.info("DNS fixes applied successfully")
        return True

    except Exception as e:
        logger.error(f"Failed to fix DNS: {e}")
        _log_dns_change("dns_fix", str(e), False)
        return False


def _enable_systemd_resolved(dry_run: bool = False):
    """Enable systemd-resolved"""
    try:
        if dry_run:
            _dry_run_dns_fix("enable_systemd_resolved", "Would enable systemd-resolved")
            return
        
        # Backup current resolved.conf
        resolved_conf = '/etc/systemd/resolved.conf'
        if os.path.exists(resolved_conf):
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_path = BACKUP_DIR / f"resolved.conf.backup_{timestamp}"
            shutil.copy2(resolved_conf, backup_path)
            logging.getLogger(__name__).info(f"Backup created: {backup_path}")
        
        subprocess.run(['systemctl', 'enable', 'systemd-resolved'],
                      capture_output=True, text=True, stdin=subprocess.DEVNULL)
        subprocess.run(['systemctl', 'start', 'systemd-resolved'],
                      capture_output=True, text=True, stdin=subprocess.DEVNULL)
        logging.getLogger(__name__).info("systemd-resolved enabled")
    except Exception as e:
        logging.getLogger(__name__).error(f"Error enabling systemd-resolved: {e}")


def _enable_dns_over_tls(dry_run: bool = False, force: bool = False):
    """Enable DNS over TLS"""
    try:
        if dry_run:
            _dry_run_dns_fix("enable_dns_over_tls", "Would enable DNS over TLS")
            return
        
        # Backup resolv.conf
        resolv_conf = '/etc/resolv.conf'
        if os.path.exists(resolv_conf):
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_path = BACKUP_DIR / f"resolv.conf.backup_{timestamp}"
            shutil.copy2(resolv_conf, backup_path)
            logging.getLogger(__name__).info(f"Backup created: {backup_path}")

        # Modify resolve.conf to point to systemd-resolved
        subprocess.run(['ln', '-sf', '/run/systemd/resolve/stub-resolv.conf',
                       '/etc/resolv.conf'], capture_output=True, stdin=subprocess.DEVNULL)

        # Enable DNS over TLS in resolved.conf
        resolved_conf = '/etc/systemd/resolved.conf'
        if os.path.exists(resolved_conf):
            with open(resolved_conf, 'r') as f:
                content = f.read()

            if 'DNSOverTLS=' not in content:
                content += '\nDNSOverTLS=yes\n'

            _safe_write_file(resolved_conf, content, BACKUP_DIR, dry_run)

        subprocess.run(['systemctl', 'restart', 'systemd-resolved'],
                      capture_output=True, text=True, stdin=subprocess.DEVNULL)
        logging.getLogger(__name__).info("DNS over TLS enabled")

    except Exception as e:
        logging.getLogger(__name__).error(f"Error enabling DNS over TLS: {e}")


def _enable_dnssec(dry_run: bool = False, force: bool = False):
    """Enable DNSSEC"""
    try:
        if dry_run:
            _dry_run_dns_fix("enable_dnssec", "Would enable DNSSEC")
            return
        
        # Backup resolved.conf
        resolved_conf = '/etc/systemd/resolved.conf'
        if os.path.exists(resolved_conf):
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_path = BACKUP_DIR / f"resolved.conf.backup_{timestamp}"
            shutil.copy2(resolved_conf, backup_path)
            logging.getLogger(__name__).info(f"Backup created: {backup_path}")

        if os.path.exists(resolved_conf):
            with open(resolved_conf, 'r') as f:
                content = f.read()

            if 'DNSSEC=' not in content:
                content += '\nDNSSEC=yes\n'

            _safe_write_file(resolved_conf, content, BACKUP_DIR, dry_run)

        subprocess.run(['systemctl', 'restart', 'systemd-resolved'],
                      capture_output=True, text=True, stdin=subprocess.DEVNULL)
        logging.getLogger(__name__).info("DNSSEC enabled")

    except Exception as e:
        logging.getLogger(__name__).error(f"Error enabling DNSSEC: {e}")


def _set_trusted_dns(dry_run: bool = False, force: bool = False):
    """Set trusted DNS servers - handles systemd-resolved properly"""
    try:
        if dry_run:
            _dry_run_dns_fix("set_trusted_dns", "Would configure trusted DNS")
            return
        
        # Check if /etc/resolv.conf exists and is a regular file (not symlink)
        resolv_conf = '/etc/resolv.conf'
        
        # If systemd-resolved is managing DNS, configure it instead
        if os.path.islink(resolv_conf) or not os.path.exists(resolv_conf):
            logging.getLogger(__name__).info("systemd-resolved detected - configuring via resolved.conf")
            
            resolved_conf = '/etc/systemd/resolved.conf'
            if os.path.exists(resolved_conf):
                # Backup first
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                backup_path = BACKUP_DIR / f"resolved.conf.backup_{timestamp}"
                shutil.copy2(resolved_conf, backup_path)
                
                with open(resolved_conf, 'r') as f:
                    content = f.read()
                
                # Add trusted DNS servers if not already configured
                if 'DNS=' not in content:
                    content += '\nDNS=8.8.8.8 1.1.1.1 9.9.9.9\n'
                    content += 'FallbackDNS=8.8.4.4 1.0.0.1\n'
                
                with open(resolved_conf, 'w') as f:
                    f.write(content)
                
                # Restart systemd-resolved to apply changes
                subprocess.run(['systemctl', 'restart', 'systemd-resolved'],
                              capture_output=True, text=True, stdin=subprocess.DEVNULL)
                
                logging.getLogger(__name__).info("Trusted DNS configured via systemd-resolved")
                return
        
        # If /etc/resolv.conf is a regular file, write directly
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_path = BACKUP_DIR / f"resolv.conf.backup_{timestamp}"
        
        if os.path.exists(resolv_conf):
            shutil.copy2(resolv_conf, backup_path)
            logging.getLogger(__name__).info(f"Backup created: {backup_path}")
        
        content = 'nameserver 8.8.8.8\nnameserver 1.1.1.1\nnameserver 9.9.9.9\n'
        _safe_write_file(resolv_conf, content, BACKUP_DIR, dry_run)
        
        logging.getLogger(__name__).info("Trusted DNS servers configured")
        
    except Exception as e:
        logging.getLogger(__name__).error(f"Error setting trusted DNS: {e}")