#!/usr/bin/env python3
"""
Shadow SSH Module
=================

Checks SSH configuration security:
- Root login (PermitRootLogin)
- Max authentication attempts (MaxAuthTries)
- Protocol version (Protocol)
- Password authentication
- Challenge response authentication
- Cipher and MAC algorithms
- SSH version
- Host key permissions
"""

from shadow.core import ui
import os
import re
import shutil
import logging
import subprocess
import tempfile
import time
import fcntl
import json
from pathlib import Path
from datetime import datetime
from typing import Tuple, Dict, List, Optional


BACKUP_DIR = Path("/var/backups/shadow/")
CHANGES_LOG = Path("/var/log/shadow/changes.log")


def _log_ssh_change(action: str, details: str, success: bool):
    logger = logging.getLogger(__name__)
    status = "SUCCESS" if success else "FAILED"
    log_entry = {
        "event": "ssh_change", "action": action, "details": details,
        "status": status, "timestamp": datetime.now().isoformat()
    }
    logger.info(f"SSH: {json.dumps(log_entry)}")
    try:
        CHANGES_LOG.parent.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(CHANGES_LOG, 'a') as f:
            f.write(f"{timestamp} - SSH: {action} - {details} ({status})\n")
    except Exception: pass


def check(config: dict) -> Tuple[str, str, dict]:
    logger = logging.getLogger(__name__)
    logger.info("Checking SSH security...")
    
    issues = []
    details = {
        'ssh_version': None, 'permit_root_login': None, 'max_auth_tries': None,
        'protocol': None, 'password_auth': None, 'challenge_response': None,
        'key_permissions_secure': False, 'ciphers': [], 'macs': [],
        'port': 22, 'config_file': '/etc/ssh/sshd_config'
    }
    
    ssh_version = _get_ssh_version()
    details['ssh_version'] = ssh_version
    if ssh_version == 'not_installed':
        issues.append("SSH is not installed")
        return 'WARN', "SSH not installed", details
    
    config_issues, config_data = _parse_ssh_config('/etc/ssh/sshd_config')
    if config_issues: issues.extend(config_issues)
    details.update(config_data)
    
    key_issues = _check_host_key_permissions()
    if key_issues: issues.extend(key_issues)
    
    if issues:
        critical = [i for i in issues if 'root login' in i.lower() or 'Protocol 1' in i]
        status = 'FAIL' if critical else 'WARN'
        message = f"{len(issues)} SSH issues found, {len(critical)} critical" if critical else f"{len(issues)} SSH issues found"
    else:
        status = 'PASS'
        message = "SSH configuration is secure"
    
    return status, message, details


def _get_ssh_version() -> str:
    try:
        result = subprocess.run(['ssh', '-V'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=10, stdin=subprocess.DEVNULL)
        for line in result.stdout.split('\n'):
            if 'OpenSSH' in line: return line.strip()
        return 'unknown'
    except FileNotFoundError: return 'not_installed'
    except Exception: return 'unknown'


def _parse_ssh_config(config_file: str) -> Tuple[List[str], Dict]:
    issues = []
    data = {
        'permit_root_login': 'unknown', 'max_auth_tries': 'unknown',
        'protocol': 'unknown', 'password_auth': 'unknown',
        'challenge_response': 'unknown', 'port': 22, 'ciphers': [], 'macs': []
    }
    
    if not os.path.exists(config_file):
        issues.append(f"SSH config file not found: {config_file}")
        return issues, data
    
    try:
        with open(config_file, 'r') as f:
            content = f.read()
            
            if re.search(r'^\s*PermitRootLogin\s+', content, re.MULTILINE):
                match = re.search(r'^\s*PermitRootLogin\s+(\S+)', content, re.MULTILINE)
                if match:
                    value = match.group(1)
                    data['permit_root_login'] = value
                    if value.lower() == 'yes': issues.append("CRITICAL: SSH root login is ENABLED")
            else:
                issues.append("PermitRootLogin not configured, default is yes")
            
            if re.search(r'^\s*MaxAuthTries\s+', content, re.MULTILINE):
                match = re.search(r'^\s*MaxAuthTries\s+(\d+)', content, re.MULTILINE)
                if match:
                    value = int(match.group(1))
                    data['max_auth_tries'] = value
                    if value > 3: issues.append(f"MaxAuthTries is {value}, should be 3 or less")
            else:
                issues.append("MaxAuthTries not configured, default is 6")
            
            if re.search(r'^\s*Protocol\s+', content, re.MULTILINE):
                match = re.search(r'^\s*Protocol\s+(\d+)', content, re.MULTILINE)
                if match:
                    value = match.group(1)
                    data['protocol'] = value
                    if value != '2': issues.append(f"Protocol {value} used, should be 2")
            else:
                data['protocol'] = '2'
            
            if re.search(r'^\s*PasswordAuthentication\s+', content, re.MULTILINE):
                match = re.search(r'^\s*PasswordAuthentication\s+(\S+)', content, re.MULTILINE)
                if match: data['password_auth'] = match.group(1)
            
            if re.search(r'^\s*ChallengeResponseAuthentication\s+', content, re.MULTILINE):
                match = re.search(r'^\s*ChallengeResponseAuthentication\s+(\S+)', content, re.MULTILINE)
                if match:
                    value = match.group(1)
                    data['challenge_response'] = value
                    if value.lower() == 'yes': issues.append("Challenge response authentication enabled (should be disabled)")
            
            if re.search(r'^\s*Port\s+', content, re.MULTILINE):
                match = re.search(r'^\s*Port\s+(\d+)', content, re.MULTILINE)
                if match: data['port'] = int(match.group(1))
            
            if re.search(r'^\s*Ciphers\s+', content, re.MULTILINE):
                match = re.search(r'^\s*Ciphers\s+(.+)$', content, re.MULTILINE)
                if match:
                    ciphers = match.group(1).split(',')
                    data['ciphers'] = ciphers
                    weak_ciphers = ['arcfour', 'aes128-cbc', 'aes256-cbc', '3des-cbc']
                    for weak in weak_ciphers:
                        if weak in ciphers: issues.append(f"Weak cipher detected: {weak}")
            
            if re.search(r'^\s*MACs\s+', content, re.MULTILINE):
                match = re.search(r'^\s*MACs\s+(.+)$', content, re.MULTILINE)
                if match:
                    macs = match.group(1).split(',')
                    data['macs'] = macs
                    weak_macs = ['hmac-md5', 'hmac-md5-96', 'hmac-sha1']
                    for weak in weak_macs:
                        if weak in macs: issues.append(f"Weak MAC detected: {weak}")
                        
    except Exception as e:
        issues.append(f"Error parsing {config_file}: {str(e)}")
    
    return issues, data


def _check_host_key_permissions() -> List[str]:
    issues = []
    host_keys = ['/etc/ssh/ssh_host_rsa_key', '/etc/ssh/ssh_host_ecdsa_key', '/etc/ssh/ssh_host_ed25519_key']
    for key_file in host_keys:
        if not os.path.exists(key_file): continue
        try:
            stat_info = os.stat(key_file)
            if stat_info.st_uid != 0 or stat_info.st_gid != 0:
                issues.append(f"{key_file} has wrong ownership: {stat_info.st_uid}:{stat_info.st_gid}")
            perms = oct(stat_info.st_mode)[-3:]
            if perms != '600':
                issues.append(f"{key_file} has wrong permissions: {perms} (should be 600)")
        except Exception as e:
            issues.append(f"Error checking {key_file}: {str(e)}")
    return issues


def _verify_backup(backup_path: Path) -> bool:
    if not backup_path.exists(): return False
    if backup_path.stat().st_size == 0: return False
    return True


def _validate_ssh_config(content: str) -> bool:
    try:
        with tempfile.NamedTemporaryFile(mode='w', suffix='.conf', delete=False) as f:
            f.write(content)
            temp_path = f.name
        
        result = subprocess.run(['sshd', '-t', '-f', temp_path], capture_output=True, text=True, timeout=10, stdin=subprocess.DEVNULL)
        os.unlink(temp_path)
        
        if result.returncode == 0: return True
        else:
            logging.getLogger(__name__).error(f"SSH config validation failed: {result.stderr}")
            return False
    except Exception as e:
        logging.getLogger(__name__).error(f"SSH config validation error: {e}")
        return False


# ✅ FIX 17: ROBUST SSH DAEMON TEST (Bypasses host key prompts)
def _test_ssh_connection(port: int = 22) -> bool:
    """Test SSH connection to verify the daemon is responding."""
    logger = logging.getLogger(__name__)
    logger.info(f"Testing SSH daemon on port {port}...")
    
    try:
        # BatchMode=yes prevents password prompts. StrictHostKeyChecking=no prevents known_hosts prompts.
        result = subprocess.run(
            ['ssh', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=no', 
             '-o', 'UserKnownHostsFile=/dev/null', '-o', 'ConnectTimeout=5', 
             '-p', str(port), 'localhost', 'exit'],
            capture_output=True,
            text=True,
            timeout=10, stdin=subprocess.DEVNULL)
        
        stderr = result.stderr.lower()
        # If connection refused or host key failed, daemon is down or blocking
        if 'connection refused' in stderr or 'host key verification failed' in stderr or 'operation timed out' in stderr:
            logger.warning(f"SSH daemon not responding: {stderr.strip()}")
            return False
        
        # "Permission denied" or "publickey" means the daemon IS running and responded!
        logger.info("SSH daemon is responding (connection test passed)")
        return True
    except Exception as e:
        logger.warning(f"SSH connection test error: {e}")
        return False


def _get_supported_ciphers() -> List[str]:
    try:
        result = subprocess.run(['ssh', '-Q', 'cipher'], capture_output=True, text=True, timeout=10, stdin=subprocess.DEVNULL)
        if result.returncode == 0:
            return [c.strip() for c in result.stdout.split('\n') if c.strip()]
    except: pass
    return []


def _safe_write_ssh_config(file_path: str, content: str, dry_run: bool = False, force: bool = False) -> bool:
    logger = logging.getLogger(__name__)
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    
    if dry_run: return _dry_run_ssh_fix("write_ssh_config", f"Would write to {file_path}")
    
    if not force:
        if not _confirm_ssh_modification(f"Write to {file_path}"):
            logger.info("SSH modification cancelled by user")
            return False
    
    lock_file = Path(file_path).with_suffix('.lock')
    fd = None
    try:
        fd = open(lock_file, 'w')
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except: pass
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
    backup_path = BACKUP_DIR / f"{Path(file_path).name}.backup_{timestamp}"
    
    if os.path.exists(file_path):
        shutil.copy2(file_path, backup_path)
        if not _verify_backup(backup_path): return False
    
    if not _validate_ssh_config(content):
        logger.error("SSH config validation failed, not writing")
        return False
    
    try:
        with tempfile.NamedTemporaryFile(mode='w', suffix='.conf', delete=False) as f:
            f.write(content)
            temp_path = f.name
        
        shutil.move(temp_path, file_path)
        
        if not _validate_ssh_config(content):
            if backup_path.exists(): shutil.copy2(backup_path, file_path)
            return False
        
        if fd:
            fcntl.flock(fd, fcntl.LOCK_UN)
            fd.close()
            lock_file.unlink(missing_ok=True)
        
        _log_ssh_change("write_ssh_config", file_path, True)
        return True
    except Exception as e:
        if backup_path.exists(): shutil.copy2(backup_path, file_path)
        return False


def _verify_ssh_running() -> bool:
    try:
        result = subprocess.run(['systemctl', 'is-active', 'ssh'], capture_output=True, text=True, timeout=10, stdin=subprocess.DEVNULL)
        return result.stdout.strip() == 'active'
    except:
        try:
            result = subprocess.run(['systemctl', 'is-active', 'sshd'], capture_output=True, text=True, timeout=10, stdin=subprocess.DEVNULL)
            return result.stdout.strip() == 'active'
        except: return False


def _dry_run_ssh_fix(action: str, details: str) -> bool:
    print(f"[DRY-RUN] Would perform: {action}")
    return True


def _confirm_ssh_modification(action: str) -> bool:
    print(f"\n[!] WARNING: About to modify SSH configuration")
    response = ui.prompt("Proceed? [y/N]: ")
    if response.lower() == 'y':
        print("\n[*] Applying fixes... please wait")
        return True
    return False


def _progress_indicator(current: int, total: int, message: str = ""):
    if total > 0:
        percent = (current / total) * 100
        print(f"\r\033[K[{current}/{total}] {percent:.1f}% - {message}", end="", flush=True)


def fix(config: dict, dry_run: bool = False, force: bool = False) -> bool:
    logger = logging.getLogger(__name__)
    logger.info("Fixing SSH security issues...")
    
    if dry_run:
        print("\n[!] DRY-RUN MODE - No changes will be applied")
        return True

    try:
        ssh_config = '/etc/ssh/sshd_config'
        if not os.path.exists(ssh_config): return False
        
        with open(ssh_config, 'r') as f:
            content = f.read()
        
        supported_ciphers = _get_supported_ciphers()
        
        fixes = [
            ('root login', _fix_permit_root_login),
            ('MaxAuthTries', _fix_max_auth_tries),
            ('Protocol', _fix_protocol),
            ('ciphers', lambda c: _fix_ciphers(c, supported_ciphers)),
            ('MACs', _fix_macs)
        ]
        
        new_content = content
        total_fixes = len(fixes)
        
        for idx, (name, fix_func) in enumerate(fixes):
            _progress_indicator(idx + 1, total_fixes, f"Fixing {name}")
            new_content = fix_func(new_content)
        print()
        
        if not _safe_write_ssh_config(ssh_config, new_content, dry_run, force):
            return False
        
        _fix_host_key_permissions()
        
        if not _validate_ssh_config(new_content):
            return False
        
        _restart_ssh()
        time.sleep(2)
        
        if not _verify_ssh_running():
            backup_files = list(BACKUP_DIR.glob("sshd_config.backup_*"))
            if backup_files:
                latest_backup = sorted(backup_files)[-1]
                shutil.copy2(latest_backup, ssh_config)
                _restart_ssh()
            return False
        
        port_match = re.search(r'^\s*Port\s+(\d+)', new_content, re.MULTILINE)
        port = int(port_match.group(1)) if port_match else 22
        
        if not _test_ssh_connection(port):
            logger.warning("SSH daemon test failed - please verify manually")
        
        return True
    except Exception as e:
        logger.error(f"Failed to fix SSH security: {e}")
        return False


def _fix_permit_root_login(content: str) -> str:
    if re.search(r'^\s*PermitRootLogin\s+', content, re.MULTILINE):
        content = re.sub(r'^\s*PermitRootLogin\s+\S+', 'PermitRootLogin no', content, flags=re.MULTILINE)
    else:
        content += '\nPermitRootLogin no\n'
    return content


def _fix_max_auth_tries(content: str) -> str:
    if re.search(r'^\s*MaxAuthTries\s+', content, re.MULTILINE):
        content = re.sub(r'^\s*MaxAuthTries\s+\d+', 'MaxAuthTries 3', content, flags=re.MULTILINE)
    else:
        content += '\nMaxAuthTries 3\n'
    return content


# ✅ FIX: Only modify Protocol if it exists (Modern OpenSSH removed this directive)
def _fix_protocol(content: str) -> str:
    if re.search(r'^\s*Protocol\s+', content, re.MULTILINE):
        content = re.sub(r'^\s*Protocol\s+\d+', 'Protocol 2', content, flags=re.MULTILINE)
    # DO NOT append "Protocol 2" if missing, as sshd -t will fail on OpenSSH >= 7.6
    return content


def _fix_ciphers(content: str, supported_ciphers: List[str] = None) -> str:
    strong_ciphers = 'chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr'
    if supported_ciphers:
        available_ciphers = [c for c in strong_ciphers.split(',') if c in supported_ciphers]
        if available_ciphers: strong_ciphers = ','.join(available_ciphers)
    
    if re.search(r'^\s*Ciphers\s+', content, re.MULTILINE):
        content = re.sub(r'^\s*Ciphers\s+\S+', f'Ciphers {strong_ciphers}', content, flags=re.MULTILINE)
    else:
        content += f'\nCiphers {strong_ciphers}\n'
    return content


def _fix_macs(content: str) -> str:
    strong_macs = 'hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-512,hmac-sha2-256'
    if re.search(r'^\s*MACs\s+', content, re.MULTILINE):
        content = re.sub(r'^\s*MACs\s+\S+', f'MACs {strong_macs}', content, flags=re.MULTILINE)
    else:
        content += f'\nMACs {strong_macs}\n'
    return content


def _fix_host_key_permissions():
    host_keys = ['/etc/ssh/ssh_host_rsa_key', '/etc/ssh/ssh_host_ecdsa_key', '/etc/ssh/ssh_host_ed25519_key']
    total_keys = len(host_keys)
    for idx, key_file in enumerate(host_keys):
        if os.path.exists(key_file):
            _progress_indicator(idx + 1, total_keys, f"Fixing {Path(key_file).name}")
            try:
                os.chown(key_file, 0, 0)
                os.chmod(key_file, 0o600)
            except Exception: pass
    print()


def _restart_ssh():
    try:
        subprocess.run(['systemctl', 'restart', 'ssh'], capture_output=True, text=True, stdin=subprocess.DEVNULL)
    except:
        try:
            subprocess.run(['systemctl', 'restart', 'sshd'], capture_output=True, text=True, stdin=subprocess.DEVNULL)
        except Exception: pass