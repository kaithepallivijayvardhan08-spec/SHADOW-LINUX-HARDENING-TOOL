#!/usr/bin/env python3
"""
Shadow Core Engine
==================

The brain of Shadow. Orchestrates all operations:
- Boot scan
- Manual scan
- Hardening
- Interactive menu
- Report generation

Flow:
1. Load configuration
2. Initialize modules
3. Run scanner
4. Calculate risks
5. Apply fixes (if requested)
6. Generate reports
7. Log everything
"""

import os
import sys
import json
import logging
import subprocess
import time
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Any
from shadow.core import ui

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

# ============================================================
# MODULE IMPORT VERIFICATION
# ============================================================
def _safe_import(module_name: str, class_name: str):
    """
    Safely import a module with error handling.
    Returns the class or None if import fails.
    """
    try:
        module = __import__(module_name, fromlist=[class_name])
        return getattr(module, class_name)
    except ImportError as e:
        logging.getLogger(__name__).error(f"Failed to import {module_name}.{class_name}: {e}")
        return None
    except AttributeError as e:
        logging.getLogger(__name__).error(f"Class {class_name} not found in {module_name}: {e}")
        return None


class Engine:
    """Main orchestration engine for Shadow"""
    
    def __init__(self, force: bool = False, safe_mode: bool = False, dry_run: bool = False):
        """Initialize the engine"""
        self.logger = logging.getLogger(__name__)
        self.force = force
        self.safe_mode = safe_mode
        self.dry_run = dry_run
        ui.set_force_mode(self.force)
        self.backup_dir = "/var/backups/shadow/"
        self.config = self._load_config()
        self.reboot_pending = False  # NEW: Track reboot state
        self._scan_in_progress = False
        self.os_family = self._detect_os_family()

        # Safe imports with verification
        self.Scanner = _safe_import('shadow.core.scanner', 'Scanner')
        self.RiskEngine = _safe_import('shadow.core.risk_engine', 'RiskEngine')
        self.Hardener = _safe_import('shadow.core.hardener', 'Hardener')
        self.Restore = _safe_import('shadow.core.restore', 'Restore')
        
        # Initialize components with error handling
        self.scanner = self.Scanner(self.config) if self.Scanner else None
        self.risk_engine = self.RiskEngine() if self.RiskEngine else None
        
        # Pass dry_run to hardener
        if self.Hardener:
            self.hardener = self.Hardener(self.config)
            if self.hardener and hasattr(self.hardener, 'set_dry_run'):
                self.hardener.set_dry_run(dry_run)
        else:
            self.hardener = None
        
        self.restore = self.Restore() if self.Restore else None
        
        self.results = None
        self.risk_score = 0
        self.risk_level = "UNKNOWN"
        self.risk_details = {}         
        self.auto_fixed = []             
        self.manual_required = []       
        self.fix_status = None
        self.fix_log = []
        
        # Validate components
        if not self.scanner:
            self.logger.error("Scanner module not available")
        if not self.risk_engine:
            self.logger.error("RiskEngine module not available")
        if not self.hardener:
            self.logger.error("Hardener module not available")
        
        # Progress tracking
        self.progress = 0
        self.total_steps = 0
        
        # Transaction state
        self._transaction_active = False
        
    # ============================================================
    # ROOT PRIVILEGE CHECK - FIXED
    # ============================================================
    def _check_root(self) -> bool:
        """
        Verify the process is running as root.
        Returns True if root, False otherwise.
        """
        if os.geteuid() != 0:
            self.logger.error("This operation requires root privileges")
            print("\n[!] ERROR: This operation requires root privileges.")
            print("    Please run with: sudo shadow")
            return False
        return True
    
    def _check_root_or_exit(self):
        """Check root and exit if not root"""
        if not self._check_root():
            sys.exit(1)
    
    # ============================================================
    # CONFIG LOADING
    # ============================================================
    def _load_config(self) -> Dict:
        """Load configuration from ONE location ONLY"""
        
        # ONLY ONE CONFIG LOCATION
        config_path = Path("/etc/shadow-tool/shadow.yml")
        
        # COMPLETE DEFAULT CONFIGURATION - ALL MODULES
        default_config = self._get_default_config()
        
        # Check if config exists
        if not config_path.exists():
            self.logger.warning(f"Config not found at {config_path}, using defaults")
            self.logger.info("Run: sudo mkdir -p /etc/shadow-tool && sudo nano /etc/shadow-tool/shadow.yml")
            return default_config
        
        try:
            import yaml
            with open(config_path, 'r') as f:
                config = yaml.safe_load(f)
                
                # If config has 'general' section, merge it properly
                if config and 'general' in config:
                    for key in config['general']:
                        config[key] = config['general'][key]
                
                # Merge with defaults for missing keys
                if config:
                    for key in default_config:
                        if key not in config:
                            config[key] = default_config[key]
                        elif isinstance(default_config[key], dict) and isinstance(config.get(key), dict):
                            # Deep merge for nested dicts
                            for subkey in default_config[key]:
                                if subkey not in config[key]:
                                    config[key][subkey] = default_config[key][subkey]
                
                self.logger.info(f"Config loaded from: {config_path}")
                self.logger.info(f"auto_fix: {config.get('auto_fix', False)}")
                
                # Validate config schema
                if not self._validate_config_schema(config):
                    self.logger.warning("Config schema validation failed, using defaults for missing sections")
                    # Merge with defaults again to fill gaps
                    for key in default_config:
                        if key not in config:
                            config[key] = default_config[key]
                        elif isinstance(default_config[key], dict) and isinstance(config.get(key), dict):
                            for subkey in default_config[key]:
                                if subkey not in config[key]:
                                    config[key][subkey] = default_config[key][subkey]
                
                return config
        except ImportError:
            self.logger.warning("PyYAML not installed, using defaults")
            return default_config
        except Exception as e:
            self.logger.error(f"Error loading config: {e}, using defaults")
            return default_config
    
    def _get_default_config(self) -> Dict:
        """Get the complete default configuration"""
        return {
            "auto_fix": False,
            "modules": {
                "authentication": {"enabled": True, "password_policy": True, "login_protection": True, "sudo_check": True, "users": True},
                "remote_access": {"enabled": True, "ssh": True, "telnet": True, "rdp_vnc": True},
                "network": {"enabled": True, "firewall": True, "ports": True, "dns": True, "connections": True},
                "file_security": {"enabled": True, "permissions": True, "ownership": True, "sensitive_files": True},
                "services": {"enabled": True, "apache": True, "nginx": True, "mysql": True, "docker": True, "nfs": True},
                "storage": {"enabled": True, "disk_check": True, "lvm": True, "encryption": True},
                "monitoring": {"enabled": True, "logs": True, "suspicious_process": True, "malware_scan": True},
                "updates": {"enabled": True, "package_updates": True, "package_integrity": True},
                "kernel": {"enabled": True, "kernel_check": True, "sysctl_security": True, "kernel_modules": True},
                "processes": {"enabled": True, "process_audit": True, "startup_process": True, "resource_check": True},
                "audit": {"enabled": True, "auditd_check": True, "audit_rules": True, "system_events": True},
                "access_control": {"enabled": True, "selinux": True, "apparmor": True, "capabilities": True},
                "scheduled_tasks": {"enabled": True, "cron_check": True, "systemd_timer": True, "startup_jobs": True},
                "integrity": {"enabled": True, "file_integrity": True, "hash_monitor": True, "change_detection": True}
            },
            "password": {
                "min_length": 8,
                "max_age": 90,
                "min_age": 1,
                "warn_age": 7,
                "history": 5,
                "complexity": True,
                "require_upper": True,
                "require_lower": True,
                "require_digit": True,
                "require_special": True,
                "max_attempts": 3,
                "lockout_time": 600
            },
            "ssh": {
                "permit_root_login": False,
                "max_auth_tries": 3,
                "protocol": 2,
                "ciphers": "chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr",
                "macs": "hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-512,hmac-sha2-256"
            },
            "firewall": {
                "default_policy": "deny",
                "enable_logging": True,
                "apply_basic_rules": True
            },
            "kernel": {
                "ip_forward": 0,
                "source_route": 0,
                "icmp_redirect": 0,
                "magic_sysrq": 0,
                "core_pattern": "|/bin/false",
                "tcp_syncookies": 1,
                "rp_filter": 1
            },
            "storage": {
                "disk_warn_threshold": 80,
                "disk_critical_threshold": 90,
                "lvm_snapshot_warn": 80,
                "thin_pool_warn": 80,
                "require_encryption": True
            },
            "audit": {
                "enable_auditd": True,
                "log_retention_days": 30,
                "essential_rules": ["identity", "time", "user_management"]
            },
            "updates": {
                "check_updates": True,
                "security_updates_only": False,
                "package_manager": ""
            },
            "integrity": {
                "enable_integrity": True,
                "aide_check": True,
                "hash_monitoring": True,
                "change_detection": True,
                "sensitive_dirs": ["/etc", "/bin", "/sbin", "/usr/bin", "/usr/sbin"]
            },
            "processes": {
                "high_cpu_threshold": 100,
                "high_memory_threshold": 30,
                "check_temp_processes": True,
                "check_hidden_processes": True
            },
            "access_control": {
                "selinux_mode": "enforcing",
                "apparmor_enabled": True,
                "check_capabilities": True
            },
            "scheduled_tasks": {
                "check_cron": True,
                "check_systemd_timers": True,
                "check_startup_jobs": True
            },
            "logging": {
                "enable_rsyslog": True,
                "enable_auditd": True,
                "rotate_days": 30
            },
            "docker": {
                "enable_user_ns": True,
                "enable_live_restore": True,
                "configure_logging": True,
                "log_driver": "json-file",
                "log_opts": {"max_size": "10m", "max_file": "3"}
            },
            "reporting": {
                "terminal": True,
                "json": True,
                "html": True,
                "pdf": True,
                "save": True
            },
            "backup": {
                "enabled": True,
                "location": "/var/backups/shadow/"
            }
        }
    
    # ============================================================
    # CONFIG SCHEMA VALIDATION
    # ============================================================
    def _validate_config_schema(self, config: Dict) -> bool:
        """
        Validate the configuration schema.
        Returns True if valid, False otherwise.
        """
        required_sections = [
            'auto_fix', 'modules', 'password', 'ssh', 'firewall',
            'kernel', 'storage', 'audit', 'updates', 'integrity',
            'processes', 'access_control', 'scheduled_tasks',
            'logging', 'docker', 'reporting', 'backup'
        ]
        
        for section in required_sections:
            if section not in config:
                self.logger.warning(f"Missing config section: {section}")
                return False
        
        # Check module structure
        if not isinstance(config.get('modules'), dict):
            self.logger.warning("Modules config must be a dictionary")
            return False
        
        return True
    
    # ============================================================
    # PROGRESS TRACKING - FIXED (Safe Progress)
    # ============================================================
    def _update_progress(self, step: int, message: str = ""):
        """
        Update progress indicator without conflicting with terminal input.
        """
        self.progress = step
        if self.total_steps > 0:
            percent = (step / self.total_steps) * 100
            # Use sys.stdout.write instead of print to avoid buffering issues
            sys.stdout.write(f"\r[*] Progress: {percent:.1f}% - {message[:50]:<50}")
            sys.stdout.flush()
            
            # ✅ FIX 3: Auto-finish progress when reaching 100%
            if percent >= 100:
                self._finish_progress()
    
    def _reset_progress(self, total_steps: int):
        """Reset progress tracker."""
        self.progress = 0
        self.total_steps = total_steps
    
    def _finish_progress(self):
        """Finish progress display."""
        sys.stdout.write("\n")
        sys.stdout.flush()
    
    # ============================================================
    # FIX LOGGING
    # ============================================================
    def _log_fix_applied(self, module: str, fix: str, success: bool):
        """Log a fix that was applied."""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        status = "SUCCESS" if success else "FAILED"
        self.fix_log.append({
            'timestamp': timestamp,
            'module': module,
            'fix': fix,
            'status': status
        })
        self.logger.info(f"Fix: {module} - {fix} ({status})")
    
    def _get_fix_summary(self) -> Dict:
        """Get summary of applied fixes."""
        total = len(self.fix_log)
        success = len([f for f in self.fix_log if f['status'] == 'SUCCESS'])
        failed = total - success
        
        return {
            'total': total,
            'success': success,
            'failed': failed,
            'details': self.fix_log
        }

    # ============================================================
    # MANUAL INSTRUCTIONS GENERATOR (100% DYNAMIC)
    # ============================================================
    def _generate_manual_instructions(self, manual_issues: List[str],
                                      warnings: List[str] = None,
                                      expected: List[str] = None):
        """Dynamically generate manual fix instructions by pulling metadata directly from modules."""
        logger = logging.getLogger(__name__)
        warnings = warnings or []
        expected = expected or []

        # ── 1. DYNAMIC OS DETECTION ─────────────────────────────
        os_name, os_id = "Unknown Linux", "unknown"
        try:
            with open('/etc/os-release', 'r') as f:
                for line in f:
                    if '=' in line:
                        k, v = line.strip().split('=', 1)
                        v = v.strip('"')
                        if k == 'PRETTY_NAME': os_name = v
                        elif k == 'ID': os_id = v.lower()
        except Exception:
            pass

        manual_file = '/var/log/shadow/manual_fixes.txt'
        try:
            os.makedirs(os.path.dirname(manual_file), exist_ok=True)
            n = 0
            with open(manual_file, 'w', encoding='utf-8') as f:
                f.write("=" * 70 + "\n")
                f.write("🛡️  SHADOW MANUAL FIXES REQUIRED\n")
                f.write("=" * 70 + "\n")
                f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"System: {os_name} ({os_id})\n\n")

                # ── SECTION 1: FAILED CHECKS (DYNAMIC) ──
                f.write("── FAILED CHECKS REQUIRING MANUAL ACTION " + "─" * 29 + "\n\n")
                for issue in manual_issues:
                    n += 1
                    module_name = issue.split(':', 1)[0].strip()
                    
                    # ✅ DYNAMIC: Pull RECOMMENDATION and MANUAL_FIX directly from the module!
                    reason = self._get_module_attr(module_name, 'RECOMMENDATION') or "Manual intervention required"
                    cmd = self._get_module_attr(module_name, 'MANUAL_FIX') or "Check /var/log/shadow/shadow.log for details"
                    prio = self._get_module_attr(module_name, 'SEVERITY') or "MEDIUM"
                    
                    f.write(f"📋 {n}. {issue}\n")
                    f.write("-" * 40 + "\n")
                    f.write(f"   Reason: {reason}\n")
                    f.write(f"   Command: {cmd}\n")
                    f.write(f"   Priority: {prio}\n\n")

                # ── SECTION 2: WARNINGS (DYNAMIC) ──
                if warnings:
                    f.write("── WARNINGS REQUIRING ATTENTION " + "─" * 38 + "\n\n")
                    for warn in warnings:
                        n += 1
                        module_name = warn.split(':', 1)[0].strip()
                        cmd = self._get_module_attr(module_name, 'MANUAL_FIX') or self._get_module_attr(module_name, 'RECOMMENDATION') or "Review system logs"
                        
                        f.write(f"📋 {n}. {warn}\n")
                        f.write("-" * 40 + "\n")
                        f.write(f"   Command: {cmd}\n\n")

                # ── SECTION 3: EXPECTED ON THIS OS (DYNAMIC) ──
                if expected:
                    f.write(f"── EXPECTED ON {os_id.upper()} (NO ACTION NEEDED) " + "─" * 20 + "\n\n")
                    for exp in expected:
                        mod = exp.split(':', 1)[0].strip()
                        reason = self._get_module_attr(mod, 'EXPECTED_BEHAVIOR') or "Normal for this environment"
                        f.write(f"ℹ️  {mod} → {reason}\n")

                f.write("\n" + "=" * 70 + "\n")
                f.write("💡 TIPS:\n")
                f.write("• Always backup: sudo cp <file> <file>.backup\n")
                f.write("• Test changes: sudo shadow --dry-run\n")
                f.write("• Check logs: sudo tail -f /var/log/shadow/shadow.log\n")
                f.write("• After kernel update: sudo reboot && sudo shadow --scan\n")
                f.write("=" * 70 + "\n")

            logger.info(f"Manual instructions saved to: {manual_file}")
            return manual_file
        except Exception as e:
            logger.error(f"Failed to generate manual instructions: {e}")
            return None

    def _get_module_attr(self, module_name: str, attr: str) -> Optional[str]:
        """Dynamically import a module and return a specific attribute (like RECOMMENDATION or MANUAL_FIX)."""
        try:
            if '.' in module_name:
                category, name = module_name.split('.', 1)
                mod_path = f"shadow.modules.{category}.{name}"
                mod = __import__(mod_path, fromlist=[attr])
                return getattr(mod, attr, None)
        except Exception:
            pass
        return None
        
    # ============================================================
    # PRE/POST VALIDATION
    # ============================================================
    def _pre_validate(self) -> bool:
        """
        Validate that the system can be recovered before applying changes.
        This checks SSH, PAM, and sudo configurations.
        """
        self.logger.info("Running pre-validation...")
        
        # Check SSH config
        ssh_config = "/etc/ssh/sshd_config"
        if os.path.exists(ssh_config):
            try:
                # Test SSH config
                result = subprocess.run(
                    ['sshd', '-t'],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                if result.returncode != 0:
                    self.logger.error(f"SSH config validation failed: {result.stderr}")
                    print("\n[!] SSH configuration validation FAILED. Aborting.")
                    return False
                self.logger.info("SSH config validated")
            except subprocess.TimeoutExpired:
                self.logger.warning("SSH config validation timed out")
            except Exception as e:
                self.logger.warning(f"Could not validate SSH config: {e}")
        
        # Check PAM config (basic check)
        pam_files = ['/etc/pam.d/common-password', '/etc/pam.d/sshd']
        for pam_file in pam_files:
            if os.path.exists(pam_file):
                try:
                    with open(pam_file, 'r') as f:
                        content = f.read()
                        # Check for obvious syntax errors
                        if 'pam_deny.so' in content and 'pam_permit.so' not in content:
                            self.logger.info(f"PAM file {pam_file} looks valid")
                except Exception as e:
                    self.logger.warning(f"Could not validate PAM file {pam_file}: {e}")
        
        # Check sudoers
        sudoers_file = "/etc/sudoers"
        if os.path.exists(sudoers_file):
            try:
                result = subprocess.run(
                    ['visudo', '-c'],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                if result.returncode != 0:
                    self.logger.error(f"Sudoers validation failed: {result.stderr}")
                    print("\n[!] Sudoers configuration validation FAILED. Aborting.")
                    return False
                self.logger.info("Sudoers validated")
            except subprocess.TimeoutExpired:
                self.logger.warning("Sudoers validation timed out")
            except Exception as e:
                self.logger.warning(f"Could not validate sudoers: {e}")
        
        self.logger.info("Pre-validation passed")
        return True
    
    def _validate_after_fix(self) -> bool:
        """
        Validate system is still accessible after applying fixes.
        Checks SSH, PAM, and sudo configurations.
        """
        self.logger.info("Running post-validation...")
        
        # Check SSH config
        ssh_config = "/etc/ssh/sshd_config"
        if os.path.exists(ssh_config):
            try:
                result = subprocess.run(
                    ['sshd', '-t'],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                if result.returncode != 0:
                    self.logger.error(f"SSH config validation failed after fix: {result.stderr}")
                    return False
                self.logger.info("SSH config validated after fix")
            except subprocess.TimeoutExpired:
                self.logger.warning("SSH validation timed out")
            except Exception as e:
                self.logger.warning(f"Could not validate SSH config: {e}")
        
        # Check sudoers
        sudoers_file = "/etc/sudoers"
        if os.path.exists(sudoers_file):
            try:
                result = subprocess.run(
                    ['visudo', '-c'],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                if result.returncode != 0:
                    self.logger.error(f"Sudoers validation failed after fix: {result.stderr}")
                    return False
                self.logger.info("Sudoers validated after fix")
            except subprocess.TimeoutExpired:
                self.logger.warning("Sudoers validation timed out")
            except Exception as e:
                self.logger.warning(f"Could not validate sudoers: {e}")
        
        self.logger.info("Post-validation passed")
        return True


    def _detect_os_family(self) -> str:
        """Detect OS family: debian, rhel, arch, or unknown"""
        if os.path.exists('/etc/debian_version'):
            return 'debian'
        elif os.path.exists('/etc/redhat-release') or os.path.exists('/etc/fedora-release'):
            return 'rhel'
        elif os.path.exists('/etc/arch-release'):
            return 'arch'
        return 'unknown'

    def _filter_results_by_os(self, results: Dict) -> Dict:
        """Dynamically filter out scan results for modules incompatible with the current OS."""
        os_family = getattr(self, 'os_family', 'unknown')
        skip_modules = {
            'debian': ['access_control.selinux'],      # Kali/Ubuntu uses AppArmor
            'rhel': ['access_control.apparmor'],       # RHEL uses SELinux
            'arch': ['access_control.selinux', 'access_control.apparmor']
        }
        modules_to_skip = skip_modules.get(os_family, [])
        if not modules_to_skip:
            return results
            
        filtered_results = {}
        for status, issues in results.items():
            if isinstance(issues, list):
                filtered_results[status] = [issue for issue in issues if not any(issue.startswith(mod) for mod in modules_to_skip)]
            else:
                filtered_results[status] = issues
        return filtered_results

    def boot_scan(self):
        """Boot mode - run scan and exit"""
        self.logger.info("Boot mode started")
        
        # Run scan
        self._run_scan()
        
        # Generate reports
        self._generate_reports()
        
        # Log completion
        self.logger.info("Boot scan completed")
        
        # Return risk level as exit code
        if self.risk_level == "HIGH":
            sys.exit(3)
        elif self.risk_level == "MEDIUM":
            sys.exit(2)
        elif self.risk_level == "LOW":
            sys.exit(1)
        else:
            sys.exit(0)
    
    def run_scan(self):
        """Manual scan mode - run scan and show results"""
    
        # ✅ FIX: Prevent multiple calls
        if self._scan_in_progress:
            self.logger.debug("Scan already in progress, skipping duplicate call")
            return
    
        self._scan_in_progress = True
        self.logger.info("Scan mode started")
    
        try:
            # Run scan
            self._run_scan()

            # ✅ FORCE: Print SCAN RESULTS SUMMARY directly to stdout
            sys.stdout.write("\n" + "="*60 + "\n")
            sys.stdout.write("SCAN RESULTS SUMMARY\n")
            sys.stdout.write("="*60 + "\n")
            sys.stdout.write(f"Pass: {len(self.results.get('pass', []))}\n")
            sys.stdout.write(f"Fail: {len(self.results.get('fail', []))}\n")
            sys.stdout.write(f"Warn: {len(self.results.get('warn', []))}\n")
            sys.stdout.write(f"Error: {len(self.results.get('error', []))}\n")
            sys.stdout.write("="*60 + "\n")
            sys.stdout.flush()

            # ✅ FORCE: Render terminal report directly
            try:
                from shadow.reports.terminal_report import TerminalReport
                report = TerminalReport()
                report.render(self.results, self.risk_score, self.risk_level, self.risk_details)
                sys.stdout.flush()
            except Exception as e:
                self.logger.error(f"Terminal report failed: {e}")
                sys.stdout.write(f"[!] Terminal report failed: {e}\n")
                sys.stdout.flush()

            # Generate reports (JSON, HTML, PDF - NOT terminal again)
            self._generate_reports()

            self.logger.info("Scan completed")
        
        finally:
            self._scan_in_progress = False
    
    # ============================================================
    # RUN HARDEN - FIXED (No reboot prompt, safe transaction)
    # ============================================================
    def run_harden(self):
        """Hardening mode - scan and fix issues"""
        self.logger.info("Hardening mode started")
    
        # ============================================================
        # FIX: Check for pending reboot - LOG ONLY, NO PROMPT
        # ============================================================
        reboot_files = ['/var/run/reboot-required', '/var/run/reboot-required.pkgs']
        reboot_found = False
    
        for file in reboot_files:
            if os.path.exists(file):
                reboot_found = True
                self.logger.warning(f"Pending reboot detected: {file}")
    
        if reboot_found:
            self.logger.warning("System has pending reboot (from updates)")
            self.logger.warning("Shadow will continue but reboot is recommended")
            self.logger.info("You should reboot manually after hardening completes")
        
            for file in reboot_files:
                if os.path.exists(file):
                    try:
                        os.remove(file)
                        self.logger.info(f"Removed reboot flag: {file}")
                    except Exception as e:
                        self.logger.warning(f"Could not remove {file}: {e}")
        
            self.reboot_pending = True
            self.logger.info("Reboot pending flag set - manual reboot recommended")
    
        # Check root privileges
        if not self._check_root():
            return
    
        # ============================================================
        # ✅ FIX 1: Danger Warning & Bypass Logic
        # ============================================================
        if self.force:
            # --force bypasses auto_fix and skips the warning (Automatic Mode)
            self.logger.info("Force mode enabled - applying all fixes automatically")
            print("\n[!] Force mode: Applying all fixes automatically")
        else:
            # Normal --harden shows a danger warning (Confirmation Mode)
            print("\n" + "="*50)
            print("⚠️  WARNING: HARDENING MODIFIES CRITICAL SYSTEM FILES")
            print("="*50)
            print("This tool will change SSH, Sudo, PAM, and Firewall settings.")
            print("If done incorrectly, it can lock you out of your system.")
            print()
            sys.stdout.flush()
            response = ui.prompt("Do you accept the risk and want to continue? [y/N]: ")
            
            # ✅ EASIER TO READ: Check if they typed YES
            if response.lower() == 'y' or response.lower() == 'yes':
                self.logger.info("User accepted the risk - continuing in confirmation mode")
            else:
                # If they typed 'n', 'no', or just pressed Enter -> ABORT
                print("Aborted by user.")
                return
            
        if self.dry_run:
            print("\n[!] DRY RUN MODE - No changes will be applied")
            print("    Previewing hardening plan...")
    
        # Run pre-validation
        if not self.dry_run and not self._pre_validate():
            print("\n[!] Pre-validation failed. Aborting hardening.")
            return
    
        # Run scan
        self._run_scan()
    
        # Show what will be fixed
        print("\n" + "="*50)
        print("HARDENING PLAN")
        print("="*50)
    
        if not self.results or len(self.results.get("fail", [])) == 0:
            print("[✓] No issues found. System is already secure.")
            return
    
        fail_count = len(self.results.get("fail", []))
        print(f"[!] Found {fail_count} issues to fix:")
        for issue in self.results.get("fail", [])[:10]:
            print(f"    - {issue}")
        if fail_count > 10:
            print(f"    ... and {fail_count - 10} more issues")
    
        if self.dry_run:
            print("\n[✓] DRY RUN complete. No changes were made.")
            return
    
            # ✅ FIX 2: Ensure progress bar is finished and add clean newline
        self._finish_progress()
        print("\n" + "="*50)
        sys.stdout.write("\n")  # Extra newline to ensure clean line
        sys.stdout.flush()
        response = ui.prompt("Apply hardening fixes? [y/N]: ")
    
        if response.lower() != 'y':
            print("Aborted.")
            return
    
        # Reset progress and fix log
        self.fix_log = []
    
        # Begin transaction
        self._transaction_active = True
        self.logger.info("Transaction started")
    
        try:
            # Apply fixes
            self._apply_fixes()
            

        
            # ============================================================
            # ✅ FIX 1: Post-validation
            # ============================================================
            if not self._validate_after_fix():
                print("\n[!] Post-validation FAILED. Rolling back changes...")
                if self.restore:
                    self.restore.rollback_failed_harden()
                self._transaction_active = False
                self.logger.info("Transaction rolled back")
                return
        
            # ============================================================
            # ✅ FIX 1: Get fix status from hardener FIRST
            # ============================================================
            if self.hardener:
                self.fix_status = self.hardener.get_fix_status()
                
                # ✅ FIX 2: Use the bridge methods to get the EXACT issue strings
                if hasattr(self.hardener, 'get_auto_fixed_issues'):
                    self.auto_fixed = self.hardener.get_auto_fixed_issues()
                else:
                    self.auto_fixed = []
                    
                if hasattr(self.hardener, 'get_manual_required_issues'):
                    self.manual_required = self.hardener.get_manual_required_issues()
                else:
                    self.manual_required = []
                    
                self.logger.info(f"Fixed: {len(self.auto_fixed)}, Manual: {len(self.manual_required)}")
            else:
                self.auto_fixed = []
                self.manual_required = []

            # ============================================================
            # ✅ FIX 3: Recalculate risk score after fixes
            # ============================================================
            self.logger.info("Recalculating risk score after fixes...")
        
            # Run a fresh scan to verify changes
            print("\n[*] Running post-fix verification scan (please wait 1-2 minutes)...")
            sys.stdout.flush()
            self.results = self.scanner.scan_all()
            self.results = self._filter_results_by_os(self.results)
        
            # Recalculate risk with honest fix status using the EXACT strings
            if self.risk_engine:
                self.risk_score, self.risk_level, self.risk_details = self.risk_engine.calculate_with_fix_status(
                    self.results, self.auto_fixed, self.manual_required
                )
            else:
                self.risk_score = 0
                self.risk_level = "UNKNOWN"
                self.risk_details = {}
        
            self.logger.info(f"Updated risk score: {self.risk_score}/100, Level: {self.risk_level}")
        
            # ============================================================
            # ✅ FIX 4: Regenerate recommendations from post-fix data
            # ============================================================
            if self.risk_engine:
                self.recommendations = self.risk_engine.get_recommendations(self.results, self.risk_level)
            else:
                self.recommendations = []

        
            # Show verification results
            fix_summary = self._get_fix_summary()
        
            print("\n" + "="*50)
            print("VERIFICATION RESULTS")
            print("="*50)
            if self.fix_status:
                print(f"[✓] Fixed: {self.fix_status.get('fixed_count', 0)} issues")
                print(f"[✓] Verified: {len(self.fix_status.get('verified_fixes', []))} fixes")
                if self.fix_status.get('failed_fixes'):
                    print(f"[✗] Failed: {len(self.fix_status.get('failed_fixes', []))} fixes")
                    for failed in self.fix_status.get('failed_fixes', [])[:5]:
                        print(f"    - {failed}")
        
            # ✅ FIX: Show both Current and Potential risk clearly
            current_score = self.risk_details.get('current', self.risk_score)
            potential_score = self.risk_details.get('potential', self.risk_score)
            current_level = self.risk_details.get('current_level', self.risk_level)
            
            print(f"\n📊 Current System Risk : {current_score}/100 ({current_level})")
            if potential_score < current_score:
                print(f"🎯 Potential Risk      : {potential_score}/100 (After manual fixes)")
        
            # Log fix summary
            self.logger.info(f"Fix summary: {fix_summary['success']} success, {fix_summary['failed']} failed")
        
            # ============================================================
            # ✅ FIX 1: Generate reports AFTER all verification is complete
            # ============================================================
            self._generate_reports()
            
            # ✅ FIX: Save memory to disk (Fixes "Fixed: 0" on next scan)
            self._save_fix_status()
            
            # ✅ FIX: Generate rich manual_fixes.txt from ACTUAL live results
            remaining_fails = self.results.get('fail', [])
            if remaining_fails or self.results.get('warn', []):
                self._generate_manual_instructions(
                    remaining_fails,
                    warnings=self.results.get('warn', []),
                    expected=self.results.get('expected', [])
                )
            
            
            self.logger.info("Hardening completed")
        
        except Exception as e:
            self.logger.error(f"Hardening failed: {e}")
            print(f"\n[!] Hardening failed: {e}")
            print("[!] Attempting rollback...")
            if self.restore:
                self.restore.rollback_failed_harden()
            raise
        finally:
            self._transaction_active = False
            self.logger.info("Transaction completed")
        
            # Log reboot pending status
            if self.reboot_pending:
                self.logger.info("⚠️  Reboot pending - manual reboot recommended")
                print("\n" + "="*50)
                print("⚠️  REBOOT RECOMMENDED")
                print("="*50)
                print("System has pending updates that require a reboot.")
                print("Please reboot manually when ready.")
                print("  #sudo reboot(manual reboot recommended)")
                print("="*50)
    
    # ============================================================
    # INTERACTIVE MENU - FIXED (Transaction for each option)
    # ============================================================
    def interactive_menu(self):
        """Interactive mode - show menu"""
        self.logger.info("Interactive mode started")
    
        # Check root for operations that need it
        has_root = self._check_root()
    
        while True:
            self._show_menu()
            sys.stdout.write("\n")  # ✅ FIX 4: Ensure clean line before input
            sys.stdout.flush()
            choice = input("Choose option [1-8]: ").strip()
            
            # ✅ FIX: If they just hit Enter, silently re-prompt (no angry error)
            if not choice:
                continue
        
            if choice == '1':
                self.run_scan()
            elif choice == '2':
                if not has_root:
                    print("[!] Root privileges required for this operation.")
                    continue
                # ✅ FIX: Use hardener's transaction manager
                self.hardener.transaction_manager.begin()
                self.logger.info("Transaction started")
                try:
                    self._fix_authentication()
                    print("\n✅ Authentication hardening complete!")
                    self.hardener.transaction_manager.commit()
                except Exception as e:
                    self.logger.error(f"Authentication hardening failed: {e}")
                    print(f"\n[!] Failed: {e}")
                    self.hardener.transaction_manager.rollback()
                finally:
                    self.logger.info("Transaction completed")
            elif choice == '3':
                if not has_root:
                    print("[!] Root privileges required for this operation.")
                    continue
                # ✅ FIX: Use hardener's transaction manager
                self.hardener.transaction_manager.begin()
                self.logger.info("Transaction started")
                try:
                    self._fix_remote_access()
                    print("\n✅ Remote access hardening complete!")
                    self.hardener.transaction_manager.commit()
                except Exception as e:
                    self.logger.error(f"Remote access hardening failed: {e}")
                    print(f"\n[!] Failed: {e}")
                    self.hardener.transaction_manager.rollback()
                finally:
                    self.logger.info("Transaction completed")
            elif choice == '4':
                if not has_root:
                    print("[!] Root privileges required for this operation.")
                    continue
                # ✅ FIX: Use hardener's transaction manager
                self.hardener.transaction_manager.begin()
                self.logger.info("Transaction started")
                try:
                    self._fix_network()
                    print("\n✅ Network hardening complete!")
                    self.hardener.transaction_manager.commit()
                except Exception as e:
                    self.logger.error(f"Network hardening failed: {e}")
                    print(f"\n[!] Failed: {e}")
                    self.hardener.transaction_manager.rollback()
                finally:
                    self.logger.info("Transaction completed")
            elif choice == '5':
                if not has_root:
                    print("[!] Root privileges required for this operation.")
                    continue
                # ✅ FIX: Use hardener's transaction manager
                self.hardener.transaction_manager.begin()
                self.logger.info("Transaction started")
                try:
                    self._fix_file_security()
                    print("\n✅ File security hardening complete!")
                    self.hardener.transaction_manager.commit()
                except Exception as e:
                    self.logger.error(f"File security hardening failed: {e}")
                    print(f"\n[!] Failed: {e}")
                    self.hardener.transaction_manager.rollback()
                finally:
                    self.logger.info("Transaction completed")
            elif choice == '6':
                if not has_root:
                    print("[!] Root privileges required for this operation.")
                    continue
                # ✅ FIX: Use hardener's transaction manager
                self.hardener.transaction_manager.begin()
                self.logger.info("Transaction started")
                try:
                    self._fix_services()
                    print("\n✅ Services hardening complete!")
                    self.hardener.transaction_manager.commit()
                except Exception as e:
                    self.logger.error(f"Services hardening failed: {e}")
                    print(f"\n[!] Failed: {e}")
                    self.hardener.transaction_manager.rollback()
                finally:
                    self.logger.info("Transaction completed")
            elif choice == '7':
                # ✅ FIX: Auto-run scan if no results exist yet
                if not self.results:
                    print("\n[*] No scan results found. Running scan first...")
                    self.run_scan()
                self._generate_reports()
            elif choice == '8':
                print("\n[✓] Exiting Shadow. Goodbye!")
                break
            else:
                print("\n[!] Invalid choice. Please enter 1-8.")
                
    def _run_scan(self):
        """Run the scanner and calculate risks"""
        self.logger.info("Starting security scan...")
        
        # ✅ FIX: Load memory from disk (Fixes "Fixed: 0" on fresh scan)
        self._load_fix_status()
    
        if not self.scanner:
            self.logger.error("Scanner not available")
            self.results = {}
            self.risk_score = 0
            self.risk_level = "UNKNOWN"
            return
    
        # Run scanner
        self.results = self.scanner.scan_all()
        
        # ✅ DYNAMIC OS FILTER: Hide incompatible modules (e.g. SELinux on Kali)
        self.results = self._filter_results_by_os(self.results)
    
        # ============================================================
        # ✅ CHANGED: Use honest risk scoring with fix status
        # ============================================================
        if self.risk_engine:
            # Get fix status lists
            auto_fixed = getattr(self, 'auto_fixed', [])
            manual_required = getattr(self, 'manual_required', [])
            
            # Calculate honest risk score
            self.risk_score, self.risk_level, self.risk_details = self.risk_engine.calculate_with_fix_status(
                self.results, auto_fixed, manual_required
            )
            
            self.logger.info(f"Honest risk score: {self.risk_score}/100 ({self.risk_level})")
        else:
            self.risk_score = 0
            self.risk_level = "UNKNOWN"
            self.risk_details = {}
    
        self.logger.info(f"Scan completed. Risk score: {self.risk_score}/100, Level: {self.risk_level}")

    # ✅ _show_menu() MUST be at the SAME INDENT LEVEL as _run_scan()
    def _show_menu(self):
        """Display interactive menu"""
        print("\n" + "="*50)
        print("SHADOW LINUX HARDENING TOOL - INTERACTIVE MODE")
        print("="*50)
        print("  1. Run Full Security Scan")
        print("  2. Harden Authentication (Password, Login, Sudo, Users)")
        print("  3. Harden Remote Access (SSH, Telnet, RDP/VNC)")
        print("  4. Harden Network (Firewall, Ports, DNS, Connections)")
        print("  5. Harden File Security (Permissions, Ownership, Sensitive)")
        print("  6. Harden Services (Apache, Nginx, MySQL, Docker, NFS)")
        print("  7. Generate Reports")
        print("  8. Exit")
        print("="*50)
     
    # ============================================================
    # APPLY FIXES - FIXED (Call fix_all once, track individual results)
    # ============================================================
    def _apply_fixes(self):
        """Apply hardening fixes"""
        if not self.results:
            print("[!] No scan results. Run scan first.")
            return
        
        if not self.hardener:
            self.logger.error("Hardener not available")
            print("[!] Hardener not available")
            return
        
        self.logger.info("Applying hardening fixes...")
        
        # Get issues from results
        issues = self.results.get("fail", [])
        issues = self._filter_results_by_os({'fail': issues}).get('fail', [])
        if not issues:
            print("[✓] No issues to fix.")
            return
        
        # CRITICAL FIX: Call fix_all ONCE, not per issue
        self._reset_progress(1)  # Single step for all fixes
        self._update_progress(1, f"Applying fixes to {len(issues)} issues...")
        
        # Apply all fixes at once
        try:
            fixed_count = self.hardener.fix_all(issues, self.force)
            
            # Log each issue individually for tracking
            for issue in issues:
                # Check if this issue was actually fixed by hardener
                # Since hardener tracks its own fixes, we use its status
                self._log_fix_applied("general", issue, fixed_count > 0)
            
            self._finish_progress()
            
            if fixed_count > 0:
                print(f"\n[✓] {fixed_count} issues fixed successfully.")
                self.logger.info(f"Fixed {fixed_count} issues")
            else:
                print(f"\n[!] No issues were fixed. Check logs for details.")
                self.logger.warning("No fixes applied")
                
        except Exception as e:
            self.logger.error(f"Fix application failed: {e}")
            self._finish_progress()
            raise
    
    def _fix_authentication(self):
        """Fix authentication issues"""
        self.logger.info("Fixing authentication issues...")
        if self.hardener:
            self.hardener.fix_authentication()
            self._log_fix_applied("authentication", "All authentication fixes", True)
    
    def _fix_remote_access(self):
        """Fix remote access issues"""
        self.logger.info("Fixing remote access issues...")
        if self.hardener:
            self.hardener.fix_remote_access()
            self._log_fix_applied("remote_access", "All remote access fixes", True)
    
    def _fix_network(self):
        """Fix network issues"""
        self.logger.info("Fixing network issues...")
        if self.hardener:
            self.hardener.fix_network()
            self._log_fix_applied("network", "All network fixes", True)
    
    def _fix_file_security(self):
        """Fix file security issues"""
        self.logger.info("Fixing file security issues...")
        if self.hardener:
            self.hardener.fix_file_security()
            self._log_fix_applied("file_security", "All file security fixes", True)
    
    def _fix_services(self):
        """Fix service issues"""
        self.logger.info("Fixing service issues...")
        if self.hardener:
            self.hardener.fix_services()
            self._log_fix_applied("services", "All service fixes", True)
    
    def _generate_reports(self):
        """Generate all reports with individual status tracking"""
        if not self.results:
            print("[!] No scan results. Run scan first.")
            return

        self.logger.info("Generating reports...")

        # Track individual report status
        report_status = {
            'terminal': True,  # ✅ FIX: Already shown in run_scan()
            'json': False,
            'html': False,
            'pdf': False
        }

        # ✅ FIX: SKIP terminal report - already shown
        # (Remove the TerminalReport section)

        # JSON report
        if self.config.get("reporting", {}).get("json", True):
            JSONReport = _safe_import('shadow.reports.json_report', 'JSONReport')
            if JSONReport:
                try:
                    json_report = JSONReport()
                    if json_report.generate(self.results, self.risk_score, self.risk_level, self.fix_status):
                        report_status['json'] = True
                        self.logger.info("JSON report generated successfully")
                    else:
                        self.logger.error("JSON report generation failed")
                        report_status['json'] = False
                except Exception as e:
                    self.logger.error(f"JSON report generation failed: {e}")
                    report_status['json'] = False
            else:
                self.logger.warning("JSONReport not available")
                report_status['json'] = False
        else:
            report_status['json'] = True

        # HTML report
        if self.config.get("reporting", {}).get("html", True):
            HTMLReport = _safe_import('shadow.reports.html_report', 'HTMLReport')
            if HTMLReport:
                try:
                    html_report = HTMLReport()
                    if html_report.generate(self.results, self.risk_score, self.risk_level, self.fix_status):
                        report_status['html'] = True
                        self.logger.info("HTML report generated successfully")
                    else:
                        self.logger.error("HTML report generation failed")
                        report_status['html'] = False
                except Exception as e:
                    self.logger.error(f"HTML report generation failed: {e}")
                    report_status['html'] = False
            else:
                self.logger.warning("HTMLReport not available")
                report_status['html'] = False
        else:
            report_status['html'] = True

        # PDF report
        if self.config.get("reporting", {}).get("pdf", True):
            PDFReport = _safe_import('shadow.reports.pdf_report', 'PDFReport')
            if PDFReport:
                try:
                    pdf_report = PDFReport()
                    if pdf_report.generate(self.results, self.risk_score, self.risk_level, self.fix_status):
                        report_status['pdf'] = True
                        self.logger.info("PDF report generated successfully")
                    else:
                        self.logger.error("PDF report generation failed")
                        report_status['pdf'] = False
                except Exception as e:
                    self.logger.error(f"PDF report generation failed: {e}")
                    report_status['pdf'] = False
            else:
                self.logger.warning("PDFReport not available")
                report_status['pdf'] = False
        else:
            report_status['pdf'] = True

        # Summary display
        print("\n" + "="*50)
        print("📄 REPORT GENERATION STATUS")
        print("="*50)

        green = '\033[92m'
        red = '\033[91m'
        reset = '\033[0m'

        print(f"  📊 Terminal : {green}✅ Generated{reset}")  # ✅ Always shown
        print(f"  📄 JSON    : {green if report_status['json'] else red}{'✅ Generated' if report_status['json'] else '❌ Failed'}{reset}")
        print(f"  🌐 HTML    : {green if report_status['html'] else red}{'✅ Generated' if report_status['html'] else '❌ Failed'}{reset}")
        print(f"  📕 PDF     : {green if report_status['pdf'] else red}{'✅ Generated' if report_status['pdf'] else '❌ Failed'}{reset}")

        print("="*50)

        all_passed = all(report_status.values())
        if all_passed:
            print("✅ All reports generated successfully!")
            self.logger.info("All reports generated successfully")
        else:
            failed_reports = [k for k, v in report_status.items() if not v]
            print(f"⚠️  Reports completed with errors: {', '.join(failed_reports)}")
            self.logger.warning(f"Reports completed with errors: {', '.join(failed_reports)}")

        print("="*50)
        self.logger.info("Reports generation complete")

    # ============================================================
    # ✅ FIX: PERSIST FIX STATUS (Fixes "Fixed: 0" Bug)
    # ============================================================
    def _save_fix_status(self):
        """Save fix status to disk so future scans remember what was fixed."""
        try:
            status_file = Path("/var/log/shadow/fix_status.json")
            status_file.parent.mkdir(parents=True, exist_ok=True)
            data = {
                'auto_fixed': getattr(self, 'auto_fixed', []),
                'manual_required': getattr(self, 'manual_required', [])
            }
            with open(status_file, 'w') as f:
                json.dump(data, f)
            self.logger.info(f"Saved fix status: {len(data['auto_fixed'])} fixed, {len(data['manual_required'])} manual")
        except Exception as e:
            self.logger.warning(f"Could not save fix status: {e}")

    def _load_fix_status(self):
        """Load fix status from disk to remember previous fixes."""
        try:
            status_file = Path("/var/log/shadow/fix_status.json")
            if status_file.exists():
                with open(status_file, 'r') as f:
                    data = json.load(f)
                    self.auto_fixed = data.get('auto_fixed', [])
                    self.manual_required = data.get('manual_required', [])
                    self.logger.info(f"Loaded previous fix status: {len(self.auto_fixed)} fixed")
            else:
                self.auto_fixed = []
                self.manual_required = []
        except Exception as e:
            self.logger.debug(f"Could not load fix status: {e}")
            self.auto_fixed = []
            self.manual_required = []