#!/usr/bin/env python3
"""
Shadow Scanner
==============

Runs all security modules and collects results.
Each module checks a specific area of Linux security.
"""

import os
import sys
import logging
import importlib
import pkgutil
import time
import contextlib
import signal
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Callable, Any

# ✅ CYBORG DISPLAY INTEGRATION
try:
    from shadow.core.cyborg_display import display as cyborg_display
    CYBORG_DISPLAY_AVAILABLE = True
except ImportError:
    CYBORG_DISPLAY_AVAILABLE = False

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))


# ============================================================
# TIMEOUT CONTEXT MANAGER - FIXED (Shared with hardener)
# ============================================================
@contextlib.contextmanager
def timeout_context(seconds: int):
    def timeout_handler(signum, frame):
        raise TimeoutError(f"Operation timed out after {seconds} seconds")
    
    original_handler = signal.signal(signal.SIGALRM, timeout_handler)
    signal.alarm(seconds)
    try:
        yield
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, original_handler)


# ============================================================
# SCAN TIME TRACKING
# ============================================================
class ScanTimer:
    def __init__(self):
        self.start_time = None
        self.end_time = None
        self.timings = {}
    
    def start(self): self.start_time = time.time()
    def end(self): self.end_time = time.time()
    
    def start_module(self, module_name: str):
        self.timings[module_name] = {'start': time.time()}
    
    def end_module(self, module_name: str):
        if module_name in self.timings:
            self.timings[module_name]['end'] = time.time()
            self.timings[module_name]['duration'] = (
                self.timings[module_name]['end'] - self.timings[module_name]['start']
            )
    
    def get_duration(self) -> float:
        if self.start_time and self.end_time: return self.end_time - self.start_time
        return 0.0
    
    def get_module_duration(self, module_name: str) -> float:
        if module_name in self.timings: return self.timings[module_name].get('duration', 0.0)
        return 0.0


class Scanner:
    """Runs all security modules"""
    
    def __init__(self, config: Dict):
        self.logger = logging.getLogger(__name__)
        self.config = config
        self.modules = []
        self.results = {"pass": [], "fail": [], "warn": [], "error": [], "expected": [], "details": {}}
        self.scan_timer = ScanTimer()
        self.module_times = {}
        self.progress_callback = None
        self.module_timeout = config.get('scan', {}).get('module_timeout', 30)
        self._load_modules()
    
    def set_progress_callback(self, callback: Callable[[int, int, str], None]):
        self.progress_callback = callback
    
    def _report_progress(self, current: int, total: int, module_name: str = ""):
        if self.progress_callback:
            try: self.progress_callback(current, total, module_name)
            except Exception as e: self.logger.debug(f"Progress callback failed: {e}")
    
    def _scan_module(self, module_info: Dict) -> Dict:
        module_name = module_info['name']
        mod = module_info['module']
        category = module_info.get('category', 'unknown')
        self.scan_timer.start_module(module_name)
        
        try:
            with timeout_context(self.module_timeout):
                result = mod.check(self.config)
            status, message, detail = self._normalize_result(result)
            result_dict = {'module': module_name, 'category': category, 'status': status, 'message': message, 'detail': detail, 'error': None}
        except TimeoutError as e:
            result_dict = {'module': module_name, 'category': category, 'status': 'ERROR', 'message': f"Module timed out after {self.module_timeout}s", 'detail': {'error': str(e)}, 'error': str(e)}
            self.logger.error(f"Module {module_name} timed out")
        except Exception as e:
            result_dict = {'module': module_name, 'category': category, 'status': 'ERROR', 'message': f"Error in module", 'detail': {'error': str(e)}, 'error': str(e)}
            self.logger.error(f"Error in module {module_name}: {e}")
        
        self.scan_timer.end_module(module_name)
        return result_dict
    
    def _normalize_result(self, result) -> Tuple[str, str, Dict]:
        if isinstance(result, tuple) and len(result) == 3:
            status, message, detail = result
            if isinstance(status, str) and isinstance(message, str):
                return status, message, detail if isinstance(detail, dict) else {}
        if isinstance(result, dict):
            status = result.get('status', 'UNKNOWN')
            message = result.get('message', '')
            detail = result.get('detail', {})
            if isinstance(status, str) and isinstance(message, str):
                return status, message, detail if isinstance(detail, dict) else {}
            if 'status' not in result and 'passed' in result:
                status = 'PASS' if result.get('passed', False) else 'FAIL'
                message = result.get('message', '')
                return status, message, {}
        if isinstance(result, bool):
            return ('PASS', 'Check passed', {}) if result else ('FAIL', 'Check failed', {})
        if isinstance(result, str): return 'PASS', result, {}
        if result is None: return 'UNKNOWN', 'No result returned', {}
        return 'UNKNOWN', f'Unexpected result type: {type(result).__name__}', {'raw': str(result)}
    
    def _load_modules(self):
        self.logger.info("Loading security modules...")
        modules_dir = Path(__file__).parent.parent / "modules"
        categories = []
        
        if modules_dir.exists():
            for item in modules_dir.iterdir():
                if item.is_dir() and not item.name.startswith('_') and not item.name.startswith('.'):
                    categories.append(item.name)
        categories.sort()
        
        if not categories:
            categories = ["authentication", "remote_access", "network", "file_security", "services", "storage", "monitoring", "updates", "kernel", "processes", "audit", "access_control", "scheduled_tasks", "integrity"]
        
        self.logger.info(f"Found {len(categories)} module categories: {', '.join(categories)}")
        
        loaded_count = 0
        disabled_count = 0
        error_count = 0
        failed_modules = []
        
        for category in categories:
            category_config = self.config.get("modules", {}).get(category, {})
            if isinstance(category_config, dict): enabled = category_config.get("enabled", True)
            elif isinstance(category_config, bool): enabled = category_config
            else: enabled = True
            
            if not enabled:
                disabled_count += 1
                continue
            
            try:
                module_dir = Path(__file__).parent.parent / "modules" / category
                if not module_dir.exists():
                    disabled_count += 1
                    continue
                
                for py_file in module_dir.glob("*.py"):
                    if py_file.name.startswith("_") or py_file.name.startswith("."): continue
                    module_name = py_file.stem
                    
                    if isinstance(category_config, dict):
                        if not category_config.get(module_name, True):
                            disabled_count += 1
                            continue
                    
                    try:
                        full_module = f"shadow.modules.{category}.{module_name}"
                        try: mod = importlib.import_module(full_module)
                        except Exception as e:
                            error_count += 1
                            failed_modules.append(f"{full_module}: {e}")
                            continue
                        
                        if not hasattr(mod, 'check'):
                            error_count += 1
                            failed_modules.append(f"{module_name}: Missing check()")
                            continue
                        
                        has_fix = hasattr(mod, 'fix') and callable(getattr(mod, 'fix', None))
                        if not hasattr(mod, 'name'): mod.name = f"{category}.{module_name}"
                        if not hasattr(mod, 'description'): mod.description = f"{module_name.replace('_', ' ').title()} module"
                        
                        self.modules.append({
                            'name': f"{category}.{module_name}", 'module': mod, 'category': category,
                            'enabled': True, 'description': getattr(mod, 'description', ''), 'has_fix': has_fix
                        })
                        loaded_count += 1
                        
                    except Exception as e:
                        error_count += 1
                        failed_modules.append(f"{module_name}: {e}")
                        
            except Exception as e:
                error_count += 1
                failed_modules.append(f"{category}: {e}")
        
        self.logger.info(f"Loaded {loaded_count} modules, {disabled_count} disabled, {error_count} errors")

    # ============================================================
    # ✅ NEW: OS-AWARE DYNAMIC ENVIRONMENT DETECTION
    # ============================================================
    def _detect_environment(self) -> Dict:
        """Dynamically detect OS, VM, and environment type"""
        env = {'os_id': 'unknown', 'os_name': 'Unknown Linux', 'is_vm': False, 'security_module': 'none'}
        
        # 1. Read OS info from /etc/os-release
        try:
            with open('/etc/os-release', 'r') as f:
                for line in f:
                    if '=' in line:
                        key, value = line.strip().split('=', 1)
                        value = value.strip('"')
                        if key == 'ID': env['os_id'] = value.lower()
                        elif key == 'PRETTY_NAME': env['os_name'] = value
        except Exception: pass
            
        # 2. Detect Virtualization
        try:
            if os.path.exists('/sys/hypervisor/type') or os.path.exists('/proc/xen') or 'hypervisor' in open('/proc/cpuinfo', 'r').read().lower():
                env['is_vm'] = True
            else:
                try:
                    product_name = open('/sys/class/dmi/id/product_name', 'r').read().lower()
                    if any(vm in product_name for vm in ['virtualbox', 'vmware', 'kvm', 'qemu', 'hyper-v']):
                        env['is_vm'] = True
                except Exception: pass
        except Exception: pass
            
        # 3. Detect Security Module
        if os.path.exists('/sys/fs/selinux'): env['security_module'] = 'selinux'
        elif os.path.exists('/sys/module/apparmor'): env['security_module'] = 'apparmor'
            
        self.logger.info(f"Detected environment: {env['os_name']} (VM: {env['is_vm']}, Security: {env['security_module']})")
        return env

    def _get_expected_warnings(self, env: Dict) -> List[str]:
        """Generate expected warnings based on DETECTED environment"""
        expected = []
        os_id = env.get('os_id', '')
        sec_mod = env.get('security_module', '')
        is_vm = env.get('is_vm', False)
        
        if sec_mod != 'selinux': expected.append('access_control.selinux')
        if sec_mod != 'apparmor': expected.append('access_control.apparmor')
            
        if is_vm:
            expected.extend(['storage.encryption', 'storage.disk_check', 'storage.lvm'])
            
        if os_id == 'kali':
            expected.extend([
                'access_control.capabilities', 'monitoring.suspicious_process',
                'services.mysql', 'services.nfs', 'services.apache', 'services.nginx',
                'file_security.permissions', 'file_security.sensitive_files', 'file_security.ownership',
                'kernel.kernel_modules', 'scheduled_tasks.startup_jobs', 'integrity.hash_monitor'
            ])
            
        return list(set(expected))

    def _filter_expected_warnings(self, results: Dict, expected_modules: List[str], env: Dict) -> Dict:
        """Move expected warnings to a separate 'expected' list so they don't inflate risk score"""
        results['expected'] = []
        new_warn = []
        
        for warn_msg in results.get('warn', []):
            module_name = warn_msg.split(':', 1)[0].strip()
            if module_name in expected_modules:
                env_note = env.get('os_name', 'Unknown OS')
                if env.get('is_vm'): env_note += " (VM)"
                results['expected'].append(f"{warn_msg} [Expected on {env_note}]")
            else:
                new_warn.append(warn_msg)
                
        results['warn'] = new_warn
        return results

    def scan_all(self) -> Dict:
        self.logger.info("Starting scan of all modules...")
        self.results = {"pass": [], "fail": [], "warn": [], "error": [], "expected": [], "details": {}}
        self.module_times = {}
        self.scan_timer.start()
        
        total_modules = len([m for m in self.modules if m.get('enabled', True)])
        processed = 0
        
        # ✅ CYBORG DISPLAY: Show scan header
        if CYBORG_DISPLAY_AVAILABLE:
            try:
                cyborg_display.start(total_modules, "SCAN")
            except Exception as e:
                self.logger.debug(f"Cyborg display start failed: {e}")
        
        for module_info in self.modules:
            if not module_info.get('enabled', True): continue
            module_name = module_info['name']
            category = module_info.get('category', 'unknown')
            processed += 1
            self._report_progress(processed, total_modules, module_name)
            
            # ✅ CYBORG DISPLAY: Show "now analyzing" message
            if CYBORG_DISPLAY_AVAILABLE:
                try:
                    cyborg_display.module_begin(processed, total_modules, category)
                except Exception as e:
                    self.logger.debug(f"Cyborg display module_begin failed: {e}")
            
            result = self._scan_module(module_info)
            duration = self.scan_timer.get_module_duration(module_name)
            self.module_times[module_name] = duration
            
            if result['status'] == 'PASS':
                self.results['pass'].append(f"{module_name}: {result['message']}")
                self.results['details'][module_name] = {'status': 'PASS', 'message': result['message'], 'duration': duration}
            elif result['status'] == 'FAIL':
                self.results['fail'].append(f"{module_name}: {result['message']}")
                self.results['details'][module_name] = {'status': 'FAIL', 'message': result['message'], 'duration': duration}
            elif result['status'] == 'WARN':
                self.results['warn'].append(f"{module_name}: {result['message']}")
                self.results['details'][module_name] = {'status': 'WARN', 'message': result['message'], 'duration': duration}
            else:
                self.results['error'].append(f"{module_name}: {result['message']}")
                self.results['details'][module_name] = {'status': 'ERROR', 'message': result['message'], 'duration': duration}
            
            # ✅ CYBORG DISPLAY: Show result for this module
            if CYBORG_DISPLAY_AVAILABLE:
                try:
                    status = result['status']
                    issue_count = 0
                    if status == 'FAIL':
                        issue_count = 1
                    elif status == 'WARN':
                        issue_count = 1
                    cyborg_display.module_result(processed, category, status, issue_count)
                except Exception as e:
                    self.logger.debug(f"Cyborg display module_result failed: {e}")

        self.scan_timer.end()
        total_duration = self.scan_timer.get_duration()
        
        self.logger.info(f"Scan complete: {len(self.results['pass'])} passed, {len(self.results['fail'])} failed, {len(self.results['warn'])} warnings, {len(self.results['error'])} errors")
        self.logger.info(f"Total scan time: {total_duration:.2f}s")
        
        slow_modules = [(name, time) for name, time in self.module_times.items() if time > 5.0]
        if slow_modules:
            slow_modules.sort(key=lambda x: x[1], reverse=True)
            for name, duration in slow_modules[:5]:
                self.logger.info(f"Slow module: {name} ({duration:.2f}s)")
                
        # ✅ NEW: OS-Aware Dynamic Filtering
        env = self._detect_environment()
        expected_modules = self._get_expected_warnings(env)
        self.results = self._filter_expected_warnings(self.results, expected_modules, env)
        self.logger.info(f"Filtered {len(self.results['expected'])} expected warnings for {env['os_name']}")
        
        # ✅ CYBORG DISPLAY: Show completion banner
        if CYBORG_DISPLAY_AVAILABLE:
            try:
                total_issues = len(self.results['fail']) + len(self.results['warn'])
                cyborg_display.finish(total_issues, total_duration)
            except Exception as e:
                self.logger.debug(f"Cyborg display finish failed: {e}")
        
        return self.results

    def scan_category(self, category: str) -> Dict:
        self.logger.info(f"Scanning category: {category}")
        self.results = {"pass": [], "fail": [], "warn": [], "error": [], "expected": [], "details": {}}
        self.module_times = {}
        self.scan_timer.start()
        total_modules = len([m for m in self.modules if m['category'] == category and m.get('enabled', True)])
        processed = 0
        
        # ✅ CYBORG DISPLAY: Show scan header
        if CYBORG_DISPLAY_AVAILABLE:
            try:
                cyborg_display.start(total_modules, "CATEGORY SCAN")
            except Exception as e:
                self.logger.debug(f"Cyborg display start failed: {e}")
        
        for module_info in self.modules:
            if module_info['category'] != category or not module_info.get('enabled', True): continue
            processed += 1
            module_name = module_info['name']
            self._report_progress(processed, total_modules, module_name)
            
            # ✅ CYBORG DISPLAY: Show "now analyzing" message
            if CYBORG_DISPLAY_AVAILABLE:
                try:
                    cyborg_display.module_begin(processed, total_modules, category)
                except Exception as e:
                    self.logger.debug(f"Cyborg display module_begin failed: {e}")
            
            result = self._scan_module(module_info)
            duration = self.scan_timer.get_module_duration(module_name)
            self.module_times[module_name] = duration
            
            if result['status'] == 'PASS':
                self.results['pass'].append(f"{module_name}: {result['message']}")
                self.results['details'][module_name] = {'status': 'PASS', 'message': result['message'], 'duration': duration}
            elif result['status'] == 'FAIL':
                self.results['fail'].append(f"{module_name}: {result['message']}")
                self.results['details'][module_name] = {'status': 'FAIL', 'message': result['message'], 'duration': duration}
            elif result['status'] == 'WARN':
                self.results['warn'].append(f"{module_name}: {result['message']}")
                self.results['details'][module_name] = {'status': 'WARN', 'message': result['message'], 'duration': duration}
            else:
                self.results['error'].append(f"{module_name}: {result['message']}")
                self.results['details'][module_name] = {'status': 'ERROR', 'message': result['message'], 'duration': duration}
            
            # ✅ CYBORG DISPLAY: Show result for this module
            if CYBORG_DISPLAY_AVAILABLE:
                try:
                    status = result['status']
                    issue_count = 1 if status in ('FAIL', 'WARN') else 0
                    cyborg_display.module_result(processed, category, status, issue_count)
                except Exception as e:
                    self.logger.debug(f"Cyborg display module_result failed: {e}")
        
        self.scan_timer.end()
        
        # ✅ NEW: Apply filtering to category scans too
        env = self._detect_environment()
        expected_modules = self._get_expected_warnings(env)
        self.results = self._filter_expected_warnings(self.results, expected_modules, env)
        
        # ✅ CYBORG DISPLAY: Show completion banner
        if CYBORG_DISPLAY_AVAILABLE:
            try:
                total_issues = len(self.results['fail']) + len(self.results['warn'])
                cyborg_display.finish(total_issues, self.scan_timer.get_duration())
            except Exception as e:
                self.logger.debug(f"Cyborg display finish failed: {e}")
        
        return self.results
    
    def check_module_dependencies(self) -> Dict[str, List[str]]:
        dependencies = {}
        for module_info in self.modules:
            module_name = module_info['name']
            mod = module_info['module']
            if hasattr(mod, 'DEPENDENCIES'):
                deps = getattr(mod, 'DEPENDENCIES')
                if isinstance(deps, list): dependencies[module_name] = deps
            else: dependencies[module_name] = []
        return dependencies
    
    def verify_dependencies(self) -> Tuple[bool, List[str]]:
        missing = []
        deps = self.check_module_dependencies()
        for module_name, dep_list in deps.items():
            for dep in dep_list:
                found = any(m['name'] == dep for m in self.modules)
                if not found: missing.append(f"{module_name} -> {dep}")
        return len(missing) == 0, missing
    
    def get_module_info(self) -> List[Dict]: return self.modules
    
    def get_result_summary(self) -> Dict:
        total = len(self.results['pass']) + len(self.results['fail']) + len(self.results['warn']) + len(self.results['error'])
        return {
            'total': total, 'pass': len(self.results['pass']), 'fail': len(self.results['fail']),
            'warn': len(self.results['warn']), 'error': len(self.results['error']),
            'pass_rate': round((len(self.results['pass']) / total * 100) if total > 0 else 0, 2),
            'total_time': self.scan_timer.get_duration(), 'module_times': self.module_times
        }
    
    def get_slow_modules(self, threshold: float = 5.0) -> List[Tuple[str, float]]:
        slow = [(name, time) for name, time in self.module_times.items() if time > threshold]
        slow.sort(key=lambda x: x[1], reverse=True)
        return slow