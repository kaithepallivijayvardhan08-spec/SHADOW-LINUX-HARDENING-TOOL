#!/usr/bin/env python3
"""
Shadow Risk Engine
==================

Calculates risk scores based on scan results.

Risk Levels:
- LOW: 0-25  (System is secure)
- MEDIUM: 26-50 (Some issues found)
- HIGH: 51-75 (Significant issues)
- CRITICAL: 76-100 (Critical issues)

Risk factors:
- Each FAIL = +10 points
- Each WARN = +5 points
- Each ERROR = +8 points
- PASS = 0 points
"""

import os
import json
import logging
import sys
from pathlib import Path
from datetime import datetime
from typing import Dict, Tuple, List, Optional, Any


# ============================================================
# HISTORICAL TRACKING
# ============================================================
HISTORY_DIR = Path("/var/log/shadow/history")


class RiskEngine:
    """Calculates risk scores from scan results"""
    
    def __init__(self, config: Optional[Dict] = None):
        """Initialize risk engine"""
        self.logger = logging.getLogger(__name__)
        self.config = config or {}
        
        # ✅ FIX 2: Adjusted weights for more balanced scoring
        self.weights = self.config.get('risk_weights', {
            'FAIL': 10,      # Reduced from 20 to 10
            'WARN': 5,       # Reduced from 10 to 5
            'ERROR': 8,      # Reduced from 15 to 8
            'PASS': 0
        })
        
        # Risk level thresholds (configurable)
        self.thresholds = self.config.get('risk_thresholds', {
            'LOW': 25,
            'MEDIUM': 50,
            'HIGH': 75,
            'CRITICAL': 100
        })
        
        # FIXED: Module-based severity detection
        self.high_severity = self.config.get('high_severity_categories', [
            'authentication', 'remote_access', 'network', 'file_security',
            'services', 'storage', 'monitoring', 'updates', 'kernel',
            'processes', 'audit', 'access_control', 'scheduled_tasks', 'integrity',
        ])

        self.critical_severity = self.config.get('critical_severity_categories', [
            'authentication.login_protection', 'authentication.users',
            'authentication.password_policy', 'authentication.sudo_check',
            'remote_access.ssh', 'remote_access.rdp_vnc', 'remote_access.telnet',
            'network.firewall', 'network.ports', 'network.dns', 'network.connections',
            'file_security.sensitive_files', 'file_security.permissions', 'file_security.ownership',
            'services.docker', 'services.nfs', 'services.mysql', 'services.apache', 'services.nginx',
            'storage.disk_check', 'storage.encryption', 'storage.lvm',
            'monitoring.logs', 'monitoring.suspicious_process', 'monitoring.malware_scan',
            'updates.package_updates', 'updates.package_integrity',
            'kernel.kernel_check', 'kernel.kernel_modules', 'kernel.sysctl_security',
            'processes.process_audit', 'processes.startup_process', 'processes.resource_check',
            'audit.auditd_check', 'audit.audit_rules', 'audit.system_events',
            'access_control.selinux', 'access_control.apparmor', 'access_control.capabilities',
            'scheduled_tasks.cron_check', 'scheduled_tasks.systemd_timer', 'scheduled_tasks.startup_jobs',
            'integrity.file_integrity', 'integrity.change_detection', 'integrity.hash_monitor',
        ])
        
        self.history_limit = self.config.get('history_limit', 1000)
        self.history = []
        self._load_history()
    
    def _load_history(self):
        try:
            HISTORY_DIR.mkdir(parents=True, exist_ok=True)
            history_file = HISTORY_DIR / "risk_history.json"
            if history_file.exists():
                with open(history_file, 'r') as f:
                    self.history = json.load(f)
        except Exception as e:
            self.logger.debug(f"Could not load history: {e}")
    
    def _save_history(self):
        try:
            HISTORY_DIR.mkdir(parents=True, exist_ok=True)
            history_file = HISTORY_DIR / "risk_history.json"
            if len(self.history) > self.history_limit:
                self.history = self.history[-self.history_limit:]
            temp_file = HISTORY_DIR / "risk_history.tmp"
            with open(temp_file, 'w') as f:
                json.dump(self.history, f, indent=2)
            temp_file.rename(history_file)
        except Exception as e:
            self.logger.debug(f"Could not save history: {e}")
    
    def _add_history_record(self, risk_score: int, risk_level: str, results: Dict):
        record = {
            'timestamp': datetime.now().isoformat(),
            'risk_score': risk_score,
            'risk_level': risk_level,
            'fail_count': len(results.get('fail', [])),
            'warn_count': len(results.get('warn', [])),
            'error_count': len(results.get('error', [])),
            'pass_count': len(results.get('pass', []))
        }
        self.history.append(record)
        self._save_history()
    
    def get_trend(self) -> Dict[str, Any]:
        if len(self.history) < 2:
            return {'has_trend': False, 'message': 'Not enough data for trend analysis'}
        last_5 = self.history[-5:]
        scores = [r['risk_score'] for r in last_5]
        avg_score = sum(scores) / len(scores)
        latest_score = scores[-1]
        previous_score = scores[-2] if len(scores) > 1 else latest_score
        trend = 'stable'
        if latest_score < previous_score - 5: trend = 'improving'
        elif latest_score > previous_score + 5: trend = 'worsening'
        change_pct = ((latest_score - previous_score) / max(previous_score, 1)) * 100
        return {
            'has_trend': True, 'scores': scores, 'average_score': round(avg_score, 2),
            'latest_score': latest_score, 'previous_score': previous_score,
            'change_percent': round(change_pct, 2), 'trend': trend, 'total_records': len(self.history)
        }
    
    def _show_progress(self, current: int, total: int, message: str = ""):
        if total > 0:
            percent = (current / total) * 100
            sys.stdout.write(f"\r[*] Calculating risk: {percent:.1f}% - {message[:50]:<50}")
            sys.stdout.flush()
    
    def _get_module_severity(self, module_name: str) -> str:
        if not module_name: return 'MEDIUM'
        try:
            if '.' in module_name:
                category, name = module_name.split('.', 1)
                mod_path = f"shadow.modules.{category}.{name}"
                try:
                    mod = __import__(mod_path, fromlist=['SEVERITY'])
                    if hasattr(mod, 'SEVERITY'):
                        severity = getattr(mod, 'SEVERITY')
                        if severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']: return severity
                except: pass
        except: pass
        for critical in self.critical_severity:
            if critical in module_name: return 'CRITICAL'
        for high in self.high_severity:
            if high in module_name: return 'HIGH'
        return 'MEDIUM'
    
    def calculate(self, results: Dict) -> Tuple[int, str]:
        self.logger.info("Calculating risk score...")
        if not results or not isinstance(results, dict): return 0, 'LOW'
        for key in ['pass', 'fail', 'warn', 'error']:
            if key not in results or not isinstance(results[key], list): results[key] = []
        
        risk_score = 0
        high_severity_count = 0
        critical_severity_count = 0
        total_items = len(results.get('fail', [])) + len(results.get('warn', [])) + len(results.get('error', []))
        current_item = 0
        
        for fail_item in results.get('fail', []):
            current_item += 1
            self._show_progress(current_item, total_items, f"Processing failure: {fail_item[:30]}...")
            risk_score += self.weights.get('FAIL', 10)
            module_name = fail_item.split(':', 1)[0] if ':' in fail_item else fail_item
            severity = self._get_module_severity(module_name)
            if severity == 'CRITICAL':
                risk_score += 5
                critical_severity_count += 1
            elif severity == 'HIGH':
                risk_score += 2
                high_severity_count += 1
        
        for warn_item in results.get('warn', []):
            current_item += 1
            self._show_progress(current_item, total_items, f"Processing warning: {warn_item[:30]}...")
            risk_score += self.weights.get('WARN', 5)
        
        for error_item in results.get('error', []):
            current_item += 1
            self._show_progress(current_item, total_items, f"Processing error: {error_item[:30]}...")
            risk_score += self.weights.get('ERROR', 8)
        
        sys.stdout.write("\n")
        sys.stdout.flush()
        risk_score = min(risk_score, 100)
        risk_level = self._determine_risk_level(risk_score)
        self._add_history_record(risk_score, risk_level, results)
        self.logger.info(f"Risk score: {risk_score}/100, Level: {risk_level}")
        return risk_score, risk_level

    # ============================================================
    # HONEST RISK SCORING WITH FIX STATUS
    # ============================================================
    def calculate_with_fix_status(self, results: Dict, 
                                   auto_fixed: List[str] = None,
                                   manual_required: List[str] = None) -> Tuple[int, str, Dict]:
        self.logger.info("Calculating honest risk score with fix status...")
        auto_fixed = auto_fixed or []
        manual_required = manual_required or []
        auto_fixed_set = set(auto_fixed)
        manual_set = set(manual_required)
        
        if not results or not isinstance(results, dict):
            return 0, 'LOW', {'error': 'Invalid results'}
        for key in ['pass', 'fail', 'warn', 'error']:
            if key not in results or not isinstance(results[key], list): results[key] = []
        
        total_score = 0
        fixed_score = 0
        manual_score = 0
        
        auto_fixed_count = len(auto_fixed)
        manual_count = len(manual_required)
        
        # ✅ FIX: Prevent negative numbers if fixed items are no longer in the fail list
        remaining_count = max(0, len(results.get('fail', [])) - auto_fixed_count - manual_count)
        
        for fail_item in results.get('fail', []):
            base_score = self.weights.get('FAIL', 10)
            module_name = fail_item.split(':', 1)[0] if ':' in fail_item else fail_item
            severity = self._get_module_severity(module_name)
            if severity == 'CRITICAL': base_score += 5
            elif severity == 'HIGH': base_score += 2
            total_score += base_score
            if fail_item in auto_fixed_set: fixed_score += base_score
            elif fail_item in manual_set: manual_score += base_score
        
        current_score = min(total_score - fixed_score, 100)
        potential_score = min(total_score - fixed_score - manual_score, 100)
        total_score = min(total_score, 100)
        
        current_level = self._determine_risk_level(current_score)
        potential_level = self._determine_risk_level(potential_score)
        
        details = {
            'total': total_score,
            'total_level': self._determine_risk_level(total_score),
            'current': current_score,
            'current_level': current_level,
            'potential': potential_score,
            'potential_level': potential_level,
            'fixed': auto_fixed_count,
            'manual_required': manual_count,
            'manual_issues': manual_required,  # ✅ Pass actual issue names
            'remaining': remaining_count, # Already capped at 0 above
            'improvement': total_score - potential_score,
            'improvement_percent': round(((total_score - potential_score) / max(total_score, 1)) * 100, 1)
        }
        
        self.logger.info(f"Honest risk score: {current_score}/100 ({current_level})")
        self.logger.info(f"  Fixed: {auto_fixed_count}, Manual: {manual_count}, Remaining: {remaining_count}")
        self.logger.info(f"  Potential score: {potential_score}/100 ({potential_level})")
        
        return current_score, current_level, details
    
    def _determine_risk_level(self, risk_score: int) -> str:
        low = self.thresholds.get('LOW', 25)
        medium = self.thresholds.get('MEDIUM', 50)
        high = self.thresholds.get('HIGH', 75)
        if risk_score <= low: return 'LOW'
        elif risk_score <= medium: return 'MEDIUM'
        elif risk_score <= high: return 'HIGH'
        else: return 'CRITICAL'
    
    def get_risk_description(self, risk_level: str) -> str:
        descriptions = {
            'LOW': 'System is secure. Minor issues found.',
            'MEDIUM': 'System has some security issues. Should be addressed.',
            'HIGH': 'System has significant security issues. Must be addressed.',
            'CRITICAL': 'System is at high risk. Immediate action required.'
        }
        return descriptions.get(risk_level, 'Unknown risk level')
    
    def get_risk_color(self, risk_level: str) -> str:
        colors = {'LOW': '\033[92m', 'MEDIUM': '\033[93m', 'HIGH': '\033[95m', 'CRITICAL': '\033[91m'}
        return colors.get(risk_level, '\033[0m')
    
    def get_priority_issues(self, results: Dict) -> List[Dict]:
        if not results or not isinstance(results, dict): return []
        priority_issues = []
        for fail_item in results.get('fail', []):
            if not fail_item: continue
            module_name = fail_item.split(':', 1)[0] if ':' in fail_item else fail_item
            severity = self._get_module_severity(module_name)
            priority_issues.append({
                'message': fail_item, 'module': module_name, 'severity': severity,
                'priority': 1 if severity == 'CRITICAL' else 2 if severity == 'HIGH' else 3
            })
        priority_issues.sort(key=lambda x: x['priority'])
        return priority_issues
    
    def get_risk_factors(self, results: Dict) -> Dict:
        if not results or not isinstance(results, dict): return {'message': 'No valid results provided'}
        total_checks = sum(len(results.get(k, [])) for k in ['pass', 'fail', 'warn', 'error'])
        if total_checks == 0: return {'message': 'No checks performed'}
        
        weighted_risk = min((
            len(results.get('fail', [])) * self.weights.get('FAIL', 10) +
            len(results.get('warn', [])) * self.weights.get('WARN', 5) +
            len(results.get('error', [])) * self.weights.get('ERROR', 8)
        ), 100)
        
        return {
            'total_checks': total_checks,
            'pass_count': len(results.get('pass', [])),
            'fail_count': len(results.get('fail', [])),
            'warn_count': len(results.get('warn', [])),
            'error_count': len(results.get('error', [])),
            'fail_rate': round(len(results.get('fail', [])) / total_checks * 100, 2),
            'warn_rate': round(len(results.get('warn', [])) / total_checks * 100, 2),
            'pass_rate': round(len(results.get('pass', [])) / total_checks * 100, 2),
            'error_rate': round(len(results.get('error', [])) / total_checks * 100, 2),
            'weighted_risk': weighted_risk,
            'risk_level': self._determine_risk_level(weighted_risk)
        }
    
    def get_recommendations(self, results: Dict, risk_level: str) -> List[str]:
        if not results or not isinstance(results, dict): return ["Run security scan first to get recommendations"]
        recommendations = []
        if risk_level in ['HIGH', 'CRITICAL']:
            recommendations.extend(["⚠️  IMMEDIATE ACTION REQUIRED", "Run: sudo shadow --harden to apply fixes", "Review each critical issue manually"])
        if risk_level in ['MEDIUM', 'HIGH', 'CRITICAL']:
            recommendations.extend(["Run: sudo shadow --interactive for detailed options", "Review logs in /var/log/shadow/"])
        if risk_level == 'LOW':
            recommendations.extend(["✅ System is relatively secure", "Run weekly scans to maintain security"])
        
        for fail_item in results.get('fail', []):
            if not fail_item: continue
            module_name = fail_item.split(':', 1)[0] if ':' in fail_item else fail_item
            try:
                if '.' in module_name:
                    category, name = module_name.split('.', 1)
                    mod_path = f"shadow.modules.{category}.{name}"
                    mod = __import__(mod_path, fromlist=['RECOMMENDATION'])
                    if hasattr(mod, 'RECOMMENDATION'):
                        rec = getattr(mod, 'RECOMMENDATION')
                        if rec and rec not in recommendations: recommendations.append(rec)
            except: pass
            
            lower_item = fail_item.lower()
            if 'ssh' in lower_item and not any('ssh' in r.lower() for r in recommendations): recommendations.append("Check SSH configuration: /etc/ssh/sshd_config")
            elif 'password' in lower_item and not any('password' in r.lower() for r in recommendations): recommendations.append("Check password policies: /etc/login.defs")
            elif 'firewall' in lower_item and not any('firewall' in r.lower() for r in recommendations): recommendations.append("Enable firewall: ufw enable")
            elif 'kernel' in lower_item and not any('kernel' in r.lower() for r in recommendations): recommendations.append("Check kernel parameters: sysctl -a")
            elif 'audit' in lower_item and not any('audit' in r.lower() for r in recommendations): recommendations.append("Check auditd configuration: auditctl -l")
            elif 'selinux' in lower_item and not any('selinux' in r.lower() for r in recommendations): recommendations.append("Check SELinux status: getenforce")
            elif 'apparmor' in lower_item and not any('apparmor' in r.lower() for r in recommendations): recommendations.append("Check AppArmor status: aa-status")
            elif 'docker' in lower_item and not any('docker' in r.lower() for r in recommendations): recommendations.append("Check Docker security: docker info")
            elif 'mysql' in lower_item and not any('mysql' in r.lower() for r in recommendations): recommendations.append("Check MySQL security: mysql_secure_installation")
        
        seen = set()
        unique_recommendations = []
        for rec in recommendations:
            if rec not in seen:
                seen.add(rec)
                unique_recommendations.append(rec)
        return unique_recommendations
    
    def get_summary(self, results: Dict, risk_score: int, risk_level: str) -> Dict:
        return {
            'risk_score': risk_score, 'risk_level': risk_level,
            'description': self.get_risk_description(risk_level),
            'factors': self.get_risk_factors(results),
            'priority_issues': self.get_priority_issues(results),
            'recommendations': self.get_recommendations(results, risk_level),
            'trend': self.get_trend()
        }