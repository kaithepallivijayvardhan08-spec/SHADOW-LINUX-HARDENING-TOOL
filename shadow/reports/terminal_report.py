#!/usr/bin/env python3
"""
Shadow Terminal Report (Sci-Fi Edition + Full Enterprise Backend)
=================================================================
Generates professional, sci-fi themed terminal reports while maintaining
all enterprise backend features (sanitization, integrity, compression).
"""

import os
import sys
import json
import gzip
import shutil
import logging
import hashlib
import re
from datetime import datetime
from typing import Dict, List, Optional, Any, Tuple
from pathlib import Path

# ============================================================
# MODULE METADATA
# ============================================================
SEVERITY = "LOW"
RECOMMENDATION = "Regular security reports should be reviewed and archived"

# ============================================================
# TRANSACTION SUPPORT
# ============================================================
_transaction_active = False
_transaction_backups = []

def begin_transaction():
    global _transaction_active, _transaction_backups
    _transaction_active = True
    _transaction_backups = []
    logging.getLogger(__name__).info("Report transaction started")

def add_to_transaction(backup_path: Path, original_path: Path):
    global _transaction_backups
    if _transaction_active:
        _transaction_backups.append({'backup_path': str(backup_path), 'original_path': str(original_path)})

def commit_transaction() -> bool:
    global _transaction_active, _transaction_backups
    _transaction_active = False
    _transaction_backups = []
    logging.getLogger(__name__).info("Report transaction committed")
    return True

def rollback_transaction() -> bool:
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

class TerminalReport:
    """Generate colored terminal reports with enterprise backend"""

    COLORS = {
        'GREEN': '\033[92m', 'RED': '\033[91m', 'YELLOW': '\033[93m',
        'BLUE': '\033[94m', 'MAGENTA': '\033[95m', 'CYAN': '\033[96m',
        'WHITE': '\033[97m', 'BOLD': '\033[1m', 'DIM': '\033[2m', 'RESET': '\033[0m'
    }

    MAX_REPORTS = 30
    REPORT_RETENTION_DAYS = 90

    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.report_dir = '/var/log/shadow/reports/'
        self.backup_dir = '/var/backups/shadow/reports/'
        self.risk_details = {}
        os.makedirs(self.report_dir, exist_ok=True)
        os.makedirs(self.backup_dir, exist_ok=True)
        self._supports_color = self._check_color_support()

    def _check_color_support(self) -> bool:
        if not sys.stdout.isatty(): return False
        if os.environ.get('NO_COLOR'): return False
        term = os.environ.get('TERM', '')
        if term in ['dumb', 'unknown']: return False
        if 'color' in term or '256' in term: return True
        if os.environ.get('COLORTERM'): return True
        return False

    def _color(self, color_name: str) -> str:
        return self.COLORS.get(color_name, '') if self._supports_color else ''

    def _color_reset(self) -> str:
        return self.COLORS['RESET'] if self._supports_color else ''

    # ============================================================
    # 🎨 NEW SCI-FI DRAWING HELPERS (Design C+B)
    # ============================================================
    def _draw_header(self):
        c = self._color('CYAN')
        r = self._color_reset()
        print(f"""
{c}        ╭──────────────────────────────────────────────────╮
        │                                                  │
        │        ◈  LINUX SYSTEM HARDENING TOOL  ◈        │
        │           Security Assessment Interface          │
        │                                                  │
        ╰──────────────────────────────────────────────────╯{r}""")

    def _draw_section(self, title: str):
        c = self._color('CYAN')
        d = self._color('DIM')
        r = self._color_reset()
        print(f"\n  {c}◤ {title.upper()} ◢{r}")
        print(f"  {d}{'═' * 55}{r}")

    def _draw_footer(self):
        c = self._color('CYAN')
        d = self._color('DIM')
        r = self._color_reset()
        print(f"""
  {d}{'═' * 60}{r}
  {c}  🛡 Scan Complete  ◈  Reports Saved to /var/log/shadow/reports/{r}
  {d}{'═' * 60}{r}""")

    # ============================================================
    # 📊 MAIN RENDER METHOD (New Sci-Fi Flow)
    # ============================================================
    def render(self, results: Dict, risk_score: int, risk_level: str, 
               risk_details: Optional[Dict] = None, fix_status: Optional[Dict] = None, 
               mode: str = "scan", dry_run: bool = False, force: bool = False) -> bool:
        try:
            if dry_run:
                print("\n  [!] DRY-RUN MODE - Preview Only\n")
                return True

            # 1. Header
            self._draw_header()
            # 2. Summary Table
            self._render_summary(results)
            # 3. Risk Assessment
            self._render_risk_score(risk_score, risk_level)
            # 4. Honest Risk Summary
            if risk_details:
                self._render_honest_summary(risk_details)
            # 5. Fix Status (If hardening was run)
            if fix_status:
                self._render_fix_status(fix_status)
            # 6. Issues List
            self._render_issues(results)
            # 7. Recommendations
            self._render_recommendations(results, risk_level)
            # 8. Footer
            self._draw_footer()
            
            sys.stdout.flush()
            return True
        except Exception as e:
            self.logger.error(f"Error rendering terminal report: {e}")
            return False

    # ============================================================
    # 📝 NEW VISUAL RENDERERS (Design C+B)
    # ============================================================
    def _render_summary(self, results: Dict):
        self._draw_section("Assessment Results")
        g, r_c, y, m, reset = self._color('GREEN'), self._color('RED'), self._color('YELLOW'), self._color('MAGENTA'), self._color_reset()
        p = len(results.get('pass', []))
        f = len(results.get('fail', []))
        w = len(results.get('warn', []))
        e = len(results.get('error', []))
        total = p + f + w + e
        pass_rate = (p / total * 100) if total > 0 else 0

        print(f"""
   {g}✔ PASSED{reset}    : {p:>4}
   {r_c}✘ FAILED{reset}    : {f:>4}
   {y}⚠ WARNING{reset}   : {w:>4}
   {m}ℹ ERROR{reset}     : {e:>4}
   {self._color('DIM')}─────────────────────────{reset}
   Total Checks : {total:>4}
   Pass Rate    : {pass_rate:.1f}%
""")

    def _render_risk_score(self, risk_score: int, risk_level: str):
        self._draw_section("Risk Assessment")
        if risk_level == 'LOW': color = self._color('GREEN')
        elif risk_level == 'MEDIUM': color = self._color('YELLOW')
        elif risk_level == 'HIGH': color = self._color('MAGENTA')
        else: color = self._color('RED')
        
        filled = max(0, min(risk_score // 10, 10))
        bar = f"{color}{'▓' * filled}{self._color('DIM')}{'░' * (10 - filled)}{self._color_reset()}"
        
        descriptions = {
            'LOW': 'System is secure. Minor issues found.',
            'MEDIUM': 'System has some security issues. Should be addressed.',
            'HIGH': 'System has significant security issues. Must be addressed.',
            'CRITICAL': 'System is at high risk. Immediate action required.'
        }
        
        print(f"""
   🛡  Risk Score : {color}{risk_score}/100{self._color_reset()}  [{bar}]  {color}{risk_level}{self._color_reset()}
   Assessment   : {descriptions.get(risk_level, 'Unknown')}
""")

    def _render_honest_summary(self, risk_details: Dict):
        self._draw_section("Honest Risk Summary")
        g, y, r_c, reset = self._color('GREEN'), self._color('YELLOW'), self._color('RED'), self._color_reset()
        
        fixed = risk_details.get('fixed', 0)
        manual = risk_details.get('manual_required', 0)
        remaining = risk_details.get('remaining', 0)
        current = risk_details.get('current', 0)
        current_level = risk_details.get('current_level', 'UNKNOWN')
        
        print(f"   Baseline Risk (before fixes)  : {risk_details.get('total', 0)}/100 ({risk_details.get('total_level', 'UNKNOWN')})")
        
        color_current = g if current_level in ['LOW', 'MEDIUM'] else r_c
        print(f"   {g}Fixed Automatically{reset}: {fixed} issues → {color_current}{current}/100 ({current_level}){reset}")
        
        potential = risk_details.get('potential', 0)
        potential_level = risk_details.get('potential_level', 'UNKNOWN')
        color_potential = g if potential_level in ['LOW', 'MEDIUM'] else y
        print(f"   {y}Manual Required   {reset}: {manual} issues → {color_potential}{potential}/100 ({potential_level}){reset}")
        
        # ✅ FIX: Do NOT say "All issues fixed" if there are manual issues!
        if manual > 0 or remaining > 0:
            total_unresolved = manual + remaining
            print(f"   {y}⚠ {total_unresolved} issue(s) still need manual attention{reset}")
        else:
            print(f"   {g}✔ All issues fixed!{reset}")
            
        improvement = risk_details.get('improvement', 0)
        if improvement > 0:
            print(f"   Improvement       : {improvement} points ({risk_details.get('improvement_percent', 0):.1f}%)")
            
        if manual > 0:
            print(f"\n   {y}⚠️  {manual} issues require manual intervention:{reset}")
            # ✅ Show WHICH issues need manual work
            for issue in risk_details.get('manual_issues', []):
                print(f"      {y}▸ {issue}{reset}")
            print(f"\n      See: /var/log/shadow/manual_fixes.txt")

    def _render_fix_status(self, fix_status: Dict):
        self._draw_section("Fix Verification")
        g, r_c, reset = self._color('GREEN'), self._color('RED'), self._color_reset()
        
        fixed_count = fix_status.get('fixed_count', 0)
        verified_count = len(fix_status.get('verified_fixes', []))
        failed_fixes = fix_status.get('failed_fixes', [])
        backup_count = fix_status.get('backup_count', 0)

        print(f"   Total fixes       : {fixed_count}")
        print(f"   {g}Verified{reset}          : {verified_count}")
        
        if failed_fixes:
            print(f"   {r_c}Failed{reset}           : {len(failed_fixes)}")
            for failed in failed_fixes[:5]:
                print(f"      - {failed}")
        else:
            print(f"   {g}Failed{reset}           : 0")
            
        print(f"   Backups created   : {backup_count}")

    def _render_issues(self, results: Dict):
        fails = results.get('fail', [])
        warns = results.get('warn', [])
        errors = results.get('error', [])
        bold, r_c, y, m, reset = self._color('BOLD'), self._color('RED'), self._color('YELLOW'), self._color('MAGENTA'), self._color_reset()

        if fails:
            self._draw_section(f"Failed Checks ({len(fails)})")
            for i, fail in enumerate(fails[:50], 1):
                print(f"  {r_c}{i:>2}.{reset} {fail}")
            if len(fails) > 50:
                print(f"  {self._color('DIM')}... and {len(fails) - 50} more{reset}")

        if warns:
            self._draw_section(f"Warnings ({len(warns)})")
            for i, warn in enumerate(warns[:50], 1):
                print(f"  {y}{i:>2}.{reset} {warn}")
            if len(warns) > 50:
                print(f"  {self._color('DIM')}... and {len(warns) - 50} more{reset}")

        if errors:
            self._draw_section(f"Errors ({len(errors)})")
            for i, error in enumerate(errors[:50], 1):
                print(f"  {m}{i:>2}.{reset} {error}")
            if len(errors) > 50:
                print(f"  {self._color('DIM')}... and {len(errors) - 50} more{reset}")

        if not fails and not warns and not errors:
            print(f"\n   {self._color('GREEN')}✓ No issues found.{self._color_reset()}")

    def _render_recommendations(self, results: Dict, risk_level: str):
        self._draw_section("Recommendations")
        c, r_c, reset = self._color('CYAN'), self._color('RED'), self._color_reset()

        if risk_level in ['HIGH', 'CRITICAL']:
            print(f"   {r_c}• IMMEDIATE ACTION REQUIRED{reset}")
            print(f"   {c}▸ Run: sudo shadow --harden to apply fixes{reset}")

        if risk_level in ['MEDIUM', 'HIGH', 'CRITICAL']:
            print(f"   {c}▸ Run: sudo shadow --interactive for detailed options{reset}")
            print(f"   {c}▸ Review logs in /var/log/shadow/{reset}")

        if risk_level == 'LOW':
            print(f"   {c}▸ System is relatively secure{reset}")
            print(f"   {c}▸ Run weekly scans to maintain security{reset}")

        recommendations_added = set()
        for fail in results.get('fail', []):
            if not fail: continue
            module_name = fail.split(':', 1)[0] if ':' in fail else fail
            rec = self._get_module_recommendations(module_name)
            if rec and rec not in recommendations_added:
                print(f"   {c}▸ {rec}{reset}")
                recommendations_added.add(rec)
                continue
            
            lower_fail = fail.lower()
            if 'ssh' in lower_fail and 'ssh' not in recommendations_added:
                print(f"   {c}▸ Check SSH configuration: /etc/ssh/sshd_config{reset}")
                recommendations_added.add('ssh')
            elif 'password' in lower_fail and 'password' not in recommendations_added:
                print(f"   {c}▸ Check password policies: /etc/login.defs{reset}")
                recommendations_added.add('password')
            elif 'firewall' in lower_fail and 'firewall' not in recommendations_added:
                print(f"   {c}▸ Enable firewall: ufw enable{reset}")
                recommendations_added.add('firewall')

    # ============================================================
    # 🛠️ ENTERPRISE BACKEND METHODS (100% PRESERVED FROM ORIGINAL)
    # ============================================================
    def _show_progress(self, message: str = "", done: bool = False):
        if done:
            sys.stdout.write(f"\r✓ {message}".ljust(60) + "\n")
        else:
            sys.stdout.write(f"\r[*] {message}...".ljust(60))
        sys.stdout.flush()

    def _sanitize_data(self, data: Dict) -> Dict:
        """Sanitize data to prevent sensitive information disclosure."""
        sanitized = {}
        patterns = [
            (r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', '[IP]'),
            (r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', '[EMAIL]'),
        ]
        patterns_with_flags = [
            (r'(api[_\-]?key|apikey|token|secret)[=:]\s*\S+', r'\1=[REDACTED]', re.IGNORECASE),
            (r'(password|passwd|pwd)[=:]\s*\S+', r'\1=[REDACTED]', re.IGNORECASE),
            (r'(user(?:name)?|username)[=:]\s*\S+', r'\1=[REDACTED]', re.IGNORECASE),
            (r'-----BEGIN (?:RSA|DSA|EC|OPENSSH) PRIVATE KEY-----.*?-----END (?:RSA|DSA|EC|OPENSSH) PRIVATE KEY-----',
             '[PRIVATE KEY REMOVED]', re.DOTALL),
        ]
        for key, value in data.items():
            if isinstance(value, list):
                sanitized[key] = []
                for item in value[:50]:
                    if isinstance(item, str):
                        sanitized_item = item
                        for pattern, replacement in patterns:
                            sanitized_item = re.sub(pattern, replacement, sanitized_item)
                        for pattern, replacement, flags in patterns_with_flags:
                            sanitized_item = re.sub(pattern, replacement, sanitized_item, flags=flags)
                        sanitized[key].append(sanitized_item)
                    else:
                        sanitized[key].append(str(item))
            elif isinstance(value, dict):
                sanitized[key] = self._sanitize_data(value)
            else:
                if isinstance(value, str):
                    sanitized[key] = value[:500]
                else:
                    sanitized[key] = str(value)[:500]
        return sanitized

    def _verify_report(self, report_file: str, expected_data: Dict) -> bool:
        try:
            if not os.path.exists(report_file): return False
            if os.path.getsize(report_file) == 0: return False
            with open(report_file, 'r') as f:
                data = json.load(f)
            for key in ['timestamp', 'risk_score']:
                if key not in data: return False
            hash_file = report_file + '.sha256'
            if os.path.exists(hash_file):
                with open(hash_file, 'r') as f:
                    stored_hash = f.read().strip()
                    with open(report_file, 'rb') as f:
                        current_hash = hashlib.sha256(f.read()).hexdigest()
                    if current_hash != stored_hash: return False
            return True
        except Exception:
            return False

    def _check_report_integrity(self, report_file: str) -> bool:
        try:
            with open(report_file, 'rb') as f:
                file_hash = hashlib.sha256(f.read()).hexdigest()
            hash_file = report_file + '.sha256'
            if os.path.exists(hash_file):
                with open(hash_file, 'r') as f:
                    stored_hash = f.read().strip()
                    if stored_hash == file_hash: return True
                    else: return False
            with open(hash_file, 'w') as f:
                f.write(file_hash)
            return True
        except Exception:
            return True

    def _clean_old_reports(self):
        try:
            now = datetime.now()
            report_files = []
            for f in os.listdir(self.report_dir):
                if f.startswith('report_') and f.endswith(('.json', '.json.gz')):
                    file_path = os.path.join(self.report_dir, f)
                    file_time = datetime.fromtimestamp(os.path.getmtime(file_path))
                    age_days = (now - file_time).days
                    file_size = os.path.getsize(file_path)
                    report_files.append((file_path, age_days, file_size))
            report_files.sort(key=lambda x: x[1], reverse=True)
            for file_path, age_days, file_size in report_files:
                should_remove = False
                if age_days > self.REPORT_RETENTION_DAYS: should_remove = True
                elif len([r for r in report_files if r[1] < self.REPORT_RETENTION_DAYS]) > self.MAX_REPORTS: should_remove = True
                if should_remove:
                    os.remove(file_path)
                    hash_file = file_path + '.sha256'
                    if os.path.exists(hash_file): os.remove(hash_file)
                    report_files = [r for r in report_files if r[0] != file_path]
        except Exception as e:
            self.logger.warning(f"Error cleaning old reports: {e}")

    def _get_module_recommendations(self, module_name: str) -> Optional[str]:
        try:
            if '.' in module_name:
                category, name = module_name.split('.', 1)
                mod_path = f"shadow.modules.{category}.{name}"
                try:
                    mod = __import__(mod_path, fromlist=['RECOMMENDATION'])
                    if hasattr(mod, 'RECOMMENDATION'):
                        return getattr(mod, 'RECOMMENDATION')
                except: pass
        except: pass
        return None

    def _validate_fix_status(self, fix_status: Dict) -> bool:
        if not isinstance(fix_status, dict): return False
        for key in ['fixed_count', 'failed_fixes', 'verified_fixes', 'backup_count']:
            if key not in fix_status: return False
        if not isinstance(fix_status.get('fixed_count'), int): return False
        if not isinstance(fix_status.get('failed_fixes'), list): return False
        if not isinstance(fix_status.get('verified_fixes'), list): return False
        if not isinstance(fix_status.get('backup_count'), int): return False
        return True

    def _validate_report_data(self, results: Dict, risk_score: int, risk_level: str) -> bool:
        if not isinstance(results, dict): return False
        if not isinstance(risk_score, (int, float)): return False
        if risk_score < 0 or risk_score > 100: return False
        if risk_level not in ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']: return False
        return True

    def _get_safe_data(self, data: Dict, key: str, default: Any = []) -> Any:
        if not data or key not in data: return default
        return data.get(key, default)

    def _backup_report(self, report_file: str) -> bool:
        try:
            if os.path.exists(report_file):
                backup_path = os.path.join(self.backup_dir, os.path.basename(report_file) + '.backup')
                shutil.copy2(report_file, backup_path)
                return True
        except Exception: pass
        return False

    def _save_report(self, results: Dict, risk_score: int, risk_level: str, risk_details: Optional[Dict] = None, fix_status: Optional[Dict] = None):
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            # ✅ FIX: Use 'report_' prefix to match the rest of the suite
            report_file = os.path.join(self.report_dir, f"report_{timestamp}.json")
            report_data = {
                'timestamp': datetime.now().isoformat(),
                'risk_score': risk_score,
                'risk_level': risk_level,
                'results': self._sanitize_data(results)
            }
            # ✅ FIX: Save risk_details so the Honest Summary isn't lost
            if risk_details: report_data['risk_details'] = risk_details
            if fix_status: report_data['fix_status'] = fix_status
            with open(report_file, 'w') as f:
                json.dump(report_data, f, indent=2)
            with open(report_file, 'rb') as f:
                file_hash = hashlib.sha256(f.read()).hexdigest()
            with open(report_file + '.sha256', 'w') as f:
                f.write(file_hash)
            self._compress_report(report_file)
        except Exception as e:
            self.logger.error(f"Error saving report: {e}")

    def _compress_report(self, report_file: str) -> bool:
        try:
            gz_file = report_file + '.gz'
            with open(report_file, 'rb') as f_in:
                with gzip.open(gz_file, 'wb') as f_out:
                    shutil.copyfileobj(f_in, f_out)
            if os.path.exists(gz_file) and os.path.getsize(gz_file) > 0:
                os.remove(report_file)
                return True
        except Exception: pass
        return False

    def generate_from_last_scan(self) -> bool:
        try:
            report_files = []
            if os.path.exists(self.report_dir):
                for f in os.listdir(self.report_dir):
                    if f.startswith('report_') and f.endswith(('.json', '.json.gz')):
                        file_path = os.path.join(self.report_dir, f)
                        if self._check_report_integrity(file_path):
                            report_files.append((file_path, os.path.getmtime(file_path)))
            if not report_files:
                print("No scan reports found. Run a scan first.")
                return False
            latest_file = max(report_files, key=lambda x: x[1])[0]
            if latest_file.endswith('.gz'):
                import gzip
                with gzip.open(latest_file, 'rt') as f:
                    data = json.load(f)
            else:
                with open(latest_file, 'r') as f:
                    data = json.load(f)
            results = data.get('results', {})
            risk_score = data.get('risk_score', 0)
            risk_level = data.get('risk_level', 'UNKNOWN')
            risk_details = data.get('risk_details', None)  # ✅ FIX: Extract risk_details
            fix_status = data.get('fix_status', None)
            self._show_progress("Loading report from last scan")
            # ✅ FIX: Pass risk_details to render so the Honest Summary shows up
            return self.render(results, risk_score, risk_level, risk_details=risk_details, fix_status=fix_status)
        except Exception as e:
            self.logger.error(f"Error generating report from last scan: {e}")
            return False