#!/usr/bin/env python3
"""
Shadow HTML Report
==================

Generates HTML reports for web-friendly viewing.

Output format:
- Professional HTML page
- Color-coded status
- Risk score visualization
- Summary cards
- Detailed findings
- Fix verification status (after hardening)
- Mobile responsive
"""

import os
import json
import tempfile
import platform
import logging
import hashlib
import gzip
import shutil
import re
import sys
from datetime import datetime
from typing import Dict, List, Optional, Any


# ============================================================
# MODULE METADATA - FIXED
# ============================================================
SEVERITY = "LOW"
RECOMMENDATION = "HTML reports should be archived for compliance and audit trails"


class HTMLReport:
    """Generate HTML reports"""

    # Report retention settings
    MAX_REPORTS = 30
    REPORT_RETENTION_DAYS = 90

    def __init__(self):
        """Initialize HTML report"""
        self.logger = logging.getLogger(__name__)
        self.report_dir = '/var/log/shadow/reports/'
        

        # Ensure report directory exists
        os.makedirs(self.report_dir, exist_ok=True)

    # ============================================================
    # FIX 1: PROGRESS INDICATOR - FIXED (Using sys.stdout.write)
    # ============================================================
    def _show_progress(self, message: str = "", done: bool = False):
        """Show progress during HTML generation using stdout.write"""
        if done:
            sys.stdout.write(f"\r✓ HTML: {message}".ljust(60) + "\n")
        else:
            sys.stdout.write(f"\r[*] HTML: {message}...".ljust(60))
        sys.stdout.flush()

    # ============================================================
    # FIX 2: ENHANCED RECURSIVE SANITIZATION
    # ============================================================
    def _sanitize_text(self, text: str) -> str:
        """Sanitize text to prevent XSS and sensitive data exposure."""
        if not text:
            return text
        
        # HTML escape
        text = text.replace('&', '&amp;')
        text = text.replace('<', '&lt;')
        text = text.replace('>', '&gt;')
        text = text.replace('"', '&quot;')
        text = text.replace("'", '&#39;')
        
        # Enhanced patterns for sensitive data
        patterns = [
            # IP addresses
            (r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', '[IP]'),
            # Email addresses
            (r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', '[EMAIL]'),
            # API keys
            (r'(api[_\-]?key|apikey|token|secret)[=:]\s*\S+', r'\1=[REDACTED]', re.IGNORECASE),
            # Passwords
            (r'(password|passwd|pwd)[=:]\s*\S+', r'\1=[REDACTED]', re.IGNORECASE),
            # Usernames
            (r'(user(?:name)?|username)[=:]\s*\S+', r'\1=[REDACTED]', re.IGNORECASE),
            # Home directories
            (r'/home/[^/\s]+', '/home/[REDACTED]'),
            # Private SSH keys
            (r'-----BEGIN (?:RSA|DSA|EC|OPENSSH) PRIVATE KEY-----.*?-----END (?:RSA|DSA|EC|OPENSSH) PRIVATE KEY-----',
             '[PRIVATE KEY REMOVED]', re.DOTALL),
        ]
        
        result = text
        for pattern_tuple in patterns:
            if len(pattern_tuple) == 3:
                pattern, replacement, flags = pattern_tuple
                result = re.sub(pattern, replacement, result, flags=flags)
            else:
                pattern, replacement = pattern_tuple
                result = re.sub(pattern, replacement, result)
        
        return result

    def _sanitize_data(self, data: Any, depth: int = 0) -> Any:
        """Recursively sanitize data."""
        if depth > 10:
            return str(data)[:500]
        
        if isinstance(data, str):
            return self._sanitize_text(data)[:500]
        
        elif isinstance(data, dict):
            return {self._sanitize_text(k): self._sanitize_data(v, depth + 1) 
                    for k, v in data.items()}
        
        elif isinstance(data, list):
            return [self._sanitize_data(item, depth + 1) for item in data[:50]]
        
        else:
            return str(data)[:500] if data is not None else None

    # ============================================================
    # FIX 3: VALIDATE FIX STATUS
    # ============================================================
    def _validate_fix_status(self, fix_status: Dict) -> bool:
        """Validate fix_status structure."""
        if not isinstance(fix_status, dict):
            return False
        
        expected_keys = ['fixed_count', 'failed_fixes', 'verified_fixes', 'backup_count']
        for key in expected_keys:
            if key not in fix_status:
                return False
        
        # Validate types
        if not isinstance(fix_status.get('fixed_count'), int):
            return False
        if not isinstance(fix_status.get('failed_fixes'), list):
            return False
        if not isinstance(fix_status.get('verified_fixes'), list):
            return False
        if not isinstance(fix_status.get('backup_count'), int):
            return False
        
        return True

    # ============================================================
    # FIX 4: COMPRESS REPORT
    # ============================================================
    def _compress_report(self, report_file: str) -> bool:
        """Compress HTML report to save space."""
        try:
            gz_file = report_file + '.gz'
            with open(report_file, 'rb') as f_in:
                with gzip.open(gz_file, 'wb') as f_out:
                    shutil.copyfileobj(f_in, f_out)
            
            # Verify compression worked
            if os.path.exists(gz_file) and os.path.getsize(gz_file) > 0:
                # Remove original after successful compression
                os.remove(report_file)
                self.logger.debug(f"HTML compressed: {gz_file}")
                return True
            
        except Exception as e:
            self.logger.warning(f"HTML compression failed: {e}")
        return False

    # ============================================================
    # FIX 5: CLEAN OLD REPORTS - FIXED (Include compressed)
    # ============================================================
    def _clean_old_reports(self, max_reports: int = 30, max_age_days: int = 90):
        """Remove old HTML reports based on retention policy."""
        try:
            now = datetime.now()
            html_files = []
            
            for f in os.listdir(self.report_dir):
                if f.startswith('report_') and f.endswith(('.html', '.html.gz')):
                    file_path = os.path.join(self.report_dir, f)
                    file_time = datetime.fromtimestamp(os.path.getmtime(file_path))
                    age_days = (now - file_time).days
                    html_files.append((file_path, age_days))
            
            # Sort by age (oldest first)
            html_files.sort(key=lambda x: x[1], reverse=True)
            
            # Remove old files
            for file_path, age_days in html_files:
                should_remove = False
                reason = ""
                
                if age_days > max_age_days:
                    should_remove = True
                    reason = f"older than {max_age_days} days"
                elif len([r for r in html_files if r[1] < max_age_days]) > max_reports:
                    should_remove = True
                    reason = f"exceeds {max_reports} reports"
                
                if should_remove:
                    os.remove(file_path)
                    # Remove hash file too
                    hash_file = file_path + '.sha256'
                    if os.path.exists(hash_file):
                        os.remove(hash_file)
                    self.logger.debug(f"Removed old HTML: {file_path} ({reason})")
                    # Remove from list
                    html_files = [r for r in html_files if r[0] != file_path]
                    
        except Exception as e:
            self.logger.warning(f"Error cleaning old HTML reports: {e}")

    # ============================================================
    # VALIDATION BEFORE WRITING
    # ============================================================
    def _validate_report_data(self, results: Dict, risk_score: int, risk_level: str) -> bool:
        """Validate report data before generation."""
        if not isinstance(results, dict):
            self.logger.error("Invalid results type")
            return False
        
        if not isinstance(risk_score, (int, float)):
            self.logger.error("Invalid risk_score type")
            return False
        
        if risk_score < 0 or risk_score > 100:
            self.logger.error(f"Invalid risk_score: {risk_score}")
            return False
        
        valid_levels = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
        if risk_level not in valid_levels:
            self.logger.error(f"Invalid risk_level: {risk_level}")
            return False
        
        return True

    # ============================================================
    # VERIFICATION AFTER WRITE
    # ============================================================
    def _verify_html(self, output_path: str) -> bool:
        """Verify HTML was written correctly."""
        try:
            # ✅ FIX: Check for both .html and .html.gz
            paths_to_check = [output_path, output_path + '.gz']
        
            found_path = None
            for path in paths_to_check:
                if os.path.exists(path):
                    found_path = path
                    break
        
            if not found_path:
                self.logger.error(f"HTML file not found: {output_path} (tried .html and .html.gz)")
                return False
        
            if os.path.getsize(found_path) == 0:
                self.logger.error(f"HTML file is empty: {found_path}")
                return False
        
            # Check for basic HTML structure
            with open(found_path, 'r', encoding='utf-8') as f:
                content = f.read()
                if '<html' not in content and '<HTML' not in content:
                    self.logger.error("Invalid HTML: missing html tag")
                    return False
                if '<body' not in content and '<BODY' not in content:
                    self.logger.error("Invalid HTML: missing body tag")
                    return False
        
            # Verify hash matches
            hash_file = output_path + '.sha256'
            if os.path.exists(hash_file):
                with open(hash_file, 'r') as f:
                    stored_hash = f.read().strip()
                    with open(found_path, 'rb') as f:
                        current_hash = hashlib.sha256(f.read()).hexdigest()
                    if current_hash != stored_hash:
                        self.logger.error("HTML hash mismatch")
                        return False
        
            self.logger.info(f"HTML verification passed: {found_path}")
            return True
        
        except Exception as e:
            self.logger.error(f"HTML verification failed: {e}")
            return False

    # ============================================================
    # ATOMIC WRITE WITH ERROR HANDLING
    # ============================================================
    def _write_html_safe(self, html_content: str, output_path: str) -> bool:
        """
        Safely write HTML using a temporary file for atomic write.
        ✅ FIX: Verifies BEFORE compression
        """
        temp_path = None
    
        try:
            self.logger.debug(f"Starting HTML write to: {output_path}")
            self.logger.debug(f"HTML content size: {len(html_content)} bytes")

            # Write to temp file first (use same directory to avoid cross-device)
            temp_dir = os.path.dirname(output_path)
            self.logger.debug(f"Using temp directory: {temp_dir}")
    
            with tempfile.NamedTemporaryFile(mode='w', suffix='.html', 
                                    delete=False, encoding='utf-8',
                                    dir=temp_dir) as f:
                f.write(html_content)
                temp_path = f.name
                self.logger.debug(f"Temp file created: {temp_path}")

            # Verify temp file was created
            if not os.path.exists(temp_path):
                self.logger.error(f"Temp HTML file was not created: {temp_path}")
                return False

            if os.path.getsize(temp_path) == 0:
                self.logger.error(f"Temp HTML file is empty: {temp_path}")
                os.unlink(temp_path)
                return False

            self.logger.debug(f"Temp file size: {os.path.getsize(temp_path)} bytes")

            # Move temp file to destination
            self.logger.debug(f"Moving temp file to: {output_path}")
            shutil.move(temp_path, output_path)
            self.logger.info(f"✅ HTML saved: {output_path} ({os.path.getsize(output_path)} bytes)")

            # ✅ FIX: Verify BEFORE compression
            if not self._verify_html(output_path):
                self.logger.error("HTML verification failed before compression")
                if os.path.exists(output_path):
                    os.remove(output_path)
                return False

            # Generate hash for integrity
            with open(output_path, 'rb') as f:
                file_hash = hashlib.sha256(f.read()).hexdigest()
            hash_path = output_path + '.sha256'
            with open(hash_path, 'w') as f:
                f.write(file_hash)
            self.logger.debug(f"Hash saved: {hash_path}")

            # Compress report (after verification)
            self.logger.debug("Compressing report...")
            if self._compress_report(output_path):
                self.logger.debug(f"Compressed: {output_path}.gz")
            else:
                self.logger.warning("Compression skipped or failed")

            return True

        except PermissionError as e:
            self.logger.error(f"Permission denied while writing HTML: {e}")
            self.logger.error(f"Check permissions for: {output_path} and {temp_dir}")
            return False
    
        except OSError as e:
            self.logger.error(f"OS error while writing HTML: {e}")
            self.logger.error(f"Check disk space and filesystem: {output_path}")
            return False
    
        except Exception as e:
            self.logger.error(f"Unexpected error writing HTML: {e}")
            self.logger.exception("Full traceback:")
            return False
    
        finally:
            # Clean up temp file on error
            if temp_path and os.path.exists(temp_path):
                try:
                    os.unlink(temp_path)
                except Exception as e:
                    self.logger.warning(f"Failed to clean up temp file {temp_path}: {e}")
                    self.logger.debug(f"Temp file cleaned up: {temp_path}")
                except Exception as e:
                    self.logger.warning(f"Failed to clean up temp file {temp_path}: {e}")

    def generate(self, results: Dict, risk_score: int, risk_level: str,
                risk_details: Optional[Dict] = None,
                fix_status: Optional[Dict] = None) -> bool:
        """
        Generate HTML report

        Args:
            results: Scan results dictionary
            risk_score: Risk score (0-100)
            risk_level: Risk level (LOW/MEDIUM/HIGH/CRITICAL)
            risk_details: Details about the risk (optional)
            fix_status: Fix status from hardener (optional)

        Returns:
            bool: True if generation successful
        """
        self._show_progress("Generating HTML report")

        try:
            # Validate data
            if not self._validate_report_data(results, risk_score, risk_level):
                self.logger.error("Invalid report data")
                return False

            # Validate fix_status
            if fix_status and not self._validate_fix_status(fix_status):
                self.logger.warning("Invalid fix_status data, ignoring")
                fix_status = None

            # Sanitize data
            self._show_progress("Sanitizing data")
            sanitized_results = self._sanitize_data(results)

            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            report_file = os.path.join(self.report_dir, f"report_{timestamp}.html")

            # Build HTML content
            self._show_progress("Building HTML content")
            html_content = self._build_html(sanitized_results, risk_score, risk_level, risk_details, fix_status)

            # Write to file safely (atomic write)
            self._show_progress("Writing report")
            success = self._write_html_safe(html_content, report_file)

            # ✅ FIX: Verification is now inside _write_html_safe()
            # If it passed, we're done
            if success:
                self.logger.info(f"HTML report saved and verified: {report_file}")
            else:
                self.logger.error("HTML report generation failed")
                return False

            # Clean old reports
            self._show_progress("Cleaning old reports")
            self._clean_old_reports()

            # Log the HTML generation
            self.logger.info(f"HTML report saved: {report_file}")
            self._show_progress("HTML generation complete", done=True)
            print()
            return True

        except Exception as e:
            self.logger.error(f"Error generating HTML report: {e}")
            self._show_progress(f"Error: {e}", done=True)
            print()
            return False

    def generate_from_last_scan(self) -> bool:
        """
        Generate report from last scan

        Returns:
            bool: True if report generated successfully
        """
        try:
            self._show_progress("Finding last scan report")
            
            # Find the most recent scan report
            report_files = []
            if os.path.exists(self.report_dir):
                for f in os.listdir(self.report_dir):
                    if f.startswith('report_') and f.endswith(('.json', '.json.gz')):
                        file_path = os.path.join(self.report_dir, f)
                        # Check integrity
                        hash_file = file_path + '.sha256'
                        if os.path.exists(hash_file):
                            # Handle compressed files
                            if file_path.endswith('.gz'):
                                import gzip
                                try:
                                    with gzip.open(file_path, 'rt') as f2:
                                        content = f2.read()
                                    current_hash = hashlib.sha256(content.encode()).hexdigest()
                                except:
                                    continue
                            else:
                                with open(file_path, 'rb') as f2:
                                    current_hash = hashlib.sha256(f2.read()).hexdigest()
                            
                            with open(hash_file, 'r') as f2:
                                stored_hash = f2.read().strip()
                            if current_hash != stored_hash:
                                self.logger.warning(f"Skipping corrupted report: {file_path}")
                                continue
                        report_files.append((file_path, os.path.getmtime(file_path)))

            if not report_files:
                print("No scan reports found. Run a scan first.")
                return False

            # Get the most recent report
            latest_file = max(report_files, key=lambda x: x[1])[0]

            # Handle compressed files
            if latest_file.endswith('.gz'):
                import gzip
                with gzip.open(latest_file, 'rt', encoding='utf-8') as f:
                    data = json.load(f)
            else:
                with open(latest_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)

            results = data.get('results', {})
            risk_score = data.get('risk_score', 0)
            risk_level = data.get('risk_level', 'UNKNOWN')
            fix_status = data.get('fix_status', None)

            self._show_progress("Generating HTML from last scan")

            risk_details = data.get('risk_details', None)
            return self.generate(results, risk_score, risk_level, risk_details, fix_status)

        except Exception as e:
            self.logger.error(f"Error generating report from last scan: {e}")
            self._show_progress(f"Error: {e}", done=True)
            print()
            return False

    def _build_html(self, results: Dict, risk_score: int, risk_level: str,
                    risk_details: Optional[Dict] = None,
                    fix_status: Optional[Dict] = None) -> str:
        """Build complete HTML content."""
        return f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Shadow Security Report</title>
    <style>
        {self._get_css()}
    </style>
</head>
<body>
    <div class="container">
        {self._get_header()}
        {self._get_summary(results)}
        {self._get_risk_card(risk_score, risk_level)}
        {self._get_honest_summary(risk_details)}
        {self._get_fix_status(fix_status) if fix_status else ''}
        {self._get_findings(results)}
        {self._get_footer()}
    </div>
</body>
</html>
    """

    def _get_css(self) -> str:
        """Get CSS styles."""
        return """
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Arial, sans-serif;
            background: #f0f2f5;
            color: #333;
            line-height: 1.6;
        }
        .container {
            max-width: 1000px;
            margin: 0 auto;
            padding: 20px;
        }
        .header {
            background: linear-gradient(135deg, #1a1a2e, #16213e);
            color: white;
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 20px;
        }
        .header h1 {
            font-size: 28px;
            font-weight: bold;
            margin-bottom: 5px;
        }
        .header .subtitle {
            color: #8899aa;
            font-size: 14px;
        }
        .header .timestamp {
            color: #8899aa;
            font-size: 12px;
            margin-top: 10px;
        }
        .card {
            background: white;
            border-radius: 10px;
            padding: 20px;
            margin-bottom: 20px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .card h2 {
            font-size: 18px;
            margin-bottom: 15px;
            color: #1a1a2e;
            border-bottom: 2px solid #f0f2f5;
            padding-bottom: 10px;
        }
        .summary-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 15px;
        }
        .summary-item {
            text-align: center;
            padding: 15px;
            border-radius: 8px;
            background: #f8f9fa;
        }
        .summary-item .number {
            font-size: 28px;
            font-weight: bold;
        }
        .summary-item .label {
            font-size: 12px;
            color: #666;
            margin-top: 5px;
        }
        .pass { color: #28a745; }
        .fail { color: #dc3545; }
        .warn { color: #ffc107; }
        .error { color: #6f42c1; }
        .verified { color: #28a745; }
        .failed { color: #dc3545; }
        .risk-card {
            text-align: center;
            padding: 25px;
            border-radius: 10px;
            margin-bottom: 20px;
        }
        .risk-low { background: #d4edda; border: 2px solid #28a745; }
        .risk-medium { background: #fff3cd; border: 2px solid #ffc107; }
        .risk-high { background: #f8d7da; border: 2px solid #dc3545; }
        .risk-critical { background: #f5c6cb; border: 2px solid #721c24; }
        .risk-score {
            font-size: 48px;
            font-weight: bold;
        }
        .risk-level {
            font-size: 24px;
            font-weight: bold;
        }
        .fix-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
        }
        .fix-item {
            text-align: center;
            padding: 15px;
            border-radius: 8px;
            background: #f8f9fa;
        }
        .fix-item .number {
            font-size: 28px;
            font-weight: bold;
        }
        .fix-item .label {
            font-size: 12px;
            color: #666;
            margin-top: 5px;
        }
        .finding-list {
            list-style: none;
            padding: 0;
        }
        .finding-list li {
            padding: 8px 12px;
            margin-bottom: 5px;
            border-radius: 5px;
            background: #f8f9fa;
            border-left: 4px solid #ccc;
            word-break: break-word;
        }
        .finding-list .pass-item { border-left-color: #28a745; }
        .finding-list .fail-item { border-left-color: #dc3545; }
        .finding-list .warn-item { border-left-color: #ffc107; }
        .finding-list .error-item { border-left-color: #6f42c1; }
        .footer {
            text-align: center;
            color: #666;
            font-size: 12px;
            margin-top: 20px;
            padding: 20px;
            border-top: 1px solid #ddd;
        }
        @media (max-width: 600px) {
            .container { padding: 10px; }
            .header h1 { font-size: 22px; }
            .summary-grid { grid-template-columns: repeat(2, 1fr); }
            .fix-grid { grid-template-columns: repeat(2, 1fr); }
            .risk-score { font-size: 32px; }
        }
        @media (prefers-color-scheme: dark) {
            body { background: #1a1a2e; color: #e0e0e0; }
            .card { background: #2d2d44; }
            .summary-item { background: #3a3a55; }
            .card h2 { color: #e0e0e0; border-bottom-color: #3a3a55; }
            .finding-list li { background: #3a3a55; }
            .fix-item { background: #3a3a55; }
            .footer { border-top-color: #3a3a55; color: #8899aa; }
            .header .subtitle, .header .timestamp { color: #8899aa; }
        }
    """

    def _get_header(self) -> str:
        """Get HTML header."""
        return f"""
        <div class="header">
            <h1>🛡️ Shadow Security Report</h1>
            <div class="subtitle">Linux Hardening Tool</div>
            <div class="timestamp">Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</div>
            <div class="timestamp">Host: {platform.node()}</div>
        </div>
        """

    def _get_summary(self, results: Dict) -> str:
        """Get summary section."""
        pass_count = len(results.get('pass', []))
        fail_count = len(results.get('fail', []))
        warn_count = len(results.get('warn', []))
        error_count = len(results.get('error', []))

        return f"""
        <div class="card">
            <h2>📊 Scan Summary</h2>
            <div class="summary-grid">
                <div class="summary-item">
                    <div class="number pass">{pass_count}</div>
                    <div class="label">PASS</div>
                </div>
                <div class="summary-item">
                    <div class="number fail">{fail_count}</div>
                    <div class="label">FAIL</div>
                </div>
                <div class="summary-item">
                    <div class="number warn">{warn_count}</div>
                    <div class="label">WARN</div>
                </div>
                <div class="summary-item">
                    <div class="number error">{error_count}</div>
                    <div class="label">ERROR</div>
                </div>
            </div>
        </div>
        """

    def _get_risk_card(self, risk_score: int, risk_level: str) -> str:
        """Get risk card."""
        risk_class = f"risk-{risk_level.lower()}"

        descriptions = {
            'LOW': 'System is secure. Minor issues found.',
            'MEDIUM': 'System has some security issues. Should be addressed.',
            'HIGH': 'System has significant security issues. Must be addressed.',
            'CRITICAL': 'System is at high risk. Immediate action required.'
        }

        return f"""
        <div class="card risk-card {risk_class}">
            <div class="risk-score">{risk_score}/100</div>
            <div class="risk-level">{risk_level}</div>
            <div style="margin-top:10px; color:#555;">{descriptions.get(risk_level, 'Unknown')}</div>
        </div>
        """

    def _get_honest_summary(self, risk_details: Optional[Dict] = None) -> str:
        """Get honest risk summary section."""
        if not risk_details:
            return ""

        total = risk_details.get('total', 0)
        current = risk_details.get('current', 0)
        potential = risk_details.get('potential', 0)
        fixed = risk_details.get('fixed', 0)
        manual = risk_details.get('manual_required', 0)
        remaining = risk_details.get('remaining', 0)
        improvement = risk_details.get('improvement', 0)
        improvement_pct = risk_details.get('improvement_percent', 0)

        return f"""
        <div class="card">
            <h2>📊 Honest Risk Summary</h2>
            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 15px; margin-top: 10px;">
                <div style="background: #f8f9fa; padding: 15px; border-radius: 8px; text-align: center;">
                    <div style="font-size: 12px; color: #666;">Total Risk Score</div>
                    <div style="font-size: 24px; font-weight: bold; color: #dc3545;">{total}/100</div>
                    <div style="font-size: 12px; color: #666;">Original</div>
                </div>
                <div style="background: #f8f9fa; padding: 15px; border-radius: 8px; text-align: center;">
                    <div style="font-size: 12px; color: #666;">Current Risk (After Auto-Fixes)</div>
                    <div style="font-size: 24px; font-weight: bold; color: {'#28a745' if current < 50 else '#ffc107'};">{current}/100</div>
                    <div style="font-size: 12px; color: #666;">Fixed: {fixed} issues</div>
                </div>
                <div style="background: #f8f9fa; padding: 15px; border-radius: 8px; text-align: center;">
                    <div style="font-size: 12px; color: #666;">Potential Risk (After Manual Fixes)</div>
                    <div style="font-size: 24px; font-weight: bold; color: {'#28a745' if potential < 50 else '#ffc107'};">{potential}/100</div>
                    <div style="font-size: 12px; color: #666;">Manual: {manual} issues</div>
                </div>
                <div style="background: #f8f9fa; padding: 15px; border-radius: 8px; text-align: center;">
                    <div style="font-size: 12px; color: #666;">Improvement</div>
                    <div style="font-size: 24px; font-weight: bold; color: #28a745;">{improvement} points</div>
                    <div style="font-size: 12px; color: #666;">{improvement_pct}%</div>
                </div>
            </div>
            {f'<div style="margin-top: 15px; padding: 15px; background: #fff3cd; border-radius: 8px; border-left: 4px solid #ffc107;"><strong>⚠️ {remaining} issues still need to be fixed</strong></div>' if remaining > 0 else ''}
            {f'<div style="margin-top: 15px; padding: 15px; background: #d4edda; border-radius: 8px; border-left: 4px solid #28a745;"><strong>✅ ALL ISSUES RESOLVED! System is secure.</strong></div>' if remaining == 0 and manual == 0 else ''}
        </div>
        """
    
    def _get_fix_status(self, fix_status: Dict) -> str:
        """Get fix verification status section."""
        fixed_count = fix_status.get('fixed_count', 0)
        verified_count = len(fix_status.get('verified_fixes', []))
        failed_fixes = fix_status.get('failed_fixes', [])
        backup_count = fix_status.get('backup_count', 0)

        failed_html = ""
        if failed_fixes:
            failed_html = """
            <ul style="list-style: none; padding: 0; margin-top: 10px;">
            """
            for failed in failed_fixes[:10]:
                failed_html += f'<li style="color: #dc3545; padding: 5px 10px;">❌ {failed}</li>'
            if len(failed_fixes) > 10:
                failed_html += f'<li style="color: #dc3545; padding: 5px 10px;">... and {len(failed_fixes) - 10} more</li>'
            failed_html += "</ul>"

        return f"""
        <div class="card">
            <h2>🔧 Fix Verification</h2>
            <div class="fix-grid">
                <div class="fix-item">
                    <div class="number">{fixed_count}</div>
                    <div class="label">Total Fixes</div>
                </div>
                <div class="fix-item">
                    <div class="number verified">{verified_count}</div>
                    <div class="label">✅ Verified</div>
                </div>
                <div class="fix-item">
                    <div class="number failed">{len(failed_fixes)}</div>
                    <div class="label">❌ Failed</div>
                </div>
                <div class="fix-item">
                    <div class="number">{backup_count}</div>
                    <div class="label">💾 Backups</div>
                </div>
            </div>
            {failed_html}
        </div>
        """

    def _get_findings(self, results: Dict) -> str:
        """Get findings section."""
        findings_html = ""

        fails = results.get('fail', [])
        warns = results.get('warn', [])
        errors = results.get('error', [])

        if fails:
            findings_html += f"""
            <div class="card">
                <h2>❌ Failed Checks ({len(fails)})</h2>
                <ul class="finding-list">
            """
            for fail in fails[:20]:
                findings_html += f'<li class="fail-item">{fail}</li>'
            if len(fails) > 20:
                findings_html += f'<li class="fail-item" style="color:#666;">... and {len(fails) - 20} more</li>'
            findings_html += "</ul></div>"

        if warns:
            findings_html += f"""
            <div class="card">
                <h2>⚠️ Warnings ({len(warns)})</h2>
                <ul class="finding-list">
            """
            for warn in warns[:20]:
                findings_html += f'<li class="warn-item">{warn}</li>'
            if len(warns) > 20:
                findings_html += f'<li class="warn-item" style="color:#666;">... and {len(warns) - 20} more</li>'
            findings_html += "</ul></div>"

        if errors:
            findings_html += f"""
            <div class="card">
                <h2>❗ Errors ({len(errors)})</h2>
                <ul class="finding-list">
            """
            for error in errors[:10]:
                findings_html += f'<li class="error-item">{error}</li>'
            if len(errors) > 10:
                findings_html += f'<li class="error-item" style="color:#666;">... and {len(errors) - 10} more</li>'
            findings_html += "</ul></div>"

        if not fails and not warns and not errors:
            findings_html = """
            <div class="card">
                <h2>✅ No Issues Found</h2>
                <p style="color:#28a745; font-size:18px;">All checks passed successfully!</p>
            </div>
            """

        return findings_html

    def _get_footer(self) -> str:
        """Get footer."""
        return f"""
        <div class="footer">
            <p>Shadow Linux Hardening Tool v1.0.0</p>
            <p>Report generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            <p>Report ID: {hashlib.md5(datetime.now().isoformat().encode()).hexdigest()[:8]}</p>
        </div>
        """