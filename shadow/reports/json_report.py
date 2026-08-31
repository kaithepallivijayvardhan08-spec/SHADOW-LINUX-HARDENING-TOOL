#!/usr/bin/env python3
"""
Shadow JSON Report
==================

Generates JSON reports for machine-readable output.

Output format:
- Structured JSON with all scan results
- Risk score and level
- Timestamp
- System information
- All findings with details
- Fix verification status (after hardening)
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
RECOMMENDATION = "JSON reports should be archived for compliance and audit trails"


class JSONReport:
    """Generate JSON reports"""

    # Report retention settings
    MAX_REPORTS = 30
    REPORT_RETENTION_DAYS = 90

    def __init__(self):
        """Initialize JSON report"""
        self.logger = logging.getLogger(__name__)
        self.report_dir = '/var/log/shadow/reports/'

        # Ensure report directory exists
        os.makedirs(self.report_dir, exist_ok=True)

    # ============================================================
    # FIX 1: PROGRESS INDICATOR - FIXED (Using sys.stdout.write)
    # ============================================================
    def _show_progress(self, message: str = "", done: bool = False):
        """Show progress during JSON generation using stdout.write"""
        if done:
            sys.stdout.write(f"\r✓ JSON: {message}".ljust(60) + "\n")
        else:
            sys.stdout.write(f"\r[*] JSON: {message}...".ljust(60))
        sys.stdout.flush()

    # ============================================================
    # FIX 2: ENHANCED RECURSIVE SANITIZATION
    # ============================================================
    def _sanitize_value(self, value: Any, depth: int = 0) -> Any:
        """Recursively sanitize data to prevent sensitive information disclosure."""
        if depth > 10:
            return str(value)[:500]
        
        if isinstance(value, str):
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
                # Private SSH keys
                (r'-----BEGIN (?:RSA|DSA|EC|OPENSSH) PRIVATE KEY-----.*?-----END (?:RSA|DSA|EC|OPENSSH) PRIVATE KEY-----',
                 '[PRIVATE KEY REMOVED]', re.DOTALL),
            ]
            
            result = value
            for pattern_tuple in patterns:
                if len(pattern_tuple) == 3:
                    pattern, replacement, flags = pattern_tuple
                    result = re.sub(pattern, replacement, result, flags=flags)
                else:
                    pattern, replacement = pattern_tuple
                    result = re.sub(pattern, replacement, result)
            
            # Limit string length
            if len(result) > 500:
                result = result[:500] + '...'
            
            return result
        
        elif isinstance(value, dict):
            return {self._sanitize_value(k, depth + 1): self._sanitize_value(v, depth + 1) 
                    for k, v in value.items()}
        
        elif isinstance(value, list):
            return [self._sanitize_value(item, depth + 1) for item in value[:100]]
        
        else:
            return str(value)[:500] if value is not None else None

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
    # FIX 4: COMPRESS REPORT - FIXED (Remove original)
    # ============================================================
    def _compress_report(self, report_file: str) -> bool:
        """Compress JSON report and remove original to save space."""
        try:
            gz_file = report_file + '.gz'
            with open(report_file, 'rb') as f_in:
                with gzip.open(gz_file, 'wb') as f_out:
                    shutil.copyfileobj(f_in, f_out)
            
            # Verify compression worked
            if os.path.exists(gz_file) and os.path.getsize(gz_file) > 0:
                # Remove original after successful compression
                os.remove(report_file)
                self.logger.debug(f"JSON compressed: {gz_file} ({os.path.getsize(gz_file)} bytes)")
                return True
            
        except Exception as e:
            self.logger.warning(f"JSON compression failed: {e}")
        return False

    # ============================================================
    # FIX 5: CLEAN OLD REPORTS - FIXED (Include compressed)
    # ============================================================
    def _clean_old_reports(self, max_reports: int = 30, max_age_days: int = 90):
        """Remove old JSON reports based on retention policy."""
        try:
            now = datetime.now()
            json_files = []
            
            for f in os.listdir(self.report_dir):
                if f.startswith('report_') and f.endswith(('.json', '.json.gz')):
                    file_path = os.path.join(self.report_dir, f)
                    file_time = datetime.fromtimestamp(os.path.getmtime(file_path))
                    age_days = (now - file_time).days
                    json_files.append((file_path, age_days))
            
            # Sort by age (oldest first)
            json_files.sort(key=lambda x: x[1], reverse=True)
            
            # Remove old files
            for file_path, age_days in json_files:
                should_remove = False
                reason = ""
                
                if age_days > max_age_days:
                    should_remove = True
                    reason = f"older than {max_age_days} days"
                elif len([r for r in json_files if r[1] < max_age_days]) > max_reports:
                    should_remove = True
                    reason = f"exceeds {max_reports} reports"
                
                if should_remove:
                    os.remove(file_path)
                    # Remove hash file too
                    hash_file = file_path + '.sha256'
                    if os.path.exists(hash_file):
                        os.remove(hash_file)
                    self.logger.debug(f"Removed old JSON: {file_path} ({reason})")
                    # Remove from list
                    json_files = [r for r in json_files if r[0] != file_path]
                    
        except Exception as e:
            self.logger.warning(f"Error cleaning old JSON reports: {e}")

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
    def _verify_json(self, output_path: str, expected_data: Dict) -> bool:
        """Verify JSON was written correctly."""
        try:
            # ✅ FIX: Check for both .json and .json.gz
            paths_to_check = [output_path, output_path + '.gz']
        
            found_path = None
            for path in paths_to_check:
                if os.path.exists(path):
                    found_path = path
                    break
        
            if not found_path:
                self.logger.error(f"JSON file not found: {output_path} (tried .json and .json.gz)")
                return False
        
            if os.path.getsize(found_path) == 0:
                self.logger.error(f"JSON file is empty: {found_path}")
                return False
        
            # If compressed, decompress to verify
            if found_path.endswith('.gz'):
                import gzip
                with gzip.open(found_path, 'rt', encoding='utf-8') as f:
                    data = json.load(f)
            else:
                with open(found_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
        
            # Verify expected data exists
            if 'report' not in data:
                self.logger.error("JSON missing 'report' section")
                return False
        
            if 'risk' not in data:
                self.logger.error("JSON missing 'risk' section")
                return False
        
            if 'summary' not in data:
                self.logger.error("JSON missing 'summary' section")
                return False
        
            # Verify hash matches
            hash_file = output_path + '.sha256'
            if os.path.exists(hash_file):
                with open(hash_file, 'r') as f:
                    stored_hash = f.read().strip()
                    with open(found_path, 'rb') as f:
                        current_hash = hashlib.sha256(f.read()).hexdigest()
                    if current_hash != stored_hash:
                        self.logger.error("JSON hash mismatch")
                        return False
        
            self.logger.info(f"JSON verification passed: {found_path}")
            return True
        
        except json.JSONDecodeError as e:
            self.logger.error(f"Invalid JSON: {e}")
            return False
        except Exception as e:
            self.logger.error(f"JSON verification failed: {e}")
            return False

    # ============================================================
    # ATOMIC WRITE WITH ERROR HANDLING
    # ============================================================
    def _write_json_safe(self, data: Dict, output_path: str) -> bool:
        """
        Safely write JSON using a temporary file for atomic write.
        ✅ FIX: Verifies BEFORE compression
        """
        temp_path = None
    
        try:
            # Create JSON content
            json_content = json.dumps(data, indent=2, ensure_ascii=False)

            # Write to temp file first (use same directory to avoid cross-device)
            temp_dir = os.path.dirname(output_path)
            with tempfile.NamedTemporaryFile(mode='w', suffix='.json', 
                                        delete=False, encoding='utf-8',
                                        dir=temp_dir) as f:
                f.write(json_content)
                temp_path = f.name

            # Verify temp file was created
            if not os.path.exists(temp_path):
                self.logger.error("Temp JSON file was not created")
                return False

            if os.path.getsize(temp_path) == 0:
                self.logger.error("Temp JSON file is empty")
                os.unlink(temp_path)
                return False

            # Move temp file to destination
            shutil.move(temp_path, output_path)
            self.logger.info(f"JSON saved: {output_path} ({os.path.getsize(output_path)} bytes)")

            # ✅ FIX: Verify BEFORE compression
            if not self._verify_json(output_path, data):
                self.logger.error("JSON verification failed before compression")
                if os.path.exists(output_path):
                    os.remove(output_path)
                return False

            # Generate hash for integrity
            with open(output_path, 'rb') as f:
                file_hash = hashlib.sha256(f.read()).hexdigest()
            with open(output_path + '.sha256', 'w') as f:
                f.write(file_hash)

            # Compress report (after verification)
            self._compress_report(output_path)

            return True

        except json.JSONDecodeError as e:
            self.logger.error(f"JSON serialization error: {e}")
            return False
        except Exception as e:
            self.logger.error(f"Error writing JSON: {e}")
            return False
        finally:
            # Clean up temp file on error
            if temp_path and os.path.exists(temp_path):
                try:
                    os.unlink(temp_path)
                except:
                    pass

    def generate(self, results: Dict, risk_score: int, risk_level: str, 
                risk_details: Optional[Dict] = None, 
                fix_status: Optional[Dict] = None) -> bool:
        """
        Generate JSON report

        Args:
            results: Scan results dictionary
            risk_score: Risk score (0-100)
            risk_level: Risk level (LOW/MEDIUM/HIGH/CRITICAL)
            fix_status: Fix status from hardener (optional)

        Returns:
            bool: True if generation successful
        """
        self._show_progress("Generating JSON report")

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
            sanitized_results = self._sanitize_value(results)

            # ✅ FIX: Create timestamp and report file path FIRST
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            report_file = os.path.join(self.report_dir, f"report_{timestamp}.json")

            # ✅ FIX: Build report data SECOND
            self._show_progress("Building report structure")
            report_data = self._build_report_data(sanitized_results, risk_score, risk_level, risk_details, fix_status)

            # ✅ FIX: Write to file THIRD
            self._show_progress("Writing report")
            success = self._write_json_safe(report_data, report_file)

            # ✅ FIX: Verification is now inside _write_json_safe()
            # If it passed, we're done
            if success:
                self.logger.info(f"JSON report saved and verified: {report_file}")
            else:
                self.logger.error("JSON report generation failed")
                return False

            # Clean old reports
            self._show_progress("Cleaning old reports")
            self._clean_old_reports()

            # Log the JSON generation
            self.logger.info(f"JSON report saved: {report_file}")
            self._show_progress("JSON generation complete", done=True)
            print()
            return True

        except Exception as e:
            self.logger.error(f"Error generating JSON report: {e}")
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
                            actual_file = file_path
                            if file_path.endswith('.gz'):
                                # For compressed, we need to decompress to check
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
            risk_details = data.get('risk_details', None)  # ✅ FIX: Extract risk_details
            fix_status = data.get('fix_status', None)

            self._show_progress("Generating JSON from last scan")

            # ✅ FIX: Pass both risk_details and fix_status correctly
            return self.generate(results, risk_score, risk_level, risk_details, fix_status)

        except Exception as e:
            self.logger.error(f"Error generating report from last scan: {e}")
            self._show_progress(f"Error: {e}", done=True)
            print()
            return False

    def _build_report_data(self, results: Dict, risk_score: int, risk_level: str,
                           risk_details: Optional[Dict] = None,
                           fix_status: Optional[Dict] = None) -> Dict:
        """
        Build report data structure

        Args:
            results: Scan results
            risk_score: Risk score
            risk_level: Risk level
            fix_status: Fix status from hardener

        Returns:
            Dict: Report data
        """
        report_data = {
            'report': {
                'timestamp': datetime.now().isoformat(),
                'version': '1.0.0',
                'generator': 'Shadow Linux Hardening Tool'
            },
            'system': {
                'hostname': platform.node(),
                'system': platform.system(),
                'release': platform.release(),
                'version': platform.version(),
                'machine': platform.machine(),
                'processor': platform.processor()
            },
            'risk': {
                'score': risk_score,
                'level': risk_level,
                'description': self._get_risk_description(risk_level)
            },
            'risk_details': risk_details or {},

            'summary': {
                'total_checks': self._get_total_checks(results),
                'passed': len(results.get('pass', [])),
                'failed': len(results.get('fail', [])),
                'warnings': len(results.get('warn', [])),
                'errors': len(results.get('error', []))
            },
            'findings': {
                'pass': results.get('pass', []),
                'fail': results.get('fail', []),
                'warn': results.get('warn', []),
                'error': results.get('error', [])
            },
            'details': results.get('details', {})
        }

        # Add fix status if available
        if fix_status:
            report_data['fix_status'] = {
                'fixed_count': fix_status.get('fixed_count', 0),
                'verified_fixes': fix_status.get('verified_fixes', []),
                'failed_fixes': fix_status.get('failed_fixes', []),
                'backup_count': fix_status.get('backup_count', 0),
                'backup_dir': fix_status.get('backup_dir', '')
            }

        return report_data

    def _get_total_checks(self, results: Dict) -> int:
        """Get total number of checks."""
        return (len(results.get('pass', [])) +
                len(results.get('fail', [])) +
                len(results.get('warn', [])) +
                len(results.get('error', [])))

    def _get_risk_description(self, risk_level: str) -> str:
        """Get risk level description."""
        descriptions = {
            'LOW': 'System is secure. Minor issues found.',
            'MEDIUM': 'System has some security issues. Should be addressed.',
            'HIGH': 'System has significant security issues. Must be addressed.',
            'CRITICAL': 'System is at high risk. Immediate action required.'
        }
        return descriptions.get(risk_level, 'Unknown risk level')