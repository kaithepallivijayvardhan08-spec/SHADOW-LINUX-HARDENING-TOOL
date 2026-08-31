#!/usr/bin/env python3
"""
Shadow PDF Report
=================

Generates PDF reports for professional documentation.
"""

import os
import json
import tempfile
import platform
import logging
import subprocess
import hashlib
import gzip
import shutil
import re
import sys
from datetime import datetime
from typing import Dict, List, Optional, Any

try:
    from weasyprint import HTML # type: ignore
    WEASYPRINT_AVAILABLE = True
except ImportError:
    WEASYPRINT_AVAILABLE = False

try:
    from jinja2 import Template
    JINJA2_AVAILABLE = True
except ImportError:
    JINJA2_AVAILABLE = False


# ============================================================
# MODULE METADATA - FIXED
# ============================================================
SEVERITY = "LOW"
RECOMMENDATION = "PDF reports should be archived for compliance and audit trails"


class PDFReport:
    """Generate PDF reports"""

    # Configurable PDF options
    DEFAULT_PDF_OPTIONS = {
        'page_size': 'A4',
        'margins': '60px 40px',
        'font_family': "'Segoe UI', Arial, sans-serif",
        'title': 'Shadow Security Report'
    }

    def __init__(self, pdf_options: Optional[Dict] = None):
        """Initialize PDF report"""
        self.logger = logging.getLogger(__name__)
        self.report_dir = '/var/log/shadow/reports/'
        self.pdf_options = self.DEFAULT_PDF_OPTIONS.copy()
        if pdf_options:
            self.pdf_options.update(pdf_options)

        # Ensure report directory exists
        os.makedirs(self.report_dir, exist_ok=True)

        # Check dependencies
        self.weasyprint_available = WEASYPRINT_AVAILABLE
        self.jinja2_available = JINJA2_AVAILABLE

        if not self.weasyprint_available:
            self.logger.warning("weasyprint not installed. PDF generation disabled.")
            self.logger.info("Install with: pip install weasyprint")
        if not self.jinja2_available:
            self.logger.warning("jinja2 not installed. PDF generation disabled.")
            self.logger.info("Install with: pip install jinja2")

    def _show_progress(self, message: str = "", done: bool = False):
        """Show progress during PDF generation using stdout.write"""
        if done:
            sys.stdout.write(f"\r✓ PDF: {message}".ljust(60) + "\n")
        else:
            sys.stdout.write(f"\r[*] PDF: {message}...".ljust(60))
        sys.stdout.flush()

    def _sanitize_text(self, text: str) -> str:
        """Sanitize text to prevent sensitive data exposure."""
        if not text:
            return text
        
        text = text.replace('&', '&amp;')
        text = text.replace('<', '&lt;')
        text = text.replace('>', '&gt;')
        text = text.replace('"', '&quot;')
        text = text.replace("'", '&#39;')
        
        patterns = [
            (r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', '[IP]'),
            (r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', '[EMAIL]'),
            (r'(api[_\-]?key|apikey|token|secret)[=:]\s*\S+', r'\1=[REDACTED]', re.IGNORECASE),
            (r'(password|passwd|pwd)[=:]\s*\S+', r'\1=[REDACTED]', re.IGNORECASE),
            (r'(user(?:name)?|username)[=:]\s*\S+', r'\1=[REDACTED]', re.IGNORECASE),
            (r'/home/[^/\s]+', '/home/[REDACTED]'),
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

    def _validate_fix_status(self, fix_status: Dict) -> bool:
        """Validate fix_status structure."""
        if not isinstance(fix_status, dict):
            return False
        
        expected_keys = ['fixed_count', 'failed_fixes', 'verified_fixes', 'backup_count']
        for key in expected_keys:
            if key not in fix_status:
                return False
        
        if not isinstance(fix_status.get('fixed_count'), int): return False
        if not isinstance(fix_status.get('failed_fixes'), list): return False
        if not isinstance(fix_status.get('verified_fixes'), list): return False
        if not isinstance(fix_status.get('backup_count'), int): return False
        
        return True

    def _compress_report(self, report_file: str) -> bool:
        """Compress PDF report to save space."""
        try:
            gz_file = report_file + '.gz'
            with open(report_file, 'rb') as f_in:
                with gzip.open(gz_file, 'wb') as f_out:
                    shutil.copyfileobj(f_in, f_out)
            
            if os.path.exists(gz_file) and os.path.getsize(gz_file) > 0:
                os.remove(report_file)
                self.logger.debug(f"PDF compressed: {gz_file}")
                return True
        except Exception as e:
            self.logger.warning(f"PDF compression failed: {e}")
        return False

    def _clean_old_reports(self, max_reports: int = 30, max_age_days: int = 90):
        """Remove old PDF reports based on retention policy."""
        try:
            now = datetime.now()
            pdf_files = []
            
            for f in os.listdir(self.report_dir):
                if f.startswith('report_') and f.endswith(('.pdf', '.pdf.gz')):
                    file_path = os.path.join(self.report_dir, f)
                    file_time = datetime.fromtimestamp(os.path.getmtime(file_path))
                    age_days = (now - file_time).days
                    pdf_files.append((file_path, age_days))
            
            pdf_files.sort(key=lambda x: x[1], reverse=True)
            
            for file_path, age_days in pdf_files:
                should_remove = False
                reason = ""
                
                if age_days > max_age_days:
                    should_remove = True
                    reason = f"older than {max_age_days} days"
                elif len([r for r in pdf_files if r[1] < max_age_days]) > max_reports:
                    should_remove = True
                    reason = f"exceeds {max_reports} reports"
                
                if should_remove:
                    os.remove(file_path)
                    hash_file = file_path + '.sha256'
                    if os.path.exists(hash_file):
                        os.remove(hash_file)
                    self.logger.debug(f"Removed old PDF: {file_path} ({reason})")
                    pdf_files = [r for r in pdf_files if r[0] != file_path]
                    
        except Exception as e:
            self.logger.warning(f"Error cleaning old PDF reports: {e}")

    def _check_dependencies(self) -> bool:
        """Check if all dependencies are available."""
        missing = []
        if not WEASYPRINT_AVAILABLE: missing.append('weasyprint')
        if not JINJA2_AVAILABLE: missing.append('jinja2')
        
        if missing:
            self.logger.error(f"Missing dependencies: {', '.join(missing)}")
            return False
        return True

    def generate(self, results: Dict, risk_score: int, risk_level: str,
                 risk_details: Optional[Dict] = None,
                 fix_status: Optional[Dict] = None) -> bool:
        """Generate PDF report"""
        if not self.weasyprint_available or not self.jinja2_available:
            self.logger.error("PDF generation requires weasyprint and jinja2")
            return False

        self._show_progress("Building PDF report")

        try:
            if fix_status and not self._validate_fix_status(fix_status):
                self.logger.warning("Invalid fix_status data, ignoring")
                fix_status = None

            sanitized_results = self._sanitize_data(results)
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            report_file = os.path.join(self.report_dir, f"report_{timestamp}.pdf")

            self._show_progress("Generating HTML content")
            html_content = self._build_html(sanitized_results, risk_score, risk_level, risk_details, fix_status)

            self._show_progress("Generating PDF")
            
            # ✅ FIX: Pass raw data for ReportLab fallback
            success = self._write_pdf_safe(html_content, report_file, results, risk_score, risk_level)

            self._clean_old_reports()

            if success:
                self.logger.info(f"PDF report saved: {report_file}")
                self._show_progress("PDF generation complete", done=True)
                print()
                return True
            else:
                self.logger.error("PDF generation failed")
                self._show_progress("PDF generation failed", done=True)
                print()
                return False

        except Exception as e:
            self.logger.error(f"Error generating PDF report: {e}")
            self._show_progress(f"Error: {e}", done=True)
            print()
            return False

    def generate_from_last_scan(self) -> bool:
        """Generate report from last scan"""
        try:
            self._show_progress("Finding last scan report")
            report_files = []
            if os.path.exists(self.report_dir):
                for f in os.listdir(self.report_dir):
                    # ✅ FIX 4: Changed 'scan_' to 'report_' to match json_report.py output
                    if f.startswith('report_') and f.endswith(('.json', '.json.gz')):
                        file_path = os.path.join(self.report_dir, f)
                        hash_file = file_path + '.sha256'
                        if os.path.exists(hash_file):
                            if file_path.endswith('.gz'):
                                import gzip
                                try:
                                    with gzip.open(file_path, 'rt') as f2:
                                        content = f2.read()
                                    current_hash = hashlib.sha256(content.encode()).hexdigest()
                                except: continue
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

            latest_file = max(report_files, key=lambda x: x[1])[0]

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

            self._show_progress("Generating PDF from last scan")
            risk_details = data.get('risk_details', None)
            return self.generate(results, risk_score, risk_level, risk_details, fix_status)

        except Exception as e:
            self.logger.error(f"Error generating report from last scan: {e}")
            self._show_progress(f"Error: {e}", done=True)
            print()
            return False

    def _verify_pdf(self, output_path: str) -> bool:
        """Verify PDF was written correctly."""
        try:
            paths_to_check = [output_path, output_path + '.gz']
            found_path = None
            for path in paths_to_check:
                if os.path.exists(path):
                    found_path = path
                    break
        
            if not found_path: return False
            if os.path.getsize(found_path) == 0: return False
        
            with open(found_path, 'rb') as f:
                header = f.read(5)
                if header != b'%PDF-': return False
        
            return True
        except Exception:
            return False

    # ============================================================
    # ✅ FIX 3: REPORTLAB FALLBACK
    # ============================================================
    def _generate_with_reportlab(self, output_path: str, results: Dict, risk_score: int, risk_level: str) -> bool:
        """Generate a professional PDF using ReportLab as a fallback when WeasyPrint crashes."""
        try:
            from reportlab.lib.pagesizes import A4  # type: ignore
            from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle  # type: ignore
            from reportlab.lib.styles import getSampleStyleSheet  # type: ignore
            from reportlab.lib import colors  # type: ignore
            
            doc = SimpleDocTemplate(output_path, pagesize=A4)
            styles = getSampleStyleSheet()
            story = []
            
            title_style = styles['Heading1']
            title_style.alignment = 1
            story.append(Paragraph("🛡️ Shadow Security Report", title_style))
            story.append(Spacer(1, 20))
            
            risk_color = colors.red if risk_score > 70 else colors.orange if risk_score > 40 else colors.green
            story.append(Paragraph(f"Risk Score: {risk_score}/100 ({risk_level})", styles['Heading2']))
            story.append(Spacer(1, 20))
            
            pass_count = len(results.get('pass', []))
            fail_count = len(results.get('fail', []))
            warn_count = len(results.get('warn', []))
            
            summary_data = [
                ['PASS', 'FAIL', 'WARN'],
                [str(pass_count), str(fail_count), str(warn_count)]
            ]
            summary_table = Table(summary_data, colWidths=[100, 100, 100])
            summary_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1a1a2e')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 14),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            story.append(summary_table)
            story.append(Spacer(1, 20))
            
            if fail_count > 0:
                story.append(Paragraph("❌ Failed Checks", styles['Heading2']))
                for fail in results.get('fail', [])[:15]:
                    story.append(Paragraph(f"• {self._sanitize_text(fail)}", styles['Normal']))
                story.append(Spacer(1, 12))
                
            if warn_count > 0:
                story.append(Paragraph("⚠️ Warnings", styles['Heading2']))
                for warn in results.get('warn', [])[:15]:
                    story.append(Paragraph(f"• {self._sanitize_text(warn)}", styles['Normal']))
                    
            doc.build(story)
            self.logger.info("✅ PDF generated successfully using ReportLab fallback")
            return True
        except ImportError:
            self.logger.error("ReportLab not installed. Cannot generate fallback PDF.")
            return False
        except Exception as e:
            self.logger.error(f"ReportLab fallback failed: {e}")
            return False

    def _write_pdf_safe(self, html_content: str, output_path: str, results: Dict = None, risk_score: int = 0, risk_level: str = "UNKNOWN") -> bool:
        """Safely write PDF using a temporary file for atomic write."""
        temp_html_path = None
        temp_pdf_path = None
    
        try:
            with tempfile.NamedTemporaryFile(mode='w', suffix='.html', delete=False) as f:
                f.write(html_content)
                temp_html_path = f.name

            temp_dir = os.path.dirname(output_path)
            with tempfile.NamedTemporaryFile(suffix='.pdf', delete=False, dir=temp_dir) as f:
                temp_pdf_path = f.name

            from weasyprint import HTML, CSS # type: ignore
            css = CSS(string='@page { size: A4; margin: 2cm; }')
            
            pdf_generated = False
            
            # Method 1: Full API with CSS
            try:
                HTML(string=html_content).write_pdf(temp_pdf_path, stylesheets=[css])
                pdf_generated = True
            except AttributeError as e:
                if 'super' in str(e) and 'transform' in str(e):
                    self.logger.warning("WeasyPrint super().transform() error detected. Trying Method 2...")
                    try:
                        HTML(string=html_content).write_pdf(temp_pdf_path)
                        pdf_generated = True
                    except Exception: pass
            
            if not pdf_generated:
                # Method 3: CLI
                try:
                    result = subprocess.run(['weasyprint', temp_html_path, temp_pdf_path], capture_output=True, timeout=30)
                    if result.returncode == 0: pdf_generated = True
                except Exception: pass

            if not pdf_generated:
                # ✅ FIX 3: Method 4 - ReportLab Fallback (Fixes Kali sudo system package mismatch)
                self.logger.warning("WeasyPrint failed completely. Falling back to ReportLab...")
                if results is not None and self._generate_with_reportlab(temp_pdf_path, results, risk_score, risk_level):
                    pdf_generated = True

            if not pdf_generated:
                self.logger.error("All PDF generation methods failed")
                return False

            if not os.path.exists(temp_pdf_path) or os.path.getsize(temp_pdf_path) == 0:
                return False

            shutil.move(temp_pdf_path, output_path)
            self.logger.info(f"✅ PDF saved: {output_path} ({os.path.getsize(output_path)} bytes)")

            if not self._verify_pdf(output_path):
                if os.path.exists(output_path): os.remove(output_path)
                return False

            with open(output_path, 'rb') as f:
                file_hash = hashlib.sha256(f.read()).hexdigest()
            hash_path = output_path + '.sha256'
            with open(hash_path, 'w') as f:
                f.write(file_hash)

            self._compress_report(output_path)
            return True

        except Exception as e:
            self.logger.error(f"Unexpected error writing PDF: {e}")
            return False
    
        finally:
            for path in [temp_html_path, temp_pdf_path]:
                if path and os.path.exists(path):
                    try: os.unlink(path)
                    except Exception: pass

    def _get_page_size(self) -> str: return self.pdf_options.get('page_size', 'A4')
    def _get_margins(self) -> str: return self.pdf_options.get('margins', '60px 40px')

    def _get_honest_summary_html(self, risk_details: Optional[Dict] = None) -> str:
        if not risk_details: return ""
        total = risk_details.get('total', 0)
        current = risk_details.get('current', 0)
        potential = risk_details.get('potential', 0)
        fixed = risk_details.get('fixed', 0)
        manual = risk_details.get('manual_required', 0)
        remaining = risk_details.get('remaining', 0)
        improvement = risk_details.get('improvement', 0)
        improvement_pct = risk_details.get('improvement_percent', 0)

        return f"""
        <div class="section">
            <h2>📊 Honest Risk Summary</h2>
            <div class="summary-grid">
                <div class="summary-item"><div class="number" style="color:#dc3545;">{total}</div><div class="label">Total Risk</div></div>
                <div class="summary-item"><div class="number" style="color:{'#28a745' if current < 50 else '#ffc107'};">{current}</div><div class="label">Current (Auto-Fixed)</div></div>
                <div class="summary-item"><div class="number" style="color:{'#28a745' if potential < 50 else '#ffc107'};">{potential}</div><div class="label">Potential (Manual)</div></div>
                <div class="summary-item"><div class="number" style="color:#28a745;">{improvement}</div><div class="label">Improvement ({improvement_pct}%)</div></div>
            </div>
            <p style="text-align:center; margin-top:10px; font-size:14px;">
                ✅ Fixed: {fixed} issues | 📋 Manual: {manual} issues | {'⚠️ Remaining: ' + str(remaining) + ' issues' if remaining > 0 else '🎉 All issues resolved!'}
            </p>
        </div>
        """

    def _build_html(self, results: Dict, risk_score: int, risk_level: str,
                    risk_details: Optional[Dict] = None,
                    fix_status: Optional[Dict] = None) -> str:
        pass_count = len(results.get('pass', []))
        fail_count = len(results.get('fail', []))
        warn_count = len(results.get('warn', []))
        error_count = len(results.get('error', []))

        risk_colors = {'LOW': '#28a745', 'MEDIUM': '#ffc107', 'HIGH': '#dc3545', 'CRITICAL': '#721c24'}
        risk_color = risk_colors.get(risk_level, '#6c757d')
        descriptions = {
            'LOW': 'System is secure. Minor issues found.',
            'MEDIUM': 'System has some security issues. Should be addressed.',
            'HIGH': 'System has significant security issues. Must be addressed.',
            'CRITICAL': 'System is at high risk. Immediate action required.'
        }

        findings_html = ""
        fails = results.get('fail', [])
        warns = results.get('warn', [])
        errors = results.get('error', [])

        if fails:
            findings_html += f'<div class="section"><h3 style="color:#dc3545;">❌ Failed Checks ({len(fails)})</h3><ul>'
            for fail in fails[:20]: findings_html += f'<li style="color:#dc3545;">{fail}</li>'
            if len(fails) > 20: findings_html += f'<li style="color:#dc3545;">... and {len(fails) - 20} more</li>'
            findings_html += "</ul></div>"

        if warns:
            findings_html += f'<div class="section"><h3 style="color:#ffc107;">⚠️ Warnings ({len(warns)})</h3><ul>'
            for warn in warns[:20]: findings_html += f'<li style="color:#856404;">{warn}</li>'
            if len(warns) > 20: findings_html += f'<li style="color:#856404;">... and {len(warns) - 20} more</li>'
            findings_html += "</ul></div>"

        if errors:
            findings_html += f'<div class="section"><h3 style="color:#6f42c1;">❗ Errors ({len(errors)})</h3><ul>'
            for error in errors[:10]: findings_html += f'<li style="color:#6f42c1;">{error}</li>'
            if len(errors) > 10: findings_html += f'<li style="color:#6f42c1;">... and {len(errors) - 10} more</li>'
            findings_html += "</ul></div>"

        if not fails and not warns and not errors:
            findings_html = '<div class="section" style="color:#28a745; text-align:center;"><h3>✅ All checks passed successfully!</h3></div>'

        fix_status_html = ""
        if fix_status:
            fixed_count = fix_status.get('fixed_count', 0)
            verified_count = len(fix_status.get('verified_fixes', []))
            failed_fixes = fix_status.get('failed_fixes', [])
            backup_count = fix_status.get('backup_count', 0)

            failed_list = ""
            if failed_fixes:
                failed_list = '<ul>'
                for f in failed_fixes[:10]: failed_list += f'<li style="color:#dc3545;">{f}</li>'
                if len(failed_fixes) > 10: failed_list += f'<li style="color:#dc3545;">... and {len(failed_fixes) - 10} more</li>'
                failed_list += '</ul>'

            fix_status_html = f"""
            <div class="section">
                <h2>🔧 Fix Verification</h2>
                <div class="summary-grid">
                    <div class="summary-item"><div class="number">{fixed_count}</div><div class="label">Total Fixes</div></div>
                    <div class="summary-item" style="color:#28a745;"><div class="number">{verified_count}</div><div class="label">✅ Verified</div></div>
                    <div class="summary-item" style="color:#dc3545;"><div class="number">{len(failed_fixes)}</div><div class="label">❌ Failed</div></div>
                    <div class="summary-item"><div class="number">{backup_count}</div><div class="label">💾 Backups</div></div>
                </div>
                {failed_list}
            </div>
            """

        page_size = self._get_page_size()
        margins = self._get_margins()
        title = self.pdf_options.get('title', 'Shadow Security Report')

        html = f"""
        <!DOCTYPE html><html><head><meta charset="UTF-8"><title>{title}</title>
            <style>
                body {{ font-family: {self.pdf_options.get('font_family', "'Segoe UI', Arial, sans-serif")}; margin: {margins}; color: #333; line-height: 1.6; }}
                .header {{ text-align: center; padding: 20px; border-bottom: 3px solid #1a1a2e; margin-bottom: 30px; }}
                .header h1 {{ font-size: 28px; color: #1a1a2e; margin: 0; }}
                .section {{ margin-bottom: 25px; padding: 15px; border: 1px solid #ddd; border-radius: 5px; background: #f9f9f9; }}
                .summary-grid {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 15px; margin: 15px 0; }}
                .summary-item {{ text-align: center; padding: 15px; border-radius: 5px; background: white; border: 1px solid #ddd; }}
                .summary-item .number {{ font-size: 28px; font-weight: bold; }}
                .risk-box {{ text-align: center; padding: 20px; background: {risk_color}10; border: 2px solid {risk_color}; border-radius: 5px; margin: 20px 0; }}
                .risk-score {{ font-size: 48px; font-weight: bold; color: {risk_color}; }}
                .risk-level {{ font-size: 24px; font-weight: bold; color: {risk_color}; }}
                @page {{ size: {page_size}; margin: {margins}; }}
            </style>
        </head><body>
            <div class="header"><h1>🛡️ {title}</h1><div class="subtitle">Linux Hardening Tool</div></div>
            <div class="section"><h2>📊 Scan Summary</h2>
                <div class="summary-grid">
                    <div class="summary-item"><div class="number pass">{pass_count}</div><div class="label">PASS</div></div>
                    <div class="summary-item"><div class="number fail">{fail_count}</div><div class="label">FAIL</div></div>
                    <div class="summary-item"><div class="number warn">{warn_count}</div><div class="label">WARN</div></div>
                    <div class="summary-item"><div class="number error">{error_count}</div><div class="label">ERROR</div></div>
                </div>
            </div>
            {fix_status_html}
            <div class="risk-box">
                <div class="risk-score">{risk_score}/100</div>
                <div class="risk-level">{risk_level}</div>
                <div class="risk-description">{descriptions.get(risk_level, 'Unknown risk level')}</div>
            </div>
            {self._get_honest_summary_html(risk_details)}
            {findings_html}
        </body></html>
        """
        return html