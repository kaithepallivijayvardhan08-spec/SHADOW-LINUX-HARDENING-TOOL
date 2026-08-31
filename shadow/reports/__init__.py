#!/usr/bin/env python3
"""
Shadow Reports Module
=====================

Generates reports in multiple formats:
- Terminal report (console output with colors)
- JSON report (machine-readable)
- HTML report (web-friendly)
- PDF report (professional document) - planned

All reports implement:
    def render(results: dict, risk_score: int, risk_level: str) -> bool:
        Returns: True if report generated successfully

    def generate_from_last_scan() -> bool:
        Returns: True if report generated successfully
"""

from shadow.reports.terminal_report import TerminalReport
from shadow.reports.json_report import JSONReport
from shadow.reports.html_report import HTMLReport

__all__ = [
    "TerminalReport",
    "JSONReport",
    "HTMLReport",
]