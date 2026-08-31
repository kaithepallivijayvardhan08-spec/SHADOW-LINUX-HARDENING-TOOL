#!/usr/bin/env python3
"""
Shadow Linux Hardening Tool
==========================

A professional Linux security hardening framework.

Features:
- Boot-time security scanning (systemd oneshot)
- Interactive manual mode
- Full Linux hardening (authentication, network, services, storage, monitoring)
- 3 failed attempts → account lockout (PAM faillock)
- Backup before any change
- Multiple report formats (terminal, TXT, JSON, HTML)
- Modular architecture

Version: 1.0.0
Author: Vijay
License: MIT
"""

import logging

# Package metadata
__version__ = "1.0.0"
__author__ = "Vijay"
__license__ = "MIT"
__description__ = "Linux Security Hardening Framework"

# Package info dict
PACKAGE_INFO = {
    'name': 'shadow',
    'version': __version__,
    'author': __author__,
    'license': __license__,
    'description': __description__,
}

# ============================================================
# FIX 1: ERROR HANDLING FOR IMPORTS
# ============================================================
logger = logging.getLogger(__name__)

# Track import status
_import_status = {}

def _safe_import(module_path: str, attr_name: str):
    """
    Safely import a module attribute with error handling.
    Returns the attribute or None if import fails.
    """
    try:
        module = __import__(module_path, fromlist=[attr_name])
        return getattr(module, attr_name)
    except ImportError as e:
        logger.warning(f"Failed to import {module_path}.{attr_name}: {e}")
        _import_status[f"{module_path}.{attr_name}"] = f'failed: {e}'
        return None
    except AttributeError as e:
        logger.warning(f"Attribute {attr_name} not found in {module_path}: {e}")
        _import_status[f"{module_path}.{attr_name}"] = f'attribute error: {e}'
        return None
    except Exception as e:
        logger.error(f"Unexpected error importing {module_path}.{attr_name}: {e}")
        _import_status[f"{module_path}.{attr_name}"] = f'error: {e}'
        return None


# Expose main entry point
main = _safe_import('shadow.main', 'main')

# Expose core components
Engine = _safe_import('shadow.core.engine', 'Engine')
Scanner = _safe_import('shadow.core.scanner', 'Scanner')
RiskEngine = _safe_import('shadow.core.risk_engine', 'RiskEngine')
Hardener = _safe_import('shadow.core.hardener', 'Hardener')
Restore = _safe_import('shadow.core.restore', 'Restore')

# Expose report components
TerminalReport = _safe_import('shadow.reports.terminal_report', 'TerminalReport')
JSONReport = _safe_import('shadow.reports.json_report', 'JSONReport')
HTMLReport = _safe_import('shadow.reports.html_report', 'HTMLReport')

# Try to import PDFReport (optional dependency)
try:
    PDFReport = _safe_import('shadow.reports.pdf_report', 'PDFReport')
except:
    PDFReport = None

# ============================================================
# MEDIUM FIX 1: COMPLETE __all__
# ============================================================
__all__ = [
    # Core
    "main",
    "Engine",
    "Scanner",
    "RiskEngine",
    "Hardener",
    "Restore",
    # Reports
    "TerminalReport",
    "JSONReport",
    "HTMLReport",
    "PDFReport",
    # Metadata
    "__version__",
    "__author__",
    "__license__",
    "__description__",
    "PACKAGE_INFO",
]

# ============================================================
# OPTIONAL: UTILITY FUNCTIONS
# ============================================================
def get_version() -> str:
    """Get the package version."""
    return __version__

def get_info() -> dict:
    """Get package information."""
    return PACKAGE_INFO.copy()

def get_import_status() -> dict:
    """Get status of all imports."""
    return _import_status.copy()

def is_complete() -> bool:
    """Check if all core components imported successfully."""
    core_components = ['main', 'Engine', 'Scanner', 'RiskEngine', 'Hardener', 'Restore']
    for comp in core_components:
        if globals().get(comp) is None:
            return False
    return True

# Log import summary
_successful = [k for k, v in _import_status.items() if not v.startswith('failed')]
if _successful:
    logger.debug(f"Successfully imported {len(_successful)} components")