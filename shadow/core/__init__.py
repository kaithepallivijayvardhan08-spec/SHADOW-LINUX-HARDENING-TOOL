#!/usr/bin/env python3
"""
Shadow Core Module
==================

The brain of Shadow. Contains:
- Engine: Orchestrates all operations
- Scanner: Runs security modules
- RiskEngine: Calculates risk scores
- Hardener: Applies fixes
- Restore: Rollback changes

All core components are exposed for clean imports.
"""

from shadow.core.engine import Engine
from shadow.core.scanner import Scanner
from shadow.core.risk_engine import RiskEngine
from shadow.core.hardener import Hardener
from shadow.core.restore import Restore

__all__ = [
    "Engine",
    "Scanner",
    "RiskEngine",
    "Hardener",
    "Restore",
]