#!/usr/bin/env python3
"""
Shadow Kali Tests
=================

Tests from the attacker perspective (Kali Linux).

These tests verify that Shadow properly detects and prevents
common attack vectors from Kali Linux:
- Port scanning detection
- SSH brute force detection
- Malware detection
- Privilege escalation detection
- Network attack detection

Run:
    python3 -m pytest tests/kali_tests/
"""

__all__ = []