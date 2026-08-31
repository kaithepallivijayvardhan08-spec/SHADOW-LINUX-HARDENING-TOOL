#!/usr/bin/env python3
"""
SHADOW Cyborg Display Module
=============================
A cyber-security themed, informative loading display for scan & harden.

DESIGN PRINCIPLES:
  • Beauty + Brains : looks like a security terminal AND explains real work.
  • Zero Risk       : every method is wrapped in try/except. If the display
                      fails for ANY reason, the actual scan/harden continues.
  • Additive        : this is a NEW file. It does not rewrite existing logic.
  • Honest          : no fake spinners. A line prints only when real work
                      starts or finishes. No time.sleep(), no \r tricks.
"""

import sys
import shutil
from typing import Optional


# ============================================================
# CYBORG COLOR PALETTE (matches shadow-fix.sh theme)
# ============================================================
class C:
    CYAN    = '\033[0;36m'
    GREEN   = '\033[0;32m'
    YELLOW  = '\033[1;33m'
    RED     = '\033[0;31m'
    MAGENTA = '\033[0;35m'
    BLUE    = '\033[0;34m'
    WHITE   = '\033[1;37m'
    DIM     = '\033[2m'
    BOLD    = '\033[1m'
    NC      = '\033[0m'


# ============================================================
# MODULE KNOWLEDGE BASE  (this is the "brains")
# ============================================================
# For every security module we store, in simple English:
#   • analyzes     -> what real work the module is doing right now
#   • neutralizes  -> what attack/threat this check protects against
# This turns the loading bar into a teaching tool, not just eye candy.
MODULE_INTEL = {
    'authentication': {
        'label': 'AUTHENTICATION',
        'analyzes': 'passwords · sudo rules · login lockout · user accounts',
        'neutralizes': 'brute-force · privilege escalation · account takeover',
    },
    'remote_access': {
        'label': 'REMOTE_ACCESS',
        'analyzes': 'SSH config · telnet · RDP / VNC exposure',
        'neutralizes': 'remote intrusion · plaintext credential sniffing',
    },
    'network': {
        'label': 'NETWORK',
        'analyzes': 'firewall · open ports · DNS · live connections',
        'neutralizes': 'unauthorized access · DNS poisoning · port abuse',
    },
    'file_security': {
        'label': 'FILE_SECURITY',
        'analyzes': 'file permissions · ownership · sensitive files',
        'neutralizes': 'tampering · sensitive data exposure',
    },
    'services': {
        'label': 'SERVICES',
        'analyzes': 'apache · nginx · mysql · docker · nfs',
        'neutralizes': 'service misconfiguration · container escape',
    },
    'storage': {
        'label': 'STORAGE',
        'analyzes': 'disk layout · LVM · encryption status',
        'neutralizes': 'data-at-rest theft · unencrypted volumes',
    },
    'monitoring': {
        'label': 'MONITORING',
        'analyzes': 'system logs · suspicious processes · malware traces',
        'neutralizes': 'blind spots · undetected intrusions',
    },
    'updates': {
        'label': 'UPDATES',
        'analyzes': 'outdated packages · package integrity',
        'neutralizes': 'known CVE exploitation',
    },
    'kernel': {
        'label': 'KERNEL',
        'analyzes': 'kernel version · sysctl hardening · loaded modules',
        'neutralizes': 'kernel exploits · weak sysctl settings',
    },
    'processes': {
        'label': 'PROCESSES',
        'analyzes': 'running processes · startup items · resource use',
        'neutralizes': 'malware · crypto-miners · rogue daemons',
    },
    'audit': {
        'label': 'AUDIT',
        'analyzes': 'auditd rules · system event logging',
        'neutralizes': 'missing forensic trail',
    },
    'access_control': {
        'label': 'ACCESS_CONTROL',
        'analyzes': 'SELinux · AppArmor · capabilities',
        'neutralizes': 'exploit blast-radius · privilege abuse',
    },
    'scheduled_tasks': {
        'label': 'SCHEDULED_TASKS',
        'analyzes': 'cron jobs · systemd timers · startup jobs',
        'neutralizes': 'persistence backdoors · hidden schedulers',
    },
    'integrity': {
        'label': 'INTEGRITY',
        'analyzes': 'file hashes · unauthorized changes',
        'neutralizes': 'rootkit tampering · silent file edits',
    },
}


# ============================================================
# THE CYBORG SCAN DISPLAY
# ============================================================
class CyborgScanDisplay:
    """
    Prints a clean, line-by-line 'security terminal' during a scan.

    SAFETY: every public method is wrapped in try/except. The display
    can NEVER crash or interrupt the real scan/harden operation.
    """

    def __init__(self):
        self.enabled = True
        try:
            # Only show fancy display on a real terminal.
            if not sys.stdout.isatty():
                self.enabled = False
            self.width = shutil.get_terminal_size((70, 20)).columns
            if self.width < 60:
                self.width = 60
        except Exception:
            self.enabled = False

    # ---------- small internal helpers ----------
    def _line(self, ch='═'):
        try:
            return f"  {C.CYAN}{ch * (self.width - 4)}{C.NC}"
        except Exception:
            return ""

    def _say(self, text):
        """Print one line. Never raises."""
        try:
            print(text)
            sys.stdout.flush()
        except Exception:
            pass

    # ---------- public API (all safe) ----------
    def start(self, total: int, mode: str = "SCAN"):
        """Print the opening banner."""
        try:
            if not self.enabled:
                return
            title = f"◈ SHADOW NEURAL {mode} v1.0"
            sub   = f"target: localhost  ·  vectors: {total}  ·  status: ACTIVE"
            self._say("")
            self._say(self._line('═'))
            self._say(f"  {C.BOLD}{C.CYAN}{title}{C.NC}")
            self._say(f"  {C.DIM}{sub}{C.NC}")
            self._say(self._line('═'))
            self._say("")
        except Exception:
            pass

    def module_begin(self, index: int, total: int, module_key: str):
        """Print the 'now analyzing' block when a module STARTS."""
        try:
            if not self.enabled:
                return
            intel = MODULE_INTEL.get(module_key, {})
            label = intel.get('label', module_key.upper())
            analyzes = intel.get('analyzes', 'system configuration')
            num = f"{index:02d}"
            tot = f"{total:02d}"

            self._say(f"  {C.BOLD}{C.WHITE}▸ VECTOR [{num}/{tot}] :: {label}{C.NC}")
            self._say(f"    {C.CYAN}⛨ analyzing  {C.NC}{C.DIM}: {analyzes}{C.NC}")
        except Exception:
            pass

    def module_result(self, index: int, module_key: str,
                      status: str = 'PASS', issues: int = 0):
        """
        Print the result line when a module FINISHES.
        status: 'PASS' | 'WARN' | 'FAIL'
        """
        try:
            if not self.enabled:
                return
            intel = MODULE_INTEL.get(module_key, {})
            neutralizes = intel.get('neutralizes', 'security weaknesses')

            # pick color + icon by real result
            if status == 'FAIL':
                icon, color, word = '✗', C.RED, f"{issues} critical"
            elif status == 'WARN':
                icon, color, word = '!', C.YELLOW, f"{issues} warning(s)"
            else:
                icon, color, word = '✓', C.GREEN, "secure"

            self._say(f"    {C.MAGENTA}⚠ neutralizes{C.NC}{C.DIM}: {neutralizes}{C.NC}")
            self._say(f"    {C.DIM}◉ result     {C.NC}{color}{icon} {word}{C.NC}")
            self._say("")
        except Exception:
            pass

    def finish(self, total_issues: int = 0, elapsed: float = 0.0):
        """Print the closing banner."""
        try:
            if not self.enabled:
                return
            self._say(self._line('═'))
            summary = f"✓ SCAN COMPLETE — {elapsed:.1f}s · {total_issues} findings"
            self._say(f"  {C.BOLD}{C.GREEN}{summary}{C.NC}")
            self._say(self._line('═'))
            self._say("")
        except Exception:
            pass


# ============================================================
# SINGLE SHARED INSTANCE (import and use anywhere)
# ============================================================
display = CyborgScanDisplay()