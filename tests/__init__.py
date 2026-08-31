#!/usr/bin/env python3
"""
Shadow Tests Package
====================

Test suite for Shadow Linux Hardening Tool.

Test categories:
- Unit tests: Individual module tests
- Integration tests: Module interaction tests
- System tests: Full system tests
- Kali tests: Tests from attacker perspective
- Ubuntu tests: Tests from target perspective

Run tests:
    python3 -m pytest tests/
    python3 -m unittest discover tests/
    python3 -m pytest tests/ -v --cov=shadow --cov-report=html

Test Configuration:
    - Test timeout: 300 seconds
    - Parallel workers: 4
    - Coverage threshold: 80%
"""

import os
import sys
import subprocess
from pathlib import Path

# ============================================================
# VERSION
# ============================================================
__version__ = "1.0.0"
__author__ = "Vijay"
__license__ = "MIT"

# Test package metadata
PACKAGE_INFO = {
    'name': 'shadow-tests',
    'version': __version__,
    'author': __author__,
    'license': __license__,
    'description': 'Test suite for Shadow Linux Hardening Tool'
}

# Test configuration
TEST_CONFIG = {
    'timeout': 300,
    'parallel': 4,
    'coverage_threshold': 80,
    'test_dirs': ['kali_tests', 'ubuntu_tests'],
    'exclude_patterns': ['*.pyc', '__pycache__', '.pytest_cache']
}

# ============================================================
# HELPERS
# ============================================================
def get_project_root() -> Path:
    """Get the project root directory."""
    return Path(__file__).parent.parent.parent


def is_root() -> bool:
    """Check if running as root."""
    return os.geteuid() == 0


def check_pytest_available() -> bool:
    """Check if pytest is installed."""
    try:
        import importlib
        importlib.import_module('pytest')
        return True
    except ImportError:
        return False


# ============================================================
# TEST RUNNER HELPER
# ============================================================
def run_all_tests(verbose: bool = False, coverage: bool = False):
    """
    Run all tests with optional coverage.
    
    Args:
        verbose: Enable verbose output
        coverage: Enable coverage reporting
    
    Returns:
        int: Exit code (0 for success)
    """
    # Check if pytest is available
    if not check_pytest_available():
        print("❌ pytest not installed. Install with: pip install pytest pytest-cov")
        return 1
    
    # Get project root
    project_root = get_project_root()
    tests_dir = project_root / "tests"
    
    if not tests_dir.exists():
        print(f"❌ Tests directory not found: {tests_dir}")
        return 1
    
    cmd = ['python3', '-m', 'pytest', str(tests_dir)]
    
    if verbose:
        cmd.append('-v')
    
    if coverage:
        cmd.extend(['--cov=shadow', '--cov-report=html', '--cov-report=term'])
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        
        if result.returncode == 0:
            print("✅ All tests passed!")
        else:
            print("❌ Some tests failed:")
            print(result.stdout)
            if result.stderr:
                print(result.stderr)
        
        return result.returncode
    except subprocess.TimeoutExpired:
        print("❌ Tests timed out after 300 seconds")
        return 1
    except Exception as e:
        print(f"❌ Error running tests: {e}")
        return 1


def run_kali_tests(verbose: bool = False):
    """Run Kali-specific tests."""
    if not check_pytest_available():
        print("❌ pytest not installed. Install with: pip install pytest")
        return 1
    
    project_root = get_project_root()
    tests_dir = project_root / "tests" / "kali_tests"
    
    if not tests_dir.exists():
        print(f"❌ Kali tests directory not found: {tests_dir}")
        return 1
    
    cmd = ['python3', '-m', 'pytest', str(tests_dir)]
    if verbose:
        cmd.append('-v')
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        print(result.stdout)
        if result.stderr:
            print(result.stderr)
        return result.returncode
    except subprocess.TimeoutExpired:
        print("❌ Kali tests timed out after 300 seconds")
        return 1


def run_ubuntu_tests(verbose: bool = False):
    """Run Ubuntu-specific tests."""
    if not check_pytest_available():
        print("❌ pytest not installed. Install with: pip install pytest")
        return 1
    
    project_root = get_project_root()
    tests_dir = project_root / "tests" / "ubuntu_tests"
    
    if not tests_dir.exists():
        print(f"❌ Ubuntu tests directory not found: {tests_dir}")
        return 1
    
    cmd = ['python3', '-m', 'pytest', str(tests_dir)]
    if verbose:
        cmd.append('-v')
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        print(result.stdout)
        if result.stderr:
            print(result.stderr)
        return result.returncode
    except subprocess.TimeoutExpired:
        print("❌ Ubuntu tests timed out after 300 seconds")
        return 1


def list_tests():
    """List all available tests."""
    if not check_pytest_available():
        print("❌ pytest not installed. Install with: pip install pytest")
        return 1
    
    project_root = get_project_root()
    tests_dir = project_root / "tests"
    
    if not tests_dir.exists():
        print(f"❌ Tests directory not found: {tests_dir}")
        return 1
    
    cmd = ['python3', '-m', 'pytest', '--collect-only', str(tests_dir)]
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        print(result.stdout)
        if result.stderr:
            print(result.stderr)
        return result.returncode
    except Exception as e:
        print(f"❌ Error listing tests: {e}")
        return 1


# ============================================================
# MAIN ENTRY POINT
# ============================================================
if __name__ == '__main__':
    import argparse
    
    parser = argparse.ArgumentParser(description='Run Shadow tests')
    parser.add_argument('--all', action='store_true', help='Run all tests')
    parser.add_argument('--kali', action='store_true', help='Run Kali tests')
    parser.add_argument('--ubuntu', action='store_true', help='Run Ubuntu tests')
    parser.add_argument('--coverage', action='store_true', help='Enable coverage')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    parser.add_argument('--list', action='store_true', help='List all available tests')
    
    args = parser.parse_args()
    
    if args.list:
        sys.exit(list_tests())
    elif args.all or not (args.kali or args.ubuntu):
        sys.exit(run_all_tests(args.verbose, args.coverage))
    elif args.kali:
        sys.exit(run_kali_tests(args.verbose))
    elif args.ubuntu:
        sys.exit(run_ubuntu_tests(args.verbose))


__all__ = [
    "kali_tests",
    "ubuntu_tests",
    "run_all_tests",
    "run_kali_tests",
    "run_ubuntu_tests",
    "list_tests",
    "check_pytest_available",
    "get_project_root",
    "is_root",
    "PACKAGE_INFO",
    "TEST_CONFIG",
    "__version__",
]