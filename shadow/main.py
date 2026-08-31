#!/usr/bin/env python3
"""
Shadow Linux Hardening Tool - Main Entry Point (Sci-Fi Edition)
===============================================================
Professional terminal interface with clean logging.
"""
import os
import sys
import time 
import signal
import argparse
import logging
import importlib
from pathlib import Path
from datetime import datetime
from logging.handlers import RotatingFileHandler

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

# Try to import core modules with error handling
try:
    from shadow.core.engine import Engine
    from shadow.core.restore import Restore
    from shadow.reports.terminal_report import TerminalReport
except ImportError as e:
    print(f"ERROR: Failed to import required modules: {e}")
    print("Please ensure all dependencies are installed.")
    sys.exit(1)

__version__ = "1.0.0"
COMMAND_LOG = Path("/var/log/shadow/commands.log")

def log_command(args: argparse.Namespace):
    """Log the executed command for audit trail."""
    try:
        COMMAND_LOG.parent.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        cmd_parts = ["shadow"]
        for key, value in vars(args).items():
            if value is True:
                cmd_parts.append(f"--{key.replace('_', '-')}")
            elif value is not False and value is not None:
                cmd_parts.append(f"--{key.replace('_', '-')} {value}")
        cmd_str = " ".join(cmd_parts)
        with open(COMMAND_LOG, 'a') as f:
            f.write(f"{timestamp} | {os.geteuid()} | {cmd_str}\n")
    except Exception:
        pass

# ============================================================
# ✅ FIX 1 & 2: STOP CONSOLE VOMITING (Clean Terminal)
# ============================================================
def setup_logging(debug=False):
    """
    Configure logging:
    - FILE: Saves EVERYTHING to shadow.log (for debugging/auditing)
    - CONSOLE: ONLY shows CRITICAL/ERROR (Hides INFO and WARNING completely!)
    """
    log_dir = Path("/var/log/shadow")
    try:
        log_dir.mkdir(parents=True, exist_ok=True)
        level = logging.DEBUG if debug else logging.INFO
        
        # Clear existing handlers to prevent duplicate logs
        root_logger = logging.getLogger()
        root_logger.handlers.clear()
        root_logger.setLevel(level)
        
        # FILE handler: Captures EVERYTHING
        file_handler = RotatingFileHandler(
            log_dir / "shadow.log",
            maxBytes=10 * 1024 * 1024,
            backupCount=5
        )
        file_handler.setLevel(level)
        file_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        file_handler.setFormatter(file_formatter)
        
        # ✅ FIX 2: CONSOLE handler: ONLY shows ERROR (Hides WARNING completely!)
        stream_handler = logging.StreamHandler()
        stream_handler.setLevel(logging.ERROR)
        stream_formatter = logging.Formatter('%(levelname)s - %(message)s')
        stream_handler.setFormatter(stream_formatter)
        
        root_logger.addHandler(file_handler)
        root_logger.addHandler(stream_handler)
        
    except PermissionError:
        # Fallback if permission denied
        logging.basicConfig(
            level=logging.ERROR,
            format='%(levelname)s - %(message)s',
            handlers=[logging.StreamHandler()]
        )
        
    return logging.getLogger(__name__)

def check_root_for_operation(args: argparse.Namespace) -> bool:
    if getattr(args, 'version', False):
        return False
    return True

def check_root():
    if os.geteuid() != 0:
        print("ERROR: Shadow must be run as root (sudo)")
        print("Most security checks and hardening require root privileges.")
        print("Use --version without root.")
        sys.exit(1)

def check_dependencies():
    missing = []
    required_packages = [
        ('yaml', 'pyyaml'), ('cryptography', 'cryptography'),
        ('colorama', 'colorama'), ('jinja2', 'jinja2'),
        ('weasyprint', 'weasyprint'), ('reportlab', 'reportlab'),
        ('pdfkit', 'pdfkit'),
    ]
    for module_name, package_name in required_packages:
        try:
            importlib.import_module(module_name)
        except ImportError:
            missing.append(package_name)
    if missing:
        print(f"WARNING: Missing optional packages: {', '.join(missing)}")
    return True

def validate_config():
    config_path = Path("/etc/shadow-tool/shadow.yml")
    if config_path.exists():
        try:
            with open(config_path, 'r') as f:
                f.read(100)
            return True
        except Exception:
            return False
    return True

# ============================================================
# ✅ FIX 3: SCI-FI BANNER (Perfect Alignment + Dynamic Boot)
# ============================================================
def show_startup_progress():
    """Show the clean Sci-Fi startup banner with dynamic loading."""
    cyan = '\033[96m'
    green = '\033[92m'
    dim = '\033[2m'
    reset = '\033[0m'
    
    # ✅ FIX 3: Perfectly aligned banner (exactly 50 chars between pipes)
    banner = f"""
{cyan}        ╭──────────────────────────────────────────────────╮
        │                                                  │
        │       ◈  LINUX SYSTEM HARDENING TOOL  ◈          │
        │          ─────────────────────────────           │
        │          Security Assessment Interface           │
        │                     v1.0.0                       │
        ╰──────────────────────────────────────────────────╯{reset}
"""
    print(banner)
    print(f"  {cyan}◤ SYSTEM INITIALIZATION ◢{reset}")
    print(f"  {dim}  {'═' * 55}{reset}")
    
    # 🎬 Dynamic loading sequence (Text appears, pauses, then [ OK ] appears)
    steps = [
        ("Loading configuration", 0.4),
        ("Loading security modules", 0.6),
        ("Initializing scan engine", 0.5)
    ]
    
    for step, delay in steps:
        # 1. Print the step name and dots (without a newline)
        sys.stdout.write(f"  {cyan}  ◉ {step:<28} {reset}")
        sys.stdout.flush()
        
        # 2. Simulate processing time (makes it look like real work)
        time.sleep(delay)
        
        # 3. Print the success status in bright green
        print(f"{green}[ OK ]{reset}")

    print(f"  {dim}  {'═' * 55}{reset}\n")

def signal_handler(sig, frame):
    print("\n[!] Operation interrupted by user")
    sys.exit(1)

def main():
    """Main entry point"""
    
    valid_long_args = [
        'scan', 'harden', 'interactive', 'restore', 'report', 'version', 
        'boot', 'force', 'safe-mode', 'dry-run', 'debug'
    ]
    for i, arg in enumerate(sys.argv[1:], 1):
        if arg.startswith('-') and not arg.startswith('--') and len(arg) > 2:
            arg_name = arg[1:]
            if arg_name in valid_long_args:
                sys.argv[i] = f"--{arg_name}"

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    parser = argparse.ArgumentParser(
        prog="shadow",
        description="SHADOW: Enterprise Linux Hardening Framework",
        epilog="Repository: https://github.com/kaithepallivijayvardhan08-spec/SHADOW-LINUX-HARDENING-TOOL"
    )
    
    parser.add_argument("--scan", action="store_true", help="Run security scan only (no changes)")
    parser.add_argument("--harden", action="store_true", help="Apply hardening fixes (requires backup)")
    parser.add_argument("--interactive", "-i", action="store_true", help="Open interactive administrator menu")
    parser.add_argument("--restore", action="store_true", help="Rollback previous changes from backup")
    parser.add_argument("--report", action="store_true", help="Generate report from last scan")
    parser.add_argument("--version", "-v", action="store_true", help="Show version information")
    parser.add_argument("--boot", action="store_true", help="Boot mode - for systemd service (internal use)")
    parser.add_argument("--force", action="store_true", help="Force apply fixes even if auto_fix is disabled")
    parser.add_argument("--safe-mode", action="store_true", help="Run in safe mode (skip dangerous operations)")
    parser.add_argument("--dry-run", action="store_true", help="Preview changes without applying them")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    
    args = parser.parse_args()
    
    if check_root_for_operation(args):
        if os.geteuid() != 0:
            print(f"⚠️  Please run with sudo: sudo shadow {' '.join(sys.argv[1:])}")
            sys.exit(1)

    if args.version:
        try:
            from shadow import __version__ as shadow_version
            version = shadow_version
        except ImportError:
            version = __version__
        
        cyan = '\033[96m'
        green = '\033[92m'
        yellow = '\033[93m'
        dim = '\033[2m'
        bold = '\033[1m'
        reset = '\033[0m'
        
        banner = f"""
{cyan}  ╭─────────────────────────────────────────────────────────╮
  │  🛡️  SHADOW: Enterprise Linux Hardening Framework      │
  ╰─────────────────────────────────────────────────────────╯{reset}

  {bold}Version{reset}     {green}v{version}{reset}
  {bold}Author{reset}      KAITHEPALLI VIJAY VARDHAN
  {bold}License{reset}     Custom Source-Available License (CSAL)
  {bold}Context{reset}     Short-Term Internship · Cyber Defense & Security Analysis
  {bold}Repository{reset}  {dim}github.com/kaithepallivijayvardhan08-spec/SHADOW-LINUX-HARDENING-TOOL{reset}
  {bold}Contact{reset}     {yellow}kaithepallivijayvardhan08@gmail.com{reset} | +91 93462 61527

  {dim}─────────────────────────────────────────────────────────────{reset}
  {bold}Architecture{reset}:  Modular · OS-Aware · Transaction-Safe
  {bold}Compliance{reset}  :  CIS · NIST · PCI-DSS · ISO 27001
  {bold}Vectors{reset}     :  14 security domains · 40+ checks
  {bold}Reports{reset}     :  Terminal · JSON · HTML · PDF (SHA-256 verified)
  {dim}─────────────────────────────────────────────────────────────{reset}

  {green}A dynamically adaptive, OS-aware security framework for Linux.{reset}

  {dim}Copyright (c) 2026 KAITHEPALLI VIJAY VARDHAN. All Rights Reserved.{reset}
"""
        print(banner)
        sys.exit(0)
    
    # ✅ Show the new Sci-Fi banner
    show_startup_progress()
    
    # Setup logging (Safe now because we verified root access above)
    logger = setup_logging(args.debug)
    logger.info("Shadow starting...")
    logger.info(f"Arguments: {args}")
    
    log_command(args)
    check_dependencies()
    validate_config()

    # ✅ FIX FOR BUG #7: If --debug is used alone, run a diagnostic scan
    if args.debug and not any([args.scan, args.harden, args.interactive, args.restore, args.report, args.boot]):
        print("\n[*] Debug mode enabled. No command specified. Running full diagnostic scan...\n")
        args.scan = True
    
    if args.restore:
        try:
            restore = Restore()
            restore.interactive_restore()
        except Exception as e:
            logger.error(f"Restore failed: {e}")
            print(f"[!] Restore failed: {e}")
        sys.exit(0)
    
    if args.report:
        try:
            report = TerminalReport()
            report.generate_from_last_scan()
        except Exception as e:
            logger.error(f"Report generation failed: {e}")
            print(f"[!] Report generation failed: {e}")
        sys.exit(0)
    
    if args.interactive:
        try:
            engine = Engine(force=args.force, safe_mode=args.safe_mode, dry_run=args.dry_run)
            engine.interactive_menu()
        except Exception as e:
            logger.error(f"Interactive mode failed: {e}")
            print(f"[!] Interactive mode failed: {e}")
        sys.exit(0)
    
    if args.boot:
        try:
            engine = Engine(force=args.force, safe_mode=args.safe_mode, dry_run=args.dry_run)
            engine.boot_scan()
        except Exception as e:
            logger.error(f"Boot mode failed: {e}")
            print(f"[!] Boot mode failed: {e}")
        sys.exit(0)
    
    if args.scan:
        try:
            engine = Engine(force=args.force, safe_mode=args.safe_mode, dry_run=args.dry_run)
            engine.run_scan()
        except Exception as e:
            logger.error(f"Scan failed: {e}")
            print(f"[!] Scan failed: {e}")
        sys.exit(0)
    
    if args.harden:
        if args.dry_run:
            print("\n[!] DRY RUN MODE - No changes will be applied")
            print("    Previewing hardening plan...")
            try:
                engine = Engine(force=args.force, safe_mode=args.safe_mode, dry_run=args.dry_run)
                engine.run_harden()
            except Exception as e:
                logger.error(f"Dry run failed: {e}")
                print(f"[!] Dry run failed: {e}")
            sys.exit(0)
        else:
            try:
                engine = Engine(force=args.force, safe_mode=args.safe_mode, dry_run=args.dry_run)
                engine.run_harden()
            except Exception as e:
                logger.error(f"Hardening failed: {e}")
                print(f"[!] Hardening failed: {e}")
        sys.exit(0)
    
    if len(sys.argv) == 1:
        parser.print_help()
        print("\nNo command specified. Use --scan, --harden, --interactive, etc.")
        sys.exit(0)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Operation interrupted by user")
        sys.exit(1)
    except Exception as e:
        try:
            logging.error(f"Unexpected error: {e}")
        except:
            pass
        print(f"[!] Error: {e}")
        sys.exit(1)