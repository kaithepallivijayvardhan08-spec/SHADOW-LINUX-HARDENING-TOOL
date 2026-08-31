import sys
import os
import logging
import subprocess
import termios

_FORCE_MODE = False
logger = logging.getLogger(__name__)

def set_force_mode(is_forced: bool):
    global _FORCE_MODE
    _FORCE_MODE = is_forced

def _restore_tty_state():
    """Restore terminal to cooked mode with echo enabled."""
    # Method 1: stty on the REAL controlling terminal (the key fix)
    try:
        subprocess.run(['stty', '--file=/dev/tty', 'sane'],
                       stdin=subprocess.DEVNULL,
                       stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL,
                       timeout=2)
        return True
    except Exception:
        pass
    # Method 2: direct termios on stdin (fallback)
    try:
        fd = sys.stdin.fileno()
        attrs = termios.tcgetattr(fd)
        attrs[3] |= (termios.ICANON | termios.ECHO)
        termios.tcsetattr(fd, termios.TCSANOW, attrs)
        return True
    except Exception:
        pass
    return False

def _drain_pending_input():
    """Clear stray keystrokes from the buffer."""
    try:
        fd = sys.stdin.fileno()
        if not os.isatty(fd):
            return
        import fcntl
        flags = fcntl.fcntl(fd, fcntl.F_GETFL)
        fcntl.fcntl(fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)
        try:
            os.read(fd, 100)
        except (OSError, BlockingIOError):
            pass
        finally:
            fcntl.fcntl(fd, fcntl.F_SETFL, flags)
    except Exception:
        pass

def prompt(message: str = "", raw: bool = False) -> str:
    """
    Get user input.
    raw=False (default): forces 'y'/'n'  -> used by the 65 hardening modules
    raw=True: returns EXACTLY what was typed -> used by restore menu (D/R/F/B)
    """
    global _FORCE_MODE

    # ✅ FIX 1: force mode MUST auto-approve ('y'), NOT decline
    if _FORCE_MODE:
        logger.debug(f"Force mode: auto-answering 'y' to: {message}")
        return 'y' if not raw else 'yes'

    # Not a real terminal -> safe default
    if not (hasattr(sys.stdin, 'fileno') and os.isatty(sys.stdin.fileno())):
        return 'n' if not raw else ''

    # Restore echo + clear ghost keys + clean line
    _restore_tty_state()
    _drain_pending_input()
    sys.stdout.write("\033[2K\r")
    sys.stdout.write("\033[0m")
    sys.stdout.flush()

    # ✅ FIX 2: raw mode returns exact typing; normal mode accepts 'y' AND 'yes'
    try:
        response = input(message).strip()
        if raw:
            return response
        lower = response.lower()
        if lower in ('y', 'yes'):
            return 'y'
        if lower in ('n', 'no', ''):
            return 'n'
        # ✅ FIX: Invalid input — warn the user, then treat as No (skip)
        print(f"\n[!] '{response}' is not valid. Enter y or n. Treating as No (skip).")
        return 'n'
    except (KeyboardInterrupt, EOFError):
        sys.stdout.write("\n")
        sys.stdout.flush()
        return 'n' if not raw else ''