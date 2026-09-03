"""
ShieldNet Section 2 Fix: Safe Terminal Encoding Guard.
Prevents UnicodeEncodeError: 'charmap' codec can't encode character crashes on Windows CP1252 consoles.
Automatically configures stdout/stderr to UTF-8 or sanitizes emojis to ASCII equivalents.
"""

import sys
import io

def enforce_safe_encoding():
    """Configures stdout/stderr to UTF-8 without crashing Windows cmd/powershell."""
    try:
        if sys.platform.startswith("win"):
            if hasattr(sys.stdout, "reconfigure"):
                sys.stdout.reconfigure(encoding="utf-8", errors="backslashreplace")
            if hasattr(sys.stderr, "reconfigure"):
                sys.stderr.reconfigure(encoding="utf-8", errors="backslashreplace")
    except Exception:
        pass

def safe_print(*args, **kwargs):
    """Clean print that replaces unencodable emojis with ASCII symbols."""
    text = " ".join(str(a) for a in args)
    try:
        print(text, **kwargs)
    except UnicodeEncodeError:
        # Strip or map common emojis
        cleaned = (
            text.replace("🔥", "[FIRE]")
                .replace("⚡", "[FAST]")
                .replace("✅", "[OK]")
                .replace("⚠️", "[WARN]")
                .replace("🔴", "[CRITICAL]")
                .replace("🟢", "[NORMAL]")
                .replace("🟡", "[ALERT]")
                .replace("★", "*")
        )
        print(cleaned.encode("ascii", errors="replace").decode("ascii"), **kwargs)

# Automatically invoke on import
enforce_safe_encoding()
