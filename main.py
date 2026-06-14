from __future__ import annotations

import os
import sys
from pathlib import Path

# ── Python environment selection ───────────────────────────────────────────────
# Garak 0.15.0 is installed under Python 3.13.
# If the current interpreter does NOT have garak, re-launch with the one that does.
APP_ROOT = Path(__file__).resolve().parent

_PYTHON313 = Path(r"C:\Users\MSI PC\AppData\Local\Programs\Python\Python313\python.exe")

def _ensure_correct_python() -> None:
    """Re-exec under Python 3.13 if garak is not importable here."""
    try:
        import garak  # noqa: F401
    except ImportError:
        if _PYTHON313.exists() and Path(sys.executable).resolve() != _PYTHON313.resolve():
            print(f"  [INFO] Switching to Python 3.13 at {_PYTHON313} (has garak installed)")
            os.execv(str(_PYTHON313), [str(_PYTHON313)] + sys.argv)
        else:
            print("  [WARN] garak not importable. Scans will fail at preflight.")

_ensure_correct_python()

# Environment defaults for garak config/cache isolation
os.environ.setdefault("XDG_CONFIG_HOME", str(APP_ROOT / ".config"))
os.environ.setdefault("XDG_CACHE_HOME",  str(APP_ROOT / ".cache"))

# Point GARAK_PYTHON at Python313 so the subprocess also uses the right interpreter
_py313_str = str(_PYTHON313) if _PYTHON313.exists() else sys.executable
os.environ.setdefault("GARAK_PYTHON", _py313_str)

import uvicorn


def main() -> int:
    print(
        "\n"
        "+---------------------------------------------------------------------+\n"
        "|   Enterprise AI Model Supply-Chain Firewalled Gatekeeper  v2.1     |\n"
        "|   Garak 0.15.0  |  FastAPI + HTMX  |  Rogue HF Model Detection    |\n"
        "+---------------------------------------------------------------------+\n"
        f"  Python  : {sys.executable}\n"
        f"  Garak   : {_py313_str}\n"
        "  URL     : http://127.0.0.1:8000\n"
        "  API     : http://127.0.0.1:8000/docs\n"
        "  Health  : http://127.0.0.1:8000/health\n"
    )
    try:
        uvicorn.run(
            "app_backend:app",
            host="127.0.0.1",
            port=8000,
            reload=False,
            log_level="info",
        )
        return 0
    except KeyboardInterrupt:
        print("\n  [STOP] Enterprise Gatekeeper shutdown. Goodbye.\n")
        return 0
    except Exception as exc:                            # pragma: no cover
        print(f"\n  [ERROR] Fatal startup: {exc}\n")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
