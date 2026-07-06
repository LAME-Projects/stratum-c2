#!/usr/bin/env python3
"""
Stratum C2 — WebGUI Server

Starts the FastAPI teamserver that serves the WebGUI and exposes the REST/WS API.

Usage:
    python3 stratum-server.py                    # start with default server.yml
    python3 stratum-server.py path/to/cfg.yml    # start with alternate config
"""

import sys

# ── dependency check ──────────────────────────────────────────────────────────
_missing = []
for _pkg, _name in [
    ("fastapi",      "fastapi"),
    ("uvicorn",      "uvicorn[standard]"),
    ("jose",         "python-jose[cryptography]"),
    ("yaml",         "pyyaml"),
    ("cryptography", "cryptography"),
    ("requests",     "requests"),
]:
    try:
        __import__(_pkg)
    except ImportError:
        _missing.append(_name)

if _missing:
    print(f"[X] Missing dependencies: {', '.join(_missing)}")
    print(f"    Run: pip install {' '.join(_missing)}")
    sys.exit(1)

# ─────────────────────────────────────────────────────────────────────────────

import argparse

if __name__ == "__main__":
    ap = argparse.ArgumentParser(
        description="Stratum C2 — WebGUI Server",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python3 stratum-server.py\n"
            "  python3 stratum-server.py /etc/stratum/server.yml\n"
        ),
    )
    ap.add_argument(
        "config",
        nargs="?",
        default="server.yml",
        metavar="CONFIG",
        help="Path to server.yml (default: server.yml)",
    )
    args = ap.parse_args()

    from server.main import run
    run(config_path=args.config)
