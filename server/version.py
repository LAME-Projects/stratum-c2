from pathlib import Path as _Path

_VERSION_FILE = _Path(__file__).resolve().parent.parent / "VERSION"

try:
    __version__ = _VERSION_FILE.read_text().strip()
except FileNotFoundError:
    __version__ = "0.0.0"
