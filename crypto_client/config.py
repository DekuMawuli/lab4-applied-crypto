"""Loads server_ip/port/username from a local, gitignored config file so the
username never lands in the shared repo (spec section 11)."""
import json
from pathlib import Path


def load_config(path, fallback=None) -> dict:
    path = Path(path)
    if not path.exists() and fallback is not None:
        path = Path(fallback)
    if not path.exists():
        return {}
    return json.loads(path.read_text())
