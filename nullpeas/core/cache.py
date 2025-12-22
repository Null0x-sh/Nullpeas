import json
from pathlib import Path

CACHE_DIR = Path("cache")
CACHE_FILE = CACHE_DIR / "state.json"


def save_state(state: dict) -> None:
    CACHE_DIR.mkdir(parents=True, exist_ok=True)

    data = {
        "schema_version": 1,
        "state": state,
    }

    with CACHE_FILE.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)