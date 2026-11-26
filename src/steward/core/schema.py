"""Write the JSON schema of the configuration: python -m steward.core.schema"""

from __future__ import annotations

import json
from pathlib import Path

from .config import SCHEMA_VERSION, Config

TARGET = Path(__file__).resolve().parents[3] / "schemas" / f"config.v{SCHEMA_VERSION}.schema.json"


def render() -> str:
    return json.dumps(Config.model_json_schema(), indent=2, sort_keys=True) + "\n"


if __name__ == "__main__":
    TARGET.write_text(render())
    print(f"wrote {TARGET}")
