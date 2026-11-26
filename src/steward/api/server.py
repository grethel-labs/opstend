"""Entry point of the administration API (binds to loopback only)."""

from __future__ import annotations

import argparse
import sys

import uvicorn

from .app import Settings, StartupError, create_app


def main() -> None:
    parser = argparse.ArgumentParser(description="steward administration API")
    parser.add_argument("--port", type=int, default=9080)
    args = parser.parse_args()
    try:
        app = create_app(Settings.from_env())
    except StartupError as exc:
        # Fail closed: without a valid admin secret nothing is served.
        sys.exit(f"steward-api refuses to start: {exc}")
    uvicorn.run(
        app,
        host="127.0.0.1",
        port=args.port,
        log_level="warning",
        access_log=False,
        server_header=False,
        proxy_headers=False,
    )


if __name__ == "__main__":
    main()
