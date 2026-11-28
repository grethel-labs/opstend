"""`opstend` command line."""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys

from opstend import __version__


def _serve(args: argparse.Namespace, demo: bool) -> int:
    import uvicorn

    from opstend.api.app import build_app
    from opstend.config import Config
    from opstend.runtime import Runtime

    config = Config.load(args.config)
    rt = Runtime(config, demo=demo, demo_delay=args.demo_delay if demo else 0.6)
    host, _, port = (args.listen or config.listen.web).rpartition(":")
    ssl = {}
    if args.tls_cert and args.tls_key:
        ssl = {"ssl_certfile": args.tls_cert, "ssl_keyfile": args.tls_key}
    uvicorn.run(
        build_app(rt),
        host=host or "127.0.0.1",
        port=int(port),
        log_level="info",
        proxy_headers=False,
        server_header=False,
        timeout_graceful_shutdown=5,
        **ssl,
    )
    return 0


def _self_update(args: argparse.Namespace) -> int:
    from opstend import __version__
    from opstend.updates.selfupdate import Layout, SelfUpdater, UpdateError

    updater = SelfUpdater(Layout(), __version__)
    rel = updater.check(args.channel)
    if args.version and (rel is None or rel.version != args.version):
        print(f"version {args.version} is not available as a newer signed release")
        return 1
    if rel is None:
        print(f"opstend {__version__} is up to date")
        return 0
    if args.check:
        print(f"update available: {__version__} -> {rel.version}")
        return 0
    try:
        print(f"updated to {updater.apply(rel, args.health_url)}")
    except UpdateError as exc:
        print(f"update failed: {exc}")
        return 1
    return 0


def _check(args: argparse.Namespace) -> int:
    from opstend.config import Config

    config = Config.load(args.config)
    print(json.dumps(config.model_dump(), indent=2))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="opstend", description="OpsTend node")
    parser.add_argument("--version", action="version", version=f"opstend {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    serve = sub.add_parser("serve", help="run this node (web app, API, automation)")
    serve.add_argument("--config", default="/etc/opstend/opstend.yaml")
    serve.add_argument("--listen", help="host:port for the web app, overrides the config")
    serve.add_argument("--tls-cert")
    serve.add_argument("--tls-key")
    serve.add_argument("--demo", action="store_true", help="run with example data")
    serve.add_argument("--demo-delay", type=float, default=0.6)

    demo = sub.add_parser("demo", help="try OpsTend with example data on http://127.0.0.1:8080")
    demo.add_argument("--listen", default="127.0.0.1:8080")
    demo.add_argument("--config", default=None)
    demo.add_argument("--tls-cert")
    demo.add_argument("--tls-key")
    demo.add_argument("--demo-delay", type=float, default=0.6)

    sub.add_parser("agent", help="run the privileged host agent (root, Unix socket only)")

    upd = sub.add_parser("self-update", help="install a newer signed release (root)")
    upd.add_argument("--check", action="store_true", help="only report whether an update exists")
    upd.add_argument("--version", help="install exactly this version")
    upd.add_argument("--channel", default="stable", choices=["stable", "preview"])
    upd.add_argument("--health-url", default="https://127.0.0.1:8443/api/session")

    check = sub.add_parser("check-config", help="validate the configuration file")
    check.add_argument("--config", default="/etc/opstend/opstend.yaml")

    args = parser.parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if os.environ.get("OPSTEND_DEBUG") else logging.INFO,
        format="%(levelname)s %(name)s: %(message)s",
    )
    if args.command == "serve":
        return _serve(args, demo=args.demo)
    if args.command == "demo":
        return _serve(args, demo=True)
    if args.command == "agent":
        from opstend.agent import main as agent_main

        return agent_main()
    if args.command == "check-config":
        return _check(args)
    if args.command == "self-update":
        return _self_update(args)
    parser.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main())
