# -*- coding: utf-8 -*-
# ------------------------------------------------------------------------------
#
#   Copyright 2026 Valory AG
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.
#
# ------------------------------------------------------------------------------

"""Run the pearl-connect agent server.

Started by the Pearl middleware as: <binary> --password <password>.

cwd is the deployment build dir (contains ethereum_private_key.txt); all other
configuration arrives via environment variables (see config.py).
"""

import argparse
import logging
import secrets
import sys
import threading
import time
from pathlib import Path

import uvicorn

from pearl_connect import workspace
from pearl_connect.activity import ActivityLog
from pearl_connect.config import AGENT_HTTP_PORT, BIND_HOST, load_config
from pearl_connect.guard import Guard
from pearl_connect.keystore import KeystoreError, load_account
from pearl_connect.server.app import create_app
from pearl_connect.settings import SETTINGS_FILE, SettingsStore, derive_mac_key
from pearl_connect.signer import Signer

LOG_FORMAT = "[%(asctime)s] [%(levelname)s] [agent] %(message)s"


def setup_logging(level: str = "info") -> logging.Logger:
    """Set up logging to log.txt in the SDK format."""
    handlers: list[logging.Handler] = [
        logging.FileHandler(Path.cwd() / "log.txt", encoding="utf-8"),
        logging.StreamHandler(),
    ]
    logging.basicConfig(
        level=getattr(logging, level.upper()), format=LOG_FORMAT, handlers=handlers
    )
    return logging.getLogger("agent")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse args."""
    parser = argparse.ArgumentParser(prog="pearl-connect")
    parser.add_argument("--password", required=True, help="keystore password")
    return parser.parse_args(argv)


def wait_and_launch(
    server: uvicorn.Server, store_path: Path, settings_store: SettingsStore
) -> None:
    """Launch Claude Code once the server reports startup complete.

    Runs in a background thread so the MCP endpoint is connectable the moment
    the session opens. The configured harness decides which Claude Code the
    workspace opens in (the other stays the fallback).
    """
    while not server.started and not server.should_exit:
        time.sleep(0.2)
    if server.started:
        workspace.launch_claude(store_path, harness=settings_store.load().harness)


def main(argv: list[str] | None = None) -> int:
    """Run the agent server; return the process exit code."""
    args = parse_args(argv)

    try:
        config = load_config()
    except ValueError as e:
        setup_logging().error("configuration error: %s", e)
        return 1

    logger = setup_logging(config.log_level)
    logger.info("pearl-connect starting")

    try:
        account = load_account(args.password)
    except KeystoreError as e:
        logger.error("keystore error: %s", e)
        return 1
    logger.info("agent EOA: %s", account.address)
    logger.info("configured chains: %s", sorted(config.chains) or "none")

    activity = ActivityLog(config.store_path)
    settings_store = SettingsStore(
        config.store_path / SETTINGS_FILE, derive_mac_key(account), activity
    )
    guard = Guard(settings_store, config)
    signer = Signer(account=account, config=config, activity=activity, guard=guard)
    logger.info("guardrail mode: %s", guard.mode())
    token = secrets.token_urlsafe(32)

    try:
        workspace.populate(config.store_path, token)
        logger.info("workspace populated at %s", config.store_path)
    except Exception:  # pylint: disable=broad-exception-caught
        logger.exception("workspace population failed; server will start anyway")

    activity.write_performance()

    app = create_app(
        signer=signer,
        config=config,
        activity=activity,
        token=token,
        guard=guard,
        settings_store=settings_store,
    )

    server = uvicorn.Server(
        uvicorn.Config(
            app,
            host=BIND_HOST,
            port=AGENT_HTTP_PORT,
            log_level=config.log_level,
            # Pearl polls /healthcheck every 5s; access logging would flood
            # log.txt with poll lines. Signing actions have their own audit
            # log. Enable request lines only when debugging.
            access_log=config.log_level == "debug",
        )
    )

    threading.Thread(
        target=wait_and_launch,
        args=(server, config.store_path, settings_store),
        daemon=True,
    ).start()

    logger.info("serving on http://%s:%s", BIND_HOST, AGENT_HTTP_PORT)
    server.run()  # handles SIGTERM/SIGINT itself
    logger.info("pearl-connect stopped")
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
