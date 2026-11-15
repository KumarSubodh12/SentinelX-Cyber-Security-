"""Agent entry point:  python -m sentinelx_agent --config agent.env"""

from __future__ import annotations

import argparse
import logging
import os
import platform
import signal
import sys
import threading
from typing import Optional

from . import __version__
from .collectors.base import Collector, OffsetState
from .collectors.firewall import FirewallCollector
from .collectors.linux_auth import AuthFileCollector, JournaldCollector, find_auth_log
from .collectors.web_access import WebAccessCollector
from .config import AgentConfig, ConfigError, load
from .shipper import Shipper

log = logging.getLogger("sentinelx.agent")


def build_collectors(cfg: AgentConfig, state: OffsetState) -> list[Collector]:
    collectors: list[Collector] = []
    system = platform.system()

    if system == "Windows":
        if cfg.windows_security:
            from .collectors.windows_security import WindowsSecurityCollector

            collectors.append(WindowsSecurityCollector(state, cfg.windows_poll_seconds, cfg.windows_logon_types))
    elif cfg.linux_auth_mode != "off":
        path = cfg.linux_auth_log or (find_auth_log() if cfg.linux_auth_mode in ("auto", "file") else None)
        if cfg.linux_auth_mode == "journald" or (path is None and cfg.linux_auth_mode == "auto"):
            collectors.append(JournaldCollector(state, cfg.hostname))
        elif path:
            collectors.append(AuthFileCollector(path, state, cfg.hostname, cfg.backfill_lines))
        else:
            log.warning("no auth log found; set LINUX_AUTH_LOG or LINUX_AUTH_MODE=journald")

    for path in cfg.web_access_logs:
        collectors.append(WebAccessCollector(path, state, cfg.hostname, cfg.web_login_paths, cfg.backfill_lines))
    for path in cfg.firewall_logs:
        collectors.append(FirewallCollector(path, state, cfg.hostname, cfg.firewall_markers, cfg.backfill_lines))
    return collectors


def check(cfg: AgentConfig, collectors: list[Collector]) -> int:
    """Connectivity self-test used during installation."""
    shipper = Shipper(cfg)
    print(f"SentinelX agent {__version__} on {cfg.hostname} ({platform.system()})")
    print(f"Server: {cfg.url}")
    ok = shipper.heartbeat()
    print("Heartbeat:", "OK - the server accepted this agent's key" if ok else "FAILED - check the URL, API key and network")
    print("Collectors:")
    for c in collectors:
        print(f"  - {c.name}")
    if not collectors:
        print("  (none enabled - configure at least one log source)")
    return 0 if ok else 1


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="sentinelx-agent", description="SentinelX log collection agent")
    parser.add_argument("--config", help="path to a KEY=VALUE configuration file")
    parser.add_argument("--check", action="store_true", help="test the connection and list enabled collectors, then exit")
    parser.add_argument("--verbose", "-v", action="store_true")
    parser.add_argument("--version", action="version", version=__version__)
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    logging.getLogger("urllib3").setLevel(logging.WARNING)

    try:
        cfg = load(args.config)
    except (ConfigError, OSError) as exc:
        print(f"Configuration error: {exc}", file=sys.stderr)
        return 2

    os.makedirs(cfg.state_dir, exist_ok=True)
    state = OffsetState(os.path.join(cfg.state_dir, "offsets.json"))
    collectors = build_collectors(cfg, state)

    if args.check:
        return check(cfg, collectors)
    if not collectors:
        print("No log sources are enabled. Edit your configuration (see agent.env.example).", file=sys.stderr)
        return 2

    stop = threading.Event()

    def _shutdown(signum: int, _frame: object) -> None:
        log.info("received signal %s, shutting down", signum)
        stop.set()

    signal.signal(signal.SIGINT, _shutdown)
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, _shutdown)

    shipper = Shipper(cfg)
    threads = [threading.Thread(target=shipper.heartbeat_loop, args=(stop,), name="heartbeat", daemon=True)]
    for c in collectors:
        threads.append(threading.Thread(target=c.run, args=(shipper.emit, stop), name=c.name, daemon=True))
    for t in threads:
        t.start()
    log.info("agent started: %d collector(s) -> %s", len(collectors), cfg.url)

    # The shipper runs on the main thread so Ctrl+C / SIGTERM flush the queue cleanly.
    shipper.run(stop)
    log.info("agent stopped (sent %d events)", shipper.sent)
    return 0


if __name__ == "__main__":
    sys.exit(main())
