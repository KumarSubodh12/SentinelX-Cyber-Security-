"""Agent configuration, read from environment variables and an optional KEY=VALUE file."""

from __future__ import annotations

import os
import platform
import socket
from dataclasses import dataclass, field
from typing import Mapping, Optional
from urllib.parse import urlparse

LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1"}
DEFAULT_LOGIN_PATHS = "/login,/signin,/api/login,/api/auth/login,/wp-login.php,/admin/login"


class ConfigError(ValueError):
    pass


def load_env_file(path: str) -> dict[str, str]:
    """Parse a simple KEY=VALUE file (comments with #, optional quotes)."""
    values: dict[str, str] = {}
    with open(path, encoding="utf-8") as handle:
        for raw in handle:
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            value = value.strip()
            if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
                value = value[1:-1]
            values[key.strip()] = value
    return values


def _bool(value: Optional[str], default: bool) -> bool:
    if value is None or value == "":
        return default
    return value.strip().lower() in ("1", "true", "yes", "on")


def _list(value: Optional[str]) -> list[str]:
    return [v.strip() for v in (value or "").split(",") if v.strip()]


@dataclass
class AgentConfig:
    url: str
    api_key: str
    hostname: str = field(default_factory=socket.gethostname)
    state_dir: str = "./state"
    verify_tls: bool = True
    ca_bundle: Optional[str] = None
    allow_insecure: bool = False

    batch_size: int = 100
    flush_interval: float = 2.0
    heartbeat_interval: float = 30.0
    spool_max_mb: int = 50
    backfill_lines: int = 0

    linux_auth_mode: str = "auto"  # auto | file | journald | off
    linux_auth_log: Optional[str] = None
    web_access_logs: list[str] = field(default_factory=list)
    web_login_paths: list[str] = field(default_factory=list)
    firewall_logs: list[str] = field(default_factory=list)
    firewall_markers: list[str] = field(default_factory=lambda: ["UFW BLOCK", "IPTABLES-DROP"])
    windows_security: bool = True
    windows_poll_seconds: float = 5.0
    windows_logon_types: list[int] = field(default_factory=lambda: [2, 3, 7, 10, 11])

    @property
    def os_name(self) -> str:
        return platform.system().lower() or "unknown"


def from_mapping(env: Mapping[str, str]) -> AgentConfig:
    url = (env.get("SENTINELX_URL") or "").strip().rstrip("/")
    key = (env.get("SENTINELX_API_KEY") or "").strip()
    if not url:
        raise ConfigError("SENTINELX_URL is required (for example https://sentinelx.example.com)")
    if not key:
        raise ConfigError("SENTINELX_API_KEY is required (create an agent in Settings > Agents)")

    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ConfigError("SENTINELX_URL must start with http:// or https://")
    allow_insecure = _bool(env.get("ALLOW_INSECURE"), False)
    if parsed.scheme == "http" and parsed.hostname not in LOCAL_HOSTS and not allow_insecure:
        raise ConfigError(
            "Refusing to send security logs over plain HTTP to a remote server. Use https:// "
            "(or set ALLOW_INSECURE=true for an isolated lab network)."
        )

    def num(name: str, default: float) -> float:
        try:
            return float(env.get(name) or default)
        except ValueError:
            raise ConfigError(f"{name} must be a number")

    return AgentConfig(
        url=url,
        api_key=key,
        hostname=(env.get("AGENT_HOSTNAME") or socket.gethostname()).strip(),
        state_dir=env.get("STATE_DIR") or "./state",
        verify_tls=_bool(env.get("VERIFY_TLS"), True),
        ca_bundle=env.get("SENTINELX_CA_BUNDLE") or None,
        allow_insecure=allow_insecure,
        batch_size=max(1, min(1000, int(num("BATCH_SIZE", 100)))),
        flush_interval=max(0.2, num("FLUSH_INTERVAL", 2.0)),
        heartbeat_interval=max(5.0, num("HEARTBEAT_INTERVAL", 30.0)),
        spool_max_mb=max(1, int(num("SPOOL_MAX_MB", 50))),
        backfill_lines=max(0, int(num("BACKFILL_LINES", 0))),
        linux_auth_mode=(env.get("LINUX_AUTH_MODE") or "auto").lower(),
        linux_auth_log=env.get("LINUX_AUTH_LOG") or None,
        web_access_logs=_list(env.get("WEB_ACCESS_LOGS")),
        web_login_paths=_list(env.get("WEB_LOGIN_PATHS") or DEFAULT_LOGIN_PATHS),
        firewall_logs=_list(env.get("FIREWALL_LOGS")),
        firewall_markers=_list(env.get("FIREWALL_MARKERS")) or ["UFW BLOCK", "IPTABLES-DROP"],
        windows_security=_bool(env.get("WINDOWS_SECURITY"), True),
        windows_poll_seconds=max(1.0, num("WINDOWS_POLL_SECONDS", 5.0)),
        windows_logon_types=[int(x) for x in _list(env.get("WINDOWS_LOGON_TYPES"))] or [2, 3, 7, 10, 11],
    )


def load(config_path: Optional[str] = None) -> AgentConfig:
    """Environment variables override values from the config file."""
    merged: dict[str, str] = {}
    if config_path:
        merged.update(load_env_file(config_path))
    merged.update(os.environ)
    return from_mapping(merged)
