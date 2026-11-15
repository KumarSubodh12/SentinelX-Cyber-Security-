"""Optional webhook notifications (Slack, Discord, Teams or any JSON endpoint)."""

from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor
from typing import Any

import requests

log = logging.getLogger("sentinelx.notify")
_pool = ThreadPoolExecutor(max_workers=2, thread_name_prefix="notify")


def _post(url: str, alert: dict[str, Any]) -> None:
    text = (
        f"[SentinelX] {str(alert.get('severity', '')).upper()} - {alert.get('title')}\n"
        f"Risk {alert.get('risk_score')}/100"
        + (f" | Source {alert['source_ip']}" if alert.get("source_ip") else "")
        + (f" | Host {alert['hostname']}" if alert.get("hostname") else "")
    )
    # `text` is read by Slack/Teams, `content` by Discord; `alert` carries the full record for custom receivers.
    payload = {"text": text, "content": text, "alert": alert}
    try:
        requests.post(url, json=payload, timeout=5).raise_for_status()
    except requests.RequestException as exc:
        log.warning("webhook delivery failed: %s", exc)


def notify_async(url: str, alert: dict[str, Any]) -> None:
    if url:
        _pool.submit(_post, url, alert)
