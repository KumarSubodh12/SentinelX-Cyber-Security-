"""Batching, retrying uploader with an on-disk spool for outages."""

from __future__ import annotations

import json
import logging
import os
import queue
import threading
from typing import Any, Optional

import requests

from . import __version__
from .config import AgentConfig

log = logging.getLogger("sentinelx.agent.shipper")

QUEUE_LIMIT = 50_000


class Spool:
    """JSON-lines file of batches that could not be delivered yet."""

    def __init__(self, path: str, max_bytes: int) -> None:
        self.path = path
        self.max_bytes = max_bytes
        self._lock = threading.Lock()
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)

    def append(self, batch: list[dict[str, Any]]) -> None:
        with self._lock:
            with open(self.path, "a", encoding="utf-8") as handle:
                handle.write(json.dumps(batch, separators=(",", ":")) + "\n")
            self._trim()

    def _trim(self) -> None:
        """Drop the oldest batches when the spool outgrows its budget."""
        try:
            if os.path.getsize(self.path) <= self.max_bytes:
                return
        except OSError:
            return
        batches = self._read()
        while batches and sum(len(json.dumps(b)) + 1 for b in batches) > self.max_bytes:
            dropped = batches.pop(0)
            log.warning("spool full: dropped %d oldest events", len(dropped))
        self._write(batches)

    def _read(self) -> list[list[dict[str, Any]]]:
        batches: list[list[dict[str, Any]]] = []
        try:
            with open(self.path, encoding="utf-8") as handle:
                for line in handle:
                    try:
                        batches.append(json.loads(line))
                    except ValueError:
                        continue
        except OSError:
            pass
        return batches

    def _write(self, batches: list[list[dict[str, Any]]]) -> None:
        if not batches:
            try:
                os.remove(self.path)
            except OSError:
                pass
            return
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as handle:
            for batch in batches:
                handle.write(json.dumps(batch, separators=(",", ":")) + "\n")
        os.replace(tmp, self.path)

    def read_all(self) -> list[list[dict[str, Any]]]:
        with self._lock:
            return self._read()

    def replace(self, batches: list[list[dict[str, Any]]]) -> None:
        with self._lock:
            self._write(batches)


class Shipper:
    def __init__(self, cfg: AgentConfig, session: Optional[requests.Session] = None) -> None:
        self.cfg = cfg
        self.queue: "queue.Queue[dict[str, Any]]" = queue.Queue(maxsize=QUEUE_LIMIT)
        self.spool = Spool(os.path.join(cfg.state_dir, "spool.jsonl"), cfg.spool_max_mb * 1024 * 1024)
        self.session = session or requests.Session()
        self.session.headers.update(
            {
                "X-Agent-Key": cfg.api_key,
                "Content-Type": "application/json",
                "User-Agent": f"sentinelx-agent/{__version__}",
            }
        )
        self.verify: Any = cfg.ca_bundle if cfg.ca_bundle else cfg.verify_tls
        self.sent = 0
        self.dropped = 0
        self.auth_failed = False

    # -- producers ---------------------------------------------------------- #
    def emit(self, event: dict[str, Any]) -> None:
        try:
            self.queue.put_nowait(event)
        except queue.Full:
            try:
                self.queue.get_nowait()  # drop the oldest to keep the freshest data
                self.queue.put_nowait(event)
            except (queue.Empty, queue.Full):
                pass
            self.dropped += 1

    # -- network -------------------------------------------------------------- #
    def _agent_info(self) -> dict[str, str]:
        return {"hostname": self.cfg.hostname, "os": self.cfg.os_name, "version": __version__}

    def send(self, batch: list[dict[str, Any]]) -> bool:
        """POST one batch. Returns True when the server stored (or already had) it."""
        if not batch:
            return True
        try:
            resp = self.session.post(
                f"{self.cfg.url}/api/ingest",
                json={"agent": self._agent_info(), "events": batch},
                timeout=(5, 30),
                verify=self.verify,
            )
        except requests.RequestException as exc:
            log.warning("could not reach SentinelX: %s", exc)
            return False

        if resp.status_code == 200:
            self.auth_failed = False
            self.sent += len(batch)
            return True
        if resp.status_code == 401:
            if not self.auth_failed:
                log.error("SentinelX rejected the API key (401). Check SENTINELX_API_KEY and that the agent is enabled.")
            self.auth_failed = True
            return False
        if resp.status_code == 413 and len(batch) > 1:
            mid = len(batch) // 2
            return self.send(batch[:mid]) and self.send(batch[mid:])
        if 400 <= resp.status_code < 500 and resp.status_code != 429:
            log.error("server rejected a batch (%s): %s - dropping %d events", resp.status_code, resp.text[:200], len(batch))
            return True  # retrying cannot help
        log.warning("server error %s, will retry", resp.status_code)
        return False

    def send_with_retry(self, batch: list[dict[str, Any]], stop: threading.Event, attempts: int = 3) -> bool:
        delay = 1.0
        for attempt in range(attempts):
            if self.send(batch):
                return True
            if attempt < attempts - 1 and not stop.wait(delay):
                delay = min(delay * 2, 15.0)
            else:
                break
        return False

    def drain_spool(self, stop: threading.Event) -> None:
        batches = self.spool.read_all()
        if not batches:
            return
        delivered = 0
        for batch in batches:
            if stop.is_set() or not self.send(batch):
                break
            delivered += 1
        if delivered:
            log.info("delivered %d spooled batch(es)", delivered)
            self.spool.replace(batches[delivered:])

    def heartbeat(self) -> bool:
        try:
            resp = self.session.post(
                f"{self.cfg.url}/api/agents/heartbeat",
                json={"agent": self._agent_info()},
                timeout=(5, 15),
                verify=self.verify,
            )
            return resp.status_code in (200, 204)
        except requests.RequestException:
            return False

    # -- loops ------------------------------------------------------------------- #
    def _collect_batch(self, stop: threading.Event) -> list[dict[str, Any]]:
        batch: list[dict[str, Any]] = []
        try:
            batch.append(self.queue.get(timeout=self.cfg.flush_interval))
        except queue.Empty:
            return batch
        while len(batch) < self.cfg.batch_size:
            try:
                batch.append(self.queue.get_nowait())
            except queue.Empty:
                break
        return batch

    def run(self, stop: threading.Event) -> None:
        while not stop.is_set():
            batch = self._collect_batch(stop)
            if batch:
                if self.send_with_retry(batch, stop):
                    self.drain_spool(stop)
                else:
                    self.spool.append(batch)
            else:
                self.drain_spool(stop)  # idle: use the quiet moment to catch up
        self.flush_on_exit()

    def flush_on_exit(self) -> None:
        """Send whatever is left; anything that cannot be sent is spooled for the next start."""
        leftover: list[dict[str, Any]] = []
        while True:
            try:
                leftover.append(self.queue.get_nowait())
            except queue.Empty:
                break
        for i in range(0, len(leftover), self.cfg.batch_size):
            chunk = leftover[i : i + self.cfg.batch_size]
            if not self.send(chunk):
                self.spool.append(chunk)

    def heartbeat_loop(self, stop: threading.Event) -> None:
        while not stop.is_set():
            self.heartbeat()
            stop.wait(self.cfg.heartbeat_interval)
