"""Collector base class, log-file tailing and shared parsing helpers."""

from __future__ import annotations

import json
import logging
import os
import re
import threading
from datetime import datetime, timedelta, timezone, tzinfo
from typing import Any, Callable, Optional

log = logging.getLogger("sentinelx.agent")

Emit = Callable[[dict[str, Any]], None]

MAX_READ_BYTES = 4 * 1024 * 1024
MAX_LINE_BYTES = 16 * 1024


class OffsetState:
    """Persists file offsets / cursors so a restart neither re-sends nor skips lines."""

    def __init__(self, path: str) -> None:
        self.path = path
        self._lock = threading.Lock()
        self._data: dict[str, Any] = {}
        try:
            with open(path, encoding="utf-8") as handle:
                self._data = json.load(handle)
        except (OSError, ValueError):
            self._data = {}

    def get(self, key: str) -> Optional[Any]:
        with self._lock:
            return self._data.get(key)

    def set(self, key: str, value: Any) -> None:
        with self._lock:
            if self._data.get(key) == value:
                return
            self._data[key] = value
            os.makedirs(os.path.dirname(os.path.abspath(self.path)), exist_ok=True)
            tmp = self.path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as handle:
                json.dump(self._data, handle)
            os.replace(tmp, self.path)


class FileTailer:
    """Follows a text log across rotation. Returns only complete lines."""

    def __init__(self, path: str, state: OffsetState, backfill_lines: int = 0) -> None:
        self.path = path
        self.state = state
        self.backfill_lines = backfill_lines
        self._key = f"file:{path}"

    def poll(self) -> list[tuple[str, str]]:
        """Return [(line, ref)] for lines written since the last poll."""
        try:
            st = os.stat(self.path)
        except OSError:
            return []
        saved = self.state.get(self._key)
        inode, size = st.st_ino, st.st_size

        if not saved:
            offset = self._initial_offset(size)
        else:
            offset = int(saved.get("offset", 0))
            if saved.get("inode") != inode or size < offset:  # rotated or truncated
                offset = 0

        if offset >= size:
            self.state.set(self._key, {"inode": inode, "offset": offset})
            return []

        try:
            with open(self.path, "rb") as handle:
                handle.seek(offset)
                chunk = handle.read(min(size - offset, MAX_READ_BYTES))
        except OSError as exc:
            log.warning("cannot read %s: %s", self.path, exc)
            return []

        lines: list[tuple[str, str]] = []
        position = offset
        consumed = 0
        for raw in chunk.splitlines(keepends=True):
            if not raw.endswith(b"\n"):
                break  # partial line, finish it on the next poll
            consumed += len(raw)
            text = raw[:MAX_LINE_BYTES].decode("utf-8", errors="replace").rstrip("\r\n")
            if text.strip():
                lines.append((text, f"{inode}:{position}"))
            position += len(raw)
        self.state.set(self._key, {"inode": inode, "offset": offset + consumed})
        return lines

    def _initial_offset(self, size: int) -> int:
        """First run: start at the end of the file, or N lines back when backfilling."""
        if self.backfill_lines <= 0:
            return size
        try:
            with open(self.path, "rb") as handle:
                start = max(0, size - 512 * 1024)
                handle.seek(start)
                data = handle.read()
        except OSError:
            return size
        pieces = data.splitlines(keepends=True)
        if start > 0 and pieces:
            pieces = pieces[1:]  # first piece is probably cut in half
        tail = pieces[-self.backfill_lines :]
        return size - sum(len(p) for p in tail)


class Collector:
    """Subclasses implement `run`, which blocks until `stop` is set."""

    name = "collector"

    def run(self, emit: Emit, stop: threading.Event) -> None:  # pragma: no cover - interface
        raise NotImplementedError


class PollingCollector(Collector):
    interval = 1.0

    def poll(self) -> list[dict[str, Any]]:  # pragma: no cover - interface
        raise NotImplementedError

    def run(self, emit: Emit, stop: threading.Event) -> None:
        while not stop.is_set():
            try:
                for event in self.poll():
                    emit(event)
            except Exception:
                log.exception("%s: poll failed", self.name)
            stop.wait(self.interval)


# --------------------------------------------------------------------------- #
# Shared parsing helpers
# --------------------------------------------------------------------------- #

MONTHS = {m: i for i, m in enumerate(["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], 1)}

_SYSLOG = re.compile(r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+(?P<rest>.*)$")
_ISO = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+(?P<host>\S+)\s+(?P<rest>.*)$"
)
_SENSITIVE = re.compile(r"(pass(word|wd)?|pwd|token|secret|api[_-]?key|auth|session|cookie|credential|otp)", re.I)


def local_tz() -> tzinfo:
    return datetime.now().astimezone().tzinfo or timezone.utc


def split_syslog_prefix(
    line: str, now: Optional[datetime] = None, tz: Optional[tzinfo] = None
) -> Optional[tuple[datetime, str, str]]:
    """Split a syslog line into (utc timestamp, hostname, remainder). Handles classic and ISO-8601 stamps."""
    now = now or datetime.now(timezone.utc)
    m = _ISO.match(line)
    if m:
        text = m.group("ts").replace(",", ".")
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        text = re.sub(r"([+-]\d{2})(\d{2})$", r"\1:\2", text)
        text = re.sub(r"(\.\d{6})\d+", r"\1", text)
        try:
            ts = datetime.fromisoformat(text)
        except ValueError:
            return None
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=tz or local_tz())
        return ts.astimezone(timezone.utc), m.group("host"), m.group("rest")

    m = _SYSLOG.match(line)
    if not m:
        return None
    month = MONTHS.get(m.group("mon"))
    if not month:
        return None
    hh, mm, ss = (int(x) for x in m.group("time").split(":"))
    zone = tz or local_tz()
    local_now = now.astimezone(zone)
    try:
        ts = datetime(local_now.year, month, int(m.group("day")), hh, mm, ss, tzinfo=zone)
    except ValueError:
        return None
    if ts > local_now + timedelta(days=1):  # December logs read in January
        ts = ts.replace(year=ts.year - 1)
    return ts.astimezone(timezone.utc), m.group("host"), m.group("rest")


def redact_query(path: str) -> str:
    """Hide values of sensitive query parameters before a request path leaves the host."""
    if "?" not in path:
        return path
    base, query = path.split("?", 1)
    out = []
    for chunk in query.split("&"):
        key, sep, _ = chunk.partition("=")
        out.append(f"{key}=[redacted]" if sep and _SENSITIVE.search(key) else chunk)
    return base + "?" + "&".join(out)


def clean_ip(value: Optional[str]) -> Optional[str]:
    if not value or value in ("-", "::1", "127.0.0.1", "0.0.0.0", "::"):
        return None
    return value.strip("[]")
