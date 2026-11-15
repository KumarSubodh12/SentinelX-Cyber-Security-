"""Linux authentication logs: /var/log/auth.log (Debian/Ubuntu), /var/log/secure (RHEL) or journald.

Only security-relevant lines are turned into events. Noise is skipped on purpose,
and duplicate-prone lines (for example the PAM line that accompanies every sshd
"Failed password" line) are ignored so one attempt is counted once.
"""

from __future__ import annotations

import json
import logging
import os
import re
import shutil
import subprocess
import threading
from datetime import datetime, timezone, tzinfo
from typing import Any, Optional

from .base import Collector, Emit, FileTailer, OffsetState, PollingCollector, clean_ip, split_syslog_prefix

log = logging.getLogger("sentinelx.agent.linux")

_PROG = re.compile(r"^(?P<prog>[\w\-./]+)(?:\[(?P<pid>\d+)\])?:\s+(?P<msg>.*)$")

_SSH_FAILED = re.compile(
    r"^Failed (?P<method>password|publickey|keyboard-interactive/pam|none) for (?:invalid user )?(?P<user>\S+) "
    r"from (?P<ip>\S+) port (?P<port>\d+)"
)
_SSH_ACCEPTED = re.compile(r"^Accepted (?P<method>\S+) for (?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)")
_SUDO_PAM_FAIL = re.compile(r"pam_unix\(sudo(?:-i)?:auth\): authentication failure;.*?\buser=(?P<user>\S+)")
_SUDO_NOT_ALLOWED = re.compile(r"^(?P<user>\S+)\s*: user NOT in sudoers")
_SUDO_RUN = re.compile(r"^(?P<user>\S+)\s*: .*?\bUSER=(?P<target>\S+)\s*;\s*COMMAND=(?P<cmd>.*)$")
_SU_FAILED = re.compile(r"^(?:FAILED SU|FAILED su) \(to (?P<target>\S+)\) (?P<user>\S+) on")
_USERADD = re.compile(r"new user: name=(?P<user>[^,\s]+)")
_USERMOD_GROUP = re.compile(r"add '(?P<user>[^']+)' to (?:shadow )?group '(?P<group>[^']+)'")
_GPASSWD = re.compile(r"user (?P<user>\S+) added by (?P<actor>\S+) to group (?P<group>\S+)")


def _event(ts: datetime, host: Optional[str], event_type: str, message: str, **kw: Any) -> dict[str, Any]:
    event: dict[str, Any] = {
        "timestamp": ts.isoformat(),
        "source": "linux_auth",
        "event_type": event_type,
        "hostname": host,
        "message": message[:300],
    }
    event.update({k: v for k, v in kw.items() if v is not None})
    return event


def parse_auth_message(prog: str, msg: str, ts: datetime, host: Optional[str]) -> Optional[dict[str, Any]]:
    """Turn one (program, message) pair into an event dict, or None when it is not interesting."""
    prog = prog.lower()

    if prog in ("sshd", "sshd-session"):
        m = _SSH_FAILED.match(msg)
        if m:
            return _event(
                ts, host, "login_failed", f"SSH {m['method']} login failed for {m['user']}",
                username=m["user"], source_ip=clean_ip(m["ip"]), extra={"method": m["method"], "port": int(m["port"])},
            )
        m = _SSH_ACCEPTED.match(msg)
        if m:
            return _event(
                ts, host, "login_success", f"SSH {m['method']} login accepted for {m['user']}",
                username=m["user"], source_ip=clean_ip(m["ip"]), extra={"method": m["method"], "port": int(m["port"])},
            )
        return None

    if prog == "sudo":
        m = _SUDO_PAM_FAIL.search(msg)
        if m:
            return _event(ts, host, "privilege_escalation_failed", f"sudo authentication failure for {m['user']}", username=m["user"])
        m = _SUDO_NOT_ALLOWED.match(msg)
        if m:
            return _event(ts, host, "privilege_escalation_failed", f"{m['user']} is not in the sudoers file", username=m["user"])
        m = _SUDO_RUN.match(msg)
        if m:
            binary = m["cmd"].strip().split(" ", 1)[0]  # never ship arguments: they may contain secrets
            return _event(
                ts, host, "privilege_escalation", f"sudo by {m['user']} as {m['target']}: {binary}",
                username=m["user"], extra={"target_user": m["target"], "command": binary[:120]},
            )
        return None

    if prog == "su":
        m = _SU_FAILED.match(msg)
        if m:
            return _event(ts, host, "privilege_escalation_failed", f"su to {m['target']} failed for {m['user']}", username=m["user"])
        return None

    if prog in ("useradd", "adduser"):
        m = _USERADD.search(msg)
        if m:
            return _event(ts, host, "account_created", f"User account {m['user']} created", username=m["user"])
        return None

    if prog == "usermod":
        m = _USERMOD_GROUP.search(msg)
        if m:
            return _event(
                ts, host, "privilege_group_change", f"{m['user']} added to group {m['group']}",
                username=m["user"], extra={"group_name": m["group"]},
            )
        return None

    if prog == "gpasswd":
        m = _GPASSWD.search(msg)
        if m:
            return _event(
                ts, host, "privilege_group_change", f"{m['user']} added to group {m['group']} by {m['actor']}",
                username=m["user"], extra={"group_name": m["group"], "subject_user": m["actor"]},
            )
        return None

    return None


def parse_auth_line(
    line: str, tz: Optional[tzinfo] = None, now: Optional[datetime] = None
) -> Optional[dict[str, Any]]:
    split = split_syslog_prefix(line, now=now, tz=tz)
    if not split:
        return None
    ts, host, rest = split
    m = _PROG.match(rest)
    if not m:
        return None
    return parse_auth_message(m["prog"], m["msg"], ts, host)


def find_auth_log() -> Optional[str]:
    for path in ("/var/log/auth.log", "/var/log/secure"):
        if os.path.exists(path):
            return path
    return None


class AuthFileCollector(PollingCollector):
    name = "linux-auth-file"
    interval = 1.0

    def __init__(self, path: str, state: OffsetState, hostname: str, backfill_lines: int = 0) -> None:
        self.path = path
        self.hostname = hostname
        self.tailer = FileTailer(path, state, backfill_lines)

    def poll(self) -> list[dict[str, Any]]:
        events = []
        for line, ref in self.tailer.poll():
            event = parse_auth_line(line)
            if event:
                event["ref"] = ref
                event["hostname"] = event.get("hostname") or self.hostname
                events.append(event)
        return events


class JournaldCollector(Collector):
    """Follows the auth facilities of the systemd journal (for hosts without /var/log/auth.log)."""

    name = "linux-auth-journald"

    def __init__(self, state: OffsetState, hostname: str) -> None:
        self.state = state
        self.hostname = hostname
        self._key = "journald:cursor"

    def _command(self) -> list[str]:
        cmd = ["journalctl", "-o", "json", "-f", "SYSLOG_FACILITY=4", "SYSLOG_FACILITY=10"]
        cursor = self.state.get(self._key)
        return cmd[:4] + (["--after-cursor", cursor] if cursor else ["-n", "0"]) + cmd[4:]

    def run(self, emit: Emit, stop: threading.Event) -> None:
        if not shutil.which("journalctl"):
            log.error("journalctl not found; cannot collect journald auth events")
            return
        backoff = 2.0
        while not stop.is_set():
            proc = subprocess.Popen(self._command(), stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, bufsize=1)
            log.info("%s: following the systemd journal", self.name)
            try:
                assert proc.stdout is not None
                for raw in proc.stdout:
                    if stop.is_set():
                        break
                    try:
                        entry = json.loads(raw)
                    except ValueError:
                        continue
                    ts = datetime.fromtimestamp(int(entry.get("__REALTIME_TIMESTAMP", "0")) / 1_000_000, tz=timezone.utc)
                    prog = str(entry.get("SYSLOG_IDENTIFIER", ""))
                    message = entry.get("MESSAGE", "")
                    if isinstance(message, str):
                        event = parse_auth_message(prog, message, ts, entry.get("_HOSTNAME") or self.hostname)
                        if event:
                            event["ref"] = f"journal:{entry.get('__CURSOR', ts.timestamp())}"
                            emit(event)
                    if entry.get("__CURSOR"):
                        self.state.set(self._key, entry["__CURSOR"])
                    backoff = 2.0
            finally:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
            if not stop.is_set():
                log.warning("%s: journalctl exited, restarting in %.0fs", self.name, backoff)
                stop.wait(backoff)
                backoff = min(60.0, backoff * 2)
