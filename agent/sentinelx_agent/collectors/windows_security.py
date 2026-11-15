"""Windows Security event log, read with the built-in `wevtutil` tool (no extra packages).

Run the agent as Administrator (or as an account in the "Event Log Readers" group).

Event IDs collected:
  4625 failed logon            -> login_failed
  4624 successful logon        -> login_success (interactive/network/RDP types only, no service noise)
  4740 account locked out      -> account_lockout
  4720 account created         -> account_created
  4728/4732/4756 group change  -> privilege_group_change
  1102 audit log cleared       -> audit_log_cleared
"""

from __future__ import annotations

import logging
import re
import subprocess
import sys
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from typing import Any, Optional

from .base import OffsetState, PollingCollector, clean_ip

log = logging.getLogger("sentinelx.agent.windows")

NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"
EVENT_IDS = (4625, 4624, 4740, 4720, 4728, 4732, 4756, 1102)
IGNORED_ACCOUNTS = re.compile(r"(\$$|^anonymous logon$|^system$|^local service$|^network service$|^dwm-\d+$|^umfd-\d+$)", re.I)
_TS_FRACTION = re.compile(r"(\.\d{6})\d+")
_CN = re.compile(r"CN=([^,]+)", re.I)


def _parse_time(text: str) -> datetime:
    text = _TS_FRACTION.sub(r"\1", text.replace("Z", "+00:00"))
    return datetime.fromisoformat(text).astimezone(timezone.utc)


def _data_map(root: ET.Element) -> dict[str, str]:
    """Merge <EventData><Data Name=..> and <UserData><Anything> fields into one dict."""
    values: dict[str, str] = {}
    for data in root.iter(f"{NS}Data"):
        name = data.get("Name")
        if name and data.text:
            values[name] = data.text.strip()
    user_data = root.find(f"{NS}UserData")
    if user_data is not None:
        for node in user_data.iter():
            tag = node.tag.split("}")[-1]
            if node.text and node.text.strip() and len(node) == 0:
                values.setdefault(tag, node.text.strip())
    return values


def parse_event(xml_text: str, logon_types: Optional[list[int]] = None) -> Optional[dict[str, Any]]:
    """Convert one <Event> XML document into an agent event, or None to skip it."""
    logon_types = logon_types or [2, 3, 7, 10, 11]
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return None
    system = root.find(f"{NS}System")
    if system is None:
        return None
    event_id_el = system.find(f"{NS}EventID")
    time_el = system.find(f"{NS}TimeCreated")
    record_el = system.find(f"{NS}EventRecordID")
    computer_el = system.find(f"{NS}Computer")
    if event_id_el is None or time_el is None or event_id_el.text is None:
        return None
    event_id = int(event_id_el.text)
    try:
        ts = _parse_time(time_el.get("SystemTime", ""))
    except ValueError:
        return None
    record = record_el.text if record_el is not None else None
    host = computer_el.text if computer_el is not None else None
    data = _data_map(root)

    base: dict[str, Any] = {
        "timestamp": ts.isoformat(),
        "source": "windows_security",
        "hostname": host,
        "ref": f"win:{record}" if record else None,
    }
    actor = data.get("SubjectUserName")

    if event_id == 4625:
        user = data.get("TargetUserName")
        base.update(
            event_type="login_failed",
            username=user,
            source_ip=clean_ip(data.get("IpAddress")),
            message=f"Failed logon for {user or 'unknown'} (type {data.get('LogonType', '?')})",
            extra={"logon_type": data.get("LogonType"), "status": data.get("Status"), "sub_status": data.get("SubStatus"), "workstation": data.get("WorkstationName")},
        )
    elif event_id == 4624:
        user = data.get("TargetUserName", "")
        try:
            logon_type = int(data.get("LogonType", "0"))
        except ValueError:
            logon_type = 0
        if logon_type not in logon_types or not user or IGNORED_ACCOUNTS.search(user):
            return None
        base.update(
            event_type="login_success",
            username=user,
            source_ip=clean_ip(data.get("IpAddress")),
            message=f"Successful logon for {user} (type {logon_type})",
            extra={"logon_type": logon_type, "workstation": data.get("WorkstationName")},
        )
    elif event_id == 4740:
        user = data.get("TargetUserName")
        base.update(
            event_type="account_lockout",
            username=user,
            message=f"Account {user or 'unknown'} was locked out",
            extra={"caller_computer": data.get("TargetDomainName")},
        )
    elif event_id == 4720:
        user = data.get("TargetUserName")
        base.update(
            event_type="account_created",
            username=user,
            message=f"User account {user or 'unknown'} was created",
            extra={"subject_user": actor},
        )
    elif event_id in (4728, 4732, 4756):
        group = data.get("TargetUserName")
        member = data.get("MemberName") or data.get("MemberSid") or ""
        cn = _CN.search(member)
        member_name = cn.group(1) if cn else member
        base.update(
            event_type="privilege_group_change",
            username=member_name or None,
            message=f"{member_name or 'A member'} was added to group {group or 'unknown'}",
            extra={"group_name": group, "subject_user": actor},
        )
    elif event_id == 1102:
        base.update(
            event_type="audit_log_cleared",
            username=actor,
            message="The audit log was cleared",
            extra={"subject_user": actor},
        )
    else:
        return None
    return {k: v for k, v in base.items() if v is not None}


def parse_events_output(output: str, logon_types: Optional[list[int]] = None) -> tuple[list[dict[str, Any]], int]:
    """Parse wevtutil's concatenated <Event> output. Returns (events, highest record id seen)."""
    chunks = re.findall(r"<Event\b.*?</Event>", output, flags=re.S)
    events: list[dict[str, Any]] = []
    highest = 0
    for chunk in chunks:
        match = re.search(r"<EventRecordID>(\d+)</EventRecordID>", chunk)
        if match:
            highest = max(highest, int(match.group(1)))
        event = parse_event(chunk, logon_types)
        if event:
            events.append(event)
    return events, highest


class WindowsSecurityCollector(PollingCollector):
    name = "windows-security"

    def __init__(self, state: OffsetState, poll_seconds: float = 5.0, logon_types: Optional[list[int]] = None) -> None:
        self.state = state
        self.interval = poll_seconds
        self.logon_types = logon_types
        self._key = "windows:last_record"
        self._warned = False

    @staticmethod
    def _run(args: list[str]) -> subprocess.CompletedProcess[str]:
        flags = getattr(subprocess, "CREATE_NO_WINDOW", 0) if sys.platform == "win32" else 0
        return subprocess.run(["wevtutil", *args], capture_output=True, text=True, timeout=45, creationflags=flags)

    def _latest_record(self) -> int:
        proc = self._run(["qe", "Security", "/c:1", "/rd:true", "/f:xml"])
        if proc.returncode != 0:
            self._explain(proc)
            return 0
        _, highest = parse_events_output(proc.stdout)
        return highest

    def _explain(self, proc: subprocess.CompletedProcess[str]) -> None:
        if not self._warned:
            self._warned = True
            hint = " Run the agent as Administrator." if proc.returncode == 5 or "denied" in proc.stderr.lower() else ""
            log.error("wevtutil failed (exit %s): %s.%s", proc.returncode, proc.stderr.strip()[:200], hint)

    def poll(self) -> list[dict[str, Any]]:
        last = self.state.get(self._key)
        if last is None:
            last = self._latest_record()  # first run: start from "now", do not replay history
            self.state.set(self._key, last)
            return []
        ids = " or ".join(f"EventID={i}" for i in EVENT_IDS)
        query = f"*[System[({ids}) and EventRecordID>{int(last)}]]"
        proc = self._run(["qe", "Security", f"/q:{query}", "/f:xml", "/c:500", "/rd:false"])
        if proc.returncode != 0:
            self._explain(proc)
            return []
        self._warned = False
        events, highest = parse_events_output(proc.stdout, self.logon_types)
        if highest > int(last):
            self.state.set(self._key, highest)
        return events
