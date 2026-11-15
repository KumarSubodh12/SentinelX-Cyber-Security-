import json
import os
import threading
from datetime import datetime, timezone

import pytest

from sentinelx_agent.collectors.base import FileTailer, OffsetState, redact_query, split_syslog_prefix
from sentinelx_agent.collectors.firewall import parse_firewall_line
from sentinelx_agent.collectors.linux_auth import parse_auth_line
from sentinelx_agent.collectors.web_access import parse_access_line
from sentinelx_agent.collectors.windows_security import parse_events_output
from sentinelx_agent.config import ConfigError, from_mapping
from sentinelx_agent.shipper import Shipper

UTC = timezone.utc
NOW = datetime(2026, 11, 13, 12, 0, tzinfo=UTC)


# --------------------------------------------------------------------------- linux auth
def test_ssh_failed_password_classic_syslog():
    line = "Nov 13 10:15:01 web01 sshd[1234]: Failed password for invalid user admin from 203.0.113.9 port 51234 ssh2"
    e = parse_auth_line(line, tz=UTC, now=NOW)
    assert e["event_type"] == "login_failed" and e["username"] == "admin" and e["source_ip"] == "203.0.113.9"
    assert e["hostname"] == "web01" and e["timestamp"].startswith("2026-11-13T10:15:01")


def test_ssh_accepted_iso_timestamp_with_offset():
    line = "2026-11-13T15:45:01.123456+05:30 web01 sshd[99]: Accepted publickey for deploy from 198.51.100.4 port 40000 ssh2: RSA SHA256:abc"
    e = parse_auth_line(line)
    assert e["event_type"] == "login_success" and e["username"] == "deploy"
    assert e["timestamp"].startswith("2026-11-13T10:15:01")  # converted to UTC


def test_pam_duplicate_and_invalid_user_lines_are_ignored():
    assert parse_auth_line("Nov 13 10:15:01 h sshd[1]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=1.2.3.4  user=root", tz=UTC, now=NOW) is None
    assert parse_auth_line("Nov 13 10:15:01 h sshd[1]: Invalid user bob from 1.2.3.4 port 22", tz=UTC, now=NOW) is None


def test_sudo_events_never_include_arguments():
    ok = parse_auth_line("Nov 13 10:15:01 h sudo[5]: alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/mysql -u root -pSuperSecret", tz=UTC, now=NOW)
    assert ok["event_type"] == "privilege_escalation" and "SuperSecret" not in json.dumps(ok)
    bad = parse_auth_line("Nov 13 10:15:01 h sudo[5]: pam_unix(sudo:auth): authentication failure; logname=alice uid=1000 euid=0 tty=/dev/pts/0 ruser=alice rhost=  user=alice", tz=UTC, now=NOW)
    assert bad["event_type"] == "privilege_escalation_failed" and bad["username"] == "alice"


def test_account_and_group_changes():
    u = parse_auth_line("Nov 13 10:15:01 h useradd[7]: new user: name=backdoor, UID=1002, GID=1002, home=/home/backdoor, shell=/bin/bash", tz=UTC, now=NOW)
    assert u["event_type"] == "account_created" and u["username"] == "backdoor"
    g = parse_auth_line("Nov 13 10:15:01 h gpasswd[8]: user backdoor added by root to group sudo", tz=UTC, now=NOW)
    assert g["event_type"] == "privilege_group_change" and g["extra"]["group_name"] == "sudo" and g["extra"]["subject_user"] == "root"


def test_december_log_read_in_january_uses_previous_year():
    jan = datetime(2027, 1, 1, 0, 30, tzinfo=UTC)
    e = parse_auth_line("Dec 31 23:59:00 h sshd[1]: Failed password for root from 1.2.3.4 port 22 ssh2", tz=UTC, now=jan)
    assert e["timestamp"].startswith("2026-12-31")


def test_unrelated_lines_return_none():
    assert parse_auth_line("Nov 13 10:15:01 h CRON[1]: pam_unix(cron:session): session opened for user root", tz=UTC, now=NOW) is None
    assert parse_auth_line("garbage", tz=UTC, now=NOW) is None


# --------------------------------------------------------------------------- web access
LOGIN = ["/login", "/api/auth/login"]


def test_nginx_combined_line():
    line = '203.0.113.9 - - [13/Nov/2026:15:45:01 +0530] "GET /.env?token=abc&x=1 HTTP/1.1" 404 153 "-" "curl/8.0"'
    e = parse_access_line(line, LOGIN, "web01")
    assert e["event_type"] == "http_request" and e["status_code"] == 404 and e["source_ip"] == "203.0.113.9"
    assert e["timestamp"].startswith("2026-11-13T10:15:01+00:00")
    assert "token=[redacted]" in e["http_path"] and "abc" not in e["http_path"]
    assert e["user_agent"] == "curl/8.0"


def test_login_endpoint_classification():
    base = '198.51.100.7 - - [13/Nov/2026:10:00:00 +0000] "POST /login HTTP/1.1" %d 10 "-" "Mozilla"'
    assert parse_access_line(base % 401, LOGIN)["event_type"] == "login_failed"
    assert parse_access_line(base % 302, LOGIN)["event_type"] == "login_success"
    assert parse_access_line(base % 200, LOGIN)["event_type"] == "http_request"  # ambiguous -> not guessed
    get = '198.51.100.7 - - [13/Nov/2026:10:00:00 +0000] "GET /login HTTP/1.1" 401 10 "-" "Mozilla"'
    assert parse_access_line(get, LOGIN)["event_type"] == "http_request"


def test_malformed_request_is_kept_not_crashed():
    line = '203.0.113.9 - - [13/Nov/2026:10:00:00 +0000] "\\x16\\x03\\x01" 400 0 "-" "-"'
    e = parse_access_line(line, LOGIN)
    assert e["status_code"] == 400 and "http_method" not in e


def test_non_log_line_ignored():
    assert parse_access_line("this is not an access log line", LOGIN) is None


# --------------------------------------------------------------------------- firewall
UFW = "Nov 13 10:15:01 fw kernel: [123.4] [UFW BLOCK] IN=eth0 OUT= MAC=aa SRC=203.0.113.9 DST=10.0.0.5 LEN=60 PROTO=TCP SPT=4444 DPT=22 WINDOW=1024"


def test_ufw_block_line():
    e = parse_firewall_line(UFW, ["UFW BLOCK"], tz=UTC, now=NOW)
    assert e["event_type"] == "connection_blocked" and e["source_ip"] == "203.0.113.9" and e["dest_port"] == 22
    assert e["extra"]["proto"] == "TCP"


def test_outbound_and_unmarked_lines_ignored():
    outbound = UFW.replace("IN=eth0 OUT=", "IN= OUT=eth0")
    assert parse_firewall_line(outbound, ["UFW BLOCK"], tz=UTC, now=NOW) is None
    assert parse_firewall_line(UFW.replace("UFW BLOCK", "UFW ALLOW"), ["UFW BLOCK"], tz=UTC, now=NOW) is None


# --------------------------------------------------------------------------- windows
def _xml(event_id, record, data, system_extra=""):
    items = "".join(f'<Data Name="{k}">{v}</Data>' for k, v in data.items())
    return (
        f'<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><EventID>{event_id}</EventID>'
        f'<TimeCreated SystemTime="2026-11-13T10:15:01.1234567Z"/><EventRecordID>{record}</EventRecordID>'
        f"<Computer>WIN01</Computer></System><EventData>{items}</EventData></Event>"
    )


def test_windows_events_are_mapped():
    out = "\n".join(
        [
            _xml(4625, 101, {"TargetUserName": "administrator", "IpAddress": "203.0.113.9", "LogonType": "3", "Status": "0xc000006d"}),
            _xml(4624, 102, {"TargetUserName": "bob", "IpAddress": "10.0.0.8", "LogonType": "10"}),
            _xml(4624, 103, {"TargetUserName": "SYSTEM", "LogonType": "5"}),  # service noise
            _xml(4624, 104, {"TargetUserName": "WIN01$", "LogonType": "3"}),  # machine account
            _xml(4740, 105, {"TargetUserName": "bob"}),
            _xml(4720, 106, {"TargetUserName": "backdoor", "SubjectUserName": "intruder"}),
            _xml(4732, 107, {"TargetUserName": "Administrators", "MemberName": "CN=backdoor,CN=Users,DC=corp", "SubjectUserName": "intruder"}),
        ]
    )
    events, highest = parse_events_output(out)
    types = [e["event_type"] for e in events]
    assert types == ["login_failed", "login_success", "account_lockout", "account_created", "privilege_group_change"]
    assert highest == 107
    failed = events[0]
    assert failed["username"] == "administrator" and failed["source_ip"] == "203.0.113.9" and failed["ref"] == "win:101"
    assert failed["timestamp"].startswith("2026-11-13T10:15:01")
    group = events[-1]
    assert group["username"] == "backdoor" and group["extra"]["group_name"] == "Administrators" and group["extra"]["subject_user"] == "intruder"


def test_windows_audit_log_cleared_uses_userdata():
    xml = (
        '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><EventID>1102</EventID>'
        '<TimeCreated SystemTime="2026-11-13T10:15:01Z"/><EventRecordID>9</EventRecordID><Computer>WIN01</Computer></System>'
        '<UserData><LogFileCleared><SubjectUserName>intruder</SubjectUserName></LogFileCleared></UserData></Event>'
    )
    events, _ = parse_events_output(xml)
    assert events[0]["event_type"] == "audit_log_cleared" and events[0]["username"] == "intruder"


# --------------------------------------------------------------------------- tailing
def test_tailer_starts_at_end_then_follows_and_handles_rotation(tmp_path):
    log = tmp_path / "auth.log"
    log.write_text("old line 1\nold line 2\n")
    state = OffsetState(str(tmp_path / "state.json"))
    tail = FileTailer(str(log), state)

    assert tail.poll() == []  # history is skipped on first run
    with open(log, "a") as fh:
        fh.write("new 1\nnew 2\npartial")
    lines = [text for text, _ in tail.poll()]
    assert lines == ["new 1", "new 2"]
    with open(log, "a") as fh:
        fh.write(" done\n")
    assert [t for t, _ in tail.poll()] == ["partial done"]

    # rotation: new file replaces the old one
    os.rename(log, tmp_path / "auth.log.1")
    log.write_text("after rotate\n")
    assert [t for t, _ in tail.poll()] == ["after rotate"]

    # offsets survive a restart
    again = FileTailer(str(log), OffsetState(str(tmp_path / "state.json")))
    assert again.poll() == []


def test_tailer_backfill(tmp_path):
    log = tmp_path / "a.log"
    log.write_text("".join(f"line {i}\n" for i in range(10)))
    tail = FileTailer(str(log), OffsetState(str(tmp_path / "s.json")), backfill_lines=3)
    assert [t for t, _ in tail.poll()] == ["line 7", "line 8", "line 9"]


def test_refs_are_unique_per_line(tmp_path):
    log = tmp_path / "a.log"
    log.write_text("x\n")
    tail = FileTailer(str(log), OffsetState(str(tmp_path / "s.json")))
    tail.poll()
    with open(log, "a") as fh:
        fh.write("same\nsame\n")
    refs = [r for _, r in tail.poll()]
    assert len(refs) == 2 and refs[0] != refs[1]


# --------------------------------------------------------------------------- config
def cfg(**over):
    env = {"SENTINELX_URL": "https://siem.example.com", "SENTINELX_API_KEY": "sx_key"}
    env.update(over)
    return from_mapping(env)


def test_config_requires_url_and_key():
    with pytest.raises(ConfigError):
        from_mapping({"SENTINELX_API_KEY": "x"})
    with pytest.raises(ConfigError):
        from_mapping({"SENTINELX_URL": "https://a.b"})


def test_plain_http_only_allowed_for_localhost_or_explicit_opt_in():
    assert cfg(SENTINELX_URL="http://localhost:8000").url == "http://localhost:8000"
    with pytest.raises(ConfigError):
        cfg(SENTINELX_URL="http://siem.example.com")
    assert cfg(SENTINELX_URL="http://10.0.0.5:8000", ALLOW_INSECURE="true").allow_insecure


def test_config_lists_and_defaults():
    c = cfg(WEB_ACCESS_LOGS="/a.log, /b.log", FIREWALL_MARKERS="")
    assert c.web_access_logs == ["/a.log", "/b.log"]
    assert "UFW BLOCK" in c.firewall_markers and "/login" in c.web_login_paths


# --------------------------------------------------------------------------- shipper
class FakeResponse:
    def __init__(self, status, text=""):
        self.status_code, self.text = status, text


class FakeSession:
    def __init__(self, statuses):
        self.statuses = list(statuses)
        self.headers = {}
        self.posts = []

    def post(self, url, json=None, **kw):
        self.posts.append((url, json))
        status = self.statuses.pop(0) if self.statuses else 200
        if isinstance(status, Exception):
            raise status
        return FakeResponse(status)


def shipper(tmp_path, statuses):
    c = cfg(STATE_DIR=str(tmp_path / "state"), BATCH_SIZE="10")
    return Shipper(c, session=FakeSession(statuses))


def events(n):
    return [{"event_type": "login_failed", "message": str(i)} for i in range(n)]


def test_successful_send_uses_api_key_header_and_counts(tmp_path):
    s = shipper(tmp_path, [200])
    assert s.send(events(3)) and s.sent == 3
    assert s.session.headers["X-Agent-Key"] == "sx_key"
    url, payload = s.session.posts[0]
    assert url.endswith("/api/ingest") and len(payload["events"]) == 3 and payload["agent"]["version"]


def test_413_splits_batch_in_half(tmp_path):
    s = shipper(tmp_path, [413, 200, 200])
    assert s.send(events(4))
    assert [len(p["events"]) for _, p in s.session.posts] == [4, 2, 2]


def test_failures_are_spooled_and_delivered_later(tmp_path):
    import requests

    s = shipper(tmp_path, [requests.ConnectionError("down")] * 3)
    stop = threading.Event()
    stop.set()  # skip the back-off sleeps
    assert not s.send_with_retry(events(2), stop, attempts=1)
    s.spool.append(events(2))
    assert len(s.spool.read_all()) == 1

    s.session.statuses = [200]
    s.drain_spool(threading.Event())
    assert s.spool.read_all() == []
    assert s.sent == 2


def test_unauthorized_is_not_dropped(tmp_path):
    s = shipper(tmp_path, [401])
    assert s.send(events(1)) is False and s.auth_failed


def test_other_client_errors_drop_the_batch_instead_of_looping(tmp_path):
    s = shipper(tmp_path, [422])
    assert s.send(events(1)) is True


def test_spool_trims_oldest_when_over_budget(tmp_path):
    from sentinelx_agent.shipper import Spool

    sp = Spool(str(tmp_path / "spool.jsonl"), max_bytes=400)
    for i in range(20):
        sp.append([{"message": f"event-{i}-" + "x" * 50}])
    batches = sp.read_all()
    assert 0 < len(batches) < 20
    assert batches[-1][0]["message"].startswith("event-19")


def test_redact_query():
    assert redact_query("/a?password=x&y=1") == "/a?password=[redacted]&y=1"
    assert split_syslog_prefix("not a log line") is None
