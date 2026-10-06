from __future__ import annotations

import re
from typing import Any

from arch_guard.events import make_event


ACCEPTED_RE = re.compile(
    r"Accepted (?P<method>\S+) for (?P<user>\S+) "
    r"from (?P<ip>\S+) port (?P<port>\d+)"
)

FAILED_RE = re.compile(
    r"Failed (?P<method>\S+) for "
    r"(?:(?:invalid user) )?"
    r"(?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)"
)

INVALID_RE = re.compile(
    r"Invalid user (?P<user>\S+) from (?P<ip>\S+)"
)

SESSION_OPEN_RE = re.compile(
    r"pam_unix\(sshd:session\): session opened "
    r"for user (?P<user>[^\s(]+)"
)

SESSION_CLOSE_RE = re.compile(
    r"pam_unix\(sshd:session\): session closed "
    r"for user (?P<user>[^\s(]+)"
)


def parse_sshd_message(
    message: str,
    *,
    timestamp: str | None = None,
) -> dict[str, Any] | None:

    match = ACCEPTED_RE.search(message)

    if match:
        data = match.groupdict()

        return make_event(
            "ssh_auth_success",
            "INFO",
            sensor="ssh",
            notify=False,
            timestamp=timestamp,
            raw=message,
            user=data["user"],
            auth_method=data["method"],
            ssh_source_ip=data["ip"],
            ssh_source_port=int(data["port"]),
        )

    match = FAILED_RE.search(message)

    if match:
        data = match.groupdict()

        return make_event(
            "ssh_auth_failure",
            "WARNING",
            sensor="ssh",
            notify=False,
            timestamp=timestamp,
            raw=message,
            user=data["user"],
            auth_method=data["method"],
            ssh_source_ip=data["ip"],
            ssh_source_port=int(data["port"]),
        )

    match = INVALID_RE.search(message)

    if match:
        data = match.groupdict()

        return make_event(
            "ssh_invalid_user",
            "WARNING",
            sensor="ssh",
            notify=False,
            timestamp=timestamp,
            raw=message,
            user=data["user"],
            ssh_source_ip=data["ip"],
        )

    match = SESSION_OPEN_RE.search(message)

    if match:
        data = match.groupdict()

        return make_event(
            "ssh_session_open",
            "INFO",
            sensor="ssh",
            notify=False,
            timestamp=timestamp,
            raw=message,
            user=data["user"],
        )

    match = SESSION_CLOSE_RE.search(message)

    if match:
        data = match.groupdict()

        return make_event(
            "ssh_session_closed",
            "INFO",
            sensor="ssh",
            notify=False,
            timestamp=timestamp,
            raw=message,
            user=data["user"],
        )

    return None
